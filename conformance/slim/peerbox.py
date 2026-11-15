#!/usr/bin/env python3
"""Slim suite, peerbox: peerboxes, requests and their checks, fetch, refused submissions and the previous schema
(PBX-1 to PBX-3).

alice creates a coordinator-free network, links a second machine (alice2), and bob and carol join as other people.
alice's peerbox serves a Git fixture repository whose `main` is the protected branch, with a side branch `secret` the
protected branch never reaches and a reference-transaction hook that marks any ref change made with hooks enabled;
bob may read and submit, carol only read, within 400 bytes. Peer operations go through the sender's `POST /v1/tasks`
and the CLI, and raw requests through the peer probe. The rest of the peerbox contract is split by area: stored
contributions, review, status, restarts and withdrawal are peerbox_contributions.py; the policy body, list and
several rules on one peerbox peerbox_rules.py; invitations and a lapsed sender peerbox_invites.py; runs
peerbox_runs.py. The shared fixtures are peerbox_common.py and peerbox_fixtures.py.

Written from docs/peerbox-contract.md only (cited as "peerbox <section>"), with the runtime task, task, artifact and
coordinator-free contracts it extends. No VM, no KVM, no model calls.
"""
import os
import re
import shutil
import sqlite3

from harness import Suite, check, members
from runtime_common import bind, need, refused, state
from peerbox_fixtures import (SCHEMA_TABLES, V3_HEADER, base_error_bundles, hostile_bundles, oversized, owner_repo,
                              predecessor, requires, self_check, sha256_clone, sha256_repo, worktree)
from peerbox_common import (REASON, bundle_heads, create, failed_with, fetch_bytes, git, op_fails, op_ok, outcome,
                            peerbox_network, raw_op, refs, rev, share, sha256, shown, submit_bundle, submit_op, tail,
                            unbundle, upload_bundle)

suite = Suite("peerbox", __doc__)
bind(suite)
MAIN_SCHEMA = 31  # the schema version on main when this suite was written; the contract adds the next one


def case(name, spec, known=REASON):
    return suite.case(name, spec, known=known)

def pbx():
    return need("pbx")[0]

def hook_ran():
    return (state["repo"] / "HOOK_RAN").exists()

def member_ref(person, branch):
    return rev(state["repo"], f"refs/peerbox/{pbx()}/members/{person}/{branch}")

@suite.case("fixtures", "peerbox_fixtures.py: every Git fixture of the peerbox suites, built host-free and checked")
def _():
    print(f"  fixtures built and checked in {self_check(suite.work / 'fixture-check'):.1f}s", flush=True)

@suite.case("setup", "decentralized-spec 6, 8 (create, join, link); a Git fixture repository")
def _():
    peerbox_network(suite, ("bob", "carol"), second_machine=True)
    owner = owner_repo(suite.work / "alice-repo")
    state.update(repo=owner["repo"], main=owner["main"], main_parent=owner["main_parent"], secret=owner["secret"])


# Create (peerbox CLI and local API: peerbox create).

@case("create_disclosure", "peerbox CLI: create shows what a read discloses, refuses by default, --yes", known=None)
def _():
    a, repo = need("a", "repo")
    argv = ["peerbox", "create", "--repository", repo, "--branch", "main", "--title", "Alice's project"]
    for label, result in (("no terminal", a.cli(*argv)), ("an empty answer", a.cli(*argv, tty=True, input="\n"))):
        said = result.stdout + result.stderr
        check(not result.ok, f"create with {label} exited 0")
        for want in (state["main"], "main", "Ada Author", "ada@example.test", "Cy Committer", "cy@example.test"):
            check(want in said, f"the disclosure ({label}) does not show {want!r}: {tail(said)}")
        check(re.search(r"\b3\b", said) and "Sly Secret" not in said and "sly@example.test" not in said,
              f"the disclosure ({label}) must count 3 reachable commits and name no author outside main")
    check(shown() == [], "a refused create left a peerbox")
    state["pbx"] = create(repo, title="Alice's project")
    records = shown(None, pbx())
    check(len(records) == 1 and records[0]["peerbox_id"] == pbx() and records[0]["title"] == "Alice's project"
          and records[0]["branch"] == "main" and records[0]["repository"] == str(repo), f"show: {records}")
    state["hidden"] = create(repo, title="hidden")

@suite.case("shares", "peerbox CLI share: bob reads and submits (2 pending, 65,536 bytes), carol reads within 400 "
                      "bytes; the rules themselves are peerbox_rules.py")
def _():
    share(pbx(), state["bob_p"], actions=("read", "submit"), extra=("--max-pending", "2", "--max-bundle-bytes",
                                                                    "65536"))
    share(pbx(), state["carol_p"], extra=("--max-bundle-bytes", "400"))


# Authorization and requests (peerbox Requests, Checks).

@case("unknown_unreadable_and_invalid", "peerbox Checks 1 (404 unknown for an unknown and an unreadable peerbox); "
                                        "Requests (400 invalid naming the field; grant, target_agent_id, branch)", known=None)
def _():
    b, main = need("b", "main")
    for label, op in (("unknown", {"op": "fetch", "peerbox_id": "pbx_" + os.urandom(16).hex()}),
                      ("unreadable", {"op": "fetch", "peerbox_id": need("hidden")[0]}),
                      ("unreadable status", {"op": "status", "peerbox_id": need("hidden")[0]})):
        status, body = raw_op(op)
        refused(status, body, 404, "unknown")
        check(need("hidden")[0] not in str(body), f"{label}: the refusal names the peerbox: {body}")
    fetch = {"op": "fetch", "peerbox_id": pbx()}
    entry = upload_bundle(b, b"# v2 git bundle\n")
    octet = upload_bundle(b, b"# v2 git bundle\n\n", name="other.bin")
    octet = {**octet, "media_type": "application/octet-stream"}
    submit = {"op": "submit", "peerbox_id": pbx(), "base": main, "branch": "ok", "bundle": entry["sha256"]}
    cases = [("target_agent_id", fetch, {"target_agent_id": "agent_" + os.urandom(16).hex()}),
             ("grant_id", fetch, {"grant_id": "grant_" + os.urandom(16).hex()}),
             ("delegation", fetch, {"delegation": []}), ("surprise", fetch, {"surprise": 1}),
             ("op", {"op": "merge", "peerbox_id": pbx()}, {}), ("peerbox_id", {"op": "fetch"}, {}),
             ("extra", {**fetch, "extra": 1}, {}), ("have", {**fetch, "have": [main, main]}, {}),
             ("have", {**fetch, "have": [os.urandom(20).hex() for _ in range(33)]}, {}),
             ("have", {**fetch, "have": [main[:39]]}, {}), ("after", {"op": "list", "after": "pbx_x"}, {}),
             ("bundle", submit, {}), ("bundle", {**submit, "bundle": octet["sha256"]}, {"artifacts": [octet]}),
             ("workspace", {"op": "run", "peerbox_id": pbx(), "commit": main,
                            "run": {"argv": ["true"], "workspace": None}}, {})]
    for name in ("", "-x", ".x", "x.lock", "x/", "a..b", "a/b", "HEAD", "@", "x.", "x" * 65):
        cases.append(("branch", {**submit, "branch": name}, {"artifacts": [entry]}))
    wrong = []
    for field, op, extra in cases:
        status, body = raw_op(op, **extra)
        if not (status == 400 and (body or {}).get("code") == "invalid" and field in (body or {}).get("error", "")):
            wrong.append(f"{field} {str(op)[:60]}: {status} {body}")
    check(not wrong, f"want 400 invalid naming the field: {wrong}")


# Fetch (peerbox Fetch).

@case("fetch_bundle", "peerbox Fetch: one ref at the protected head, digest and size, verifies, nothing outside "
                      "main; CLI fetch sets refs/peerbox/PEERBOX/BRANCH", known=None)
def _():
    a, b, main = need("a", "b", "main")
    value, last, task_id = op_ok({"op": "fetch", "peerbox_id": pbx()})
    check(set(value) == {"head", "bundle_sha256", "size"} and value["head"] == main, f"fetch result {value}")
    data = fetch_bytes(task_id, last)
    check(sha256(data) == value["bundle_sha256"] and len(data) == value["size"], "bundle digest or size")
    check(data.startswith(b"# v2 git bundle\n") and bundle_heads(data, suite.work) == [(main, "refs/heads/main")],
          f"bundle heads {bundle_heads(data, suite.work)}")
    got = unbundle(data, suite.work)
    check(rev(got, "refs/fetched/main") == main and git(got, "rev-list", "--count", "--all") == "3"
          and git(got, "cat-file", "-e", state["secret"], ok=False).returncode != 0,
          "the bundle holds other than exactly main's three commits")
    state["full_size"] = len(data)
    clone = suite.work / "bob-clone"
    fetched = b.cli("--json", "peerbox", "fetch", "--peer", a.id, pbx(), "--repository", clone, timeout=90)
    check(fetched.ok and rev(clone, f"refs/peerbox/{pbx()}/main") == main and isinstance(fetched.json, dict)
          and set(fetched.json) == {"head", "bundle_sha256", "size"} and fetched.json["head"] == main,
          f"peerbox fetch --json prints the fetch result: exit {fetched.code} {tail(fetched.stderr)}")
    wt = state["bob_wt"] = suite.work / "bob-wt"
    worktree(clone, wt, pbx())
    state["bob_clone"] = clone


@case("fetch_have_and_repeat", "peerbox Fetch: have shortens the bundle, a have outside main changes nothing, the "
                               "head in have gives no artifact and changes no ref", known=None)
def _():
    a, b, main, clone = need("a", "b", "main", "bob_clone")
    value, last, task_id = op_ok({"op": "fetch", "peerbox_id": pbx(), "have": [state["main_parent"]]})
    data = fetch_bytes(task_id, last)
    status, said = requires(clone, data, suite.work)
    check(value["size"] < need("full_size")[0] and status == 0 and state["main_parent"] in said,
          f"a have bundle of {value['size']} bytes (full {state['full_size']}) requiring {said[-200:]!r}")
    value, last, task_id = op_ok({"op": "fetch", "peerbox_id": pbx(), "have": [state["secret"], os.urandom(20).hex()]})
    data = fetch_bytes(task_id, last)
    check(len(data) == need("full_size")[0] and rev(unbundle(data, suite.work), "refs/fetched/main") == main,
          "a have outside the protected branch changed the bundle")
    task_id = submit_op({"op": "fetch", "peerbox_id": pbx(), "have": [main]})
    kind, value, last = outcome(task_id)
    check(kind == "succeeded" and value == {"head": main, "bundle_sha256": None, "size": 0}
          and not last.get("artifacts"), f"a fetch with the head in have: {kind} {value} {last.get('artifacts')}")
    before = refs(clone)
    again = b.cli("--json", "peerbox", "fetch", "--peer", a.id, pbx(), "--repository", clone, timeout=90)
    check(again.ok and refs(clone) == before and again.json == {"head": main, "bundle_sha256": None, "size": 0},
          f"a repeat CLI fetch: exit {again.code} {again.json}, refs changed "
                                              f"{refs(clone) != before}")


@case("fetch_sha256", "peerbox Peerboxes and contributions (commit IDs: 64 hex digits for SHA-256, any other "
                      "length 400 invalid); Fetch (a version 3 bundle for a SHA-256 repository); CLI fetch", known=None)
def _():
    a, b, main = need("a", "b", "main")
    owner = sha256_repo(suite.work / "alice-sha256")
    head, parent = owner["main"], owner["main_parent"]
    box = create(owner["repo"], title="sha256")
    share(box, state["bob_p"])
    value, last, task_id = op_ok({"op": "fetch", "peerbox_id": box})
    data = fetch_bytes(task_id, last)
    check(value["head"] == head and len(head) == 64 and data.startswith(V3_HEADER)
          and bundle_heads(data, suite.work) == [(head, "refs/heads/main")],
          f"a SHA-256 fetch: head {value['head']}, header {data[:60]!r}")
    clone = sha256_clone(owner, suite.work / "bob-sha256", box)
    value, last, task_id = op_ok({"op": "fetch", "peerbox_id": box, "have": [parent]})
    status, said = requires(clone, fetch_bytes(task_id, last), suite.work)
    check(value["head"] == head and status == 0 and parent in said, f"a SHA-256 fetch with have: {said[-200:]!r}")
    for peerbox_id, wrong in ((box, os.urandom(20).hex()), (pbx(), os.urandom(32).hex())):
        status, body = raw_op({"op": "fetch", "peerbox_id": peerbox_id, "have": [wrong]})
        refused(status, body, 400, "invalid", "have")
    fresh = suite.work / "bob-sha256-fresh"
    for label, target in (("a fresh directory", fresh), ("an existing SHA-256 clone", clone)):
        result = b.cli("--json", "peerbox", "fetch", "--peer", a.id, box, "--repository", target, timeout=90)
        check(result.ok and isinstance(result.json, dict) and result.json.get("head") == head
              and rev(target, f"refs/peerbox/{box}/main") == head
              and git(target, "rev-parse", "--show-object-format") == "sha256",
              f"peerbox fetch into {label}: exit {result.code} {result.json} {tail(result.stderr)}")


@case("fetch_too_large", "peerbox Fetch: a bundle over max_bundle_bytes fails too_large with its size (PBX-3)", known=None)
def _():
    c, full = need("c", "full_size")
    check(full > 400, f"fixture: main's bundle has {full} bytes, not over carol's bound of 400")
    value = op_fails("too_large", {"op": "fetch", "peerbox_id": pbx()}, sender=c)
    check(str(need("full_size")[0]) in value["message"], f"the message does not give the size: {value}")


# Submissions refused before anything is stored (peerbox Checks 2 and 3, Submit); stored ones are
# peerbox_contributions.py.

@case("submit_refused_403", "peerbox Checks 2 and 3: submit without peerbox.submit, a bundle over max_bundle_bytes", known=None)
def _():
    b, c, main = need("b", "c", "main")
    small = upload_bundle(c, b"# v2 git bundle\n\n")
    status, body = raw_op({"op": "submit", "peerbox_id": pbx(), "base": main, "branch": "c1",
                           "bundle": small["sha256"]}, sender=c, artifacts=[small])
    check(status == 403, f"carol, read only, submitting: {status} {body}")
    _, data = oversized(need("bob_clone")[0], need("bob_wt")[0], suite.work / "big.bundle", "big", main, 65536, 96000,
                        start=main)
    entry = upload_bundle(b, data)
    status, body = raw_op({"op": "submit", "peerbox_id": pbx(), "base": main, "branch": "big",
                           "bundle": entry["sha256"]}, artifacts=[entry])
    check(status == 403 and member_ref(state["bob_pid"], "big") is None, f"a bundle over the bound: {status} {body}")


@case("submit_base_errors", "peerbox Submit step 3: base_unknown, base_not_ancestor; a failed step stores nothing", known=None)
def _():
    main = need("main")[0]
    before = refs(state["repo"])
    based, old = base_error_bundles(need("bob_clone")[0], need("bob_wt")[0], suite.work, main, state["main_parent"])
    for base in (state["secret"], os.urandom(20).hex()):
        failed_with("base_unknown", submit_bundle(pbx(), based, base, "based"))
    failed_with("base_not_ancestor", submit_bundle(pbx(), old, main, "old-base"))
    check(refs(state["repo"]) == before, "a refused submission changed a ref of the repository")


@case("submit_hostile_bundles", "peerbox Submit: a mutated byte (bundle_invalid), a ref outside refs/heads/, an "
                                "option-like ref, two refs, .git paths and hooks; nothing stored, no hook run", known=None)
def _():
    main = need("main")[0]
    before = refs(state["repo"])
    mutated, variants, dotgit = hostile_bundles(need("bob_clone")[0], need("bob_wt")[0], suite.work, main,
                                                f"refs/peerbox/{pbx()}/members/{state['bob_pid']}/hostile")
    failed_with("bundle_invalid", submit_bundle(pbx(), mutated, main, "hostile"))
    stored = []
    for label, data in variants.items():  # the bundle's single ref must be refs/heads/BRANCH; no code is named
        kind, value, _ = outcome(submit_bundle(pbx(), data, main, "hostile"))
        if kind != "failed":
            stored.append(f"{label}: {kind} {value}")
    for label, data in dotgit.items():
        kind, value, _ = outcome(submit_bundle(pbx(), data, main, "hostile"))
        if not (kind == "failed" and isinstance(value, dict) and set(value) == {"error", "message"}
                and value["error"] == "bundle_invalid"):
            stored.append(f"{label}: {kind} {value}, want failed bundle_invalid")
    check(not stored, f"hostile bundles not refused as required: {stored}")
    check(refs(state["repo"]) == before and not hook_ran(), "a hostile submission changed a ref or ran a hook")


# Persistence.

@case("open_previous_schema", "peerbox Persistence: a schema-31 database opens, keeps its data, moves to the next "
                              "version, and holds peerboxes", known=None)
def _():
    """A real schema-31 state (DEC-OWN9, as schema28_compatibility.py does for conversations): alice2's state, made by
    the binary under test, with every table that schema 31 does not have dropped and the version set back. The
    contract adds only new tables (peerbox Persistence; task records are JSON), so this is the predecessor's shape,
    and a migration that only bumps the version leaves peerbox storage missing."""
    a2, repo = need("a2", "repo")
    copy = suite.host("alice2-copy", start=False)
    a2.stop()
    shutil.copytree(a2.state, copy.state, dirs_exist_ok=True)
    for leftover in ("admin.sock", "adapter.sock"):
        (copy.state / leftover).unlink(missing_ok=True)
    path = copy.state / "host.db"
    check(path.exists(), "no host.db in the copy")
    db = sqlite3.connect(str(path))
    current = db.execute("PRAGMA user_version").fetchone()[0]
    # Later contracts add versions after the peerbox one (PF-1(a) takes 33); the schema-31 state still upgrades
    # to the current one.
    check(current >= MAIN_SCHEMA + 1, f"schema version {current}; this contract adds {MAIN_SCHEMA + 1} (update "
                                      f"MAIN_SCHEMA and SCHEMA_TABLES if main moved)")
    counts = {t: db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("networks", "network_statements")}
    db.close()
    predecessor(path, SCHEMA_TABLES, MAIN_SCHEMA)
    copy.start()
    try:
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            check(db.execute("PRAGMA user_version").fetchone()[0] == current, "the schema-31 state was not upgraded")
            for table, count in counts.items():  # statements may grow by sync, never shrink
                got = db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                check(got >= count and (table != "networks" or got == count), f"{table}: {count} rows, then {got}")
        finally:
            db.close()
        status, network = copy.api("GET", f"/v2/networks/{state['net']}")
        check(status == 200 and network.get("person_public_key") == state["alice_public"]
              and copy.id == a2.id and a2.public_key in members(copy, state["net"]),
              f"the upgraded host lost its identity or network: {status} {str(network)[:200]}")
        made = create(repo, host=copy, title="after upgrade")
        check(made in [r["peerbox_id"] for r in shown(copy)], "peerbox show on the upgraded state misses the record")
    finally:
        copy.stop()


suite.finish()
