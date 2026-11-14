#!/usr/bin/env python3
"""Slim suite, peerbox: peerboxes, their rules, fetch, submit, review, status, withdrawal and invites (PBX-1 to PBX-8).

alice creates a coordinator-free network, links a second machine (alice2), and bob and carol join as other people;
dan, erin, fay and gus join later through peerbox invites. alice's peerbox serves a Git fixture repository whose
`main` is the protected branch, with a side branch `secret` the protected branch never reaches and a
reference-transaction hook that marks any ref change made with hooks enabled. Peer operations go through the
sender's `POST /v1/tasks` and the CLI, and raw requests through the peer probe. Runs, the fake runtime and the
30-day window of a superseded contribution are peerbox_runs.py; the shared fixtures are peerbox_common.py.

Written from docs/peerbox-contract.md only (cited as "peerbox <section>"), with the runtime task, task, artifact and
coordinator-free contracts it extends. No VM, no KVM, no model calls. Nothing in the contract is implemented yet:
every case past the network setup is a strict expected failure.
"""
import os
import re
import shutil
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from harness import (Suite, attention, check, create_network, join_new_person, link_machine, members, rfc3339,
                     ssh_key, wait_for)
from runtime_common import (bind, learn, need, policy_statement, policy_version, refused,
                            run_side_by_side, sign_policy, state)
from peerbox_fixtures import (SCHEMA_TABLES, V3_HEADER, base_error_bundles, commit_on, head_mover, hostile_bundles,
                              oversized, owner_repo, paging_bundles, predecessor, requires, self_check, sha256_clone,
                              sha256_repo, worktree)
from peerbox_common import (DEFAULT_BUNDLE, OUTPUT_LIMIT, PSB1, REASON, RULE_KEYS, Prompted, admit_waiting,
                            b64url_json, bundle, bundle_heads, check_record, commit_files, create, failed_with,
                            fetch_bytes, git, init_repo, join_with_code, op_fails, op_ok, outcome, owner_cli,
                            pbx_rules, principal, raw_op, refs, rev, rule, rules_for, settle, sha256, share,
                            status_all, shown, submit_bundle, submit_op, tail, unbundle, unshare, upload_bundle,
                            with_peerbox_rules)

suite = Suite("peerbox", __doc__)
bind(suite)
clock = suite.use_clock()
MAIN_SCHEMA = 31  # the schema version on main when this suite was written; the contract adds the next one
DAY, HOUR = 86400, 3600


def case(name, spec, known=REASON):
    return suite.case(name, spec, known=known)


def pbx():
    return need("pbx")[0]


def hook_ran():
    return (state["repo"] / "HOOK_RAN").exists()


def person_id(host, key):
    return host.ok("person", "show", "--person-key", key)["person_id"]


def new_commit(branch, files, start=None, wt=None):
    """A commit on BRANCH in bob's worktree (reset to START when given); returns its ID."""
    return commit_on(wt or need("bob_wt")[0], branch, files, start)


def send(branch, tip, base=None, sender=None, clone=None):
    """Bundle TIP as refs/heads/BRANCH without BASE's history and submit it; returns the task ID."""
    base = base or state["main"]
    data = bundle(clone or need("bob_clone")[0], suite.work / f"{branch}-{tip[:8]}.bundle", tip, exclude=[base],
                  ref=branch)
    return submit_bundle(pbx(), data, base, branch, sender=sender)


def contribute(branch, files, start=None):
    """A new commit on BRANCH, submitted; returns the contribution record."""
    tip = new_commit(branch, files, start)
    kind, value, _ = outcome(send(branch, tip))
    check(kind == "succeeded", f"submit {branch}: {kind} {value}")
    return check_record(value, pbx())


def member_ref(person, branch):
    return rev(state["repo"], f"refs/peerbox/{pbx()}/members/{person}/{branch}")


def mine(contribution_id, sender=None):
    value, _, _ = op_ok({"op": "status", "peerbox_id": pbx(), "contribution_id": contribution_id}, sender)
    check(len(value["contributions"]) == 1 and value["next"] is None, f"status of {contribution_id}: {value}")
    return check_record(value["contributions"][0], pbx())


def review(contribution_id, verdict, *extra):
    return state["a"].cli("--json", "peerbox", "review", contribution_id, f"--{verdict}", *extra, timeout=60)


def invite_code(*args, host=None):
    result = owner_cli("invite", *args, host=host)
    text = result.stdout + result.stderr
    found = PSB1.search(text)
    check(found, f"peerbox invite printed no psb1- code: exit {result.code}")
    inner = b64url_json(found.group(0), "psb1-")
    made = result.json
    check(isinstance(made, dict) and set(made) == {"code", "invitation_id", "expires_at"}
          and made["code"] == found.group(0) and made["invitation_id"], "peerbox invite --json is not "
                                                                         "{code, invitation_id, expires_at}")
    return made["code"], inner, made["invitation_id"]


def pending_shares(host=None):
    return owner_cli("invite", "--list", host=host).stdout


@suite.case("fixtures", "peerbox_fixtures.py: every Git fixture of the peerbox suites, built host-free and checked")
def _():
    print(f"  fixtures built and checked in {self_check(suite.work / 'fixture-check'):.1f}s", flush=True)


@suite.case("setup", "decentralized-spec 6, 8 (create, join, link); a Git fixture repository")
def _():
    a, a2, b, c = (suite.host(n) for n in ("alice", "alice2", "bob", "carol"))
    state.update(a=a, a2=a2, b=b, c=c)
    net = state["net"] = create_network(a, "peerbox", "alice")["id"]
    state["alice_public"] = a.api("GET", f"/v2/networks/{net}")[1]["person_public_key"]
    state["alice_key"] = a.home / ".config/peerspan/person_ed25519"
    state["bob_key"], state["carol_key"] = ssh_key(b.root, "bob"), ssh_key(c.root, "carol")
    run_side_by_side((join_new_person, (a, b, "bob", state["bob_key"], net), {}),
                     (join_new_person, (a, c, "carol", state["carol_key"], net), {}),
                     (link_machine, (a, a2, net, state["alice_public"]), {"key": state["alice_key"]}))
    state["alice_pid"] = person_id(a, state["alice_key"])
    for who, host in (("bob", b), ("carol", c)):
        state[f"{who}_pid"] = person_id(host, state[f"{who}_key"])
        state[f"{who}_p"] = principal(state[f"{who}_pid"])
        state[f"{who}_public"] = host.api("GET", f"/v2/networks/{net}")[1]["person_public_key"]
    b.ok("allow", "alice", "--person-key", state["bob_key"])  # bob's own policy, for his peerbox later
    state["learners"] = [a2, b, c]
    for host in state["learners"]:
        learn(host, state["alice_public"], policy_version(a, state["alice_public"]))
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


# The policy body (peerbox Peerbox rules, Policy body).

@case("share_and_policy_body", "peerbox Policy body (key order, admitted by the owner's other host and another "
                               "person's host); CLI share defaults", known=None)
def _():
    a, a2, b = need("a", "a2", "b")
    share(pbx(), state["bob_p"], actions=("read", "submit"), extra=("--max-pending", "2", "--max-bundle-bytes",
                                                                    "65536"))
    share(pbx(), state["carol_p"], extra=("--max-bundle-bytes", "400"))
    bad = a.cli("peerbox", "share", pbx(), "--for", state["carol_p"], "--max-pending", "3", "--person-key",
                state["alice_key"], timeout=60)
    check(not bad.ok, "share without submit accepted --max-pending 3")
    body = policy_statement(a, state["alice_public"])[3]
    keys = list(body)
    anchor = "runtime_rules" if "runtime_rules" in keys else "capability_rules"
    check("peerbox_rules" in keys and keys.index("peerbox_rules") == keys.index(anchor) + 1,
          f"peerbox_rules is not right after {anchor}: {keys}")
    rules = body["peerbox_rules"]
    check(all(list(r) == RULE_KEYS for r in rules), f"rule keys {[list(r) for r in rules]}, want {RULE_KEYS}")
    check(rules_for(pbx(), state["bob_p"]) == [rule(pbx(), [state["bob_p"]], ("read", "submit"), 65536, 2)],
          f"bob's rule {rules_for(pbx(), state['bob_p'])}")
    check(rules_for(pbx(), state["carol_p"]) == [rule(pbx(), [state["carol_p"]], ("read",), 400, 0)],
          f"carol's read-only rule (max_pending defaults to 0): {rules_for(pbx(), state['carol_p'])}")
    for host in (a2, b):
        check(pbx_rules(host) == rules, f"{host.name} holds {pbx_rules(host)}")


@case("policy_body_refusals", "peerbox Policy body (Reading): empty, unknown or missing key, a principal in two "
                              "rules of one peerbox, submit without read, max_pending against submit, ranges", known=None)
def _():
    a, b = need("a", "b")
    good = pbx_rules()
    check(good, "no peerbox rules to amend")
    bob = rules_for(pbx(), state["bob_p"])[0]
    check(good.count(bob) == 1, f"bob's rule {bob} is not one rule of {good}")
    others = [r for r in good if r != bob]  # by value: each variant below then has exactly one defect
    check(not [r for r in others if r["peerbox"] == pbx() and state["bob_p"] in r["principals"]],
          "fixture: the rules besides bob's still name bob on this peerbox")
    variants = {
        "empty peerbox_rules": [],
        "an unknown key": others + [{**bob, "max_runs": 1}],
        "a missing key": others + [{k: v for k, v in bob.items() if k != "max_pending"}],
        "keys out of order": others + [dict(reversed(list(bob.items())))],
        "bob in two rules of one peerbox": good + [rule(pbx(), [state["bob_p"]])],
        "submit without read": others + [{**bob, "actions": ["peerbox.submit"]}],
        "actions out of order": others + [{**bob, "actions": ["peerbox.submit", "peerbox.read"]}],
        "max_pending 0 with submit": others + [{**bob, "max_pending": 0}],
        "max_pending 1 without submit": others + [{**bob, "actions": ["peerbox.read"], "max_pending": 1}],
        "max_pending 65": others + [{**bob, "max_pending": 65}],
        "max_bundle_bytes 0": others + [{**bob, "max_bundle_bytes": 0}],
        "max_bundle_bytes over 100 MiB": others + [{**bob, "max_bundle_bytes": DEFAULT_BUNDLE + 1}],
        "a malformed peerbox ID": others + [{**bob, "peerbox": "pbx_1234"}],
    }
    before = policy_version(a, state["alice_public"])
    accepted = [label for label, rules in variants.items()
                if (lambda s: s[0] == 200 and s[1].get("committed"))(
                    sign_policy(lambda body, rules=rules: with_peerbox_rules(body, rules)))]
    check(not accepted, f"policies admitted: {accepted}")
    check(policy_version(a, state["alice_public"]) == before, "a refused policy changed the current version")
    status, response = sign_policy(lambda body: with_peerbox_rules(body, good + [rule(need("hidden")[0],
                                                                                      [state["carol_p"]])]))
    check(status == 200 and response.get("committed"), f"control, a valid second peerbox: {status} {response}")
    for host in state["learners"]:
        learn(host, state["alice_public"], before + 1)


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


@case("list_readable_and_paging", "peerbox Results (list entries, ascending, whole entries within 65,536 bytes, "
                                  "after and next); CLI list follows next", known=None)
def _():
    a, b, c = need("a", "b", "c")
    with ThreadPoolExecutor(8) as pool:
        many = list(pool.map(lambda i: create(state["repo"], title=f"{i:03d}" + "p" * 197), range(200)))
    status, response = sign_policy(lambda body: with_peerbox_rules(
        body, pbx_rules() + [rule(x, [state["bob_p"]]) for x in many]))
    check(status == 200 and response.get("committed"), f"200 more rules for bob: {status} {response}")
    learn(b, state["alice_public"], policy_version(a, state["alice_public"]))
    readable, seen, after, pages = sorted(many + [pbx()]), [], None, 0
    while True:
        value, last, _ = op_ok({"op": "list", **({"after": after} if after else {})})
        pages += 1
        check(len(last["output"].encode()) <= OUTPUT_LIMIT and set(value) == {"peerboxes", "next"}, f"list {value}")
        for entry in value["peerboxes"]:
            check(set(entry) == {"peerbox_id", "title", "branch", "head", "actions"} and entry["branch"] == "main"
                  and entry["head"] == state["main"], f"list entry {entry}")
            want = ["peerbox.read", "peerbox.submit"] if entry["peerbox_id"] == pbx() else ["peerbox.read"]
            check(entry["actions"] == want, f"actions {entry['actions']} of {entry['peerbox_id']}, want {want}")
        seen += [e["peerbox_id"] for e in value["peerboxes"]]
        if value["next"] is None:
            break
        check(value["next"] == seen[-1], f"next {value['next']} is not the last returned ID")
        after = value["next"]
    check(pages > 1 and seen == readable, f"{pages} pages, {len(seen)} entries (sorted, unique: "
                                          f"{seen == sorted(set(seen))}), want {len(readable)} over several pages")
    listed = b.cli("--json", "peerbox", "list", "--peer", a.id, timeout=90)
    check(listed.ok and isinstance(listed.json, dict)
          and [e["peerbox_id"] for e in listed.json.get("peerboxes") or []] == readable,
          f"peerbox list --peer --json, one merged peerboxes array: exit {listed.code} {tail(listed.stderr)}")
    value, _, _ = op_ok({"op": "list"}, sender=c)
    check([e["peerbox_id"] for e in value["peerboxes"]] == sorted([pbx(), need("hidden")[0]]) and value["next"] is None,
          f"carol's list {value}")


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


# Submit (peerbox Submit, Peerboxes and contributions).

@case("submit_contribution", "peerbox Submit: stored under the member ref and the contribution ref; the record; "
                             "CLI submit with the default base", known=None)
def _():
    a, b, main = need("a", "b", "main")
    head = new_commit("feature", {"feature.txt": "bob's change\n"})
    result = b.cli("--json", "peerbox", "submit", "--peer", a.id, pbx(), "--repository", need("bob_clone")[0],
                   "--branch", "feature", timeout=90)
    check(result.ok, f"peerbox submit: exit {result.code} {tail(result.stderr)}")
    record = check_record(result.json, pbx())  # --json prints the operation's result: the contribution record
    records, _ = status_all(pbx())
    check([r for r in records if r["head"] == head] == [record], "status does not list exactly the submitted record")
    check(record["state"] == "pending" and record["base"] == main and record["branch"] == "feature"
          and record["decision"] is None and record["runs"] == [] and record["runs_total"] == 0
          and record["contributor"] == {"person_id": state["bob_pid"], "host_id": b.id, "agent_id": None,
                                        "session_id": None} and re.match(r"^[0-9a-f]{64}$", record["bundle_sha256"]),
          f"the record {record}")
    check(member_ref(state["bob_pid"], "feature") == head
          and rev(state["repo"], f"refs/peerbox/{pbx()}/contributions/{record['contribution_id']}") == head
          and rev(state["repo"], "main") == main and not hook_ran(), "member ref, contribution ref or main")
    state["first"] = record


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


@case("submit_pending_limit_and_supersede", "peerbox Submit step 1 (pending_limit; a replacement at the same member "
                                            "ref accepted at the limit); superseding keeps the contribution ref", known=None)
def _():
    main, first = need("main", "first")
    second = contribute("feature2", {"f2.txt": "2\n"}, start=main)
    tip = new_commit("feature3", {"f3.txt": "3\n"}, start=main)
    failed_with("pending_limit", send("feature3", tip))
    check(member_ref(state["bob_pid"], "feature3") is None, "a refused submission set a member ref")
    replaced = contribute("feature", {"feature.txt": "bob's change, revised\n"})
    old = mine(first["contribution_id"])
    check(old["state"] == "superseded" and replaced["state"] == "pending"
          and member_ref(state["bob_pid"], "feature") == replaced["head"]
          and rev(state["repo"], f"refs/peerbox/{pbx()}/contributions/{first['contribution_id']}") == first["head"],
          f"after the replacement: old {old['state']}, new {replaced['state']}")
    state.update(feature=replaced, feature2=second)


# Review (peerbox Review; CLI review).

@case("review_accept", "peerbox Review: accept fast-forwards main and the clean worktree; the decision in status", known=None)
def _():
    a, main, feature = need("a", "main", "feature")
    listed = owner_cli("review", pbx()).json
    check(isinstance(listed, list) and {r.get("contribution_id") for r in listed}
          == {feature["contribution_id"], need("feature2")[0]["contribution_id"]},
          f"peerbox review --json does not list exactly the pending contributions: {str(listed)[:300]}")
    result = review(feature["contribution_id"], "accept")
    check(result.ok, f"accept: exit {result.code} {tail(result.stderr)}")
    check(rev(state["repo"], "main") == feature["head"] and (state["repo"] / "feature.txt").read_text()
          == "bob's change, revised\n" and not hook_ran(), "main or its worktree was not fast-forwarded")
    record = mine(feature["contribution_id"])
    decision = record["decision"] or {}
    check(record["state"] == "accepted" and set(decision) == {"decision", "reason", "decided_at", "decided_by",
                                                              "old_head", "new_head"}
          and decision["decision"] == "accepted" and decision["old_head"] == main
          and decision["new_head"] == feature["head"] and decision["decided_by"] == state["alice_pid"],
          f"the accepted record {record}")
    state["main"] = feature["head"]


@case("review_conflicts", "peerbox Review: not_fast_forward, dirty_worktree, head_moved (409, exit 1); main kept", known=None)
def _():
    a, main = need("a", "main")
    result = review(need("feature2")[0]["contribution_id"], "accept")
    check(result.code == 1 and "not_fast_forward" in result.stderr and rev(state["repo"], "main") == main,
          f"a contribution behind main: exit {result.code} {tail(result.stderr)}")
    ahead = contribute("feature4", {"f4.txt": "4\n"}, start=main)
    (state["repo"] / "README").write_text("edited\n")
    result = review(ahead["contribution_id"], "accept")
    git(state["repo"], "checkout", "--", "README")
    check(result.code == 1 and "dirty_worktree" in result.stderr and rev(state["repo"], "main") == main,
          f"a dirty worktree: exit {result.code} {tail(result.stderr)}")
    # main moves between the read and the update: a git wrapper on the daemon's PATH moves it on the first
    # ref-changing command (the owner's own push, as it were), with main not checked out.
    git(state["repo"], "switch", "-q", "--detach")
    wrapper, flag, moved = head_mover(suite.work, state["repo"], main)
    a.extra_env = {"PATH": f"{wrapper}:{os.environ.get('PATH', '/usr/bin:/bin')}"}
    a.restart()
    try:
        flag.write_text("1")
        result = review(ahead["contribution_id"], "accept")
        check(result.code == 1 and "head_moved" in result.stderr and rev(state["repo"], "main") == moved
              and mine(ahead["contribution_id"])["state"] == "pending",
              f"main moved during accept: exit {result.code} {tail(result.stderr)}")
    finally:
        flag.unlink(missing_ok=True)
        a.extra_env = {}
        a.restart()
        git(state["repo"], "update-ref", "refs/heads/main", main)
        git(state["repo"], "switch", "-q", "main")
    state["feature4"] = ahead


@case("review_reject_and_withdraw", "peerbox Review (reject with a reason, no ref changed); Status and withdraw "
                                    "(409 decided; withdraw supersedes and deletes the member ref)", known=None)
def _():
    a, main, second, ahead = need("a", "main", "feature2", "feature4")
    before = refs(state["repo"])
    result = review(second["contribution_id"], "reject", "--reason", "please rebase onto main")
    check(result.ok and refs(state["repo"]) == before, f"reject: exit {result.code} {tail(result.stderr)}")
    record = mine(second["contribution_id"])
    decision = record["decision"] or {}
    check(record["state"] == "rejected" and decision.get("decision") == "rejected"
          and decision.get("reason") == "please rebase onto main" and decision["old_head"] == decision["new_head"]
          == main, f"the rejected record {record}")
    again = review(second["contribution_id"], "accept")
    check(again.code == 1, f"accepting a rejected contribution: exit {again.code}")
    op_fails("decided", {"op": "withdraw", "peerbox_id": pbx(), "contribution_id": second["contribution_id"]})
    value, _, _ = op_ok({"op": "withdraw", "peerbox_id": pbx(), "contribution_id": ahead["contribution_id"]})
    check(check_record(value)["state"] == "superseded" and member_ref(state["bob_pid"], "feature4") is None
          and rev(state["repo"], f"refs/peerbox/{pbx()}/contributions/{ahead['contribution_id']}") == ahead["head"],
          f"withdraw: {value}")


@case("status_paging", "peerbox Status: newest first by (submitted_at, contribution_id), whole records within "
                       "65,536 bytes, at most 100, before and next with equal submitted_at (test clock); CLI status", known=None)
def _():
    a, b, main = need("a", "b", "main")
    share(pbx(), state["bob_p"], actions=("read", "submit"), extra=("--max-pending", "20", "--max-bundle-bytes",
                                                                    "65536"))
    datas = paging_bundles(need("bob_clone")[0], need("bob_wt")[0], suite.work, main)
    frozen, stop = clock.now().replace(microsecond=0), threading.Event()

    def freeze():  # hold the hosts' now within one second while the submissions are stored
        while not stop.is_set():
            clock.set(int((frozen - clock.now()).total_seconds()) + clock.offset)
            time.sleep(0.1)
    offset = clock.offset
    holder = threading.Thread(target=freeze, daemon=True)
    holder.start()
    try:
        with ThreadPoolExecutor(4) as pool:
            tasks = list(pool.map(lambda nd: submit_bundle(pbx(), nd[1], main, nd[0]), datas))
        results = [outcome(t) for t in tasks]
    finally:
        stop.set()
        holder.join()
        clock.set(max(clock.offset, offset))
    check(all(k == "succeeded" for k, _, _ in results), f"submissions {[(k, v) for k, v, _ in results if k != 'succeeded']}")
    for _, value, _ in results:
        check(review(value["contribution_id"], "reject", "--reason", "r" * 4096).ok, "reject with a 4,096-byte reason")
    records, pages = status_all(pbx())
    ids = [r["contribution_id"] for r in records]
    order = [(r["submitted_at"], r["contribution_id"]) for r in records]
    check(len(pages) > 1 and len(ids) == len(set(ids)) and order == sorted(order, reverse=True),
          f"{len(pages)} pages; repeats {len(ids) - len(set(ids))}; ordered {order == sorted(order, reverse=True)}")
    check({v["contribution_id"] for _, v, _ in results} <= set(ids) and all(
        r["contributor"]["person_id"] == state["bob_pid"] for r in records), "status misses or adds records")
    stamps = [r["submitted_at"] for r in records]
    check(len(stamps) > len(set(stamps)), "fixture: no two contributions share a submitted_at")
    every = b.cli("--json", "peerbox", "status", "--peer", a.id, pbx(), timeout=90)
    check(every.ok and isinstance(every.json, dict) and [r["contribution_id"] for r in
                                                       every.json.get("contributions") or []] == ids,
          f"CLI status --json, one merged contributions array: exit {every.code}")
    five = b.cli("--json", "peerbox", "status", "--peer", a.id, pbx(), "--limit", "5", "--before", ids[2], timeout=90)
    check(five.ok and isinstance(five.json, dict)
          and [r["contribution_id"] for r in five.json.get("contributions") or []] == ids[3:8],
          f"CLI status --limit 5 --before: exit {five.code}")
    state["bob_records"] = len(ids)


# Several rules on one peerbox (peerbox Peerbox rules; CLI share).

@case("several_rules", "peerbox Peerbox rules: two people with different actions and bounds, share for one leaves "
                       "the other unchanged, person and network rules give the union and the largest bound", known=None)
def _():
    a, c, main = need("a", "c", "main")
    bob_before = rules_for(pbx(), state["bob_p"])
    share(pbx(), state["carol_p"], actions=("read", "submit"), extra=("--max-pending", "1", "--max-bundle-bytes",
                                                                      "2000"))
    carol = rules_for(pbx(), state["carol_p"])
    check(rules_for(pbx(), state["bob_p"]) == bob_before and len(carol) == 1
          and carol[0]["actions"] == ["peerbox.read", "peerbox.submit"] and carol[0]["max_bundle_bytes"] == 2000,
          f"bob's rule {bob_before} -> {rules_for(pbx(), state['bob_p'])}; carol's {carol}")
    share(pbx(), "network", extra=("--max-bundle-bytes", str(DEFAULT_BUNDLE)))
    value, _, _ = op_ok({"op": "list"}, sender=c)
    entry = [e for e in value["peerboxes"] if e["peerbox_id"] == pbx()]
    check(entry and entry[0]["actions"] == ["peerbox.read", "peerbox.submit"], f"carol's actions {entry}")
    op_ok({"op": "fetch", "peerbox_id": pbx()}, sender=c)  # the network rule's larger read bound
    # Status: another person's contribution, or an unknown one, ends the task failed with unknown (no HTTP 404).
    for other in (need("feature2")[0]["contribution_id"], "pbc_" + os.urandom(16).hex()):
        op_fails("unknown", {"op": "status", "peerbox_id": pbx(), "contribution_id": other}, sender=c)
    clone, wt = suite.work / "carol-clone", suite.work / "carol-wt"
    check(c.cli("--json", "peerbox", "fetch", "--peer", a.id, pbx(), "--repository", clone, timeout=90).ok,
          "carol's CLI fetch")
    worktree(clone, wt, pbx())
    _, data = oversized(clone, wt, suite.work / "carol-big.bundle", "feature", main, 2000, 6000)
    check(len(data) > 2000, f"fixture: carol's big bundle has {len(data)} bytes, not over her bound of 2000")
    entry = upload_bundle(c, data)
    status, body = raw_op({"op": "submit", "peerbox_id": pbx(), "base": main, "branch": "feature",
                           "bundle": entry["sha256"]}, sender=c, artifacts=[entry])
    check(status == 403, f"carol's bundle over her submit bound: {status} {body}")
    bobs = member_ref(state["bob_pid"], "feature")
    git(wt, "reset", "-q", "--hard", main)
    small = new_commit("feature", {"carol.txt": "c\n"}, wt=wt)
    result = c.cli("--json", "peerbox", "submit", "--peer", a.id, pbx(), "--repository", clone, "--branch",
                   "feature", timeout=90)
    check(result.ok and check_record(result.json, pbx())["head"] == small
          and member_ref(state["carol_pid"], "feature") == small
          and member_ref(state["bob_pid"], "feature") == bobs, f"carol's submit: exit {result.code} "
                                                               f"{tail(result.stderr)}")
    unshare(pbx(), "network")


# Invitations (peerbox Invitations for new participants).

@case("invite_code_and_refusals", "peerbox Invitations 1, 2: the psb1- code; a code as an argument refused; a "
                                  "member refused; the pending share kept across a home restart", known=None)
def _():
    a, b = need("a", "b")
    code, inner, invitation = invite_code(pbx(), "dan", "--action", "read", "--action", "submit", "--max-pending",
                                          "2")
    check(set(inner) == {"invite", "peerbox_id", "title", "home_host_id", "actions"}
          and inner["invite"].startswith("psi2-") and inner["peerbox_id"] == pbx() and inner["home_host_id"] == a.id
          and inner["title"] == "Alice's project"
          and inner["actions"] == ["peerbox.read", "peerbox.submit"], f"psb1 body {inner}")
    check(invitation and invitation in pending_shares(), "peerbox invite --list does not show the pending share")
    d = state["d"] = suite.host("dan")
    for argv in (("peerbox", "join", code), ("join", code)):
        result = d.cli(*argv, timeout=60)
        check(not result.ok, f"`{argv[0]} {argv[1]} CODE` was accepted as a command argument")
    check(not d.api("GET", "/v2/link/requests")[1], "a refused code made a join request")
    for argv in (("peerbox", "join", "--invite-stdin"), ("join", "--invite-stdin", "--person-key", state["bob_key"])):
        result = b.cli(*argv, input=code + "\n", timeout=60)
        check(not result.ok and "peerbox share" in result.stdout + result.stderr,
              f"a member's `{' '.join(argv[:2])}` with a peerbox code: exit {result.code} {tail(result.stderr)}")
    a.restart()
    check(invitation in pending_shares(), "the pending share was lost across a restart of the home host")
    state.update(dan_code=code, dan_invitation=invitation)


@case("invite_join", "peerbox Invitations 2 to 5: peerbox join and join accept the code; the rule signed for "
                     "exactly the admitted person; other rules unchanged; the joiner lists and fetches", known=None)
def _():
    a, d, code, net = need("a", "d", "dan_code", "net")
    e = state["e"] = suite.host("erin")
    erin_code, _, erin_invitation = invite_code(pbx(), "erin")
    before = pbx_rules()
    state["erin_key"], state["dan_key"] = ssh_key(e.root, "erin"), ssh_key(d.root, "dan")
    joined = {}

    def dan():
        run = Prompted(d, "--json", "peerbox", "join", "--invite-stdin", "--repository", d.root / "repo", "--as",
                       "dan", "--person-key-file", need("dan_key")[0], first_line=code)
        admit_waiting(a, d)
        joined["dan"] = (run.wait(240), run.text)
    run_side_by_side((dan, (), {}), (join_with_code, (a, e, erin_code, need("erin_key")[0], net), {}))
    check(joined["dan"][0] == 0, f"peerbox join exited {joined['dan'][0]}")
    state["dan_pid"] = person_id(d, need("dan_key")[0])
    state["erin_pid"] = person_id(e, need("erin_key")[0])
    wait_for(lambda: rules_for(pbx(), principal(need("erin_pid")[0])), timeout=60, message="erin's rule")
    dan_rules, erin_rules = rules_for(pbx(), principal(need("dan_pid")[0])), rules_for(pbx(), principal(need("erin_pid")[0]))
    check(len(dan_rules) == 1 and dan_rules[0]["actions"] == ["peerbox.read", "peerbox.submit"]
          and dan_rules[0]["max_pending"] == 2 and dan_rules[0]["max_bundle_bytes"] == DEFAULT_BUNDLE,
          f"dan's rule {dan_rules}")
    check(len(erin_rules) == 1 and erin_rules[0]["actions"] == ["peerbox.read"] and erin_rules[0]["max_pending"] == 0,
          f"erin's rule {erin_rules}")
    strip = {principal(need("dan_pid")[0]), principal(need("erin_pid")[0])}
    after = [dict(r, principals=[p for p in r["principals"] if p not in strip]) for r in pbx_rules()]
    check([r for r in after if r["principals"]] == before, "an invitation changed another principal's rule")
    check(rev(d.root / "repo", f"refs/peerbox/{pbx()}/main") == state["main"], "peerbox join --repository fetched "
                                                                               "nothing")
    value, _, _ = op_ok({"op": "list"}, sender=e)
    check(pbx() in [x["peerbox_id"] for x in value["peerboxes"]], "erin does not list the peerbox")
    op_ok({"op": "fetch", "peerbox_id": pbx()}, sender=e)
    listed = pending_shares()
    check(need("dan_invitation")[0] not in listed and (erin_invitation or "-") not in listed, "a signed share is "
                                                                                           "still pending")


@case("invite_expired_and_cancelled", "peerbox Invitations: a share ending with its invite's expiry (test clock); "
                                      "a cancelled share giving membership and no access")
def _():
    a, net = need("a", "net")
    _, _, late = invite_code(pbx(), "late", "--expires-in", "1h")
    check(late in pending_shares(), "the pending share is not listed")
    clock.set(clock.offset + 2 * HOUR)
    wait_for(lambda: late not in pending_shares(), timeout=30, message="the expired pending share to end")
    f = state["f"] = suite.host("fay")
    state["fay_key"] = ssh_key(f.root, "fay")
    code, _, invitation = invite_code(pbx(), "fay", "--action", "read")
    owner_cli("invite", "--cancel", invitation)
    check(invitation not in pending_shares(), "a cancelled pending share is still listed")
    state["fay_offset"] = clock.offset
    join_with_code(a, f, code, need("fay_key")[0], net, not_after=rfc3339(clock.now() + timedelta(days=4, hours=1)))
    state["fay_pid"] = person_id(f, need("fay_key")[0])
    check(f.public_key in members(a, net), "fay is not a member")
    settle(3)
    check(not rules_for(pbx(), principal(need("fay_pid")[0])), "a cancelled share granted fay a rule")
    status, body = raw_op({"op": "fetch", "peerbox_id": pbx()}, sender=f)
    refused(status, body, 404, "unknown")
    f.stop()  # fay's grants are left to lapse (lapsed_sender)


@case("share_waiting_for_owner", "peerbox Invitations 4: peerbox_share_waiting for an SSH person key, kept across "
                                 "a restart, completed by peerbox share --pending")
def _():
    a, b, net = need("a", "b", "net")
    brepo = init_repo(suite.work / "bob-repo")
    commit_files(brepo, {"tool.sh": "echo tool\n"}, "tool")
    bpbx = create(brepo, host=b, title="Bob's tools")
    code, _, invitation = invite_code(bpbx, "gus", host=b)
    g = suite.host("gus")
    key = ssh_key(g.root, "gus")
    join_with_code(a, g, code, key, net)
    gus = principal(person_id(g, key))

    def waiting():
        kinds, body = attention(b)
        return [i for i in body.get("attention") or [] if i.get("kind") == "peerbox_share_waiting"
                and f"peerbox share --pending {invitation}" in str(i.get("command"))]
    wait_for(waiting, timeout=60, message="peerbox_share_waiting on bob's host")
    b.restart()
    check(waiting() and invitation in pending_shares(host=b), "the waiting share was lost across a restart")
    owner_cli("share", "--pending", invitation, "--person-key", state["bob_key"], host=b)
    found = rules_for(bpbx, gus, host=b, person_public=state["bob_public"])
    check(len(found) == 1 and found[0]["actions"] == ["peerbox.read"] and not waiting()
          and invitation not in pending_shares(host=b), f"gus's rule {found}")
    learn(g, state["bob_public"], policy_version(b, state["bob_public"]))
    value, _, _ = op_ok({"op": "list"}, sender=g, receiver=b)
    check([x["peerbox_id"] for x in value["peerboxes"]] == [bpbx], f"gus's list {value}")


# Restarts and withdrawal.

@case("restarts_during_fetch_and_submit", "peerbox Requests (task durability); restarts of both hosts keep records", known=None)
def _():
    a, b, main = need("a", "b", "main")
    task_id = submit_op({"op": "fetch", "peerbox_id": pbx()})
    a.restart(kill=True)
    b.restart(kill=True)
    kind, value, last = outcome(task_id, timeout=90)
    check(kind == "succeeded" and sha256(fetch_bytes(task_id, last)) == value["bundle_sha256"], f"fetch: {kind}")
    tip = new_commit("restart", {"r.txt": "r\n"}, start=main)
    task_id = send("restart", tip)
    b.restart(kill=True)
    a.restart(kill=True)
    kind, value, _ = outcome(task_id, timeout=90)
    records, _ = status_all(pbx())
    check(kind == "succeeded" and [r["head"] for r in records].count(tip) == 1, f"submit across restarts: {kind}")
    status, listed = a.api("GET", f"/v1/peerboxes/{pbx()}/contributions")
    check(status == 200 and value["contribution_id"] in str(listed) and pbx() in [r["peerbox_id"] for r in shown()],
          f"records after restarts: {status}")


@case("withdrawal", "peerbox Withdrawal and Checks 1: fetch and submit refused, status kept for the former "
                    "contributor's own records, 404 unknown for a former reader who never submitted", known=None)
def _():
    b, d, main = need("b", "d", "main")
    unshare(pbx(), state["bob_p"])
    status, body = raw_op({"op": "fetch", "peerbox_id": pbx()})
    refused(status, body, 404, "unknown")
    entry = upload_bundle(b, b"# v2 git bundle\n\n\n")
    status, body = raw_op({"op": "submit", "peerbox_id": pbx(), "base": main, "branch": "late",
                           "bundle": entry["sha256"]}, artifacts=[entry])
    refused(status, body, 404, "unknown")
    records, _ = status_all(pbx())
    check(records and all(r["contributor"]["person_id"] == state["bob_pid"] for r in records)
          and len(records) >= state.get("bob_records", 1), f"bob's status after withdrawal: {len(records)} records")
    unshare(pbx(), principal(need("dan_pid")[0]))
    learn(d, state["alice_public"], policy_version(state["a"], state["alice_public"]))
    status, body = raw_op({"op": "status", "peerbox_id": pbx()}, sender=d)
    refused(status, body, 404, "unknown")


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
    check(current == MAIN_SCHEMA + 1, f"schema version {current}; this contract adds {MAIN_SCHEMA + 1} (update "
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


# Test-clock cases last: they move every host days ahead.

@case("lapsed_sender", "peerbox Checks 1: a sender whose grants lapsed (test clock), refused without "
                       "allow_disconnected and accepted with it")
def _():
    a, f = need("a", "f")
    clock.set(need("fay_offset")[0] + 4 * DAY + 2 * HOUR)
    fay = principal(need("fay_pid")[0])

    def sign(allow):
        status, response = sign_policy(lambda body: with_peerbox_rules(body, [
            r for r in pbx_rules() if fay not in r["principals"]] + [rule(pbx(), [fay], allow_disconnected=allow)]))
        check(status == 200 and response.get("committed"), f"the rule for fay: {status} {response}")
    sign(False)
    f.start()
    status, body = raw_op({"op": "fetch", "peerbox_id": pbx()}, sender=f)
    refused(status, body, 404, "unknown")
    sign(True)
    status, body = raw_op({"op": "fetch", "peerbox_id": pbx()}, sender=f)
    check(status == 200 and body.get("state") == "queued", f"a lapsed sender with allow_disconnected: {status} {body}")


@case("renewal_keeps_peerbox_rules", "peerbox Policy body (Renewal and edits): automatic renewal copies "
                                     "peerbox_rules; test clock", known=None)
def _():
    a, = need("a")
    version, before = policy_version(a, state["alice_public"]), pbx_rules()
    check(before, "no peerbox rules to renew")
    clock.set(clock.offset + 16 * HOUR + 10 * 60)
    wait_for(lambda: policy_version(a, state["alice_public"]) > version, timeout=75, interval=1,
             message="alice's host to renew its policy automatically")
    check(pbx_rules() == before, "peerbox_rules changed across the renewal")


suite.finish()
