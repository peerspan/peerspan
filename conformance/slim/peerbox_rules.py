#!/usr/bin/env python3
"""Slim suite, peerbox_rules: the policy body, list and several rules on one peerbox (peerbox Peerbox rules, Policy
body, Results).

alice creates a coordinator-free network, links a second machine (alice2), and bob and carol join as other people,
all on the suite's debug test clock. alice's peerboxes serve a Git fixture repository whose `main` is the protected
branch: one shared with bob (read and submit) and carol (read within 400 bytes), one hidden, and for list paging 200
more shared with bob and removed again. The rules are written with `peerbox share` and signed directly through the
policy actions route, then read back on alice's other host and on bob's; the last case moves the clock 16 hours for
an automatic renewal. Peerboxes, requests and fetch are peerbox.py; the shared fixtures are peerbox_common.py and
peerbox_fixtures.py.

Written from docs/peerbox-contract.md only (cited as "peerbox <section>"), with the runtime task, task, artifact and
coordinator-free contracts it extends. No VM, no KVM, no model calls.
"""
import os
from concurrent.futures import ThreadPoolExecutor

from harness import Suite, check, wait_for
from runtime_common import bind, learn, need, policy_statement, policy_version, sign_policy, state
from peerbox_fixtures import commit_on, oversized, owner_repo, suite_clone, worktree
from peerbox_common import (DEFAULT_BUNDLE, OUTPUT_LIMIT, REASON, RULE_KEYS, bundle, check_record, create, git,
                            op_fails, op_ok, outcome, pbx_rules, peerbox_network, raw_op, rev, rule, rules_for, share,
                            shown, submit_bundle, tail, unshare, upload_bundle, with_peerbox_rules)

suite = Suite("peerbox_rules", __doc__)
bind(suite)
clock = suite.use_clock()
HOUR = 3600


def case(name, spec, known=REASON):
    return suite.case(name, spec, known=known)

def pbx():
    return need("pbx")[0]

def new_commit(branch, files, start=None, wt=None):
    """A commit on BRANCH in bob's worktree (reset to START when given); returns its ID."""
    return commit_on(wt or need("bob_wt")[0], branch, files, start)

def member_ref(person, branch):
    return rev(state["repo"], f"refs/peerbox/{pbx()}/members/{person}/{branch}")

@suite.case("setup", "decentralized-spec 6, 8 (create, join, link); a Git fixture repository; peerbox CLI create")
def _():
    peerbox_network(suite, ("bob", "carol"), second_machine=True)
    owner = owner_repo(suite.work / "alice-repo")
    state.update(repo=owner["repo"], main=owner["main"])
    state["pbx"] = create(state["repo"], title="Alice's project")
    state["hidden"] = create(state["repo"], title="hidden")


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


def listed_and_paged(a, b, c, many):
    learn(b, state["alice_public"], policy_version(a, state["alice_public"]))
    readable, seen, after, pages = sorted(many + [pbx()]), [], None, 0
    while True:
        value, last, _ = op_ok({"op": "list", **({"after": after} if after else {})})
        pages += 1
        check(len(last["output"].encode()) <= OUTPUT_LIMIT and set(value) == {"peerboxes", "next"}, f"list {value}")
        for entry in value["peerboxes"]:
            check(set(entry) == {"peerbox_id", "title", "branch", "head", "actions", "gate"}
                  and entry["branch"] == "main" and entry["head"] == state["main"] and entry["gate"] is None,
                  f"list entry {entry}")
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


@case("list_readable_and_paging", "peerbox Results (list entries, ascending, whole entries within 65,536 bytes, "
                                  "after and next); CLI list follows next", known=None)
def _():
    a, b, c = need("a", "b", "c")
    with ThreadPoolExecutor(8) as pool:
        many = list(pool.map(lambda i: create(state["repo"], title=f"{i:03d}" + "p" * 197), range(200)))
    status, response = sign_policy(lambda body: with_peerbox_rules(
        body, pbx_rules() + [rule(x, [state["bob_p"]]) for x in many]))
    check(status == 200 and response.get("committed"), f"200 more rules for bob: {status} {response}")
    try:
        listed_and_paged(a, b, c, many)
    finally:
        # Leave the network as it was: 200 more rules in alice's policy slow every later projection on every host.
        status, response = sign_policy(lambda body: with_peerbox_rules(
            body, [r for r in pbx_rules() if r["peerbox"] not in set(many)]))
        check(status == 200 and response.get("committed"), f"removing the 200 rules: {status} {response}")
        for host in state["learners"]:
            learn(host, state["alice_public"], policy_version(a, state["alice_public"]))
        with ThreadPoolExecutor(8) as pool:
            gone = list(pool.map(lambda x: a.api("DELETE", f"/v1/peerboxes/{x}")[0], many))
        check(all(g in (200, 204) for g in gone) and not set(many) & {r["peerbox_id"] for r in shown()}
              and not [r for r in pbx_rules() if r["peerbox"] in set(many)], f"deleting the 200 peerboxes: {set(gone)}")


@suite.case("bob_contribution", "peerbox Submit: bob's pending contribution on `feature`, for the next case")
def _():
    main = need("main")[0]
    clone = suite_clone(state["repo"], suite.work / "bob-clone")
    tip = commit_on(clone, "feature", {"feature.txt": "bob's change\n"}, start=main)
    data = bundle(clone, suite.work / "bob-feature.bundle", tip, exclude=[main], ref="feature")
    kind, value, _ = outcome(submit_bundle(pbx(), data, main, "feature"))
    check(kind == "succeeded", f"bob's submit: {kind} {value}")
    state["bob_contribution"] = check_record(value, pbx())
    check(member_ref(state["bob_pid"], "feature") == tip, "bob's feature member ref")


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
    for other in (need("bob_contribution")[0]["contribution_id"], "pbc_" + os.urandom(16).hex()):
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


# Test clock last: the renewal moves every host 16 hours ahead.

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
