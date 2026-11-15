#!/usr/bin/env python3
"""Slim suite, peerbox_contributions: stored contributions, review, status, restarts and withdrawal (peerbox Submit,
Status and withdraw, Review, Withdrawal).

alice creates a coordinator-free network and bob and carol join as other people, all on the suite's debug test clock.
alice's peerbox serves a Git fixture repository whose `main` is the protected branch, with a side branch `secret` the
protected branch never reaches and a reference-transaction hook that marks any ref change made with hooks enabled;
bob, who reads and submits (2 pending, 65,536 bytes), contributes from a clone his CLI fetched, and carol only
reads. Each case builds on the contributions of the cases before it: submitted, superseded, accepted, rejected,
withdrawn, cancelled and paged, then the hosts restarted and bob's and carol's access withdrawn. Peerboxes, requests,
fetch and refused submissions are peerbox.py; the shared fixtures are peerbox_common.py and peerbox_fixtures.py.

Written from docs/peerbox-contract.md only (cited as "peerbox <section>"), with the runtime task, task, artifact and
coordinator-free contracts it extends. No VM, no KVM, no model calls.
"""
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from harness import Suite, check, peer
from runtime_common import bind, learn, need, new_task_id, policy_version, refused, state
from peerbox_fixtures import commit_on, head_mover, owner_repo, paging_bundles, worktree
from peerbox_common import (REASON, bundle, check_record, create, failed_with, fetch_bytes, git, op_fails, op_ok,
                            outcome, owner_cli, peerbox_network, raw_op, refs, rev, settle, sha256, share, shown,
                            status_all, submit_bundle, submit_op, tail, unshare, upload_bundle)

suite = Suite("peerbox_contributions", __doc__)
bind(suite)
clock = suite.use_clock()


def case(name, spec, known=REASON):
    return suite.case(name, spec, known=known)

def pbx():
    return need("pbx")[0]

def hook_ran():
    return (state["repo"] / "HOOK_RAN").exists()

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

@suite.case("setup", "decentralized-spec 6, 8 (create, join); a Git fixture repository; peerbox CLI create, share "
                     "and fetch (bob's clone, as peerbox.py's fetch_bundle makes it)")
def _():
    peerbox_network(suite, ("bob", "carol"))
    a, b = state["a"], state["b"]
    owner = owner_repo(suite.work / "alice-repo")
    state.update(repo=owner["repo"], main=owner["main"], main_parent=owner["main_parent"], secret=owner["secret"])
    state["pbx"] = create(state["repo"], title="Alice's project")
    share(pbx(), state["bob_p"], actions=("read", "submit"), extra=("--max-pending", "2", "--max-bundle-bytes",
                                                                    "65536"))
    share(pbx(), state["carol_p"], extra=("--max-bundle-bytes", "400"))
    clone = suite.work / "bob-clone"
    fetched = b.cli("--json", "peerbox", "fetch", "--peer", a.id, pbx(), "--repository", clone, timeout=90)
    check(fetched.ok and rev(clone, f"refs/peerbox/{pbx()}/main") == state["main"],
          f"bob's peerbox fetch: exit {fetched.code} {tail(fetched.stderr)}")
    state["bob_wt"] = worktree(clone, suite.work / "bob-wt", pbx())
    state["bob_clone"] = clone


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


@case("review_conflicts", "peerbox Review: not_fast_forward, dirty_worktree, head_moved (409, exit 1); main kept; "
                          "Submit step 1 (pending_limit beside a decided contribution)", known=None)
def _():
    a, main = need("a", "main")
    result = review(need("feature2")[0]["contribution_id"], "accept")
    check(result.code == 1 and "not_fast_forward" in result.stderr and rev(state["repo"], "main") == main,
          f"a contribution behind main: exit {result.code} {tail(result.stderr)}")
    ahead = contribute("feature4", {"f4.txt": "4\n"}, start=main)
    # Submit step 1: at the limit (feature2 and feature4 pending, max_pending 2), a submission on `feature`, whose
    # member ref holds the accepted contribution, is refused: a decided contribution is never the one replaced.
    held = member_ref(state["bob_pid"], "feature")
    failed_with("pending_limit", send("feature", new_commit("feature", {"f5.txt": "5\n"}, start=main)))
    check(held == need("feature")[0]["head"] and member_ref(state["bob_pid"], "feature") == held,
          "a submission refused with pending_limit moved the member ref holding a decided contribution")
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


@case("review_not_pending", "peerbox Review: accepting or rejecting a contribution withdrawn, superseded by a "
                            "replacement or already decided is 409 not_pending (exit 1) and changes nothing; an "
                            "owner's decision has exactly six keys", known=None)
def _():
    main = need("main")[0]
    targets = {"withdrawn": need("feature4")[0], "replaced": need("first")[0], "rejected": need("feature2")[0],
               "accepted": need("feature")[0]}
    before, (records, _) = (refs(state["repo"]), git(state["repo"], "status", "--porcelain")), status_all(pbx())
    by_id = {r["contribution_id"]: r for r in records}
    states = {label: by_id[t["contribution_id"]]["state"] for label, t in targets.items()}
    check(states == {"withdrawn": "superseded", "replaced": "superseded", "rejected": "rejected",
                     "accepted": "accepted"}, f"fixture: states {states}")
    check(set(by_id[targets["rejected"]["contribution_id"]]["decision"]) == {"decision", "reason", "decided_at",
                                                                              "decided_by", "old_head", "new_head"},
          "an owner's rejection does not have exactly the six decision keys")
    wrong = []
    for label, target in targets.items():
        for verdict, extra in (("accept", ()), ("reject", ("--reason", "too late"))):
            result = review(target["contribution_id"], verdict, *extra)
            if not (result.code == 1 and "not_pending" in result.stderr):
                wrong.append(f"{verdict} {label}: exit {result.code} {tail(result.stderr)}")
    check(not wrong, f"want exit 1 with not_pending: {wrong}")
    check((refs(state["repo"]), git(state["repo"], "status", "--porcelain")) == before
          and rev(state["repo"], "main") == main, "a not_pending review changed a ref or the worktree")
    after = {r["contribution_id"]: r for r in status_all(pbx())[0]}
    check(after == by_id, "a not_pending review changed a contribution record")


@case("submit_cancelled", "peerbox Submit (a cancel while the task is queued, its bundle not yet fetched: the task "
                          "ends cancelled, no contribution ref, the member ref unchanged, no record)", known=None)
def _():
    b, main = need("b", "main")
    held = member_ref(state["bob_pid"], "feature2")
    check(held == need("feature2")[0]["head"], f"fixture: bob's feature2 member ref is {held}")
    before, records = refs(state["repo"]), len(status_all(pbx())[0])
    tip = new_commit("feature2", {"cancelled.txt": "c\n"}, start=main)
    data = bundle(need("bob_clone")[0], suite.work / "cancelled.bundle", tip, exclude=[main], ref="feature2")
    entry = upload_bundle(b, data)
    # Sent with bob's host key but not through his daemon, which therefore serves the home host no such input: the
    # task stays queued with its bundle pending (artifact contract, Transfer) until the cancel.
    task_id = new_task_id()
    status, body = raw_op({"op": "submit", "peerbox_id": pbx(), "base": main, "branch": "feature2",
                           "bundle": entry["sha256"]}, artifacts=[entry], task_id=task_id)
    check(status == 200 and body.get("state") == "queued", f"the submission: {status} {body}")
    settle(1)
    status, body = peer(b, state["a"], "POST", f"/peer/v1/tasks/{task_id}/cancel", {})
    check(status == 200 and body.get("cancel_requested") is True, f"the cancel: {status} {body}")
    kind, value, _ = outcome(task_id)
    check(kind == "cancelled", f"a submit cancelled while queued ended {kind} {value}")
    records_after = status_all(pbx())[0]
    check(refs(state["repo"]) == before and member_ref(state["bob_pid"], "feature2") == held
          and len(records_after) == records and tip not in [r["head"] for r in records_after],
          "a cancelled submit stored a ref or a record")


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
                                                       every.json.get("contributions") or []] == ids
          and "next" in every.json and every.json["next"] is None,
          f"CLI status --json, one merged contributions array and next null: exit {every.code} "
          f"next {(every.json or {}).get('next', 'missing') if isinstance(every.json, dict) else None}")

    def cli_status(*args):
        result = b.cli("--json", "peerbox", "status", "--peer", a.id, pbx(), *args, timeout=90)
        got = result.json if result.ok and isinstance(result.json, dict) else {}
        return [r["contribution_id"] for r in got.get("contributions") or []], got.get("next", "missing")
    # --limit cutting the records prints the last printed ID as next, and --before with it continues; with every
    # remaining record printed (exactly the limit) next is null.
    printed = cli_status("--limit", "5", "--before", ids[2])
    check(printed == (ids[3:8], ids[7]), f"CLI status --limit 5 --before: {printed}, want {ids[3:8]}, next {ids[7]}")
    printed = cli_status("--limit", "3", "--before", ids[7])
    check(printed == (ids[8:11], ids[10]), f"CLI status --limit 3 --before next: {printed}")
    printed = cli_status("--limit", "3", "--before", ids[-4])
    check(printed == (ids[-3:], None), f"CLI status --limit 3 printing the last 3 records: {printed}, next null")
    state["bob_records"] = len(ids)


# Restarts and withdrawal.

def check_recovered_refs(planted):
    """peerbox Submit (Startup recovery): no contribution ref without a record, and each member ref at the head of the
    latest recorded submission of that person on that branch, absent when that one was withdrawn or there is none.
    Records come from each contributor's `status`; with submitted_at tied, any of the tied latest is allowed (the
    storage order is never shown). PLANTED maps member refs to the exact state they must have."""
    prefix = f"refs/peerbox/{pbx()}/"
    records = status_all(pbx())[0] + status_all(pbx(), sender=state["c"])[0]
    latest = {}
    for r in records:
        key = (r["contributor"]["person_id"], r["branch"])
        latest.setdefault(key, []).append(r)
    expected = {}
    for (person, branch), group in latest.items():
        top = max((r["submitted_at"], r["contribution_id"]) for r in group)[0]
        expected[f"{prefix}members/{person}/{branch}"] = {None if r["state"] == "superseded" else r["head"]
                                                          for r in group if r["submitted_at"] == top}
    present = refs(state["repo"])
    ids = {r["contribution_id"] for r in records}
    orphans = [n for n in present if n.startswith(prefix + "contributions/") and n.rsplit("/", 1)[1] not in ids]
    wrong = [f"{n}: {present.get(n)} not in {want}" for n, want in expected.items() if present.get(n) not in want]
    wrong += [f"{n}: {present[n]}, no record" for n in present if n.startswith(prefix + "members/") and n not in expected]
    wrong += [f"{n}: {present.get(n)}, want {want}" for n, want in planted.items() if present.get(n) != want]
    check(not orphans and not wrong, f"after a restart: contribution refs without a record {orphans}; member refs "
                                     f"{wrong}")


@case("restarts_during_fetch_and_submit", "peerbox Requests (task durability); restarts of both hosts keep records; "
                                          "Submit (Startup recovery: unrecorded contribution refs deleted, member "
                                          "refs set to the latest recorded submission, an interrupted resubmission "
                                          "of an older head included)", known=None)
def _():
    a, b, main = need("a", "b", "main")
    # What a submission interrupted between its refs and its record leaves, written into the owner's repository:
    # a contribution ref with no record; bob's `feature` member ref back at his first, replaced head (A, B, A with
    # no record for the second A); his withdrawn `feature4` and an unrecorded branch given member refs again.
    bob_refs = f"refs/peerbox/{pbx()}/members/{state['bob_pid']}/"
    stray = f"refs/peerbox/{pbx()}/contributions/pbc_" + os.urandom(16).hex()
    planted = {stray: None, bob_refs + "feature": need("feature")[0]["head"], bob_refs + "feature4": None,
               bob_refs + "ghost": None}
    check(member_ref(state["bob_pid"], "feature") == need("feature")[0]["head"]
          and member_ref(state["bob_pid"], "feature4") is None, "fixture: bob's feature or feature4 member ref")
    for name, target in ((stray, main), (bob_refs + "feature", need("first")[0]["head"]),
                         (bob_refs + "feature4", need("feature4")[0]["head"]), (bob_refs + "ghost", main)):
        git(state["repo"], "update-ref", name, target)
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
    check_recovered_refs(planted)


@case("withdrawal", "peerbox Withdrawal and Checks 1: fetch and submit refused, status kept for the former "
                    "contributor's own records, 404 unknown for a former reader who never submitted", known=None)
def _():
    b, c, main = need("b", "c", "main")  # carol, a reader, never submits in this suite
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
    unshare(pbx(), state["carol_p"])
    learn(c, state["alice_public"], policy_version(state["a"], state["alice_public"]))
    status, body = raw_op({"op": "status", "peerbox_id": pbx()}, sender=c)
    refused(status, body, 404, "unknown")


suite.finish()
