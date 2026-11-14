#!/usr/bin/env python3
"""Slim suite, peerbox_runs: runs on a peerbox's exact commits (peerbox Runs, Withdrawal; PBX-4).

alice creates a coordinator-free network and bob joins as another person, both on the suite's debug test clock;
alice's host serves runtime tasks through conformance/slim/fake_runtime.py (RUN-4), as in the runtime suites, and a
peerbox on a Git fixture repository whose `main` holds an executable, a symbolic link, a submodule entry and a
`.gitattributes` with `export-ignore`, `export-subst` and an end-of-line rule. The fake runtime logs each start
request and unpacks the workspace archive into a run directory it keeps, so the suite compares the workspace with
the commit's tree directly, and its `cat` step reads files from inside the run. The rest of the peerbox contract is
peerbox.py; the shared fixtures are peerbox_common.py and runtime_common.py.

Written from docs/peerbox-contract.md only (cited as "peerbox <section>"), with the runtime task contract it extends.
No VM, no KVM, no model calls. Nothing in the contract is implemented yet: every case past the network setup is a
strict expected failure.
"""
import json
import os
import stat
from datetime import timedelta
from pathlib import Path

from harness import Suite, check, rfc3339, wait_for
from runtime_common import (bind, cancel, enable, has_kind, need, new_task_id, occupy, policy_statement,
                            receiver_events, refused, result_of, run_id, setup_network, state, stream)
from peerbox_fixtures import commit_on, expected_workspace, run_workspaces, runs_repo, self_check, worktree
from peerbox_common import (REASON, bundle, check_record, create, git, op_ok, outcome, raw_op, refs, rev, settle,
                            share, submit_bundle, submit_op)

suite = Suite("peerbox_runs", __doc__)
bind(suite)
clock = suite.use_clock()
DAY, HOUR = 86400, 3600


def case(name, spec, known=REASON):
    return suite.case(name, spec, known=known)


def pbx():
    return need("pbx")[0]


def run_task(commit, argv, sender=None, **run):
    """A peerbox `run` through bob's POST /v1/tasks; returns the task ID."""
    return submit_op({"op": "run", "peerbox_id": pbx(), "commit": commit, "run": {"argv": argv, **run}}, sender)


def run_ok(commit, argv, **run):
    task_id = run_task(commit, argv, **run)
    events = receiver_events(task_id, timeout=60)
    check(events[-1]["kind"] == "succeeded", f"run {argv}: {[(e['kind'], e.get('message')) for e in events]}")
    return task_id, events


def raw_run(commit, argv=("echo", "raw"), **run):
    return raw_op({"op": "run", "peerbox_id": pbx(), "commit": commit, "run": {"argv": list(argv), **run}})


def refused_before_run(code, task_id):
    """peerbox Results, Runs: the run ends queued to failed with exactly {"error": CODE, "message"}, no run result,
    and the runtime never asked to start it."""
    events = receiver_events(task_id, timeout=60)
    kinds = [e["kind"] for e in events]
    last = events[-1]
    try:
        value = json.loads(last.get("output") or "null")
    except ValueError:
        value = last.get("output")
    check(kinds == ["queued", "failed"] and isinstance(value, dict) and set(value) == {"error", "message"}
          and value["error"] == code and isinstance(value["message"], str),
          f"events {kinds}, final output {value}, want queued then failed with only {{error: {code}, message}}")
    check(not state["rt"].entries("post", run_id(state["b"], task_id)), "the runtime was asked to start the run")


def commit_unknown(commit):
    refused_before_run("commit_unknown", run_task(commit, ["echo", "never"]))


def bob_share(*actions):
    return share(pbx(), state["bob_principal"], actions=actions, hosts=[state["b"]])


def contribute(branch, files):
    """bob's commit on BRANCH from main, submitted; returns the contribution record."""
    wt = need("bob_wt")[0]
    tip = commit_on(wt, branch, files, start=state["main"])
    data = bundle(need("bob_clone")[0], suite.work / f"{branch}-{tip[:8]}.bundle", tip, exclude=[state["main"]],
                  ref=branch)
    kind, value, _ = outcome(submit_bundle(pbx(), data, state["main"], branch))
    check(kind == "succeeded", f"submit {branch}: {kind} {value}")
    return check_record(value, pbx())


def workspace(task_id):
    """The directory the fake runtime unpacked the run's archive into (kept until the daemon deletes the run)."""
    found = run_workspaces(state["rt"].dir, run_id(state["b"], task_id))
    check(len(found) == 1, f"the fake runtime holds {len(found)} workspaces for {task_id}")
    return found[0]


def listing(root):
    """{path: (kind, mode, content or link target)} of every entry under ROOT."""
    out = {}
    for path in sorted(Path(root).rglob("*")):
        rel = path.relative_to(root).as_posix()
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            out[rel] = ("link", None, os.readlink(path).encode())
        elif stat.S_ISDIR(info.st_mode):
            out[rel] = ("dir", None, sorted(p.name for p in path.iterdir()))
        else:
            out[rel] = ("file", stat.S_IMODE(info.st_mode), path.read_bytes())
    return out


@suite.case("fixtures", "peerbox_fixtures.py: every Git fixture of the peerbox suites, built host-free and checked")
def _():
    print(f"  fixtures built and checked in {self_check(suite.work / 'fixture-check'):.1f}s", flush=True)


@suite.case("setup", "decentralized-spec 6, 8 (create, join); a Git fixture repository")
def _():
    setup_network()
    made = runs_repo(suite.work / "alice-repo")
    state.update(repo=made["repo"], main=made["main"], secret=made["secret"])
    state["learners"] = [state["b"]]


@suite.case("peerbox_setup", "peerbox CLI: create, share (read, submit), fetch; Submit")
def _():
    a, b = need("a", "b")
    state["pbx"] = create(state["repo"], title="runs")
    bob_share("read", "submit")
    clone, wt = suite.work / "bob-clone", suite.work / "bob-wt"
    result = b.cli("--json", "peerbox", "fetch", "--peer", a.id, pbx(), "--repository", clone, timeout=90)
    check(result.ok and rev(clone, f"refs/peerbox/{pbx()}/main") == state["main"] and isinstance(result.json, dict)
          and result.json.get("head") == state["main"],
          f"peerbox fetch: exit {result.code} {result.stderr.strip()[-300:]}")
    worktree(clone, wt, pbx(), branch="work")
    state.update(bob_clone=clone, bob_wt=wt)
    state["work"] = contribute("work", {"change.txt": "bob\n"})
    state["work_runs"] = 0


@case("run_needs_both_rules_and_switch", "peerbox Checks 2 and 4: peerbox.run, a runtime rule matching the sender "
                                         "and the local switch, each required", known=None)
def _():
    a, rt, main = need("a", "rt", "main")
    status, body = raw_run(main)
    check(status == 403, f"without peerbox.run: {status} {body}")
    bob_share("read", "submit", "run")
    status, body = raw_run(main)
    refused(status, body, 403, "runtime_disabled")
    status, body = a.api("PUT", "/v1/runtime", {"socket": str(rt.socket)})
    check(status == 200, f"PUT /v1/runtime: {status} {body}")
    status, body = raw_run(main)
    check(status == 403 and body.get("code") != "runtime_disabled", f"peerbox.run without a runtime rule: {status} "
                                                                    f"{body}")
    enable("--for", state["alice_principal"])
    status, body = raw_run(main)
    check(status == 403, f"a runtime rule that does not match bob: {status} {body}")
    enable("--for", state["alice_principal"], "--for", state["bob_principal"])
    keys = list(policy_statement(a, state["alice_public"])[3])
    check("runtime_rules" in keys and keys.index("peerbox_rules") == keys.index("runtime_rules") + 1,
          f"peerbox_rules is not immediately after runtime_rules: {keys}")
    run_ok(main, ["echo", "both"])
    bob_share("read", "submit")
    status, body = raw_run(main)
    check(status == 403, f"a runtime rule without peerbox.run: {status} {body}")
    bob_share("read", "submit", "run")
    a.api("DELETE", "/v1/runtime")
    try:
        status, body = raw_run(main)
        refused(status, body, 403, "runtime_disabled")
    finally:
        a.api("PUT", "/v1/runtime", {"socket": str(rt.socket)})
    state["ready"] = True


@case("bounds_from_runtime_rule", "peerbox Checks 4 and Runs: the runtime rule's bounds, its maximums as defaults, "
                                  "max_artifact_bytes over the archive", known=None)
def _():
    b, rt, main = need("b", "rt", "main")
    need("ready")
    status, body = raw_run(main, resources={"cpus": 3})
    check(status == 403, f"cpus 3 over the rule's 2: {status} {body}")
    task_id, _ = run_ok(main, ["echo", "bounds"])
    posts = rt.entries("post", run_id(b, task_id))
    check(posts and posts[0]["request"]["resources"] == {"cpus": 2, "memory_mib": 2048, "timeout_seconds": 3600}
          and posts[0]["request"]["workspace_archive"] and posts[0]["request"]["peerfs_workspace"] is None,
          f"the start request {posts[:1]}")
    enable("--for", state["alice_principal"], "--for", state["bob_principal"], "--max-artifact-bytes", "100")
    try:
        refused_before_run("too_large", run_task(main, ["echo", "never"]))  # the archive is far over 100 bytes
    finally:
        enable("--for", state["alice_principal"], "--for", state["bob_principal"])


@case("workspace_is_the_tree", "peerbox Runs: the archive is the commit's tree byte for byte, modes, links, "
                               "submodules as empty directories, no .git, no attribute applied", known=None)
def _():
    main = need("main")[0]
    need("ready")
    task_id = run_task(main, ["cat", "ignored.txt", ";", "cat", "subst.txt", ";", "cat", "lines.txt", ";", "cat",
                              "sub/dir/deep.txt", ";", "sleep", "5"])
    receiver_events(task_id, until=has_kind("accepted"), timeout=30)
    got = listing(workspace(task_id))  # read while the run sleeps: the fake deletes it with the run
    events = receiver_events(task_id, timeout=40)
    check(events[-1]["kind"] == "succeeded", f"the run {[e['kind'] for e in events]}")
    check(stream(events, "stdout") == b"kept\n$Format:%H$\na\nb\ndeep\n",
          f"files read in the run {stream(events, 'stdout')!r}: export-ignore, export-subst or eol applied")
    check(result_of(events[-1])["exit_code"] == 0, "the run result")
    want = expected_workspace()
    got_cmp = {k: (v if v[0] != "dir" or k == "vendor/lib" else ("dir", None, None)) for k, v in got.items()}
    check(not any(p.split("/")[-1] == ".git" for p in got), f"a .git entry in the workspace: {sorted(got)}")
    check(got_cmp == want, f"the workspace differs from the tree: extra {sorted(set(got) - set(want))}, missing "
                           f"{sorted(set(want) - set(got))}, different "
                           f"{sorted(k for k in want if k in got_cmp and got_cmp[k] != want[k])}")


@case("commit_unknown", "peerbox Runs: commit_unknown for an unknown commit and one outside the protected branch; "
                        "a commit ID of another length 400", known=None)
def _():
    main = need("main")[0]
    need("ready")
    commit_unknown(os.urandom(20).hex())
    commit_unknown(state["secret"])
    status, body = raw_run(main[:39])
    refused(status, body, 400, "invalid", "commit")
    status, body = raw_run(main, workspace={"archive": "0" * 64})
    refused(status, body, 400, "invalid", "workspace")


@case("run_changes_no_ref", "peerbox Runs: a run never changes a ref; the owner's repository unchanged", known=None)
def _():
    work = need("work")[0]
    need("ready")
    before, status_before = refs(state["repo"]), git(state["repo"], "status", "--porcelain")
    run_ok(work["head"], ["write", "change.txt", "changed", ";", "rm", "README.md", ";", "echo", "done"])
    state["work_runs"] += 1
    check(refs(state["repo"]) == before and git(state["repo"], "status", "--porcelain") == status_before,
          "a run changed a ref or the owner's worktree")


@case("runs_recorded", "peerbox Peerboxes and contributions: runs recorded oldest first, cut to the latest 8, "
                       "runs_total", known=None)
def _():
    work = need("work")[0]
    need("ready")
    tasks = []
    for i in range(9):
        argv = ["exit", "3"] if i == 8 else ["echo", str(i)]
        task_id = run_task(work["head"], argv)
        receiver_events(task_id, timeout=60)
        tasks.append(task_id)
    state["work_runs"] += 9
    value, _, _ = op_ok({"op": "status", "peerbox_id": pbx(), "contribution_id": work["contribution_id"]})
    record = check_record(value["contributions"][0], pbx())
    runs = record["runs"]
    check(record["runs_total"] == need("work_runs")[0] and [r["task_id"] for r in runs] == tasks[-8:],
          f"runs {[r['task_id'][-6:] for r in runs]} total {record['runs_total']}, want the last 8 of "
          f"{state['work_runs']}")
    check(all(set(r) == {"task_id", "state", "exit_code", "created_at"} for r in runs)
          and runs[-1]["state"] == "failed" and runs[-1]["exit_code"] == 3 and runs[0]["state"] == "succeeded"
          and runs[0]["exit_code"] == 0, f"run entries {runs[0]} {runs[-1]}")


@case("withdrawal_cancels_run", "peerbox Withdrawal (PBX-4): losing peerbox.run cancels a started run with "
                                "`access withdrawn`; a runtime rule's withdrawal does not", known=None)
def _():
    b, rt, main = need("b", "rt", "main")
    need("ready")
    task_id = run_task(main, ["sleep", "30"])
    receiver_events(task_id, until=has_kind("accepted"), timeout=30)
    bob_share("read", "submit")
    try:
        events = receiver_events(task_id, timeout=40)
        last = events[-1]
        check(last["kind"] == "cancelled" and last.get("message") == "access withdrawn"
              and result_of(last)["signal"] == 9 and rt.entries("cancel", run_id(b, task_id)),
              f"after the withdrawal: {last['kind']} {last.get('message')!r}")
    finally:
        bob_share("read", "submit", "run")
    task_id = run_task(main, ["sleep", "4", ";", "echo", "finished"])
    receiver_events(task_id, until=has_kind("accepted"), timeout=30)
    try:
        enable("--for", state["alice_principal"])
        events = receiver_events(task_id, timeout=40)
        check(events[-1]["kind"] == "succeeded" and stream(events, "stdout") == b"finished\n",
              f"a started run after the runtime rule's withdrawal: {[e['kind'] for e in events]}")
    finally:
        enable("--for", state["alice_principal"], "--for", state["bob_principal"])


@case("deadline_past_and_expiry", "task contract (deadline in the future at the receiver; queued at its deadline "
                                  "becomes expired); peerbox Requests; runtime Running (expired before dispatch); "
                                  "test clock")
def _():
    a, b, rt, main = need("a", "b", "rt", "main")
    need("ready")
    past = rfc3339(a.now() - timedelta(minutes=1))
    for op in ({"op": "fetch", "peerbox_id": pbx()},
               {"op": "run", "peerbox_id": pbx(), "commit": main, "run": {"argv": ["echo", "late"]}}):
        status, body = raw_op(op, deadline=past)
        refused(status, body, 400, "invalid", "deadline")
    holder = occupy(60)  # the fake runtime's one slot: the peerbox run below stays queued
    try:
        task_id = new_task_id()
        op = {"op": "run", "peerbox_id": pbx(), "commit": main, "run": {"argv": ["echo", "never"]}}
        status, record = b.api("POST", "/v1/tasks", {
            "peer_host_id": a.id, "executor": "peerbox", "task_id": task_id, "peerbox": op, "input": "peerbox run",
            "deadline": rfc3339(a.now() + timedelta(minutes=10))})
        check(status in (200, 201), f"POST /v1/tasks with a 10-minute deadline: {status} {record}")
        receiver_events(task_id, until=lambda evs: bool(evs), timeout=30)
        clock.set(clock.offset + 11 * 60)
        events = receiver_events(task_id, timeout=30)
        last = events[-1]
        check([e["kind"] for e in events] == ["queued", "expired"] and last["state"] == "expired"
              and last.get("output") is None and not last.get("artifacts"),
              f"a run queued past its deadline: {[(e['kind'], e.get('output')) for e in events]}")
        rid = run_id(b, task_id)
        check(not rt.entries("started", rid) and not [p for p in rt.entries("post", rid) if p["status"] in (200, 201)],
              "an expired run was started")
    finally:
        cancel(holder)
        receiver_events(holder, timeout=30)


@case("superseded_runnable_window", "peerbox Peerboxes and contributions: a superseded contribution runnable through "
                                    "its contribution ref; the ref kept 30 days (test clock), then deleted, the "
                                    "record kept")
def _():
    a = need("a")[0]
    need("ready")
    old = contribute("again", {"again.txt": "1\n"})
    new = contribute("again", {"again.txt": "2\n"})
    value, _, _ = op_ok({"op": "status", "peerbox_id": pbx(), "contribution_id": old["contribution_id"]})
    check(value["contributions"][0]["state"] == "superseded" and new["state"] == "pending", "superseding")
    task_id, events = run_ok(old["head"], ["cat", "again.txt"])
    check(stream(events, "stdout") == b"1\n", "the superseded commit's tree")
    ref = f"refs/peerbox/{pbx()}/contributions/{old['contribution_id']}"
    clock.set(29 * DAY)
    settle(3)
    check(rev(state["repo"], ref) == old["head"], "the contribution ref was deleted before 30 days")
    clock.set(30 * DAY + HOUR)
    wait_for(lambda: rev(state["repo"], ref) is None, timeout=30, message="the contribution ref to be deleted")
    # Not asserted: a run of old["head"] ending commit_unknown after the 30 days. Every grant and policy has lapsed
    # by then (7-day grants, 24-hour policies renewed only by running hosts at their thresholds, spec 7.1), and
    # keeping them current means about 45 renewal steps of 16 hours, each waiting for a 60-second renewal pass:
    # far over the suite's 2 minutes. The ref's deletion is what makes the commit unknown (peerbox Runs).
    status, listed = a.api("GET", f"/v1/peerboxes/{pbx()}/contributions")
    check(status == 200 and old["contribution_id"] in str(listed), f"the record after 30 days: {status}")


suite.finish()
