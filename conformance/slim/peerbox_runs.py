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
import os
import stat
from pathlib import Path

from harness import Suite, check, wait_for
from runtime_common import (bind, enable, has_kind, need, receiver_events, refused, result_of, run_id,
                            setup_network, state, stream)
from peerbox_common import (REASON, bundle, check_record, commit_files, create, git, init_repo, op_ok, outcome,
                            raw_op, refs, rev, settle, share, submit_bundle, submit_op, tree_commit)

suite = Suite("peerbox_runs", __doc__)
bind(suite)
clock = suite.use_clock()
DAY, HOUR = 86400, 3600
SUBMODULE = "5" * 40
ATTRIBUTES = b"ignored.txt export-ignore\nsubst.txt export-subst\n*.txt text eol=crlf\n"
TREE = {"README.md": ("100644", b"hello\n"), "bin/run.sh": ("100755", b"#!/bin/sh\necho run\n"),
        "link": ("120000", b"README.md"), "vendor/lib": ("160000", SUBMODULE.encode()),
        ".gitattributes": ("100644", ATTRIBUTES), "ignored.txt": ("100644", b"kept\n"),
        "subst.txt": ("100644", b"$Format:%H$\n"), "lines.txt": ("100644", b"a\nb\n"),
        "sub/dir/deep.txt": ("100644", b"deep\n")}


def case(name, spec):
    return suite.case(name, spec, known=REASON)


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


def commit_unknown(commit):
    kind, value, _ = outcome(run_task(commit, ["echo", "never"]))
    error = value.get("error") if isinstance(value, dict) else None
    check(kind == "failed" and error is not None and "commit_unknown" in str(error),
          f"a run on {commit[:12]}: {kind} {value}, want failed with commit_unknown")


def bob_share(*actions):
    return share(pbx(), state["bob_principal"], actions=actions, hosts=[state["b"]])


def contribute(branch, files):
    """bob's commit on BRANCH from main, submitted; returns the contribution record."""
    wt = need("bob_wt")[0]
    git(wt, "checkout", "-q", "-B", branch, state["main"])
    tip = commit_files(wt, files, branch)
    data = bundle(need("bob_clone")[0], suite.work / f"{branch}-{tip[:8]}.bundle", tip, exclude=[state["main"]],
                  ref=branch)
    kind, value, _ = outcome(submit_bundle(pbx(), data, state["main"], branch))
    check(kind == "succeeded", f"submit {branch}: {kind} {value}")
    return check_record(value, pbx())


def workspace(task_id):
    """The directory the fake runtime unpacked the run's archive into (kept until the daemon deletes the run)."""
    found = sorted(state["rt"].dir.glob(run_id(state["b"], task_id)[:16] + "-*/workspace"))
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


@suite.case("setup", "decentralized-spec 6, 8 (create, join); a Git fixture repository")
def _():
    setup_network()
    repo = state["repo"] = init_repo(suite.work / "alice-repo")
    first = commit_files(repo, {"README.md": "hello\n"}, "first")
    git(repo, "checkout", "-q", "-b", "secret")
    state["secret"] = commit_files(repo, {"secret.txt": "s\n"}, "secret")
    git(repo, "checkout", "-q", "main")
    main = tree_commit(repo, TREE, parent=first, message="the workspace fixture")
    git(repo, "update-ref", "refs/heads/main", main)
    git(repo, "reset", "-q", "--hard", "main")
    state["main"] = main
    state["learners"] = [state["b"]]


@case("peerbox_setup", "peerbox CLI: create, share (read, submit), fetch; Submit")
def _():
    a, b = need("a", "b")
    state["pbx"] = create(state["repo"], title="runs")
    bob_share("read", "submit")
    clone, wt = suite.work / "bob-clone", suite.work / "bob-wt"
    result = b.cli("--json", "peerbox", "fetch", "--peer", a.id, pbx(), "--repository", clone, timeout=90)
    check(result.ok and rev(clone, f"refs/peerbox/{pbx()}/main") == state["main"],
          f"peerbox fetch: exit {result.code} {result.stderr.strip()[-300:]}")
    git(clone, "worktree", "add", "-q", wt, "-b", "work", f"refs/peerbox/{pbx()}/main")
    state.update(bob_clone=clone, bob_wt=wt)
    state["work"] = contribute("work", {"change.txt": "bob\n"})
    state["work_runs"] = 0


@case("run_needs_both_rules_and_switch", "peerbox Checks 2 and 4: peerbox.run, a runtime rule matching the sender "
                                         "and the local switch, each required")
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
                                  "max_artifact_bytes over the archive")
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
        task_id = run_task(main, ["echo", "never"])
        events = receiver_events(task_id, timeout=60)
        check(events[-1]["kind"] != "succeeded" and not rt.entries("started", run_id(b, task_id)),
              f"a workspace archive over max_artifact_bytes 100: {[e['kind'] for e in events]}")
    finally:
        enable("--for", state["alice_principal"], "--for", state["bob_principal"])


@case("workspace_is_the_tree", "peerbox Runs: the archive is the commit's tree byte for byte, modes, links, "
                               "submodules as empty directories, no .git, no attribute applied")
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
    want = {}
    for path, (mode, data) in TREE.items():
        parts = path.split("/")
        for i in range(1, len(parts)):
            want.setdefault("/".join(parts[:i]), ("dir", None, None))
        if mode == "120000":
            want[path] = ("link", None, data)
        elif mode == "160000":
            want[path] = ("dir", None, [])
        else:
            want[path] = ("file", 0o755 if mode == "100755" else 0o644, data)
    got_cmp = {k: (v if v[0] != "dir" or k == "vendor/lib" else ("dir", None, None)) for k, v in got.items()}
    check(not any(p.split("/")[-1] == ".git" for p in got), f"a .git entry in the workspace: {sorted(got)}")
    check(got_cmp == want, f"the workspace differs from the tree: extra {sorted(set(got) - set(want))}, missing "
                           f"{sorted(set(want) - set(got))}, different "
                           f"{sorted(k for k in want if k in got_cmp and got_cmp[k] != want[k])}")


@case("commit_unknown", "peerbox Runs: commit_unknown for an unknown commit and one outside the protected branch; "
                        "a commit ID of another length 400")
def _():
    main = need("main")[0]
    need("ready")
    commit_unknown(os.urandom(20).hex())
    commit_unknown(state["secret"])
    status, body = raw_run(main[:39])
    refused(status, body, 400, "invalid", "commit")
    status, body = raw_run(main, workspace={"archive": "0" * 64})
    refused(status, body, 400, "invalid", "workspace")


@case("run_changes_no_ref", "peerbox Runs: a run never changes a ref; the owner's repository unchanged")
def _():
    work = need("work")[0]
    need("ready")
    before, status_before = refs(state["repo"]), git(state["repo"], "status", "--porcelain")
    run_ok(work["head"], ["write", "change.txt", "changed", ";", "rm", "README.md", ";", "echo", "done"])
    state["work_runs"] += 1
    check(refs(state["repo"]) == before and git(state["repo"], "status", "--porcelain") == status_before,
          "a run changed a ref or the owner's worktree")


@case("runs_recorded", "peerbox Peerboxes and contributions: runs recorded oldest first, cut to the latest 8, "
                       "runs_total")
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
                                "`access withdrawn`; a runtime rule's withdrawal does not")
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
    status, listed = a.api("GET", f"/v1/peerboxes/{pbx()}/contributions")
    check(status == 200 and old["contribution_id"] in str(listed), f"the record after 30 days: {status}")


suite.finish()
