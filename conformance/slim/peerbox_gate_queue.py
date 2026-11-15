#!/usr/bin/env python3
"""Slim suite, peerbox_gate_queue: an outputs gate's queue and lifecycle (peerbox Gates, Evaluation; PBX-14, PBX-35,
PBX-36).

The same network, fake runtime, repository and peerbox as peerbox_gate.py, with peerbox_gate_common.py's outputs
gates (a candidate command writing the frontier's line and, through a directory the contribution links into
`.peerbox-gate`, the contribution's own; a checker that cats the output). bob may hold 8 pending contributions here.
Cases that act during an evaluation use a checker that sleeps 2 seconds before printing, and wait for a check run
to start in the fake's log before acting.

It covers evaluation order and one evaluation at a time; superseding and withdrawal while queued; pause, resume and
review by hand while paused; clear, with and without an evaluation running; `runtime_disabled` and `gate set` with
the switch off; `gate set` refused while busy (409 `gate_busy`); the owner accepting another contribution during an
evaluation (nothing swapped, the candidate evaluated again against the new head) and rejecting the candidate during
its own (cancelled, the owner's rejection kept); `dirty_worktree` pausing; and a restart during an evaluation.

Written from docs/peerbox-contract.md only (cited as "peerbox <section>"), with the runtime task contract. No VM, no
KVM, no model calls. Second tier only. Nothing in the gate contract is implemented yet: every case past the network
and peerbox setup is a strict expected failure.
"""
from harness import Suite, check
from runtime_common import bind, need, state
from peerbox_common import git, op_ok, owner_cli, rev, settle, share
from peerbox_fixtures import commit_on
from peerbox_gate_common import (CHECK, CHECKER_MARK, DECISION_KEYS, OUT, OUTPUTS_CHECKER, contribute_link, decided,
                                 gate_decision, gate_peerbox, gate_setup, listed, logged, mark, measurements,
                                 outputs_args, outputs_command, paused_with, pbx, posts, queue_order, record,
                                 refused_set, run_ids, set_outputs, show, started, status_of, submit_tip, tidy,
                                 workspace, written)

REASON = "peerbox gates not implemented (peerbox contract, Gates; PBX-9 to PBX-15, PBX-35, PBX-36)"
suite = Suite("peerbox_gate_queue", __doc__)
bind(suite)
SLOW = ["stderr", CHECKER_MARK, ";", "sleep", "2", ";", "cat", OUT]  # a check run that is still running for 2 s
SLOWER = ["stderr", CHECKER_MARK, ";", "sleep", "4", ";", "cat", OUT]  # still running once a restarted host is up
SIDES = [(s, k) for s in ("frontier", "candidate") for k in ("candidate", "check")]


def case(name, spec, known=REASON):
    return suite.case(name, spec, known=known)


def command(var, score=80):
    """An outputs gate where a contribution linking VAR scores SCORE against the frontier's 100 (lower, 10%)."""
    return outputs_command(written(100), [(var, written(score))])


def gate_path():
    return f"/v1/peerboxes/{pbx()}/gate"


def gate_state(want, reason=None):
    rec = record(show())
    check(rec["state"] == want and (reason is None or rec.get("paused_reason") == reason),
          f"the gate {rec['state']} {rec.get('paused_reason')}, want {want} {reason or ''}")


def nothing_ran(since, cid):
    """peerbox Evaluation: while the gate waits nothing starts and CID stays pending."""
    settle(3)
    rec = status_of(cid)
    check(posts(since) == [] and rec["state"] == "pending" and rec["decision"] is None,
          f"{len(posts(since))} runs started and the contribution is {rec['state']}, want none and pending")


def owner_decision(rec, decision):
    d = rec["decision"]
    check(rec["state"] == decision and set(d) == DECISION_KEYS - {"gate"} and d["decided_by"] != "gate",
          f"an owner's decision {d}, want {decision} with exactly {sorted(DECISION_KEYS - {'gate'})}")


def drop(*cids):
    for cid in cids:
        if cid in state["pending"]:
            state["pending"].remove(cid)


@suite.case("setup", "decentralized-spec 6, 8 (create, join); the fake runtime; a Git repository")
def _():
    gate_setup(suite, {}, checker=OUTPUTS_CHECKER)


@suite.case("peerbox_setup", "peerbox CLI: create, share (read, submit, max_pending 8), fetch; Submit; Review")
def _():
    gate_peerbox(suite)
    share(pbx(), state["bob_principal"], actions=("read", "submit"), extra=("--max-pending", "8"), hosts=[state["b"]])


@case("order_one_at_a_time", "peerbox Evaluation (PBX-14, PBX-35): contributions queued while paused, shown in "
                             "gate show's queue oldest first by (submitted_at, contribution_id), evaluated in that "
                             "order and one at a time, each frontier, candidate as a candidate run then a check run")
def _():
    argv = command("ord", 99)
    set_outputs(argv)
    owner_cli("gate", "pause", pbx())
    records = [contribute_link(f"ord-{i}", "ord", {f"ord{i}.txt": f"{i}\n"}) for i in range(3)]
    want = queue_order(records)
    check(show()["queue"] == want, f"queue {show()['queue']}, want {want}")
    since = mark()
    owner_cli("gate", "resume", pbx())
    for cid in want:
        gate_decision(decided(cid, timeout=120), "rejected", "below_margin")
    found = posts(since)
    _, pairs = measurements(found, argv, CHECK)  # every run started after the one before it exited
    check(len(pairs) == 6, f"{len(pairs)} measurements, want 2 for each of 3 contributions")
    evaluations = [e for e in reversed(show()["evaluations"]) if e["contribution_id"] in want]
    order = [e["contribution_id"] for e in evaluations]
    check(order == want, f"evaluated {order}, want {want}")
    ids = [i for e in evaluations for i in run_ids(e)]
    check(ids == [e["run_id"] for e in found] and all([(r["side"], r["kind"]) for r in e["runs"]] == SIDES
                                                      for e in evaluations), "gate show's runs are not those started")


@case("superseded_while_queued", "peerbox Evaluation: a contribution superseded or withdrawn while queued leaves the "
                                 "queue and is never evaluated")
def _():
    argv = command("sup")
    set_outputs(argv)
    owner_cli("gate", "pause", pbx())
    first = contribute_link("sup", "sup", {"sup.txt": "first\n"})["contribution_id"]
    second = contribute_link("sup", "sup", {"sup.txt": "second\n"})["contribution_id"]
    gone = contribute_link("wd", "sup", {"wd.txt": "withdrawn\n"})["contribution_id"]
    op_ok({"op": "withdraw", "peerbox_id": pbx(), "contribution_id": gone})
    drop(first, gone)
    check(status_of(first)["state"] == "superseded" and status_of(gone)["state"] == "superseded",
          "the replaced and the withdrawn contributions are not superseded")
    check(show()["queue"] == [second], f"queue {show()['queue']}, want only the replacement")
    since = mark()
    owner_cli("gate", "resume", pbx())
    gate_decision(decided(second), "promoted")
    check(len(posts(since)) == 4 and not {first, gone} & {e["contribution_id"] for e in show()["evaluations"]},
          "a superseded or withdrawn contribution was evaluated")


@case("pause_resume_review", "peerbox Gate CLI (pause, resume), Evaluation: paused with owner, evaluations wait, "
                             "review by hand works; resume makes it active")
def _():
    set_outputs(command("pr"))
    owner_cli("gate", "pause", pbx())
    gate_state("paused", "owner")
    summary, _ = listed()
    check(summary["state"] == "paused", f"list's gate state {summary['state']}")
    since = mark()
    cid = contribute_link("pr", "pr")["contribution_id"]
    nothing_ran(since, cid)
    check(show()["queue"] == [cid], f"queue {show()['queue']}")
    owner_cli("review", cid, "--accept")
    rec = decided(cid)
    owner_decision(rec, "accepted")
    check(show()["queue"] == [] and rev(state["repo"], "main") == rec["head"], "the acceptance by hand")
    owner_cli("gate", "resume", pbx())
    gate_state("active")
    settle(2)
    check(posts(since) == [], "resume evaluated a contribution decided by hand")


@case("clear", "peerbox Gate CLI (clear): removes the gate, cancelling a running evaluation; queued contributions "
               "stay pending for review by hand; gate show 404 not_found and list's gate null")
def _():
    a = need("a")[0]
    argv = command("clr")
    set_outputs(argv, checker=SLOW)
    since = mark()
    cid = contribute_link("clr", "clr")["contribution_id"]
    running = started(SLOW, since)
    owner_cli("gate", "clear", pbx())
    cut = mark()
    status, body = a.api("GET", gate_path())
    check(status == 404 and (body or {}).get("code") == "not_found", f"gate show after clear: {status} {body}")
    summary, _ = listed()
    check(summary is None, f"list's gate after clear {summary}")
    check(logged("cancel", running["run_id"]), "the running check run was not cancelled")
    nothing_ran(cut, cid)
    owner_cli("review", cid, "--reject", "--reason", "reviewed by hand")
    drop(cid)
    owner_decision(status_of(cid), "rejected")


@case("runtime_disabled", "peerbox Evaluation (PBX-36), Gate CLI: with the switch off the gate shows paused with "
                          "runtime_disabled and evaluations wait; gate set is 503 unavailable; resume clears only an "
                          "owner pause; with the switch on evaluation goes on by itself")
def _():
    a, rt = need("a", "rt")
    argv = command("rd")
    set_outputs(argv)
    before = record(show())
    status, body = a.api("DELETE", "/v1/runtime")
    check(status == 200, f"DELETE /v1/runtime: {status} {body}")
    try:
        gate_state("paused", "runtime_disabled")
        summary, _ = listed()
        check(summary["state"] == "paused", f"list's gate state {summary['state']}")
        tidy()
        refused_set(outputs_args(argv), "unavailable", "")
        check(record(show())["version"] == before["version"], "a refused gate set changed the gate")
        since = mark()
        cid = contribute_link("rd", "rd")["contribution_id"]
        nothing_ran(since, cid)
        owner_cli("gate", "pause", pbx())
        gate_state("paused", "owner")
        owner_cli("gate", "resume", pbx())
        gate_state("paused", "runtime_disabled")
    finally:
        status, body = a.api("PUT", "/v1/runtime", {"socket": str(rt.socket)})
    check(status == 200, f"PUT /v1/runtime: {status} {body}")
    gate_decision(decided(cid, timeout=120), "promoted")
    gate_state("active")


@case("gate_busy", "peerbox Gate CLI and local API: gate set while an evaluation runs is refused with 409 "
                   "gate_busy, by the CLI and PUT, leaving the gate and the evaluation as they were")
def _():
    a = need("a")[0]
    argv = command("bz")
    set_outputs(argv, checker=SLOW)
    before = record(show())
    since = mark()
    cid = contribute_link("bz", "bz")["contribution_id"]
    started(SLOW, since)
    refused_set(outputs_args(argv), "gate_busy", "")
    body = {"inputs_dir": str(state["inputs"]), "command": argv, "checker_dir": str(state["checker"]),
            "checker": CHECK, "score": "checker", "direction": "lower", "min_gain": 10}
    status, answer = a.api("PUT", gate_path(), body)
    check(status == 409 and (answer or {}).get("code") == "gate_busy", f"PUT during an evaluation: {status} {answer}")
    check(record(show())["version"] == before["version"], "a refused gate set changed the gate")
    gate_decision(decided(cid, timeout=120), "promoted")


@case("accepted_by_hand_meanwhile", "peerbox Verdict, Evaluation: the owner accepting another contribution during an "
                                    "evaluation swaps nothing; the candidate returns to the front of the queue and is "
                                    "evaluated again against the new head")
def _():
    argv = command("mv")
    set_outputs(argv, checker=SLOW)
    owner_cli("gate", "pause", pbx())
    main = state["main"]
    base = commit_on(state["wt"], "mv-base", {"mv_base.txt": "an ancestor of the candidate\n"}, start=main)
    candidate = contribute_link("mv", "mv", {"mv_top.txt": "the candidate\n"}, start=base)["contribution_id"]
    ancestor = submit_tip("mv-base", base)["contribution_id"]  # the newer, so evaluated second
    since = mark()
    owner_cli("gate", "resume", pbx())
    started(SLOW, since)
    owner_cli("review", ancestor, "--accept")
    drop(ancestor)
    state["main"] = base
    rec = decided(candidate, timeout=150)
    gate_decision(rec, "promoted", frontier=base)
    owner_decision(status_of(ancestor), "accepted")
    check(rev(state["repo"], "main") == rec["head"], "main is not the candidate")
    tries = [e for e in show()["evaluations"] if e["contribution_id"] == candidate]
    check(len(tries) >= 2 and tries[0]["frontier"] == base and tries[0]["result"] == rec["decision"]["gate"]
          and tries[-1]["frontier"] == main, f"the candidate's evaluations' frontiers "
                                             f"{[e['frontier'] for e in tries]}, want {base} last and {main} first")


@case("rejected_by_hand_meanwhile", "peerbox Evaluation: the owner rejecting the candidate during its evaluation "
                                    "cancels it and its runs; the owner's rejection is kept and it is not evaluated "
                                    "again")
def _():
    argv = command("rj")
    set_outputs(argv, checker=SLOW)
    since = mark()
    cid = contribute_link("rj", "rj")["contribution_id"]
    running = started(SLOW, since)
    owner_cli("review", cid, "--reject", "--reason", "the owner's call")
    cut = mark()
    drop(cid)
    settle(4)
    rec = status_of(cid)
    owner_decision(rec, "rejected")
    check(rec["decision"]["reason"] == "the owner's call", f"the owner's reason {rec['decision']['reason']!r}")
    check(logged("cancel", running["run_id"]) and posts(cut) == [], "the evaluation's run was not cancelled, or "
                                                                    "another started after the rejection")
    shown = show()
    entry = [e for e in shown["evaluations"] if e["contribution_id"] == cid]
    check(len(entry) == 1 and entry[0]["decided_at"] is None and entry[0]["result"] is None and shown["queue"] == [],
          f"the cancelled evaluation {entry}, queue {shown['queue']}")
    gate_state("active")


@case("dirty_worktree", "peerbox Verdict: a promotion into a checked-out protected branch with a dirty worktree "
                        "pauses the gate with dirty_worktree and leaves the contribution queued")
def _():
    repo = state["repo"]
    set_outputs(command("dw"))
    main = state["main"]
    (repo / "README.md").write_text("an owner's edit in progress\n")
    try:
        since = mark()
        cid = contribute_link("dw", "dw")["contribution_id"]
        paused_with("dirty_worktree", cid)
        check(rev(repo, "main") == main and len(posts(since)) == 4, "main moved, or the evaluation did not finish")
    finally:
        git(repo, "checkout", "--", "README.md")
    owner_cli("gate", "resume", pbx())
    gate_decision(decided(cid, timeout=120), "promoted", frontier=main)


@case("restart_during_evaluation", "peerbox Evaluation: after a restart an undecided evaluation starts again from "
                                   "its first measurement with a new secret; the run it had running is cancelled "
                                   "before the first new run")
def _():
    a = need("a")[0]
    argv = command("rs")
    set_outputs(argv, checker=SLOWER)
    since = mark()
    cid = contribute_link("rs", "rs")["contribution_id"]
    running = started(SLOWER, since)
    cut = mark()
    a.restart()
    rec = decided(cid, timeout=150)
    gate_decision(rec, "promoted")
    after = posts(cut)
    entries = state["rt"].entries()
    cancels = [i for i, e in enumerate(entries) if e.get("event") == "cancel" and e.get("run_id") == running["run_id"]]
    check(after and cancels and cancels[0] < after[0]["at_index"], "the check run running at the restart was not "
                                                                   "cancelled before the first new run")
    _, pairs = measurements(after, argv, SLOWER)
    check(len(pairs) == 2 and workspace(pairs[0][0]["run_id"]).get("rs") is None
          and workspace(pairs[1][0]["run_id"]).get("rs") == "link:.peerbox-gate",
          f"{len(pairs)} measurements after the restart, want the frontier's then the candidate's")
    old = workspace(running["run_id"]).get(".peerbox-gate/secret")
    new = {workspace(chk["run_id"]).get(".peerbox-gate/secret") for _, chk in pairs}
    check(old and len(new) == 1 and old not in new, "the evaluation kept its secret across the restart")
    tries = [e for e in show()["evaluations"] if e["contribution_id"] == cid]
    check(len(tries) == 2 and tries[1]["decided_at"] is None and tries[1]["result"] is None
          and tries[0]["result"] == rec["decision"]["gate"], f"the evaluations across the restart {tries}")


suite.finish()
