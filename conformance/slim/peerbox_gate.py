#!/usr/bin/env python3
"""Slim suite, peerbox_gate: outputs gates (peerbox Gates; PBX-9 to PBX-15, and the generator of PBX-31).

alice creates a coordinator-free network and bob joins as another person; alice's host runs its gate's measurements
on conformance/slim/fake_runtime.py, for a peerbox on a Git fixture repository that bob fetches and contributes to.
Each case sets an `outputs` gate (peerbox_gate_common.py, Outputs mode): the candidate command writes the frontier's
result line to `.peerbox-gate/out/r.txt` and the case's own line through a directory that only the contribution makes
a symbolic link into `.peerbox-gate`, and the checker cats the output. bob submits a contribution, the suite reads the
decision through bob's `status`, the gate through `gate show` and `list`, and what ran where through the fake's log:
each start request, each run's unpacked workspace and each run's result. For `score: time` the commit makes its
candidate run slow by holding a 16 MiB file the command cats, and the fake's `duration_ms` is the oracle.

It covers promotion and the moved frontier, both workspaces (no `.peerbox-gate/` entry of the commit, no expected
output or secret in a candidate run, exactly the outputs in a check run), a candidate's own result line and writes
outside `.peerbox-gate/out/`, `below_margin` in both directions and for both score sources, `check_failed`,
`run_failed`, `outputs_too_large` (a changes.tar over max_changes_bytes), `frontier_failed`, `not_fast_forward`, the
generator (its inputs, its other files, the secret, the checker's bounds and image) and `generator_failed`, the public
summary in `list`, the command's size bounds and the least max_changes_bytes. Order, superseding, pause, clear, the
runtime switch, manual decisions during an evaluation, `dirty_worktree`, restarts and `gate_busy` are
peerbox_gate_queue.py.

Written from docs/peerbox-contract.md only (cited as "peerbox <section>"), with the runtime task contract. No VM, no
KVM, no model calls. Second tier only. Nothing in the gate contract is implemented yet: every case past the network
and peerbox setup is a strict expected failure.
"""
import json

from harness import Suite, check
from runtime_common import bind, need, state
from peerbox_common import owner_cli, rev
from peerbox_gate_common import (CHECK, CHECKER_MARK, DEFAULT_RESOURCES, HEX64, INPUTS, OUT, OUTPUTS_CHECKER,
                                 SUMMARY, contribute_link, decided, digests, files_of, gate_decision, gate_peerbox,
                                 gate_setup, last_line, listed, mark, measurements, outputs_args, outputs_check,
                                 outputs_command, paused_with, pbx, posts, queue_order, record, refused_set, run_ids,
                                 run_result, secret_file, secret_sha256, set_outputs, sha, show, status_of, tidy,
                                 time_score, tree_files, workspace, written)

REASON = "peerbox gates not implemented (peerbox contract, Gates; PBX-9 to PBX-15, PBX-31)"
suite = Suite("peerbox_gate", __doc__)
bind(suite)
IMAGE = "registry.example/solver@sha256:" + "3" * 64
CHECKER_IMAGE = "registry.example/checker@sha256:" + "4" * 64
STDOUT_MARK = "printed-by-the-candidate"
GEN_MARK = "the-owners-generator"
BIG = "x" * (16 << 20)  # what a slow candidate run cats (score time)
# max_changes_bytes bounds a run's changes size, the size of its changes.tar among the result artifacts (peerbox The
# gate record): the bound is 1 MiB, a small run's changes.tar (headers, padding, a few small files) stays far below
# it, and an oversized run changes one 2 MiB file (fake `fill`), so its changes.tar is over 2 MiB.
BOUND, OVER = 1 << 20, 2 << 20
CHANGES = "x" * OVER  # main's f/changes.txt: the candidate failures' command fills it back unchanged
FRONTIER = {"run_ok": "present\n", "changes": CHANGES, "time": ""}  # main's f/NAME.txt
TIME_CMD = ["cat", "f/time.txt", ";", "write", OUT, "timed"]
TIME_CHECK = ["stderr", CHECKER_MARK, ";", "echo", written(None)]
CHECKER_FILES = {path: sha(text) for path, text in OUTPUTS_CHECKER.items()}
SEED = {f".peerbox-gate/inputs/{path}": sha(text) for path, text in INPUTS.items()}
# check_failed: (directory, the candidate's output, its checker_reason; "either" where the contract leaves it open).
FAILURES = [("cf_missing", "nothing to score here", None), ("cf_json", 'PEERBOX-GATE {"pass":true,"score":50', None),
            ("cf_keys", 'PEERBOX-GATE {"pass":true,"score":50}', None),
            ("cf_extra", 'PEERBOX-GATE {"pass":true,"score":50,"reason":"","extra":1}', None),
            ("cf_null", written(None), None), ("cf_long", written(50, reason="r" * 201), None),
            ("cf_last", written(50) + "\nnot a result line", None),
            ("cf_false", written(50, passed=False, reason="wrong answer"), "wrong answer"),
            ("cf_fail", written(50, reason="printed before failing"), "either")]
OK_FILE = ".peerbox-gate/out/ok.txt"  # check_failed's checker cats it last; cf_fail's contribution removes it
FAILURE_CMD = outputs_command(written(100), [(v, t) for v, t, _ in FAILURES],
                              [";", "write", OK_FILE, "\n", ";", "write", "cf_fail/out/ok.txt", "x", ";", "rm",
                               "cf_fail/out/ok.txt"])
FAILURE_CHECK = CHECK + [";", "cat", OK_FILE]
GENERATOR = ["stderr", GEN_MARK, ";", "write", ".peerbox-gate/inputs/fresh.txt", "generated input", ";", "write",
             "cases/c1.txt", "generated case"]


def case(name, spec, known=REASON):
    return suite.case(name, spec, known=known)


def evaluate(command, branch, var=None, files=None, timeout=120, **gate):
    """Set an outputs gate with COMMAND, submit bob's BRANCH (VAR linked, FILES), wait for the decision.
    Returns (record, frontier head, the runs started, gate show after)."""
    set_outputs(command, **gate)
    since, frontier = mark(), state["main"]
    rec = decided(contribute_link(branch, var, files)["contribution_id"], timeout)
    return rec, frontier, posts(since), show()


def sides(found, command, checker, var=None, generator=None):
    """The measurements' (side, candidate run, check run): the candidate's side is the one whose commit links VAR,
    and without VAR (time) the order frontier, candidate, frontier, ..."""
    _, pairs = measurements(found, command, checker, generator)
    out = []
    for i, (cand, chk) in enumerate(pairs):
        side = ("frontier", "candidate")[i % 2]
        if var:
            side = "candidate" if workspace(cand["run_id"]).get(var) == "link:.peerbox-gate" else "frontier"
        out.append((side, cand, chk))
    check([s for s, _, _ in out] == [("frontier", "candidate")[i % 2] for i in range(len(out))],
          f"measurement order {[s for s, _, _ in out]}, want frontier, candidate, ...")
    return out


def valid(text, score="checker"):
    """peerbox Result line, host-free: TEXT's last non-empty line is a well-formed passing result line."""
    value = last_line(text)
    if not isinstance(value, dict) or set(value) != {"pass", "score", "reason"} or value["pass"] is not True:
        return False
    good = value["score"] is None if score == "time" else (isinstance(value["score"], (int, float))
                                                           and not isinstance(value["score"], bool)
                                                           and value["score"] > 0)
    return good and isinstance(value["reason"], str) and len(value["reason"].encode()) <= 200


@suite.case("fixtures", "this suite's result lines and commands against peerbox Result line and The gate record, "
                        "host-free")
def _():
    check(valid(written(100)) and valid(written(80) + "\n\n") and valid(written(None), "time")
          and not valid(written(None)), "the valid lines")
    for var, text, _ in FAILURES:
        check(var == "cf_fail" or not valid(text), f"{var}: a valid line, want an invalid one")
    check(valid(dict((v, t) for v, t, _ in FAILURES)["cf_fail"]), "cf_fail prints a valid line before failing")
    for argv in (FAILURE_CMD, FAILURE_CHECK, TIME_CMD, TIME_CHECK, GENERATOR):
        check(1 <= len(argv) <= 64 and sum(len(a.encode()) for a in argv) <= 4096, f"{argv[:4]}: too long")


@suite.case("setup", "decentralized-spec 6, 8 (create, join); the fake runtime; a Git repository; the outputs "
                     "trick on the fake")
def _():
    gate_setup(suite, FRONTIER, checker=OUTPUTS_CHECKER)
    outputs_check(suite.work)


@suite.case("peerbox_setup", "peerbox CLI: create, share (read, submit), fetch; Submit; Review (reject)")
def _():
    gate_peerbox(suite)


@case("outputs_promotes", "peerbox Evaluation (outputs), Verdict: a candidate writing outputs and a checker echoing "
                          "a PEERBOX-GATE line, measured frontier, candidate, frontier, candidate as a candidate run "
                          "then a check run; enough gain promotes and moves the protected branch and the frontier")
def _():
    command = outputs_command(written(100), [("promote", written(80))])
    forged = {OUT: written(1) + "\n", ".peerbox-gate/inputs/seed.txt": "forged inputs\n",
              ".peerbox-gate/secret": "f" * 64 + "\n", ".peerbox-gate/generated/x.txt": "forged\n"}
    rec, frontier, found, after = evaluate(command, "promote", "promote", forged, extra=("--repeats", 2))
    g = gate_decision(rec, "promoted", frontier=frontier)
    check(g["frontier_scores"] == [100, 100] and g["candidate_scores"] == [80, 80] and g["compare"] == "worst_best"
          and g["paired"] is None and g["direction"] == "lower" and g["min_gain"] == 10, f"the public result {g}")
    gate = record(after)
    check(gate["mode"] == "outputs" and gate["link"] is None and gate["generator"] is None
          and gate["max_changes_bytes"] == 104857600, f"the outputs gate's record {gate}")
    check(isinstance(gate["frontier"], dict) and gate["frontier"]["commit"] == rec["head"]
          and gate["frontier"]["scores"] == [80, 80] and gate["frontier"].get("measured_at"),
          f"the gate's frontier after a promotion {gate['frontier']}")
    measured = sides(found, command, CHECK, "promote")
    check(len(measured) == 4, f"{len(measured)} measurements, want 4")
    for entry in found:
        r = entry["request"]
        check(r["resources"] == DEFAULT_RESOURCES and r.get("image") is None and r["workspace_archive"],
              f"a run's request {r['resources']} image {r.get('image')}")
    entry = after["evaluations"][0]
    want = [(s, k) for s in ("frontier", "candidate") * 2 for k in ("candidate", "check")]
    check(entry["contribution_id"] == rec["contribution_id"] and entry["result"] == g
          and [(r["side"], r["kind"]) for r in entry["runs"]] == want
          and run_ids(entry) == [e["run_id"] for e in found], f"gate show's evaluation {str(entry)[:400]}")
    state["promote"] = {"measured": measured, "record": rec, "frontier": frontier, "evaluation": entry}


@case("workspaces", "peerbox Evaluation (outputs), Fresh episodes: a candidate run has the commit's tree without "
                    "its .peerbox-gate/ entries plus the inputs snapshot, never the expected outputs or the secret; "
                    "a check run has the checker snapshot, the secret and exactly the outputs")
def _():
    run = need("promote")[0]
    secrets = set()
    for side, cand, chk in run["measured"]:
        commit = run["frontier"] if side == "frontier" else run["record"]["head"]
        want, got = {**tree_files(state["repo"], commit), **SEED}, files_of(cand)
        differ = sorted(k for k in want if got.get(k, want[k]) != want[k])
        check(got == want, f"the {side}'s candidate run: extra {sorted(set(got) - set(want))}, missing "
                           f"{sorted(set(want) - set(got))}, different {differ}")
        check(not set(CHECKER_FILES.values()) & set(got.values()), "the checker snapshot in a candidate run")
        ws = workspace(chk["run_id"])
        secrets.add(ws.pop(".peerbox-gate/secret", None))
        want = {**CHECKER_FILES, OUT: sha(written(100 if side == "frontier" else 80))}
        check(ws == want, f"the {side}'s check run: {sorted(ws)}, want {sorted(want)} and the secret")
    entry = run["evaluation"]
    check(secrets == {secret_file(entry["secret"])} and HEX64.match(entry["secret"])
          and run["record"]["decision"]["gate"]["secret_sha256"] == secret_sha256(entry["secret"]),
          f"{len(secrets)} secrets in the check runs, want gate show's one")


@case("candidate_claims", "peerbox Evaluation (outputs): what a candidate prints, its own PEERBOX-GATE line, and "
                          "what it writes outside .peerbox-gate/out/ are ignored; status and list never show run "
                          "output or the checker command")
def _():
    win = written(1, reason="claimed")
    tail = [";", "cat", "claim.txt", ";", "echo", win, ";", "write", ".peerbox-gate/r.txt", win, ";", "write",
            "out/r.txt", win, ";", "write", ".peerbox-gate/outputs/r.txt", win]
    command = outputs_command(written(100), [("claim", written(99))], tail)
    rec, _, found, _ = evaluate(command, "claim", "claim", {"claim.txt": written(1, reason=STDOUT_MARK) + "\n"})
    g = gate_decision(rec, "rejected", "below_margin")
    check(g["frontier_scores"] == [100] and g["candidate_scores"] == [99], f"scores {g}")
    for side, _, chk in sides(found, command, CHECK, "claim"):
        ws = workspace(chk["run_id"])
        ws.pop(".peerbox-gate/secret", None)
        check(ws == {**CHECKER_FILES, OUT: sha(written(100 if side == "frontier" else 99))},
              f"the {side}'s check run held {sorted(ws)}: more than the output under .peerbox-gate/out/")
    _, text = listed()
    check(STDOUT_MARK not in text and CHECKER_MARK not in text, "list or status shows run output or the checker")


@case("checker_verdicts", "peerbox Verdict (worst_best, score checker): below min_gain is below_margin and moves "
                          "nothing, lower and higher; enough gain with higher promotes")
def _():
    for name, direction, f, c, verdict in (("lower_below", "lower", 100, 95, "rejected"),
                                           ("higher_promote", "higher", 50, 60, "promoted"),
                                           ("higher_below", "higher", 50, 54, "rejected")):
        command = outputs_command(written(f), [(name, written(c))])
        rec, frontier, found, _ = evaluate(command, name.replace("_", "-"), name, direction=direction)
        g = gate_decision(rec, verdict, "below_margin", frontier=frontier)
        check(g["frontier_scores"] == [f] and g["candidate_scores"] == [c] and g["direction"] == direction
              and len(found) == 4, f"{name}: {g}, {len(found)} runs")
        check(verdict == "promoted" or rev(state["repo"], "main") == frontier, f"{name}: a rejection moved main")


@case("check_failed", "peerbox Result line: a missing line, a malformed one (bad JSON, a key missing or extra, a "
                      "null score with checker, a reason over 200 bytes, not the last line), pass false and a failed "
                      "check run are check_failed, with the checker's reason only from a valid line")
def _():
    set_outputs(FAILURE_CMD, checker=FAILURE_CHECK)
    for var, _, reason in FAILURES:
        rec = decided(contribute_link(var.replace("_", "-"), var)["contribution_id"], timeout=120)
        if reason == "either":  # a failed run's line: whether it was read is not settled
            reason = rec["decision"]["gate"]["checker_reason"]
            check(reason in (None, "printed before failing"), f"cf_fail: checker_reason {reason!r}")
        g = gate_decision(rec, "rejected", "check_failed", checker_reason=reason)
        check(g["frontier_scores"] == [100] and g["candidate_scores"] == [None], f"{var}: scores {g}")
    check(record(show())["state"] == "active", "a candidate's check failure paused the gate")


@case("candidate_failures", "peerbox Evaluation (outputs), The gate record (max_changes_bytes): a candidate run that "
                            "fails is run_failed; one whose changes size (its changes.tar, changes outside its "
                            "outputs too) exceeds max_changes_bytes is outputs_too_large")
def _():
    tail = [";", "cat", "f/run_ok.txt", ";", "fill", "f/changes.txt", str(OVER)]
    command = outputs_command(written(100), [("cand", written(80))], tail)
    set_outputs(command, extra=("--max-changes-bytes", BOUND))
    check(record(show())["max_changes_bytes"] == BOUND, "max_changes_bytes in the record")
    for branch, files, code in (("run-failed", {"f/run_ok.txt": None}, "run_failed"),
                                ("too-large", {"f/changes.txt": "y\n"}, "outputs_too_large")):
        since = mark()
        rec = decided(contribute_link(branch, "cand", files)["contribution_id"], timeout=120)
        g = gate_decision(rec, "rejected", code, checker_reason=None)
        check(g["frontier_scores"] == [100] and g["candidate_scores"] == [None], f"{code}: scores {g}")
        runs = [e for e in posts(since) if e["request"]["argv"] == command]
        check(len(runs) == 2 and run_result(runs[0])["exit_code"] == 0
              and run_result(runs[1])["exit_code"] == (1 if code == "run_failed" else 0),
              f"{code}: the candidate runs' exits {[run_result(e)['exit_code'] for e in runs]}")


@case("frontier_failed", "peerbox Verdict: a failed frontier measurement stops the evaluation, pauses the gate with "
                         "frontier_failed and leaves the contribution queued")
def _():
    command = outputs_command("no result line on the frontier", [("ff", written(80))])
    set_outputs(command)
    since, frontier = mark(), state["main"]
    cid = contribute_link("ff", "ff")["contribution_id"]
    paused_with("frontier_failed", cid)
    found = posts(since)
    measured = sides(found, command, CHECK, "ff")
    check(len(measured) == 1 and rev(state["repo"], "main") == frontier, f"{len(measured)} measurements, want the "
                                                                         f"frontier's alone")
    summary, _ = listed()
    check(summary["state"] == "paused", f"list's gate state {summary['state']}")


@case("not_fast_forward", "peerbox Evaluation: a candidate that is not a descendant of the frontier is rejected "
                          "with not_fast_forward before any run, with empty scores; review by hand while paused")
def _():
    set_outputs(outputs_command(written(100), [("nff", written(80))]))
    owner_cli("gate", "pause", pbx())
    records = [contribute_link("nff-x", None, {"nff_x.txt": "moves the head\n"}), contribute_link("nff-y", "nff")]
    ahead, behind = (r["contribution_id"] for r in records)
    check(show()["queue"] == queue_order(records), f"queue {show()['queue']}, want {queue_order(records)}")
    owner_cli("review", ahead, "--accept")
    state["pending"].remove(ahead)
    state["main"] = status_of(ahead)["head"]
    since = mark()
    owner_cli("gate", "resume", pbx())
    rec = decided(behind)
    g = gate_decision(rec, "rejected", "not_fast_forward", checker_reason=None, frontier=state["main"])
    check(g["frontier_scores"] == [] and g["candidate_scores"] == [] and posts(since) == [],
          f"scores {g['frontier_scores']} {g['candidate_scores']}, {len(posts(since))} runs, want none")
    check(status_of(ahead)["decision"]["decided_by"] != "gate", "the owner's acceptance is not the owner's")


@case("generator", "peerbox Generator, Fresh episodes, The gate record (images, bounds): the generator runs first "
                   "on the checker snapshot and the secret; its .peerbox-gate/inputs/ replace the inputs in candidate "
                   "runs, its other files are under .peerbox-gate/generated/ in check runs only; one secret; "
                   "checker_image and checker bounds on generator and check runs")
def _():
    command = outputs_command(written(100), [("gen", written(80))], [";", "cat", ".peerbox-gate/inputs/fresh.txt"])
    checker = ["stderr", CHECKER_MARK, ";", "cat", ".peerbox-gate/generated/cases/c1.txt", ";", "echo", ";", "cat",
               OUT]
    extra = ("--generator", json.dumps(GENERATOR), "--image", IMAGE, "--checker-image", CHECKER_IMAGE, "--cpus", 1,
             "--memory-mib", 1024, "--checker-cpus", 2, "--checker-memory-mib", 1536, "--timeout", "5m")
    rec, frontier, found, after = evaluate(command, "gen", "gen", checker=checker, extra=extra)
    g = gate_decision(rec, "promoted", frontier=frontier)
    gate = record(after)
    check(gate["generator"] == GENERATOR and gate["image"] == IMAGE and gate["checker_image"] == CHECKER_IMAGE
          and (gate["cpus"], gate["memory_mib"], gate["checker_cpus"], gate["checker_memory_mib"],
               gate["timeout_seconds"]) == (1, 1024, 2, 1536, 300), f"the gate record {gate}")
    generator, _ = measurements(found, command, checker, GENERATOR)
    owner = ({"cpus": 2, "memory_mib": 1536, "timeout_seconds": 300}, CHECKER_IMAGE)
    for entry in found:
        r = entry["request"]
        want = ({"cpus": 1, "memory_mib": 1024, "timeout_seconds": 300}, IMAGE) if r["argv"] == command else owner
        check((r["resources"], r.get("image")) == want, f"{r['argv'][:2]}: {r['resources']} {r.get('image')}")
    ws = workspace(generator["run_id"])
    secret = ws.pop(".peerbox-gate/secret", None)
    check(secret and ws == CHECKER_FILES, f"the generator's workspace {sorted(ws)}")
    generated = {".peerbox-gate/generated/cases/c1.txt": sha("generated case")}
    for side, cand, chk in sides(found, command, checker, "gen", GENERATOR):
        commit = frontier if side == "frontier" else rec["head"]
        want = {**tree_files(state["repo"], commit), ".peerbox-gate/inputs/fresh.txt": sha("generated input")}
        check(files_of(cand) == want, f"the {side}'s candidate run {sorted(files_of(cand))}, want {sorted(want)}")
        ws = workspace(chk["run_id"])
        want = {**CHECKER_FILES, **generated, ".peerbox-gate/secret": secret,
                OUT: sha(written(100 if side == "frontier" else 80))}
        check(ws == want, f"the {side}'s check run {sorted(ws)}, want {sorted(want)} and the generator's secret")
    entry = after["evaluations"][0]
    check(secret_file(entry["secret"]) == secret and g["secret_sha256"] == secret_sha256(entry["secret"])
          and [(r["side"], r["kind"]) for r in entry["runs"]][0] == ("evaluation", "generator"),
          f"gate show's evaluation {str(entry)[:300]}")
    summary, text = listed()
    check(summary["image"] == IMAGE and GEN_MARK not in text and CHECKER_IMAGE not in text
          and CHECKER_MARK not in text, "list shows the generator, the checker or its image")


@case("generator_failed", "peerbox Generator: a generator that fails, or whose changes size exceeds max_changes_bytes, "
                          "pauses the gate with generator_failed before any candidate run; the contribution stays "
                          "queued")
def _():
    for i, (generator, extra) in enumerate(((["exit", "2"], ()),
                                            (["fill", "big.txt", str(OVER)], ("--max-changes-bytes", BOUND)))):
        command = outputs_command(written(100), [("genf", written(80))])
        set_outputs(command, extra=("--generator", json.dumps(generator), *extra))
        since = mark()
        paused_with("generator_failed", contribute_link(f"genf-{i}", "genf")["contribution_id"])
        found = posts(since)
        check([e["request"]["argv"] for e in found] == [generator], f"runs {[e['request']['argv'] for e in found]}, "
                                                                    f"want the generator's alone")


@case("time_verdicts", "peerbox Evaluation, Verdict (score time): the candidate run's duration_ms, at least 1, as "
                       "the score; promotion and below_margin, higher and lower; a check run with a null score")
def _():
    steps = (("time-higher", "higher", 10, {"f/time.txt": BIG}, "promoted", 1),
             ("time-higher-below", "higher", 10, {"f/time.txt": ""}, "rejected", 1),
             ("time-lower-below", "lower", 100, {"f/time_note.txt": "still slow\n"}, "rejected", 1),
             ("time-lower", "lower", 10, {"f/time.txt": ""}, "promoted", 2))
    for branch, direction, gain, files, verdict, repeats in steps:
        rec, frontier, found, after = evaluate(TIME_CMD, branch, None, files, checker=TIME_CHECK, score="time",
                                               direction=direction, min_gain=gain, extra=("--repeats", repeats))
        g = gate_decision(rec, verdict, "below_margin", frontier=frontier, score="time")
        measured = sides(found, TIME_CMD, TIME_CHECK)
        f = [time_score(run) for s, run, _ in measured if s == "frontier"]
        c = [time_score(run) for s, run, _ in measured if s == "candidate"]
        check(g["frontier_scores"] == f and g["candidate_scores"] == c, f"{branch}: scores {g['frontier_scores']} "
                                                                        f"{g['candidate_scores']}, want {f} {c}")
        passes = (max(c) <= min(f) * (1 - gain / 100) if direction == "lower" else
                  min(c) >= max(f) * (1 + gain / 100))
        check(passes == (verdict == "promoted"), f"{branch}: the fixture's durations {f} {c} do not give {verdict}")
    state["time"] = {"record": rec, "after": after, "scores": g["candidate_scores"]}


@case("public_summary", "peerbox What readers see: list's gate summary with exactly its keys, the frontier's best "
                        "score, link_port null; never the salt, a secret, a digest or the checker command; the "
                        "public result in status as gate show records it")
def _():
    run = need("time")[0]
    gate = record(run["after"])
    summary, text = listed()
    want = {"version": gate["version"], "state": "active", "mode": "outputs", "command": TIME_CMD, "score": "time",
            "direction": "lower", "min_gain": 10, "compare": "worst_best", "score_range": None, "image": None,
            "link_port": None, "commitment": gate["commitment"],
            "frontier": {"commit": run["record"]["head"], "score": min(run["scores"])}}
    check(isinstance(summary, dict) and set(summary) == SUMMARY and summary == want,
          f"the public summary {summary}, want {want}")
    hidden = [gate["salt"], *digests().values(), CHECKER_MARK, *(e["secret"] for e in run["after"]["evaluations"])]
    check(not [h for h in hidden if h in text], "list or status shows the salt, a secret, a digest or the checker")
    check(status_of(run["record"]["contribution_id"])["decision"]["gate"] == run["after"]["evaluations"][0]["result"],
          "status's public result differs from gate show's")


@case("command_bounds", "peerbox The gate record (command, checker, generator, max_changes_bytes): 1 to 64 strings "
                        "of at most 4,096 bytes summed, and max_changes_bytes at least 65,536; past a bound 400 "
                        "invalid naming the field, the gate unchanged")
def _():
    tidy()
    before = record(show())
    over, at = ["echo", "x" * 4092, "y"], ["echo", "x" * 4092]

    def args(flag, argv):
        out = outputs_args(["echo", "x"])
        if flag == "--generator":
            return out + [flag, json.dumps(argv)]
        out[out.index(flag) + 1] = json.dumps(argv)
        return out
    for flag, argv in (("--command", over), ("--command", []), ("--command", ["x"] * 65), ("--checker", over),
                       ("--generator", over)):
        refused_set(args(flag, argv), "invalid", flag[2:])
    refused_set(outputs_args(["echo", "x"], extra=("--max-changes-bytes", 65535)), "invalid", "max_changes_bytes")
    check(record(show())["version"] == before["version"], "a refused gate set changed the gate")
    for argv in (at, ["echo"] + ["x"] * 63):
        check(record(set_outputs(argv))["command"] == argv, f"a command of {len(argv)} strings refused")
    least = record(set_outputs(["echo", "x"], extra=("--max-changes-bytes", 65536)))["max_changes_bytes"]
    check(least == 65536, f"max_changes_bytes 65536 recorded as {least}")


suite.finish()
