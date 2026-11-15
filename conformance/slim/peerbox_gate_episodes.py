#!/usr/bin/env python3
"""Slim suite, peerbox_gate_episodes: episode gates (peerbox Gates; PBX-25 to PBX-32).

alice creates a coordinator-free network and bob joins as another person; alice's host runs its gate's measurements
on conformance/slim/fake_runtime.py with two slots and linked pairs (runtime task contract, Linked runs), for a
peerbox on a Git fixture repository that bob fetches and contributes to. Each case sets an `episode` gate whose
environment is the fake's `serve` step on the link port and whose candidate sends one file of the measured commit
over the link (peerbox_gate_common.py), submits bob's contribution, and reads the decision through bob's `status`,
the gate through `gate show` and `list`, and what ran where through the fake's log: each start request, each run's
unpacked workspace and the link's connections. It covers an episode gate promoting and rejecting on the
environment's score, both runs' workspaces, a candidate's own result line, environment failures on the frontier and
on a candidate, the link's bounds as the gate sets them, the evaluation secret (within and across evaluations, after a
restart and after a moved head), images and checker-side bounds, the commitment, the public summary and the episode,
image and range refusals of `gate set`. Paired comparison is peerbox_gate_paired.py; the outputs-mode gate and the
generator are left to a `peerbox_gate` suite.

Written from docs/peerbox-contract.md only (cited as "peerbox <section>"), with the runtime task contract's Linked
runs. No VM, no KVM, no model calls. Second tier only. Nothing in the gate contract is implemented yet: every case
past the network and peerbox setup is a strict expected failure.
"""
import json
import re

from harness import Suite, check, wait_for
from runtime_common import bind, need, state
from peerbox_common import op_ok, owner_cli, rev, status_all
from peerbox_fixtures import commit_on
from peerbox_gate_common import (CHECKER, HEX64, INPUTS, PORT, REASON, RUNTIME, SUMMARY, check_pair, commitment,
                                 contribute, decided, gate_args, gate_decision, gate_peerbox, gate_setup, jcs_check,
                                 last_line, line, logged, mark, pairs, pbx, record, secret_digest, secret_file,
                                 secret_sha256, secrets_in, set_gate, sha, show, side, status_of, submit_tip, tidy,
                                 tree_files, workspace)
import fake_runtime

suite = Suite("peerbox_gate_episodes", __doc__)
bind(suite)
IMAGE = "registry.example/bot@sha256:" + "1" * 64
CHECKER_IMAGE = "registry.example/env@sha256:" + "2" * 64
WAIT = (";", "sleep", "3")  # an environment that stays up 3 s after its episodes, for the cases that act meanwhile
BYTES_FILE = "x" * 200 + "\n" + line(80)  # the good line only past the link's 64 bytes
# Each case's frontier (main's f/NAME.txt) and the file its contribution sends instead.
FRONTIER = {"promote": line(100), "reject": line(50), "claim": line(100), "frontier_bad": "no episode was played\n",
            "candidate_bad": line(100), "conns": line(100), "bytes": line(100), "restart": line(100),
            "moved": line(100), "images": line(100)}
CANDIDATE = {"promote": line(80), "reject": line(52), "claim": line(99), "frontier_bad": line(80),
             "candidate_bad": "the candidate sent this instead of playing\n", "conns": line(80), "bytes": BYTES_FILE,
             "restart": line(80), "moved": line(80), "images": line(80)}


def case(name, spec, known=REASON):
    return suite.case(name, spec, known=known)


def evaluate(name, files=None, timeout=90, **gate):
    """Set case NAME's gate, submit bob's contribution of CANDIDATE[NAME] (and FILES), and wait for the decision.
    Returns (record, frontier head, pairs, gate show after)."""
    set_gate(name, **gate)
    since, frontier = mark(), state["main"]
    rec = decided(contribute(name, {f"f/{name}.txt": CANDIDATE[name], **(files or {})})["contribution_id"], timeout)
    return rec, frontier, pairs(since), show()


def started(entry):
    return bool(logged("started", entry["run_id"]))


def first_env_started(since):
    def ready():
        found = pairs(since)
        return bool(found) and "listen" in found[0] and started(found[0]["listen"])
    wait_for(ready, timeout=60, interval=0.2, message="the first environment run to start")


@suite.case("fixtures", "fake_runtime.py linked pairs (runtime Linked runs) and this suite's files, host-free")
def _():
    print(f"  linked pairs checked in {fake_runtime.self_check(suite.work):.1f}s", flush=True)
    jcs_check()
    for name, text in FRONTIER.items():
        got, want = last_line(text), last_line(CANDIDATE[name])
        check(name == "frontier_bad" or (got and set(got) == {"pass", "score", "reason"}), f"{name}'s frontier line")
        check(name == "candidate_bad" or want, f"{name}'s candidate line")
    check(last_line(BYTES_FILE[:64]) is None and len(FRONTIER["bytes"]) < 64 and last_line(BYTES_FILE)["score"] == 80,
          "the bytes case: only the cut file loses its line")


@suite.case("setup", "decentralized-spec 6, 8 (create, join); the fake runtime with linked pairs; a Git repository")
def _():
    gate_setup(suite, FRONTIER)


@suite.case("peerbox_setup", "peerbox CLI: create, share (read, submit), fetch; Submit; Review (reject)")
def _():
    gate_peerbox(suite)


@suite.case("episode_promotes", "peerbox Evaluation (episode; PBX-26, PBX-27), Verdict: the environment's score promotes "
                          "and moves the frontier; frontier, candidate, frontier, candidate as linked pairs, listen "
                          "first; several connections reach the listener")
def _():
    forged = {".peerbox-gate/secret": "f" * 64 + "\n", ".peerbox-gate/inputs/seed.txt": "the candidate's inputs\n",
              ".peerbox-gate/out/result.txt": "forged\n", ".peerbox-gate/generated/x.txt": "forged\n"}
    rec, frontier, found, after = evaluate("promote", files=forged, n=3, extra=("--repeats", "2"))
    g = gate_decision(rec, "promoted", frontier=frontier)
    check(g["frontier_scores"] == [100, 100] and g["candidate_scores"] == [80, 80] and g["compare"] == "worst_best"
          and g["paired"] is None and g["score"] == "checker" and g["direction"] == "lower" and g["min_gain"] == 10,
          f"the public result {g}")
    gate = record(after)
    check(gate["link"] == {"port": PORT, "connections": 16, "bytes": 268435456} and gate["score"] == "checker",
          f"the record's link and score {gate.get('link')} {gate.get('score')}")
    check(isinstance(gate["frontier"], dict) and gate["frontier"]["commit"] == rec["head"]
          and gate["frontier"]["scores"] == [80, 80] and gate["frontier"].get("measured_at"),
          f"the gate's frontier after a promotion {gate['frontier']}")
    check(len(found) == 4, f"{len(found)} linked pairs, want 4 measurements")
    for pair in found:
        check_pair(pair)
        check(logged("serve", pair["listen"]["run_id"])[0]["accepted"] == 3, "three connections did not all arrive")
    check(len({p["connect"]["request"]["link"]["id"] for p in found}) == 4, "two measurements shared a link")
    order = [side(p, "promote", FRONTIER["promote"], CANDIDATE["promote"]) for p in found]
    check(order == ["frontier", "candidate"] * 2, f"measurement order {order}")
    state["promote"] = {"pairs": found, "record": rec, "show": after, "frontier": frontier, "order": order}


@suite.case("workspaces", "peerbox Evaluation, episode mode: the environment's workspace is the checker snapshot and the "
                    "secret, no candidate tree or outputs; the candidate's is its tree without .peerbox-gate/ entries "
                    "plus the inputs snapshot, never the checker snapshot, the secret or anything generated")
def _():
    run = need("promote")[0]
    want_env = {path: sha(text) for path, text in CHECKER.items()}
    inputs = {f".peerbox-gate/inputs/{path}": sha(text) for path, text in INPUTS.items()}
    for pair, role in zip(run["pairs"], run["order"]):
        env = workspace(pair["listen"]["run_id"])
        secret = env.pop(".peerbox-gate/secret", None)
        check(secret is not None and env == want_env, f"the environment's workspace {sorted(env)} (secret "
                                                      f"{'present' if secret else 'missing'}), want {sorted(want_env)}")
        bot = workspace(pair["connect"]["run_id"])
        commit = run["frontier"] if role == "frontier" else run["record"]["head"]
        want = {**tree_files(state["repo"], commit), **inputs}
        differ = sorted(k for k in want if bot.get(k, want[k]) != want[k])
        check(bot == want, f"the {role}'s candidate workspace: extra {sorted(set(bot) - set(want))}, missing "
                           f"{sorted(set(want) - set(bot))}, different {differ}")
        check(secret not in bot.values(), "the secret in a candidate run's workspace")


@suite.case("episode_rejects", "peerbox Verdict (worst_best, higher): less than min_gain is below_margin, nothing moves, "
                         "and the gate's frontier is the evaluation's frontier measurements")
def _():
    rec, frontier, found, after = evaluate("reject", direction="higher")
    g = gate_decision(rec, "rejected", "below_margin", frontier=frontier)
    check(g["frontier_scores"] == [50] and g["candidate_scores"] == [52] and g["direction"] == "higher",
          f"scores {g['frontier_scores']} {g['candidate_scores']}")
    check(rev(state["repo"], "main") == frontier and len(found) == 2, "a rejection moved main, or not 2 measurements")
    gate = record(after)
    check(gate["frontier"]["commit"] == frontier and gate["frontier"]["scores"] == [50], f"frontier {gate['frontier']}")
    state["reject"] = {"pairs": found, "record": rec, "show": after}


@suite.case("candidate_line_ignored", "peerbox Evaluation, episode mode: what the candidate run writes, prints or returns "
                                "and how it exits are ignored; its own PEERBOX-GATE line changes nothing")
def _():
    rec, _, _, _ = evaluate("claim", files={"claim.txt": line(1, reason="I win")}, tail=(";", "exit", "3"))
    g = gate_decision(rec, "rejected", "below_margin")
    check(g["frontier_scores"] == [100] and g["candidate_scores"] == [99], f"scores {g}")


@suite.case("environment_fails_on_frontier", "peerbox Verdict (PBX-30): a failed environment measurement on the frontier "
                                       "stops the evaluation, pauses the gate with frontier_failed and leaves the "
                                       "contribution queued")
def _():
    set_gate("frontier_bad")
    since, frontier = mark(), state["main"]
    cid = contribute("frontier_bad", {"f/frontier_bad.txt": CANDIDATE["frontier_bad"]})["contribution_id"]
    wait_for(lambda: record(show()).get("state") == "paused", timeout=60, interval=1, message="the gate to pause")
    shown = show()
    check(record(shown).get("paused_reason") == "frontier_failed", f"paused with {record(shown).get('paused_reason')}")
    rec = status_of(cid)
    check(rec["state"] == "pending" and rec["decision"] is None and cid in json.dumps(shown.get("queue")),
          f"the contribution {rec['state']} {rec['decision']}, queue {shown.get('queue')}")
    check(len(pairs(since)) == 1 and rev(state["repo"], "main") == frontier, "more than the frontier's measurement ran")


@suite.case("environment_fails_on_candidate", "peerbox Verdict (PBX-30): an environment without a valid result line on a "
                                        "candidate rejects it with check_failed, in episode mode too")
def _():
    rec, _, found, after = evaluate("candidate_bad")
    gate_decision(rec, "rejected", "check_failed")
    check(record(after)["state"] == "active" and len(found) == 2, "a candidate's failure paused the gate")


@suite.case("link_bounds", "peerbox The gate record (link), Evaluation; runtime Linked runs: the gate's connections and "
                     "bytes on both runs; a connection beyond them refused while the others go on; the link closed "
                     "at its bytes and the environment deciding")
def _():
    rec, _, found, _ = evaluate("conns", n=3, extra=("--link-connections", "2"))
    gate_decision(rec, "promoted")
    for pair in found:
        check_pair(pair, connections=2)
        refusals = [e["reason"] for e in logged("link_refused", link=pair["connect"]["request"]["link"]["id"])]
        check(refusals == ["max_connections"] and logged("serve", pair["listen"]["run_id"])[0]["accepted"] == 2,
              f"refusals {refusals}, want one beyond 2 connections and 2 accepted")
    rec, _, found, _ = evaluate("bytes", extra=("--link-bytes", "64"))
    gate_decision(rec, "rejected", "check_failed")
    for pair, role in zip(found, ("frontier", "candidate")):
        check_pair(pair, max_bytes=64)
        closed = [e["reason"] for e in logged("link_closed", link=pair["connect"]["request"]["link"]["id"])]
        served = logged("serve", pair["listen"]["run_id"])[0]["bytes"]
        want = (["exited"], [len(FRONTIER["bytes"])]) if role == "frontier" else (["max_bytes", "exited"], [64])
        check((closed, served) == want, f"the {role}'s link closed by {closed}, carried {served}, want {want}")


@suite.case("evaluation_secret", "peerbox Fresh episodes (PBX-31), Verdict: one secret in every environment run of an "
                           "evaluation, a new one in the next; secret_sha256 the SHA-256 of the secret gate show keeps")
def _():
    digests = []
    for key in ("promote", "reject"):
        run = need(key)[0]
        found = {secret_digest(p) for p in run["pairs"]}
        check(len(found) == 1 and None not in found, f"the {key} evaluation's environment runs had {len(found)} "
                                                     f"secrets")
        mine = [s for s in secrets_in(run["show"]) if secret_file(s) in found]
        check(mine, f"gate show after the {key} evaluation keeps no secret matching its environment runs")
        public = run["record"]["decision"]["gate"]["secret_sha256"]
        check(public == secret_sha256(mine[0]), f"secret_sha256 {public} is not the SHA-256 of the kept secret")
        digests += found
    check(digests[0] != digests[1], "two evaluations shared a secret")


@suite.case("secret_after_restart", "peerbox Evaluation, Fresh episodes: after a restart an undecided evaluation starts "
                              "again from its first measurement with a new secret; the runs it had started cancelled")
def _():
    a = need("a")[0]
    set_gate("restart", env=WAIT)
    since = mark()
    cid = contribute("restart", {"f/restart.txt": CANDIDATE["restart"]})["contribution_id"]
    first_env_started(since)
    cut = mark()
    a.restart()
    rec = decided(cid, timeout=120)
    gate_decision(rec, "promoted")
    before, after = pairs(since, cut), pairs(cut)
    entries = state["rt"].entries()
    for pair in before:
        for entry in pair.values():
            done = any(e.get("event") == "exited" and e.get("run_id") == entry["run_id"] for e in entries[:cut])
            check(done or logged("cancel", entry["run_id"]), f"a {entry['request']['link']['role']} run started "
                                                             f"before the restart was not cancelled")
    check([side(p, "restart", FRONTIER["restart"], CANDIDATE["restart"]) for p in after] == ["frontier", "candidate"],
          f"{len(after)} measurements after the restart, want the frontier's then the candidate's")
    new = {secret_digest(p) for p in after}
    check(len(new) == 1 and secret_digest(before[0]) not in new, "the evaluation kept its secret across a restart")
    mine = [s for s in secrets_in(show()) if secret_file(s) in new]
    check(mine and rec["decision"]["gate"]["secret_sha256"] == secret_sha256(mine[0]), "secret_sha256 after restart")


@suite.case("secret_after_head_moved", "peerbox Verdict, Fresh episodes: the owner moving the head during an evaluation "
                                 "promotes nothing; the candidate is evaluated again against the new head with a new "
                                 "secret")
def _():
    set_gate("moved", env=WAIT)
    owner_cli("gate", "pause", pbx())
    main, wt = state["main"], state["wt"]
    base = commit_on(wt, "base-x", {"x.txt": "an ancestor of the candidate\n"}, start=main)
    top = commit_on(wt, "moved", {"f/moved.txt": CANDIDATE["moved"]}, start=base)
    candidate = submit_tip("moved", top)["contribution_id"]  # the older, so evaluated first
    ancestor = submit_tip("base-x", base)["contribution_id"]
    since = mark()
    owner_cli("gate", "resume", pbx())
    first_env_started(since)
    owner_cli("review", ancestor, "--accept")
    state["pending"].remove(ancestor)
    state["main"] = base
    rec = decided(candidate, timeout=120)
    gate_decision(rec, "promoted", frontier=base)
    check(status_of(ancestor)["decision"]["decided_by"] != "gate", "the owner's acceptance was not kept")
    groups = []
    for pair in pairs(since):
        if not groups or secret_digest(pair) != secret_digest(groups[-1][0]):
            groups.append([])
        groups[-1].append(pair)
    check(len(groups) == 2, f"{len(groups)} secrets across the evaluations, want 2")
    has_x = ["x.txt" in workspace(g[0]["connect"]["run_id"]) for g in groups]
    check(has_x == [False, True], f"the frontiers measured: x.txt present {has_x}, want main then the new head")
    mine = [s for s in secrets_in(show()) if secret_file(s) == secret_digest(groups[1][0])]
    check(mine and rec["decision"]["gate"]["secret_sha256"] == secret_sha256(mine[0]), "secret_sha256 of the second")


@suite.case("images_and_bounds", "peerbox The gate record (image, checker_image, bounds, link; PBX-28): the candidate's "
                           "image and bounds on the connect run, the checker's on the environment run, one timeout")
def _():
    extra = ("--image", IMAGE, "--checker-image", CHECKER_IMAGE, "--cpus", "1", "--memory-mib", "1024",
             "--checker-cpus", "3", "--checker-memory-mib", "3072", "--timeout", "5m", "--link-connections", "4",
             "--link-bytes", "100000")
    set_gate("images", extra=extra)
    before = show()
    gate = record(before)
    want = {"image": IMAGE, "checker_image": CHECKER_IMAGE, "cpus": 1, "memory_mib": 1024, "checker_cpus": 3,
            "checker_memory_mib": 3072, "timeout_seconds": 300, "link": {"port": PORT, "connections": 4,
                                                                         "bytes": 100000}}
    check({k: gate.get(k) for k in want} == want, f"the gate record {gate}")
    since = mark()
    rec = decided(contribute("images", {"f/images.txt": CANDIDATE["images"]})["contribution_id"])
    gate_decision(rec, "promoted")
    for pair in pairs(since):
        check_pair(pair, connections=4, max_bytes=100000, image=IMAGE, checker_image=CHECKER_IMAGE,
                   resources={"cpus": 1, "memory_mib": 1024, "timeout_seconds": 300},
                   checker_resources={"cpus": 3, "memory_mib": 3072, "timeout_seconds": 300})
    state["images"] = {"before": before, "after": show(), "extra": extra, "record": rec}


@case("public_summary", "peerbox What readers see, Verdict: list's gate summary with exactly its keys and the "
                        "frontier's best score; never the salt, a secret, the checker command or image, a digest or a "
                        "sample, there or in status")
def _():
    run = need("images")[0]
    gate = record(run["after"])
    value, _, _ = op_ok({"op": "list"})
    entry = [p for p in value["peerboxes"] if p["peerbox_id"] == pbx()]
    check(len(entry) == 1 and isinstance(entry[0].get("gate"), dict), f"list entry {entry}")
    summary = entry[0]["gate"]
    want = {"version": gate["version"], "state": "active", "mode": "episode", "command": gate["command"],
            "score": "checker", "direction": "lower", "min_gain": 10, "compare": "worst_best", "score_range": None,
            "image": IMAGE, "link_port": PORT, "commitment": gate["commitment"],
            "frontier": {"commit": run["record"]["head"], "score": 80}}
    check(set(summary) == SUMMARY and summary == want, f"the public summary {summary}, want {want}")
    records, _ = status_all(pbx())
    text = json.dumps(value) + json.dumps(records)
    hidden = [gate["salt"], gate["inputs_sha256"], gate["checker_sha256"], CHECKER_IMAGE, '"serve"', '"samples"',
              *secrets_in(run["after"])]
    check(not [h for h in hidden if h and h in text], "list or status shows the salt, a secret, a digest, the "
                                                      "checker command or image, or samples")


@suite.case("commitment", "peerbox Commitment (PBX-32): SHA-256 of `peerbox-gate-commitment-v1` and a line feed and the "
                    "RFC 8785 JSON of the salt and the record's fields; unchanged by an evaluation; changed by gate "
                    "set")
def _():
    run = need("images")[0]
    before, after = record(run["before"]), record(run["after"])
    check(HEX64.match(str(before.get("commitment"))) and before["commitment"] == commitment(before),
          f"the commitment {before.get('commitment')} is not {commitment(before)}, computed from the record")
    check((after["commitment"], after["salt"], after["version"]) == (before["commitment"], before["salt"],
                                                                      before["version"]), "an evaluation changed it")
    again = record(set_gate("images", extra=run["extra"]))
    check(again["version"] == before["version"] + 1 and again["salt"] != before["salt"]
          and again["commitment"] not in (before["commitment"], None) and again["commitment"] == commitment(again),
          f"gate set again: version {again['version']}, commitment {again['commitment']}")


@suite.case("gate_set_refusals", "peerbox Gate CLI and local API: 400 invalid naming the field for the episode, paired, "
                           "range, image and link rules; 409 runtime_unsupported for an image without images and for "
                           "episode without links or two slots; each leaving the gate unchanged")
def _():
    rt = need("rt")[0]
    before = record(show())
    base = gate_args("refused")
    plain = base[:base.index("--mode")]  # outputs mode: no --mode, no --link-port

    def swap(args, flag, value):
        out = list(args)
        out[out.index(flag) + 1] = value
        return out

    def refused(args, code, field):
        result = owner_cli("gate", "set", pbx(), *args, ok=False)
        text = result.stdout + result.stderr
        check(not result.ok and code in text and re.search(field, text, re.I),
              f"gate set {args[-4:]}: exit {result.code} {' '.join(text.split())[-200:]}, want {code} naming {field}")
    tidy()
    invalid = [(swap(base, "--score", "time"), "score"),
               (swap(plain, "--score", "time") + ["--compare", "paired_normal"], "score|compare"),
               (base + ["--generator", '["echo", "x"]'], "generator"),
               (plain + ["--link-port", str(PORT)], "link"), (plain + ["--link-connections", "4"], "link"),
               (plain + ["--link-bytes", "4096"], "link"), (base[:-2], "link"),
               (base + ["--compare", "paired_bounded"], "score.range"),
               (base + ["--score-range", "1", "10"], "score.range"),
               (base + ["--compare", "paired_normal", "--score-range", "1", "10"], "score.range"),
               (base + ["--compare", "paired_bounded", "--score-range", "0", "10"], "score.range"),
               (base + ["--compare", "paired_bounded", "--score-range", "5", "5"], "score.range"),
               (base + ["--image", "registry.example/bot:latest"], "image"),
               (base + ["--image", "registry.example/bot@sha256:" + "A" * 64], "image"),
               (base + ["--image", "registry.example/bot@sha256:" + "1" * 63], "image"),
               (base + ["--checker-image", "registry.example/env"], "checker.image"),
               (swap(base, "--link-port", "0"), "link"), (swap(base, "--link-port", "65536"), "link"),
               (base + ["--link-connections", "0"], "link"), (base + ["--link-connections", "65"], "link"),
               (base + ["--link-bytes", "0"], "link"), (base + ["--link-bytes", "1073741825"], "link")]
    for args, field in invalid:
        refused(args, "invalid", field)
    try:
        for options, args in (({"links": 0}, base), ({"max_concurrent_runs": 1}, base),
                              ({"images": 0}, base + ["--image", IMAGE])):
            rt.restart(**{**RUNTIME, **options})
            refused(args, "runtime_unsupported", "")
    finally:
        rt.restart(**RUNTIME)
    after = record(show())
    check((after["version"], after["commitment"]) == (before["version"], before["commitment"]),
          "a refused gate set changed the gate")


suite.finish()
