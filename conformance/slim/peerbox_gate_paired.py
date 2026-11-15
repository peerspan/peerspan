#!/usr/bin/env python3
"""Slim suite, peerbox_gate_paired: paired comparison of an episode gate's samples (peerbox Verdict; PBX-33).

The same network, fake runtime with linked pairs, repository and peerbox as peerbox_gate_episodes.py, with
peerbox_gate_common.py: each case sets an `episode` gate with `paired_normal` or `paired_bounded`, and bob submits a
contribution whose file carries the environment's result line with one sample per episode, against a frontier file in
`main` carrying the frontier's. The samples are chosen so that the contract's bound falls well clear of 0 on the side
the case wants, and the `fixtures` case checks that host-free: promotion and `below_margin` on both sides of each
bound in both directions; repeats averaged per episode, where pooling identical repeats as more episodes would
promote; a gain that beats the margin against mean(f) taken as exact but not per episode; rare-large-loss samples
that `paired_normal` promotes and `paired_bounded` rejects; and `check_failed` for fewer than 30 samples, a count
that differs from the frontier's, and a sample outside `score_range`. Each decision's public result is read through
bob's `status`, with `compare`, `secret_sha256` and `paired` checked against the samples.

Written from docs/peerbox-contract.md only (cited as "peerbox <section>"), with the runtime task contract's Linked
runs. No VM, no KVM, no model calls. Second tier only. Nothing in the gate contract is implemented yet: every case
past the network and peerbox setup is a strict expected failure.
"""
from harness import Suite, check
from runtime_common import bind, state
from peerbox_common import rev
from peerbox_gate_common import (contribute, decided, gate_decision, gate_peerbox, gate_setup, line, mark,
                                 near_half, pairs, paired_bound, rounded, set_gate)

suite = Suite("peerbox_gate_paired", __doc__)
bind(suite)


def samples(n, f_cycle, e_cycle, direction, min_gain):
    """Frontier samples cycling F_CYCLE and candidate samples whose margin-adjusted gains cycle E_CYCLE."""
    k = min_gain / 100
    f = [f_cycle[i % len(f_cycle)] for i in range(n)]
    e = [e_cycle[i % len(e_cycle)] for i in range(n)]
    c = [round(fi * (1 - k) - ei if direction == "lower" else fi * (1 + k) + ei, 4) for fi, ei in zip(f, e)]
    return f, c


def scenario(compare, direction, min_gain, f, c, score_range=None, repeats=1, expect="promoted", code=None,
             reason=""):
    """REASON: the public result's checker_reason, None where the deciding line is malformed and so not read."""
    return {"compare": compare, "direction": direction, "min_gain": min_gain, "f": f, "c": c, "range": score_range,
            "repeats": repeats, "expect": expect, "code": code, "reason": reason}


F3, F2 = (90, 100, 110), (50, 150)
LOSS = [3.0] * 60
LOSS[17] = -30.0  # one large loss among 60 small gains
CASES = {
    "normal_lower_pass": scenario("paired_normal", "lower", 5, *samples(30, F3, (6, -2), "lower", 5)),
    "normal_lower_fail": scenario("paired_normal", "lower", 5, *samples(30, F3, (4.5, -3.5), "lower", 5),
                                  expect="rejected", code="below_margin"),
    "normal_higher_pass": scenario("paired_normal", "higher", 5, *samples(30, F3, (6, -2), "higher", 5)),
    "normal_higher_fail": scenario("paired_normal", "higher", 5, *samples(30, F3, (4.5, -3.5), "higher", 5),
                                   expect="rejected", code="below_margin"),
    "bounded_lower_pass": scenario("paired_bounded", "lower", 5, *samples(600, (95, 100, 105), (3, 1), "lower", 5),
                                   score_range=(80, 110)),
    "bounded_lower_fail": scenario("paired_bounded", "lower", 5,
                                   *samples(600, (95, 100, 105), (1.5, -0.5), "lower", 5), score_range=(80, 110),
                                   expect="rejected", code="below_margin"),
    "bounded_higher_pass": scenario("paired_bounded", "higher", 5,
                                    *samples(600, (95, 100, 105), (3.5, 1.5), "higher", 5), score_range=(80, 120)),
    "bounded_higher_fail": scenario("paired_bounded", "higher", 5,
                                    *samples(600, (95, 100, 105), (1.5, -0.5), "higher", 5), score_range=(80, 120),
                                    expect="rejected", code="below_margin"),
    "repeats": scenario("paired_normal", "lower", 5, *samples(30, F3, (5.05, -2.95), "lower", 5), repeats=2,
                        expect="rejected", code="below_margin"),
    "margin": scenario("paired_normal", "lower", 10, [F2[i % 2] for i in range(30)],
                       [F2[i % 2] - 11 for i in range(30)], expect="rejected", code="below_margin"),
    "rare_bounded": scenario("paired_bounded", "lower", 5, *samples(60, F3, LOSS, "lower", 5), score_range=(50, 150),
                             expect="rejected", code="below_margin"),
    "few": scenario("paired_normal", "lower", 5, samples(30, F3, (6, -2), "lower", 5)[0],
                    samples(29, F3, (6, -2), "lower", 5)[1], expect="rejected", code="check_failed", reason=None),
    "count": scenario("paired_normal", "lower", 5, samples(30, F3, (6, -2), "lower", 5)[0],
                      samples(31, F3, (6, -2), "lower", 5)[1], expect="rejected", code="check_failed"),
    "outside": scenario("paired_bounded", "lower", 5, samples(30, F3, (6, -2), "lower", 5)[0],
                        [*samples(30, F3, (6, -2), "lower", 5)[1][:29], 120.0], score_range=(75, 115),
                        expect="rejected", code="check_failed"),
}
CASES["rare_normal"] = {**CASES["rare_bounded"], "compare": "paired_normal", "range": None, "expect": "promoted",
                        "code": None}
FILE = {"rare_normal": "rare_bounded"}  # one frontier file: the bounded gate rejects first, so main is unchanged


def result_line(values):
    return line(round(sum(values) / len(values), 4), samples=values)


def gate_options(s):
    extra = ["--compare", s["compare"], "--repeats", str(s["repeats"])]
    if s["range"]:
        extra += ["--score-range", *map(str, s["range"])]
    return {"direction": s["direction"], "min_gain": s["min_gain"], "extra": extra}


def run(name):
    """Set case NAME's gate, submit its candidate samples, and check the decision and its public result."""
    s, file = CASES[name], FILE.get(name, name)
    set_gate(file, **gate_options(s))
    since, frontier = mark(), state["main"]
    rec = decided(contribute(name, {f"f/{file}.txt": result_line(s["c"])})["contribution_id"])
    g = gate_decision(rec, s["expect"], s["code"], checker_reason=s["reason"], frontier=frontier)
    check(g["compare"] == s["compare"] and g["direction"] == s["direction"] and g["min_gain"] == s["min_gain"],
          f"the public result's settings {g}")
    check(len(pairs(since)) == 2 * s["repeats"], f"{len(pairs(since))} measurements, want {2 * s['repeats']}")
    want = [round(sum(v) / len(v), 4) for v in (s["f"], s["c"])]
    if s["code"] == "check_failed":
        check(g["paired"] is None and g["frontier_scores"] == [want[0]] and g["candidate_scores"] == [None],
              f"paired {g['paired']}, scores {g['frontier_scores']} {g['candidate_scores']} with a failed candidate "
              f"measurement, want null, [{want[0]}], [None]")
        return g
    passes, n, gain, bound = paired_bound([s["f"]] * s["repeats"], [s["c"]] * s["repeats"], s["direction"],
                                          s["min_gain"], s["compare"], s["range"])
    p = g["paired"]
    check(isinstance(p, dict) and set(p) == {"episodes", "mean_gain_percent", "margin_bound_percent"}
          and p["episodes"] == n and rounded(p["mean_gain_percent"], gain)
          and rounded(p["margin_bound_percent"], bound)
          and (s["expect"] == "rejected" or p["margin_bound_percent"] >= 0),
          f"paired {p}, want episodes {n}, mean_gain_percent {gain:.4f}, margin_bound_percent {bound:.4f}")
    check(g["frontier_scores"] == [want[0]] * s["repeats"] and g["candidate_scores"] == [want[1]] * s["repeats"],
          f"scores {g['frontier_scores']} {g['candidate_scores']}, want {want}")
    if s["expect"] == "rejected":
        check(rev(state["repo"], "main") == frontier, "a rejection moved main")
    return g


@suite.case("fixtures", "the samples: each case's verdict under peerbox Verdict's formulas, clear of the bound; the "
                        "wrong computations each case rules out")
def _():
    for name, s in CASES.items():
        values = s["f"] + s["c"]
        check(all(v > 0 for v in values), f"{name}: a sample not positive")
        if s["code"] == "check_failed":
            continue
        check(30 <= len(s["f"]) == len(s["c"]) <= 10000 and (not s["range"] or all(s["range"][0] <= v <= s["range"][1]
                                                                                  for v in values)), f"{name}: samples")
        passes, n, gain, bound = paired_bound([s["f"]] * s["repeats"], [s["c"]] * s["repeats"], s["direction"],
                                              s["min_gain"], s["compare"], s["range"])
        check(passes == (s["expect"] == "promoted") and abs(bound) > 0.1, f"{name}: bound {bound:.3f}% passes {passes}")
        # Clear of a half-hundredth, so any faithful computation rounds them to the one value the case asserts.
        check(not near_half(gain) and not near_half(bound), f"{name}: {gain} or {bound} too near a half to round")
        check(len(result_line(s["c"])) < 262144, f"{name}: the result line is too long")
    # repeats: the same samples pooled as 60 episodes would promote.
    r = CASES["repeats"]
    check(paired_bound([r["f"] * 2], [r["c"] * 2], "lower", 5, "paired_normal")[0], "repeats: pooling does not promote")
    # margin: d is a constant 11 against min_gain 10% of mean(f) = 10, which a bound on d alone would pass.
    m = CASES["margin"]
    d = [fi - ci for fi, ci in zip(m["f"], m["c"])]
    check(len(set(d)) == 1 and d[0] > 0.1 * sum(m["f"]) / 30, "margin: the gain does not beat mean(f)'s margin")
    # few, count, outside: the failing side only.
    check(len(CASES["few"]["c"]) == 29 and len(CASES["count"]["c"]) == 31 and max(CASES["outside"]["c"]) > 115
          and max(CASES["outside"]["f"]) <= 115, "the sample-failure cases")


FRONTIER = {FILE.get(name, name): result_line(s["f"]) for name, s in CASES.items()}


@suite.case("setup", "decentralized-spec 6, 8 (create, join); the fake runtime with linked pairs; a Git repository")
def _():
    gate_setup(suite, FRONTIER)


@suite.case("peerbox_setup", "peerbox CLI: create, share (read, submit), fetch; Submit; Review (reject)")
def _():
    gate_peerbox(suite)


@suite.case("paired_normal_verdicts", "peerbox Verdict (paired_normal): mean(e) - 1.645 sd/sqrt(n) >= 0 promotes, below "
                                "is below_margin, lower and higher; the public result's compare, secret_sha256, paired")
def _():
    for name in ("normal_lower_pass", "normal_lower_fail", "normal_higher_pass", "normal_higher_fail"):
        run(name)


@suite.case("paired_bounded_verdicts", "peerbox Verdict (paired_bounded): the empirical Bernstein bound with L = ln 40 and "
                                 "R = (2 + min_gain/100)(HI - LO), promoting and below_margin, lower and higher")
def _():
    for name in ("bounded_lower_pass", "bounded_lower_fail", "bounded_higher_pass", "bounded_higher_fail"):
        run(name)


@suite.case("repeats_averaged", "peerbox Verdict: each episode averaged over the repeats, n the episodes (never samples "
                          "times repeats), so identical repeats leave the bound unchanged")
def _():
    run("repeats")


@suite.case("margin_per_episode", "peerbox Verdict: e = d - (min_gain/100) f per episode; a gain beating the margin "
                            "against mean(f) taken as exact but not per episode is below_margin")
def _():
    run("margin")


@suite.case("rare_large_loss", "peerbox Verdict: samples with one rare large loss that paired_normal promotes and "
                         "paired_bounded rejects")
def _():
    run("rare_bounded")
    run("rare_normal")


@suite.case("sample_failures", "peerbox Result line: a count other than the first frontier measurement's, and a sample "
                         "outside score_range with paired_bounded are check_failed, the line read")
def _():
    for name in ("count", "outside"):
        run(name)


@suite.case("too_few_samples", "peerbox Result line: fewer than 30 samples is a malformed line, check_failed, and not read: "
                         "checker_reason null and the decision's reason the code alone")
def _():
    run("few")


suite.finish()
