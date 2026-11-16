#!/usr/bin/env python3
"""Slim suite, runtime_build_cache_outcomes: how a build cache refresh ends, and what follows (RUN-18, RUN-20, RUN-21).

The stored last refresh's `reason` in its order (`timed out`, `signal N`, `exit N`, the run result's `error`, `exit
0`) and for a run the runtime refuses; the `runtime.cache_refreshed` activity; `cache clear` through the runtime's
`DELETE /v1/caches/{name}`; a refresh lost to a runtime restart, one resumed across a host restart, and the check when
the host starts; removing `build_cache` or the profile, which stops refreshes, never cancels one and keeps the cache.
runtime_build_cache_common.py describes the fixtures. Written from docs/build-cache-contract.md only (cited as
"cache <section>"). No VM, no KVM, no peerfs, no model calls.
"""
from harness import Suite, check, wait_for
from runtime_build_cache_common import (BUILD, IMAGE, agent_id, bind, cache_name, cli_json, count, ended, events,
                                        expect_refresh, exited, fake, head, move_head, no_refresh, profile,
                                        refresh_by_hand, requests, send, show, shown, stored, subjects, task_body, tick)
from runtime_common import need, state

suite = Suite("runtime_build_cache_outcomes", __doc__)
bind(suite)
suite.use_clock()  # before any host starts
NAME = cache_name("main", IMAGE)


def imaged(*flags, command=BUILD):
    return profile("imaged", "--image", IMAGE, "--build-cache", command, *flags)


def by_hand(why):
    """A refresh of `imaged` asked for by hand, once it has ended: (run ID, stored last refresh)."""
    since = count(NAME)
    refresh_by_hand("imaged")
    rid = expect_refresh(NAME, why, since)
    return rid, ended("imaged", rid)


@suite.case("setup", "decentralized-spec 6, 8; runtime Runtime administration (PUT /v1/runtime); task-contract "
                     "Authorization (grants); a first refresh of imaged saved")
def _():
    from runtime_build_cache_common import setup
    setup()
    since = count(NAME)
    imaged()
    rid = expect_refresh(NAME, "for a profile whose cache does not exist", since)
    last = ended("imaged", rid)
    check(last["saved"] is True and stored(NAME)["commit"] == head(), f"the first refresh: {last}")
    check(f"{agent_id('imaged')}/{last['commit']}/true" in subjects(),
          f"runtime.cache_refreshed AGENT_ID/COMMIT/true: {subjects()}")
    state["refreshed"] = True


@suite.case("refresh_reasons", "cache The host refresh: reason, the first of timed out, signal N, exit N for a "
                               "non-zero status, the run result's error, exit 0; activity saved false")
def _():
    need("refreshed")
    before = stored(NAME)
    for command, flags, reason in (
            ("fail broken ; sleep 5", ("--timeout", "1s"), "timed out"),
            ("fail broken ; kill 9", (), "signal 9"),
            ("fail broken ; exit 3", (), "exit 3"),
            ("fail broken", (), "broken"),
            ("write target/app.o v ; write a.rs y ; write Z.rs x", (), "the build changed source files: Z.rs"),
            ("write target/app.o v ; write a.rs y ; exit 4", (), "exit 4")):
        imaged(*flags, command=command)
        rid, last = by_hand(f"by hand for {command!r}")
        check(last["saved"] is False and last["reason"] == reason and stored(NAME) == before,
              f"{command!r}: the stored last refresh {last}, want reason {reason!r}; cache {stored(NAME)}")
    check(f"{agent_id('imaged')}/{last['commit']}/false" in subjects(),
          f"runtime.cache_refreshed AGENT_ID/COMMIT/false: {subjects()[-3:]}")
    imaged()
    fake(no_cache_saves=1)
    try:
        rid, last = by_hand("on a runtime that saves nothing")
        check(last["saved"] is False and last["reason"] == "exit 0", f"exit 0 and nothing saved: {last}")
    finally:
        fake()


@suite.case("refresh_refused", "cache The host refresh: any refusal but 429 ends it with `the runtime refused the "
                               "run: ERROR`")
def _():
    rt, = need("rt")
    need("refreshed")
    imaged("--cpus", "3")
    fake(max_cpus=2)  # the profile's 3 vCPUs are over the runtime's maximum now: 422 too_large
    try:
        since = len([1 for s, b in requests() if str(b.get("run_id")).startswith("cache_") and s == 422])
        refresh_by_hand("imaged")
        tick()
        wait_for(lambda: len([1 for s, b in requests() if str(b.get("run_id")).startswith("cache_") and s == 422])
                 > since, timeout=8, message="a refused refresh")
        refusal = rt.api("POST", "/v1/runs", {
            "run_id": "cache_" + "1" * 32, "argv": ["echo"], "cwd": "/workspace", "env": {}, "workspace_archive": None,
            "resources": {"cpus": 3, "memory_mib": 128, "timeout_seconds": 60}, "results": "none",
            "peerfs_workspace": None})[1]["error"]  # the runtime's error for the same refusal

        def refused_end():
            last = shown("imaged")["last_refresh"]
            return last if last and (last["reason"] or "").startswith("the runtime refused the run: ") else None
        last = wait_for(refused_end, timeout=10, message="the refused refresh's stored end")
        check(last["reason"] == f"the runtime refused the run: {refusal}" and last["saved"] is False
              and last["ended_at"], f"a refused refresh: {last}")
    finally:
        fake()
        imaged()


@suite.case("cache_clear", "cache Host: cache clear (the runtime's DELETE /v1/caches/{name}; {}; again for a cache "
                           "that does not exist; tasks build cold; the last refresh kept)")
def _():
    a, rt = need("a", "rt")
    need("refreshed")
    imaged("--build-cache-interval", "86400s")
    if stored(NAME) is None:
        rid, _ = by_hand("to have a cache to clear")
    last = shown("imaged")["last_refresh"]
    check(stored(NAME) is not None, "fixture: no cache to clear")
    check(cli_json("agent", "runtime", "cache", "clear", "imaged") == {} and stored(NAME) is None
          and rt.entries("cache_removed")[-1]["cache"] == NAME, "agent runtime cache clear")
    one = shown("imaged")
    check(one["commit"] is None and one["saved_at"] is None and one["bytes"] is None and one["last_refresh"] == last,
          f"cache show after clear: {one}")
    status, body = a.api("DELETE", f"/v1/agents/{agent_id('imaged')}/runtime/cache")
    check(status == 200 and body == {}, f"clearing a cache that does not exist: {status} {body}")
    task_id = send("imaged", "echo cold")
    events(task_id)
    logged = rt.entries("fork_cache", task_body(task_id)["run_id"])
    check(logged and logged[0]["commit"] is None, f"a task after clear was given a cache: {logged}")


@suite.case("refresh_restarts", "cache The host refresh: lost to a runtime restart (the runtime restarted); a host "
                                "restart resumes the stored run; the check when the host starts")
def _():
    a, rt = need("a", "rt")
    need("refreshed")
    imaged(command="sleep 20")
    since = count(NAME)
    refresh_by_hand("imaged")
    rid = expect_refresh(NAME, "to be lost", since)
    wait_for(lambda: rt.entries("started", rid), timeout=10, message="the refresh to start")
    fake()
    last = ended("imaged", rid, timeout=40)
    check(last["saved"] is False and last["reason"] == "the runtime restarted", f"a lost refresh: {last}")
    imaged(command="sleep 4 ; write target/app.o resumed")
    since = count(NAME)
    refresh_by_hand("imaged")
    rid = expect_refresh(NAME, "to resume", since)
    wait_for(lambda: rt.entries("started", rid), timeout=10, message="the refresh to start")
    a.stop(kill=True)
    a.start()
    last = ended("imaged", rid, timeout=40)
    sent = [(s, b) for s, b in requests() if b.get("run_id") == rid]
    check(last["saved"] is True and stored(NAME)["commit"] == head() and [s for s, _ in sent][:1] == [201]
          and all(s == 200 and b == sent[0][1] for s, b in sent[1:]),
          f"a refresh across a host restart: {last}; answers {[s for s, _ in sent]}")
    imaged("--build-cache-interval", "60s")
    a.stop()
    move_head()
    tick()  # while the host is stopped: only its check at start can see the moved head
    since = count(NAME)
    a.start()
    exited(expect_refresh(NAME, "at the check when the host starts", since, move=False))


@suite.case("build_cache_removed", "cache Host: removing build_cache, or the profile, stops refreshes and never cancels "
                                   "one dispatched; the cache stays")
def _():
    rt, = need("rt")
    need("refreshed")
    imaged("--build-cache-interval", "60s", command="sleep 5 ; write target/app.o late")
    move_head()
    rid = expect_refresh(NAME, "to outlive build_cache")
    profile("imaged", "--image", IMAGE)
    check(exited(rid)["result"]["cache_saved"] is True and not rt.entries("cancel", rid),
          "removing build_cache cancelled the refresh it had dispatched")
    move_head()
    no_refresh(NAME, "after build_cache was removed from the profile")
    check(stored(NAME) is not None and stored(NAME)["commit"] != head() and show("imaged")[0] == 404,
          "the cache went with build_cache, or cache show still answers")
    since = count(NAME)
    profile("codex2", "--image", IMAGE, "--build-cache", BUILD, "--build-cache-interval", "60s")  # shares NAME
    rid = expect_refresh(NAME, "for codex2", since)
    exited(rid)
    cli_json("agent", "runtime", "clear", "codex2")
    move_head()
    no_refresh(NAME, "after the profile was cleared")
    check(stored(NAME) is not None, "the cache went with the profile")


suite.finish()
