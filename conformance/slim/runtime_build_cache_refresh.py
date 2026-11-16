#!/usr/bin/env python3
"""Slim suite, runtime_build_cache_refresh: when the host starts a build cache refresh, and what it sends (RUN-18,
RUN-20, RUN-21).

The first refresh of a profile whose cache does not exist and its exact request; the stored last refresh while it
runs and once it ends; each condition of the list (the switch and `peerfs_caches`, the head, `interval_seconds`, one
refresh per cache across profiles sharing it, a free slot, no queued task, `max_runs`); `cache refresh` by hand and
409 `busy`; the last refresh kept when the profile is replaced; and a 429 from the runtime, which is no refresh.
runtime_build_cache_common.py describes the fixtures. Written from docs/build-cache-contract.md only (cited as
"cache <section>"). No VM, no KVM, no peerfs, no model calls.
"""
import re

from harness import Suite, check, wait_for
from runtime_build_cache_common import (BUILD, IMAGE, agent_id, bind, cache_name, cli_json, count, ended,
                                        expect_refresh, exited, fake, finished, head, held, move_head, no_refresh,
                                        profile, refresh_body, refresh_by_hand, refresh_ids, sh, shown, stored, tick,
                                        waiting, utc_time)
from runtime_common import need, refused, state

suite = Suite("runtime_build_cache_refresh", __doc__)
bind(suite)
suite.use_clock()  # before any host starts
NAME = cache_name("main", IMAGE)
REFRESH_ID = re.compile(r"^cache_[0-9a-f]{32}$")
SLOW = "sleep 8 ; write target/app.o slow"


def imaged(*flags, command=BUILD):
    return profile("imaged", "--image", IMAGE, "--build-cache", command, *flags)


@suite.case("setup", "decentralized-spec 6, 8; runtime Runtime administration (PUT /v1/runtime); task-contract "
                     "Authorization (grants)")
def _():
    from runtime_build_cache_common import setup
    setup()


@suite.case("refresh_first_and_request", "cache The host refresh (a cache that does not exist; what a refresh run "
                                         "has; the stored last refresh while running and once ended)")
def _():
    rt, = need("rt")
    need("ready")
    since = count(NAME)
    imaged("--network", "none", "--cpus", "3", "--memory-mib", "3072", "--timeout", "300s",
           command="sleep 2 ; " + BUILD)
    check(shown("imaged")["last_refresh"] is None and stored(NAME) is None, "fixture: a refresh or a cache already")
    at_main = head()
    rid = expect_refresh(NAME, "for a profile whose cache does not exist", since)
    state["first_start"] = suite.offset
    body = refresh_body(rid)
    want = {"run_id": rid, "argv": sh("sleep 2 ; " + BUILD), "cwd": "/workspace", "env": {}, "stdin": None,
            "resources": {"cpus": 3, "memory_mib": 3072, "timeout_seconds": 300}, "network": "none", "image": IMAGE,
            "peerfs_workspace": f"{NAME}.refresh.{rid[len('cache_'):]}", "peerfs_fork_from": "main",
            "peerfs_cache": NAME, "peerfs_cache_save": NAME, "peerfs_commit": False, "results": "none",
            "workspace_archive": None}
    check(REFRESH_ID.match(rid) and body == want, f"the refresh run differs from the contract: "
          f"{ {k: body.get(k) for k in set(body) | set(want) if body.get(k) != want.get(k)} }")
    wait_for(lambda: rt.entries("started", rid), timeout=10, message="the refresh to start")
    last = shown("imaged")["last_refresh"]
    check(last["run_id"] == rid and last["commit"] == at_main and last["ended_at"] is None and last["saved"] is None
          and last["reason"] is None, f"the stored last refresh while it runs: {last}")
    check(exited(rid)["result"]["cache_saved"] is True, "the refresh saved nothing")
    last = ended("imaged", rid)
    current = stored(NAME)
    check(current["commit"] == at_main and last["saved"] is True and last["reason"] is None
          and utc_time(last["ended_at"]) >= utc_time(last["started_at"]), f"the stored last refresh {last}")
    one = shown("imaged")
    check(one["commit"] == current["commit"] and one["bytes"] == current["bytes"], f"cache show {one}")
    no_refresh(NAME, "with the branch's head at the cache's commit")
    status, body = state["a"].api("POST", f"/v1/agents/{agent_id('codex')}/runtime/cache/refresh", {})
    refused(status, body, 404, "not_found")  # codex has no build_cache
    state["refreshed"] = True


@suite.case("refresh_null_image", "cache The host refresh: every other field left out (no image when the profile's "
                                  "is null; never peerfs_agent or peerfs_discard)")
def _():
    need("refreshed")
    main = cache_name("main")
    since = count(main)
    profile("codex", "--build-cache", BUILD)
    rid = expect_refresh(main, "for codex, whose cache does not exist", since)
    body = refresh_body(rid)
    check("image" not in body and "peerfs_agent" not in body and "peerfs_discard" not in body
          and "harness" not in body and "secrets" not in body and body["network"] == "internet"
          and body["resources"] == {"cpus": 2, "memory_mib": 2048, "timeout_seconds": 3600},
          f"a refresh of a profile with defaults: {body}")
    check(ended("codex", rid)["saved"] is True, "codex's refresh")
    profile("codex")


@suite.case("refresh_when", "cache The host refresh: the head moved, interval_seconds, a free slot, no task queued "
                            "and not yet dispatched, max_runs, the switch on and peerfs_caches true")
def _():
    a, rt = need("a", "rt")
    need("refreshed")
    moved = move_head()
    no_refresh(NAME, "within interval_seconds (600) of the last start")
    since = count(NAME)
    suite.set_offset(state["first_start"] + 600)
    rid = expect_refresh(NAME, "once the head moved and interval_seconds passed", since)
    check(exited(rid)["result"]["cache_saved"] and stored(NAME)["commit"] == moved, "the refresh of the new head")
    flags = ("--build-cache-interval", "60s")
    for arrange, why in (
            (lambda: [imaged("--max-runs", "1", *flags), held("imaged")][1:], "with the profile's max_runs dispatched"),
            (lambda: [imaged(*flags), profile("codex2"), held("codex2"), held("codex2")][2:], "with no free slot"),
            (lambda: [profile("codex2", "--max-runs", "1"), held("codex2"), waiting("codex2")][1:],
             "while a runtime agent's task was queued")):
        tasks = arrange()
        move_head()
        no_refresh(NAME, why)
        since = count(NAME)
        finished(*tasks)
        exited(expect_refresh(NAME, f"once the condition cleared ({why})", since))
    for off, on, why in ((lambda: a.api("DELETE", "/v1/runtime"), lambda: a.api("PUT", "/v1/runtime",
                                                                                   {"socket": str(rt.socket)}),
                          "with the runtime switch off"),
                         (lambda: fake(peerfs_caches=0), fake, "with peerfs_caches false")):
        off()
        try:
            move_head()
            no_refresh(NAME, why)
        finally:
            since = count(NAME)
            on()
        exited(expect_refresh(NAME, f"once it was back ({why})", since))


@suite.case("refresh_one_per_cache", "cache The host refresh: no refresh of a cache dispatched or running, for this "
                                     "profile or another sharing it; cache refresh 409 busy")
def _():
    a, = need("a")
    need("refreshed")
    profile("codex", "--image", IMAGE, "--build-cache", SLOW, "--build-cache-interval", "60s")  # shares NAME
    imaged("--build-cache-interval", "60s", command=SLOW)
    move_head()
    rid = expect_refresh(NAME, "for a slow build")
    move_head()
    no_refresh(NAME, "while one was running")
    for name in ("imaged", "codex"):
        status, body = a.api("POST", f"/v1/agents/{agent_id(name)}/runtime/cache/refresh", {})
        refused(status, body, 409, "busy")
    check(exited(rid)["result"]["cache_saved"], "the slow refresh saved nothing")
    profile("codex")


@suite.case("refresh_by_hand", "cache Host: cache refresh (the next check, ignoring interval_seconds and an "
                               "unchanged head, not the other conditions; {}); the last refresh kept when the profile "
                               "is replaced; removing build_cache forgets one asked for by hand")
def _():
    need("refreshed")
    if stored(NAME)["commit"] != head():
        since = count(NAME)
        imaged("--build-cache-interval", "60s")
        exited(expect_refresh(NAME, "to catch up with the head", since))
    before = shown("imaged")["last_refresh"]
    imaged("--max-runs", "1")
    check(shown("imaged")["last_refresh"] == before, "replacing the profile changed its last refresh")
    no_refresh(NAME, "with the head unchanged")
    since = count(NAME)
    refresh_by_hand("imaged")
    rid = expect_refresh(NAME, "asked by hand with the head unchanged", since)
    check(ended("imaged", rid)["saved"] is True, "the refresh by hand")
    task = held("imaged")
    refresh_by_hand("imaged", api=True)
    no_refresh(NAME, "by hand with the profile's max_runs dispatched")
    since = count(NAME)
    finished(task)
    exited(expect_refresh(NAME, "by hand within interval_seconds of the last start, once the task ended", since))
    task = held("imaged")
    refresh_by_hand("imaged")
    profile("imaged", "--image", IMAGE, "--max-runs", "1")
    imaged("--max-runs", "1")
    finished(task)
    no_refresh(NAME, "asked by hand before build_cache was removed and set again")


@suite.case("refresh_refused_busy", "cache The host refresh: a run the runtime refuses with 429 is no refresh (the "
                                    "stored last refresh as it was), and the next check tries again")
def _():
    need("refreshed")
    imaged("--build-cache-interval", "60s")
    before = shown("imaged")["last_refresh"]
    busy, since = len(refresh_ids(NAME, 429)), count(NAME)
    fake(busy_refreshes=1)
    try:
        move_head()
        tick()
        wait_for(lambda: len(refresh_ids(NAME, 429)) > busy, timeout=8, message="a refresh answered 429")
        check(shown("imaged")["last_refresh"] == before and count(NAME) == since,
              f"a 429 changed the stored last refresh: {shown('imaged')['last_refresh']}, was {before}")
        rid = expect_refresh(NAME, "at the check after a 429", since)
        check(ended("imaged", rid)["saved"] is True, "the refresh tried again saved nothing")
    finally:
        fake()
    cli_json("agent", "runtime", "clear", "codex2")


suite.finish()
