#!/usr/bin/env python3
"""Slim suite, runtime_build_cache: a runtime agent profile's build cache, without refreshes (RUN-17 to RUN-21).

The fake runtime's two run fields and three space routes, the profile's `build_cache`, the cache's name, `peerfs_cache`
on tasks, and `cache show`, `refresh` and `clear` where no refresh is needed: a cache made on the runtime directly,
404 without `build_cache` and 503 when the runtime cannot be asked. The host's refreshes are
runtime_build_cache_refresh (when one starts and what it sends) and runtime_build_cache_outcomes (how it ends);
runtime_build_cache_common.py describes the fixtures. Written from docs/build-cache-contract.md only (cited as
"cache <section>"), with the runtime agent and runtime task contracts it extends. No VM, no KVM, no peerfs, no model
calls.
"""
import hashlib

from harness import Suite, check
from runtime_build_cache_common import (BUILD, IMAGE, agent_id, bind, cache_name, cli_json, direct, events, fake, head,
                                        profile, seed, send, set_profile, sh, show, shown, stored, task_body, workspace,
                                        utc_time)
from runtime_common import need, refused, state

suite = Suite("runtime_build_cache", __doc__)
bind(suite)
suite.use_clock()  # before any host starts


@suite.case("setup", "decentralized-spec 6, 8; runtime Runtime administration (PUT /v1/runtime); task-contract "
                     "Authorization (grants)")
def _():
    from runtime_build_cache_common import setup
    setup()


@suite.case("fake_runtime_cache_fields", "cache Verification (the fake runtime: both fields, peerfs_caches, cache_saved, "
                                         "the cache a fork was given, the three routes); cache Runtime")
def _():
    rt, = need("rt")
    need("ready")
    check(rt.api("GET", "/v1/runtime")[1].get("peerfs_caches") is True, "the fake reports peerfs_caches false")
    name = "bc-fixture"
    save = {"peerfs_cache": name, "peerfs_cache_save": name}
    base = {"run_id": "cache_" + "0" * 32, "argv": sh("echo x"), "cwd": "/workspace", "env": {},
            "resources": {"cpus": 1, "memory_mib": 128, "timeout_seconds": 60}, "workspace_archive": None,
            "results": "none", "peerfs_workspace": "fixture.bad", "peerfs_fork_from": "main"}
    for field, fields in (("peerfs_cache", {"peerfs_cache": "Bad"}), ("peerfs_cache", {"peerfs_cache": "-x"}),
                          ("peerfs_cache", {"peerfs_cache": "x" * 129}), ("peerfs_cache", {"peerfs_cache": 5}),
                          ("peerfs_cache", {"peerfs_cache": name, "peerfs_fork_from": None}),
                          ("peerfs_cache_save", {"peerfs_cache_save": name, "peerfs_fork_from": None}),
                          ("peerfs_cache_save", {"peerfs_cache_save": name, "peerfs_commit": True,
                                                 "peerfs_commit_message": "m"})):
        status, body = rt.api("POST", "/v1/runs", {**base, **fields})
        refused(status, body, 400, "invalid", field)
    check(rt.api("GET", "/v1/caches") == (200, {"caches": []}), "GET /v1/caches before any cache")
    check(rt.api("GET", "/v1/branches/main") == (200, {"name": "main", "head": head()}), "GET /v1/branches/main")
    done = direct(sh(BUILD), **save)
    result, current = done["result"], stored(name)
    check(done["started"] and result["exit_code"] == 0 and result["error"] is None and result["cache_saved"] is True
          and result["commit"] is None, f"a refresh: {result}")
    check(current and current["commit"] == head() and current["bytes"] == len("built") + len("crate"),
          f"the saved version {current}, head {head()}")
    status, listed = rt.api("GET", "/v1/caches")
    check(status == 200 and listed == {"caches": [{"name": name, "commit": current["commit"], "versions": 1,
                                                   "saved_at": current["saved_at"], "bytes": current["bytes"]}]}
          and utc_time(current["saved_at"]).tzinfo is not None, f"GET /v1/caches: {listed}")
    check(not workspace(done["workspace"]).exists() and rt.api("GET", f"/v1/branches/{done['workspace']}")[0] == 404
          and direct(["echo", "x"], peerfs_fork_from=done["workspace"])["started"] is False,
          "a workspace or branch of the refresh's name was left")
    given = direct(sh("cat target/app.o"), peerfs_cache=name)
    logged = rt.entries("fork_cache", given["run_id"])
    check(given["stdout"] == "built" and logged and logged[0]["commit"] == current["commit"]
          and given["result"]["cache_saved"] is False, f"a fork given the cache: {given} {logged}")
    cold = direct(sh("cat target/app.o"))
    check(cold["result"]["exit_code"] == 1 and not rt.entries("fork_cache", cold["run_id"])
          and cold["result"]["cache_saved"] is False, f"a fork without a cache: {cold}")
    missing = direct(sh("echo cold"), peerfs_cache="bc-none")
    check(missing["result"]["error"] is None and rt.entries("fork_cache", missing["run_id"])[0]["commit"] is None,
          f"a cache that does not exist is no error: {missing}")
    for command, error in (("write target/app.o v2 ; write b.rs x ; write Z.rs y", "the build changed source files: Z.rs"),
                           ("write target/app.o v3 ; write c.rs x ; exit 2", None),  # a failed run is not checked
                           ("fail outside the command", "outside the command")):
        done = direct(sh(command), **save)
        check(done["result"]["cache_saved"] is False and done["result"]["error"] == error and stored(name) == current
              and not workspace(done["workspace"]).exists(), f"{command!r}: {done['result']}")
    again = direct(sh("cat target/app.o ; write target/app.o v4"), **save)
    check(again["stdout"] == "built" and again["result"]["cache_saved"] is True and stored(name)["version"] == 2,
          f"an incremental refresh: {again}")
    for path, http in (("/v1/caches/Bad", 400), ("/v1/branches/..", 400), ("/v1/branches/nothing", 404)):
        status, body = rt.api("DELETE" if "caches" in path else "GET", path)
        check(status == http, f"{path}: {status} {body}")
    for _ in range(2):  # a cache that does not exist is no error
        check(rt.api("DELETE", f"/v1/caches/{name}") == (200, {}) and stored(name) is None, "DELETE /v1/caches")
    fake(peerfs_caches=0)
    try:
        check(rt.api("GET", "/v1/runtime")[1].get("peerfs_caches") is False, "--peerfs-caches 0")
        for field in save:
            status, body = rt.api("POST", "/v1/runs", {**base, field: name})
            refused(status, body, 400, "invalid", field)
        for method, path in (("GET", "/v1/caches"), ("DELETE", f"/v1/caches/{name}"), ("GET", "/v1/branches/main")):
            status, body = rt.api(method, path)
            refused(status, body, 422, "unavailable")
    finally:
        fake()


# Host: the profile's build cache (cache Host).

@suite.case("profile_build_cache", "cache Host: build_cache (command 1 to 4,096 bytes, interval_seconds 60 to 86,400, "
                                   "default 600; 400 invalid naming it; left out when null); the CLI flags")
def _():
    a, = need("a")
    need("ready")
    path = f"/v1/agents/{agent_id('plain')}/runtime"
    check("build_cache" not in profile("plain"), "a profile without build_cache shows the field")
    value = profile("plain", "--build-cache", "cargo build --tests")
    check(value.get("build_cache") == {"command": "cargo build --tests", "interval_seconds": 600},
          f"--build-cache with the default interval: {value.get('build_cache')}")
    value = profile("plain", "--build-cache", "make all", "--build-cache-interval", "90s")
    check(value.get("build_cache") == {"command": "make all", "interval_seconds": 90}, f"an interval: {value}")
    status, body = a.api("GET", path)
    check(status == 200 and body.get("build_cache") == value["build_cache"], f"show: {status} {body}")
    check(cli_json("agent", "runtime", "show", "plain") == body, "agent runtime show differs from the API")
    check("build_cache" not in profile("plain"), "a replacement without --build-cache kept build_cache")
    for flags in (("--build-cache-interval", "90s"), ("--build-cache", "make", "--build-cache-interval", "59s"),
                  ("--build-cache", "make", "--build-cache-interval", "86401s"), ("--build-cache", "")):
        result, _ = set_profile("plain", *flags)
        check(not result.ok, f"agent runtime set {flags} succeeded")
    body = {"harness": "codex", "harness_dir": str(state["harness"])}
    for cache, want in (({"command": "é" * 2048}, 600), ({"command": "x", "interval_seconds": 60}, 60),
                        ({"command": "x", "interval_seconds": 86400}, 86400)):
        status, answer = a.api("PUT", path, {**body, "build_cache": cache})
        check(status == 200 and answer.get("build_cache") == {"command": cache["command"], "interval_seconds": want},
              f"build_cache {str(cache)[:40]}: {status} {str(answer)[:300]}")
    for cache in ({"command": ""}, {"command": "é" * 2049}, {"command": "x" * 4097}, {"interval_seconds": 60},
                  {"command": 5}, {"command": "x", "interval_seconds": 59}, {"command": "x", "interval_seconds": 86401},
                  {"command": "x", "interval_seconds": "60"}, "make"):
        status, answer = a.api("PUT", path, {**body, "build_cache": cache})
        refused(status, answer, 400, "invalid", "build_cache")
    status, answer = a.api("GET", path)
    check(answer.get("build_cache") == {"command": "x", "interval_seconds": 86400}, f"a refusal changed it: {answer}")
    status, answer = a.api("PUT", path, {**body, "build_cache": None})
    check(status == 200 and "build_cache" not in answer, f"build_cache null: {status} {answer}")


@suite.case("profile_needs_peerfs_caches", "cache Host: a profile with build_cache needs a runtime reporting "
                                           "peerfs_caches true (409 runtime_unavailable)")
def _():
    a, rt = need("a", "rt")
    need("ready")
    path = f"/v1/agents/{agent_id('plain')}/runtime"
    fake(peerfs_caches=0)
    try:
        check(rt.api("GET", "/v1/runtime")[1].get("peerfs_caches") is False, "the fake reports peerfs_caches true")
        value = profile("plain", "--cpus", "1")  # control: without build_cache the profile is set
        status, answer = a.api("PUT", path, {"harness": "codex", "harness_dir": str(state["harness"]),
                                             "build_cache": {"command": "make"}})
        refused(status, answer, 409, "runtime_unavailable")
        result, _ = set_profile("plain", "--build-cache", "make")
        check(not result.ok, "agent runtime set --build-cache on a runtime without caches succeeded")
        status, answer = a.api("GET", path)
        check(status == 200 and "build_cache" not in answer and answer.get("cpus") == value["cpus"],
              f"a refusal changed the profile: {answer}")
    finally:
        fake()
        profile("plain")


@suite.case("cache_name_and_tasks", "cache The cache's name (branch and image, a null image, shared by profiles); "
                                    "cache Tasks (peerfs_cache, nothing else changes)")
def _():
    rt, = need("rt")
    need("ready")
    main = cache_name("main")
    seed(main)
    build = ("--build-cache", "write target/t.o x", "--build-cache-interval", "86400s")
    profile("codex", *build)
    profile("codex2", *build)
    profile("imaged", "--image", IMAGE, *build)
    profile("devcache", "--from-branch", "dev", *build)
    # The names written out: SHA-256 of from_branch, a NUL byte and the image, empty when null.
    want = {"codex": "bc-" + hashlib.sha256(b"main\0").hexdigest()[:32],
            "codex2": "bc-" + hashlib.sha256(b"main\0").hexdigest()[:32],
            "imaged": "bc-" + hashlib.sha256(b"main\0" + IMAGE.encode()).hexdigest()[:32],
            "devcache": "bc-" + hashlib.sha256(b"dev\0").hexdigest()[:32], "plain": None}
    check(want["codex"] == main, f"{main} is not the name written out")
    tasks = {name: send(name, "cat target/seed.o") for name in want}
    for name, task_id in tasks.items():
        found = events(task_id)
        body = task_body(task_id)
        check(body.get("peerfs_cache") == want[name] and "peerfs_cache_save" not in body,
              f"{name}: peerfs_cache {body.get('peerfs_cache')!r}, save {body.get('peerfs_cache_save')!r}, want "
              f"{want[name]!r}")
        logged = rt.entries("fork_cache", body["run_id"])
        fork = f"{name}.{task_id}"
        if name in ("codex", "codex2"):
            check(logged and logged[0]["commit"] == stored(main)["commit"], f"{name}: the fork's cache {logged}")
            check(found[-1]["kind"] == "succeeded" and found[-1]["output"]
                  == f"seeded\n\nBranch: {fork}, unchanged from main", f"{name}: {found[-1].get('output')!r}")
        elif name == "plain":
            check(not logged and "peerfs_cache" not in body and found[-1]["kind"] == "failed",
                  f"plain: {logged} {found[-1]['kind']}")
        else:  # a cache that does not exist is no error (or a host refresh has made it since)
            now = stored(want[name])
            check(logged and logged[0]["commit"] in (None, now and now["commit"]) and found[-1]["kind"] == "failed"
                  and found[-1]["output"].endswith(f"Branch: {fork}, unchanged from "
                                                   f"{'dev' if name == 'devcache' else 'main'}"),
                  f"{name}: {logged} {found[-1].get('output')!r}")
    plain, codex = task_body(tasks["plain"]), task_body(tasks["codex"])
    same = ("argv", "cwd", "env", "resources", "network", "workspace_archive", "results", "peerfs_fork_from",
            "peerfs_commit", "peerfs_discard", "harness", "stdin")
    check(set(codex) - {"peerfs_cache"} == set(plain) and all(codex.get(k) == plain.get(k) for k in same)
          and "image" not in codex and task_body(tasks["imaged"]).get("image") == IMAGE,
          f"a task with build_cache differs beyond peerfs_cache: {sorted(set(codex) ^ set(plain))}")


@suite.case("cache_show", "cache Host: cache show (CLI, both routes; the runtime's GET /v1/caches; null fields when "
                          "it has no such cache; last_refresh null before the first; {caches} by agent ID)")
def _():
    a, rt = need("a", "rt")
    need("ready")
    main = cache_name("main")
    current = stored(main) or seed(main)
    status, listed = rt.api("GET", "/v1/caches")
    entry = next(c for c in listed["caches"] if c["name"] == main)
    one = shown("codex")
    check(one == {"agent_id": agent_id("codex"), "name": main, "commit": entry["commit"],
                  "saved_at": one["saved_at"], "bytes": entry["bytes"], "last_refresh": None}
          and utc_time(one["saved_at"]) == utc_time(entry["saved_at"]) and entry["commit"] == current["commit"],
          f"cache show codex: {one}, the runtime's {entry}")
    check(cli_json("agent", "runtime", "cache", "show", "codex") == one, "agent runtime cache show differs")
    profile("imaged", "--image", IMAGE, "--build-cache", BUILD, "--build-cache-interval", "86400s")
    name = cache_name("main", IMAGE)
    rt.api("DELETE", f"/v1/caches/{name}")  # fixture: the runtime has no such cache
    none = shown("imaged")
    check(none["name"] == name and none["commit"] is None and none["saved_at"] is None and none["bytes"] is None,
          f"cache show without a cache on the runtime: {none}")
    status, every = a.api("GET", "/v1/agents/runtime/cache")
    with_cache = sorted(agent_id(n) for n in ("codex", "codex2", "imaged", "devcache"))
    check(status == 200 and set(every) == {"caches"} and [c["agent_id"] for c in every["caches"]] == with_cache
          and all(set(c) == {"agent_id", "name", "commit", "saved_at", "bytes", "last_refresh"} for c in every["caches"]),
          f"GET /v1/agents/runtime/cache: {status} {every}")
    check(cli_json("agent", "runtime", "cache", "show") == every, "agent runtime cache show without an agent differs")


@suite.case("cache_routes_without_build_cache", "cache Host: show, refresh and clear are 404 not_found for an agent "
                                                "without build_cache")
def _():
    a, = need("a")
    need("ready")
    profile("plain")
    for name in ("plain", "noprofile"):
        base = f"/v1/agents/{agent_id(name)}/runtime/cache"
        for method, path in (("GET", base), ("POST", base + "/refresh"), ("DELETE", base)):
            status, body = a.api(method, path, {} if method == "POST" else None)
            refused(status, body, 404, "not_found")
        for verb in ("show", "refresh", "clear"):
            result = a.cli("--json", "agent", "runtime", "cache", verb, name)
            check(not result.ok, f"agent runtime cache {verb} {name}: {result.json}")


@suite.case("cache_runtime_unreachable", "cache Host: cache show and clear are 503 when the runtime cannot be asked")
def _():
    a, rt = need("a", "rt")
    need("ready")
    main = cache_name("main")
    if stored(main) is None:
        seed(main)
    rt.stop()
    try:
        status, body = show("codex")
        check(status == 503, f"cache show with the runtime stopped: {status} {body}")
        status, body = a.api("DELETE", f"/v1/agents/{agent_id('codex')}/runtime/cache")
        check(status == 503, f"cache clear with the runtime stopped: {status} {body}")
    finally:
        fake()
    check(stored(main) is not None, "a clear that answered 503 removed the cache")
    check(cli_json("agent", "runtime", "cache", "clear", "codex") == {} and stored(main) is None,
          "agent runtime cache clear")
    status, body = a.api("DELETE", f"/v1/agents/{agent_id('codex')}/runtime/cache")
    check(status == 200 and body == {}, f"clearing a cache that does not exist: {status} {body}")
    for name in ("codex", "codex2", "imaged", "devcache"):
        profile(name)


suite.finish()
