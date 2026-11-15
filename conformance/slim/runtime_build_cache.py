#!/usr/bin/env python3
"""Slim suite, runtime_build_cache: a runtime agent profile's build cache (RUN-17 to RUN-20).

alice creates a coordinator-free network and bob joins as another person. alice's host serves through
conformance/slim/fake_runtime.py, started with the peerfs workspaces `main` and `dev`, two run slots and `--requests`,
so the suite sees each `POST /v1/runs` body as the host sent it. alice registers the agents `codex`, `codex2`,
`imaged`, `devcache` and `plain`, and bob sends them tasks under `task.submit` grants. Every host is on one debug test
clock (DEC-OWN9 question 2), which the suite moves 61 seconds to reach the host's next 60-second refresh check.

The fake classes paths under `target/`, `node_modules/` and `.peerspan/cache/` as derived and all others as source;
a branch's head is `01` and the SHA-256 of its source paths and contents (`fake_runtime.branch_head`), so writing a
source file into the `main` directory moves `main`'s head. A refresh run's `argv` `["/bin/sh", "-c", COMMAND]` runs
COMMAND as the fake's steps, so a profile's `--build-cache "write target/app.o built"` is a build that writes output.

Blocked cases. The contract has the host read the profile's branch head and the cache's current version "from the
runtime's peerfs" and remove the cache with `cache rm`, but does not say how the host reaches that peerfs (contract
question 1 in this suite's PR). Every case that needs a refresh to start, `cache show`'s fields or `cache clear` is
written in full and reports SKIP until then; `SLIM_BUILD_CACHE_PEERFS=1` runs them once the contract says how and the
fake serves it.

Written from docs/build-cache-contract.md only (cited as "cache <section>"), with the runtime agent and runtime task
contracts it extends. No VM, no KVM, no peerfs, no model calls. runtime_common.py holds the shared fixtures.
"""
import base64
import hashlib
import json
import os
import re
import shutil
import time
from datetime import timedelta

from fake_runtime import branch_head
from harness import Skip, Suite, check, parse_time, rfc3339, wait_for
from runtime_common import has_kind, need, new_task_id, receiver_events, refused, run_id, setup_network, state
import runtime_common

suite = Suite("runtime_build_cache", __doc__)
runtime_common.bind(suite)
suite.use_clock()  # before any host starts
FAKE = {"peerfs_workspace": ["main", "dev"], "max_concurrent_runs": 2, "max_cpus": 4, "max_memory_mib": 8192,
        "max_seconds": 7200}
IMAGE = "registry.example/peerspan/rust@sha256:" + "a" * 64
BUILD = "write target/app.o built ; write .peerspan/cache/cargo/registry/crate.txt crate ; echo built"
REFRESH_ID = re.compile(r"^cache_[0-9a-f]{32}$")
CHECK_WAIT = 8  # real seconds for the check after the clock moves 61 s (contract question 2)
QUIET = 2  # real seconds watched for a refresh that must not start
PEERFS_GAP = ("blocked on contract question 1: the contract does not say how the host reaches the runtime's peerfs "
              "(a branch's head, a cache's current version, cache rm)")


def blocked():
    if os.environ.get("SLIM_BUILD_CACHE_PEERFS") != "1":
        raise Skip(PEERFS_GAP)


def cache_name(from_branch="main", image=None):
    """cache The cache's name: `bc-` and the first 32 hex digits of SHA-256(from_branch, NUL, image or empty)."""
    return "bc-" + hashlib.sha256(from_branch.encode() + b"\0" + (image or "").encode()).hexdigest()[:32]


def tail(text):
    return text.strip()[-300:]


def agent_id(name):
    return state["agents"][name]["id"]


def fake(**override):
    """(Re)start alice's fake runtime with the suite's options and OVERRIDE; workspaces and caches are kept."""
    state["rt"].restart(**{**FAKE, "requests": str(state["requests"]), **override})


def set_profile(name, *flags):
    """`agent runtime set NAME --harness-dir DIR FLAGS...` on alice's host: (result, profile or None)."""
    result = state["a"].cli("--json", "agent", "runtime", "set", name, "--harness-dir", str(state["harness"]), *flags)
    return result, result.json if result.ok and isinstance(result.json, dict) else None


def profile(name, *flags):
    result, value = set_profile(name, *flags)
    check(value is not None, f"agent runtime set {name} {' '.join(flags)}: exit {result.code} {tail(result.stderr)}")
    return value


def cli_json(*args):
    result = state["a"].cli("--json", *args)
    check(result.ok, f"{' '.join(args)}: exit {result.code} {tail(result.stderr)}")
    return result.json


def send(name, prompt):
    """An ordinary agent task from bob to alice's agent NAME under his grant."""
    a, b = need("a", "b")
    body = {"peer_host_id": a.id, "target_agent_id": agent_id(name), "input": prompt, "task_id": new_task_id(),
            "grant_id": state["grants"][name]}
    status, record = b.api("POST", "/v1/tasks", body)
    check(status in (200, 201), f"bob: POST /v1/tasks to {name}: {status} {record}")
    return body["task_id"]


def events(task_id, until=None, timeout=30):
    return receiver_events(task_id, until=until, timeout=timeout, sender=state["b"])


def requests():
    """[(status, body)] of every POST /v1/runs the fake saw, from its --requests file."""
    out = []
    path = state["requests"]
    for line in path.read_text().splitlines() if path.exists() else []:
        entry = json.loads(line)
        try:
            out.append((entry["status"], json.loads(entry["body"])))
        except ValueError:
            continue
    return [(s, b) for s, b in out if isinstance(b, dict)]


def task_body(task_id):
    rid = run_id(state["b"], task_id)
    found = [b for s, b in requests() if b.get("run_id") == rid]
    check(found, f"the runtime saw no start for {task_id}")
    return found[0]


def refresh_ids(name):
    """The distinct refresh run IDs whose `peerfs_cache_save` is NAME, in the order first sent."""
    seen = []
    for _, body in requests():
        rid = body.get("run_id")
        if isinstance(rid, str) and rid.startswith("cache_") and body.get("peerfs_cache_save") == name \
                and rid not in seen:
            seen.append(rid)
    return seen


def refresh_body(rid):
    return next(b for _, b in requests() if b.get("run_id") == rid)


def workspace(name):
    return state["rt"].dir / "peerfs" / name


def head(branch="main"):
    return branch_head(workspace(branch))


def move_head():
    """A new source file on `main`: its head moves (the fake's heads are of source paths)."""
    path = workspace("main") / "src" / f"m{os.urandom(4).hex()}.rs"
    path.parent.mkdir(exist_ok=True)
    path.write_text("fn moved() {}\n")
    return head()


def stored(name):
    """The fake's current version of the cache NAME, `{version, commit, saved_at, bytes}`, or None."""
    path = workspace(".caches") / name / "current.json"
    return json.loads(path.read_text()) if path.exists() else None


def tick(seconds=61):
    suite.set_offset(suite.offset + seconds)


def expect_refresh(name, why, count=None):
    """Move the clock to the next check; the refresh of NAME it starts (the first after COUNT, by default those
    sent so far), by run ID. Pass COUNT from before the condition clears: a real-time check may come first."""
    count = len(refresh_ids(name)) if count is None else count
    tick()
    wait_for(lambda: len(refresh_ids(name)) > count, timeout=CHECK_WAIT, interval=0.2,
             message=f"a refresh of {name} {why}")
    return refresh_ids(name)[count]


def no_refresh(name, why):
    count = len(refresh_ids(name))
    tick()
    time.sleep(QUIET)
    check(len(refresh_ids(name)) == count, f"a refresh of {name} started {why}")


def exited(rid, timeout=30):
    rt, = need("rt")
    return wait_for(lambda: rt.entries("exited", rid), timeout=timeout, message=f"{rid} to end")[-1]


def show(name):
    return state["a"].api("GET", f"/v1/agents/{agent_id(name)}/runtime/cache")


def last_refresh(shown):
    """The last refresh in a `cache show` answer, by its fields (contract question 5: the key is not named)."""
    found = [v for v in (shown or {}).values() if isinstance(v, dict) and "run_id" in v and "started_at" in v]
    return found[0] if found else None


def ended(name, rid, timeout=20):
    """The stored last refresh of NAME's profile once the refresh RID has ended (`ended_at` set)."""
    def done():
        status, shown = show(name)
        last = last_refresh(shown) if status == 200 else None
        return last if last and last["run_id"] == rid and last.get("ended_at") else None
    return wait_for(done, timeout=timeout, interval=0.3, message=f"the stored end of {rid}")


def activity(kind):
    status, body = state["a"].api("GET", "/v1/activity?limit=1000")
    check(status == 200 and isinstance(body, list), f"GET /v1/activity: {status} {str(body)[:200]}")
    return [e for e in body if e.get("kind") == kind]


def held(name, prompt="sleep 6"):
    """A task of NAME, once it runs."""
    task_id = send(name, prompt)
    events(task_id, until=has_kind("accepted"))
    return task_id


def waiting(name):
    """A task of NAME, once alice's host has it queued."""
    task_id = send(name, "echo queued")
    events(task_id, until=lambda found: bool(found))
    return task_id


def finished(*tasks):
    for task_id in tasks:
        check(events(task_id)[-1]["kind"] == "succeeded", f"{task_id} did not succeed")


def kinds_of(found):
    return [e["kind"] for e in found]


@suite.case("setup", "decentralized-spec 6, 8; runtime Runtime administration (PUT /v1/runtime); task-contract "
                     "Authorization (grants)")
def _():
    state["requests"] = suite.work / "alice-requests.jsonl"
    setup_network(requests=str(state["requests"]), **FAKE)
    a, b, rt = need("a", "b", "rt")
    for name in ("main", "dev"):
        (workspace(name) / "README").write_text(f"{name} seed\n")
    status, body = a.api("PUT", "/v1/runtime", {"socket": str(rt.socket)})
    check(status == 200 and body.get("peerfs") is True, f"the runtime switch: {status} {body}")
    harness = suite.work / "owner" / "codex-release"
    harness.mkdir(parents=True)
    for binary in ("codex", "codex-code-mode-host"):
        (harness / binary).write_text("#!/bin/sh\nexit 0\n")
        (harness / binary).chmod(0o755)
    key_file = suite.work / "owner" / "openai.key"
    key_file.write_text("sk-test-" + os.urandom(24).hex() + "\n")
    state.update(harness=harness, key_file=key_file, agents={}, grants={})
    for name in ("codex", "codex2", "imaged", "devcache", "plain", "noprofile"):
        status, agent = a.api("POST", "/v1/agents", {"name": name, "owner": "alice"})
        check(status in (200, 201), f"register {name}: {status} {agent}")
        state["agents"][name] = agent
        state["grants"][name] = a.ok("grant", "create", "--peer", b.id, "--agent", agent["id"], "--action",
                                     "task.submit", "--expires-at", rfc3339(a.now() + timedelta(hours=6)))["id"]
    for name in ("codex", "codex2", "imaged", "devcache", "plain"):
        profile(name)
        cli_json("agent", "credential", "set", name, "--from-file", str(key_file))
    state["ready"] = True


def direct(argv, **fields):
    """A run sent straight to the fake (a fixture made on the runtime), forked from `main`; its `exited` entry."""
    rt, = need("rt")
    rid, name = "run_" + os.urandom(32).hex(), "fixture." + os.urandom(4).hex()
    status, body = rt.api("POST", "/v1/runs", {
        "run_id": rid, "argv": argv, "cwd": "/workspace", "env": {}, "workspace_archive": None,
        "resources": {"cpus": 1, "memory_mib": 128, "timeout_seconds": 60}, "results": "none",
        "peerfs_workspace": name, "peerfs_fork_from": "main", **fields})
    check(status == 201, f"a run on the fake: {status} {body}")
    done = exited(rid)
    out = rt.api("GET", f"/v1/runs/{rid}/events")[1]
    done["stdout"] = b"".join(base64.b64decode(e["data"]) for e in out if e["kind"] == "stdout").decode()
    done["workspace"] = name
    return done


def sh(text):
    return ["/bin/sh", "-c", text]


@suite.case("fake_runtime_cache_fields", "cache Verification (the fake runtime: both fields, peerfs_caches, the cache "
                                         "a fork was given, cache_saved); cache Runtime: two run fields")
def _():
    rt, = need("rt")
    need("ready")
    check(rt.api("GET", "/v1/runtime")[1].get("peerfs_caches") is True, "the fake reports peerfs_caches false")
    name = "bc-fixture"
    save = {"peerfs_cache": name, "peerfs_cache_save": name}
    base = {"run_id": "cache_" + os.urandom(16).hex(), "argv": sh("echo x"), "cwd": "/workspace", "env": {},
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
    done = direct(sh(BUILD), **save)
    result = done["result"]
    current = stored(name)
    check(done["started"] and result["exit_code"] == 0 and result["error"] is None and result["cache_saved"] is True
          and result["commit"] is None, f"a refresh: {result}")
    check(current and current["commit"] == head() and current["bytes"] == len("built") + len("crate"),
          f"the saved version {current}, head {head()}")
    check(not workspace(done["workspace"]).exists() and direct(["echo", "x"], peerfs_fork_from=done["workspace"])
          ["started"] is False, "the refresh's workspace or branch was kept")
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
    changed = direct(sh("write target/app.o v2 ; write b.rs x ; write Z.rs y"), **save)
    check(changed["result"]["cache_saved"] is False and changed["result"]["exit_code"] == 0
          and changed["result"]["error"] == "the build changed source files: Z.rs" and stored(name) == current
          and not workspace(changed["workspace"]).exists(), f"a refresh that changed source: {changed['result']}")
    failed = direct(sh("write target/app.o v3 ; exit 2"), **save)
    check(failed["result"]["cache_saved"] is False and failed["result"]["error"] is None and stored(name) == current
          and not workspace(failed["workspace"]).exists(), f"a failed refresh: {failed['result']}")
    again = direct(sh("cat target/app.o ; write target/app.o v4"), **save)
    check(again["stdout"] == "built" and again["result"]["cache_saved"] is True and stored(name)["version"] == 2,
          f"an incremental refresh: {again}")
    fake(peerfs_caches=0)
    try:
        check(rt.api("GET", "/v1/runtime")[1].get("peerfs_caches") is False, "--peerfs-caches 0")
        for field in save:
            status, body = rt.api("POST", "/v1/runs", {**base, field: name})
            refused(status, body, 400, "invalid", field)
    finally:
        fake()


# Host: the profile's build cache (cache Host).

@suite.case("profile_build_cache", "cache Host: build_cache (command 1 to 4,096 bytes, interval_seconds 60 to 86,400, "
                                   "default 600); --build-cache, --build-cache-interval needing --build-cache")
def _():
    a, = need("a")
    need("ready")
    path = f"/v1/agents/{agent_id('plain')}/runtime"
    check(profile("plain").get("build_cache") is None, "a profile without build_cache")
    value = profile("plain", "--build-cache", "cargo build --tests")
    check(value.get("build_cache") == {"command": "cargo build --tests", "interval_seconds": 600},
          f"--build-cache with the default interval: {value.get('build_cache')}")
    value = profile("plain", "--build-cache", "make all", "--build-cache-interval", "90s")
    check(value.get("build_cache") == {"command": "make all", "interval_seconds": 90}, f"an interval: {value}")
    status, shown = a.api("GET", path)
    check(status == 200 and shown.get("build_cache") == value["build_cache"], f"show: {status} {shown}")
    check(profile("plain").get("build_cache") is None, "a replacement without --build-cache kept build_cache")
    for flags in (("--build-cache-interval", "90s"), ("--build-cache", "make", "--build-cache-interval", "59s"),
                  ("--build-cache", "")):
        result, _ = set_profile("plain", *flags)
        check(not result.ok, f"agent runtime set {flags} succeeded")
    body = {"harness": "codex", "harness_dir": str(state["harness"])}
    for cache, want in (({"command": "é" * 2048}, 600), ({"command": "x", "interval_seconds": 60}, 60),
                        ({"command": "x", "interval_seconds": 86400}, 86400)):
        status, answer = a.api("PUT", path, {**body, "build_cache": cache})
        check(status == 200 and answer.get("build_cache") == {"command": cache["command"], "interval_seconds": want},
              f"build_cache {str(cache)[:40]}: {status} {str(answer)[:300]}")
    for cache in ({"command": ""}, {"command": "é" * 2049}, {"command": "x" * 4097}, {"interval_seconds": 60},
                  {"command": 5}, {"command": "x", "interval_seconds": 59},
                  {"command": "x", "interval_seconds": 86401}):
        status, answer = a.api("PUT", path, {**body, "build_cache": cache})
        check(400 <= status < 500, f"build_cache {str(cache)[:40]}: {status} {str(answer)[:200]}")
    status, answer = a.api("GET", path)
    check(answer.get("build_cache") == {"command": "x", "interval_seconds": 86400}, f"a refusal changed it: {answer}")
    status, answer = a.api("PUT", path, {**body, "build_cache": None})
    check(status == 200 and answer.get("build_cache") is None, f"build_cache null: {status} {answer}")


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
        check(status == 200 and answer.get("build_cache") is None and answer.get("cpus") == value["cpus"],
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
    seeded = direct(sh("write target/seed.o seeded"), peerfs_cache=main, peerfs_cache_save=main)
    check(seeded["result"]["cache_saved"], f"fixture: a cache made on the runtime: {seeded['result']}")
    build = ("--build-cache", "write target/t.o x", "--build-cache-interval", "86400s")
    profile("codex", *build)
    profile("codex2", *build)
    profile("imaged", "--image", IMAGE, *build)
    profile("devcache", "--from-branch", "dev", *build)
    # The names written out: SHA-256 of from_branch, a NUL byte and the image, empty when null (the profiles of
    # one branch and image share a name).
    want = {"codex": "bc-" + hashlib.sha256(b"main\0").hexdigest()[:32],
            "codex2": "bc-" + hashlib.sha256(b"main\0").hexdigest()[:32],
            "imaged": "bc-" + hashlib.sha256(b"main\0" + IMAGE.encode()).hexdigest()[:32],
            "devcache": "bc-" + hashlib.sha256(b"dev\0").hexdigest()[:32], "plain": None}
    tasks = {name: send(name, "cat target/seed.o") for name in want}
    try:
        for name, task_id in tasks.items():
            found = events(task_id)
            body = task_body(task_id)
            check(body.get("peerfs_cache") == want[name] and body.get("peerfs_cache_save") is None,
                  f"{name}: peerfs_cache {body.get('peerfs_cache')!r} save {body.get('peerfs_cache_save')!r}, "
                  f"want {want[name]!r}")
            logged = rt.entries("fork_cache", body["run_id"])
            fork = f"{name}.{task_id}"
            if name in ("codex", "codex2"):
                check(logged and logged[0]["commit"] == stored(main)["commit"], f"{name}: the fork's cache {logged}")
                check(found[-1]["kind"] == "succeeded" and found[-1]["output"]
                      == f"seeded\n\nBranch: {fork}, unchanged from main", f"{name}: {found[-1].get('output')!r}")
            elif name == "plain":
                check(not logged and found[-1]["kind"] == "failed", f"plain: {logged} {kinds_of(found)}")
            else:  # a cache that does not exist is no error: the task builds cold (or on a refresh's version)
                now = stored(want[name])
                check(logged and logged[0]["commit"] in (None, now and now["commit"]) and found[-1]["kind"] == "failed"
                      and found[-1]["output"].endswith(f"Branch: {fork}, unchanged from "
                                                       f"{'dev' if name == 'devcache' else 'main'}"),
                      f"{name}: {logged} {found[-1].get('output')!r}")
        plain, codex = task_body(tasks["plain"]), task_body(tasks["codex"])
        same = ("argv", "cwd", "env", "resources", "network", "workspace_archive", "results", "peerfs_fork_from",
                "peerfs_commit", "peerfs_discard", "harness", "stdin")
        check(set(codex) - {"peerfs_cache"} == set(plain) - {"peerfs_cache"}
              and all(codex.get(k) == plain.get(k) for k in same) and codex.get("image") is None
              and task_body(tasks["imaged"]).get("image") == IMAGE,
              f"a task with build_cache differs beyond peerfs_cache: {sorted(set(codex) ^ set(plain))}")
    finally:
        for name in ("codex", "codex2", "imaged", "devcache"):
            profile(name)


@suite.case("cache_show_without_build_cache", "cache Host: cache show is 404 for an agent without build_cache")
def _():
    a, = need("a")
    need("ready")
    profile("plain")
    for name in ("plain", "noprofile"):
        status, body = show(name)
        check(status == 404, f"cache show for {name}: {status} {body}")
        result = a.cli("--json", "agent", "runtime", "cache", "show", name)
        check(not result.ok, f"agent runtime cache show {name}: {result.json}")


# The host refresh (cache The host refresh). Each needs the host to read the runtime's peerfs (question 1).

@suite.case("refresh_first_and_request", "cache The host refresh (a cache that does not exist; what a refresh run "
                                         "has; the stored last refresh); cache show (CLI, both routes); activity")
def _():
    blocked()
    a, rt = need("a", "rt")
    need("ready")
    name = cache_name("main", IMAGE)
    shutil.rmtree(workspace(".caches") / name, ignore_errors=True)
    count = len(refresh_ids(name))
    profile("imaged", "--image", IMAGE, "--network", "none", "--cpus", "3", "--memory-mib", "3072", "--timeout",
            "300s", "--build-cache", BUILD)
    status, shown = show("imaged")
    check(status == 200 and shown.get("name") == name and shown.get("commit") is None and shown.get("saved_at") is None
          and shown.get("bytes") is None, f"cache show before any refresh: {status} {shown}")
    at_main = head()
    rid = expect_refresh(name, "for a profile whose cache does not exist", count)
    state["first_start"] = suite.offset
    body = refresh_body(rid)
    want = {"argv": sh(BUILD), "cwd": "/workspace", "env": {}, "network": "none", "image": IMAGE,
            "resources": {"cpus": 3, "memory_mib": 3072, "timeout_seconds": 300},
            "peerfs_workspace": f"{name}.refresh.{rid[len('cache_'):]}", "peerfs_fork_from": "main",
            "peerfs_cache": name, "peerfs_cache_save": name, "results": "none", "workspace_archive": None}
    wrong = {k: body.get(k) for k, v in want.items() if body.get(k) != v}
    check(REFRESH_ID.match(rid) and not wrong, f"the refresh run {rid} differs from the contract: {wrong}")
    check(body.get("stdin") is None and body.get("peerfs_commit", False) is False and body.get("harness") is None
          and body.get("secrets") is None, f"stdin, peerfs_commit, harness or secrets: {body}")
    check(exited(rid)["result"]["cache_saved"] is True, "the refresh saved nothing")
    last = ended("imaged", rid)
    current = stored(name)
    check(current["commit"] == at_main and last["commit"] == at_main and last.get("saved") is True
          and last.get("reason") is None and parse_time(last["ended_at"]) >= parse_time(last["started_at"]),
          f"the stored last refresh {last}")
    status, shown = show("imaged")
    check(status == 200 and shown["name"] == name and shown["commit"] == current["commit"]
          and shown["bytes"] == current["bytes"] and parse_time(shown["saved_at"]) == parse_time(current["saved_at"]),
          f"cache show {shown}, the runtime's {current}")
    check(cli_json("agent", "runtime", "cache", "show", "imaged") == shown, "cache show on the CLI differs")
    status, every = a.api("GET", "/v1/agents/runtime/cache")
    check(status == 200 and name in json.dumps(every) and rid in json.dumps(every), f"every cache: {status} {every}")
    entries = [e for e in activity("runtime.cache_refreshed") if agent_id("imaged") in json.dumps(e)]
    check(entries and at_main in json.dumps(entries[-1]) and "true" in json.dumps(entries[-1]),
          f"runtime.cache_refreshed: {entries}")
    no_refresh(name, "with the branch's head at the cache's commit")
    state["refreshed"] = True


@suite.case("refresh_when", "cache The host refresh: the head moved, interval_seconds, one refresh per cache, a free "
                            "slot, no task queued, max_runs")
def _():
    blocked()
    need("refreshed")
    name = cache_name("main", IMAGE)
    moved = move_head()
    no_refresh(name, "within interval_seconds (600) of the last start")
    count = len(refresh_ids(name))
    suite.set_offset(state["first_start"] + 600)
    rid = expect_refresh(name, "once the head moved and interval_seconds passed", count)
    check(exited(rid)["result"]["cache_saved"] and stored(name)["commit"] == moved, "the refresh of the new head")
    flags = ("--image", IMAGE, "--build-cache", BUILD, "--build-cache-interval", "60s")
    for setup, why in (
            (lambda: [profile("imaged", "--max-runs", "1", *flags), held("imaged")][1:],
             "with the profile's max_runs dispatched"),
            (lambda: [profile("imaged", *flags), profile("codex2"), held("codex2"), held("codex2")][2:],
             "with no free slot"),
            (lambda: [profile("codex2", "--max-runs", "1"), held("codex2"), waiting("codex2")][1:],
             "while a runtime agent's task was queued")):
        tasks = setup()
        move_head()
        no_refresh(name, why)
        count = len(refresh_ids(name))
        finished(*tasks)
        exited(expect_refresh(name, f"once the condition cleared ({why})", count))
    profile("imaged", "--image", IMAGE, "--build-cache", "sleep 10 ; write target/app.o slow",
            "--build-cache-interval", "60s")
    move_head()
    rid = expect_refresh(name, "for a slow build")
    move_head()
    no_refresh(name, "while one was running")
    status, body = state["a"].api("POST", f"/v1/agents/{agent_id('imaged')}/runtime/cache/refresh", {})
    refused(status, body, 409, "busy")
    check(exited(rid)["result"]["cache_saved"], "the slow refresh saved nothing")


@suite.case("refresh_by_hand", "cache The host refresh: cache refresh (at the next check, ignoring interval_seconds "
                               "and an unchanged head, not the other conditions; returns {})")
def _():
    blocked()
    need("refreshed")
    name = cache_name("main", IMAGE)
    if stored(name)["commit"] != head():
        count = len(refresh_ids(name))
        profile("imaged", "--image", IMAGE, "--build-cache", BUILD, "--build-cache-interval", "60s")
        exited(expect_refresh(name, "to catch up with the head", count))
    profile("imaged", "--image", IMAGE, "--max-runs", "1", "--build-cache", BUILD)
    no_refresh(name, "with the head unchanged")
    count = len(refresh_ids(name))
    check(cli_json("agent", "runtime", "cache", "refresh", "imaged") == {}, "cache refresh returns {}")
    rid = expect_refresh(name, "asked by hand with the head unchanged", count)
    check(exited(rid)["result"]["cache_saved"] and ended("imaged", rid).get("saved") is True, "the refresh by hand")
    task = held("imaged", "sleep 6")
    status, body = state["a"].api("POST", f"/v1/agents/{agent_id('imaged')}/runtime/cache/refresh", {})
    check(status == 200 and body == {}, f"POST .../cache/refresh: {status} {body}")
    no_refresh(name, "by hand with the profile's max_runs dispatched")
    count = len(refresh_ids(name))
    finished(task)
    exited(expect_refresh(name, "by hand within interval_seconds of the last start, once the task ended", count))


@suite.case("refresh_reasons", "cache The host refresh: the stored last refresh when nothing was saved (exit N, "
                               "signal N, timed out, the run result's error); runtime.cache_refreshed saved false")
def _():
    blocked()
    need("refreshed")
    name = cache_name("main", IMAGE)
    before = stored(name)
    for command, flags, reason in (("exit 3", (), "exit 3"), ("kill 9", (), "signal 9"),
                                   ("sleep 5", ("--timeout", "1s"), "timed out"),
                                   ("write target/app.o v ; write a.rs y ; write Z.rs x", (),
                                    "the build changed source files: Z.rs")):
        profile("imaged", "--image", IMAGE, "--build-cache", command, *flags)
        count = len(refresh_ids(name))
        cli_json("agent", "runtime", "cache", "refresh", "imaged")
        rid = expect_refresh(name, f"by hand for {command!r}", count)
        last = ended("imaged", rid)
        check(last.get("saved") is False and last.get("reason") == reason and stored(name) == before,
              f"{command!r}: the stored last refresh {last}, want reason {reason!r}; cache {stored(name)}")
    entries = [e for e in activity("runtime.cache_refreshed") if agent_id("imaged") in json.dumps(e)]
    check(entries and "false" in json.dumps(entries[-1]), f"runtime.cache_refreshed saved false: {entries[-1:]}")


@suite.case("cache_clear", "cache Host: cache clear (DELETE .../runtime/cache: cache rm on the runtime's peerfs; {}; "
                           "tasks build cold)")
def _():
    blocked()
    a, rt = need("a", "rt")
    need("refreshed")
    name = cache_name("main", IMAGE)
    profile("imaged", "--image", IMAGE, "--build-cache", BUILD, "--build-cache-interval", "86400s")
    check(stored(name) is not None, "fixture: no cache to clear")
    status, body = a.api("DELETE", f"/v1/agents/{agent_id('imaged')}/runtime/cache")
    check(status == 200 and body == {} and stored(name) is None, f"DELETE .../runtime/cache: {status} {body}; "
                                                                 f"the runtime's cache {stored(name)}")
    status, shown = show("imaged")
    check(status == 200 and shown["name"] == name and shown["commit"] is None and shown["saved_at"] is None
          and shown["bytes"] is None and last_refresh(shown), f"cache show after clear: {shown}")
    task_id = send("imaged", "echo cold")
    events(task_id)
    logged = rt.entries("fork_cache", task_body(task_id)["run_id"])
    check(logged and logged[0]["commit"] is None, f"a task after clear was given a cache: {logged}")


@suite.case("refresh_restarts", "cache The host refresh: a refresh lost to a runtime restart (the runtime restarted); "
                                "a host restart resumes the stored run; cache clear on the CLI")
def _():
    blocked()
    a, rt = need("a", "rt")
    need("refreshed")
    name = cache_name("main", IMAGE)
    for command, why in (("sleep 20", "to be lost"), ("sleep 4 ; write target/app.o resumed", "to resume")):
        profile("imaged", "--image", IMAGE, "--build-cache", command)
        count = len(refresh_ids(name))
        cli_json("agent", "runtime", "cache", "refresh", "imaged")
        rid = expect_refresh(name, why, count)
        wait_for(lambda: rt.entries("started", rid), timeout=10, message="the refresh to start")
        if command == "sleep 20":
            fake()
            last = ended("imaged", rid, timeout=40)
            check(last.get("saved") is False and last.get("reason") == "the runtime restarted",
                  f"a lost refresh: {last}")
        else:
            a.stop(kill=True)
            a.start()
            last = ended("imaged", rid, timeout=40)
            sent = [b for _, b in requests() if b.get("run_id") == rid]
            check(last.get("saved") is True and stored(name)["commit"] == head() and all(b == sent[0] for b in sent),
                  f"a refresh across a host restart: {last}; {len(sent)} starts")
    check(cli_json("agent", "runtime", "cache", "clear", "imaged") == {} and stored(name) is None,
          "agent runtime cache clear")


@suite.case("build_cache_removed", "cache Host: removing build_cache, or the profile, stops refreshes; the cache stays")
def _():
    blocked()
    need("refreshed")
    name, main = cache_name("main", IMAGE), cache_name("main")
    count = len(refresh_ids(main))
    profile("codex2", "--build-cache", BUILD, "--build-cache-interval", "60s")
    exited(expect_refresh(main, "for codex2, whose cache's commit is behind the head", count))
    profile("imaged", "--image", IMAGE, "--build-cache", BUILD, "--build-cache-interval", "60s")
    profile("imaged")
    cli_json("agent", "runtime", "clear", "codex2")
    move_head()
    no_refresh(name, "after build_cache was removed from the profile")
    no_refresh(main, "after the profile was cleared")
    check(stored(main) is not None and show("imaged")[0] == 404, "the cache went, or cache show still answers")


suite.finish()
