"""Shared fixtures of the build cache slim suites (runtime_build_cache, runtime_build_cache_refresh and
runtime_build_cache_outcomes), written from docs/build-cache-contract.md only (cited as "cache <section>").

alice creates a coordinator-free network and bob joins as another person. alice's host serves through
conformance/slim/fake_runtime.py, started with the peerfs workspaces `main` and `dev`, two run slots and `--requests`,
so a suite sees each `POST /v1/runs` body as the host sent it. alice registers the agents `codex`, `codex2`, `imaged`,
`devcache`, `plain` and `noprofile`; each but `noprofile` gets a profile and a key, and bob sends them tasks under
`task.submit` grants. Every host is on one debug test clock (DEC-OWN9 question 2), which a suite moves 61 seconds to
reach the host's next refresh check ("checking when it starts and every 60 seconds after by its clock (the test
clock, in a debug build)").

The fake classes paths under `target/`, `node_modules/` and `.peerspan/cache/` as derived and all others as source;
`main`'s head is `01` and the SHA-256 of its source paths and contents (`fake_runtime.branch_head`), so writing a
source file into the `main` directory moves it. A refresh's `argv` `["/bin/sh", "-c", COMMAND]` runs COMMAND as the
fake's steps, so `--build-cache "write target/app.o built"` is a build that writes output. A suite calls `bind(suite)`
and `suite.use_clock()` before its first case, then `setup()` in its first case.
"""
import base64
import hashlib
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone

from fake_runtime import branch_head
from harness import check, rfc3339, wait_for
from runtime_common import has_kind, need, new_task_id, receiver_events, run_id, setup_network, state
import runtime_common

FAKE = {"peerfs_workspace": ["main", "dev"], "max_concurrent_runs": 2, "max_cpus": 4, "max_memory_mib": 8192,
        "max_seconds": 7200}
IMAGE = "registry.example/peerspan/rust@sha256:" + "a" * 64
BUILD = "write target/app.o built ; write .peerspan/cache/cargo/registry/crate.txt crate ; echo built"
SHOW_KEYS = {"agent_id", "name", "commit", "saved_at", "bytes", "last_refresh"}  # cache Host, cache show
LAST_KEYS = {"started_at", "run_id", "commit", "ended_at", "saved", "reason"}  # cache The host refresh
RUN_ID = re.compile(r"^run_[0-9a-f]{64}$")  # every run's ID, a refresh's included (RUN-22)
CHECK_WAIT = 8  # real seconds for the check after the clock moves 61 s
QUIET = 2  # real seconds watched for a refresh that must not start
suite = None


def bind(the_suite):
    global suite
    suite = the_suite
    runtime_common.bind(the_suite)


def cache_name(from_branch="main", image=None):
    """cache The cache's name: `bc-` and the first 32 hex digits of SHA-256(from_branch, NUL, image or empty)."""
    return "bc-" + hashlib.sha256(from_branch.encode() + b"\0" + (image or "").encode()).hexdigest()[:32]


RFC3339_UTC = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:[Zz]|\+00:00|-00:00)$")


def utc_time(text):
    """An RFC 3339 UTC time, with or without fractional seconds (the contract fixes no precision); fractions beyond
    microseconds are cut. Fails the case for anything else."""
    found = RFC3339_UTC.match(text) if isinstance(text, str) else None
    check(found is not None, f"not an RFC 3339 UTC time: {text!r}")
    *parts, fraction = found.groups()
    micro = int((fraction or "0")[:6].ljust(6, "0"))
    return datetime(*map(int, parts), micro, tzinfo=timezone.utc)


def tail(text):
    return text.strip()[-300:]


def agent_id(name):
    return state["agents"][name]["id"]


def fake(**override):
    """(Re)start alice's fake runtime with the suites' options and OVERRIDE; workspaces and caches are kept."""
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


def requests():
    """[(status, body)] of every POST /v1/runs the fake saw, from its --requests file."""
    out = []
    path = state["requests"]
    for line in path.read_text().splitlines() if path.exists() else []:
        entry = json.loads(line)
        try:
            body = json.loads(entry["body"])
        except ValueError:
            continue
        if isinstance(body, dict):
            out.append((entry["status"], body))
    return out


def task_body(task_id):
    rid = run_id(state["b"], task_id)
    found = [b for s, b in requests() if b.get("run_id") == rid]
    check(found, f"the runtime saw no start for {task_id}")
    return found[0]


def refresh_ids(name, status=201):
    """The distinct refresh run IDs whose `peerfs_cache_save` is NAME and that the fake answered STATUS (None: any),
    in the order first sent."""
    seen = []
    for answered, body in requests():
        rid = body.get("run_id")
        if (isinstance(rid, str) and body.get("peerfs_cache_save") == name  # a refresh, by its fields (RUN-22)
                and (status is None or answered == status) and rid not in seen):
            seen.append(rid)
    return seen


def refresh_body(rid):
    return next(b for s, b in requests() if b.get("run_id") == rid and s == 201)


def workspace(name):
    return state["rt"].dir / "peerfs" / name


def head(branch="main"):
    return branch_head(workspace(branch))


def move_head():
    """A new source file on `main`: its head moves."""
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


def count(name):
    return len(refresh_ids(name))


def expect_refresh(name, why, since=None, move=True):
    """Move the clock to the next check (MOVE) and return the refresh of NAME it starts: the first after SINCE
    (default: those started so far). Take SINCE before the condition clears, since a real-time check may come
    first."""
    since = count(name) if since is None else since
    if move:
        tick()
    wait_for(lambda: count(name) > since, timeout=CHECK_WAIT, interval=0.2, message=f"a refresh of {name} {why}")
    rid = refresh_ids(name)[since]
    named = refresh_body(rid).get("peerfs_workspace")
    check(RUN_ID.match(rid) and named == f"{name}.refresh.{rid[len('run_'):]}",
          f"a refresh's run_id {rid!r} is not run_ and 64 lowercase hex digits (RUN-22), or its workspace "
          f"{named!r} is not {name}.refresh. and those digits")
    return rid


def no_refresh(name, why):
    before = len(refresh_ids(name, None))
    tick()
    time.sleep(QUIET)
    check(len(refresh_ids(name, None)) == before, f"a refresh of {name} was sent {why}")


def exited(rid, timeout=30):
    rt, = need("rt")
    return wait_for(lambda: rt.entries("exited", rid), timeout=timeout, message=f"{rid} to end")[-1]


def show(name):
    return state["a"].api("GET", f"/v1/agents/{agent_id(name)}/runtime/cache")


def shown(name):
    status, body = show(name)
    check(status == 200 and isinstance(body, dict) and set(body) == SHOW_KEYS
          and body["agent_id"] == agent_id(name), f"cache show {name}: {status} {body}")
    last = body["last_refresh"]
    check(last is None or set(last) == LAST_KEYS, f"last_refresh keys {sorted(last or {})}, want {sorted(LAST_KEYS)}")
    return body


def ended(name, rid, timeout=20):
    """The stored last refresh of NAME once the refresh RID has ended (`ended_at` set)."""
    def done():
        last = shown(name)["last_refresh"]
        return last if last and last["run_id"] == rid and last["ended_at"] else None
    last = wait_for(done, timeout=timeout, interval=0.3, message=f"the stored end of {rid}")
    check(isinstance(last["saved"], bool) and (last["reason"] is None) == last["saved"],
          f"saved and reason of an ended refresh: {last}")
    return last


def refresh_by_hand(name, api=False):
    if api:
        status, body = state["a"].api("POST", f"/v1/agents/{agent_id(name)}/runtime/cache/refresh", {})
        check(status == 200 and body == {}, f"POST .../runtime/cache/refresh: {status} {body}")
    else:
        check(cli_json("agent", "runtime", "cache", "refresh", name) == {}, "agent runtime cache refresh returns {}")


def subjects(kind="runtime.cache_refreshed"):
    status, body = state["a"].api("GET", "/v1/activity?limit=1000")
    check(status == 200 and isinstance(body, list), f"GET /v1/activity: {status} {str(body)[:200]}")
    return [e.get("subject_id") for e in body if e.get("kind") == kind]


def sh(text):
    return ["/bin/sh", "-c", text]


def direct(argv, **fields):
    """A run sent straight to the fake (a fixture made on the runtime), forked from `main`: its `exited` entry, with
    `stdout` and `workspace` added."""
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


def seed(name, command="write target/seed.o seeded"):
    """A cache NAME made on the runtime by a refresh sent straight to it, at `main`'s head."""
    done = direct(sh(command), peerfs_cache=name, peerfs_cache_save=name)
    check(done["result"]["cache_saved"], f"fixture: a cache made on the runtime: {done['result']}")
    return stored(name)


def setup():
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
