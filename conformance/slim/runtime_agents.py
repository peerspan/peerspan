#!/usr/bin/env python3
"""Slim suite, runtime_agents: an agent's tasks run by the host, each in a microVM on a peerfs fork (RUN-8 to RUN-11).

alice creates a coordinator-free network, bob joins as another person and alice links a second machine, alice2.
alice's host serves through conformance/slim/fake_runtime.py, started with the peerfs workspaces `main` and `dev`,
two run slots and `--requests`, so the suite sees each `POST /v1/runs` body as the host sent it. alice registers
the agents `codex`, `codex2`, `late` and `claude`; bob sends them tasks under `task.submit` grants and alice2 under self
access. With `harness` set the fake ignores `argv` and runs the task's input, the prompt, as steps, so a prompt
`write notes.txt hello ; echo done` changes the fork and answers `done`. The rest of the runtime is the other
runtime_* suites; the shared fixtures are runtime_common.py.

The second harness and per-profile images (RUN-12, RUN-13): `claude` gets its own harness directory and an Anthropic
key, and the fake is also started with `--unpullable-image`, naming one image it cannot pull. The cases that need
the host's `--harness claude` and `--image` are strict expected failures until the host implements them.

Written from docs/runtime-agent-contract.md only (cited as "agents <section>"), with the runtime task, task and
launch contracts it builds on. No VM, no KVM, no peerfs, no model calls.
"""
import base64
import json
import os
import re
import shutil
import sqlite3
from datetime import timedelta

from harness import Suite, check, peer, rfc3339, wait_for
from runtime_common import (FakeRuntime, bind, cancel, has_kind, need, new_task_id, peer_submit, receiver_events,
                            refused, run_id, setup_network, state)

suite = Suite("runtime_agents", __doc__)
bind(suite)
COMMIT = re.compile(r"^[0-9a-f]{66}$")  # a peerfs object ID (agents, The output)
MAIN_SCHEMA = 30  # the schema version on main when this suite was written; the contract adds the next one
MISSING_IMAGE = "registry.invalid/peerspan/missing:1"  # the fake cannot pull it
GLIBC_IMAGE = "python:3.12-slim"
FAKE = {"peerfs_workspace": ["main", "dev"], "max_concurrent_runs": 2, "max_cpus": 4, "max_memory_mib": 8192,
        "max_seconds": 7200, "unpullable_image": [MISSING_IMAGE]}
CLAUDE_GAP = "Claude harness and images not implemented (runtime-agent-contract.md, RUN-12/RUN-13)"
DEFAULTS = {"harness": "codex", "from_branch": "main", "network": "internet", "cpus": 2, "memory_mib": 2048,
            "timeout_seconds": 3600, "max_runs": 3}


def tail(text):
    return text.strip()[-300:]


def fake(**override):
    """(Re)start alice's fake runtime with the suite's options and OVERRIDE; forks are kept."""
    rt = state["rt"]
    rt.restart(**{**FAKE, "requests": str(state["requests"]), **override})
    return rt


def agent_id(name):
    return state["agents"][name]["id"]


def profile(name, *flags, harness=None):
    """`agent runtime set NAME --harness-dir DIR FLAGS...` on alice's host; returns the profile."""
    a, = need("a")
    result = a.cli("--json", "agent", "runtime", "set", name, "--harness-dir", str(harness or state["harness"]), *flags)
    check(result.ok and isinstance(result.json, dict),
          f"agent runtime set {name} {' '.join(flags)}: exit {result.code} {tail(result.stderr)}")
    return result.json


def credential(name, key_file=None):
    a, = need("a")
    result = a.cli("--json", "agent", "credential", "set", name, "--from-file", str(key_file or state["key_file"]))
    check(result.ok and result.json == {"agent_id": agent_id(name), "credential": True},
          f"agent credential set {name}: exit {result.code} {result.json} {tail(result.stderr)}")
    return result


def ready(name, *flags):
    """NAME as a runtime agent: a profile with FLAGS and the stored key."""
    value = profile(name, *flags)
    credential(name)
    return value


def bare(value):
    """A profile without `image` (RUN-12), so the cases written before it hold whether or not the host reports it."""
    return {k: v for k, v in value.items() if k != "image"} if isinstance(value, dict) else value


def clear(*args):
    a, = need("a")
    result = a.cli("--json", *args)
    check(result.ok, f"{' '.join(args)}: exit {result.code} {tail(result.stderr)}")
    return result.json


def send(name, prompt, sender=None, task_id=None):
    """An ordinary agent task to alice's agent NAME: bob's under his grant, alice2's under self access."""
    a, b = need("a", "b")
    sender = sender or b
    body = {"peer_host_id": a.id, "target_agent_id": agent_id(name), "input": prompt,
            "task_id": task_id or new_task_id()}
    if sender is b:
        body["grant_id"] = state["grants"][name]
    status, record = sender.api("POST", "/v1/tasks", body)
    check(status in (200, 201), f"{sender.name}: POST /v1/tasks to {name}: {status} {record}")
    return body["task_id"]


def accepted(task_id, sender=None):
    return wait_for(lambda: (r := (sender or state["b"]).api("GET", f"/v1/tasks/{state['a'].id}/{task_id}")[1])
                    and r.get("submit_state") == "accepted" and r, timeout=30, message=f"{task_id} accepted")


def events(task_id, sender=None, until=None, timeout=30):
    found = receiver_events(task_id, until=until, timeout=timeout, sender=sender or state["b"])
    for event in found:
        check("chunk" not in event and event["kind"] not in ("output", "progress"),
              f"a runtime agent's events are agent task events (no chunk, output or progress): {event}")
    return found


def kinds(found):
    return [e["kind"] for e in found]


def fork(task_id, name="codex"):
    return f"{name}.{task_id}"


def split(event):
    """(message, last line) of a final event's output (agents, The output)."""
    text = event.get("output")
    check(isinstance(text, str) and "\n\n" in text, f"the {event['kind']} output is not MESSAGE, a blank line and "
                                                    f"a branch line: {text!r}")
    message, _, trailer = text.rpartition("\n\n")
    check("\n" not in trailer, f"the branch line is not the last line: {text[-300:]!r}")
    return message, trailer


def exited(task_id, sender=None):
    rt, b = need("rt", "b")
    found = wait_for(lambda: rt.entries("exited", run_id(sender or b, task_id)), timeout=10,
                     message="the runtime's exit")
    return found[-1]["result"]


def at(event, task_id, sender=None):
    found = state["rt"].entries(event, run_id(sender or state["b"], task_id))
    return found[0]["at"] if found else None


def posts(task_id, sender=None):
    """[(status, raw body, body)] of each POST /v1/runs for TASK_ID, from the fake's --requests file."""
    rid = run_id(sender or state["b"], task_id)
    path = state["requests"]
    out = []
    for line in path.read_text().splitlines() if path.exists() else []:
        entry = json.loads(line)
        try:
            body = json.loads(entry["body"])
        except ValueError:
            continue
        if isinstance(body, dict) and body.get("run_id") == rid:
            out.append((entry["status"], entry["body"], body))
    return out


def workspace(name):
    return state["rt"].dir / "peerfs" / name


def activity_kinds():
    status, body = state["a"].api("GET", "/v1/activity?limit=1000")
    check(status == 200 and isinstance(body, list), f"GET /v1/activity: {status} {str(body)[:200]}")
    return [entry["kind"] for entry in body]


def key_nowhere(*answers, key=None, key_file=None):
    """The key appears in none of ANSWERS, no file of the hosts' homes and states (logs, databases, records)
    but alice's credentials/ directory, and none of the fake runtime's logs (agents, The launch profile)."""
    key, key_file = key or state["key"], key_file or state["key_file"]
    for answer in answers:
        check(key not in str(answer), f"the key appears in a response: {str(answer)[:200]}")
    leaks = []
    credentials = state["a"].state / "credentials"
    for path in suite.work.rglob("*"):  # every host's home and state, and the fake runtime's files and logs
        if path == key_file or credentials in path.parents or not path.is_file():
            continue
        try:
            if key.encode() in path.read_bytes():
                leaks.append(str(path))
        except OSError:
            pass
    check(not leaks, f"the key was written to {leaks}")


@suite.case("setup", "decentralized-spec 6, 8; runtime Runtime administration (PUT /v1/runtime); task-contract "
                     "Authorization (grants); launch-contract Self access")
def _():
    state["requests"] = suite.work / "alice-requests.jsonl"
    setup_network(second_machine=True, requests=str(suite.work / "alice-requests.jsonl"), **FAKE)
    a, a2, b, rt = need("a", "a2", "b", "rt")
    for name in ("main", "dev"):
        (workspace(name) / "README").write_text(f"{name} seed\n")
    status, body = a.api("PUT", "/v1/runtime", {"socket": str(rt.socket)})
    check(status == 200 and body.get("peerfs") is True and body.get("max_network") == "internet",
          f"the runtime switch: {status} {body}")
    owner = suite.work / "owner"
    harness = owner / "codex-release"
    harness.mkdir(parents=True)
    for binary in ("codex", "codex-code-mode-host"):
        (harness / binary).write_text("#!/bin/sh\nexit 0\n")
        (harness / binary).chmod(0o755)
    state["key"] = "sk-test-" + os.urandom(24).hex()
    key_file = owner / "openai.key"
    key_file.write_text(state["key"] + "\n")  # a trailing newline in the input is dropped
    claude = owner / "claude-release"  # Claude Code's single Linux x64 binary (RUN-12)
    claude.mkdir()
    (claude / "claude").write_text("#!/bin/sh\nexit 0\n")
    (claude / "claude").chmod(0o755)
    state["anthropic_key"] = "sk-ant-test-" + os.urandom(24).hex()
    anthropic_file = owner / "anthropic.key"
    anthropic_file.write_text(state["anthropic_key"] + "\n")
    state.update(harness=harness, key_file=key_file, agents={}, grants={}, claude_harness=claude,
                 anthropic_file=anthropic_file)
    for name in ("codex", "codex2", "late", "claude", "Bad Name"):
        status, agent = a.api("POST", "/v1/agents", {"name": name, "owner": "alice"})
        check(status in (200, 201), f"register {name}: {status} {agent}")
        state["agents"][name] = agent
    for name in ("codex", "codex2", "late", "claude"):
        grant = a.ok("grant", "create", "--peer", b.id, "--agent", agent_id(name), "--action", "task.submit",
                     "--expires-at", rfc3339(a.now() + timedelta(hours=6)))
        state["grants"][name] = grant["id"]
    # The fixtures work today: tasks to `late`, before it has a profile, are received under the grant and under
    # self access (the first half of receive_before_profile).
    state["late_tasks"] = [send("late", "before the profile"), send("late", "from alice2", sender=a2)]
    accepted(state["late_tasks"][0])
    accepted(state["late_tasks"][1], sender=a2)
    state["ready"] = True


@suite.case("fake_runtime_agent_fields", "agents Verification (the fake runtime); The runtime's local API")
def _():
    rt, = need("rt")
    status, report = rt.api("GET", "/v1/runtime")
    check(status == 200 and report["max_network"] == "internet", f"max_network: {report}")
    base = {"argv": ["ignored"], "cwd": "/workspace", "env": {}, "resources": {"cpus": 1, "memory_mib": 128,
            "timeout_seconds": 60}, "workspace_archive": None, "results": "none"}
    name = "fixture." + os.urandom(4).hex()

    def start(**fields):
        body = {**base, "run_id": "run_" + os.urandom(32).hex(), "peerfs_workspace": name, **fields}
        return rt.api("POST", "/v1/runs", body), body["run_id"]
    agent = {"harness": str(state["harness"]), "secrets": {"openai_api_key": str(state["key_file"])},
             "peerfs_fork_from": "main", "peerfs_agent": "codex", "peerfs_commit": True,
             "peerfs_commit_message": "fixture", "stdin": base64.b64encode(b"write a.txt b ; echo done").decode()}
    for label, fields in (("network", {"network": "lan"}), ("stdin", {"stdin": "%%"}), ("harness", {"harness": "x"}),
                          ("secrets", {"secrets": {"..": "/x"}}), ("peerfs_agent", {"peerfs_agent": "Bad"}),
                          ("peerfs_commit_message", {"peerfs_commit_message": ""}), ("unknown", {"surprise": 1})):
        (status, body), _ = start(**{**agent, **fields})
        check(status == 400 and body["code"] == "invalid", f"{label}: {status} {body}")
    (status, _), rid = start(**agent)
    check(status == 201, f"a harness run: {status}")
    done = wait_for(lambda: rt.entries("exited", rid), timeout=10, message="the harness run")[-1]
    check(done["started"] and done["result"]["error"] is None and COMMIT.match(done["result"]["commit"] or ""),
          f"the harness run: {done}")
    check((workspace(name) / "a.txt").read_text() == "b" and not (workspace("main") / "a.txt").exists(),
          "the fork does not hold the write, or main changed")
    out = rt.api("GET", f"/v1/runs/{rid}/events")[1]
    check(any(e["kind"] == "stdout" and base64.b64decode(e["data"]) == b"done\n" for e in out), f"events {out}")
    (status, _), rid = start(**agent)  # the name exists now
    check(status == 201 and not wait_for(lambda: rt.entries("exited", rid), message="refused fork")[-1]["started"],
          "a fork onto an existing name started")
    (status, _), rid = start(**{**agent, "secrets": {}, "peerfs_workspace": name + "x"})
    result = wait_for(lambda: rt.entries("exited", rid), message="no secret")[-1]["result"]
    check(status == 201 and "openai_api_key" in (result["error"] or ""), f"a harness run without the key: {result}")
    check(state["key"] not in state["requests"].read_text() + rt.log.read_text(), "the fake logged the key")


@suite.case("fake_runtime_images", "agents Verification (the fake runtime: images, image, the two harness secrets); "
                                   "The runtime's local API (image)")
def _():
    rt, = need("rt")
    status, report = rt.api("GET", "/v1/runtime")
    check(status == 200 and report.get("images") is True, f"images: {report}")
    base = {"argv": ["ignored"], "cwd": "/workspace", "env": {}, "resources": {"cpus": 1, "memory_mib": 128,
            "timeout_seconds": 60}, "workspace_archive": None, "results": "none", "harness": str(state["harness"]),
            "peerfs_fork_from": "main", "stdin": base64.b64encode(b"echo done").decode()}

    def run(**fields):
        body = {**base, "run_id": "run_" + os.urandom(32).hex(), "peerfs_workspace": "fixture." + os.urandom(4).hex(),
                **fields}
        status, answer = rt.api("POST", "/v1/runs", body)
        if status != 201:
            return status, answer
        return status, wait_for(lambda: rt.entries("exited", body["run_id"]), timeout=10, message="the run")[-1]
    anthropic = {"anthropic_api_key": str(state["anthropic_file"])}
    for image in ("", "a b", "x" * 1025, "caf\u00e9", 3):
        status, answer = run(image=image, secrets=anthropic)
        check(status == 400 and answer["code"] == "invalid", f"image {str(image)[:20]!r}: {status} {answer}")
    status, done = run(image=GLIBC_IMAGE, secrets=anthropic)
    check(status == 201 and done["started"] and done["result"]["error"] is None, f"an anthropic key alone: {done}")
    status, done = run(image=MISSING_IMAGE, secrets=anthropic)
    check(status == 201 and not done["started"] and MISSING_IMAGE in (done["result"]["error"] or ""),
          f"an image it cannot pull: {done}")
    status, done = run(secrets={**anthropic, "openai_api_key": str(state["key_file"])})
    error = done["result"]["error"] or ""
    check(status == 201 and not done["started"] and "openai_api_key" in error and "anthropic_api_key" in error,
          f"both harness secrets: {done}")
    sent = [json.loads(json.loads(line)["body"]) for line in state["requests"].read_text().splitlines()]
    check(any(b.get("image") == GLIBC_IMAGE for b in sent), "the fake did not record image")
    check(state["anthropic_key"] not in state["requests"].read_text() + rt.log.read_text(), "the fake logged the key")
    fake(images=0)
    try:
        status, report = rt.api("GET", "/v1/runtime")
        check(report.get("images") is False, f"--images 0: {report}")
        status, answer = run(image=GLIBC_IMAGE, secrets=anthropic)
        check(status == 422, f"an image on a runtime reporting images false: {status} {answer}")
    finally:
        fake()


# Profiles (agents, The launch profile).

@suite.case("profile_set_show_clear", "agents The launch profile: set (defaults, every option, replacement), show, "
                                      "clear; runtime-agents.json 0600; activity")
def _():
    a, = need("a")
    need("ready")
    codex = agent_id("codex")
    value = profile("codex")
    check(bare(value) == {"agent_id": codex, "harness_dir": str(state["harness"]), **DEFAULTS},
          f"a profile with defaults: {value}")
    stored = a.state / "runtime-agents.json"
    check(stored.is_file() and stored.stat().st_mode & 0o777 == 0o600, "runtime-agents.json (0600) missing")
    every = {"from_branch": "dev", "network": "none", "cpus": 3, "memory_mib": 3072, "timeout_seconds": 300,
             "max_runs": 2}
    value = profile(codex, "--from-branch", "dev", "--network", "none", "--cpus", "3", "--memory-mib", "3072",
                    "--timeout", "300s", "--max-runs", "2")
    check(bare(value) == {"agent_id": codex, "harness_dir": str(state["harness"]), **DEFAULTS, **every},
          f"every option, by agent ID: {value}")
    value = profile("codex")
    check(value["from_branch"] == "main" and value["cpus"] == 2 and value["max_runs"] == 3,
          f"a replacement takes defaults, not the previous values: {value}")
    status, body = a.api("PUT", f"/v1/agents/{codex}/runtime",
                         {"harness": "codex", "harness_dir": str(state["harness"]), **every})
    check(status == 200 and bare(body) == {"agent_id": codex, "harness_dir": str(state["harness"]), **DEFAULTS,
                                           **every},
          f"PUT /v1/agents/{{id}}/runtime: {status} {body}")
    status, body = a.api("GET", f"/v1/agents/{codex}/runtime")
    check(status == 200 and body.get("credential") is False and body.get("max_runs") == 2,
          f"show without a credential: {status} {body}")
    shown = a.cli("--json", "agent", "runtime", "show", "codex")
    check(shown.ok and shown.json == body, f"agent runtime show codex: {shown.json} {tail(shown.stderr)}")
    profile("codex2")
    status, every_profile = a.api("GET", "/v1/agents/runtime")
    listed = every_profile if isinstance(every_profile, list) else next(
        (v for v in (every_profile or {}).values() if isinstance(v, list)), None)
    check(status == 200 and listed is not None and [p["agent_id"] for p in listed] == sorted([codex, agent_id("codex2")])
          and all("credential" in p for p in listed), f"every profile in agent ID order: {status} {every_profile}")
    check(clear("agent", "runtime", "clear", "codex2") == {}, "agent runtime clear returns {}")
    status, body = a.api("GET", f"/v1/agents/{agent_id('codex2')}/runtime")
    check(status == 404, f"show after clear: {status} {body}")
    found = activity_kinds()
    check("runtime.agent_set" in found and "runtime.agent_cleared" in found, f"activity {found[-8:]}")


@suite.case("profile_refusals", "agents The launch profile: 409 runtime_unavailable (switch off, peerfs false), "
                                "422 over the runtime's maximums, a name that is not addressable")
def _():
    a, rt = need("a", "rt")
    need("ready")
    profile("codex2", "--cpus", "4")  # control: a profile at the runtime's maximum
    path = f"/v1/agents/{agent_id('codex2')}/runtime"
    body = {"harness": "codex", "harness_dir": str(state["harness"])}
    a.api("DELETE", "/v1/runtime")
    try:
        status, answer = a.api("PUT", path, body)
        refused(status, answer, 409, "runtime_unavailable")
    finally:
        a.api("PUT", "/v1/runtime", {"socket": str(rt.socket)})
    plain = FakeRuntime("plain").start()  # no peerfs workspaces: peerfs false
    try:
        check(a.api("PUT", "/v1/runtime", {"socket": str(plain.socket)})[0] == 200, "switch to the plain runtime")
        status, answer = a.api("PUT", path, body)
        refused(status, answer, 409, "runtime_unavailable")
    finally:
        a.api("PUT", "/v1/runtime", {"socket": str(rt.socket)})
        plain.stop()
    for field, value in (("cpus", 5), ("memory_mib", 8193), ("timeout_seconds", 7201)):
        status, answer = a.api("PUT", path, {**body, field: value})
        check(status == 422, f"{field} {value} over the runtime's maximum: {status} {answer}")
    status, answer = a.api("GET", path)
    check(status == 200 and answer.get("cpus") == 4, f"a refusal changed the profile: {status} {answer}")
    status, answer = a.api("PUT", f"/v1/agents/{agent_id('Bad Name')}/runtime", body)
    check(400 <= status < 500 and a.api("GET", f"/v1/agents/{agent_id('Bad Name')}/runtime")[0] == 404,
          f"a profile for an agent whose name is not addressable: {status} {answer}")
    result = a.cli("agent", "runtime", "set", "Bad Name", "--harness-dir", str(state["harness"]))
    check(not result.ok, "agent runtime set for a name that is not addressable succeeded")


@suite.case("profile_claude_image", "agents The launch profile: harness claude, image (default null, --image, "
                                    "replacement)", known=CLAUDE_GAP)
def _():
    a, = need("a")
    need("ready")
    claude = agent_id("claude")
    value = profile("claude")
    check(value == {"agent_id": claude, "harness_dir": str(state["harness"]), "image": None, **DEFAULTS},
          f"a profile with defaults has image null: {value}")
    every = {"harness": "claude", "image": GLIBC_IMAGE, "from_branch": "dev", "network": "none", "cpus": 3,
             "memory_mib": 3072, "timeout_seconds": 300, "max_runs": 2}
    value = profile("claude", "--harness", "claude", "--image", GLIBC_IMAGE, "--from-branch", "dev", "--network",
                    "none", "--cpus", "3", "--memory-mib", "3072", "--timeout", "300s", "--max-runs", "2",
                    harness=state["claude_harness"])
    check(value == {"agent_id": claude, "harness_dir": str(state["claude_harness"]), **DEFAULTS, **every},
          f"every option, harness claude and an image: {value}")
    status, body = a.api("GET", f"/v1/agents/{claude}/runtime")
    check(status == 200 and body == {**value, "credential": False}, f"show: {status} {body}")
    value = profile("claude")
    check(value["harness"] == "codex" and value["image"] is None,
          f"a replacement takes defaults (codex, image null), not the previous values: {value}")
    status, body = a.api("PUT", f"/v1/agents/{claude}/runtime", {"harness": "claude", "image": GLIBC_IMAGE,
                                                                 "harness_dir": str(state["claude_harness"])})
    check(status == 200 and body.get("harness") == "claude" and body.get("image") == GLIBC_IMAGE,
          f"PUT with harness claude and image: {status} {body}")
    for bad in ("", "a b", "x" * 1025):
        status, body = a.api("PUT", f"/v1/agents/{claude}/runtime", {"harness_dir": str(state["harness"]),
                                                                     "image": bad})
        check(400 <= status < 500, f"image {bad[:20]!r}: {status} {body}")
    status, body = a.api("PUT", f"/v1/agents/{claude}/runtime", {"harness_dir": str(state["harness"]),
                                                                 "harness": "gemini"})
    check(400 <= status < 500, f"harness gemini: {status} {body}")
    check(clear("agent", "runtime", "clear", "claude") == {}, "agent runtime clear")


@suite.case("profile_image_refused", "agents The launch profile: an image on a runtime reporting images false is 409 "
                                     "runtime_unavailable", known=CLAUDE_GAP)
def _():
    a, rt = need("a", "rt")
    need("ready")
    path = f"/v1/agents/{agent_id('codex2')}/runtime"
    fake(images=0)
    try:
        check(rt.api("GET", "/v1/runtime")[1].get("images") is False, "the fake reports images true")
        value = profile("codex2", "--cpus", "1")  # control: without an image the profile is set
        result = a.cli("--json", "agent", "runtime", "set", "codex2", "--harness-dir", str(state["harness"]),
                       "--image", GLIBC_IMAGE)
        check(not result.ok, f"agent runtime set --image on a runtime without images: {result.json}")
        status, answer = a.api("PUT", path, {"harness": "codex", "harness_dir": str(state["harness"]),
                                             "image": GLIBC_IMAGE})
        refused(status, answer, 409, "runtime_unavailable")
        status, answer = a.api("GET", path)
        check(status == 200 and answer.get("cpus") == 1 and answer.get("image") is None
              and bare(answer) == {**bare(value), "credential": answer.get("credential")},
              f"a refusal changed the profile: {status} {answer}")
    finally:
        fake()


@suite.case("credential_set_clear", "agents The launch profile: credential set and clear, credentials/AGENT_ID "
                                    "0600, the key in no response, record, event, activity or log")
def _():
    a, = need("a")
    need("ready")
    profile("codex")
    answers = [credential("codex").stdout]
    stored = a.state / "credentials" / agent_id("codex")
    check(stored.is_file() and stored.stat().st_mode & 0o777 == 0o600 and stored.read_text() == state["key"],
          "credentials/AGENT_ID (0600) does not hold the key without its trailing newline")
    status, shown = a.api("GET", f"/v1/agents/{agent_id('codex')}/runtime")
    check(status == 200 and shown.get("credential") is True, f"show with a credential: {status} {shown}")
    answers.append(shown)
    cleared = clear("agent", "credential", "clear", "codex")
    check(cleared == {"agent_id": agent_id("codex"), "credential": False} and not stored.exists(),
          f"agent credential clear: {cleared}")
    check(a.api("GET", f"/v1/agents/{agent_id('codex')}/runtime")[1].get("credential") is False, "show after clear")
    status, body = a.api("PUT", f"/v1/agents/{agent_id('codex')}/credential", {"value": state["key"]})
    check(status == 200 and body == {"agent_id": agent_id("codex"), "credential": True}, f"PUT credential: {body}")
    answers += [body, a.api("GET", "/v1/agents/runtime")[1], a.api("GET", "/v1/activity?limit=1000")[1]]
    found = activity_kinds()
    check("runtime.credential_set" in found and "runtime.credential_cleared" in found, f"activity {found[-8:]}")
    key_nowhere(*answers)


# Receiving (agents, Receiving a task).

@suite.case("receive_never_offered_to_sessions", "agents Receiving a task: under a grant and self access, never "
                                                 "offered to an attached session")
def _():
    a, a2 = need("a", "a2")
    need("ready")
    ready("codex")
    session = a.attach(state["agents"]["codex"])
    tasks = [(send("codex", "echo from bob"), None), (send("codex", "echo from alice2", sender=a2), a2)]
    for task_id, sender in tasks:
        found = events(task_id, sender=sender)
        check(kinds(found) == ["queued", "accepted", "succeeded"], f"{task_id}: {kinds(found)}")
        status, body = session.post("/adapter/v1/tasks/next")
        check(status == 200 and body is None, f"tasks/next offered a runtime agent's task: {status} {body}")
        status, body = session.post(f"/adapter/v1/tasks/{task_id}/complete", {"status": "failed", "output": "x"})
        check(status != 200, f"a session changed a runtime agent's task: {status} {body}")
    state["session"] = session
    state["reached"] = True


@suite.case("receive_before_profile", "agents Receiving a task: one received before the profile stays with the "
                                      "adapter path")
def _():
    a, a2 = need("a", "a2")
    need("ready")
    ready("late")
    session = a.attach(state["agents"]["late"])
    for task_id, sender in zip(state["late_tasks"], (state["b"], a2)):
        claimed = session.next_task()
        check(claimed["task"]["task_id"] in state["late_tasks"], f"claimed {claimed['task']}")
        for step, body in (("accept", {}), ("complete", {"status": "succeeded", "output": "by the session"})):
            status, answer = session.post(f"/adapter/v1/tasks/{claimed['task']['task_id']}/{step}", body)
            check(status == 200, f"{step}: {status} {answer}")
        check(not posts(task_id, sender), "a task received before the profile reached the runtime")
    task_id = send("late", "echo now a runtime agent")
    check(kinds(events(task_id)) == ["queued", "accepted", "succeeded"], "a task received after the profile")


@suite.case("receive_artifacts_refused", "agents Receiving a task: a non-empty artifacts manifest is 400 invalid "
                                         "naming artifacts, nothing persisted")
def _():
    a, b = need("a", "b")
    need("ready")
    ready("codex")
    task_id = new_task_id()
    manifest = [{"name": "notes.txt", "size": 1, "sha256": "a" * 64, "media_type": "text/plain"}]
    body = {"task_id": task_id, "target_agent_id": agent_id("codex"), "input": "read notes.txt",
            "deadline": rfc3339(a.now() + timedelta(minutes=30)), "grant_id": state["grants"]["codex"],
            "artifacts": manifest}
    status, answer = peer_submit(body)
    refused(status, answer, 400, "invalid", "artifacts")
    status, answer = peer_submit({k: v for k, v in body.items() if k != "artifacts"} | {"task_id": new_task_id()})
    check(status == 200, f"control, the same task without artifacts: {status} {answer}")
    status, answer = peer(b, a, "GET", f"/peer/v1/tasks/{task_id}")
    check(status == 404, f"the refused task was persisted: {status} {answer}")


# Running (agents, Running; The output).

@suite.case("run_request", "agents Running (The run, the fork's name, the harness command); The runtime's local API")
def _():
    a, b = need("a", "b")
    need("ready")
    ready("codex", "--network", "none", "--cpus", "3", "--memory-mib", "3072", "--timeout", "300s")
    prompt = "write notes.txt hello ; echo done"
    task_id = send("codex", prompt)
    state["lifecycle"] = (task_id, events(task_id))
    sent = posts(task_id)
    check(sent and sent[0][0] == 201, f"the runtime saw no start for {task_id}")
    body = sent[0][2]
    check(body["argv"][:2] == ["/bin/sh", "-c"] and len(body["argv"]) == 3, f"argv {body['argv']}")
    want = {"cwd": "/workspace", "env": {}, "resources": {"cpus": 3, "memory_mib": 3072, "timeout_seconds": 300},
            "network": "none", "workspace_archive": None, "results": "none", "peerfs_workspace": fork(task_id),
            "peerfs_fork_from": "main", "peerfs_agent": "codex", "peerfs_commit": True,
            "peerfs_commit_message": f"{task_id} from {b.id}", "stdin": base64.b64encode(prompt.encode()).decode(),
            "harness": str(state["harness"])}
    wrong = {k: body.get(k) for k, v in want.items() if body.get(k) != v}
    check(not wrong, f"the request differs from the contract: {wrong}")
    secrets = body.get("secrets") or {}
    check(list(secrets) == ["openai_api_key"] and os.path.isabs(secrets["openai_api_key"]), f"secrets {secrets}")
    with open(secrets["openai_api_key"]) as f:
        check(f.read() == state["key"], "the secret's file does not hold the stored key")
    key_nowhere()


@suite.case("run_request_no_image", "agents Running (image left out when the profile's is null)")
def _():
    task_id, _ = need("lifecycle")[0]
    sent = posts(task_id)
    check(sent and "image" not in sent[0][2], f"a profile without an image sent one: {sent[0][2].get('image')!r}")


@suite.case("run_claude_image", "agents Running (the Claude harness command, secret anthropic_api_key, image); "
                                "The output", known=CLAUDE_GAP)
def _():
    b, = need("b")
    need("ready")
    profile("claude", "--harness", "claude", "--image", GLIBC_IMAGE, harness=state["claude_harness"])
    credential("claude", state["anthropic_file"])
    prompt = "write claude.txt hi ; echo done"
    task_id = send("claude", prompt)
    found = events(task_id)
    sent = posts(task_id)
    check(sent and sent[0][0] == 201, f"the runtime saw no start for {task_id}")
    body = sent[0][2]
    argv = body["argv"]
    check(argv[:2] == ["/bin/sh", "-c"] and len(argv) == 3 and re.search(r"\bclaude -p\b", argv[2]),
          f"argv does not run claude -p: {argv}")
    want = {"image": GLIBC_IMAGE, "harness": str(state["claude_harness"]), "peerfs_workspace": fork(task_id, "claude"),
            "peerfs_fork_from": "main", "peerfs_agent": "claude", "peerfs_commit": True,
            "peerfs_commit_message": f"{task_id} from {b.id}", "stdin": base64.b64encode(prompt.encode()).decode(),
            "cwd": "/workspace", "env": {}, "network": "internet", "workspace_archive": None, "results": "none"}
    wrong = {k: body.get(k) for k, v in want.items() if body.get(k) != v}
    check(not wrong, f"the request differs from the contract: {wrong}")
    secrets = body.get("secrets") or {}
    check(list(secrets) == ["anthropic_api_key"] and os.path.isabs(secrets["anthropic_api_key"]),
          f"secrets {secrets}")
    with open(secrets["anthropic_api_key"]) as f:
        check(f.read() == state["anthropic_key"], "the secret's file does not hold the stored Anthropic key")
    check(kinds(found) == ["queued", "accepted", "succeeded"], f"events {kinds(found)}")
    commit = exited(task_id)["commit"]
    check(found[-1]["output"] == f"done\n\nBranch: {fork(task_id, 'claude')} at commit {commit}",
          f"output {found[-1]['output']!r}")
    key_nowhere(key=state["anthropic_key"], key_file=state["anthropic_file"])


@suite.case("lifecycle_succeeded", "agents Transitions; The output (Branch: NAME at commit ID); The branch")
def _():
    task_id, found = need("lifecycle")[0]
    check(kinds(found) == ["queued", "accepted", "succeeded"], f"events {kinds(found)}")
    commit = exited(task_id)["commit"]
    check(isinstance(commit, str) and COMMIT.match(commit), f"the runtime's commit {commit!r}")
    check(found[-1]["output"] == f"done\n\nBranch: {fork(task_id)} at commit {commit}",
          f"output {found[-1]['output']!r}")
    check((workspace(fork(task_id)) / "notes.txt").read_text() == "hello", "the fork does not hold the write")
    check(sorted(p.name for p in workspace("main").iterdir()) == ["README"]
          and (workspace("main") / "README").read_text() == "main seed\n", "from_branch changed")


@suite.case("failure_and_empty_output", "agents Transitions; The output (a failing exit, exit N, unchanged from FROM)")
def _():
    need("ready")
    ready("codex")
    tasks = [send("codex", "write f1.txt x ; echo broke ; exit 3"), send("codex", "write f2.txt y ; exit 4"),
             send("codex", "echo nothing")]
    found = [events(t) for t in tasks]
    want = [("failed", "broke", "at commit"), ("failed", "exit 4", "at commit"), ("succeeded", "nothing", None)]
    for task_id, evs, (kind, message, how) in zip(tasks, found, want):
        check(evs[-1]["kind"] == kind, f"{message}: {kinds(evs)}")
        got, trailer = split(evs[-1])
        line = (f"Branch: {fork(task_id)} at commit {exited(task_id)['commit']}" if how
                else f"Branch: {fork(task_id)}, unchanged from main")
        check(got == message and trailer == line, f"output {evs[-1]['output']!r}, want {message!r} and {line!r}")


@suite.case("before_the_start", "agents Transitions (queued to failed); The output (Branch: none, the bound); "
                                "Running (the credential read at each start)")
def _():
    rt, = need("rt")
    need("ready")
    ready("codex")
    # A fork name that exists already, made directly on the runtime.
    task_id = new_task_id()
    status, _ = rt.api("POST", "/v1/runs", {
        "run_id": "run_" + os.urandom(32).hex(), "argv": ["write", "marker.txt", "mine"], "cwd": "/workspace",
        "env": {}, "resources": {"cpus": 1, "memory_mib": 128, "timeout_seconds": 60}, "workspace_archive": None,
        "peerfs_workspace": fork(task_id), "results": "none", "peerfs_fork_from": "main"})
    check(status == 201, f"fixture: an existing fork: {status}")
    wait_for(lambda: (workspace(fork(task_id)) / "marker.txt").exists(), message="the existing fork")
    send("codex", "write marker.txt theirs", task_id=task_id)
    found = events(task_id)
    check(kinds(found) == ["queued", "failed"] and split(found[-1])[1] == "Branch: none" and split(found[-1])[0],
          f"a fork name clash: {kinds(found)} {found[-1].get('output')!r}")
    check((workspace(fork(task_id)) / "marker.txt").read_text() == "mine" and at("started", task_id) is None,
          "the clash touched the existing fork")
    # A message over the output bound.
    task_id = send("codex", "bytes 70000")
    final = events(task_id)[-1]
    message, trailer = split(final)
    check(final["kind"] == "succeeded" and len(final["output"].encode()) <= 65536 and message.endswith("…")
          and set(message[:-1]) == {"x"} and len(message) > 60000
          and trailer == f"Branch: {fork(task_id)}, unchanged from main", f"a cut message: {final['output'][-200:]!r}")
    # The credential cleared after dispatch and before started: the secret file is missing at the start.
    fake(start_delay=3)
    try:
        task_id = send("codex", "echo never")
        wait_for(lambda: posts(task_id), timeout=15, interval=0.2, message="the dispatch")
        clear("agent", "credential", "clear", "codex")
        found = events(task_id)
        check(kinds(found) == ["queued", "failed"] and split(found[-1])[1] == "Branch: none"
              and "openai_api_key" in split(found[-1])[0], f"a missing secret file: {found[-1].get('output')!r}")
    finally:
        fake()
        credential("codex")


@suite.case("image_cannot_be_pulled", "agents The runtime's local API (image); Transitions (queued to failed); "
                                      "The output (Branch: none)", known=CLAUDE_GAP)
def _():
    need("ready")
    try:
        ready("codex2", "--image", MISSING_IMAGE)
        task_id = send("codex2", "write never.txt x ; echo never")
        found = events(task_id)
        sent = posts(task_id)
        check(sent and sent[0][2].get("image") == MISSING_IMAGE, f"the request's image: {sent and sent[0][2]}")
        result = exited(task_id)
        message, trailer = split(found[-1])
        check(kinds(found) == ["queued", "failed"] and trailer == "Branch: none" and at("started", task_id) is None
              and message == result["error"] and MISSING_IMAGE in message,
              f"an image that cannot be pulled: {kinds(found)} {found[-1].get('output')!r}")
        check(not workspace(fork(task_id, "codex2")).exists(), "the fork was made for a run that never started")
    finally:
        clear("agent", "runtime", "clear", "codex2")


@suite.case("concurrency", "agents Running: max_runs 1 runs one after the other; two agents side by side")
def _():
    need("ready")
    ready("codex", "--max-runs", "1")
    first, second = send("codex", "sleep 2 ; echo one"), send("codex", "sleep 1 ; echo two")
    for task_id in (first, second):
        check(events(task_id)[-1]["kind"] == "succeeded", f"{task_id} did not succeed")
    check(at("post", second) > at("exited", first), "max_runs 1 dispatched a second run while the first ran")
    ready("codex2", "--max-runs", "1")
    one, two = send("codex", "sleep 2 ; echo one"), send("codex2", "sleep 2 ; echo two")
    for task_id in (one, two):
        check(events(task_id)[-1]["kind"] == "succeeded", f"{task_id} did not succeed")
    check(at("started", two) < at("exited", one) and at("started", one) < at("exited", two),
          "two agents with max_runs 1 did not run side by side")


def held(names, change):
    """Hold each of NAMES (max_runs 1) with a running task, queue one more for each, apply CHANGE, and return the
    queued tasks' final events."""
    holders = [send(n, "sleep 2") for n in names]
    for task_id in holders:
        events(task_id, until=has_kind("accepted"))
    queued = [send(n, "echo queued") for n in names]
    for task_id in queued:
        accepted(task_id)
    change()
    for task_id in holders:
        check(events(task_id)[-1]["kind"] == "succeeded", "a started run did not finish")
    return [events(t)[-1] for t in queued]


@suite.case("checks_at_start", "agents Running: the checks at start (profile, credential, switch) and the "
                               "authorization recheck, each ending rejected")
def _():
    a, rt = need("a", "rt")
    need("ready")
    ready("codex", "--max-runs", "1")
    ready("codex2", "--max-runs", "1")
    no_profile, no_key = held(["codex", "codex2"], lambda: (clear("agent", "runtime", "clear", "codex"),
                                                           clear("agent", "credential", "clear", "codex2")))
    check(no_profile["kind"] == "rejected" and no_profile["message"] == "the agent has no launch profile",
          f"the profile cleared while queued: {no_profile}")
    check(no_key["kind"] == "rejected" and no_key["message"] == "the agent has no credential",
          f"the credential cleared while queued: {no_key}")
    ready("codex", "--max-runs", "1")
    ready("codex2", "--max-runs", "1")

    def revoke():
        a.ok("grant", "revoke", state["grants"]["codex"])
    lapsed, = held(["codex"], revoke)
    state["grants"]["codex"] = a.ok("grant", "create", "--peer", state["b"].id, "--agent", agent_id("codex"),
                                    "--action", "task.submit", "--expires-at",
                                    rfc3339(a.now() + timedelta(hours=6)))["id"]
    check(lapsed["kind"] == "rejected" and lapsed["message"] == "authorization lapsed before acceptance",
          f"the grant revoked while queued: {lapsed}")
    try:
        disabled, = held(["codex2"], lambda: a.api("DELETE", "/v1/runtime"))
    finally:
        a.api("PUT", "/v1/runtime", {"socket": str(rt.socket)})
    check(disabled["kind"] == "rejected" and disabled["message"] == "the runtime is disabled",
          f"the switch turned off while queued: {disabled}")


@suite.case("cancellation", "agents Transitions (cancelled); The output of a cancelled task; before dispatch "
                            "output null")
def _():
    rt, b = need("rt", "b")
    need("ready")
    ready("codex", "--max-runs", "1")
    task_id = send("codex", "write c.txt partial ; sleep 20")
    events(task_id, until=has_kind("accepted"))
    wait_for(lambda: any(e["step"][0] == "sleep" for e in rt.entries("step", run_id(b, task_id))), timeout=10,
             interval=0.1, message="the run to reach its sleep")
    queued = send("codex", "echo never")
    accepted(queued)
    cancel(queued)
    found = events(queued)
    check(kinds(found)[-1] == "cancelled" and found[-1]["output"] is None and not posts(queued),
          f"cancelled before dispatch: {kinds(found)} {found[-1].get('output')!r}")
    cancel(task_id)
    final = events(task_id)[-1]
    check(final["kind"] == "cancelled" and final["output"]
          == f"cancelled\n\nBranch: {fork(task_id)} at commit {exited(task_id)['commit']}",
          f"cancelled while running: {final['kind']} {final.get('output')!r}")
    check((workspace(fork(task_id)) / "c.txt").read_text() == "partial", "the partial work was not kept")


@suite.case("restarts", "agents Running (the stored request, resends); runtime The runtime's local API "
                        "(restarts)")
def _():
    a, = need("a")
    need("ready")
    ready("codex")
    task_id = send("codex", "sleep 3 ; echo after the restart")
    events(task_id, until=has_kind("accepted"))
    a.stop(kill=True)
    a.start()
    final = events(task_id)[-1]
    check(final["kind"] == "succeeded" and final["output"]
          == f"after the restart\n\nBranch: {fork(task_id)}, unchanged from main",
          f"the daemon restarted during a run: {final['kind']} {final.get('output')!r}")
    task_id = send("codex", "write lost.txt x ; sleep 20")
    events(task_id, until=has_kind("accepted"))
    fake()
    final = events(task_id, timeout=40)[-1]
    check(final["kind"] == "failed" and final["output"] == "the runtime restarted\n\nBranch: "
          f"{fork(task_id)}, not committed: the runtime restarted",
          f"the fake runtime restarted during a run: {final['kind']} {final.get('output')!r}")
    fake(start_delay=4)
    try:
        task_id = send("codex", "echo resent")
        wait_for(lambda: posts(task_id), timeout=15, interval=0.2, message="the dispatch")
        profile("codex", "--cpus", "1", "--from-branch", "dev")
        clear("agent", "runtime", "clear", "codex")
        a.stop(kill=True)
        a.start()
        sent = wait_for(lambda: len(posts(task_id)) >= 2 and posts(task_id), timeout=20,
                        message="the restarted daemon to resend the start")
        check([s[0] for s in sent[:2]] == [201, 200] and sent[1][1] == sent[0][1],
              f"start answers {[s[0] for s in sent]}; byte-identical: {sent[1][1] == sent[0][1]}")
        final = events(task_id)[-1]
        check(final["kind"] == "succeeded" and final["output"] == f"resent\n\nBranch: {fork(task_id)}, "
              "unchanged from main", f"the resent run: {final['kind']} {final.get('output')!r}")
    finally:
        fake()


@suite.case("failed_commit", "agents Transitions (a run result with error fails the task); The output (not "
                             "committed: ERROR)")
def _():
    need("ready")
    ready("codex")
    fake(fail_commits=1)
    try:
        task_id = send("codex", "write k.txt z ; echo wrote it")
        final = events(task_id)[-1]
        error = exited(task_id)["error"]
        check(final["kind"] == "failed" and final["output"]
              == f"wrote it\n\nBranch: {fork(task_id)}, not committed: {error}",
              f"a failed commit: {final['kind']} {final.get('output')!r}")
    finally:
        fake()


# Persistence (agents, Persistence).

@suite.case("open_previous_schema", "agents Persistence: the next schema version; a database of the previous one "
                                    "opens")
def _():
    a2, = need("a2")
    copy = suite.host("alice2-copy", start=False)
    a2.stop()
    shutil.copytree(a2.state, copy.state, dirs_exist_ok=True)
    for leftover in ("admin.sock", "adapter.sock"):
        (copy.state / leftover).unlink(missing_ok=True)
    path = None
    for candidate in sorted(copy.state.glob("*.db")):
        probe = sqlite3.connect(str(candidate))
        try:
            if probe.execute("SELECT 1 FROM sqlite_master WHERE name = 'networks'").fetchone():
                path = candidate
        finally:
            probe.close()
    check(path is not None, "no state database in the copy")
    db = sqlite3.connect(str(path))
    current = db.execute("PRAGMA user_version").fetchone()[0]
    db.execute(f"PRAGMA user_version = {current - 1}")
    db.commit()
    db.close()
    copy.start()
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        check(db.execute("PRAGMA user_version").fetchone()[0] == current, "the previous version was not upgraded")
    finally:
        db.close()
    copy.stop()
    check(current > MAIN_SCHEMA, f"schema version {current}; this contract adds the version after {MAIN_SCHEMA}")


suite.finish()
