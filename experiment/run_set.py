#!/usr/bin/env python3
"""One set of the lead comparison (PREREGISTRATION.md), with real Claude Code agents.

Environment: LEAD_SET, LEAD_ARM (today or lead), LEAD_OUT (results directory), LEAD_MODE (run or pilot).
Run: LEAD_SET=1 LEAD_ARM=today LEAD_OUT=DIR python3 experiment/run_set.py --bin DIR --keep
"""
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "conformance" / "slim"))
from harness import Suite, check, create_network, join_new_person, ssh_key, wait_for  # noqa: E402

SET, ARM = os.environ["LEAD_SET"], os.environ["LEAD_ARM"]
OUT = Path(os.environ["LEAD_OUT"]) / f"set{SET}"
MODE = os.environ.get("LEAD_MODE", "run")
PROJECTS = Path(f"/tmp/pslead/{MODE}{SET}")
TMUX = ["tmux", "-L", f"pslead{SET}"]
QUIET, TASK_LIMIT = 60, 420
TASKS = {
    "T1": "What Retry-After value does POST /orders send when it is throttled?",
    "T2": "What is the vacuum window for warehouse-7?",
    "T3": "What is the latest time on Friday we can begin a full invoice-archive restore and still have it finished before the code freeze?",
    "T4": "Plan: on Tuesday we ship the gallery thumbnail change, which makes POST /image-resize use a width of 640. Question: is 640 within the largest width that endpoint allows?",
}
if MODE == "pilot":
    TASKS = {"P": "Pilot: say hello in one line."}
if ARM not in ("today", "lead"):
    sys.exit("LEAD_ARM")
OUT.mkdir(parents=True, exist_ok=True)
EVENTS = OUT / "events.jsonl"


def log(event, **fields):
    line = {"at": time.time(), "event": event, **fields}
    with EVENTS.open("a") as f:
        f.write(json.dumps(line) + "\n")
    print(json.dumps(line)[:300], flush=True)


suite = Suite("lead_comparison", __doc__)
a, b = suite.host("alice", start=False), suite.host("bob", start=False)
for host in (a, b):
    if ARM == "lead":
        host.extra_env["PEERSPAN_EXPERIMENT_WAKE"] = "lead"
    host.start()
state = {}
AGENTS = {"api": a, "db": b, "release": b}


def tmux(*args, **kw):
    return subprocess.run([*TMUX, *args], capture_output=True, text=True, **kw)


def pane(name):
    return tmux("capture-pane", "-p", "-t", f"pslead:{name}").stdout


def launch(name):
    host = AGENTS[name]
    project = PROJECTS / name
    shutil.copytree(HERE / "fixtures" / name, project)
    env = {
        "XDG_CONFIG_HOME": host.env["XDG_CONFIG_HOME"], "XDG_STATE_HOME": host.env["XDG_STATE_HOME"],
        "XDG_RUNTIME_DIR": host.env["XDG_RUNTIME_DIR"], "DISABLE_AUTOUPDATER": "1",
        "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
    }
    if ARM == "lead":
        env["PEERSPAN_EXPERIMENT_WAKE"] = "lead"
    command = " ".join(f"{k}={v}" for k, v in env.items()) + (
        f" {suite.host_bin} --state {host.state} attach claude --name {name} --directory {project}"
        f" --integrations {HERE.parent / 'integrations'} --runner {shutil.which('node')} --no-calls"
        " -- --model haiku --setting-sources project,local; sleep 100000")
    if tmux("has-session", "-t", "pslead").returncode:
        tmux("new-session", "-d", "-s", "pslead", "-n", "idle", "-x", "150", "-y", "50", "sleep 100000")
    tmux("new-window", "-d", "-t", "pslead", "-n", name, "-c", str(project), f"unset SSH_AUTH_SOCK; {command}")


@suite.case("setup", "two people, allowing each other")
def _():
    net = create_network(a, "lead", "alice")
    key = ssh_key(b.root, "bob")
    join_new_person(a, b, "bob", key, net["id"])
    for host, other, who in ((b, a, "alice"), (a, b, "bob")):
        extra = ["--person-key", key] if host is b else []
        allowed = host.ok("allow", who, "--no-tasks", *extra)

        def held():
            other.api("POST", f"/v2/networks/{net['id']}/sync", {}, timeout=40)
            versions = other.api("GET", f"/v2/networks/{net['id']}/access-versions")[1]
            return any(p["version"] >= allowed["policy"]["version"] for p in versions["policies"])
        wait_for(held, timeout=30, interval=1, message=f"the policy allowing {who}")
    log("set_start", set=SET, arm=ARM)
    for name in AGENTS:
        launch(name)


def slug(name):
    return re.sub(r"[^A-Za-z0-9]", "-", str(PROJECTS / name))


def transcripts(name):
    return sorted((Path.home() / ".claude" / "projects" / slug(name)).glob("*.jsonl"))


def transcript_bytes():
    return sum(f.stat().st_size for name in AGENTS for f in transcripts(name))


def ready(name):
    return any('"name":"mcp__peerspan__peerspan_ready"' in f.read_text(errors="replace") for f in transcripts(name))


@suite.case("ready", "each agent's model has called peerspan_ready; prompts answered")
def _():
    end = time.time() + 180
    waiting = set(AGENTS)
    while waiting and time.time() < end:
        for name in AGENTS:
            text = pane(name)
            if "I am using this for local development" in text and "Enter to confirm" in text:
                tmux("send-keys", "-t", f"pslead:{name}", "Enter")
            elif "Teach auto mode" in text:
                tmux("send-keys", "-t", f"pslead:{name}", "Down")
                time.sleep(0.3)
                tmux("send-keys", "-t", f"pslead:{name}", "Enter")
            if name in waiting and ready(name):
                waiting.discard(name)
        time.sleep(2)
    check(not waiting, f"harness failure: agents never ready: {waiting}")
    # Let the launch turns end, and clear any dialog that follows them.
    end = time.time() + 20
    while time.time() < end:
        for name in AGENTS:
            if "Teach auto mode" in pane(name):
                tmux("send-keys", "-t", f"pslead:{name}", "Down")
                time.sleep(0.3)
                tmux("send-keys", "-t", f"pslead:{name}", "Enter")
        time.sleep(2)
    a.ok("agents", "--refresh", "--json")
    log("launched")


def messages(conv):
    return a.api("GET", f"/v1/conversations/{conv}/messages")[1].get("messages", [])


def run_task(task, text):
    started = a.ok("conversation", "start", f"{a.id}/api", "bob/db", "bob/release", timeout=60)
    check(all(o["state"] == "joined" for o in started["invites"]), f"harness failure: {started['invites']}")
    conv = started["conversation"]["conversation_id"]
    log("conversation", task=task, conv=conv)
    message = a.ok("conversation", "say", conv, text)["message"]["message_id"]
    log("said", task=task, conv=conv, message=message)
    begun = last = time.time()
    seen = (0, transcript_bytes())
    while time.time() - begun < TASK_LIMIT:
        time.sleep(3)
        for name in AGENTS:
            if "Teach auto mode" in pane(name):
                tmux("send-keys", "-t", f"pslead:{name}", "Down")
                time.sleep(0.3)
                tmux("send-keys", "-t", f"pslead:{name}", "Enter")
        now = (len(messages(conv)), transcript_bytes())
        if now != seen:
            seen, last = now, time.time()
        elif time.time() - last >= QUIET:
            break
    log("task_end", task=task, conv=conv, seconds=round(time.time() - begun, 1), timed_out=time.time() - begun >= TASK_LIMIT)
    (OUT / f"{task}.messages.json").write_text(json.dumps(messages(conv), indent=1))


for task, text in TASKS.items():
    suite.case(task, "the task runs to its end")(lambda task=task, text=text: run_task(task, text))


@suite.case("collect", "host databases and transcripts copied out")
def _():
    for host in (a, b):
        rows = []
        database = host.state / "host.db"
        with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as conn:
            conn.row_factory = sqlite3.Row
            for r in conn.execute("SELECT * FROM conversation_notifications ORDER BY rowid"):
                rows.append(dict(r))
        (OUT / f"{host.name}.notifications.json").write_text(json.dumps(rows, indent=1))
    for name in AGENTS:
        (OUT / f"{name}.pane.txt").write_text(pane(name))
        for i, f in enumerate(transcripts(name)):
            shutil.copy(f, OUT / f"{name}.{i}.jsonl")
    log("set_end")


tmux("kill-server")
suite.finish()
