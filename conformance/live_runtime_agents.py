#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright The Peerspan Authors
"""Live check: story 2 of the runtime (docs/runtime-agent-contract.md, RUN-8 to RUN-11), with real VMs and a model.

alice's host is the "server": it serves through the real peerspan-runtime (KVM microVMs) with a real peerfs
space whose `main` holds a small repository with a slow function. alice2 is the "laptop": it sends three tasks
for one performance fix to alice's runtime agent `codex`, with no session attached anywhere. Codex runs headless
in three VMs at once, each on its own fork, with a real OpenAI key. Then the best branch is merged into `main`
on the server, and the others are left alone. Records memory per VM, wall time and tokens per task.

A manual check, not a suite (AGENTS.md: live runs with real models are separate): it needs root, /dev/kvm, a
built peerspan-runtime with its guest and libkrun, peerfs, a Codex release directory and an OpenAI API key, and it
spends a few cents of model usage. Both hosts run on this machine, as the slim suites' hosts do; the contract's
full acceptance uses an installed release on two machines.

    PEERSPAN_RUNTIME=.../peerspan-runtime PEERSPAN_PEERFS=.../peerfs PEERSPAN_LIBKRUN=.../libkrun.so.2 \
    PEERSPAN_RUNTIME_GUEST=.../guest CODEX_DIR=.../codex-release/bin OPENAI_KEY_FILE=... \
    LIVE_OUT=DIR python3 conformance/live_runtime_agents.py --bin target/debug

CODEX_DIR holds the Codex release's `codex` and `codex-code-mode-host`. The report is LIVE_OUT/report.json.
"""
import base64
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

SLIM = Path(__file__).resolve().parent / "slim"
sys.path.insert(0, str(SLIM))

import runtime_common  # noqa: E402
from harness import Suite, check, wait_for  # noqa: E402
from runtime_common import FakeRuntime, UnixHTTPConnection, bind, need, new_task_id, setup_network, state  # noqa: E402

def required(name):
    value = os.environ.get(name)
    if not value:
        sys.exit(f"live_runtime_agents: set {name} (see the module docstring)")
    return value


RUNTIME = required("PEERSPAN_RUNTIME")
PEERFS = required("PEERSPAN_PEERFS")
CODEX_DIR = required("CODEX_DIR")
KEY = required("OPENAI_KEY_FILE")
ENV = {name: required(name) for name in ("PEERSPAN_LIBKRUN", "PEERSPAN_RUNTIME_GUEST")}
OUT = Path(required("LIVE_OUT"))
PROMPT = ("count_primes in primes.py is far too slow: `python3 -m unittest -v` fails test_speed. Make it fast "
          "without changing its results, run the tests to confirm they all pass, and summarise your change in two "
          "sentences.")

suite = Suite("live_runtime_agents", __doc__)
bind(suite)
OUT.mkdir(parents=True, exist_ok=True)


def pf(*argv, check_rc=True):
    r = subprocess.run([PEERFS, "--space", str(state["space"]), *argv], capture_output=True, text=True)
    if check_rc and r.returncode != 0:
        raise RuntimeError(f"peerfs {' '.join(argv)}: {r.stderr.strip()}")
    return r.stdout


class RealRuntime(FakeRuntime):
    """peerspan-runtime serve with a peerfs space, in place of the fake."""

    def start(self, **_options):
        space = suite.work / "space"
        state["space"] = space
        seed = suite.work / "seed"
        seed.mkdir(exist_ok=True)
        (seed / "primes.py").write_text(
            "def count_primes(n):\n"
            "    \"\"\"How many primes are below n.\"\"\"\n"
            "    count = 0\n"
            "    for i in range(2, n):\n"
            "        if all(i % d for d in range(2, i)):\n"
            "            count += 1\n"
            "    return count\n")
        (seed / "test_primes.py").write_text(
            "import time\nimport unittest\nfrom primes import count_primes\n\n"
            "class T(unittest.TestCase):\n"
            "    def test_small(self):\n"
            "        self.assertEqual([count_primes(n) for n in (0, 2, 3, 10, 100, 1000)], [0, 0, 1, 4, 25, 168])\n\n"
            "    def test_speed(self):\n"
            "        start = time.monotonic()\n"
            "        self.assertEqual(count_primes(2_000_000), 148933)\n"
            "        self.assertLess(time.monotonic() - start, 3.0)\n\n"
            "if __name__ == '__main__':\n    unittest.main()\n")
        pf("init")
        pf("import", str(seed), "-m", "a slow count_primes")
        os.chmod(suite.work, 0o711)
        os.chmod(self.dir, 0o711)  # each run's workspace server runs as the run's own user
        argv = [RUNTIME, "serve", "--socket", str(self.socket), "--state", str(self.dir / "state"),
                "--peerfs-space", str(space), "--peerfs", PEERFS, "--max-network", "internet",
                "--max-concurrent-runs", "3", "--max-cpus", "4", "--max-memory-mib", "4096",
                "--max-seconds", "3600", "--image", "python:3.12-alpine"]
        self.serve_log = OUT / "runtime-serve.log"
        out = self.serve_log.open("ab")
        self.process = subprocess.Popen(argv, stdout=out, stderr=out, env={**os.environ, **ENV})
        import atexit
        atexit.register(lambda p=self.process: p.poll() is None and (p.terminate(), p.wait(timeout=30)))
        out.close()
        def up():
            if self.process.poll() is not None:
                raise RuntimeError("serve exited: " + self.serve_log.read_text(errors="replace")[-500:])
            return self._ping()
        wait_for(up, timeout=600, interval=0.5, message="peerspan-runtime serve (pulling the image)")
        return self


runtime_common.FakeRuntime = RealRuntime


def runtime_api(method, path):
    conn = UnixHTTPConnection(str(state["rt"].socket), timeout=40)
    try:
        conn.request(method, path)
        r = conn.getresponse()
        data = r.read()
    finally:
        conn.close()
    return r.status, json.loads(data) if data.strip() else None


class Recorder:
    """A proxy on its own Unix socket between alice's host and the runtime: it forwards every request and keeps
    every event of every run as the host reads it, so nothing is lost when the host deletes a finished run."""

    def __init__(self, upstream, path):
        import http.client
        import http.server
        import socketserver

        recorder = self
        self.events = {}  # run ID -> {sequence: event}
        self.lock = threading.Lock()

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def address_string(self):
                return "host"

            def forward(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else None
                conn = UnixHTTPConnection(upstream, timeout=60)
                try:
                    headers = {k: v for k, v in self.headers.items() if k.lower() in ("content-type",)}
                    conn.request(self.command, self.path, body=body, headers=headers)
                    r = conn.getresponse()
                    data = r.read()
                finally:
                    conn.close()
                m = re.match(r"^/v1/runs/(run_[0-9a-f]{64})/events", self.path)
                if m and r.status == 200:
                    with recorder.lock:
                        kept = recorder.events.setdefault(m.group(1), {})
                        for e in json.loads(data or b"[]"):
                            kept[e["sequence"]] = e
                self.send_response(r.status)
                self.send_header("Content-Type", r.getheader("Content-Type") or "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_DELETE = forward

        class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True

        Path(path).unlink(missing_ok=True)
        self.path = str(path)
        self.server = Server(self.path, Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def of(self, run_id):
        with self.lock:
            return [e for _, e in sorted(self.events.get(run_id, {}).items())]


@suite.case("setup", "two of alice's machines, a real runtime, a runtime agent `codex` with a real key")
def _():
    setup_network(second_machine=True)
    a, a2, rt = need("a", "a2", "rt")
    state["recorder"] = Recorder(str(rt.socket), suite.work / "recorder.sock")
    status, body = a.api("PUT", "/v1/runtime", {"socket": state["recorder"].path})
    check(status == 200 and body.get("peerfs") is True, f"the runtime switch: {status} {body}")
    status, agent = a.api("POST", "/v1/agents", {"name": "codex", "owner": "alice"})
    check(status in (200, 201), f"register codex: {status} {agent}")
    state["codex"] = agent["id"]
    r = a.cli("--json", "agent", "runtime", "set", "codex", "--harness-dir", CODEX_DIR, "--max-runs", "3")
    check(r.ok, f"agent runtime set: {r.code} {r.stderr[-300:]}")
    r = a.cli("--json", "agent", "credential", "set", "codex", "--from-file", KEY)
    check(r.ok and r.json.get("credential") is True, f"agent credential set: {r.code} {r.stderr[-300:]}")
    sessions = a.api("GET", f"/v1/sessions?agent_id={agent['id']}")[1]
    check(not sessions, f"no session is attached to codex: {sessions}")


@suite.case("three_tasks", "three tasks for one fix, from alice2, run concurrently on three forks")
def _():
    a, a2 = need("a", "a2")
    tasks = []
    for _ in range(3):
        body = {"peer_host_id": a.id, "target_agent_id": state["codex"], "input": PROMPT, "task_id": new_task_id()}
        status, record = a2.api("POST", "/v1/tasks", body)
        check(status in (200, 201), f"submit: {status} {record}")
        tasks.append({"id": body["task_id"], "sent": time.time()})
    state["tasks"] = tasks
    for t in tasks:
        t["run_id"] = runtime_common.run_id(a2, t["id"])
    running_max = 0
    deadline = time.time() + 3600
    while time.time() < deadline:
        records = [a2.api("GET", f"/v1/tasks/{a.id}/{t['id']}")[1] for t in tasks]
        running_max = max(running_max, runtime_api("GET", "/v1/runtime")[1]["running"])
        states = [((r or {}).get("status") or {}).get("state") for r in records]
        for t, s in zip(tasks, states):
            if s in ("succeeded", "failed", "cancelled", "rejected", "expired") and "done" not in t:
                t["done"] = time.time()
        if all("done" in t for t in tasks):
            break
        time.sleep(2)
    state["running_max"] = running_max
    for t in tasks:
        events = a2.api("GET", f"/v1/tasks/{a.id}/{t['id']}/events")[1]
        final = events[-1]
        t["state"], t["output"] = final["state"], final["output"] or ""
        m = re.search(r"Branch: (\S+) at commit ([0-9a-f]{66})$", t["output"])
        t["branch"], t["commit"] = (m.group(1), m.group(2)) if m else (None, None)
        # stderr chunks are not line-aligned (runtime task contract, The runtime's local API): join them first.
        stderr = b"".join(base64.b64decode(e["data"]) for e in state["recorder"].of(t["run_id"])
                          if e["kind"] == "stderr")
        usage = []
        for line in stderr.decode(errors="replace").splitlines():
            if '"turn.completed"' in line:
                try:
                    usage.append(json.loads(line).get("usage"))
                except json.JSONDecodeError:
                    pass
        t["usage"] = [u for u in usage if u]
    check(running_max == 3, f"three VMs at once: the runtime reported at most {running_max} running")
    check(all(t["state"] == "succeeded" for t in tasks), f"states {[t['state'] for t in tasks]}")
    check(all(t["branch"] and t["commit"] for t in tasks), f"outputs {[t['output'][-200:] for t in tasks]}")
    check(len({t["branch"] for t in tasks}) == 3, "three distinct branches")


@suite.case("branches", "each branch's history attributed to the agent; each branch passes the tests")
def _():
    for t in state["tasks"]:
        log = pf("log", "--branch", t["branch"])
        t["log"] = log
        check(t["commit"] in log and "codex" in log, f"{t['branch']} log: {log[:400]}")
        out = suite.work / f"export-{t['branch']}"
        pf("export", str(out), "--branch", t["branch"])
        start = time.monotonic()
        r = subprocess.run([sys.executable, "-m", "unittest", "-q"], cwd=out, capture_output=True, text=True,
                           timeout=120)
        t["tests_ok"], t["tests_s"] = r.returncode == 0, round(time.monotonic() - start, 2)
    check(all(t["tests_ok"] for t in state["tasks"]), f"tests {[(t['branch'], t['tests_ok']) for t in state['tasks']]}")


@suite.case("merge_best", "the fastest branch merged into main; the others untouched")
def _():
    tasks = state["tasks"]
    best = min((t for t in tasks if t["tests_ok"]), key=lambda t: t["tests_s"])
    heads_before = pf("branches")
    pf("ws", "create", "review", "--branch", "main")
    pf("ws", "merge", "review", best["branch"])
    pf("ws", "commit", "review", "-m", f"Merge {best['branch']}", "--agent", "alice")
    heads_after = pf("branches")
    heads = dict(reversed(line.split()) for line in heads_after.splitlines() if line.strip())
    others = [t for t in tasks if t is not best]
    unchanged = all(heads.get(t["branch"]) == t["commit"] for t in others)
    # A merge into main that main has not moved past fast-forwards it to the branch's commit.
    main_log = pf("log", "--branch", "main")
    main_now = pf("ws", "read", "review", "primes.py")
    state["best"], state["main_head"] = best["branch"], heads.get("main")
    check(best["commit"] in main_log and heads.get(best["branch"]) == best["commit"],
          f"main's history does not hold {best['commit']}: {main_log[:400]}")
    check(unchanged, f"another branch moved: before {heads_before} after {heads_after}")
    check("all(i % d" not in main_now, "main still has the slow count_primes")


@suite.case("record", "memory per VM, wall time and tokens per task")
def _():
    serve = state["rt"].serve_log.read_text(errors="replace")
    mem = {}
    for line in serve.splitlines():
        if "run finished" in line:
            rid = re.search(r"run=(\S+)", line)
            peak = re.search(r"memory_peak_mib=(\d+)", line)
            dur = re.search(r"duration_ms=(\d+)", line)
            if rid and peak:
                mem[rid.group(1)] = (int(peak.group(1)), int(dur.group(1)) if dur else None)
    report = {"running_max": state["running_max"], "merged_branch": state["best"], "main_head": state["main_head"],
              "tasks": []}
    for t in state["tasks"]:
        peak, dur = mem.get(t["run_id"], (None, None))
        report["tasks"].append({"task": t["id"], "branch": t["branch"], "state": t["state"],
                                "wall_s": round(t["done"] - t["sent"], 1), "run_ms": dur, "memory_peak_mib": peak,
                                "tests_s": t["tests_s"], "usage": t["usage"],
                                "message": t["output"].rsplit("\n\nBranch:", 1)[0][:600]})
    (OUT / "report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2), flush=True)
    secret = Path(KEY).read_text().strip()
    leaked = [p for p in [state["rt"].serve_log, *suite.work.rglob("*.log")]
              if p.is_file() and secret in p.read_text(errors="replace")]
    check(not leaked and all(secret not in t["output"] for t in state["tasks"]), f"key in {leaked}")
    missing = [t["task"] for t in report["tasks"] if t["memory_peak_mib"] is None]
    check(not missing, f"no memory measurement for {missing}")
    check(all(t["usage"] for t in report["tasks"]), f"no token usage for {[t['task'] for t in report['tasks'] if not t['usage']]}")


suite.finish()
