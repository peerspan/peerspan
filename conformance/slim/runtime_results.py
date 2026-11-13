#!/usr/bin/env python3
"""Slim suite, runtime_results: workspace archives, result artifacts, and the submitter's CLI, adapter and MCP tools
(RUN-1 to RUN-4).

alice creates a coordinator-free network and bob joins as another person; alice's host serves runtime tasks through
conformance/slim/fake_runtime.py (RUN-4), which reads `argv` as the step language of the contract's Verification
section and logs every request. bob submits through the owner API, the CLI, the peer probe, the adapter socket and
the MCP adapter. Running, cancellation, output and restarts are runtime_runs.py; authorization and administration
are runtime.py; peerfs workspaces (RUN-6, RUN-7) are runtime_peerfs.py; the shared fixtures are runtime_common.py.

Not suite cases (Rust tests that drive the binaries, per the contract's Verification section): a `changes.tar` over
the 104,857,600-byte per-artifact limit, and the 104,857,600-byte cut of `stdout.log` and `stderr.log`, which need
files too large for a two-minute suite; the 65,536-byte cut of `meta.output`.

Written from docs/runtime-task-contract.md only (cited as "runtime <section>"), with the task, artifact and
coordinator-free contracts it builds on. No VM, no KVM, no model calls.
"""
import io
import os
import shutil
import subprocess
import tarfile
import threading
from datetime import timedelta

from harness import Suite, check, rfc3339, wait_for
from runtime_common import (FINAL, adapter_upload, bind, cancel, enable, enable_for_both, final, local_artifact,
                            make_tar, mcp_channel, names, need, new_task_id, occupy, peer_submit, raw_task,
                            result_of, setup_network, state, stream, submit, upload)

suite = Suite("runtime_results", __doc__)
bind(suite)


@suite.case("setup", "decentralized-spec 6, 8; runtime Runtime administration (runtime enable --for)")
def _():
    setup_network()
    enable_for_both()


# The workspace (runtime Requests, Packing).

@suite.case("workspace_archive", "runtime Requests (workspace), Packing; archive fetched before start and readable")
def _():
    a, b, rt = need("a", "b", "rt")
    need("ready")
    work = b.root / "ws-git"
    (work / "sub").mkdir(parents=True)
    (work / "a.txt").write_text("alpha\n")
    (work / "sub" / "b.txt").write_text("beta\n")
    (work / "secret.txt").write_text("ignored\n")
    (work / ".gitignore").write_text("secret.txt\n")
    for argv in (["git", "init", "-q"], ["git", "add", "a.txt", ".gitignore"]):
        subprocess.run(argv, cwd=work, check=True, capture_output=True)
    result = b.cli("task", "run", "--peer", a.id, "--workspace", str(work), "--", "cat", "a.txt", ";",
                   "cat", "sub/b.txt", timeout=90)
    check(result.code == 0 and result.stdout == "alpha\nbeta\n",
          f"task run --workspace: exit {result.code} stdout {result.stdout!r} {result.stderr.strip()[-300:]}")
    post = rt.entries("post")[-1]
    archive = post["request"]["workspace_archive"]
    check(archive and archive.startswith("/"), f"workspace_archive {archive}")
    ignored = b.cli("task", "run", "--peer", a.id, "--workspace", str(work), "--", "cat", "secret.txt", timeout=90)
    check(ignored.code == 1, f"an ignored file was packed: exit {ignored.code} {ignored.stdout!r}")


# Results (runtime Result artifacts).

def changes_workspace():
    b = state["b"]
    return upload(b, make_tar({"keep.txt": b"keep", "gone.txt": b"gone", "edit.txt": b"old"}))


@suite.case("results_none_and_output", "runtime Result artifacts: none, output, no output, identical streams")
def _():
    need("ready")
    task_id = submit(["echo", "hi"], results="none")
    last = final(task_id)[-1]
    check(not last.get("artifacts"), f"results none attached {last.get('artifacts')}")
    task_id = submit(["echo", "hi", ";", "stderr", "there"], results="output")
    last = final(task_id)[-1]
    found = {a["name"]: a for a in last["artifacts"]}
    check(list(found) == ["stdout.log", "stderr.log"] and found["stdout.log"]["size"] == 3
          and found["stderr.log"]["size"] == 6 and found["stdout.log"]["media_type"] == "text/plain",
          f"output artifacts {last['artifacts']}")
    task_id = submit(["sleep", "0"])
    last = final(task_id)[-1]
    result = result_of(last)
    check(not last.get("artifacts") and result["stdout_bytes"] == 0 and result["results_dropped"] == [],
          f"no output: artifacts {last.get('artifacts')}, result {result}")
    task_id = submit(["echo", "same", ";", "stderr", "same"])
    last = final(task_id)[-1]
    result = result_of(last)
    check(names(last) == ["stdout.log"] and result["results_same"] == {"stderr.log": "stdout.log"}
          and result["results_dropped"] == [], f"identical streams: {names(last)} {result}")


@suite.case("results_changes", "runtime Result artifacts: changes, deletions, deleted.txt left out when nothing removed")
def _():
    need("ready")
    entry = changes_workspace()
    task_id = submit(["write", "new.txt", "hello", ";", "write", "edit.txt", "changed", ";", "rm", "gone.txt"],
                     results="changes", artifacts=[entry], workspace={"archive": entry["sha256"]})
    last = final(task_id)[-1]
    check(last["kind"] == "succeeded" and names(last) == ["changes.tar", "deleted.txt"],
          f"changes artifacts {last.get('artifacts')}")
    found = {a["name"]: a for a in last["artifacts"]}
    check(found["changes.tar"]["media_type"] == "application/x-tar" and found["deleted.txt"]["media_type"] == "text/plain",
          f"media types {last['artifacts']}")
    data = local_artifact(task_id, found["changes.tar"]["sha256"])
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        members = {m.name: tar.extractfile(m).read() for m in tar if m.isfile()}
    check(members == {"new.txt": b"hello", "edit.txt": b"changed"}, f"changes.tar holds {members}")
    check(local_artifact(task_id, found["deleted.txt"]["sha256"]) == b"gone.txt\n", "deleted.txt")
    task_id = submit(["write", "only.txt", "x"], results="changes", artifacts=[entry],
                     workspace={"archive": entry["sha256"]})
    last = final(task_id)[-1]
    check(names(last) == ["changes.tar"], f"nothing removed: {names(last)}")


@suite.case("task_run_saves_results", "runtime CLI: --results changes saves into ./peerspan-results/TASK_ID/")
def _():
    a, b = need("a", "b")
    need("ready")
    work = b.root / "ws-plain"
    work.mkdir()
    (work / "keep.txt").write_text("keep")
    out = b.root / "peerspan-results"
    shutil.rmtree(out, ignore_errors=True)
    result = b.cli("task", "run", "--peer", a.id, "--workspace", str(work), "--results", "changes", "--",
                   "echo", "same", ";", "stderr", "same", ";", "write", "made.txt", "made", timeout=90)
    check(result.code == 0 and result.stdout == "same\n" and "same\n" in result.stderr,
          f"task run: exit {result.code} stdout {result.stdout!r} stderr {result.stderr[-200:]!r}")
    dirs = [d for d in out.iterdir()] if out.exists() else []
    check(len(dirs) == 1 and dirs[0].name.startswith("task_"), f"results directories {dirs}")
    saved = {p.name: p.read_bytes() for p in dirs[0].iterdir()}
    check(saved.get("stdout.log") == b"same\n" and saved.get("stderr.log") == b"same\n" and "changes.tar" in saved
          and "deleted.txt" not in saved, f"saved results {sorted(saved)}")


def small_bounds():
    b = state["b"]
    enable("--for", state["alice_principal"], "--for", state["bob_principal"], "--max-output-bytes", "100",
           "--max-artifact-bytes", "30000")
    events = final(submit(["bytes", "1000"]))
    result = result_of(events[-1])
    check(len(stream(events, "stdout")) == 100 and result["output_truncated"] is True
          and result["stdout_bytes"] == 1000, f"streamed {len(stream(events, 'stdout'))}, result {result}")
    # stdout.log fits, stderr.log does not.
    last = final(submit(["echo", "a", ";", "stderr", "y" * 4000, "y" * 4000, "y" * 4000, "y" * 4000,
                         "y" * 4000, "y" * 4000, "y" * 4000, "y" * 4000]))[-1]
    result = result_of(last)
    check(names(last) == ["stdout.log"] and result["results_dropped"] == ["stderr.log"],
          f"drops: {names(last)} {result['results_dropped']}")
    # A result that does not fit is skipped and later ones are still tried.
    last = final(submit(["bytes", "40000", ";", "stderr", "e"]))[-1]
    result = result_of(last)
    check(names(last) == ["stderr.log"] and result["results_dropped"] == ["stdout.log"],
          f"a later result after a drop: {names(last)} {result['results_dropped']}")
    # changes.tar does not fit with the input archive: deleted.txt goes with it; a drop never fails the task.
    entry = changes_workspace()
    big = ["y" * 4000] * 4
    last = final(submit(["write", "big.txt", *big, ";", "rm", "gone.txt"], results="changes", artifacts=[entry],
                        workspace={"archive": entry["sha256"]}))[-1]
    result = result_of(last)
    check(last["kind"] == "succeeded" and "changes.tar" not in names(last) and "deleted.txt" not in names(last)
          and result["results_dropped"] == ["changes.tar", "deleted.txt"],
          f"changes drop: {last['kind']} {names(last)} {result['results_dropped']}")
    # An input archive over max_artifact_bytes is refused at submission (403).
    huge = upload(b, make_tar({f"f{i}.bin": os.urandom(8000) for i in range(5)}))
    status, body = peer_submit(raw_task(run={"argv": ["echo"], "workspace": {"archive": huge["sha256"]}},
                                        artifacts=[huge]))
    check(status == 403, f"an input over max_artifact_bytes: {status} {body}")


def zero_bounds():
    enable("--for", state["alice_principal"], "--for", state["bob_principal"], "--max-output-bytes", "0",
           "--max-artifact-bytes", "0")
    events = final(submit(["echo", "hi"]))
    result = result_of(events[-1])
    check(not [e for e in events if e["kind"] == "output"], "output events under max_output_bytes 0")
    check(result["output_truncated"] is True and result["results_dropped"] == ["stdout.log"] and not names(events[-1]),
          f"bounds 0: {result} {names(events[-1])}")
    entry = changes_workspace()
    status, body = peer_submit(raw_task(run={"argv": ["echo"], "workspace": {"archive": entry["sha256"]}},
                                        artifacts=[entry]))
    check(status == 403, f"a workspace under max_artifact_bytes 0: {status} {body}")


@suite.case("small_bounds", "runtime Output events (max_output_bytes, output_truncated); Result artifacts (drops); "
                            "Checks step 3 (input over max_artifact_bytes)")
def _():
    a, b = need("a", "b")
    need("ready")
    try:
        small_bounds()
        zero_bounds()
    finally:
        enable("--for", state["alice_principal"], "--for", state["bob_principal"])


# The CLI (runtime CLI and local API) and administration (runtime Runtime administration).

@suite.case("task_run_exit_codes_and_detach", "runtime CLI: exit_code, 128+signal, 124, 125; --detach; --input")
def _():
    a, b = need("a", "b")
    need("ready")
    for argv, want in ((["echo", "hi"], 0), (["exit", "3"], 3), (["kill", "9"], 137)):
        result = b.cli("task", "run", "--peer", a.id, "--", *argv, timeout=60)
        check(result.code == want, f"task run -- {' '.join(argv)}: exit {result.code}, want {want} "
                                   f"{result.stderr.strip()[-200:]}")
    result = b.cli("task", "run", "--peer", a.id, "--timeout", "1s", "--", "sleep", "5", timeout=60)
    check(result.code == 124, f"a timed-out run: exit {result.code}, want 124")
    holder = occupy(5)
    result = b.cli("task", "run", "--peer", a.id, "--deadline", rfc3339(a.now() + timedelta(seconds=3)), "--",
                   "echo", "late", timeout=60)
    check(result.code == 125, f"an expired run: exit {result.code}, want 125")
    cancel(holder)
    # A cancelled task ends "otherwise": 125, even with a run result carrying signal 9.
    cancelled = {}
    follower = threading.Thread(target=lambda: cancelled.setdefault(
        "result", b.cli("task", "run", "--peer", a.id, "--", "sleep", "30", timeout=90)))
    follower.start()

    def running_task():
        tasks, after = [], 0
        while True:  # task list pages like messages: [{sequence, task}]
            status, page = b.api("GET", f"/v1/tasks?after={after}")
            check(status == 200, f"task list: {status} {page}")
            if not page:
                break
            tasks += page
            after = page[-1]["sequence"]
        for item in reversed(tasks):
            request = item["task"]["request"]
            if request.get("run", {}).get("argv") == ["sleep", "30"] and item["task"]["status"] \
                    and item["task"]["status"]["state"] == "running":
                return request["task_id"]
        return None
    task_id = wait_for(running_task, timeout=30, interval=0.5, message="the followed task to be running")
    cancel(task_id)
    follower.join(timeout=60)
    check("result" in cancelled and cancelled["result"].code == 125,
          f"a cancelled task run: exit {cancelled.get('result') and cancelled['result'].code}, want 125")
    result = b.cli("--json", "task", "run", "--peer", a.id, "--detach", "--", "echo", "detached", timeout=30)
    check(result.ok and isinstance(result.json, dict) and result.json["request"]["executor"] == "runtime"
          and result.json["request"]["input"] == "echo detached", f"--detach: exit {result.code} {result.stdout[-300:]}")
    final(result.json["request"]["task_id"])

# Agents (runtime Agents).

@suite.case("adapter_runs_and_notifications", "runtime Agents: POST /adapter/v1/runs; Output notifications")
def _():
    a, b = need("a", "b")
    need("ready")
    bert = b.agent("bert")
    route = b.cli("adapter", "route", "add", "--adapter", bert.adapter_id, "--name", "rt", "--peer", a.id,
                  "--action", "runtime.run", "--expires-in", "1h")
    check(route.ok, f"a runtime.run route naming alice's host: exit {route.code} {route.stderr.strip()[-300:]}")
    state["route"] = "rt"
    entry = adapter_upload(bert, make_tar({"in.txt": b"from the agent\n"}))
    task_id = new_task_id()
    argv = ["cat", "in.txt"]
    for i in range(6):
        argv += [";", "sleep", "0.35", ";", "echo", f"line{i}"]
    body = {"destination": state["route"], "task_id": task_id, "run": {"argv": argv},
            "workspace_archive": entry["sha256"]}
    status, record = bert.post("/adapter/v1/runs", body)
    check(status == 200 and record["request"]["executor"] == "runtime", f"POST /adapter/v1/runs: {status} {record}")
    check(record["request"].get("artifacts") and record["request"]["artifacts"][0]["sha256"] == entry["sha256"],
          f"the workspace archive is not the input manifest: {record['request'].get('artifacts')}")
    status, again = bert.post("/adapter/v1/runs", body)
    check(status == 200 and again["request"]["task_id"] == task_id, f"an identical repeat: {status} {again}")
    status, again = bert.post("/adapter/v1/runs", dict(body, run={"argv": ["echo"]}))
    check(status == 409, f"the same task_id with another run: {status} {again}")
    events = final(task_id)
    check(events[-1]["kind"] == "succeeded" and stream(events, "stdout").startswith(b"from the agent\n"),
          f"events {[e['kind'] for e in events]}")
    status, view = bert.call("GET", f"/adapter/v1/delegations/{task_id}")
    check(status == 200 and view["request"]["task_id"] == task_id, f"task_status for a runtime task: {status}")
    # Drain the task-update notifications of this task until the final one.
    notified = []

    def drained():
        while True:
            status, claim = bert.post("/adapter/v1/task-updates/next")
            check(status == 200, f"task-updates/next: {status} {claim}")
            if claim is None:
                return any(n["kind"] in FINAL for n in notified)
            event = claim["event"]
            if claim.get("delivery", {}).get("task_id", task_id) == task_id:
                notified.append(event)
            bert.post(f"/adapter/v1/task-updates/{claim['delivery']['id']}/forwarded")
    wait_for(drained, timeout=40, interval=0.5, message="the final task update")
    local = b.api("GET", f"/v1/tasks/{a.id}/{task_id}/events")[1]
    outputs = [e for e in local if e["kind"] == "output"]
    told = [e for e in notified if e["kind"] == "output"]
    check(len(outputs) >= 3, f"only {len(outputs)} output events were stored on bob's host")
    check(told and len(told) < len(outputs), f"{len(told)} output notifications for {len(outputs)} output events")
    check(told[-1]["sequence"] == outputs[-1]["sequence"], "the last output event before the final one was not notified")
    others = [e["kind"] for e in notified if e["kind"] != "output"]
    check(others[-1] == "succeeded" and "queued" in others, f"other notifications {others}")


@suite.case("mcp_run_task", "runtime Agents: MCP run_task with a workspace path; output notifications and meta.output")
def _():
    a, b = need("a", "b")
    need("ready")
    work = b.root / "mcp-ws"
    work.mkdir()
    (work / "note.txt").write_text("packed by the adapter\n")
    channel = mcp_channel("bea", "rt-mcp")
    try:
        argv = ["cat", "note.txt"]
        for i in range(5):
            argv += [";", "sleep", "0.4", ";", "echo", f"tick{i}"]
        task_id = channel.run_task({"destination": "rt-mcp", "argv": argv, "workspace_path": str(work),
                                    "results": "output"})
        updates, contents = channel.task_updates(task_id)
        # Output notifications are the running-state updates that carry meta.output text.
        outputs = [m for m in updates if m.get("state") == "running" and m.get("output")]
        text = "".join(m["output"] for m in outputs)
        want = "packed by the adapter\n" + "".join(f"tick{i}\n" for i in range(5))
        check(text == want, f"meta.output across {len(outputs)} output notifications: {text!r}, want {want!r}")
        events = b.api("GET", f"/v1/tasks/{a.id}/{task_id}/events")[1]
        stored = len([e for e in events if e["kind"] == "output"])
        check(stored < 3 or len(outputs) < stored, f"{len(outputs)} output notifications for {stored} output events")
        last, content = updates[-1], contents[-1]
        text = "".join(c.get("text", "") for c in content) if isinstance(content, list) else str(content or "")
        check(last.get("state") == "succeeded" and '"exit_code":0' in text.replace(" ", ""),
              f"final update {last}, content {text[:300]!r}: want the run result as the content")
    finally:
        channel.close()


suite.finish()
