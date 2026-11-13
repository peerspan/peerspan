#!/usr/bin/env python3
"""Slim suite, runtime_runs: running runtime tasks, their output, cancellation and restarts (RUN-1 to RUN-4).

alice creates a coordinator-free network and bob joins as another person; alice's host serves runtime tasks through
conformance/slim/fake_runtime.py (RUN-4), which reads `argv` as the step language of the contract's Verification
section and logs every request, so the suite sees what the runtime was asked to do. bob submits through the owner
API and the peer probe. Workspaces, results and the CLI and agent tools are runtime_results.py; authorization and
administration are runtime.py; peerfs workspaces (RUN-6, RUN-7) are runtime_peerfs.py; the shared fixtures are
runtime_common.py.

Not a suite case: the 250 ms output flush timing (a Rust test that drives the binaries).

Written from docs/runtime-task-contract.md only (cited as "runtime <section>"), with the task, artifact and
coordinator-free contracts it builds on. No VM, no KVM, no model calls.
"""
import base64
import tarfile
import time
from datetime import timedelta

from harness import Suite, check, rfc3339, wait_for
from runtime_common import (bind, cancel, enable_for_both, final, has_kind, make_tar, names, need, occupy, peer_events,
                            receiver_events, result_of, run_id, setup_network, show, state, stream, submit, upload)

suite = Suite("runtime_runs", __doc__)
bind(suite)


@suite.case("setup", "decentralized-spec 6, 8; runtime Runtime administration (runtime enable --for)")
def _():
    setup_network()
    enable_for_both()


# The lifecycle (runtime Running, Output events, The run result).

@suite.case("lifecycle_succeeded", "runtime Running (transitions, missing resources, dispatch), Output events, "
                                   "The run result")
def _():
    a, b, rt = need("a", "b", "rt")
    need("ready")
    task_id = submit(["echo", "hello", ";", "stderr", "oops"], env={"GREETING": "hi"}, cwd="/workspace/sub")
    events = final(task_id)
    kinds = [e["kind"] for e in events]
    check(kinds[0] == "queued" and kinds[1] == "accepted" and kinds[-1] == "succeeded"
          and set(kinds[2:-1]) <= {"output"} and "output" in kinds, f"events {kinds}")
    for e in events:
        check(("chunk" in e) and ((e["chunk"] is None) == (e["kind"] != "output")), f"chunk on {e['kind']}: {e}")
        if e["kind"] == "output":
            check(e["state"] == "running" and e["chunk"]["stream"] in ("stdout", "stderr"), f"output event {e}")
    check(stream(events, "stdout") == b"hello\n" and stream(events, "stderr") == b"oops\n",
          f"streams {stream(events, 'stdout')!r} {stream(events, 'stderr')!r}")
    result = result_of(events[-1])
    check(result["exit_code"] == 0 and result["signal"] is None and result["timed_out"] is False
          and result["stdout_bytes"] == 6 and result["stderr_bytes"] == 5 and result["output_truncated"] is False
          and result["results_dropped"] == [] and result["results_same"] == {} and result["error"] is None
          and isinstance(result["duration_ms"], int), f"run result {result}")
    check(names(events[-1]) == ["stdout.log", "stderr.log"], f"result artifacts {events[-1].get('artifacts')}")
    rid = run_id(b, task_id)
    posts = rt.entries("post", rid)
    check(posts and posts[0]["status"] == 201, f"the runtime saw no start for {rid} (run_id formula): "
                                               f"{[e.get('run_id') for e in rt.entries('post')][-3:]}")
    request = posts[0]["request"]
    check(request["resources"] == {"cpus": 2, "memory_mib": 2048, "timeout_seconds": 3600},
          f"missing resources take the rule's maximum: {request['resources']}")
    check(request["cwd"] == "/workspace/sub" and request["env"] == {"GREETING": "hi"}
          and request["workspace_archive"] is None and request["peerfs_workspace"] is None
          and request["results"] == "output", f"start request {request}")
    deleted = wait_for(lambda: rt.entries("delete", rid), timeout=10, message="the daemon to delete the run")
    check(deleted, "run not deleted")
    # The submitter's record shows executor, run and chunk (runtime CLI and local API).
    record = wait_for(lambda: (r := b.api("GET", f"/v1/tasks/{a.id}/{task_id}")[1])["events_after"] == len(kinds)
                      and r, timeout=30, message="bob's host to store every event")
    check(record["request"]["executor"] == "runtime" and record["request"]["run"]["argv"][0] == "echo",
          f"bob's record {record['request']}")
    local = b.api("GET", f"/v1/tasks/{a.id}/{task_id}/events")[1]
    check([e["kind"] for e in local] == kinds and all("chunk" in e for e in local), f"bob's events {local}")
    state["defaults_checked"] = True


@suite.case("failures", "runtime Running: failure by exit code, signal and timeout; The run result")
def _():
    need("ready")
    exit_task = submit(["echo", "x", ";", "exit", "3"])
    kill_task = submit(["kill", "9"])
    timeout_task = submit(["sleep", "5"], resources={"timeout_seconds": 1})
    for task_id, want in ((exit_task, {"exit_code": 3, "signal": None, "timed_out": False}),
                          (kill_task, {"exit_code": None, "signal": 9, "timed_out": False}),
                          (timeout_task, {"exit_code": None, "signal": None, "timed_out": True})):
        events = final(task_id)
        check(events[-1]["kind"] == "failed" and events[-1]["state"] == "failed", f"{want}: {[e['kind'] for e in events]}")
        check("accepted" in [e["kind"] for e in events], f"{want}: never running")
        result = result_of(events[-1])
        got = {k: result[k] for k in want}
        check(got == want and result["error"] is None, f"run result {result}, want {want}")
    check(result_of(final(timeout_task)[-1])["duration_ms"] >= 900, "the timeout run lasted under a second")


@suite.case("start_order_one_slot", "runtime Running: created_at order with one slot (max_concurrent_runs 1)")
def _():
    b, rt = need("b", "rt")
    need("ready")
    first = occupy(2)
    queued = []
    for i in range(3):
        queued.append(submit(["echo", str(i)]))
        receiver_events(queued[-1], until=lambda evs: bool(evs))  # created_at order is submission order
    for task_id in [first] + queued:
        check(final(task_id)[-1]["kind"] == "succeeded", f"{task_id} did not succeed")
    started = [e["run_id"] for e in rt.entries("started")]
    order = [started.index(run_id(b, t)) for t in queued]
    check(order == sorted(order), f"queued runs started out of order: {order}")


@suite.case("expiry_before_start", "runtime Running: queued to expired when not dispatched by the deadline")
def _():
    a, b, rt = need("a", "b", "rt")
    need("ready")
    holder = occupy(5)
    task_id = submit(["echo", "late"], deadline=rfc3339(a.now() + timedelta(seconds=3)))
    events = final(task_id, timeout=20)
    check([e["kind"] for e in events] == ["queued", "expired"], f"events {[e['kind'] for e in events]}")
    check(not rt.entries("post", run_id(b, task_id)), "an expired task was dispatched")
    cancel(holder)
    final(holder)


@suite.case("output_chunks", "runtime Output events: order per stream, 16,384-byte bound")
def _():
    need("ready")
    task_id = submit(["bytes", "40000", ";", "stderr", "e1", ";", "bytes", "10", ";", "stderr", "e2"])
    events = final(task_id)
    sizes = [len(base64.b64decode(e["chunk"]["data"])) for e in events if e["kind"] == "output"]
    check(sizes and all(1 <= n <= 16384 for n in sizes), f"chunk sizes {sizes}")
    check(stream(events, "stdout") == b"x" * 40010, f"stdout {len(stream(events, 'stdout'))} bytes")
    check(stream(events, "stderr") == b"e1\ne2\n", f"stderr {stream(events, 'stderr')!r}")
    result = result_of(events[-1])
    check(result["stdout_bytes"] == 40010 and result["output_truncated"] is False, f"run result {result}")


# Cancellation (runtime Running).

@suite.case("cancel_running", "runtime Running: running to cancelled with the run result, signal 9")
def _():
    need("ready")
    task_id = occupy(30)
    cancel(task_id)
    events = final(task_id, timeout=20)
    check(events[-1]["kind"] == "cancelled", f"events {[e['kind'] for e in events]}")
    result = result_of(events[-1])
    check(result["signal"] == 9 and result["exit_code"] is None, f"run result {result}")


@suite.case("cancel_queued", "runtime Running: queued, not dispatched, cancelled at once without a run result")
def _():
    b, rt = need("b", "rt")
    need("ready")
    holder = occupy(5)
    task_id = submit(["echo", "never"])
    receiver_events(task_id, until=lambda evs: evs and evs[0]["kind"] == "queued")
    cancel(task_id)
    events = final(task_id, timeout=10)
    check(events[-1]["kind"] == "cancelled" and events[-1]["output"] is None,
          f"events {[(e['kind'], e['output']) for e in events]}")
    check("accepted" not in [e["kind"] for e in events], "a cancelled queued task ran")
    cancel(holder)
    final(holder)
    time.sleep(0.5)
    check(not rt.entries("post", run_id(b, task_id)), "a cancelled queued task was dispatched")


@suite.case("cancel_during_start_delay", "runtime Running: cancelled after dispatch, before started; no command run")
def _():
    b, rt = need("b", "rt")
    need("ready")
    rt.restart(start_delay=3)
    try:
        task_id = submit(["echo", "never"])
        rid = run_id(b, task_id)
        wait_for(lambda: rt.entries("post", rid), timeout=15, interval=0.2, message="the dispatch")
        cancel(task_id)
        events = final(task_id, timeout=20)
        kinds = [e["kind"] for e in events]
        check(kinds[-1] == "cancelled" and "accepted" not in kinds, f"events {kinds}")
        check(rt.entries("cancel", rid), "the cancellation was not forwarded to the runtime")
        check(not rt.entries("started", rid) and not rt.entries("step", rid), "the command ran")
        if events[-1]["output"] is not None:
            result = result_of(events[-1])
            check(result["exit_code"] is None and result["duration_ms"] == 0, f"run result {result}")
    finally:
        rt.restart()


# The workspace (runtime Requests, Running; The runtime's local API guarantees).

@suite.case("failure_before_start", "runtime Running: queued to failed on a refused archive entry")
def _():
    a, b = need("a", "b")
    need("ready")
    for label, refused_entry in (("..", ("../evil", tarfile.REGTYPE)), ("absolute", ("/abs/evil", tarfile.REGTYPE)),
                                 ("fifo", ("pipe", tarfile.FIFOTYPE))):
        entry = upload(b, make_tar({"ok.txt": b"ok"}, refused=refused_entry))
        task_id = submit(["echo", "never"], artifacts=[entry], workspace={"archive": entry["sha256"]})
        events = final(task_id)
        kinds = [e["kind"] for e in events]
        check(kinds == ["queued", "failed"], f"{label}: events {kinds}")
        result = result_of(events[-1])
        name = refused_entry[0].lstrip("/") if label == "absolute" else refused_entry[0]
        check(result["exit_code"] is None and result["duration_ms"] == 0 and result["error"]
              and name in result["error"], f"{label}: run result {result}")


# Peer events (runtime Submitter, Peer events).

@suite.case("peer_events_wait", "runtime Peer events: wait=S holds until an event, returns early")
def _():
    need("ready")
    task_id = submit(["sleep", "2", ";", "echo", "late"])
    events = receiver_events(task_id, until=has_kind("accepted"))
    began = time.monotonic()
    status, got = peer_events(task_id, after=len(events), wait=10)
    took = time.monotonic() - began
    check(status == 200 and got, f"wait=10 answered {status} {got}")
    check(0.8 <= took < 8, f"wait=10 returned after {took:.1f}s, want once the next event arrives (about 2s)")
    events = final(task_id)
    began = time.monotonic()
    status, got = peer_events(task_id, after=len(events), wait=0)
    check(status == 200 and got == [] and time.monotonic() - began < 3, f"wait=0 after the last event: {status} {got}")


# Restarts (runtime The runtime's local API: restarted daemon).

@suite.case("restart_daemon_during_run", "runtime The runtime's local API: a restarted daemon reattaches; "
                                         "run --runtime-socket")
def _():
    a, rt = need("a", "rt")
    need("ready")
    task_id = submit(["sleep", "3", ";", "echo", "after the restart"])
    receiver_events(task_id, until=has_kind("accepted"))
    a.stop(kill=True)
    a.extra_args = ["--runtime-socket", str(rt.socket)]
    a.start()
    shown = show(a)
    check(shown["enabled"] is True and shown["socket"] == str(rt.socket), f"run --runtime-socket: {shown}")
    events = final(task_id, timeout=30)
    check(events[-1]["kind"] == "succeeded" and stream(events, "stdout") == b"after the restart\n",
          f"after reattaching: {[e['kind'] for e in events]} {stream(events, 'stdout')!r}")


@suite.case("restart_daemon_after_dispatch", "runtime The runtime's local API: an unanswered start is resent (200)")
def _():
    a, b, rt = need("a", "b", "rt")
    need("ready")
    rt.restart(start_delay=4)
    try:
        task_id = submit(["echo", "resumed"])
        rid = run_id(b, task_id)
        wait_for(lambda: rt.entries("post", rid), timeout=15, interval=0.2, message="the dispatch")
        a.stop(kill=True)
        a.start()
        posts = wait_for(lambda: len(rt.entries("post", rid)) >= 2 and rt.entries("post", rid), timeout=20,
                         message="the restarted daemon to resend the start")
        check(posts[0]["status"] == 201 and posts[1]["status"] == 200 and posts[1]["request"] == posts[0]["request"],
              f"start answers {[p['status'] for p in posts]}; identical: {posts[1]['request'] == posts[0]['request']}")
        events = final(task_id, timeout=30)
        check(events[-1]["kind"] == "succeeded" and stream(events, "stdout") == b"resumed\n",
              f"events {[e['kind'] for e in events]}")
        check(len(rt.entries("started", rid)) == 1, "the run started twice")
    finally:
        rt.restart()


@suite.case("restart_runtime_during_run", "runtime The runtime's local API: a lost run fails with the runtime restarted")
def _():
    rt, = need("rt")
    need("ready")
    task_id = submit(["sleep", "5", ";", "echo", "never"])
    receiver_events(task_id, until=has_kind("accepted"))
    rt.restart()
    events = final(task_id, timeout=40)
    check(events[-1]["kind"] == "failed" and "accepted" in [e["kind"] for e in events],
          f"events {[e['kind'] for e in events]}")
    result = result_of(events[-1])
    check(result["error"] == "the runtime restarted" and result["exit_code"] is None, f"run result {result}")


@suite.case("restart_runtime_during_start_delay", "runtime The runtime's local API: a lost dispatched run fails "
                                                  "from queued")
def _():
    b, rt = need("b", "rt")
    need("ready")
    rt.restart(start_delay=4)
    try:
        task_id = submit(["echo", "never"])
        wait_for(lambda: rt.entries("post", run_id(b, task_id)), timeout=15, interval=0.2, message="the dispatch")
        rt.restart(start_delay=4)
        events = final(task_id, timeout=40)
        check([e["kind"] for e in events] == ["queued", "failed"], f"events {[e['kind'] for e in events]}")
        result = result_of(events[-1])
        check(result["error"] == "the runtime restarted" and result["exit_code"] is None
              and result["duration_ms"] == 0, f"run result {result}")
    finally:
        rt.restart()

suite.finish()
