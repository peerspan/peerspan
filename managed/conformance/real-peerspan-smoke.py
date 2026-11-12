#!/usr/bin/env python3
"""Isolated actual Peerspan transport smoke with a scripted adapter, never a model.

Uses only the public managed CLI/HTTP and existing spec-authored host harness.
All hosts, network membership, authorization, credentials and state are throwaway.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.request

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "conformance" / "slim"))

from harness import Suite, check, create_network, free_port, join_new_person, ssh_key, wait_for
import runtime_common


suite = Suite("managed-real-scripted", "Real Peerspan transport, isolated scripted adapter, no model")
runtime_common.bind(suite)


def node_24():
    node = shutil.which("node")
    check(node is not None, "Node 24 is required")
    version = subprocess.check_output([node, "--version"], text=True).strip()
    check(version.startswith("v24."), f"Node 24 required, found {version}")
    return node


def two_hosts(prefix, agent_name=None):
    """A worker host with a scripted agent, and a second person's sender host with task access to it."""
    worker = suite.host(f"{prefix}-worker")
    sender = suite.host(f"{prefix}-sender")
    network = create_network(worker, f"SCRIPTED-{prefix.upper()}", "ScriptedWorkerOwner")
    network_id = network.get("id") or network.get("network_id")
    check(network_id, f"network creation returned no ID: {network}")
    join_new_person(worker, sender, "ScriptedSenderOwner", ssh_key(sender.root, f"{prefix}-person"), network_id)
    adapter = worker.agent(agent_name or f"SCRIPTED-{prefix.upper()}")
    worker.ok("allow", "ScriptedSenderOwner", "--agent", adapter.name, "--network", network_id)
    worker.managed_network = network_id
    return worker, sender, adapter


def another_agent(worker, name):
    """A second scripted agent on the worker host, with task access for the same sender."""
    adapter = worker.agent(name)
    worker.ok("allow", "ScriptedSenderOwner", "--agent", adapter.name, "--network", worker.managed_network)
    return adapter


class Controller:
    """A managed controller on throwaway state, driven through its documented CLI and HTTP API."""

    def __init__(self, node, sender, name):
        self.command = [node, str(REPO / "managed" / "cli.mjs")]
        self.state = suite.work / f"private-managed-{name}"
        self.environment = {**sender.env, "PEERSPAN_BIN": str(suite.host_bin), "MANAGED_TICK_MS": "100"}
        self.port = free_port(socket.SOCK_STREAM)
        self.process = None
        self.token = None
        self.log_path = suite.work / f"managed-{name}.log"

    def cli(self, *args):
        result = subprocess.run([*self.command, *map(str, args), "--state", str(self.state)],
                                env=self.environment, capture_output=True, text=True, timeout=30)
        check(result.returncode == 0, f"managed {args[0]} failed: {result.stderr[-500:]}")
        return result.stdout.strip()

    def start(self):
        log = self.log_path.open("wb")
        self.process = suite.spawn([*self.command, "serve", "--state", str(self.state), "--port", str(self.port)],
                                   env=self.environment, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        log.close()
        self.token = self.cli("token")
        wait_for(self.healthy, timeout=15, message="managed loopback server")

    def request(self, method, route, body=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{route}", data=data, method=method,
                                     headers={"Authorization": "Bearer " + self.token,
                                              "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as response:
            return json.load(response)

    def healthy(self):
        check(self.process.poll() is None, f"managed controller exited early: {self.log_path.read_text()[-800:]}")
        try:
            return self.request("GET", "/health").get("ok")
        except urllib.error.URLError:
            return False

    def connection(self, connection_id):
        snapshot = self.request("GET", "/api/snapshot")
        return next(row for row in snapshot["connections"] if row["id"] == connection_id)

    def wait_ready(self, connection_id, worker, adapter, sender):
        seen = {}

        def ready():
            row = self.connection(connection_id)
            seen.update(row["readiness"])
            return row if row["readiness"]["ready"] else False

        try:
            return wait_for(ready, timeout=20, message="actual host and scripted adapter readiness")
        except AssertionError:
            upstream_status = worker.cli("--json", "status")
            upstream_connection = worker.ok("adapter", "connection", adapter.adapter_id)
            sender_status = sender.cli("--json", "status")
            status = upstream_status.json or {}
            summary = {"exit": upstream_status.code, "host_id": status.get("host_id"),
                       "agents": status.get("agents"), "attention": status.get("attention"),
                       "service": {key: value for key, value in status.get("service", {}).items() if key != "unit"},
                       "sender_exit": sender_status.code, "sender_host": (sender_status.json or {}).get("host_id")}
            raise AssertionError(f"actual readiness failed: {seen}; status={summary}; "
                                 f"connection={upstream_connection}") from None

    def run(self, workflow_id, state):
        rows = self.request("GET", "/api/snapshot")["runs"]
        matches = [row for row in rows if row["workflowId"] == workflow_id and row["state"] == state]
        return matches[0] if matches else False


@suite.case("real-managed-task", "managed contract: separate real Peerspan compatibility smoke")
def actual_transport():
    node = node_24()
    worker, sender, adapter = two_hosts("scripted")
    worker_state = suite.work / "scripted-worker.json"
    worker_state.write_text(json.dumps({"host_dir": str(worker.state), "host_id": worker.id,
                                       "agent_id": adapter.id, "adapter_id": adapter.adapter_id,
                                       "session_id": adapter.session_id}))
    worker_state.chmod(0o600)
    managed = Controller(node, sender, "file")
    connection = json.loads(managed.cli("connect", "--name", "SCRIPTED TRANSPORT SMOKE — no model",
                                        "--worker-state", worker_state, "--sender-state", sender.state))
    managed.start()
    managed.wait_ready(connection["id"], worker, adapter, sender)

    instructions = "SCRIPTED TRANSPORT SMOKE ONLY. Produce the predetermined receipt; no model executes this."
    workflow = managed.request("POST", "/api/workflows", {
        "name": "SCRIPTED real transport smoke — no model", "connectionId": connection["id"],
        "instructions": instructions, "intervalMinutes": 60, "maxRunsPerDay": 1,
        "acceptanceMinutes": 2, "enabled": True})
    handoff = adapter.next_task(timeout=30)
    check(handoff["task"]["input"] == instructions, "transport changed exact workflow instructions")
    task_id = handoff["task"]["task_id"]
    check(handoff["status"]["sender_host_id"] == sender.id, "task arrived from unexpected sender")
    code, accepted = adapter.post(f"/adapter/v1/tasks/{task_id}/accept")
    check(code == 200 and accepted["state"] == "running", f"scripted accept failed: {code}")

    running = wait_for(lambda: managed.run(workflow["id"], "running"), timeout=20, message="managed running result")
    check(running["taskId"] == task_id, "managed task ID differs from actual adapter handoff")
    output = "SCRIPTED PEERSPAN TRANSPORT RECEIPT: real two-host delivery succeeded; no model was called."
    code, completed = adapter.post(f"/adapter/v1/tasks/{task_id}/complete",
                                   {"status": "succeeded", "output": output})
    check(code == 200 and completed["state"] == "succeeded", f"scripted completion failed: {code}")
    result = wait_for(lambda: managed.run(workflow["id"], "succeeded"), timeout=20,
                      message="actual remote completion retained")
    check(result["taskId"] == task_id, "completion changed task ID")
    upstream = sender.ok("task", "inspect", "--peer", worker.id, task_id)
    check(upstream["status"]["state"] == "succeeded", "actual upstream record is not succeeded")
    events = wait_for(lambda: sender.ok("task", "events", "--peer", worker.id, task_id),
                      timeout=10, message="actual task events")
    check(any(event.get("output") == output for event in events), "real completion event lost output")
    try:
        wait_for(lambda: managed.run(workflow["id"], "succeeded")["output"] == output,
                 timeout=10, message="actual task-event output retained by managed")
    except AssertionError:
        raise AssertionError(f"managed output={managed.run(workflow['id'], 'succeeded')['output']!r}; "
                             f"actual status={upstream['status']}; actual events={events}") from None
    print("  Real two-host membership, signed access, verified scripted adapter, task and output checked; no model.",
          flush=True)
    adapter.stop()


@suite.case("real-agent-cancel", "managed contract rev 2: agent registration, hyphen input, timeline, cancel")
def agent_mode_and_cancel():
    node = node_24()
    worker, sender, adapter = two_hosts("agentmode")
    managed = Controller(node, sender, "agent")
    # Registration by agent name; a sender that is the worker host itself is refused.
    same = subprocess.run([*managed.command, "connect", "--name", "SCRIPTED same host", "--agent", adapter.name,
                           "--host-state", str(worker.state), "--sender-state", str(worker.state),
                           "--state", str(managed.state)],
                          env=managed.environment, capture_output=True, text=True, timeout=30)
    check(same.returncode != 0 and "same Peerspan host" in same.stderr,
          f"a sender that is the worker host was accepted: {same.returncode} {same.stderr[-300:]}")
    connection = json.loads(managed.cli("connect", "--name", "SCRIPTED agent-mode worker — no model",
                                        "--agent", adapter.name, "--host-state", worker.state,
                                        "--sender-state", sender.state))
    check(connection["mode"] == "agent" and connection["agentId"] == adapter.id and connection["hostId"] == worker.id,
          f"agent registration pinned the wrong identity: {connection}")
    managed.start()
    managed.wait_ready(connection["id"], worker, adapter, sender)

    # Instructions that begin with a hyphen must reach the agent byte for byte.
    instructions = "- SCRIPTED first step: report progress, then wait for cancellation.\n--json is text here, not an option."
    workflow = managed.request("POST", "/api/workflows", {
        "name": "SCRIPTED cancellation smoke — no model", "connectionId": connection["id"],
        "instructions": instructions, "intervalMinutes": 60, "maxRunsPerDay": 2,
        "acceptanceMinutes": 2, "enabled": True})
    handoff = adapter.next_task(timeout=30)
    check(handoff["task"]["input"] == instructions,
          f"transport changed instructions that begin with a hyphen: {handoff['task']['input']!r}")
    task_id = handoff["task"]["task_id"]
    code, _ = adapter.post(f"/adapter/v1/tasks/{task_id}/accept")
    check(code == 200, f"scripted accept failed: {code}")
    progress = "SCRIPTED progress: step 1 of 2"
    code, _ = adapter.post(f"/adapter/v1/tasks/{task_id}/progress", {"message": progress})
    check(code == 200, f"scripted progress failed: {code}")

    running = wait_for(lambda: (row := managed.run(workflow["id"], "running")) and row["progress"] == progress and row,
                       timeout=20, message="progress from actual task events in the run")
    detail = managed.request("GET", f"/api/runs/{running['id']}")
    kinds = [event["kind"] for event in detail["events"]]
    check(kinds[:3] == ["queued", "accepted", "progress"], f"actual timeline not retained in order: {kinds}")
    check(detail["run"]["instructions"] == instructions, "run detail lost the exact submitted instructions")

    # Cancellation is a request through actual transport; the run ends only when the agent confirms.
    managed.request("POST", f"/api/runs/{running['id']}/cancel", {})

    def cancel_delivered():
        status, body = adapter.post("/adapter/v1/tasks/cancels/next")
        check(status == 200, f"cancels/next: {status} {body}")
        return body

    request = wait_for(cancel_delivered, timeout=20, message="the cancellation request at the worker's adapter")
    check(request["status"]["task_id"] == task_id, f"cancellation reached another task: {request}")
    still = managed.run(workflow["id"], "running")
    check(still and still["cancelRequestedAt"], "the run left running before the agent confirmed cancellation")
    code, confirmed = adapter.post(f"/adapter/v1/tasks/{task_id}/cancelled")
    check(code == 200 and confirmed["state"] == "cancelled", f"scripted cancellation failed: {code} {confirmed}")
    wait_for(lambda: managed.run(workflow["id"], "cancelled"), timeout=20, message="the confirmed cancellation retained")
    snapshot = managed.request("GET", "/api/snapshot")
    current = next(row for row in snapshot["workflows"] if row["id"] == workflow["id"])
    check(current["failureStreak"] == 0, f"an operator cancellation counted as a failure: {current['failureStreak']}")
    kinds = [entry["kind"] for entry in snapshot["activity"]]
    check("run.cancel_requested" in kinds and "run.finished" in kinds, f"activity missing cancellation: {kinds}")
    print("  Agent registration, hyphen input, progress timeline and confirmed cancellation checked; no model.",
          flush=True)
    adapter.stop()


@suite.case("real-remote-worker", "managed contract rev 3: remote worker, schedule with run now, operator review")
def remote_worker():
    node = node_24()
    # The sender's directory lists only addressable agents: lowercase names, as attach creates.
    worker, sender, adapter = two_hosts("remote", "scripted-remote")
    managed = Controller(node, sender, "remote")
    # The sender lists the agent once the worker owner's new policy has reached it by sync.
    wait_for(lambda: any(entry.get("agent_id") == adapter.id
                         for entry in (sender.cli("--json", "agents", "--refresh").json or {}).get("reachable", [])),
             timeout=40, interval=1, message="the worker's agent in the sender's directory")
    # Only the sender's state is named: the worker host is treated as another machine's.
    connection = json.loads(managed.cli("connect", "--name", "SCRIPTED remote worker — no model",
                                        "--remote", adapter.id, "--sender-state", sender.state))
    check(connection["mode"] == "remote" and connection["agentId"] == adapter.id and connection["hostId"] == worker.id,
          f"remote registration pinned the wrong identity: {connection}")
    managed.start()
    ready = managed.wait_ready(connection["id"], worker, adapter, sender)
    check(ready["readiness"]["code"] == "ready" and ready["readiness"]["directoryAt"],
          f"remote readiness lacks the directory evidence: {ready['readiness']}")

    instructions = "SCRIPTED REMOTE SMOKE ONLY. Produce the predetermined receipt; no model executes this."
    workflow = managed.request("POST", "/api/workflows", {
        "name": "SCRIPTED remote scheduled smoke — no model", "connectionId": connection["id"],
        "instructions": instructions, "schedule": {"timeZone": "UTC", "days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
                                                   "times": ["00:00"]},
        "review": "operator", "maxRunsPerDay": 2, "acceptanceMinutes": 2, "enabled": True})
    check(workflow["schedule"]["times"] == ["00:00"] and workflow["intervalMinutes"] is None,
          f"schedule not stored as given: {workflow}")
    # The next slot is up to a day away; run now makes it due without bypassing readiness.
    managed.request("POST", f"/api/workflows/{workflow['id']}/run", {})
    handoff = adapter.next_task(timeout=30)
    check(handoff["task"]["input"] == instructions, "transport changed exact workflow instructions")
    task_id = handoff["task"]["task_id"]
    code, _ = adapter.post(f"/adapter/v1/tasks/{task_id}/accept")
    check(code == 200, f"scripted accept failed: {code}")
    output = "SCRIPTED REMOTE RECEIPT: delivered through the sender's directory entry; no model was called."
    code, _ = adapter.post(f"/adapter/v1/tasks/{task_id}/complete", {"status": "succeeded", "output": output})
    check(code == 200, f"scripted completion failed: {code}")
    run = wait_for(lambda: managed.run(workflow["id"], "succeeded"), timeout=20, message="remote completion retained")
    check(run["review"] == "pending" and run["output"] == output, f"a reviewed success did not wait for review: {run}")
    current = next(row for row in managed.request("GET", "/api/snapshot")["workflows"] if row["id"] == workflow["id"])
    check(current["stats"]["succeeded"] == 0 and current["stats"]["awaitingReview"] == 1,
          f"a pending result counted as a success: {current['stats']}")
    reviewed = managed.request("POST", f"/api/runs/{run['id']}/review", {"verdict": "accepted", "note": "  receipt matches  "})
    check(reviewed["review"] == "accepted" and reviewed["reviewNote"] == "receipt matches", f"verdict not kept: {reviewed}")
    current = next(row for row in managed.request("GET", "/api/snapshot")["workflows"] if row["id"] == workflow["id"])
    check(current["stats"]["succeeded"] == 1 and current["stats"]["awaitingReview"] == 0,
          f"an accepted result did not count: {current['stats']}")
    check(current["nextRunAt"].startswith(("20", "21")) and current["nextRunAt"][11:16] == "00:00",
          f"the next run is not the next 00:00 UTC slot: {current['nextRunAt']}")

    # The directory is refreshed at most once a minute: a lapsed lease shows within about that long.
    adapter.stop()
    lapsed = wait_for(lambda: (row := managed.connection(connection["id"]))["readiness"]["code"] == "session_not_ready" and row,
                      timeout=100, message="a lapsed remote session seen through the refreshed directory")
    check(not lapsed["readiness"]["ready"], f"a lapsed remote session stayed ready: {lapsed['readiness']}")
    print("  Remote registration, directory readiness, scheduled run now, operator review and lease lapse checked; no model.",
          flush=True)


REVIEW_HEADER = ("Review the result below, which an agent produced for the assignment that follows it. Decide whether "
                 "the result does what the assignment asks.\nBegin your answer with one line that says exactly "
                 "VERDICT: ACCEPT or VERDICT: REJECT. Then give your reasons briefly: the operator reads them, and "
                 "after a rejection the agent may receive them with the assignment.")


def review_input(assignment, criteria, result):
    """The review task's input of managed contract section 15.1."""
    return f"{REVIEW_HEADER}\n\nASSIGNMENT\n{assignment}\n\nCRITERIA\n{criteria}\n\nRESULT\n{result}"


def rework_input(instructions, note, result):
    """The rework's input of managed contract section 15.2."""
    return (f"{instructions}\n\nREVISION REQUESTED\nA reviewer rejected your previous result for this assignment. "
            f"Do the assignment again in full, addressing the review.\n\nREVIEW\n{note}\n\nPREVIOUS RESULT\n{result}")


def answer(adapter, expected_input, output, what):
    """Takes the adapter's next task, checks its exact input, accepts it and completes it with `output`."""
    handoff = adapter.next_task(timeout=30)
    check(handoff["task"]["input"] == expected_input,
          f"{what}: transport delivered another input than the contract's: {handoff['task']['input']!r}")
    task_id = handoff["task"]["task_id"]
    code, _ = adapter.post(f"/adapter/v1/tasks/{task_id}/accept")
    check(code == 200, f"{what}: scripted accept failed: {code}")
    code, _ = adapter.post(f"/adapter/v1/tasks/{task_id}/complete", {"status": "succeeded", "output": output})
    check(code == 200, f"{what}: scripted completion failed: {code}")
    return task_id


@suite.case("real-reviewer-agent", "managed contract rev 4: reviewer agent, rejection, rework and acceptance")
def reviewer_agent():
    node = node_24()
    worker, sender, adapter = two_hosts("review", "scripted-worker")
    reviewer = another_agent(worker, "scripted-reviewer")
    managed = Controller(node, sender, "review")
    register = lambda name, agent: json.loads(managed.cli(
        "connect", "--name", name, "--agent", agent.name, "--host-state", worker.state, "--sender-state", sender.state))
    worker_connection = register("SCRIPTED worker — no model", adapter)
    reviewer_connection = register("SCRIPTED reviewer — no model", reviewer)
    managed.start()
    managed.wait_ready(worker_connection["id"], worker, adapter, sender)
    managed.wait_ready(reviewer_connection["id"], worker, reviewer, sender)

    instructions = "SCRIPTED REVIEW SMOKE ONLY. Report the receipt number; no model executes this."
    criteria = "The result names the receipt number."
    workflow = managed.request("POST", "/api/workflows", {
        "name": "SCRIPTED reviewed smoke — no model", "connectionId": worker_connection["id"],
        "instructions": instructions, "intervalMinutes": 60, "maxRunsPerDay": 3, "acceptanceMinutes": 2,
        "review": "agent", "reviewerId": reviewer_connection["id"], "reviewCriteria": f"  {criteria}  ",
        "reworkLimit": 1, "enabled": True})
    check(workflow["reviewCriteria"] == criteria and workflow["reworkLimit"] == 1, f"review settings not kept: {workflow}")

    # Attempt 1: the reviewer agent rejects it with reasons, which go back to the worker.
    first = "SCRIPTED attempt 1: done."
    first_task = answer(adapter, instructions, first, "attempt 1")
    note = "SCRIPTED: the receipt number is missing."
    review_task = answer(reviewer, review_input(instructions, criteria, first), f"**VERDICT: REJECT**\n{note}",
                         "first review")
    check(review_task != first_task, "the review task reused the run's task ID")

    # Attempt 2, the rework, at once: the assignment, the review and the previous result.
    second = "SCRIPTED attempt 2: receipt 42."
    answer(adapter, rework_input(instructions, note, first), second, "rework")
    answer(reviewer, review_input(instructions, criteria, second), "verdict: accept\nSCRIPTED: receipt 42 is named.",
           "second review")

    def reviewed_rework():
        runs = [row for row in managed.request("GET", "/api/snapshot")["runs"] if row["workflowId"] == workflow["id"]]
        return runs if len(runs) == 2 and runs[0]["review"] == "accepted" else False

    rework, rejected = wait_for(reviewed_rework, timeout=30, message="the reviewed rework")
    check(rejected["review"] == "rejected" and rejected["reviewedBy"] == "agent" and rejected["reviewNote"] == note,
          f"the agent's rejection was not recorded: {rejected}")
    check(rejected["reviewTask"]["taskId"] == review_task and rejected["reviewTask"]["state"] == "succeeded",
          f"the first review task is not the one delivered: {rejected['reviewTask']}")
    check(rework["attempt"] == 2 and rework["reworkOf"] == rejected["id"] and rework["reviewedBy"] == "agent"
          and rework["reviewNote"] == "SCRIPTED: receipt 42 is named.", f"the rework was not recorded: {rework}")
    current = next(row for row in managed.request("GET", "/api/snapshot")["workflows"] if row["id"] == workflow["id"])
    check(current["stats"]["succeeded"] == 1 and current["stats"]["failed"] == 1 and current["reworkPending"] is None,
          f"statistics after a rejection and an accepted rework: {current['stats']}")
    upstream = sender.ok("task", "inspect", "--peer", worker.id, review_task)
    check(upstream["status"]["state"] == "succeeded", f"the review task is not a real succeeded task: {upstream['status']}")
    print("  Reviewer agent rejection, exact review and rework inputs, rework and acceptance over real transport; no model.",
          flush=True)
    adapter.stop()
    reviewer.stop()


@suite.case("real-runtime-agent", "managed contract rev 5: runtime agent ready without a session, run on a fork")
def runtime_agent():
    node = node_24()
    # alice's host runs upstream's fake runtime, which serves a peerfs space with a `main` branch; bob sends.
    runtime_common.setup_network(peerfs_workspace=["main"], max_concurrent_runs=2)
    alice, bob, runtime = runtime_common.need("a", "b", "rt")
    main = runtime.dir / "peerfs" / "main"
    main.mkdir(parents=True, exist_ok=True)
    (main / "README").write_text("SCRIPTED runtime smoke seed\n")
    status, body = alice.api("PUT", "/v1/runtime", {"socket": str(runtime.socket)})
    check(status == 200 and body.get("peerfs") is True, f"the runtime switch: {status} {body}")
    status, agent = alice.api("POST", "/v1/agents", {"name": "codex", "owner": "alice"})
    check(status in (200, 201), f"register codex: {status} {agent}")
    # Submissions cite the worker owner's policy, as for every managed run; bob sees it once it has synced.
    alice.ok("allow", "bob", "--agent", "codex", "--person-key", str(runtime_common.state["alice_key"]))
    wait_for(lambda: any(entry.get("agent_id") == agent["id"] and "task.submit" in entry.get("actions", [])
                         for entry in (bob.cli("--json", "agents", "--refresh").json or {}).get("reachable", [])),
             timeout=40, interval=1, message="alice's policy for codex at bob's host")

    managed = Controller(node, bob, "runtime")
    connection = json.loads(managed.cli("connect", "--name", "SCRIPTED runtime agent — no model", "--agent", "codex",
                                        "--host-state", alice.state, "--sender-state", bob.state))
    managed.start()

    def code(expected, what):
        return wait_for(lambda: (row := managed.connection(connection["id"]))["readiness"]["code"] == expected and row,
                        timeout=30, message=what)

    # Without a launch profile it is an ordinary agent with no session.
    code("session_not_ready", "an agent without a profile or a session")
    harness = suite.work / "scripted-codex-release"
    harness.mkdir()
    for binary in ("codex", "codex-code-mode-host"):
        (harness / binary).write_text("#!/bin/sh\nexit 0\n")
        (harness / binary).chmod(0o755)
    alice.ok("agent", "runtime", "set", "codex", "--harness-dir", str(harness), "--max-runs", "2")
    missing = code("runtime_credential_missing", "a launch profile without a credential")
    check(missing["readiness"]["runtime"] == {"fromBranch": "main", "network": "internet", "cpus": 2, "memoryMib": 2048,
                                              "timeoutSeconds": 3600, "maxRuns": 2},
          f"readiness does not summarize the launch profile: {missing['readiness']}")
    check(str(harness) not in json.dumps(managed.request("GET", "/api/snapshot")), "a launch profile path was returned")
    key = suite.work / "scripted-openai.key"
    key.write_text("sk-scripted-" + os.urandom(12).hex() + "\n")
    key.chmod(0o600)
    alice.ok("agent", "credential", "set", "codex", "--from-file", str(key))
    ready = code("ready_runtime", "a runtime agent ready without any session")
    check(ready["readiness"]["ready"] is True, f"ready_runtime is not ready: {ready['readiness']}")

    # The fake runtime acts as the agent: it runs the instructions as steps on a fork of `main`.
    workflow = managed.request("POST", "/api/workflows", {
        "name": "SCRIPTED runtime agent smoke — no model", "connectionId": connection["id"],
        "instructions": "write notes.txt SCRIPTED-RUNTIME-RECEIPT ; echo done", "intervalMinutes": 60,
        "maxRunsPerDay": 1, "acceptanceMinutes": 2, "enabled": True})
    run = wait_for(lambda: managed.run(workflow["id"], "succeeded"), timeout=60, message="the runtime agent's run")
    fork = f"codex.{run['taskId']}"
    branch = run["branch"]
    check(branch and branch["outcome"] == "committed" and branch["name"] == fork and len(branch["commit"]) == 66,
          f"the run's branch is not the committed fork: {branch} (output {run['output']!r})")
    check(run["output"].startswith("done\n\nBranch: " + fork + " at commit "), f"runtime agent output: {run['output']!r}")
    check((runtime.dir / "peerfs" / fork / "notes.txt").read_text() == "SCRIPTED-RUNTIME-RECEIPT"
          and not (main / "notes.txt").exists(), "the fork does not hold the write, or main changed")

    # The runtime switched off: the host would reject new tasks, so the worker is not ready.
    status, _ = alice.api("DELETE", "/v1/runtime")
    check(status == 200, f"switching the runtime off: {status}")
    code("runtime_disabled", "a runtime agent whose host's runtime is off")
    print("  Runtime agent readiness from its launch profile, a run on a peerfs fork with its branch, and the switch; "
          "no model.", flush=True)


suite.finish()
