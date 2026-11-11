#!/usr/bin/env python3
"""Isolated actual Peerspan transport smoke with a scripted adapter, never a model.

Uses only the public managed CLI/HTTP and existing spec-authored host harness.
All hosts, network membership, authorization, credentials and state are throwaway.
"""
from __future__ import annotations

import json
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


suite = Suite("managed-real-scripted", "Real Peerspan transport, isolated scripted adapter, no model")


def node_24():
    node = shutil.which("node")
    check(node is not None, "Node 24 is required")
    version = subprocess.check_output([node, "--version"], text=True).strip()
    check(version.startswith("v24."), f"Node 24 required, found {version}")
    return node


def two_hosts(prefix):
    """A worker host with a scripted agent, and a second person's sender host with task access to it."""
    worker = suite.host(f"{prefix}-worker")
    sender = suite.host(f"{prefix}-sender")
    network = create_network(worker, f"SCRIPTED-{prefix.upper()}", "ScriptedWorkerOwner")
    network_id = network.get("id") or network.get("network_id")
    check(network_id, f"network creation returned no ID: {network}")
    join_new_person(worker, sender, "ScriptedSenderOwner", ssh_key(sender.root, f"{prefix}-person"), network_id)
    adapter = worker.agent(f"SCRIPTED-{prefix.upper()}")
    worker.ok("allow", "ScriptedSenderOwner", "--agent", adapter.name, "--network", network_id)
    return worker, sender, adapter


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


suite.finish()
