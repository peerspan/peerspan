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


@suite.case("real-managed-task", "managed contract: separate real Peerspan compatibility smoke")
def actual_transport():
    node = shutil.which("node")
    check(node is not None, "Node 24 is required")
    version = subprocess.check_output([node, "--version"], text=True).strip()
    check(version.startswith("v24."), f"Node 24 required, found {version}")
    worker = suite.host("scripted-worker")
    sender = suite.host("scripted-sender")
    network = create_network(worker, "SCRIPTED-MANAGED-SMOKE", "ScriptedWorkerOwner")
    network_id = network.get("id") or network.get("network_id")
    check(network_id, f"network creation returned no ID: {network}")
    join_new_person(worker, sender, "ScriptedSenderOwner", ssh_key(sender.root, "scripted-person"),
                    network_id)
    adapter = worker.agent("SCRIPTED-MANAGED-SMOKE")
    worker.ok("allow", "ScriptedSenderOwner", "--agent", adapter.name,
              "--network", network_id)
    worker_state = suite.work / "scripted-worker.json"
    worker_state.write_text(json.dumps({"host_dir": str(worker.state), "host_id": worker.id,
                                       "agent_id": adapter.id, "adapter_id": adapter.adapter_id,
                                       "session_id": adapter.session_id}))
    worker_state.chmod(0o600)
    managed_state = suite.work / "private-managed"
    environment = {**sender.env, "PEERSPAN_BIN": str(suite.host_bin), "MANAGED_TICK_MS": "100"}
    command = [node, str(REPO / "managed" / "cli.mjs")]

    def managed(*args):
        result = subprocess.run([*command, *map(str, args), "--state", str(managed_state)],
                                env=environment, capture_output=True, text=True, timeout=15)
        check(result.returncode == 0, f"managed {args[0]} failed: {result.stderr[-500:]}")
        return result.stdout.strip()

    connection = json.loads(managed("connect", "--name", "SCRIPTED TRANSPORT SMOKE — no model",
                                    "--worker-state", worker_state, "--sender-state", sender.state))
    port = free_port(socket.SOCK_STREAM)
    log = (suite.work / "managed.log").open("wb")
    controller = suite.spawn([*command, "serve", "--state", str(managed_state), "--port", str(port)],
                             env=environment, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    log.close()
    token = managed("token")

    def request(method, route, body=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{port}{route}", data=data, method=method,
                                     headers={"Authorization": "Bearer " + token,
                                              "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as response:
            return json.load(response)

    def healthy():
        check(controller.poll() is None, "managed controller exited early")
        try:
            return request("GET", "/health").get("ok")
        except urllib.error.URLError:
            return False

    wait_for(healthy, timeout=15, message="managed loopback server")

    readiness = {}

    def ready():
        snapshot = request("GET", "/api/snapshot")
        connection_state = next(row for row in snapshot["connections"] if row["id"] == connection["id"])
        readiness.update(connection_state["readiness"])
        return connection_state if connection_state["readiness"]["ready"] else False

    try:
        wait_for(ready, timeout=20, message="actual host and scripted adapter readiness")
    except AssertionError:
        upstream_status = worker.cli("--json", "status")
        upstream_connection = worker.ok("adapter", "connection", adapter.adapter_id)
        status = upstream_status.json or {}
        summary = {"exit": upstream_status.code, "host_id": status.get("host_id"),
                   "agents": status.get("agents"), "attention": status.get("attention"),
                   "service": {key: value for key, value in status.get("service", {}).items() if key != "unit"}}
        raise AssertionError(f"actual readiness failed: {readiness}; status={summary}; "
                             f"connection={upstream_connection}") from None
    instructions = "SCRIPTED TRANSPORT SMOKE ONLY. Produce the predetermined receipt; no model executes this."
    workflow = request("POST", "/api/workflows", {
        "name": "SCRIPTED real transport smoke — no model", "connectionId": connection["id"],
        "instructions": instructions, "intervalMinutes": 60, "maxRunsPerDay": 1,
        "acceptanceMinutes": 2, "enabled": True})
    handoff = adapter.next_task(timeout=30)
    check(handoff["task"]["input"] == instructions, "transport changed exact workflow instructions")
    task_id = handoff["task"]["task_id"]
    check(handoff["status"]["sender_host_id"] == sender.id, "task arrived from unexpected sender")
    code, accepted = adapter.post(f"/adapter/v1/tasks/{task_id}/accept")
    check(code == 200 and accepted["state"] == "running", f"scripted accept failed: {code}")

    def managed_run(state):
        rows = request("GET", "/api/snapshot")["runs"]
        matches = [row for row in rows if row["workflowId"] == workflow["id"] and row["state"] == state]
        return matches[0] if matches else False

    running = wait_for(lambda: managed_run("running"), timeout=20, message="managed running result")
    check(running["taskId"] == task_id, "managed task ID differs from actual adapter handoff")
    output = "SCRIPTED PEERSPAN TRANSPORT RECEIPT: real two-host delivery succeeded; no model was called."
    code, completed = adapter.post(f"/adapter/v1/tasks/{task_id}/complete",
                                   {"status": "succeeded", "output": output})
    check(code == 200 and completed["state"] == "succeeded", f"scripted completion failed: {code}")
    result = wait_for(lambda: managed_run("succeeded"), timeout=20, message="actual remote completion retained")
    check(result["taskId"] == task_id, "completion changed task ID")
    upstream = sender.ok("task", "inspect", "--peer", worker.id, task_id)
    check(upstream["status"]["state"] == "succeeded", "actual upstream record is not succeeded")
    events = wait_for(lambda: sender.ok("task", "events", "--peer", worker.id, task_id),
                      timeout=10, message="actual task events")
    check(any(event.get("output") == output for event in events), "real completion event lost output")
    try:
        wait_for(lambda: managed_run("succeeded")["output"] == output,
                 timeout=10, message="actual task-event output retained by managed")
    except AssertionError:
        raise AssertionError(f"managed output={managed_run('succeeded')['output']!r}; "
                             f"actual status={upstream['status']}; actual events={events}") from None
    print("  Real two-host membership, signed access, verified scripted adapter, task and output checked; no model.",
          flush=True)
    adapter.stop()


suite.finish()
