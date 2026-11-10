"""Shared fixtures and helpers of the runtime slim suites (runtime.py, runtime_runs.py, runtime_peerfs.py).

Written from docs/runtime-task-contract.md only (cited as "runtime <section>"), with the task, artifact and
coordinator-free contracts it builds on. A suite calls `bind(suite)` once, right after creating its `Suite`, and
then uses these helpers and the shared `state` dictionary its cases fill.
"""
import base64
import hashlib
import io
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import time
import urllib.parse
from datetime import timedelta
from pathlib import Path

from harness import (Failure, Skip, UnixHTTPConnection, check, create_network, join_new_person, link_machine, peer,
                     rfc3339, ssh_key, wait_for)

HERE = Path(__file__).resolve().parent
FAKE = HERE / "fake_runtime.py"
REPO = HERE.parents[1]
FINAL = {"succeeded", "failed", "cancelled", "rejected", "expired"}
# runtime, The run result: exactly these keys in this order (`snapshot` from RUN-7).
RESULT_KEYS = ["exit_code", "signal", "timed_out", "duration_ms", "stdout_bytes", "stderr_bytes", "output_truncated",
               "results_dropped", "results_same", "snapshot", "error"]
# runtime, Policy body: each rule has exactly these keys in this order (`peerfs_workspaces` from RUN-6).
RULE_KEYS = ["host", "principals", "max_cpus", "max_memory_mib", "max_seconds", "max_output_bytes",
             "max_artifact_bytes", "peerfs_workspaces", "allow_disconnected"]
# runtime, The runtime's local API: GET /v1/runtime.
REPORT_KEYS = {"version", "image", "max_cpus", "max_memory_mib", "max_seconds", "max_concurrent_runs", "running",
               "peerfs"}
DEFAULTS = {"max_cpus": 2, "max_memory_mib": 2048, "max_seconds": 3600, "max_output_bytes": 1048576,
            "max_artifact_bytes": 104857600}

suite = None
state = {}


def bind(the_suite):
    """Use THE_SUITE for hosts, processes and the work directory."""
    global suite
    suite = the_suite


def need(*names):
    missing = [n for n in names if n not in state]
    check(not missing, f"an earlier case did not finish ({', '.join(missing)} missing)")
    return [state[n] for n in names]


# The fake runtime.

class FakeRuntime:
    """One fake runtime process on a fixed socket; `restart` replaces it with a fresh one that knows no runs."""

    def __init__(self, name):
        self.name = name
        self.socket = suite.work / f"{name}-rt.sock"
        self.log = suite.work / f"{name}-rt.jsonl"
        self.dir = suite.work / f"{name}-rt"
        self.dir.mkdir(mode=0o700, exist_ok=True)
        self.process = None
        self.options = {}

    def start(self, **options):
        self.options = options
        argv = [sys.executable, "-I", str(FAKE), "serve", "--socket", str(self.socket), "--log", str(self.log),
                "--dir", str(self.dir)]
        for key, value in options.items():
            for one in value if isinstance(value, (list, tuple)) else [value]:
                argv += ["--" + key.replace("_", "-"), str(one)]
        out = (suite.work / f"{self.name}-rt.out").open("ab")
        self.process = suite.spawn(argv, stdout=out, stderr=out)
        out.close()
        wait_for(self._ping, timeout=15, interval=0.1, message=f"fake runtime {self.name}")
        return self

    def _ping(self):
        try:
            return self.api("GET", "/v1/runtime")[0] == 200
        except OSError:
            return False

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=5)
        self.process = None
        self.socket.unlink(missing_ok=True)

    def restart(self, **options):
        self.stop()
        return self.start(**options)

    def api(self, method, path, body=None):
        conn = UnixHTTPConnection(str(self.socket), timeout=10)
        try:
            data = None if body is None else json.dumps(body).encode()
            conn.request(method, path, body=data, headers={"Content-Type": "application/json"} if data else {})
            response = conn.getresponse()
            data = response.read()
        finally:
            conn.close()
        return response.status, json.loads(data) if data.strip() else None

    def entries(self, event=None, run_id=None):
        if not self.log.exists():
            return []
        found = [json.loads(line) for line in self.log.read_text().splitlines() if line.strip()]
        return [e for e in found if (event is None or e.get("event") == event)
                and (run_id is None or e.get("run_id") == run_id)]



# Helpers.

def run_id(sender, task_id):
    """runtime, The runtime's local API: run_ + hex SHA-256 of `<sender host ID>/<task_id>`."""
    return "run_" + hashlib.sha256(f"{sender.id}/{task_id}".encode()).hexdigest()


def new_task_id():
    return "task_" + os.urandom(16).hex()


def raw(host, method, path, data=None, content_type="application/octet-stream", timeout=60):
    """An owner-API or adapter request with a raw body or answer."""
    conn = UnixHTTPConnection(str(host.state / "admin.sock"), timeout=timeout)
    try:
        conn.request(method, path, body=data, headers={"Content-Type": content_type} if data is not None else {})
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def upload(host, data, name="workspace.tar", media_type="application/x-tar"):
    """artifact contract, Submitter: POST /v1/artifacts with the raw file; returns the manifest entry."""
    query = urllib.parse.urlencode({"name": name, "media_type": media_type})
    status, body = raw(host, "POST", f"/v1/artifacts?{query}", data)
    check(status in (200, 201), f"{host.name}: upload {name}: {status} {body[:300]!r}")
    return json.loads(body)


def make_tar(files, refused=None):
    """An uncompressed pax tar of FILES {path: bytes}; REFUSED adds one (name, type) entry the contract refuses."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o644
            tar.addfile(info, io.BytesIO(data))
        if refused:
            name, kind = refused
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == tarfile.REGTYPE:
                info.size = 1
                tar.addfile(info, io.BytesIO(b"x"))
            else:
                tar.addfile(info)
    return buffer.getvalue()


def policy_statement(host, person_public, net=None):
    """The person's current policy statement on HOST: (statement_id, envelope, payload, body)."""
    net = net or state["net"]
    status, current = host.api("GET", f"/v2/networks/{net}/policy/{urllib.parse.quote(person_public, safe='')}")
    check(status == 200, f"{host.name}: current policy: {status} {current}")
    envelope = json.loads(base64.b64decode(current["statement_base64"]))
    payload = json.loads(base64.b64decode(envelope["payload_base64"]))
    body = json.loads(base64.b64decode(payload["body_base64"]))
    return current["statement_id"], envelope, payload, body


def policy_version(host, person_public, net=None):
    status, body = host.api("GET", f"/v2/networks/{net or state['net']}/access-versions")
    check(status == 200, f"{host.name}: access-versions: {status} {body}")
    return max((p["version"] for p in body["policies"] if p["person_public_key"] == person_public), default=0)


def learn(host, person_public, version, net=None, timeout=30):
    """Sync HOST until it holds PERSON's policy at VERSION or later (spec 10)."""
    net = net or state["net"]

    def done():
        if policy_version(host, person_public, net) >= version:
            return True
        host.api("POST", f"/v2/networks/{net}/sync", {}, timeout=40)
        return policy_version(host, person_public, net) >= version
    wait_for(done, timeout=timeout, interval=0.5, message=f"{host.name} to learn policy version {version}")


def cite(receiver, person_public=None, person_id=None):
    """A policy citation `{person_id, version}` of the receiver owner's policy, at the version the receiver holds."""
    return {"person_id": person_id or state["alice_pid"],
            "version": policy_version(receiver, person_public or state["alice_public"])}


def enable(*extra, host=None, socket=None):
    """`runtime enable` on alice's host; returns the new policy version once bob's host knows it."""
    host = host or state["a"]
    rt = state["rt"]
    result = host.cli("--json", "runtime", "enable", "--socket", str(socket or rt.socket), "--person-key", state["alice_key"],
                      *extra, timeout=90)
    check(result.ok, f"runtime enable {' '.join(extra)}: exit {result.code} {result.stderr.strip()[-400:]}")
    version = policy_version(host, state["alice_public"])
    if host is state["a"]:
        learn(state["b"], state["alice_public"], version)
    return result, version


def show(host):
    result = host.cli("runtime", "show", "--json")
    check(result.ok and isinstance(result.json, dict), f"{host.name}: runtime show: exit {result.code} "
                                                       f"{result.stderr.strip()[-300:]}")
    return result.json


def run_body(argv, **run):
    body = {"argv": argv}
    body.update({k: v for k, v in run.items() if v is not None})
    return body


def submit(argv, sender=None, receiver=None, artifacts=None, deadline=None, task_id=None, input=None, **run):
    """POST /v1/tasks with `executor` and `run` (runtime, CLI and local API); returns the task ID."""
    sender, receiver = sender or state["b"], receiver or state["a"]
    task_id = task_id or new_task_id()
    body = {"peer_host_id": receiver.id, "executor": "runtime", "task_id": task_id, "run": run_body(argv, **run),
            "input": input or " ".join(argv)}
    if artifacts is not None:
        body["artifacts"] = artifacts
    if deadline is not None:
        body["deadline"] = deadline
    status, record = sender.api("POST", "/v1/tasks", body)
    check(status in (200, 201), f"{sender.name}: POST /v1/tasks (runtime): {status} {record}")
    check(record["request"].get("executor") == "runtime" and record["request"].get("run", {}).get("argv") == argv,
          f"the local record does not show executor and run: {record['request']}")
    return task_id


def peer_submit(body, sender=None, receiver=None):
    """A raw POST /peer/v1/tasks from SENDER's host key (peerspan-peer-probe)."""
    return peer(sender or state["b"], receiver or state["a"], "POST", "/peer/v1/tasks", body)


def raw_task(argv=("echo", "raw"), receiver=None, **fields):
    receiver = receiver or state["a"]
    body = {"task_id": new_task_id(), "executor": "runtime", "run": {"argv": list(argv)},
            "deadline": rfc3339(receiver.now() + timedelta(minutes=30)), "input": "raw runtime task",
            "policy": cite(receiver)}
    body.update(fields)
    return body


def peer_events(task_id, after=0, wait=0, sender=None, receiver=None):
    """The receiver's events through GET /peer/v1/tasks/{id}/events (runtime, Peer events)."""
    sender, receiver = sender or state["b"], receiver or state["a"]
    return peer(sender, receiver, "GET", f"/peer/v1/tasks/{task_id}/events?after={after}&limit=1000&wait={wait}")


def receiver_events(task_id, until=None, timeout=30, sender=None, receiver=None):
    """Read the receiver's events with `wait` until UNTIL(events) holds (default: a final event)."""
    until = until or (lambda evs: evs and evs[-1]["kind"] in FINAL)
    events = []
    deadline = time.monotonic() + timeout
    while True:
        status, got = peer_events(task_id, len(events), 5, sender, receiver)
        if status == 404 and not events:
            pass  # not yet received: the sender submits asynchronously
        else:
            check(status == 200, f"peer events of {task_id}: {status} {got}")
            for event in got:
                check(event["sequence"] == len(events) + 1, f"events out of sequence: {[e['sequence'] for e in got]}")
                events.append(event)
        if until(events):
            return events
        if time.monotonic() > deadline:
            raise Failure(f"{task_id}: timed out; events so far {[(e['kind'], e['state']) for e in events]}")
        if status == 404:
            time.sleep(0.3)


def final(task_id, **kw):
    return receiver_events(task_id, **kw)


def has_kind(kind):
    return lambda evs: any(e["kind"] == kind for e in evs)


def result_of(event, peerfs=False):
    """The run result of EVENT; `snapshot` is null for every run not on a peerfs workspace (RUN-7)."""
    check(event.get("output") is not None, f"the {event['kind']} event has no run result")
    text = event["output"]
    check(isinstance(text, str), f"the run result is not text: {text!r}")
    value = json.loads(text)
    check(list(value) == RESULT_KEYS, f"run result keys {list(value)}, want {RESULT_KEYS}")
    if not peerfs:
        check(value["snapshot"] is None, f"snapshot {value['snapshot']!r} on a run without a peerfs workspace")
    return value


def stream(events, name):
    return b"".join(base64.b64decode(e["chunk"]["data"]) for e in events
                    if e["kind"] == "output" and e["chunk"]["stream"] == name)


def names(event):
    return [a["name"] for a in event.get("artifacts") or []]


def occupy(seconds):
    """Hold the fake runtime's single slot with a run of `sleep SECONDS`; returns its task ID once running."""
    task_id = submit(["sleep", str(seconds)])
    receiver_events(task_id, until=has_kind("accepted"), timeout=20)
    return task_id


def cancel(task_id, sender=None, receiver=None):
    sender, receiver = sender or state["b"], receiver or state["a"]
    status, body = sender.api("POST", f"/v1/tasks/{receiver.id}/{task_id}/cancel", {})
    check(status == 200, f"cancel {task_id}: {status} {body}")
    return body


def refused(status, body, http, code=None, field=None):
    ok = status == http and isinstance(body, dict)
    if code is not None:
        ok = ok and body.get("code") == code
    if field is not None:
        ok = ok and field in (body.get("error") or "")
    check(ok, f"answer {status} {body}, want {http} {code or ''} naming {field or '-'}")


def local_artifact(task_id, sha256, sender=None, receiver=None, timeout=20):
    """A fetched result through GET /v1/tasks/{peer}/{id}/artifacts/{sha256} (409 until fetched)."""
    sender, receiver = sender or state["b"], receiver or state["a"]
    found = {}

    def stored_final():
        # Until the submitter stores the final event it has no row for the result, and 404 is correct
        # (artifact contract): wait for its record first.
        status, record = sender.api("GET", f"/v1/tasks/{receiver.id}/{task_id}")
        check(status == 200, f"{sender.name}: record of {task_id}: {status} {record}")
        status_record = record.get("status") or {}
        return status_record.get("state") in FINAL and record["events_after"] >= status_record.get("last_event", 0)
    wait_for(stored_final, timeout=timeout, interval=0.3, message=f"{sender.name} to store the final event")

    def fetched():
        status, data = raw(sender, "GET", f"/v1/tasks/{receiver.id}/{task_id}/artifacts/{sha256}")
        if status == 200:
            found["data"] = data
            return True
        check(status == 409, f"result {sha256[:12]}: {status} {data[:200]!r}")
        return False
    wait_for(fetched, timeout=timeout, interval=0.5, message=f"the result {sha256[:12]} on {sender.name}")
    return found["data"]


def sign_policy(mutate, host=None, net=None, person_public=None, key=None):
    """Prepare the successor of a person's current policy (alice's by default) with MUTATE(body) applied, through
    POST .../actions (appendix 16.4), signing any requests with the person's original key. Returns (status,
    response)."""
    host, net = host or state["a"], net or state["net"]
    person_public, key = person_public or state["alice_public"], key or state["alice_key"]
    statement_id, _, payload, body = policy_statement(host, person_public, net)
    now = host.now().replace(microsecond=0)
    until = now + timedelta(hours=23)
    body.update(version=body["version"] + 1, issued_at=rfc3339(now), valid_until=rfc3339(until))
    # A content change is an edit: it names this host's next local edit number (spec 12.1, DEC-S16), which the
    # read-only plan route gives (appendix 16.6).
    status, plan = host.api("POST", f"/v2/networks/{net}/policy-edits/plan", {"provider_id": person_public})
    check(status == 200, f"policy-edits/plan: {status} {plan}")
    body["edits"] = sorted([e for e in body.get("edits", []) if e["host"] != host.id]
                           + [{"host": host.id, "seq": plan["seq"]}], key=lambda e: e["host"])
    body = mutate(body)
    # Signed by the original key (a policy signer, wire appendix 5), whose only parent is the person grant.
    payload.update(sequence=payload["sequence"] + 1, predecessors=[statement_id], resolves=[],
                   issuer={"kind": "person", "person_public_key": person_public},
                   parents=[p for p in payload["parents"] if p["role"] == "issuer_person"],
                   issued_at=rfc3339(now), not_before=rfc3339(now), not_after=rfc3339(until),
                   body_base64=base64.b64encode(json.dumps(body, separators=(",", ":")).encode()).decode())
    status, response = host.api("POST", f"/v2/networks/{net}/actions", {
        "kind": "policy", "provider_id": person_public, "signature_format": "sshsig",
        "payload_base64": base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode(),
        "approve": True})
    while status == 200 and response.get("signing_requests"):
        signatures = [{"slot_id": r["slot_id"], "role": r["role"],
                       "signature": sshsig(key, base64.b64decode(r["message_base64"]))}
                      for r in response["signing_requests"]]
        status, response = host.api("POST", f"/v2/networks/{net}/actions/{response['action_id']}/signed",
                                    {"intent_id": response["signing_requests"][0]["intent_id"],
                                     "signatures": signatures})
    return status, response


def sshsig(key, message):
    signed = subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", str(key), "-n", "peerspan-person-v1"],
                            input=message, capture_output=True, check=True).stdout.decode()
    return "".join(line for line in signed.splitlines() if not line.startswith("-----"))


def with_runtime_rules(body, rules):
    """BODY with `runtime_rules` placed right after `capability_rules`."""
    out = {}
    for key, value in body.items():
        if key == "runtime_rules":
            continue
        out[key] = value
        if key == "capability_rules":
            out["runtime_rules"] = rules
    return out



def adapter_upload(adapter, data, name="workspace.tar", media_type="application/x-tar"):
    query = urllib.parse.urlencode({"name": name, "media_type": media_type})
    conn = UnixHTTPConnection(str(adapter.host.state / "adapter.sock"), timeout=30)
    try:
        conn.request("POST", f"/adapter/v1/artifacts?{query}", body=data, headers={
            "Authorization": f"Bearer {adapter.token}", "X-Peerspan-Instance": adapter.instance,
            "Content-Type": "application/octet-stream"})
        response = conn.getresponse()
        body = response.read()
    finally:
        conn.close()
    check(response.status in (200, 201), f"adapter upload: {response.status} {body[:200]!r}")
    return json.loads(body)


class Channel:
    """The real MCP adapter over stdio, as conformance/agent_adapter.py starts it, with no model."""

    def __init__(self, host, setup, directory):
        node = shutil.which("node")
        # PEERSPAN_SLIM_INTEGRATIONS points at another checkout's integrations/ (a branch under test); default: this one.
        integrations = Path(os.environ.get("PEERSPAN_SLIM_INTEGRATIONS") or REPO / "integrations")
        script = integrations / "claude-channel" / "channel.mjs"
        sdk = script.parent / "node_modules/@modelcontextprotocol/sdk/dist/esm/server/stdio.js"
        if node is None or not sdk.exists():
            raise Skip("node and the claude-channel MCP SDK are needed (npm ci in integrations/claude-channel)")
        directory.mkdir(parents=True, exist_ok=True)
        self.instance = "instance_" + os.urandom(32).hex()
        credential = directory / "credential.json"
        credential.write_text(json.dumps({**setup["credential"], "test_instance": self.instance}))
        credential.chmod(0o600)
        launcher = directory / "test-channel.mjs"
        launcher.write_text(
            "import { readCredential, configuredChannel } from " + json.dumps(script.as_uri()) + ";\n"
            "import { StdioServerTransport } from " + json.dumps(sdk.as_uri()) + ";\n"
            "const [socket,path] = process.argv.slice(2);\n"
            "const secret = await readCredential(path);\n"
            "const channel = await configuredChannel(socket,path,{instanceId:secret.test_instance,pollMs:50});\n"
            "process.stdin.once('end',()=>{void channel.stop()});\n"
            "await channel.server.connect(new StdioServerTransport());\n")
        self.logs = (directory / "channel.log").open("wb")
        self.process = subprocess.Popen([node, str(launcher), str(host.state / "adapter.sock"), str(credential)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.logs, text=True)
        suite.processes.append(self.process)
        self.events = queue.Queue()
        self.pending = []
        self.count = 0
        threading.Thread(target=self._read, daemon=True).start()
        self.call("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                 "clientInfo": {"name": "peerspan-runtime-conformance", "version": "1"}})
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        hello = self.notification()
        check(hello["meta"].get("kind") == "hello", f"first channel event {hello}")
        self.call("tools/call", {"name": "peerspan_ready", "arguments": {"nonce": hello["meta"]["nonce"]}})

    def _read(self):
        for line in self.process.stdout:
            self.events.put(json.loads(line))
        self.events.put(None)

    def send(self, value):
        self.process.stdin.write(json.dumps(value) + "\n")
        self.process.stdin.flush()

    def call(self, method, params, seconds=20, whole=False):
        """The result of one MCP request; with WHOLE, the whole JSON-RPC answer, an error included."""
        self.count += 1
        rid = self.count
        self.send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            event = self.events.get(timeout=max(0.01, deadline - time.monotonic()))
            check(event is not None, "the MCP adapter exited")
            if event.get("id") == rid:
                if whole:
                    return event
                check("error" not in event, f"MCP {method}: {event}")
                return event["result"]
            self.pending.append(event)
        raise Failure(f"MCP {method} timed out")

    def notification(self, seconds=30):
        for i, event in enumerate(self.pending):
            if event.get("method") == "notifications/claude/channel":
                return self.pending.pop(i)["params"]
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                event = self.events.get(timeout=max(0.01, deadline - time.monotonic()))
            except queue.Empty:
                break
            check(event is not None, "the MCP adapter exited")
            if event.get("method") == "notifications/claude/channel":
                return event["params"]
            self.pending.append(event)
        raise Failure("no channel notification")

    def run_task(self, arguments):
        """MCP `run_task` with ARGUMENTS; returns the task ID it answers with."""
        answer = self.call("tools/call", {"name": "run_task", "arguments": arguments})
        check(not answer.get("isError"), f"run_task: {answer}")
        text = answer["content"][0]["text"]
        try:
            task_id = json.loads(text).get("task_id")
        except (ValueError, AttributeError):
            task_id = None
        if not task_id:
            found = re.search(r"task_[0-9a-f]{32}", text)
            task_id = found.group(0) if found else None
        check(task_id, f"run_task returned no task ID: {text[:300]}")
        return task_id

    def task_updates(self, task_id):
        """The task-update notifications of TASK_ID up to the final one: ([meta], [content])."""
        updates, contents = [], []
        while True:
            note = self.notification(seconds=40)
            meta = note.get("meta", {})
            if meta.get("kind") != "task_update" or task_id not in meta.values():
                continue
            updates.append(meta)
            contents.append(note.get("content"))
            if meta.get("state") in FINAL:
                return updates, contents

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.logs.close()


def mcp_channel(name, route):
    """bob's agent NAME with a claude-channel adapter session, a runtime.run route ROUTE to alice's host, and the
    real MCP adapter connected to that session."""
    a, b = state["a"], state["b"]
    status, agent = b.api("POST", "/v1/agents", {"name": name, "owner": "bob"})
    check(status in (200, 201), f"register {name}: {status} {agent}")
    status, setup = b.api("POST", "/v1/adapters/setup", {
        "agent_id": agent["id"], "session_id": "session_" + os.urandom(16).hex(), "integration": "claude-channel",
        "expires_at": rfc3339(b.now() + timedelta(hours=2))})
    check(status == 201, f"adapter setup for {name}: {status} {setup}")
    added = b.cli("adapter", "route", "add", "--adapter", setup["credential"]["adapter"]["id"], "--name", route,
                  "--peer", a.id, "--action", "runtime.run", "--expires-in", "1h")
    check(added.ok, f"runtime.run route for {name}: {added.stderr.strip()[-300:]}")
    return Channel(b, setup, suite.work / f"mcp-{name}")


# Setup shared by the suites.

def run_side_by_side(*calls):
    """Run independent (function, args, kwargs) calls in threads; re-raise the first error."""
    errors = []

    def guarded(function, args, kw):
        try:
            function(*args, **kw)
        except Exception as error:  # noqa: BLE001 - re-raised below
            errors.append(error)
    threads = [threading.Thread(target=guarded, args=call) for call in calls]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if errors:
        raise errors[0]


def setup_network(second_machine=False, **runtime_options):
    """alice creates a coordinator-free network, bob joins as another person and, with SECOND_MACHINE, alice links
    alice2; alice's host gets a fake runtime started with RUNTIME_OPTIONS (decentralized-spec 6, 8)."""
    a, b = suite.host("alice"), suite.host("bob")
    state.update(a=a, b=b)
    hosts = [a, b]
    if second_machine:
        state["a2"] = suite.host("alice2")
        hosts.append(state["a2"])
    net = create_network(a, "runtime", "alice")
    state["net"] = net["id"]
    state["alice_public"] = a.api("GET", f"/v2/networks/{net['id']}")[1]["person_public_key"]
    state["alice_key"] = a.home / ".config/peerspan/person_ed25519"
    state["bob_key"] = ssh_key(b.root, "bob")
    calls = [(join_new_person, (a, b, "bob", state["bob_key"], net["id"]), {})]
    if second_machine:
        calls.append((link_machine, (a, state["a2"], net["id"], state["alice_public"]), {"key": state["alice_key"]}))
    rt = FakeRuntime("alice")
    calls.append((rt.start, (), runtime_options))
    run_side_by_side(*calls)  # independent requests: side by side to keep the suites short
    state["rt"] = rt
    state["bob_public"] = b.api("GET", f"/v2/networks/{net['id']}")[1]["person_public_key"]
    state["alice_pid"] = a.ok("person", "show", "--person-key", state["alice_key"])["person_id"]
    state["bob_pid"] = b.ok("person", "show", "--person-key", state["bob_key"])["person_id"]
    state["alice_principal"], state["bob_principal"] = f"person:{state['alice_pid']}", f"person:{state['bob_pid']}"
    # bob's policy (no runtime rules) lets alice message his agents: a policy without runtime rules, signed today.
    b.ok("allow", "alice", "--person-key", state["bob_key"])
    for host in hosts:
        learn(host, state["alice_public"], policy_version(a, state["alice_public"]))
    state["policy_before"] = policy_statement(a, state["alice_public"])[3]


def enable_for_both(*extra):
    """runtime enable with alice and bob as principals, then one authorized run end to end."""
    _, version = enable("--for", state["alice_principal"], "--for", state["bob_principal"], *extra)
    state["version_rule"] = version
    events = final(submit(["echo", "ready"]))
    check(events[-1]["kind"] == "succeeded", f"a first authorized run: {[e['kind'] for e in events]}")
    state["ready"] = True
    return version
