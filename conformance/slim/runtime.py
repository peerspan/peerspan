#!/usr/bin/env python3
"""Slim suite, runtime: runtime tasks run by a host's runtime instead of an agent (RUN-1 to RUN-5).

alice creates a coordinator-free network and links a second machine (alice2); bob joins as another person. alice's
host serves runtime tasks through conformance/slim/fake_runtime.py (RUN-4), which reads `argv` as the step language of
the contract's Verification section and logs every request, so the suite sees what the runtime was asked to do.
bob submits through the owner API, the CLI, the peer probe and the adapter socket. A second, separate network
(rhea and sam, with a runtime of its own) runs in the background on its own debug test clock for the two cases that
need days to pass: runtime rules kept across an automatic policy renewal, and a sender whose grants lapsed.

Not suite cases (Rust tests that drive the binaries, per the contract's Verification section): a `changes.tar` over
the 104,857,600-byte per-artifact limit, and the 104,857,600-byte cut of `stdout.log` and `stderr.log`, which need
files too large for a two-minute suite; the 65,536-byte cut of `meta.output`; the 250 ms output flush timing.

Written from docs/runtime-task-contract.md only (cited as "runtime <section>"), with the task, artifact and
coordinator-free contracts it builds on. No VM, no KVM, no model calls.
"""
import base64
import hashlib
import io
import json
import os
import queue
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import threading
import time
import traceback
import urllib.parse
from datetime import timedelta
from pathlib import Path

from harness import (Clock, Failure, Skip, Suite, UnixHTTPConnection, check, create_network, join_new_person,
                     link_machine, members, peer, rfc3339, ssh_key, wait_for)

HERE = Path(__file__).resolve().parent
FAKE = HERE / "fake_runtime.py"
REPO = HERE.parents[1]
FINAL = {"succeeded", "failed", "cancelled", "rejected", "expired"}
RESULT_KEYS = ["exit_code", "signal", "timed_out", "duration_ms", "stdout_bytes", "stderr_bytes", "output_truncated",
               "results_dropped", "results_same", "error"]
RULE_KEYS = ["host", "principals", "max_cpus", "max_memory_mib", "max_seconds", "max_output_bytes",
             "max_artifact_bytes", "allow_disconnected"]
DEFAULTS = {"max_cpus": 2, "max_memory_mib": 2048, "max_seconds": 3600, "max_output_bytes": 1048576,
            "max_artifact_bytes": 104857600}
DAY, HOUR = 86400, 3600
WINDOW = 75  # one 60-second renewal pass plus sync jitter (spec 7.1, 10), as in the renewal suite

suite = Suite("runtime", __doc__)
state = {}
background = {"results": {}, "errors": {}}


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
            argv += ["--" + key.replace("_", "-"), str(value)]
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

    def api(self, method, path):
        conn = UnixHTTPConnection(str(self.socket), timeout=10)
        try:
            conn.request(method, path)
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


def policy_statement(host, person_public):
    """The person's current policy statement on HOST: (statement_id, envelope, payload, body)."""
    status, current = host.api("GET", f"/v2/networks/{state['net']}/policy/{urllib.parse.quote(person_public, safe='')}")
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
    result = host.cli("runtime", "enable", "--socket", str(socket or rt.socket), *extra, timeout=90)
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


def result_of(event):
    check(event.get("output") is not None, f"the {event['kind']} event has no run result")
    text = event["output"]
    check(isinstance(text, str), f"the run result is not text: {text!r}")
    value = json.loads(text)
    check(list(value) == RESULT_KEYS, f"run result keys {list(value)}, want {RESULT_KEYS}")
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

    def fetched():
        status, data = raw(sender, "GET", f"/v1/tasks/{receiver.id}/{task_id}/artifacts/{sha256}")
        if status == 200:
            found["data"] = data
            return True
        check(status == 409, f"result {sha256[:12]}: {status} {data[:200]!r}")
        return False
    wait_for(fetched, timeout=timeout, interval=0.5, message=f"the result {sha256[:12]} on {sender.name}")
    return found["data"]


# The background network on its own clock: renewal and a lapsed sender (runtime Policy body; Checks step 2).

def lapse_world():
    clock = Clock(suite.work / "clock-lapse")
    r, s = suite.host("rhea", clock=clock), suite.host("sam", clock=clock)
    rt = FakeRuntime("rhea").start()
    net = create_network(r, "runtime-lapse", "rhea")["id"]
    key = ssh_key(s.root, "sam")
    join_new_person(r, s, "sam", key, net)
    rhea_public = r.api("GET", f"/v2/networks/{net}")[1]["person_public_key"]
    rhea_pid = r.ok("person", "show", "--person-key", r.home / ".config/peerspan/person_ed25519")["person_id"]
    sam_pid = s.ok("person", "show", "--person-key", key)["person_id"]
    s.stop()  # sam's host cannot consent to renewing its own host grant from here on

    def sign(*extra):
        result = r.cli("runtime", "enable", "--socket", str(rt.socket), "--for", f"person:{sam_pid}", *extra,
                       timeout=90)
        check(result.ok, f"rhea: runtime enable: exit {result.code} {result.stderr.strip()[-300:]}")
        return policy_version(r, rhea_public, net)

    def body():
        status, current = r.api("GET", f"/v2/networks/{net}/policy/{urllib.parse.quote(rhea_public, safe='')}")
        check(status == 200, f"rhea's policy: {status}")
        payload = json.loads(base64.b64decode(json.loads(base64.b64decode(current["statement_base64"]))["payload_base64"]))
        return json.loads(base64.b64decode(payload["body_base64"]))

    def renewal():
        clock.set(4 * DAY + 8 * HOUR + 50 * 60)
        version = sign()
        rules = body()["runtime_rules"]
        start = members(r, net)[r.public_key]
        clock.set(5 * DAY + 1 * HOUR)  # 7 h 50 min left on the policy; every grant of rhea's due
        wait_for(lambda: policy_version(r, rhea_public, net) > version
                 and all(members(r, net)[r.public_key][k] != start[k]
                         for k in ("host_lease_id", "device_lease_id", "binding_lease_id")),
                 timeout=WINDOW, interval=1, message="rhea's host to renew its policy and grants")
        check(body().get("runtime_rules") == rules, f"runtime_rules after renewal {body().get('runtime_rules')}, "
                                                    f"want {rules}")
    step("renewal_keeps_runtime_rules", renewal)

    def lapsed():
        clock.set(7 * DAY + 1 * HOUR)  # sam's host grant, unrenewed, has ended
        sign()
        sam = members(r, net).get(s.public_key)
        check(sam is None or sam["not_after"] <= rfc3339(r.now()),
              f"fixture: sam's host is still a current member on rhea's host: {sam}")
        s.start()

        def attempt():
            body = {"task_id": new_task_id(), "executor": "runtime", "run": {"argv": ["echo", "lapsed"]},
                    "deadline": rfc3339(r.now() + timedelta(minutes=30)), "input": "lapsed sender",
                    "policy": {"person_id": rhea_pid, "version": policy_version(r, rhea_public, net)}}
            return peer(s, r, "POST", "/peer/v1/tasks", body)
        status, answer = attempt()
        check(status == 403, f"a lapsed sender without allow_disconnected: {status} {answer}")
        sign("--allow-disconnected")
        status, answer = attempt()
        check(status == 200 and answer["state"] == "queued", f"a lapsed sender with allow_disconnected: {status} "
                                                             f"{answer}")
    step("lapsed_sender_needs_allow_disconnected", lapsed)


def step(name, function):
    try:
        background["results"][name] = function()
    except Exception as error:  # noqa: BLE001 - reported by the case of the same name
        background["errors"][name] = error
        traceback.print_exc()


def run_lapse_world():
    try:
        lapse_world()
    except Exception as error:  # noqa: BLE001
        background["errors"]["setup"] = error
        traceback.print_exc()


def outcome(name):
    check(worker.ident is not None, "the background network was not started")
    worker.join(timeout=200)
    check(not worker.is_alive(), "the background network did not finish")
    if name in background["errors"]:
        raise background["errors"][name]
    if "setup" in background["errors"]:
        raise background["errors"]["setup"]
    check(name in background["results"], f"step {name} did not run")


BACKGROUND = ("renewal_keeps_runtime_rules", "lapsed_sender_needs_allow_disconnected")
worker = threading.Thread(target=run_lapse_world, daemon=True)
if (not suite.args.only or any(n in suite.args.only for n in BACKGROUND)) and \
        not all(n in suite.args.skip for n in BACKGROUND):
    worker.start()

# Setup.

@suite.case("setup", "decentralized-spec 6, 8; runtime Authorization")
def _():
    a, a2, b = suite.host("alice"), suite.host("alice2"), suite.host("bob")
    state.update(a=a, a2=a2, b=b)
    net = create_network(a, "runtime", "alice")
    state["net"] = net["id"]
    state["alice_public"] = a.api("GET", f"/v2/networks/{net['id']}")[1]["person_public_key"]
    state["alice_key"] = a.home / ".config/peerspan/person_ed25519"
    state["bob_key"] = ssh_key(b.root, "bob")
    # The join and the link are independent requests: run them side by side to keep the suite short.
    errors = []

    def guarded(function, *args, **kw):
        try:
            function(*args, **kw)
        except Exception as error:  # noqa: BLE001 - re-raised below
            errors.append(error)
    threads = [threading.Thread(target=guarded, args=(join_new_person, a, b, "bob", state["bob_key"], net["id"])),
               threading.Thread(target=guarded, args=(link_machine, a, a2, net["id"], state["alice_public"]),
                                kwargs={"key": state["alice_key"]})]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if errors:
        raise errors[0]
    state["bob_public"] = b.api("GET", f"/v2/networks/{net['id']}")[1]["person_public_key"]
    state["alice_pid"] = a.ok("person", "show", "--person-key", state["alice_key"])["person_id"]
    state["bob_pid"] = b.ok("person", "show", "--person-key", state["bob_key"])["person_id"]
    state["alice_principal"], state["bob_principal"] = f"person:{state['alice_pid']}", f"person:{state['bob_pid']}"
    state["rt"] = FakeRuntime("alice").start()
    # bob's policy (no runtime rules) lets alice message his agents: a policy without runtime rules, signed today.
    b.ok("allow", "alice", "--person-key", state["bob_key"])
    for host in (a, a2, b):
        learn(host, state["alice_public"], policy_version(a, state["alice_public"]))
    state["policy_before"] = policy_statement(a, state["alice_public"])[3]


# Authorization: the switch and the rule (runtime Authorization, Checks).

@suite.case("switch_off_refused", "runtime The local switch; Checks step 1 (403 runtime_disabled)")
def _():
    (a,) = need("a")
    shown = show(a)
    check(list(shown) == ["enabled", "socket", "runtime", "rule"] and shown["enabled"] is False
          and shown["rule"] is None, f"runtime show before enable: {shown}")
    status, body = peer_submit(raw_task())
    refused(status, body, 403, "runtime_disabled")


@suite.case("switch_on_without_rule", "runtime Checks step 2: no runtime rule (403); runtime show")
def _():
    a, rt = need("a", "rt")
    status, body = a.api("PUT", "/v1/runtime", {"socket": str(rt.socket)})
    check(status == 200, f"PUT /v1/runtime: {status} {body}")
    shown = show(a)
    check(shown["enabled"] is True and shown["socket"] == str(rt.socket) and shown["rule"] is None,
          f"runtime show with the switch only: {shown}")
    check(isinstance(shown["runtime"], dict) and shown["runtime"].get("version") == "fake-runtime-1"
          and shown["runtime"].get("max_concurrent_runs") == 1, f"the runtime's own report: {shown['runtime']}")
    status, body = peer_submit(raw_task())
    check(status == 403 and (body or {}).get("code") != "runtime_disabled", f"no runtime rule: {status} {body}")


@suite.case("task_submit_rule_does_not_authorize", "runtime Checks: task.submit never authorizes a runtime task")
def _():
    a, b = need("a", "b")
    out = a.ok("allow", "bob")
    check("task.submit" in out["actions"], f"allow bob: {out}")
    learn(b, state["alice_public"], out["policy"]["version"])
    status, body = peer_submit(raw_task())
    check(status == 403, f"a runtime task under a task.submit rule only: {status} {body}")


@suite.case("enable_default_principal", "runtime Runtime administration (runtime enable defaults; RUN-5); Checks 2")
def _():
    (a,) = need("a")
    result, version = enable()
    said = (result.stdout + result.stderr).lower()
    check(any(word in said for word in ("software", "upgrade", "older", "earlier")),
          f"runtime enable did not state the compatibility warning (RUN-5): {said[-300:]!r}")
    rule = show(a)["rule"]
    want = {"host": a.id, "principals": [state["alice_principal"]], **DEFAULTS, "allow_disconnected": False}
    check(rule == want, f"the default rule {rule}, want {want}")
    state["version_alice_only"] = version
    status, body = peer_submit(raw_task())
    check(status == 403, f"bob, not a principal of the rule: {status} {body}")


@suite.case("enable_for_both", "runtime Runtime administration (--for); Checks 1 to 3 pass")
def _():
    (a,) = need("a")
    _, version = enable("--for", state["alice_principal"], "--for", state["bob_principal"])
    state["version_rule"] = version
    rule = show(a)["rule"]
    check(rule["principals"] == [state["alice_principal"], state["bob_principal"]], f"rule principals {rule}")
    body = raw_task(("echo", "authorized"))
    status, record = peer_submit(body)
    check(status == 200 and record["state"] == "queued", f"an authorized runtime task: {status} {record}")
    events = final(body["task_id"])
    check(events[-1]["kind"] == "succeeded", f"the authorized run: {[e['kind'] for e in events]}")
    # Idempotency covers the whole request, run included (runtime Requests).
    status, again = peer_submit(body)
    check(status == 200 and again["task_id"] == body["task_id"], f"an identical repeat: {status} {again}")
    changed = dict(body, run={"argv": ["echo", "other"]})
    status, again = peer_submit(changed)
    check(status == 409, f"the same task_id with another run: {status} {again}")
    state["ready"] = True


@suite.case("rule_naming_another_host", "runtime Runtime rules: a host honours only rules naming itself")
def _():
    a2, b, rt, version = need("a2", "b", "rt", "version_rule")
    learn(a2, state["alice_public"], version)
    status, body = a2.api("PUT", "/v1/runtime", {"socket": str(rt.socket)})
    check(status == 200, f"alice2: PUT /v1/runtime: {status} {body}")
    try:
        # bob is a principal of alice's only runtime rule, but that rule names alice's host, not alice2.
        status, body = peer_submit(raw_task(receiver=a2), receiver=a2)
        check(status == 403 and (body or {}).get("code") != "runtime_disabled",
              f"a request to alice2, which no runtime rule names: {status} {body}")
    finally:
        a2.api("DELETE", "/v1/runtime")


# The policy body (runtime Runtime rules, Policy body).

@suite.case("policy_body_runtime_rules", "runtime Policy body: key order; admitted by the owner's other host and by "
                                         "another person's host")
def _():
    a, a2, b = need("a", "a2", "b")
    need("version_rule")
    _, _, payload, body = policy_statement(a, state["alice_public"])
    keys = list(body)
    check("runtime_rules" in keys, f"no runtime_rules in the body: {keys}")
    check(keys.index("runtime_rules") == keys.index("capability_rules") + 1,
          f"runtime_rules is not right after capability_rules: {keys}")
    rules = body["runtime_rules"]
    check(len(rules) == 1 and list(rules[0]) == RULE_KEYS, f"rule keys {[list(r) for r in rules]}, want {RULE_KEYS}")
    check(rules[0]["host"] == a.id and rules[0]["principals"] == [state["alice_principal"], state["bob_principal"]]
          and rules[0]["max_cpus"] == 2, f"the signed rule {rules[0]}")
    check(body["version"] == payload["sequence"] == state["version_rule"], "body version and statement sequence")
    for host in (a2, b):
        learn(host, state["alice_public"], state["version_rule"])
        _, _, _, seen = policy_statement(host, state["alice_public"])
        check(seen.get("runtime_rules") == rules, f"{host.name} holds {seen.get('runtime_rules')}")


@suite.case("policy_without_runtime_rules", "runtime Policy body: omitted when empty, same body as before")
def _():
    b, a = need("b", "a")
    before = state.get("policy_before")
    check(before is not None and "runtime_rules" not in before, f"alice's body before enable: {list(before or {})}")
    _, _, _, bobs = policy_statement(a, state["bob_public"])
    check("runtime_rules" not in bobs, f"bob's policy, with no runtime rules, has keys {list(bobs)}")


def sign_policy(mutate):
    """Prepare the successor of alice's current policy with MUTATE(body) applied through POST .../actions (appendix
    16.4), signing any requests with her original key. Returns (status, response)."""
    a = state["a"]
    statement_id, _, payload, body = policy_statement(a, state["alice_public"])
    now = a.now().replace(microsecond=0)
    until = now + timedelta(hours=23)
    body.update(version=body["version"] + 1, issued_at=rfc3339(now), valid_until=rfc3339(until))
    body = mutate(body)
    # Signed by alice's original key (a policy signer, wire appendix 5), whose only parent is her person grant.
    payload.update(sequence=payload["sequence"] + 1, predecessors=[statement_id], resolves=[],
                   issuer={"kind": "person", "person_public_key": state["alice_public"]},
                   parents=[p for p in payload["parents"] if p["role"] == "issuer_person"],
                   issued_at=rfc3339(now), not_before=rfc3339(now), not_after=rfc3339(until),
                   body_base64=base64.b64encode(json.dumps(body, separators=(",", ":")).encode()).decode())
    status, response = a.api("POST", f"/v2/networks/{state['net']}/actions", {
        "kind": "policy", "provider_id": state["alice_public"], "signature_format": "sshsig",
        "payload_base64": base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode(),
        "approve": True})
    while status == 200 and response.get("signing_requests"):
        signatures = [{"slot_id": r["slot_id"], "role": r["role"],
                       "signature": sshsig(state["alice_key"], base64.b64decode(r["message_base64"]))}
                      for r in response["signing_requests"]]
        status, response = a.api("POST", f"/v2/networks/{state['net']}/actions/{response['action_id']}/signed",
                                 {"intent_id": response["signing_requests"][0]["intent_id"], "signatures": signatures})
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


@suite.case("policy_body_refusals", "runtime Policy body (Reading): empty, unknown key, duplicate host, out of range; "
                                    "runtime.run refused in rules")
def _():
    a, a2 = need("a", "a2")
    need("version_rule")
    good = policy_statement(a, state["alice_public"])[3]["runtime_rules"][0]
    before = policy_version(a, state["alice_public"])
    cases = {
        "empty runtime_rules": lambda body: with_runtime_rules(body, []),
        "an unknown key": lambda body: with_runtime_rules(body, [{**good, "max_gpus": 1}]),
        "a missing key": lambda body: with_runtime_rules(body, [{k: v for k, v in good.items() if k != "max_seconds"}]),
        "two rules for one host": lambda body: with_runtime_rules(body, [good, {**good, "max_cpus": 1}]),
        "max_cpus 65": lambda body: with_runtime_rules(body, [{**good, "max_cpus": 65}]),
        "max_output_bytes over 64 MiB": lambda body: with_runtime_rules(body, [{**good, "max_output_bytes": 67108865}]),
        "runtime.run in an agent rule": lambda body: dict(body, rules=[
            dict(rule, actions=list(rule["actions"]) + ["runtime.run"]) for rule in body["rules"]]),
    }
    check(policy_statement(a, state["alice_public"])[3]["rules"], "alice has no agent rule to amend")
    accepted = []
    for label, mutate in cases.items():
        status, response = sign_policy(mutate)
        if status == 200 and response.get("committed"):
            accepted.append(f"{label} ({status})")
    check(not accepted, f"policies admitted: {accepted}")
    check(policy_version(a, state["alice_public"]) == before, "a refused policy changed the current version")
    # A valid successor with a second rule, for alice2, is admitted (control for the refusals above).
    second = {**good, "host": a2.id, "principals": [state["alice_principal"]]}
    status, response = sign_policy(lambda body: with_runtime_rules(body, body["runtime_rules"] + [second]))
    check(status == 200 and response.get("committed"), f"a valid policy with two runtime rules: {status} {response}")
    learn(state["b"], state["alice_public"], before + 1)


@suite.case("routes_refuse_runtime_run_for_agents", "runtime Agents: a runtime.run route names a host, not an agent")
def _():
    a, b = need("a", "b")
    bert = state.setdefault("bert", b.agent("bert"))
    ada = state.setdefault("ada", a.agent("ada"))
    control = a.cli("adapter", "route", "add", "--adapter", ada.adapter_id, "--name", "to-bert", "--peer", b.id,
                    "--agent", bert.id, "--action", "task.submit", "--expires-in", "1h")
    check(control.ok, f"control: a task.submit route to an agent: exit {control.code} {control.stderr.strip()[-300:]}")
    bad = a.cli("adapter", "route", "add", "--adapter", ada.adapter_id, "--name", "rt-agent", "--peer", b.id,
                "--agent", bert.id, "--action", "runtime.run", "--expires-in", "1h")
    check(not bad.ok, "a runtime.run route naming an agent was created")
    host_route = b.cli("adapter", "route", "add", "--adapter", bert.adapter_id, "--name", "rt", "--peer", a.id,
                       "--action", "runtime.run", "--expires-in", "1h")
    check(host_route.ok, f"a runtime.run route naming alice's host: exit {host_route.code} "
                         f"{host_route.stderr.strip()[-300:]}")
    state["route"] = "rt"


# Requests (runtime Requests).

@suite.case("request_validation", "runtime Requests: executor, fields, run limits, manifest (400 invalid, field named)")
def _():
    a, b = need("a", "b")
    need("ready")
    sha = hashlib.sha256(b"x").hexdigest()
    manifest = [{"name": "ws.tar", "size": 1, "sha256": sha, "media_type": "application/x-tar"}]
    cases = [
        ("executor", raw_task(executor="vm")),
        ("target_agent_id", raw_task(target_agent_id="agent_" + "0" * 32)),
        ("grant_id", raw_task(grant_id="grant_" + "0" * 32)),
        ("chain", raw_task(chain=[])),
        ("argv", raw_task(run={"argv": []})),
        ("argv", raw_task(run={"argv": ["a\u0000b"]})),
        ("argv", raw_task(run={"argv": ["x" * 4097]})),
        ("argv", raw_task(run={"argv": ["x"] * 257})),
        ("cwd", raw_task(run={"argv": ["echo"], "cwd": "relative"})),
        ("env", raw_task(run={"argv": ["echo"], "env": {"1BAD": "x"}})),
        ("env", raw_task(run={"argv": ["echo"], "env": {f"V{i}": "x" for i in range(65)}})),
        ("cpus", raw_task(run={"argv": ["echo"], "resources": {"cpus": 0}})),
        ("memory_mib", raw_task(run={"argv": ["echo"], "resources": {"memory_mib": 127}})),
        ("timeout_seconds", raw_task(run={"argv": ["echo"], "resources": {"timeout_seconds": 86401}})),
        ("results", raw_task(run={"argv": ["echo"], "results": "everything"})),
        (("run", "stdin"), raw_task(run={"argv": ["echo"], "stdin": "x"})),
        (("workspace", "artifacts"), raw_task(run={"argv": ["echo"], "workspace": {"archive": sha}})),
        (("workspace", "artifacts", "media_type"), raw_task(run={"argv": ["echo"], "workspace": {"archive": sha}},
                                                            artifacts=[dict(manifest[0], media_type="text/plain")])),
    ]
    failures = []
    for field, body in cases:
        fields = (field,) if isinstance(field, str) else field
        status, answer = peer_submit(body)
        if not (status == 400 and isinstance(answer, dict) and answer.get("code") == "invalid"
                and any(f in (answer.get("error") or "") for f in fields)):
            failures.append(f"{'/'.join(fields)}: {status} {answer}")
    check(not failures, "requests not refused as 400 invalid naming the field: " + "; ".join(failures))


@suite.case("resources_over_rule_refused", "runtime Checks step 3: resources over the rule's maximum (403)")
def _():
    need("ready")
    for resources in ({"cpus": 3}, {"memory_mib": 4096}, {"timeout_seconds": 3601}):
        status, body = peer_submit(raw_task(run={"argv": ["echo"], "resources": resources}))
        check(status == 403, f"resources {resources} over the rule: {status} {body}")
    status, body = peer_submit(raw_task(run={"argv": ["echo"], "resources": {"cpus": 2, "memory_mib": 2048,
                                                                             "timeout_seconds": 3600}}))
    check(status == 200, f"resources at the rule's maximum: {status} {body}")
    final(body["task_id"])


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
          and request["workspace_archive"] is None and request["results"] == "output", f"start request {request}")
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
    result = b.cli("task", "run", "--peer", a.id, "--detach", "--", "echo", "detached", timeout=30)
    check(result.ok and isinstance(result.json, dict) and result.json["request"]["executor"] == "runtime"
          and result.json["request"]["input"] == "echo detached", f"--detach: exit {result.code} {result.stdout[-300:]}")
    final(result.json["request"]["task_id"])


@suite.case("runtime_enable_disable_show", "runtime Runtime administration: enable checks, disable, show")
def _():
    a, rt = need("a", "rt")
    need("ready")
    over = a.cli("runtime", "enable", "--socket", str(rt.socket), "--max-cpus", "9", timeout=60)
    check(not over.ok, "runtime enable accepted a maximum over the runtime's report")
    missing = a.cli("runtime", "enable", "--socket", str(suite.work / "nothing.sock"), timeout=60)
    check(not missing.ok, "runtime enable accepted a socket where no runtime answers")
    out = a.cli("runtime", "disable", timeout=90)
    check(out.ok, f"runtime disable: exit {out.code} {out.stderr.strip()[-300:]}")
    shown = show(a)
    check(shown["enabled"] is False and shown["rule"] is None, f"after disable: {shown}")
    rules = policy_statement(a, state["alice_public"])[3].get("runtime_rules") or []
    check(all(r["host"] != a.id for r in rules), f"alice's host still has a runtime rule: {rules}")
    status, body = peer_submit(raw_task())
    refused(status, body, 403, "runtime_disabled")
    enable("--for", state["alice_principal"], "--for", state["bob_principal"])
    check(show(a)["enabled"] is True, "enable after disable")


# Rechecks at start (runtime Checks).

@suite.case("recheck_switch_off_while_queued", "runtime Checks: switch off while queued ends rejected; a started run "
                                               "finishes")
def _():
    a, rt = need("a", "rt")
    need("ready")
    holder = occupy(3)
    task_id = submit(["echo", "queued"])
    receiver_events(task_id, until=lambda evs: bool(evs))
    status, body = a.api("DELETE", "/v1/runtime")
    check(status == 200, f"DELETE /v1/runtime: {status} {body}")
    try:
        events = final(task_id, timeout=20)
        check(events[-1]["kind"] == "rejected" and events[-1]["message"], f"events {[e['kind'] for e in events]}")
        check(final(holder)[-1]["kind"] == "succeeded", "the started run did not finish after the switch went off")
    finally:
        a.api("PUT", "/v1/runtime", {"socket": str(rt.socket)})


@suite.case("recheck_rule_withdrawn_while_queued", "runtime Checks: the rule withdrawn while queued ends rejected")
def _():
    a, rt = need("a", "rt")
    need("ready")
    holder = occupy(4)
    task_id = submit(["echo", "queued"])
    receiver_events(task_id, until=lambda evs: bool(evs))
    out = a.cli("runtime", "disable", timeout=90)
    check(out.ok, f"runtime disable: {out.stderr.strip()[-300:]}")
    status, body = a.api("PUT", "/v1/runtime", {"socket": str(rt.socket)})  # the switch on again, without a rule
    check(status == 200, f"PUT /v1/runtime: {status} {body}")
    try:
        events = final(task_id, timeout=20)
        check(events[-1]["kind"] == "rejected" and events[-1]["message"], f"events {[e['kind'] for e in events]}")
        check(final(holder)[-1]["kind"] == "succeeded", "a started run was stopped by withdrawing the rule")
    finally:
        enable("--for", state["alice_principal"], "--for", state["bob_principal"])


@suite.case("recheck_runtime_maximums", "runtime Running: a 422 from the runtime ends rejected")
def _():
    b, rt = need("b", "rt")
    need("ready")
    rt.restart(max_cpus=1)
    try:
        task_id = submit(["echo", "too big"])
        events = final(task_id, timeout=20)
        check([e["kind"] for e in events] == ["queued", "rejected"] and events[-1]["message"],
              f"events {[e['kind'] for e in events]}")
        posts = rt.entries("post", run_id(b, task_id))
        check(all(p["status"] == 422 for p in posts) and not rt.entries("started", run_id(b, task_id)),
              f"runtime answers {[p['status'] for p in posts]}")
    finally:
        rt.restart()


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


# Agents (runtime Agents).

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


@suite.case("adapter_runs_and_notifications", "runtime Agents: POST /adapter/v1/runs; Output notifications")
def _():
    a, b = need("a", "b")
    need("ready", "route")
    bert = state["bert"]
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


class Channel:
    """The real MCP adapter over stdio, as conformance/agent_adapter.py starts it, with no model."""

    def __init__(self, host, setup, directory):
        node = shutil.which("node")
        script = REPO / "integrations" / "claude-channel" / "channel.mjs"
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

    def call(self, method, params, seconds=20):
        self.count += 1
        rid = self.count
        self.send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            event = self.events.get(timeout=max(0.01, deadline - time.monotonic()))
            check(event is not None, "the MCP adapter exited")
            if event.get("id") == rid:
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

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.logs.close()


@suite.case("mcp_run_task", "runtime Agents: MCP run_task with a workspace path; output notifications and meta.output")
def _():
    a, b = need("a", "b")
    need("ready")
    status, agent = b.api("POST", "/v1/agents", {"name": "bea", "owner": "bob"})
    check(status in (200, 201), f"register bea: {status} {agent}")
    status, setup = b.api("POST", "/v1/adapters/setup", {
        "agent_id": agent["id"], "session_id": "session_" + os.urandom(16).hex(), "integration": "claude-channel",
        "expires_at": rfc3339(b.now() + timedelta(hours=2))})
    check(status == 201, f"adapter setup for bea: {status} {setup}")
    route = b.cli("adapter", "route", "add", "--adapter", setup["credential"]["adapter"]["id"], "--name", "rt-mcp",
                  "--peer", a.id, "--action", "runtime.run", "--expires-in", "1h")
    check(route.ok, f"runtime.run route for bea: {route.stderr.strip()[-300:]}")
    work = b.root / "mcp-ws"
    work.mkdir()
    (work / "note.txt").write_text("packed by the adapter\n")
    channel = Channel(b, setup, suite.work / "mcp")
    try:
        argv = ["cat", "note.txt"]
        for i in range(5):
            argv += [";", "sleep", "0.4", ";", "echo", f"tick{i}"]
        answer = channel.call("tools/call", {"name": "run_task", "arguments": {
            "destination": "rt-mcp", "argv": argv, "workspace_path": str(work), "results": "output"}})
        check(not answer.get("isError"), f"run_task: {answer}")
        text = answer["content"][0]["text"]
        task_id = next((w for w in text.replace('"', " ").replace(",", " ").split() if w.startswith("task_")), None)
        check(task_id, f"run_task returned no task ID: {text[:300]}")
        updates = []
        while True:
            note = channel.notification(seconds=40)
            meta = note.get("meta", {})
            if meta.get("kind") != "task_update" or task_id not in meta.values():
                continue
            updates.append(meta)
            if meta.get("state") in FINAL:
                break
        # Output notifications are the running-state updates that carry meta.output text.
        outputs = [m for m in updates if m.get("state") == "running" and m.get("output")]
        text = "".join(m["output"] for m in outputs)
        want = "packed by the adapter\n" + "".join(f"tick{i}\n" for i in range(5))
        check(text == want, f"meta.output across {len(outputs)} output notifications: {text!r}, want {want!r}")
        events = b.api("GET", f"/v1/tasks/{a.id}/{task_id}/events")[1]
        stored = len([e for e in events if e["kind"] == "output"])
        check(stored < 3 or len(outputs) < stored, f"{len(outputs)} output notifications for {stored} output events")
        last = updates[-1]
        check(last.get("state") == "succeeded" and "exit_code" in json.dumps(last), f"final update {last}")
    finally:
        channel.close()


# Persistence (runtime Persistence).

@suite.case("open_previous_schema", "runtime Persistence: a database of the previous schema version opens")
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
    check(current >= 25, f"schema version {current}; this contract needs the next version after 24")
    db.execute(f"PRAGMA user_version = {current - 1}")
    db.commit()
    db.close()
    copy.start()
    check(copy.id == a2.id, "the copy has another host ID")
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        check(db.execute("PRAGMA user_version").fetchone()[0] == current, "the previous version was not upgraded")
    finally:
        db.close()
    check(copy.api("GET", "/v1/tasks")[0] == 200, "task list on the upgraded database")
    copy.stop()


for _name, _spec in (("renewal_keeps_runtime_rules", "runtime Policy body (Renewal and edits): automatic renewal "
                                                     "copies runtime_rules; test clock"),
                     ("lapsed_sender_needs_allow_disconnected", "runtime Checks step 2: a sender whose grants "
                                                                "lapsed; allow_disconnected; test clock")):
    suite.case(_name, _spec)(lambda name=_name: outcome(name))

suite.finish()
