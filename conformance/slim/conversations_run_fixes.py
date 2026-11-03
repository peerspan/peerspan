#!/usr/bin/env python3
"""Slim suite, conversations C6: the fixes from the multi-machine run.

alice and bob share a coordinator-free network, and bob allows alice. A third host, tess, has no network and only
runs `attach` with fixture bundles. The cases cover the forms of `addressed_to`, a host where only agents take part,
the order rule of `conversation watch` and `earlier_missing`, what the daemon does on a stop, and a launch that needs
a terminal. Written only from docs/conversations-contract.md (C6: Multi-machine run fixes, cited as "Fixes"),
docs/host-service-contract.md, docs/harness-integration-contract.md and docs/launch-contract.md.

Timing. A limit in the contract is checked with a margin where a loaded machine could miss it, and the margin is named
at its constant. A check that something has NOT happened yet gives no verdict if the machine stalled past the point
the contract allows it to happen: such a case is skipped, not passed or failed.

The order cases force the race: the probe pushes the later message first, and the case confirms that it is being held
before pushing the earlier one. Not proven here: `up`'s refusal (its service stage installs a real user service, so
it needs an installed run), a gap closed by a real sync, the 5-second and 10-second limits with a peer request in
flight (no fixture holds one open), `not_bound` in the agents-only error, and the Claude Code plan (`node --test`, in
integrations/claude-channel). A cursor that passes a released message before it prints is only caught if the sampling
lands in that window: nothing can hold watch between printing and posting.
"""
import json
import os
import pty
import re
import select
import signal
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

from harness import (Failure, Skip, Suite, api_error, check, create_network, find_message, join_new_person, message_id,
                     peer, refused, rfc3339, show_targets, ssh_key, view_as, wait_for)

suite = Suite("conversations_run_fixes", __doc__)
a, b, tess = suite.host("alice"), suite.host("bob"), suite.host("tess")
state = {}

NO_PARTICIPANT = "No such participant in that conversation."
CONFLICT = "This message_id was already used with different content."
C1_LINE = "error: not_participant: This participant is not in that conversation."
WATCHING = "Watching; press Ctrl-C to stop."

STOP_LIMIT = 5.0  # Fixes says 3 seconds and the host service contract 2; the old behaviour waits out the long poll
PRINT_LIMIT = 12.0  # Fixes says 8 seconds: the 5-second hold, then a margin
LATE_LINE_LIMIT = 38.0  # the contract says 30 seconds
HOLD = 5.0  # the contract's longest hold; no claim that a message is still held is made near it
BLOCKED_AFTER = 1.0  # how long a command runs before the stop, as Fixes says
SHARED_HOLD_LIMIT = 4.25  # from a push 3s into a hold: its limit is 2s off, a read 1s more; its own hold would be 5s


# The markers come off as the fixes land: a marked case that passes fails the suite.


def need(*names):
    missing = [n for n in names if n not in state]
    check(not missing, f"an earlier case did not finish ({', '.join(missing)} missing)")
    return [state[n] for n in names]


def participant(adapter):
    return f"agent:{adapter.host.id}/{adapter.id}"


def agent(name):
    """A fixture agent on bob that alice's host can address."""
    adapter = b.agent(name)
    a.ok("agents", "--refresh", "--json")
    return adapter


def start(*targets, join=True):
    """alice's person starts a conversation with TARGETS; bob's person joins it unless JOIN is false."""
    started = a.ok("conversation", "start", *targets, timeout=60)
    conv = started["conversation"]["conversation_id"]
    for outcome in started["invites"]:
        check(outcome["state"] in ("joined", "invited"), f"start {targets}: {outcome}")
        if outcome["state"] == "invited":
            state["bob_person"] = outcome["participant"].split(":", 1)[1]
            wait_for(lambda: conv in invites(b), timeout=20, interval=0.2, message=f"bob to hold the invite to {conv}")
            if join:
                b.ok("conversation", "join", conv, timeout=60)
    return conv


def invites(host):
    status, body = host.api("GET", "/v1/conversations/invites")
    check(status == 200, f"{host.name}: invites: {status} {body}")
    return {i["conversation_id"] for i in body["invites"]}


def bob_p():
    return f"person:{b.id}/{state['bob_person']}"


def say(conv, what, host=a, *extra):
    return host.ok("conversation", "say", conv, what, *extra)["message"]["message_id"]


def message_view(host, conv, mid, query=""):
    status, body = host.api("GET", f"/v1/conversations/{conv}/messages/{mid}{query}")
    check(status == 200, f"{host.name}: message {mid}: {status} {body}")
    check(isinstance(body.get("earlier_missing"), bool), f"earlier_missing is not a boolean: {body}")
    return body


def unread(conv):
    status, body = b.api("GET", "/v1/conversations?state=all")
    check(status == 200, f"bob: list: {status} {body}")
    found = [s for s in body["conversations"] if s["conversation_id"] == conv]
    check(found, f"bob does not list {conv}")
    return found[0]["unread"]


def lines(text):
    return [line for line in text.splitlines() if line.strip()]


def only_agents_error(names):
    return f"{C1_LINE} Agents on this host that are: {names}. Use --as NAME."


def not_showing(conv, names):
    return (f"Not showing {conv[:13]}: this host's person is not in it. Agents on this host that are: {names}. "
            "Use conversation watch --as NAME.")


def refused_with(result, line):
    check(result.code == 1, f"`{' '.join(result.args[:3])}`: exit {result.code}, want 1: {result.stderr[-300:]!r}")
    check(line in lines(result.stderr), f"`{' '.join(result.args[:3])}`: stderr {result.stderr[-400:]!r}, want the "
                                        f"line {line!r}")


class Watch:
    """`conversation watch` through suite.spawn, its output in files so nothing blocks."""
    count = 0

    def __init__(self, host, *args):
        Watch.count += 1
        self.out = host.root / f"watch{Watch.count}.out"
        self.err = host.root / f"watch{Watch.count}.err"
        self.args, self.host = args, host

    def __enter__(self):
        with self.out.open("wb") as out, self.err.open("wb") as err:
            self.process = suite.spawn([str(suite.host_bin), "--state", str(self.host.state), "conversation", "watch",
                                        *self.args], stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                       env=self.host.env, cwd=str(self.host.root))
        try:
            wait_for(lambda: WATCHING in self.errors(), timeout=20, interval=0.1, message="the `Watching` line")
        except BaseException:
            self.__exit__()
            raise
        return self

    def __exit__(self, *_):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=5)

    def text(self):
        return self.out.read_bytes().decode(errors="replace")

    def errors(self):
        return self.err.read_bytes().decode(errors="replace")

    def wait_text(self, piece, timeout=20):
        try:
            wait_for(lambda: piece in self.text(), timeout=timeout, interval=0.05, message=f"watch to print {piece!r}")
        except AssertionError as error:
            raise AssertionError(f"{error}; stdout {self.text()[-500:]!r}") from None

    def stop(self):
        self.process.terminate()
        try:
            code = self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            raise AssertionError("watch did not end within 10s of SIGTERM") from None
        check(code == 0, f"watch exit {code} on SIGTERM, want 0")


def chat(what, *others):
    """A conversation of alice's person, bob's person and OTHERS with s1 `delivered`; returns (ID, roster version, s1's
    clock)."""
    conv = start("person:bob", *others)
    s1 = say(conv, f"{what} s1")
    show_targets(a, conv, s1, bob_p(), "delivered")
    status, body = b.api("GET", f"/v1/conversations/{conv}/messages?limit=100")  # the route: `show` moves the cursor
    check(status == 200, f"bob: messages: {status} {body}")
    seen = find_message(body, s1)
    check(seen["seq"] == 1, f"s1 has seq {seen['seq']}, want 1")
    return conv, view_as(b, conv, bob_p())["roster_version"], seen["clock"]


def push(conv, version, s1_clock, seq, prev_seq, content):
    """A probe message from alice's host to bob's person (Fixes: Order). Returns its ID."""
    mid = message_id()
    message = {"message_id": mid, "conversation_id": conv, "author": state["alice_p"], "seq": seq,
               "clock": s1_clock + seq - 1, "roster_version": version, "sent_at": rfc3339(a.now()), "content": content}
    status, body = peer(a, b, "POST", f"/peer/v1/conversations/{conv}/messages",
                        {"message": message, "target": bob_p(), "prev_seq": prev_seq})
    check(status == 200, f"probe seq {seq}: {status} {body}")
    return mid


def latest_event():
    status, body = b.api("GET", "/v1/conversations/events?wait=0&limit=1")
    check(status == 200, f"bob: events: {status} {body}")
    return body["latest"]


def cursor_posts(conv, after):
    """The cursor moves of bob's person in CONV since event AFTER: the route's only view of what watch has posted."""
    status, body = b.api("GET", f"/v1/conversations/events?after={after}&limit=1000&conversation={conv}")
    check(status == 200, f"bob: events: {status} {body}")
    return [e for e in body["events"] if e["kind"] == "read_changed"]


def signal_stop(host, number, limit=STOP_LIMIT):
    """Send NUMBER to HOST's daemon alone, and return once it has exited; fail, leaving it stopped, past LIMIT."""
    began = time.monotonic()
    host.process.send_signal(number)
    try:
        host.process.wait(timeout=limit)
    except subprocess.TimeoutExpired:
        host.stop(kill=True)
        raise Failure(f"{host.name}'s daemon was still running {limit:.0f}s after signal {number}") from None
    host.process = None
    return time.monotonic() - began


def running(*hosts):
    for host in hosts:
        if host.process is None or host.process.poll() is not None:
            host.process = None
            host.start()


class Blocked:
    """A CLI command that waits on a route while the daemon gets stopped."""

    def __init__(self, host, *args):
        self.out = host.root / "blocked.out"
        self.err = host.root / "blocked.err"
        with self.out.open("wb") as out, self.err.open("wb") as err:
            self.process = suite.spawn([str(suite.host_bin), "--state", str(host.state), *args],
                                       stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=host.env,
                                       cwd=str(host.root))
        time.sleep(BLOCKED_AFTER)
        self.waiting = self.process.poll() is None

    def finish(self, what):
        check(self.waiting, f"{what} had already answered after {BLOCKED_AFTER:.0f}s, so nothing was waiting: the "
                            "route should wait for the host that is down")
        try:
            code = self.process.wait(timeout=STOP_LIMIT)
        except subprocess.TimeoutExpired:
            self.process.kill()
            raise Failure(f"{what} hung after the daemon stopped") from None
        return code, self.out.read_text(errors="replace"), self.err.read_text(errors="replace")


# A launch that needs a terminal (launch contract), with fixture bundles and a fixture program.

HELPER = """import json, sys
request = json.load(sys.stdin)
answer = {"version": 1, "checks": [{"name": "fixture", "status": "ok", "detail": "ok"}]}
if request.get("operation") == "launch":
    answer["launch"] = json.load(open(%r))
print(json.dumps(answer))
"""
PROGRAM = """#!/bin/sh
if [ -t 1 ]; then echo terminal >> "$1"; else echo not-a-terminal >> "$1"; fi
"""
projects = iter(range(1000))


def terminal_required():
    """The exact text from the contract, so a change of wording there needs no change here."""
    contract = Path(__file__).resolve().parents[2] / "docs" / "launch-contract.md"
    found = re.search(r"^error: terminal_required: .*$", contract.read_text(), re.M)
    check(found, "docs/launch-contract.md has no terminal_required line")
    return found.group(0)


def bundle(integration, terminal):
    """Integration INTEGRATION, whose launch plan has TERMINAL (left out when None); returns its record file."""
    root = suite.work / "integrations" / integration
    root.mkdir(parents=True)
    record = suite.work / f"{integration}.ran"
    program = suite.work / "fixture-program"
    if not program.exists():
        program.write_text(PROGRAM)
        program.chmod(program.stat().st_mode | stat.S_IXUSR)
    plan = {"program": str(program), "args": [str(record)]}
    if terminal is not None:
        plan["terminal"] = terminal
    (root / "plan.json").write_text(json.dumps(plan))
    (root / "helper.py").write_text(HELPER % str(root / "plan.json"))
    (root / "integration.json").write_text(json.dumps({
        "version": 1, "id": integration, "command": [sys.executable, "./helper.py"],
        "operations": ["prepare", "check", "launch"]}))
    return record


def project():
    directory = suite.work / "projects" / f"p{next(projects)}"
    directory.mkdir(parents=True)
    return directory


def attach_args(integration, directory, *extra):
    return ["attach", integration, "--integrations", suite.work / "integrations", "--directory", directory, *extra]


def ran(record):
    return record.read_text().split() if record.exists() else []


def on_terminal(host, *args, timeout=60):
    """Run the CLI with stdout a terminal and stdin not one; returns (exit code, stderr). harness `tty=True` gives the
    other way round: stdin a terminal and stdout a pipe."""
    master, slave = pty.openpty()
    process = suite.spawn([str(suite.host_bin), "--state", str(host.state), *map(str, args)],
                          stdin=subprocess.DEVNULL, stdout=slave, stderr=subprocess.PIPE, env=host.env,
                          cwd=str(host.root))
    os.close(slave)
    deadline = time.monotonic() + timeout
    try:
        while process.poll() is None and time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    os.read(master, 65536)
                except OSError:
                    pass
        check(process.poll() is not None, f"{' '.join(map(str, args[:2]))} did not end within {timeout}s")
        return process.returncode, process.stderr.read().decode(errors="replace")
    finally:
        os.close(master)
        process.stderr.close()


def object_on_stderr(stderr):
    """The output object `attach` prints on stderr, before any error line."""
    text = stderr[:stderr.index("error:")] if "error:" in stderr else stderr
    begin = text.find("{")
    check(begin >= 0, f"no output object on stderr: {stderr[-400:]!r}")
    try:
        return json.JSONDecoder().raw_decode(text[begin:])[0]
    except ValueError:
        raise Failure(f"no output object on stderr: {stderr[-400:]!r}") from None


@suite.case("setup", "C6 Verification Setup; C1 Verification setup; decentralized-spec 6, 8")
def _():
    net = create_network(a, "fixes", "alice")
    key = ssh_key(b.root, "bob")
    join_new_person(a, b, "bob", key, net["id"])
    allowed = b.ok("allow", "alice", "--no-tasks", "--person-key", key)
    state["alice_person"] = allowed["principal"].split(":", 1)[1]
    state["alice_p"] = f"person:{a.id}/{state['alice_person']}"

    def held():
        status, body = a.api("POST", f"/v2/networks/{net['id']}/sync", {}, timeout=40)
        check(status == 200, f"alice: sync: {status} {body}")
        status, versions = a.api("GET", f"/v2/networks/{net['id']}/access-versions")
        check(status == 200, f"alice: access-versions: {status} {versions}")
        return any(p["version"] >= allowed["policy"]["version"] for p in versions["policies"])
    wait_for(held, timeout=30, interval=1, message="alice to hold bob's policy")
    state["bert"] = agent("bert")
    state["bea"] = agent("bea")
    state["ned"] = agent("ned")


@suite.case("addressed_forms", "C6 `addressed_to`: Local sending; Fixes: `addressed_to` forms")
def _():
    alice_p, bert = need("alice_p", "bert")[0], state["bert"]
    person = state["alice_person"]
    conv = start("person:bob", "bob/bert")
    state["forms_conv"] = conv
    bert_p = participant(bert)
    wanted = [(form, alice_p) for form in ("person:alice", "alice", f"person:{person}", person, alice_p)]
    wanted += [(form, bert_p) for form in ("bob/bert", f"{b.id}/bert", f"{b.id}/{bert.id}")]
    wrong = []

    def expect(route, form, want, status, body):
        got = body.get("message", {}).get("addressed_to") if status == 200 and isinstance(body, dict) else None
        if got != [want]:
            wrong.append(f"{route} {form}: {status} {got if got is not None else body}")

    path = f"/v1/conversations/{conv}/messages"
    for form, want in wanted:
        said = a.cli("conversation", "say", conv, f"cli {form}", "--to", form)
        expect("say", form, want, 200 if said.ok else said.code, said.json if said.ok else said.stderr[-200:])
        expect("owner", form, want, *a.api("POST", path, {"content": f"owner {form}", "addressed_to": [form]}))
        expect("adapter", form, want, *bert.post(f"/adapter{path}", {
            "content": f"adapter {form}", "message_id": message_id(), "addressed_to": [form]}))
    check(not wrong, "forms that did not resolve: " + "; ".join(wrong))


@suite.case("addressed_refused", "C6 `addressed_to`: no match; Fixes: `addressed_to` forms")
def _():
    conv, bert = need("forms_conv", "bert")
    path = f"/v1/conversations/{conv}/messages"
    for form in ("person:nobody", "person:bob/bert"):
        refused(a.cli("conversation", "say", conv, "no", "--to", form), "not_found", NO_PARTICIPANT)
        api_error(*a.api("POST", path, {"content": "no", "addressed_to": [form]}), 404, "not_found", NO_PARTICIPANT)
        api_error(*bert.post(f"/adapter{path}", {"content": "no", "message_id": message_id(), "addressed_to": [form]}),
                  404, "not_found", NO_PARTICIPANT)
    invited = start("person:bob", join=False)
    forms = ("person:bob", f"person:{state['bob_person']}", state["bob_person"])
    for form in forms:
        refused(a.cli("conversation", "say", invited, "no", "--to", form), "not_found", NO_PARTICIPANT)


@suite.case("addressed_repeats", "C6 `addressed_to`: Repeats; Fixes: `addressed_to` forms")
def _():
    conv, alice_p = need("forms_conv", "alice_p")
    mid = message_id()
    first = a.ok("conversation", "say", conv, "repeat me", "--message-id", mid, "--to", "alice")["message"]
    for form in ("person:alice", f"person:{state['alice_person']}", state["alice_person"], alice_p):
        again = a.ok("conversation", "say", conv, "repeat me", "--message-id", mid, "--to", form)["message"]
        check(again["seq"] == first["seq"], f"a repeat with {form} made a new message: {again}")
    conflict = a.cli("conversation", "say", conv, "repeat me", "--message-id", mid, "--to", "bob/bert")
    refused(conflict, "conflict", CONFLICT)
    refused(a.cli("conversation", "say", conv, "repeat me", "--message-id", mid), "conflict", CONFLICT)
    ned = state["ned"]
    gone = start("bob/ned")
    mid = message_id()
    first = a.ok("conversation", "say", gone, "for ned", "--message-id", mid, "--to", f"{b.id}/ned")["message"]
    a.ok("conversation", "remove", gone, "bob/ned")
    again = a.ok("conversation", "say", gone, "for ned", "--message-id", mid, "--to", f"{b.id}/{ned.id}")["message"]
    check(again["seq"] == first["seq"], f"a repeat after ned departed made a new message: {again}")


@suite.case("only_agents_show", "C6 A host where only agents take part; Fixes: Agents only: `show`")
def _():
    need("bert", "bea")
    a.agent("ada")
    conv = start("bob/bert")
    state["agents_conv"] = conv
    listed = b.cli("conversations", "--json")
    check(listed.ok and conv in listed.stdout, f"bob's `conversations` does not list {conv}: {listed}")
    refused_with(b.cli("conversation", "show", conv), only_agents_error("bert"))
    refused_with(b.cli("conversation", "show", conv, "--json"), only_agents_error("bert"))
    b.ok("conversation", "show", conv, "--as", "bert", "--json")
    a.ok("conversation", "add", conv, "bob/bea", timeout=30)
    a.ok("conversation", "add", conv, "alice/ada", timeout=30)  # another host's agent is not named

    def holds():
        view = view_as(b, conv, participant(state["bert"]))
        names = {p.get("name") for p in view["participants"] if p["state"] == "joined"}
        return {"bea", "ada"} <= names
    wait_for(holds, timeout=20, interval=0.2, message="bob to hold the roster with bea and ada")
    refused_with(b.cli("conversation", "show", conv), only_agents_error("bea, bert"))
    refused_with(b.cli("conversation", "show", conv, "--json"), only_agents_error("bea, bert"))
    state["agents_show_done"] = True


@suite.case("only_agents_watch_id", "C6 A host where only agents take part; Fixes: Agents only: `watch`")
def _():
    conv = need("agents_conv")[0]
    need("agents_show_done")
    result = b.cli("conversation", "watch", conv, timeout=20)
    refused_with(result, only_agents_error("bea, bert"))
    check(WATCHING not in result.stderr, f"a `Watching` line before the refusal: {result.stderr!r}")
    outside = b.cli("conversation", "watch", conv, "--as", "ned", timeout=20)
    refused_with(outside, C1_LINE)
    check(WATCHING not in outside.stderr, f"a `Watching` line before the refusal: {outside.stderr!r}")


@suite.case("only_agents_watch_all", "C6 A host where only agents take part; Fixes: Agents only: `watch`")
def _():
    conv = need("agents_conv")[0]
    watch = Watch(b)
    state["wide_watch"] = watch.__enter__()
    line = not_showing(conv, "bea, bert")
    wait_for(lambda: line in lines(watch.errors()), timeout=15, interval=0.1, message=f"the line {line!r}")
    found = lines(watch.errors())
    check(found.index(WATCHING) < found.index(line), f"the line came before `Watching`: {found}")
    with Watch(b, "--as", "bert") as as_bert:
        said = say(conv, "agents only content")
        show_targets(a, conv, said, participant(state["bert"]), "delivered")
        as_bert.wait_text("agents only content")
        as_bert.stop()
    time.sleep(3)
    check(watch.text() == "", f"stdout has something about an agents-only conversation: {watch.text()!r}")
    joined = start("person:bob")
    state["joined_conv"] = joined
    said = say(joined, "joined content")
    watch.wait_text("joined content")
    began = time.monotonic()
    late = start("bob/bert")
    state["late_conv"] = late
    want = not_showing(late, "bert")
    try:
        wait_for(lambda: want in lines(watch.errors()), timeout=LATE_LINE_LIMIT, interval=0.2,
                 message=f"the line {want!r}")
    except AssertionError as error:
        raise AssertionError(f"{error}; stderr {watch.errors()[-500:]!r}") from None
    state["late_line_at"] = time.monotonic()
    state["late_took"] = state["late_line_at"] - began
    print(f"  late conversation's line after {state['late_took']:.1f}s", flush=True)


@suite.case("terminal_required", "launch A launch that needs a terminal: refuses, keeps the setup")
def _():
    want = terminal_required()
    record = bundle("needs-terminal", True)
    directory = project()
    args = attach_args("needs-terminal", directory)
    result = tess.cli(*args, timeout=60)
    refused_with(result, want)
    check(ran(record) == [], f"the fixture ran: {ran(record)}")
    check(result.stdout.strip() == "", f"stdout belongs to the harness: {result.stdout[-300:]!r}")
    out = object_on_stderr(result.stderr)
    check(out["reused"] is False, f"object on stderr: {out}")
    doctor = tess.cli("session", "doctor", "--directory", out["profile"], timeout=30)
    check("registered" in doctor.stdout, f"`session doctor` does not report registered: {doctor.code} "
                                         f"{doctor.stdout[-500:]!r}")
    code, stderr = on_terminal(tess, *args)
    check(code == 0, f"at a terminal: exit {code}: {stderr[-300:]!r}")
    check(ran(record) == ["terminal"], f"the fixture at a terminal: {ran(record)}")
    out = object_on_stderr(stderr)
    check(out["reused"] is True, f"at a terminal the object says reused {out['reused']}")


@suite.case("terminal_stdin_ignored", "launch A launch that needs a terminal: only stdout decides, stdin is not checked")
def _():
    want = terminal_required()
    record = bundle("stdin-only", True)
    args = attach_args("stdin-only", project())
    # The harness's tty: stdin a terminal, stdout a pipe. attach then asks about capability calls, hence the answer.
    refused_with(tess.cli(*args, tty=True, input="n\n", timeout=20), want)
    check(ran(record) == [], f"the fixture ran with a terminal on stdin alone: {ran(record)}")


@suite.case("terminal_no_start", "launch A launch that needs a terminal: --no-start never launches")
def _():
    record = bundle("set-up-only", True)
    out = tess.ok(*attach_args("set-up-only", project(), "--no-start"), timeout=60)
    check(out and out["agent"]["name"], f"the object on stdout: {out}")
    check(ran(record) == [], f"the fixture ran with --no-start: {ran(record)}")
    doctor = tess.cli("session", "doctor", "--directory", out["profile"], timeout=30)
    check("registered" in doctor.stdout, f"`session doctor` does not report registered: {doctor.stdout[-900:]!r}")


@suite.case("terminal_session_start", "launch A launch that needs a terminal: `session start` does not refuse")
def _():
    record = bundle("scripted", True)
    out = tess.ok(*attach_args("scripted", project(), "--no-start"), timeout=60)
    tess.ok("session", "start", "--directory", out["profile"], timeout=60)
    check(ran(record) == ["not-a-terminal"], f"`session start` with a pipe: fixture {ran(record)}")


@suite.case("terminal_false", "launch A launch that needs a terminal: `terminal` false, stdout a pipe: the fixture runs")
def _():
    record = bundle("said-false", False)
    tess.ok(*attach_args("said-false", project()), timeout=60)
    check(ran(record) == ["not-a-terminal"], f"with a pipe: fixture {ran(record)}")


@suite.case("terminal_absent", "harness launch: `terminal` defaults to false; launch: the fixture runs")
def _():
    record = bundle("left-out", None)
    tess.ok(*attach_args("left-out", project()), timeout=60)
    check(ran(record) == ["not-a-terminal"], f"with a pipe: fixture {ran(record)}")


@suite.case("terminal_invalid", "harness launch: any other type is an invalid launch plan")
def _():
    record = bundle("wrong-type", "yes")
    result = tess.cli(*attach_args("wrong-type", project()), timeout=60)
    check(result.code == 1 and "integration returned an invalid launch plan" in result.stderr,
          f"exit {result.code}: {result.stderr[-300:]!r}")
    check(ran(record) == [], f"the fixture ran: {ran(record)}")


@suite.case("order_gap_closed", "C6 watch Order; `earlier_missing`; Fixes: Order, gap closed")
def _():
    need("alice_p")
    conv, version, clock = chat("closed")
    state["order"] = (conv, version, clock)
    with Watch(b, conv) as watch:
        began = time.monotonic()
        three = push(conv, version, clock, 3, 2, "closed seq3")
        check(message_view(b, conv, three)["earlier_missing"] is True, "seq 3 past a gap: earlier_missing not true")
        time.sleep(0.4)  # the watch has seen it: its long poll ends on the arrival
        printed = watch.text()
        elapsed = time.monotonic() - began
        if elapsed >= HOLD - 1:
            raise Skip(f"the machine took {elapsed:.1f}s to get here, too near the hold to say anything")
        check("closed seq3" not in printed, f"seq 3 printed while its gap was open: {printed!r}")
        push(conv, version, clock, 2, 1, "closed seq2")
        watch.wait_text("closed seq3")
        printed = watch.text()
        check("closed seq2" in printed and printed.index("closed seq2") < printed.index("closed seq3"),
              f"seq 2's line, then seq 3's: {printed!r}")
        check(message_view(b, conv, three)["earlier_missing"] is False, "earlier_missing still true after the gap closed")
        watch.stop()
    state["head3"] = True


@suite.case("order_printable_together", "C6 watch Order: printable together, in display order")
def _():
    need("alice_p")
    conv, version, clock = chat("together")
    with Watch(b, conv) as watch:
        began = time.monotonic()
        push(conv, version, clock, 4, 3, "together seq4")
        push(conv, version, clock, 3, 2, "together seq3")
        time.sleep(0.4)
        printed = watch.text()
        elapsed = time.monotonic() - began
        if elapsed >= HOLD - 1:
            raise Skip(f"the machine took {elapsed:.1f}s to get here, too near the hold to say anything")
        check("together seq" not in printed, f"printed while the gap was open: {printed!r}")
        push(conv, version, clock, 2, 1, "together seq2")
        watch.wait_text("together seq4")
        printed = watch.text()
        positions = [printed.find(f"together seq{n}") for n in (2, 3, 4)]
        check(-1 not in positions and positions == sorted(positions), f"seq 2, 3, 4 in order: {printed!r}")
        watch.stop()


@suite.case("order_gap_open", "C6 watch Order; `earlier_missing`; Fixes: Order, gap not closed")
def _():
    conv, version, clock = need("order")[0]
    need("head3")
    with Watch(b, conv) as watch:
        b.ok("conversation", "read", conv)
        check(unread(conv) == 0, f"unread {unread(conv)} before the push")
        mark = latest_event()
        began = time.monotonic()
        six = push(conv, version, clock, 6, 5, "open seq6")
        check(message_view(b, conv, six)["earlier_missing"] is True, "seq 6 past a gap: earlier_missing not true")
        time.sleep(max(0.0, began + 2 - time.monotonic()))
        printed, count = watch.text(), unread(conv)
        elapsed = time.monotonic() - began
        if elapsed >= HOLD - 1:
            raise Skip(f"the machine took {elapsed:.1f}s to get here, too near the hold to say anything")
        check("open seq6" not in printed, f"seq 6 printed {elapsed:.1f}s after the push: {printed!r}")
        check(count >= 1, f"unread {count} while seq 6 is held: it does not count until printed")
        # The same hold: another author's message prints through it and moves no cursor, and further messages of this
        # author wait behind seq 6 on its limit, one that follows it and one past a gap of its own.
        say(conv, "open own", b)
        watch.wait_text("open own", timeout=PRINT_LIMIT)  # with nothing about seq 6: it may have released on a stall
        time.sleep(max(0.0, began + 2.3 - time.monotonic()))
        seven = push(conv, version, clock, 7, 6, "open seq7")
        check(message_view(b, conv, seven)["earlier_missing"] is True, "seq 7 past a gap: earlier_missing not true")
        time.sleep(max(0.0, began + 3.0 - time.monotonic()))
        nine = push(conv, version, clock, 9, 8, "open seq9")
        pushed = time.monotonic()
        check(message_view(b, conv, nine)["earlier_missing"] is True, "seq 9 past a gap: earlier_missing not true")
        printed, count, posts = watch.text(), unread(conv), cursor_posts(conv, mark)
        elapsed = time.monotonic() - began
        in_time = elapsed < HOLD - 1  # a stall costs only these claims: the rest of the case still gives its verdict
        if in_time:
            for n in (6, 7, 9):
                check(f"open seq{n}" not in printed, f"seq {n} printed during seq 6's hold: {printed!r}")
            check(count == 3, f"unread {count} with seq 6, 7 and 9 held, want 3: the cursor passed a held message")
            check(not posts, f"a cursor post while the conversation holds a message: {posts}")
        else:
            print(f"  NO VERDICT on the shared hold: the machine took {elapsed:.1f}s to get here", flush=True)
        watch.wait_text("open seq6", timeout=max(0.1, began + PRINT_LIMIT - time.monotonic()))
        if in_time:
            try:
                watch.wait_text("open seq9", timeout=max(0.1, pushed + SHARED_HOLD_LIMIT - time.monotonic()))
            except AssertionError as error:
                raise Failure(f"seq 9 not printed {SHARED_HOLD_LIMIT}s after its push, so it extended seq 6's hold: "
                              f"{error}") from None
            printed = watch.text()
            positions = [printed.find(f"open seq{n}") for n in (6, 7, 9)]
            check(-1 not in positions and positions == sorted(positions), f"seq 6, 7, 9 in order: {printed!r}")
        check(message_view(b, conv, six)["earlier_missing"] is True, "a gap that stayed open: earlier_missing not true")
        wait_for(lambda: unread(conv) == 0, timeout=20, interval=0.2, message="seq 6 to leave the unread count")
        check(cursor_posts(conv, mark), "unread 0 with no cursor move in the event log")
        # Later than the hold, so out of order, and they still print. seq 4 closes the gap, so nothing waits out a hold.
        push(conv, version, clock, 5, 4, "open seq5")
        push(conv, version, clock, 4, 3, "open seq4")
        watch.wait_text("open seq5", timeout=PRINT_LIMIT)
        watch.wait_text("open seq4", timeout=PRINT_LIMIT)
        check(message_view(b, conv, six)["earlier_missing"] is False, "earlier_missing still true after the gap closed")
        watch.stop()


@suite.case("order_lower_arrival", "C6 watch Order: any held message of the author shares its limit, a lower seq too")
def _():
    need("alice_p")
    conv, version, clock = chat("lower")
    with Watch(b, conv) as watch:
        began = time.monotonic()
        push(conv, version, clock, 5, 4, "lower seq5")
        time.sleep(max(0.0, began + 3.0 - time.monotonic()))
        three = push(conv, version, clock, 3, 2, "lower seq3")
        pushed = time.monotonic()
        check(message_view(b, conv, three)["earlier_missing"] is True, "seq 3 past a gap: earlier_missing not true")
        printed = watch.text()
        elapsed = time.monotonic() - began
        if elapsed >= HOLD - 1:
            raise Skip(f"the machine took {elapsed:.1f}s to get here, too near the hold to say anything")
        check("lower seq" not in printed, f"printed during the hold: {printed!r}")
        try:
            watch.wait_text("lower seq3", timeout=max(0.1, pushed + SHARED_HOLD_LIMIT - time.monotonic()))
            watch.wait_text("lower seq5", timeout=max(0.1, pushed + SHARED_HOLD_LIMIT - time.monotonic()))
        except AssertionError as error:
            raise Failure(f"not printed {SHARED_HOLD_LIMIT}s after seq 3's push, so it extended seq 5's hold: "
                          f"{error}") from None
        printed = watch.text()
        check(printed.index("lower seq3") < printed.index("lower seq5"), f"seq 3, then seq 5: {printed!r}")
        watch.stop()


@suite.case("earlier_missing_otherwise", "C6 `earlier_missing`; Fixes: `earlier_missing` otherwise")
def _():
    need("bert", "alice_p")
    bert = state["bert"]
    bert_p = participant(bert)
    conv = start("person:bob", "bob/bert")
    s1 = say(conv, "plain s1")
    show_targets(a, conv, s1, bob_p(), "delivered")
    check(message_view(a, conv, s1)["earlier_missing"] is False, "on its own author's read")
    check(message_view(b, conv, s1)["earlier_missing"] is False, "with no gap")
    mine = say(conv, "bob's own", host=b)
    check(message_view(b, conv, mine)["earlier_missing"] is False, "on its own author's read, on bob")
    status, body = bert.post(f"/adapter/v1/conversations/{conv}/messages",
                             {"content": "from bert", "message_id": message_id()})
    check(status == 200, f"bert: send: {status} {body}")
    his = body["message"]["message_id"]
    check(message_view(b, conv, his)["earlier_missing"] is False, "for an agent on this host")
    check(message_view(b, conv, his, f"?participant={bert_p}")["earlier_missing"] is False, "on bert's own read")


@suite.case("only_agents_watch_once", "C6 A host where only agents take part: once per run, nothing on stdout")
def _():
    conv, joined, late, at = need("agents_conv", "joined_conv", "late_conv", "late_line_at")
    watch = need("wide_watch")[0]
    # A line sent again would come with the next look, at most 30 seconds on: the cases since then have used that time.
    time.sleep(max(0.0, at + 32 - time.monotonic()))
    found = lines(watch.errors())
    for one in (conv, late):
        count = sum(1 for x in found if x.startswith(f"Not showing {one[:13]}"))
        check(count == 1, f"{one[:13]} got {count} lines: {found}")
    check(not any(x.startswith(f"Not showing {joined[:13]}") for x in found), f"a joined conversation got a line: {found}")
    printed = watch.text()
    check(conv[:13] not in printed and late[:13] not in printed, f"stdout names an agents-only one: {printed!r}")
    watch.stop()


@suite.case("order_held_unread", "C6 watch: a held message stays unread if watch ends first")
def _():
    need("alice_p")
    wide = state.get("wide_watch")
    if wide:  # it would print the held message and move the cursor
        wide.__exit__()
    conv, version, clock = chat("ended")
    with Watch(b, conv) as watch:
        b.ok("conversation", "read", conv)
        check(unread(conv) == 0, f"unread {unread(conv)} before the push")
        began = time.monotonic()
        push(conv, version, clock, 3, 2, "ended seq3")
        time.sleep(0.5)
        elapsed = time.monotonic() - began
        if elapsed >= HOLD - 1:
            raise Skip(f"the machine took {elapsed:.1f}s to get here, too near the hold to say anything")
        watch.stop()
        check("ended seq3" not in watch.text(), f"printed: {watch.text()!r}")
    check(unread(conv) == 1, f"unread {unread(conv)} after a watch ended holding the message, want 1")


@suite.case("order_printed_stays_unread", "C6 watch: no cursor post while a conversation holds a message")
def _():
    need("alice_p", "bert")
    wide = state.get("wide_watch")
    if wide:  # it would post for this conversation too
        wide.__exit__()
    conv, version, clock = chat("kept", "bob/bert")
    with Watch(b, conv) as watch:
        b.ok("conversation", "read", conv)
        check(unread(conv) == 0, f"unread {unread(conv)} before the push")
        mark = latest_event()
        began = time.monotonic()
        push(conv, version, clock, 3, 2, "kept seq3")
        status, body = state["bert"].post(f"/adapter/v1/conversations/{conv}/messages",
                                          {"content": "kept bert", "message_id": message_id()})
        check(status == 200, f"bert: send: {status} {body}")
        watch.wait_text("kept bert", timeout=PRINT_LIMIT)
        printed, count, posts = watch.text(), unread(conv), cursor_posts(conv, mark)
        elapsed = time.monotonic() - began
        if elapsed >= HOLD - 1:
            raise Skip(f"the machine took {elapsed:.1f}s to get here, too near the hold to say anything")
        check("kept seq3" not in printed, f"printed: {printed!r}")
        check(count == 2, f"unread {count} with one message held and one printed, want 2")
        check(not posts, f"a cursor post while the conversation holds a message: {posts}")
        watch.stop()
    check(unread(conv) == 2, f"unread {unread(conv)} after a watch ended during the hold, want 2: what it printed "
                             "meanwhile stays unread")
    check(not cursor_posts(conv, mark), f"a cursor post on the way out: {cursor_posts(conv, mark)}")


@suite.case("order_cursor_follows_print", "C6 watch Order: a cursor does not pass a held or released, unprinted message")
def _():
    need("alice_p")
    wide = state.get("wide_watch")
    if wide:  # its output is not this watch's, so its posts say nothing about what this one printed
        wide.__exit__()
    conv, version, clock = chat("released")
    pieces = [f"released seq{n}" for n in (2, 3, 4)]
    with Watch(b, conv) as watch:
        mark = latest_event()
        began = time.monotonic()
        push(conv, version, clock, 4, 3, pieces[2])
        push(conv, version, clock, 3, 2, pieces[1])
        printed, count, posts = watch.text(), unread(conv), cursor_posts(conv, mark)
        elapsed = time.monotonic() - began
        if elapsed >= HOLD - 1:
            raise Skip(f"the machine took {elapsed:.1f}s to get here, too near the hold to say anything")
        check("released seq" not in printed, f"printed while the gap was open: {printed!r}")
        check(count == 3, f"unread {count} with s1 and two held, want 3")
        check(not posts, f"a cursor post while the conversation holds a message: {posts}")
        push(conv, version, clock, 2, 1, pieces[0])
        deadline = time.monotonic() + 20
        while True:  # read the count first: a cursor that has moved must find every line already out
            count = unread(conv)
            printed = watch.text()
            if count < 4:
                missing = [p for p in pieces if p not in printed]
                check(not missing, f"unread {count}: the cursor moved before {missing} printed: {printed!r}")
            if count == 0:
                break
            check(time.monotonic() < deadline, f"unread still {count} 20s after the gap closed: {printed!r}")
            time.sleep(0.01)
        positions = [printed.find(p) for p in pieces]
        check(positions == sorted(positions), f"seq 2, 3, 4 in order: {printed!r}")
        watch.stop()


@suite.case("only_agents_gone", "C6 A host where only agents take part: no agent, C1's line; Fixes: Agents only: `show`")
def _():
    conv = need("agents_conv")[0]
    need("agents_show_done")
    a.ok("conversation", "remove", conv, "bob/bea")

    def now_one():
        return only_agents_error("bert") in lines(b.cli("conversation", "show", conv).stderr)
    wait_for(now_one, timeout=20, interval=0.3, message="the sentence to name bert alone")
    a.ok("conversation", "remove", conv, "bob/bert")

    def now_none():
        return C1_LINE in lines(b.cli("conversation", "show", conv).stderr)
    try:
        wait_for(now_none, timeout=20, interval=0.3, message="C1's line alone")
    except AssertionError:
        raise AssertionError(f"{b.cli('conversation', 'show', conv).stderr!r}") from None


@suite.case("stop_with_watch", "C6 Daemon stop; host service: stop limits; Fixes: Stop with a watch")
def _():
    conv = start("person:bob")
    try:
        with Watch(b, conv) as watch:
            time.sleep(2)
            took = [signal_stop(b, signal.SIGINT)]
            b.start()
            time.sleep(2)
            took.append(signal_stop(b, signal.SIGTERM))
            b.start()
            print(f"  stops took {took[0]:.1f}s and {took[1]:.1f}s", flush=True)
            check(watch.process.poll() is None, "the watch ended with the daemon")
            say(conv, "after the restarts")
            watch.wait_text("after the restarts", timeout=30)
            watch.stop()
    finally:
        running(b)


@suite.case("stop_long_poll", "C6 Daemon stop: a held events request answers at once")
def _():
    answer = {}
    status, body = b.api("GET", "/v1/conversations/events?wait=0&limit=1")
    check(status == 200, f"bob: events: {status} {body}")
    latest = body["latest"]

    def poll():
        try:
            answer["got"] = b.api("GET", f"/v1/conversations/events?after={latest}&wait=25", timeout=40)
        except OSError as error:
            answer["error"] = error
    thread = threading.Thread(target=poll, daemon=True)
    thread.start()
    time.sleep(1)
    try:
        signal_stop(b, signal.SIGTERM)
        thread.join(timeout=STOP_LIMIT)
        check("got" in answer, f"the held request got no answer: {answer}")
        status, body = answer["got"]
        check(status == 200 and isinstance(body.get("events"), list), f"answer {status} {body}")
    finally:
        running(b)


@suite.case("stop_route_start", "C6 Daemon stop: POST /v1/conversations; Fixes: Stop with a route waiting")
def _():
    need("alice_p", "bob_person")
    b.stop()
    conv = None
    try:
        blocked = Blocked(a, "conversation", "start", "person:bob")
        signal_stop(a, signal.SIGINT)
        code, out, err = blocked.finish("`conversation start`")
        check(code == 0, f"`conversation start`: exit {code}: {err[-300:]!r}; it answers as it does at 15 seconds")
        answer = json.loads(out)
        conv = answer["conversation"]["conversation_id"]
        states = [o["state"] for o in answer["invites"]]
        check(states == ["inviting"], f"the invite outcomes: {answer['invites']}")
        running(a)
        people = [p for p in view_as(a, conv, state["alice_p"])["participants"]
                  if p.get("person_id") == state["bob_person"]]
        check(len(people) == 1 and people[0]["state"] in ("inviting", "invited"), f"bob after the restart: {people}")
    finally:
        running(a, b)


@suite.case("stop_route_add", "C6 Daemon stop: C2's add")
def _():
    need("bert", "bea")
    conv = start("bob/bert")
    b.stop()
    try:
        blocked = Blocked(a, "conversation", "add", conv, "bob/bea")
        signal_stop(a, signal.SIGINT)
        code, out, err = blocked.finish("`conversation add`")
        check(code == 0 and "inviting" in out, f"`conversation add`: exit {code}: {out[-300:]!r} {err[-300:]!r}")
    finally:
        running(a, b)


@suite.case("stop_route_join", "C6 Daemon stop: join answers its 503 unavailable")
def _():
    need("alice_p")
    conv = start("person:bob", join=False)
    a.stop()
    try:
        blocked = Blocked(b, "conversation", "join", conv)
        signal_stop(b, signal.SIGINT)
        code, _, err = blocked.finish("`conversation join`")
        check(code == 1 and "error: unavailable:" in err, f"`conversation join`: exit {code}: {err[-300:]!r}")
    finally:
        running(a, b)


suite.finish()
