#!/usr/bin/env python3
"""Slim suite 1b, join_teammate: a new person (a teammate) joins a network.

The full seven-stage join with its crash points and commit decline, and the ML-3/ML-4 join: the joiner's two
default-no prompts, the inviter's `link_request_waiting`, link-command exit status and `next`.

Written from docs/decentralized-spec.md sections 6, 8 and 16 and the wire appendix
(docs/decentralized-wire-formats.md sections 9, 10, 16 and 20.2), the exit status and `next` rules of
docs/machine-linking-transactions.md and docs/decentralized-runtime-contract.md section 6 (ML-3, ML-4) only.
"""
import base64
import json
import os
import pty
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
import traceback

from harness import (Failure, Result, Suite, attention, b64url_json, check, create_network, finalize, invite,
                     join_request, link_view, parse_time, pull_until, redact, select, ssh_key, ssh_public_base64,
                     wait_for, wait_linked)

suite = Suite("join_teammate", __doc__)
a, b = suite.host("alice"), suite.host("bob")
inviter, dave = suite.host("erin"), suite.host("dave")  # the two-prompt join's own inviter and joiner
state = {}


def need(*names):
    missing = [n for n in names if n not in state]
    check(not missing, f"an earlier case did not finish ({', '.join(missing)} missing)")
    return [state[n] for n in names]


def no_secret(text, code):
    return text.replace(code, "<code>") if code else text


# ML-3 and ML-4 (decision log, "ML-3 to ML-5: joining a teammate, step by step"): one interactive join of a new
# person carries the checks of spec 20 items 28 and 29, section 16's `link_request_waiting`, and the transactions
# contract's exit status and `next`. The flow records what it saw; each case below checks its own part.
PROMPT = re.compile(r"[\[(]y/N[\])]")
APPROVE_PROMPT, COMMIT_PROMPT = "Approve this exact machine?", "Commit this exact machine link?"
# The transactions contract: each `next` entry names who acts (owner, administrator or requester) and on which
# machine (this one, the joining machine, a machine of the person, or an administrator's machine).
WHO = re.compile(r"\b(owner|administrator|requester)\b", re.I)
WHERE = re.compile(r"\bthis (machine|one)\b|\bjoining machine\b|\bmachine of the person\b|\badministrator's machine\b",
                   re.I)
TERMINAL = ("linked", "cancelled", "expired")
seen = {"next": [], "notes": []}


class Terminal:
    """One CLI run with a terminal on stdin, answered prompt by prompt while it runs (stdout/stderr are pipes)."""

    def __init__(self, host, *args):
        self.host, self.args = host, list(map(str, args))
        self.master, slave = pty.openpty()
        self.p = subprocess.Popen([str(host.suite.host_bin), "--state", str(host.state), *self.args], stdin=slave,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=host.env,
                                  start_new_session=True, cwd=str(host.root))
        os.close(slave)
        self.lock, self.out, self.err, self.both = threading.Lock(), [], [], []  # both: in arrival order
        self.readers = [threading.Thread(target=self._read, args=(stream, sink), daemon=True)
                        for stream, sink in ((self.p.stdout, self.out), (self.p.stderr, self.err))]
        self.readers.append(threading.Thread(target=self._drain, daemon=True))  # the terminal's echo
        for t in self.readers:
            t.start()

    def _read(self, stream, sink):
        for chunk in iter(lambda: stream.read1(4096), b""):
            with self.lock:
                sink.append(chunk.decode(errors="replace"))
                self.both.append(sink[-1])

    def _drain(self):
        try:
            while os.read(self.master, 4096):
                pass
        except OSError:
            pass

    @property
    def text(self):
        with self.lock:
            return "".join(self.both)

    def prompts(self):
        """Each default-no question asked so far: the text of its line up to [y/N]."""
        text = self.text
        return [text[:m.end()].splitlines()[-1].strip() for m in PROMPT.finditer(text)]

    def wait_prompts(self, count, timeout):
        """Wait until COUNT questions were asked; False if the command exited first or time ran out."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if len(self.prompts()) >= count:
                return True
            if self.p.poll() is not None:
                time.sleep(0.3)  # let the readers catch up with the last output
                return len(self.prompts()) >= count
            time.sleep(0.2)
        return False

    def answer(self, line):
        os.write(self.master, (line + "\n").encode())

    def finish(self, timeout):
        try:
            self.p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(self.p.pid, signal.SIGKILL)
            self.p.wait()
        for t in self.readers[:2]:
            t.join(timeout=5)
        os.close(self.master)
        return Result(self.args, self.p.returncode, "".join(self.out), "".join(self.err))

    def tail(self):
        return redact(self.text.strip()[-400:])


def waiting_item(host, rid):
    """HOST's `link_request_waiting` attention item for request RID (spec 16; launch contract item shape)."""
    _, body = attention(host)
    for item in body.get("attention") or []:
        if item.get("kind") == "link_request_waiting" and any(
                rid in str(item.get(f) or "") for f in ("subject", "detail", "command")):
            return item
    return None


def no_command(item):
    return str(item.get("command") or "").strip() in ("", "-")


def sample_next(host, rid, where):
    """Record HOST's public view of RID: (where, host, state, next)."""
    view = link_view(host, rid)
    seen["next"].append((where, host.name, view["state"], view.get("next")))
    return view


def gone(name, why):
    return f"the join flow never reached {name}: {why}"


def two_prompt_join():
    """Spec 20 item 28 and 29 on a network of its own: erin invites, dave joins with one interactive `join`."""
    a, d = inviter, dave
    net = create_network(a, "join-teammate-ml", "erin")
    key = ssh_key(d.root, "dave")
    invitation = d.root / "invite"
    invitation.write_text(invite(a, "dave", net["id"])["invitation"] + "\n")
    invitation.chmod(0o600)
    # The pinned identity is given, so there is no identity choice (spec 8.1 step 2); --untrusted answers the
    # separate trust question up front, so only consent prompts remain.
    join = Terminal(d, "join", "--invite-file", invitation, "--person-key", key, "--untrusted")
    seen["join"] = join
    asked = join.wait_prompts(1, timeout=60)
    requests = [v for v in d.api("GET", "/v2/link/requests")[1] if v["role"] == "requester"]
    check(len(requests) == 1, f"dave holds {len(requests)} requester requests after join: {join.tail()}")
    rid = requests[0]["request_id"]
    seen["rid"] = rid
    # Before the joiner answers: the request reaches the inviter, whose status says it waits on the joining machine.
    try:
        seen["before"] = wait_for(lambda: waiting_item(a, rid), timeout=30, message="link_request_waiting on the inviter")
    except Failure as error:
        seen["notes"].append(f"before approval: {error}")
    sample_next(d, rid, "joiner, before owner approval")
    if any(v["request_id"] == rid for v in a.api("GET", "/v2/link/requests")[1]):
        sample_next(a, rid, "inviter, before owner approval")
    check(asked, f"join asked no question (exit {join.p.poll()}); want {APPROVE_PROMPT!r} right after the identity "
                 f"choice: {join.tail()}")
    check(APPROVE_PROMPT in join.prompts()[0],
          f"first question {join.prompts()[0]!r}, want {APPROVE_PROMPT!r}")
    join.answer("y")
    # After the owner approval and the automatic selection, the inviter's status gives the exact `link admit` command.
    try:
        item = wait_for(lambda: (lambda i: i if i and not no_command(i) else None)(waiting_item(a, rid)),
                        timeout=60, message="a command in the inviter's link_request_waiting")
        seen["after"] = item
    except Failure as error:
        seen["notes"].append(f"after approval: {error}")
        raise Failure(f"after the joiner approved, {error}; join so far: {join.tail()}") from None
    sample_next(d, rid, "joiner, after owner approval")
    sample_next(a, rid, "inviter, after owner approval")
    status = a.cli("link", "status", rid)  # the CLI's view of the same request
    seen["next"].append(("inviter's link status, after owner approval", a.name,
                         (status.json or {}).get("state", f"exit {status.code}, no JSON view"),
                         (status.json or {}).get("next")))
    argv = shlex.split(item["command"])
    check(argv[:3] == ["peerspan", "link", "admit"], f"the inviter's command is {item['command']!r}, want peerspan link admit")
    # A declined prompt exits nonzero and admits nothing (ML-3; spec 8.4): the interactive form of the command.
    interactive = [x for x in argv[1:] if x != "--approve"]
    seen["declined"] = a.cli(*interactive, tty=True, input="\n", timeout=90)
    seen["declined_view"] = link_view(a, rid)
    # Run exactly as given, answering its prompt.
    seen["admitted"] = a.cli(*argv[1:], tty=True, input="y\n", timeout=90)
    sample_next(a, rid, "inviter, after link admit")
    sample_next(d, rid, "joiner, after link admit")
    check(join.wait_prompts(2, timeout=120), f"join never asked {COMMIT_PROMPT!r} after admission "
                                             f"(exit {join.p.poll()}): {join.tail()}")
    sample_next(d, rid, "joiner, at commit")
    join.answer("y")
    result = join.finish(timeout=90)
    prompts = join.prompts()
    check(len(prompts) == 2 and APPROVE_PROMPT in prompts[0] and COMMIT_PROMPT in prompts[1],
          f"the joiner saw {len(prompts)} default-no prompts {prompts}, want exactly approve then commit")
    check(result.ok, f"join exited {result.code} after both yes answers: {redact(result.stderr.strip()[-300:])}")
    # The joiner runs nothing else: its daemon finishes on its own; the inviter may be nudged.
    wait_for(lambda: link_view(d, rid)["state"] == "linked", timeout=60, message="dave applying the request")
    wait_linked(a, rid)
    check(d.public_key in {m["host_public_key"] for m in a.api("GET", f"/v2/networks/{net['id']}/members")[1]["members"]},
          "the inviter does not list dave's host")
    seen["linked"] = True


def run_two_prompt_join():
    try:
        two_prompt_join()
    except BaseException as error:  # noqa: BLE001 - reported by the case below
        seen["error"] = error
        if not isinstance(error, Failure):
            traceback.print_exc(file=sys.stderr)


# The two-prompt join waits mostly on mailbox delivery between its own hosts, which share nothing with alice and
# bob, so it runs alongside join_new_person (each alone takes about a minute); the cases at the end wait for it
# and report what it saw. It is skipped only when --only names none of those cases.
ML_CASES = ("join_new_person_two_prompts", "inviter_status_names_whose_step", "link_step_done_exits_zero",
            "link_next_never_empty")
flow_thread = threading.Thread(target=run_two_prompt_join, daemon=True)
if not suite.args.only or set(ML_CASES) & set(suite.args.only):
    flow_thread.start()


@suite.case("create_network", "spec 6 (setup; the join suite checks creation itself)")
def _():
    net = create_network(a, "join-teammate", "alice")
    state["net"] = net
    check(net["authority"]["state"] == "usable", f"authority {net['authority']}")


@suite.case("join_new_person", "spec 8.1, 8.2, 8.4, 8.7; 20 items 28, 36, 37")
def _():
    (net,) = need("net")
    key = ssh_key(b.root, "bob")
    state["bob_key"] = key
    made = invite(a, "bob", net["id"])
    payload = json.loads(base64.b64decode(b64url_json(made["invitation"], "psi2-")["payload_base64"]))
    state["return_secret"] = payload.get("return_secret_base64")
    request = join_request(b, made["invitation"], key)
    rid, code = request["request_id"], request["display_code"]
    state["bob_request"] = request
    # The request should reach the inviter through the invite's return path, with no code (DEC-Q3).
    try:
        wait_for(lambda: any(v["request_id"] == rid for v in a.api("GET", "/v2/link/requests")[1]), timeout=5)
        state["returned"] = True
    except AssertionError:
        state["returned"] = False
    check(rid.startswith("link_") and request["mode"] == "new" and request["role"] == "requester", f"request {request}")
    window = (parse_time(request["expires_at"]) - parse_time(request["created_at"])).total_seconds()
    check(window == 3600, f"request window {window:.0f}s, want created_at + 3600")
    check(request["person_public_key"] == ssh_public_base64(key), "request names another person key")
    b.ok_incomplete("link", "approve", "--network", net["id"], "--person-key", key, "--code-stdin", "--approve",
                    input=code + "\n")
    view = pull_until(b, rid, "owner_offer_id")
    state["bob_single_offer_state"] = view["state"]
    if view["state"] == "needs_selection":
        select(b, view)
    b.restart(kill=True)  # crash after selection: the same request continues (8.7)
    view = link_view(b, rid)
    check(view["selection_id"].startswith("dpk_"), f"selection lost across a restart: {view['selection_id']}")
    a.ok_incomplete("link", "admit", "--network", net["id"], "--owner-offer", view["owner_offer_id"], "--selection",
                    view["selection_id"], "--person", view["person_public_key"], "--expect-host-key",
                    view["host_public_key"], "--expect-device-key", view["device_public_key"], "--code-stdin",
                    "--approve", input=code + "\n")
    a.restart(kill=True)  # crash after the administrator stage
    view = pull_until(b, rid, "administrator_offer_id")
    finalize(b, view, key)
    view = pull_until(b, rid, "owner_finalization_id")
    check(view["state"] == "needs_commit" and not view["commit_approved"], f"before commit: {view['state']}")
    # The one consent prompt: blank means no (8.4).
    declined = b.cli("link", "resume", rid, tty=True, input="\n", timeout=60)
    check(not declined.ok, "a blank answer at commit exited 0")
    check("Commit this exact machine link?" in declined.stderr + declined.stdout,
          f"no commit prompt: {no_secret(declined.stderr[-300:], code)}")
    view = link_view(b, rid)
    check(view["state"] == "needs_commit" and not view["commit_approved"], f"blank answer changed state: {view['state']}")
    check(b.api("GET", "/v2/networks")[1] == [], "a declined commit applied the network")
    accepted = b.cli("link", "resume", rid, tty=True, input="yes\n", timeout=60)
    check(accepted.ok, f"answering yes: exit {accepted.code}: {no_secret(accepted.stderr[-300:], code)}")
    wait_linked(b, a, rid)
    view = link_view(b, rid)
    check(view["completed"][-1] == "locally_applied" and view["activation_id"].startswith("da_"), f"linked {view}")
    members = {m["host_public_key"]: m for m in a.api("GET", f"/v2/networks/{net['id']}/members")[1]["members"]}
    check(b.public_key in members and members[b.public_key]["member"] == "bob", "alice does not list bob's host")
    check(members[b.public_key]["person_public_key"] == ssh_public_base64(key), "bob's host is bound to another person")
    networks = b.api("GET", "/v2/networks")[1]
    check(len(networks) == 1 and networks[0]["id"] == net["id"], f"bob's networks {networks}")
    check(networks[0]["authority"]["state"] == "usable", f"bob's authority {networks[0]['authority']}")
    check(networks[0]["provider"]["kind"] == "device" and networks[0]["provider"]["scopes"] == 7,
          f"bob's provider {networks[0]['provider']} (new person default scopes 7)")
    state["bob_joined"] = True


@suite.case("join_request_returns_without_code", "spec 8.1 step 4 (DEC-Q3); appendix 10.1; 20 item 29")
def _():
    secret, returned = need("return_secret", "returned")
    check(secret and len(base64.b64decode(secret)) == 16, "the invite payload carries no 16-byte return_secret_base64")
    check(returned, "the inviter never received the join request through the invite's return path; "
                    "join printed a psl2- code at once")


@suite.case("single_offer_selected_without_prompt", "spec 8.4 (DEC-S5, DEC-Q5); 20 item 34")
def _():
    (seen,) = need("bob_single_offer_state")
    check(seen != "needs_selection", "with exactly one owner offer the request still waited in needs_selection "
                                      "(link resume asks 'Select this exact owner offer?')")


def wait_flow():
    if flow_thread.ident is not None:
        flow_thread.join(timeout=360)
    check(flow_thread.ident is not None and not flow_thread.is_alive(),
          "the two-prompt join did not finish within 360 s")


@suite.case("join_new_person_two_prompts", "spec 8.1 step 5, 8.3, 8.4 (ML-4); 20 item 28")
def _():
    wait_flow()
    if "error" in seen:
        raise seen["error"]
    check(seen.get("linked"), "the two-prompt join stopped without linking")


@suite.case("inviter_status_names_whose_step", "spec 8.1 step 5, 16 link_request_waiting (ML-4); 20 item 29")
def _():
    wait_flow()
    check("rid" in seen, gone("the inviter's status", "the join created no request"))
    before = seen.get("before")
    check(before, f"the inviter's status never showed link_request_waiting for the new person's request before the "
                  f"joiner approved ({'; '.join(seen['notes'])})")
    check(no_command(before), f"before the joiner approved, the inviter's item gives a command: {before.get('command')!r}")
    check("joining" in str(before.get("detail") or "").lower(),
          f"before the joiner approved, the inviter's item does not say it waits on the joining machine: {before}")
    after = seen.get("after")
    check(after, gone("a link admit command in the inviter's status", "; ".join(seen["notes"]) or "see the case above"))
    admitted = seen.get("admitted")
    check(admitted is not None, gone("running the inviter's link admit command", "see the case above"))
    view = link_view(inviter, seen["rid"])
    check(admitted.ok and view["administrator_offer_id"] != "-",
          f"the inviter's command {redact(after['command'])!r}, run as given and answered yes: exit {admitted.code}, "
          f"administrator_offer_id {view['administrator_offer_id']}: {admitted.stderr.strip()[-300:]}")


@suite.case("link_step_done_exits_zero", "machine-linking transactions, exit status (ML-3); runtime contract 6")
def _():
    wait_flow()
    declined, admitted = seen.get("declined"), seen.get("admitted")
    check(declined is not None and admitted is not None, gone("the inviter's link admit", "see the cases above"))
    check(not declined.ok, f"a blank answer at link admit's prompt exited 0: {declined.stderr.strip()[-300:]}")
    check(seen["declined_view"]["administrator_offer_id"] == "-", "a declined link admit signed the admin offer")
    check(admitted.ok, f"link admit completed its own step (the request now waits on the joiner's commit) but "
                       f"exited {admitted.code}: {admitted.stderr.strip()[-300:]}")
    check("joining" in admitted.stderr.lower(),
          f"link admit does not say the next step is on the joining machine: {admitted.stderr.strip()[-300:]}")
    entries = (admitted.json or {}).get("next")
    check(entries, f"link admit's JSON view has an empty next: {admitted.json}")


@suite.case("link_next_never_empty", "machine-linking transactions, `next` (ML-3 fixes); runtime contract 5")
def _():
    wait_flow()
    check(seen["next"], gone("any public request view", "the join created no request"))
    bad = []
    for where, host, state, entries in seen["next"]:
        if state in TERMINAL:
            continue
        if not entries:
            bad.append(f"{where} ({host}, {state}): next {entries!r}")
            continue
        for entry in entries:
            if not (WHO.search(entry) and WHERE.search(entry)):
                bad.append(f"{where} ({host}, {state}): entry {entry!r} does not name who acts and on which machine")
    check(not bad, "; ".join(bad))


suite.finish()
