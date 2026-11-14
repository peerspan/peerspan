#!/usr/bin/env python3
"""Slim suite, peerbox_proposals: agent-proposed, owner-approved peerbox changes (peerbox Agent proposals, PBX-16 to
PBX-21).

alice creates a coordinator-free network, and bob and carol join as other people. alice's host is the home host of
two peerboxes on a Git fixture repository, made and shared with the CLI; its daemon runs with a `git` wrapper first on
its PATH that can hold a git command, so an approved proposal can be caught mid-execution. bob's host has a peerbox of
its own under bob's SSH person key, which signing needs. Fixture adapters on the hosts' adapter sockets propose through
`POST /adapter/v1/peerbox/proposals`; the real MCP adapter (claude-channel, no model) uses the five proposal tools; the
person decides with `approvals`, `approve` (on a pseudo-terminal) and `deny`. dan joins later with a code an approved
invite proposal gave the agent. The peerbox operations themselves are peerbox.py; the shared fixtures are
peerbox_common.py, peerbox_fixtures.py and runtime_common.py.

Not suite cases: a membership label holding control characters (the host refuses such a label in `invite`, so no
member can have one without a hand-signed membership statement), and the `branch` and invite `label` values with
control characters (Git refnames and `peerspan invite` labels cannot hold them, so such a proposal is refused at
Shape); the agent-supplied path and title and the repository identities carry the escapes instead.

Written from docs/peerbox-contract.md (cited as "peerbox <section>") and the per-call approval, agent tools and call
update sections of docs/capabilities-contract.md it reuses. No VM, no KVM, no model calls. Nothing in the Agent
proposals section is implemented yet: every case past the fixtures, the network and peerbox setup and the MCP session
is a strict expected failure.
"""
import json
import os
import re
import signal
import sys
from datetime import datetime, timedelta

from harness import Adapter, Suite, check, create_network, join_new_person, peer, rfc3339, ssh_key, \
    terminal_escaped, wait_for
from runtime_common import Channel, bind, learn, need, policy_version, run_side_by_side, state
from peerbox_fixtures import HOSTILE_AUTHOR, HOSTILE_COMMITTER, held_git, hostile_repo, owner_repo, proposal_check
from peerbox_common import (DEFAULT_BUNDLE, PSB1, Prompted, admit_waiting, commit_files, create, init_repo, op_ok,
                            owner_cli, principal, raw_op, rev, rules_for, settle, sha256, share, shown, tail, unshare)

suite = Suite("peerbox_proposals", __doc__)
bind(suite)
clock = suite.use_clock()
REASON = "peerbox agent proposals not implemented (peerbox contract, Agent proposals)"
PBP = re.compile(r"^pbp_[0-9a-f]{32}$")
RECORD_KEYS = {"proposal_id", "op", "args", "review", "request_sha256", "proposal_sha256", "origin", "state",
               "requested_at", "expires_at", "decided_at", "reason", "result", "error"}
VIEW_KEYS = RECORD_KEYS - {"origin", "request_sha256"} | {"note"}
ARGS = {"create": {"repository", "branch", "title", "network_id"},
        "share": {"peerbox_id", "principals", "actions", "max_bundle_bytes", "max_pending", "allow_disconnected"},
        "invite": {"peerbox_id", "label", "actions", "max_bundle_bytes", "max_pending", "expires_in_seconds"}}
TOOLS = {"peerbox_propose_create", "peerbox_propose_share", "peerbox_propose_invite", "peerbox_proposal_status",
         "peerbox_proposal_cancel"}
NEVER = "This was not done, and nothing was changed. Proposing again makes a new proposal."
NOTES = {"approved": "The person approved this; it is being carried out.",
         "failed": "The person approved this, but it could not be carried out (see error). Nothing was changed.",
         "denied": NEVER, "expired": NEVER, "cancelled": NEVER,
         "invite": "The invite was created. Give the code only to the person it is for, privately: whoever holds it "
                   "can ask to join the network and receive this access once an administrator admits them."}
PENDING_NOTE = ("The person must approve this in a terminal on this machine (peerspan approve {}); it has not been "
                "done, and you cannot approve it. Tell the person what you prepared and why. Its outcome arrives as a "
                "kind=peerbox_proposal_update event; peerbox_proposal_status reports it at any time. Do not propose "
                "it again.")
NO_FLAG = ("This session may not prepare peerbox changes. The person enables it with peerspan attach "
           "--peerbox-proposals.")
RECOVERY = "Nothing was proposed or recorded."
QUESTIONS = {"create": "Create this peerbox? [y/N] ", "share": "Sign a policy giving these people this access? [y/N] ",
             "invite": "Create this invite? Your agent will receive the code and choose who gets it. [y/N] "}
PROMPT = "Let this agent prepare peerbox changes (create, share, invite) for you to approve? [y/N] "
RAW_CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f]")  # anything an escaped display never prints raw
HOUR = 3600


def case(name, spec, known=REASON):
    return suite.case(name, spec, known=known)


def hide(text):
    return PSB1.sub("<code>", str(text))


# Credentials (peerbox Agent proposals, Who may propose).

def credential(host, name, proposals=True, agent=None):
    """A fixture adapter session for agent NAME (registered unless AGENT is given) whose credential has
    `peerbox_proposals` PROPOSALS, set up through POST /v1/adapters/setup and connected."""
    if agent is None:
        status, agent = host.api("POST", "/v1/agents", {"name": name, "owner": host.name})
        check(status in (200, 201), f"{host.name}: register {name}: {status} {agent}")
    session = "session_" + os.urandom(16).hex()
    body = {"agent_id": agent["id"], "session_id": session, "integration": "fixture", "directory": True,
            "expires_at": rfc3339(host.now() + timedelta(hours=12))}
    if proposals is not None:
        body["peerbox_proposals"] = proposals
    status, setup = host.api("POST", "/v1/adapters/setup", body)
    check(status == 201, f"{host.name}: adapter setup for {name} (peerbox_proposals {proposals}): {status} {setup}")
    adapter = Adapter(host, agent, session, setup["credential"])
    adapter.setup = setup
    adapter.connect()
    status, record = host.api("GET", f"/v1/adapters/{adapter.adapter_id}")
    want = bool(proposals)
    check(status == 200 and record.get("peerbox_proposals") is want
          and setup["credential"]["adapter"].get("peerbox_proposals") is want,
          f"{name}'s adapter record shows peerbox_proposals {record.get('peerbox_proposals')!r} (setup "
          f"{setup['credential']['adapter'].get('peerbox_proposals')!r}), want {want}")
    return adapter


# Proposing (peerbox Agent proposals, Adapter routes).

def new_pid():
    return "pbp_" + os.urandom(16).hex()


def propose(adapter, op, args, pid=None):
    pid = pid or new_pid()
    status, body = adapter.post("/adapter/v1/peerbox/proposals", {"proposal_id": pid, "op": op, "args": args})
    return status, body, pid


def canonical_sha(value):
    """SHA-256 of VALUE in the call view's result-text encoding (sorted keys, no whitespace, minimal escapes)."""
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())


def digest(view):
    """proposal_sha256: SHA-256 of {op, args, review} in the call view's result-text encoding (sorted keys, no
    whitespace, minimal string escapes, raw UTF-8)."""
    text = json.dumps({"op": view["op"], "args": view["args"], "review": view["review"]}, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False)
    return sha256(text.encode())


def check_view(view, pid, op, want_state):
    check(isinstance(view, dict) and set(view) == VIEW_KEYS, f"proposal view keys {sorted(view or {})}, want "
                                                             f"{sorted(VIEW_KEYS)}")
    check(view["proposal_id"] == pid and view["op"] == op and view["state"] == want_state
          and set(view["args"]) == ARGS[op] and view["proposal_sha256"] == digest(view),
          f"proposal view {hide(view)}, want {pid} {op} {want_state} with the digest of op, args and review")
    requested, expires = when(view["requested_at"]), when(view["expires_at"])
    check(expires - requested == timedelta(hours=1), f"expires_at {view['expires_at']} is not requested_at plus 1 hour")
    note = {"pending": PENDING_NOTE.format(pid), "executed": NOTES["invite"] if op == "invite" else None}.get(
        want_state, NOTES.get(want_state))
    check(view["note"] == note, f"{want_state} note {view['note']!r}, want {note!r}")
    check((view["decided_at"] is None) == (want_state == "pending"), f"decided_at {view['decided_at']} when "
                                                                     f"{want_state}")
    return view


def proposed(adapter, op, args, pid=None):
    """A proposal that must be accepted: its pending view."""
    status, view, pid = propose(adapter, op, args, pid)
    check(status == 200, f"propose {op} {hide(args)}: {status} {hide(view)}")
    return check_view(view, pid, op, "pending")


def invite_args(label, pbx=None, **extra):
    return {"peerbox_id": pbx or need("pbx")[0], "label": label, **extra}


def refused_and_absent(adapter, status, body, http, code, pid, field=None):
    """A refusal HTTP CODE (with `field` FIELD when given) that persisted nothing."""
    check(status == http and isinstance(body, dict) and body.get("code") == code
          and (field is None or body.get("field") == field),
          f"answer {status} {hide(body)}, want {http} {code}{f' with field {field}' if field else ''}")
    check(adapter.call("GET", f"/adapter/v1/peerbox/proposals/{pid}")[0] == 404, f"refused {pid} was persisted")
    check(state["a"].api("GET", f"/v1/peerbox-proposals/{pid}")[0] == 404, f"refused {pid} is on the owner API")


def when(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


# The person (peerbox Agent proposals, Approving).

def record(pid, host=None):
    status, body = (host or state["a"]).api("GET", f"/v1/peerbox-proposals/{pid}")
    check(status == 200 and isinstance(body, dict) and set(body) == RECORD_KEYS,
          f"GET /v1/peerbox-proposals/{pid}: {status} {hide(body)}")
    return body


def approve(pid, answer="y", key=None, host=None):
    """`approve PID` at a terminal (stdin a pseudo-terminal), answering ANSWER."""
    host = host or state["a"]
    extra = ["--person-key", key] if key else []
    return host.cli("--json", "approve", pid, *extra, tty=True, input=answer + "\n", timeout=150)


def approved(pid, key=None, host=None):
    """An approval that must execute: exit 0 and the executed record on stdout."""
    result = approve(pid, key=key, host=host)
    check(result.code == 0 and isinstance(result.json, dict) and result.json.get("state") == "executed",
          f"approve {pid}: exit {result.code} {hide(result.stdout[-300:])} {hide(tail(result.stderr))}")
    return result


def failed_approval(pid, code, key=None, host=None):
    """An approval whose execution fails with CODE: exit 1 and the failed record."""
    result = approve(pid, key=key, host=host)
    got = result.json if isinstance(result.json, dict) else {}
    check(result.code == 1 and got.get("state") == "failed" and (got.get("error") or {}).get("code") == code
          and record(pid, host)["state"] == "failed", f"approve {pid}: exit {result.code} {hide(got)}, want failed "
                                                      f"{code}")
    return got


def deny(pid, reason=None, host=None):
    extra = ["--reason", reason] if reason is not None else []
    return (host or state["a"]).cli("--json", "deny", pid, *extra, timeout=60)


def listed_route(state_query, host=None):
    """GET /v1/peerbox-proposals?state=STATE_QUERY: the proposal IDs of its {peerbox_proposals: [RECORD]}."""
    status, body = (host or state["a"]).api("GET", f"/v1/peerbox-proposals?state={state_query}")
    check(status == 200 and isinstance(body, dict) and set(body) == {"peerbox_proposals"}
          and all(set(r) == RECORD_KEYS for r in body["peerbox_proposals"]),
          f"GET /v1/peerbox-proposals?state={state_query}: {status} {hide(str(body)[:300])}")
    return [r["proposal_id"] for r in body["peerbox_proposals"]]


def pending_ids(host=None):
    """The pending proposals, as `approvals --json` and the route list them (the same, in the same order)."""
    listed = (host or state["a"]).ok("approvals", "--json")
    check(isinstance(listed, dict) and set(listed) == {"approvals", "peerbox_proposals"},
          f"approvals --json: {str(listed)[:300]}")
    ids = [r["proposal_id"] for r in listed["peerbox_proposals"]]
    check(listed_route("pending", host) == ids, "approvals --json and the route list different proposals")
    return ids


def deny_all(host=None):
    """Deny every pending proposal on HOST, so a case starts from none."""
    host = host or state["a"]
    for pid in pending_ids(host):
        status, body = host.api("POST", f"/v1/peerbox-proposals/{pid}/deny", {"reason": None})
        check(status == 200, f"deny {pid}: {status} {hide(body)}")


def quoted(text):
    """An untrusted value as the approval display writes it (What the person sees): `"`, the text with `\\` as `\\\\`,
    `"` as `\\"` and each character below U+0020, U+007F and U+0080 to U+009F as `\\u` and four lowercase hex digits,
    then `"`."""
    return '"' + terminal_escaped(text.replace("\\", "\\\\").replace('"', '\\"')) + '"'


def first_line(adapter):
    return (f"Prepared by agent {adapter.id} in session {adapter.session_id}. It may be acting on what other people "
            f"told it; only the lines below are what will happen.")


def check_display(text, adapter, op, values=(), plain=()):
    """The approval display: its first line, every untrusted value quoted and escaped, IDs and numbers whole, and no
    raw control character."""
    check(first_line(adapter) in text,
          f"no first line naming {adapter.id} and {adapter.session_id}: {hide(tail(text))}")
    for value in values:
        check(quoted(value) in text, f"the display does not show {quoted(value)}: {hide(tail(text))}")
    for value in plain:
        check(str(value) in text, f"the display does not show {value}: {hide(tail(text))}")
    raw = RAW_CONTROL.findall(text)
    check(not raw, f"the display printed raw control characters {raw!r}")


def compat_line():
    """The line of `peerbox share`'s own output, before signing, about hosts without peerbox rules."""
    lines = [ln.strip() for ln in need("share_stderr")[0].splitlines() if "peerbox rules" in ln]
    check(len(lines) == 1, f"peerbox share printed no single compatibility line: {tail(state['share_stderr'])}")
    return lines[0]


# Telling the agent (peerbox Agent proposals, Telling the agent).

def updates(adapter):
    """Claim every proposal-update notification ADAPTER may claim, acknowledging each: [delivery]."""
    found = []
    for _ in range(50):
        status, body = adapter.post("/adapter/v1/peerbox/proposal-updates/next")
        check(status == 200, f"{adapter.name}: proposal-updates/next: {status} {hide(body)}")
        if body is None:
            return found
        delivery = body.get("delivery") or {}
        check(set(body) == {"delivery", "proposal", "redelivered"} and PBP.match(str(delivery.get("proposal_id")))
              and body.get("redelivered") is False and isinstance(body["proposal"], dict)
              and set(body["proposal"]) == VIEW_KEYS and body["proposal"]["proposal_id"] == delivery["proposal_id"],
              f"a proposal-update claim {hide(body)}, want {{delivery, proposal (the view), redelivered}}")
        status, _ = adapter.post(f"/adapter/v1/peerbox/proposal-updates/{delivery['id']}/forwarded")
        check(status == 200, f"forwarded {delivery['id']}: {status}")
        found.append(delivery)
    raise AssertionError("more than 50 proposal-update notifications")


def tool(name, **arguments):
    answer = need("mia_channel")[0].call("tools/call", {"name": name, "arguments": arguments}, seconds=60)
    return answer, tool_json(answer)


def tool_json(answer):
    content = answer.get("content") or []
    try:
        return json.loads(content[0].get("text", "")) if content else None
    except ValueError:
        return content[0].get("text")


@suite.case("fixtures", "peerbox_fixtures.py: the proposal fixtures (hostile identities and path, the held git), "
                        "built host-free and checked; the quoting of What the person sees")
def _():
    print(f"  fixtures built and checked in {proposal_check(suite.work / 'fixture-check'):.1f}s", flush=True)
    want = '"a\\"b\\\\c\\u001b[2J\\u0007\\u007f\\u0085\\u009b\\u000ad"'
    got = quoted('a"b\\c\x1b[2J\x07\x7f\x85\x9b\nd')
    check(got == want, f"quoted() gives {got!r}, want {want!r}")


def learn_all():
    version = policy_version(state["a"], state["alice_public"])
    for host in state["learners"]:
        learn(host, state["alice_public"], version)
    return version


@suite.case("setup", "decentralized-spec 6, 8 (create, join); peerbox CLI and local API: create and share (slice A)")
def _():
    held, flag = held_git(suite.work / "held-git")
    a = suite.host("alice", start=False)
    a.extra_env["PATH"] = f"{held}:{os.environ.get('PATH', '/usr/bin:/bin')}"
    a.start()
    b, c = suite.host("bob"), suite.host("carol")
    state.update(a=a, b=b, c=c, hold=flag)
    net = state["net"] = create_network(a, "proposals", "alice")["id"]
    state["alice_public"] = a.api("GET", f"/v2/networks/{net}")[1]["person_public_key"]
    state["alice_key"] = a.home / ".config/peerspan/person_ed25519"
    state["bob_key"], state["carol_key"] = ssh_key(b.root, "bob"), ssh_key(c.root, "carol")
    run_side_by_side((join_new_person, (a, b, "bob", state["bob_key"], net), {}),
                     (join_new_person, (a, c, "carol", state["carol_key"], net), {}))
    for who, host in (("alice", a), ("bob", b), ("carol", c)):
        state[f"{who}_pid"] = host.ok("person", "show", "--person-key", state[f"{who}_key"])["person_id"]
        state[f"{who}_p"] = principal(state[f"{who}_pid"])
    state["bob_public"] = b.api("GET", f"/v2/networks/{net}")[1]["person_public_key"]
    b.ok("allow", "alice", "--person-key", state["bob_key"])
    state["learners"] = [b, c]
    for host in state["learners"]:
        learn(host, state["alice_public"], policy_version(a, state["alice_public"]))
    learn(a, state["bob_public"], policy_version(b, state["bob_public"]))
    stranger = ssh_key(suite.work, "stranger")  # a person who is no member
    state["stranger_p"] = principal(a.ok("person", "show", "--person-key", stranger)["person_id"])
    owner = owner_repo(suite.work / "alice-repo")
    state.update(repo=owner["repo"], main=owner["main"])
    state["pbx"] = create(owner["repo"], title="proposals")
    state["pbx_rc"] = create(owner["repo"], title="changes")
    result = owner_cli("share", state["pbx_rc"], "--for", state["bob_p"], "--person-key", state["alice_key"])
    state["share_stderr"] = result.stderr  # holds the compatibility line `peerbox share` prints before signing
    print(f"  compatibility line: {compat_line()!r}", flush=True)
    learn_all()
    brepo = init_repo(suite.work / "bob-repo")
    commit_files(brepo, {"tool.sh": "echo tool\n"}, "tool")
    state["bpbx"] = create(brepo, host=b, title="bob's tools")


@suite.case("mcp_session", "runtime_common.Channel: the claude-channel MCP adapter on a session of alice's agent nomi, "
                           "set up without peerbox_proposals")
def _():
    a = need("a")[0]
    status, agent = a.api("POST", "/v1/agents", {"name": "nomi", "owner": "alice"})
    check(status in (200, 201), f"register nomi: {status} {agent}")
    status, setup = a.api("POST", "/v1/adapters/setup", {
        "agent_id": agent["id"], "session_id": "session_" + os.urandom(16).hex(), "integration": "claude-channel",
        "expires_at": rfc3339(a.now() + timedelta(hours=12))})
    check(status == 201, f"adapter setup for nomi: {status} {setup}")
    state["nomi_setup"] = setup
    state["nomi_channel"] = Channel(a, setup, suite.work / "mcp-nomi")


@case("credential_flag", "peerbox Agent proposals, Who may propose: peerbox_proposals on POST /v1/adapters/setup and "
                         "the adapter record, default false; 403 no_peerbox_proposals on every route without it, a "
                         "peerbox route giving none")
def _():
    a, b = need("a", "b")
    status, record = a.api("GET", f"/v1/adapters/{need('nomi_setup')[0]['credential']['adapter']['id']}")
    check(status == 200 and record.get("peerbox_proposals") is False, f"a setup without the flag: {status} {record}")
    nox = credential(a, "nox", proposals=None)
    added = a.cli("adapter", "route", "add", "--adapter", nox.adapter_id, "--name", "pb", "--peer", b.id, "--action",
                  "peerbox.read", "--expires-in", "1h")
    check(added.ok, f"nox's peerbox.read route: {tail(added.stderr)}")
    pid = new_pid()
    for method, path, body in (
            ("POST", "/adapter/v1/peerbox/proposals", {"proposal_id": pid, "op": "invite", "args": invite_args("x")}),
            ("GET", f"/adapter/v1/peerbox/proposals/{pid}", None),
            ("POST", f"/adapter/v1/peerbox/proposals/{pid}/cancel", {}),
            ("POST", "/adapter/v1/peerbox/proposal-updates/next", {}),
            ("POST", f"/adapter/v1/peerbox/proposal-updates/notification_{'0' * 32}/forwarded", {})):
        status, answer = nox.call(method, path, body)
        check(status == 403 and isinstance(answer, dict) and answer.get("code") == "no_peerbox_proposals"
              and isinstance(answer.get("error"), str), f"{method} {path} without the flag: {status} {answer}")
    check(a.api("GET", f"/v1/peerbox-proposals/{pid}")[0] == 404, "a refused proposal was recorded")
    state["pia"] = credential(a, "pia")
    state["pia2"] = credential(a, "pia", agent=state["pia"].agent)  # a second credential of the same agent
    state["oth"] = credential(a, "oth")
    state["bia"] = credential(b, "bia")
    state["nox"] = nox


@case("attach_flag", "peerbox Agent proposals, Who may propose: attach --peerbox-proposals and "
                     "--no-peerbox-proposals with the prompt, terminal and re-attach rules of --calls (capabilities "
                     "Opt-in at attach)")
def _():
    a = need("a")[0]
    bundles = suite.work / "integrations"
    (bundles / "pbprop").mkdir(parents=True, exist_ok=True)
    (bundles / "pbprop" / "helper.py").write_text(
        "import json, sys\njson.load(sys.stdin)\nprint(json.dumps({'version': 1, 'checks': [{'name': 'fixture', "
        "'status': 'ok', 'detail': 'ok'}]}))\n")
    (bundles / "pbprop" / "integration.json").write_text(json.dumps({
        "version": 1, "id": "pbprop", "command": [sys.executable, "./helper.py"], "operations": ["prepare", "check"]}))

    def attach(project, *extra, tty=False, answer=""):
        directory = suite.work / "projects" / project
        directory.mkdir(parents=True, exist_ok=True)
        return a.cli("--json", "attach", "pbprop", "--integrations", bundles, "--directory", directory, "--name",
                     project, "--no-calls", *extra, tty=tty, input=answer, timeout=90)

    def flag(result, label):
        check(result.ok and isinstance(result.json, dict),
              f"attach ({label}): exit {result.code} {tail(result.stderr)}")
        status, record = a.api("GET", f"/v1/adapters/{result.json['adapter_id']}")
        check(status == 200 and result.json.get("peerbox_proposals") is record.get("peerbox_proposals"),
              f"attach output ({label}) peerbox_proposals {result.json.get('peerbox_proposals')!r}, record "
              f"{status} {record.get('peerbox_proposals')!r}")
        return record.get("peerbox_proposals")

    check(flag(attach("pp-yes", "--peerbox-proposals"), "--peerbox-proposals") is True, "--peerbox-proposals")
    check(flag(attach("pp-no", "--no-peerbox-proposals"), "--no-peerbox-proposals") is False, "--no-peerbox-proposals")
    quiet = attach("pp-pipe")
    check(flag(quiet, "no terminal") is False and PROMPT not in quiet.stderr, "without a terminal the answer is no")
    asked = attach("pp-tty-y", tty=True, answer="y\n")
    check(PROMPT in asked.stderr and flag(asked, "y at the prompt") is True, f"the prompt: {tail(asked.stderr)}")
    asked = attach("pp-tty-n", tty=True, answer="\n")
    check(PROMPT in asked.stderr and flag(asked, "empty answer") is False, "an empty answer is no")
    both = attach("pp-both", "--peerbox-proposals", "--no-peerbox-proposals")
    check(both.code == 1, f"both flags: exit {both.code}")
    check(attach("pp-both", "--no-peerbox-proposals").json.get("reused") is False,
          "the refused attach set something up")
    differ = attach("pp-yes", "--no-peerbox-proposals")
    check(differ.code == 1 and "peerbox" in differ.stderr, f"a differing flag on re-attach: exit {differ.code} "
                                                           f"{tail(differ.stderr)}")
    again = attach("pp-yes", "--peerbox-proposals")
    check(again.ok and again.json.get("reused") is True and flag(again, "a matching flag") is True,
          "a matching flag on re-attach")
    kept = attach("pp-yes", tty=True, answer="n\n")
    check(kept.ok and kept.json.get("reused") is True and PROMPT not in kept.stderr
          and flag(kept, "no flag on re-attach") is True,
          "re-attaching with no flag asks nothing and keeps the setting")


@case("mcp_tools", "peerbox Agent proposals, MCP tools: the five tools listed whatever the credential; "
                   "no_peerbox_proposals with its exact text; propose, status, cancel; not_recorded; "
                   "additionalProperties")
def _():
    a = need("a")[0]
    nomi = need("nomi_channel")[0]
    names = {t["name"] for t in nomi.call("tools/list", {})["tools"]}
    check(TOOLS <= names, f"tools missing without the flag: {sorted(TOOLS - names)}")
    for t in nomi.call("tools/list", {})["tools"]:
        if t["name"] in TOOLS:
            check(t["inputSchema"].get("additionalProperties") is False, f"{t['name']} allows other properties")
    pid = new_pid()
    answer = nomi.call("tools/call", {"name": "peerbox_propose_invite", "arguments": {
        "peerbox_id": need("pbx")[0], "label": "nomi", "proposal_id": pid}})
    check(answer.get("isError") and tool_json(answer) == {"proposal_id": pid, "code": "no_peerbox_proposals",
                                                          "error": NO_FLAG, "recovery": RECOVERY},
          f"a proposal without the flag: {tool_json(answer)}")
    status, agent = a.api("POST", "/v1/agents", {"name": "mia", "owner": "alice"})
    check(status in (200, 201), f"register mia: {status} {agent}")
    session = "session_" + os.urandom(16).hex()
    status, setup = a.api("POST", "/v1/adapters/setup", {
        "agent_id": agent["id"], "session_id": session, "integration": "claude-channel", "peerbox_proposals": True,
        "expires_at": rfc3339(a.now() + timedelta(hours=12))})
    check(status == 201 and setup["credential"]["adapter"].get("peerbox_proposals") is True,
          f"adapter setup for mia with the flag: {status} {setup}")
    state["mia_channel"] = Channel(a, setup, suite.work / "mcp-mia")
    mia = Adapter(a, agent, session, setup["credential"])
    answer, view = tool("peerbox_propose_invite", peerbox_id=need("pbx")[0], label="mia")
    check(not answer.get("isError") and isinstance(view, dict), f"peerbox_propose_invite: {hide(view)}")
    pid = view["proposal_id"]
    check_view(view, pid, "invite", "pending")
    check(view["args"] == {"peerbox_id": need("pbx")[0], "label": "mia", "actions": ["read"],
                           "max_bundle_bytes": DEFAULT_BUNDLE, "max_pending": 0, "expires_in_seconds": 3600}
          and view["review"] == {"title": "proposals", "network_id": need("net")[0]},
          f"the invite's args and review: {view['args']} {view['review']}")
    check(record(pid)["origin"] == {"adapter_id": mia.adapter_id, "agent_id": mia.id, "session_id": session},
          f"origin {record(pid)['origin']}")
    answer, again = tool("peerbox_proposal_status", proposal_id=pid)
    check(not answer.get("isError") and again == view, f"peerbox_proposal_status: {hide(again)}")
    result = deny(pid, reason="not now")
    check(result.ok, f"deny {pid}: exit {result.code} {tail(result.stderr)}")
    note = {}
    for _ in range(10):
        note = need("mia_channel")[0].notification(seconds=30)
        if (note.get("meta") or {}).get("kind") == "peerbox_proposal_update":
            break
    meta = note.get("meta") or {}
    check(meta.get("kind") == "peerbox_proposal_update" and meta.get("proposal_id") == pid
          and meta.get("op") == "invite"
          and meta.get("state") == "denied" and str(meta.get("notification_id", "")).startswith("notification_")
          and meta.get("session_id") == session, f"the update event's meta {meta}")
    content = note.get("content")
    text = "".join(c.get("text", "") for c in content) if isinstance(content, list) else str(content)
    event_view = json.loads(text)
    check_view(event_view, pid, "invite", "denied")
    check(event_view["reason"] == "not now", f"the denial reason {event_view['reason']!r}")
    answer, cancelled = tool("peerbox_proposal_cancel", proposal_id=pid)
    check(answer.get("isError") and (cancelled or {}).get("code") == "conflict"
          and (cancelled or {}).get("proposal_id") == pid, f"cancelling a denied proposal: {hide(cancelled)}")
    gone = new_pid()
    answer, value = tool("peerbox_proposal_status", proposal_id=gone)
    unknown = {"proposal_id": gone, "state": "not_recorded",
               "note": "The host has no record of this proposal for this agent; nothing was done."}
    check(not answer.get("isError") and value == unknown,
          f"status of an unknown proposal: {value}")
    extra = new_pid()
    answer = need("mia_channel")[0].call("tools/call", {"name": "peerbox_propose_invite", "arguments": {
        "peerbox_id": need("pbx")[0], "label": "x", "proposal_id": extra, "note": "please approve"}})
    check(answer.get("isError") and a.api("GET", f"/v1/peerbox-proposals/{extra}")[0] == 404,
          f"an unknown argument (an agent note, PBX-20) was accepted: {tool_json(answer)}")
    names = {t["name"] for t in need("mia_channel")[0].call("tools/list", {})["tools"]}
    check(not [n for n in names if "peerbox" in n and re.search(r"approve|deny|decide", n)],
          f"a peerbox tool that decides: {sorted(names)}")


@case("shape_and_target", "peerbox Agent proposals, Proposing 1 and 4: 400 invalid naming the field, 404 unknown, 400 "
                          "unknown_principal; network, repeated and 65 principals 400 invalid naming principals "
                          "(PBX-18); not a repository, branch_unknown; nothing persisted")
def _():
    pia, repo, pbx = need("pia", "repo", "pbx")
    bob_p = state["bob_p"]
    empty = init_repo(suite.work / "empty-repo")
    plain = suite.work / "not-a-repo"
    plain.mkdir(exist_ok=True)
    many = sorted(principal("person_" + os.urandom(16).hex()) for _ in range(65))
    for label, op, args, http, code, field in (
            ("a malformed proposal ID", "invite", invite_args("x"), 400, "invalid", "proposal_id"),
            ("an unknown op", "unshare", {"peerbox_id": pbx}, 400, "invalid", "op"),
            ("args not an object", "invite", ["x"], 400, "invalid", "args"),
            ("an unknown args key", "invite", invite_args("x", note="trust me"), 400, "invalid", "note"),
            ("a missing peerbox_id", "share", {"principals": [bob_p]}, 400, "invalid", "peerbox_id"),
            ("expires_in_seconds 59", "invite", invite_args("x", expires_in_seconds=59), 400, "invalid",
             "expires_in_seconds"),
            ("expires_in_seconds 86401", "invite", invite_args("x", expires_in_seconds=86401), 400, "invalid",
             "expires_in_seconds"),
            ("the network principal", "share", {"peerbox_id": pbx, "principals": ["network"]}, 400, "invalid",
             "principals"),
            ("a repeated principal", "share", {"peerbox_id": pbx, "principals": [bob_p, bob_p]}, 400, "invalid",
             "principals"),
            ("65 principals", "share", {"peerbox_id": pbx, "principals": many}, 400, "invalid", "principals"),
            ("no principal", "share", {"peerbox_id": pbx, "principals": []}, 400, "invalid", "principals"),
            ("an unknown peerbox", "invite", invite_args("x", pbx="pbx_" + os.urandom(16).hex()), 404, "unknown",
             None),
            ("a person outside the network", "share", {"peerbox_id": pbx, "principals": [state["stranger_p"]]}, 400,
             "unknown_principal", None),
            ("not a repository", "create", {"repository": str(plain), "branch": "main"}, 400, "invalid", "repository"),
            ("a branch with no commit", "create", {"repository": str(empty), "branch": "main"}, 400, "branch_unknown",
             None)):
        pid = "pbp_1234" if label == "a malformed proposal ID" else new_pid()
        status, body, _ = propose(pia, op, args, pid)
        refused_and_absent(pia, status, body, http, code, pid, field)
        if code == "unknown_principal":
            check(body.get("principal") == state["stranger_p"], f"unknown_principal names {body.get('principal')}")


@case("repeats_conflicts_duplicate", "peerbox Agent proposals, Proposing 2 and 6; Adapter routes (scope): the same "
                                     "view for a repeat of the body as sent (request_sha256), 409 conflict, 409 "
                                     "duplicate; another credential of the agent reads it, another agent gets 404; "
                                     "principals given out of order stored sorted by UTF-8 bytes")
def _():
    pia, pia2, oth = need("pia", "pia2", "oth")
    args = invite_args("repeat")
    view = proposed(pia, "invite", args)
    pid = view["proposal_id"]
    status, again, _ = propose(pia, "invite", args, pid)
    check(status == 200 and again == view, f"an identical repeat: {status} {hide(again)}")
    status, again, _ = propose(pia2, "invite", args, pid)
    check(status == 200 and again == view, f"a repeat through the agent's other credential: {status} {hide(again)}")
    status, body, _ = propose(pia, "invite", invite_args("other"), pid)
    check(status == 409 and body.get("code") == "conflict", f"the same ID, other args: {status} {hide(body)}")
    status, body, _ = propose(oth, "invite", args, pid)
    check(status == 409 and body.get("code") == "conflict", f"the same ID from another agent: {status} {hide(body)}")
    status, body, dup = propose(pia, "invite", args)
    refused_and_absent(pia, status, body, 409, "duplicate", dup)
    check(body.get("proposal_id") == pid, f"duplicate names {body.get('proposal_id')}, want {pid}")
    status, body, _ = propose(pia2, "invite", args)
    check(status == 409 and body.get("code") == "duplicate", f"a duplicate through the other credential: {status}")
    check(proposed(oth, "invite", args)["proposal_sha256"] == view["proposal_sha256"],
          "another agent's identical proposal")
    check(pia2.call("GET", f"/adapter/v1/peerbox/proposals/{pid}") == (200, view), "the other credential's view")
    check(oth.call("GET", f"/adapter/v1/peerbox/proposals/{pid}")[0] == 404, "another agent reads the proposal")
    check(oth.post(f"/adapter/v1/peerbox/proposals/{pid}/cancel")[0] == 404, "another agent cancels the proposal")
    people = sorted([state["bob_p"], state["carol_p"]], key=lambda p: p.encode())
    given = {"peerbox_id": need("pbx")[0], "principals": people[::-1], "actions": ["submit", "read"]}
    shared = proposed(pia, "share", given)
    check(shared["args"]["principals"] == people and shared["args"]["actions"] == ["read", "submit"]
          and [x["principal"] for x in shared["review"]["people"]] == people,
          f"principals and actions given out of order are stored sorted: {shared['args']} {shared['review']['people']}")
    spid = shared["proposal_id"]
    check(record(spid)["request_sha256"] == canonical_sha({"proposal_id": spid, "op": "share", "args": given}),
          "request_sha256 is not the digest of the body as sent")
    status, again, _ = propose(pia, "share", given, spid)
    check(status == 200 and again == shared, f"a repeat of the body as sent: {status} {hide(again)}")
    status, again, _ = propose(pia, "share", dict(given, principals=people, actions=["read", "submit"]), spid)
    check(status == 409 and again.get("code") == "conflict",
          f"a repeat whose body differs, though equal once normalized: {status} {hide(again)}")
    repo = init_repo(suite.work / "retry-repo")
    commit_files(repo, {"r.txt": "r\n"}, "retry")
    retry = {"repository": str(repo), "branch": "main"}  # no network_id: the host's only network
    state["retry"] = (proposed(pia, "create", retry), retry)
    check(record(pid)["state"] == "pending", "the proposal after another agent's attempts")
    deny_all()


@case("create_executed", "peerbox Agent proposals: create proposed through a symbolic link (args made absolute and "
                         "resolved, title defaulted), review the disclosure, listed by approvals, approved at a "
                         "terminal, executed, provenance in peerbox show; approving twice changes nothing")
def _():
    a, pia, net = need("a", "pia", "net")
    repo = init_repo(suite.work / "create-repo")
    commit_files(repo, {"a.txt": "a\n"}, "one")
    head = commit_files(repo, {"b.txt": "b\n"}, "two")
    link = suite.work / "create-link"
    link.symlink_to(repo)
    view = proposed(pia, "create", {"repository": str(link), "branch": "main"})
    pid = view["proposal_id"]
    check(view["args"] == {"repository": str(repo.resolve()), "branch": "main", "title": "create-repo",
                           "network_id": net}, f"create args {view['args']}")
    review = view["review"]
    check(set(review) == {"head", "commits", "identities", "identities_total", "bundle_bytes"}
          and review["head"] == head and review["commits"] == 2 and review["identities_total"] == 2
          and review["identities"] == [{"name": "Ada Author", "email": "ada@example.test"},
                                       {"name": "Cy Committer", "email": "cy@example.test"}]
          and isinstance(review["bundle_bytes"], int) and review["bundle_bytes"] > 0, f"create review {review}")
    readable = a.cli("approvals")
    check(pid in pending_ids() and pid in readable.stdout + readable.stderr, "approvals does not list the proposal")
    check(pid not in json.dumps(a.api("GET", "/v1/approvals")[1]), "GET /v1/approvals lists a proposal")
    shown_text = a.cli("approvals", "show", pid)
    check(shown_text.ok, f"approvals show: exit {shown_text.code}")
    check_display(shown_text.stdout + shown_text.stderr, pia, "create",
                  values=(str(repo.resolve()), "main", "Ada Author", "ada@example.test", "Cy Committer"),
                  plain=(head, net, review["bundle_bytes"]))
    before = {r["peerbox_id"] for r in shown()}
    result = approved(pid)
    check_display(result.stderr, pia, "create", plain=(head,))
    check(QUESTIONS["create"].rstrip() in result.stderr, f"the create question: {tail(result.stderr)}")
    made = result.json["result"]
    after = [r for r in shown() if r["peerbox_id"] not in before]
    check(set(made) == {"peerbox_id"} and [r["peerbox_id"] for r in after] == [made["peerbox_id"]]
          and after[0].get("proposal_id") == pid and after[0]["title"] == "create-repo",
          f"the created peerbox {made} {after}")
    check(all("proposal_id" in r and r["proposal_id"] is None for r in shown() if r["peerbox_id"] == need("pbx")[0]),
          "a peerbox the person created does not show proposal_id null")
    check_view(pia.call("GET", f"/adapter/v1/peerbox/proposals/{pid}")[1], pid, "create", "executed")
    twice = approve(pid)
    status, body = a.api("POST", f"/v1/peerbox-proposals/{pid}/approve", {"proposal_sha256": view["proposal_sha256"],
                                                                          "person_key": None})
    check(twice.code == 1 and status == 409 and body.get("code") == "conflict"
          and body["proposal"]["state"] == "executed"
          and len(shown()) == len(before) + 1, f"approving twice: exit {twice.code}, {status} {hide(body)}")
    check(pid in json.dumps(a.ok("approvals", "--all", "--json")["peerbox_proposals"]) and pid not in pending_ids()
          and pid in listed_route("all"), "approvals --all lists the decided proposal, approvals does not")
    check(a.api("GET", "/v1/peerbox-proposals?state=decided")[0] == 400, "an unknown state query")


@case("share_executed", "peerbox Agent proposals: share proposed with defaults filled in, the people and before "
                        "access reviewed, the compatibility line, signed on approval with the person key; result "
                        "policy_version; nothing signed when the access is already held")
def _():
    a, b, pia, pbx = need("a", "b", "pia", "pbx")
    view = proposed(pia, "share", {"peerbox_id": pbx, "principals": [state["bob_p"]], "actions": ["read", "submit"]})
    pid = view["proposal_id"]
    check(view["args"] == {"peerbox_id": pbx, "principals": [state["bob_p"]], "actions": ["read", "submit"],
                           "max_bundle_bytes": DEFAULT_BUNDLE, "max_pending": 4, "allow_disconnected": False},
          f"share args {view['args']}")
    check(view["review"] == {"title": "proposals", "network_id": need("net")[0], "people": [
        {"principal": state["bob_p"], "person_id": state["bob_pid"], "label": "bob"}], "before": [None]},
          f"share review {view['review']}")
    version = policy_version(a, state["alice_public"])
    result = approved(pid, key=state["alice_key"])
    check_display(result.stderr, pia, "share", values=("bob",), plain=(state["bob_pid"], compat_line()))
    check(QUESTIONS["share"].rstrip() in result.stderr, f"the share question: {tail(result.stderr)}")
    signed = result.json["result"]
    check(signed == {"policy_version": version + 1} and policy_version(a, state["alice_public"]) == version + 1,
          f"share result {signed}, version {policy_version(a, state['alice_public'])}")
    rules = rules_for(pbx, state["bob_p"])
    check(len(rules) == 1 and rules[0]["actions"] == ["peerbox.read", "peerbox.submit"]
          and rules[0]["max_pending"] == 4,
          f"bob's rule {rules}")
    learn_all()
    listed, _, _ = op_ok({"op": "list"}, sender=b)
    check(pbx in [p["peerbox_id"] for p in listed["peerboxes"]], f"bob does not list {pbx}")
    same = proposed(pia, "share", {"peerbox_id": pbx, "principals": [state["bob_p"]], "actions": ["read", "submit"]})
    check(same["review"]["before"] == [{"actions": ["read", "submit"], "max_bundle_bytes": DEFAULT_BUNDLE,
                                        "max_pending": 4, "allow_disconnected": False}],
          f"before, as the access now is: {same['review']['before']}")
    check(approved(same["proposal_id"], key=state["alice_key"]).json["result"] == {"policy_version": version + 1}
          and policy_version(a, state["alice_public"]) == version + 1, "an unchanged access was signed again")


@case("invite_executed_and_join", "peerbox Agent proposals: invite approved and executed; the psb1- code reaching the "
                                  "agent with its note; provenance in invite --list; dan joining with it as peerbox "
                                  "join does, his rule signed with the proposal's access")
def _():
    a, pia, pbx, net = need("a", "pia", "pbx", "net")
    view = proposed(pia, "invite", invite_args("dan", actions=["read", "submit"], max_pending=2))
    pid = view["proposal_id"]
    result = approved(pid)
    check_display(result.stderr, pia, "invite", values=("dan",), plain=(pbx, net))
    check(QUESTIONS["invite"].rstrip() in result.stderr, "the invite question")
    made = result.json["result"]
    check(set(made) == {"code", "invitation_id", "expires_at"} and PSB1.fullmatch(made["code"] or "")
          and abs((when(made["expires_at"]) - a.now()).total_seconds() - 3600) < 120,
          f"the invite result {hide(made)}")
    status, seen = pia.call("GET", f"/adapter/v1/peerbox/proposals/{pid}")
    check(status == 200 and seen["result"] == made, "the agent's view lacks the code")
    check_view(seen, pid, "invite", "executed")
    listed = owner_cli("invite", "--list").stdout
    check(made["invitation_id"] in listed and pid in listed, "invite --list does not show the proposal's pending share")
    d = state["d"] = suite.host("dan")
    key = ssh_key(d.root, "dan")
    run = Prompted(d, "--json", "peerbox", "join", "--invite-stdin", "--repository", d.root / "repo", "--as", "dan",
                   "--person-key-file", key, first_line=made["code"])
    admit_waiting(a, d)
    check(run.wait(240) == 0, f"peerbox join: {hide(tail(run.text))}")
    dan = principal(d.ok("person", "show", "--person-key", key)["person_id"])
    found = wait_for(lambda: rules_for(pbx, dan), timeout=60, message="dan's rule")
    check(len(found) == 1 and found[0]["actions"] == ["peerbox.read", "peerbox.submit"]
          and found[0]["max_pending"] == 2,
          f"dan's rule {found}")
    check(rev(d.root / "repo", f"refs/peerbox/{pbx}/main") == state["main"], "dan's peerbox join fetched nothing")


@case("approve_refusals", "peerbox Agent proposals, Approving: approve without a terminal, declined at the prompt, a "
                          "wrong digest (409 proposal_changed), an unknown ID (404), a reason over 1,024 bytes (400); "
                          "the proposal stays pending")
def _():
    a, pia = need("a", "pia")
    view = proposed(pia, "invite", invite_args("refusals"))
    pid = view["proposal_id"]
    plain = a.cli("approve", pid)
    check(plain.code == 1 and "peerspan approve needs a terminal: approval must come from the person." in plain.stderr,
          f"approve without a terminal: exit {plain.code} {tail(plain.stderr)}")
    no = approve(pid, answer="n")
    check(no.code == 1 and QUESTIONS["invite"].rstrip() in no.stderr, f"declining: exit {no.code}")
    status, body = a.api("POST", f"/v1/peerbox-proposals/{pid}/approve", {"proposal_sha256": "0" * 64,
                                                                          "person_key": None})
    check(status == 409 and body.get("code") == "proposal_changed", f"a wrong digest: {status} {hide(body)}")
    check(a.api("POST", f"/v1/peerbox-proposals/{new_pid()}/approve",
                {"proposal_sha256": view["proposal_sha256"], "person_key": None})[0] == 404, "an unknown ID")
    status, body = a.api("POST", f"/v1/peerbox-proposals/{pid}/deny", {"reason": "x" * 1025})
    check(status == 400, f"a reason over 1,024 bytes: {status} {body}")
    check(record(pid)["state"] == "pending" and pid in pending_ids(), "the refusals changed the proposal")
    check(not [r for r in shown() if r.get("proposal_id") == pid], "a refusal created a peerbox")
    deny(pid)


@case("deny_and_cancel", "peerbox Agent proposals: deny with a reason and without a terminal, cancel, each changing "
                         "nothing; 409 conflict for cancel, approve and deny after; the denied and cancelled notes")
def _():
    a, pia, pbx = need("a", "pia", "pbx")
    version, boxes, invites = policy_version(a, state["alice_public"]), shown(), owner_cli("invite", "--list").stdout
    share_view = proposed(pia, "share", {"peerbox_id": pbx, "principals": [state["carol_p"]]})
    result = deny(share_view["proposal_id"], reason="ask me first")
    check(result.ok and result.json["state"] == "denied" and result.json["reason"] == "ask me first",
          f"deny: exit {result.code} {result.json}")
    create_view = proposed(pia, "create", {"repository": str(state["repo"]), "branch": "main", "title": "denied"})
    check(deny(create_view["proposal_id"]).ok, "deny without a reason")
    invite_view = proposed(pia, "invite", invite_args("cancelled"))
    pid = invite_view["proposal_id"]
    status, body = pia.post(f"/adapter/v1/peerbox/proposals/{pid}/cancel")
    check(status == 200, f"cancel: {status} {hide(body)}")
    check_view(body, pid, "invite", "cancelled")
    status, body = pia.post(f"/adapter/v1/peerbox/proposals/{pid}/cancel")
    check(status == 409 and body.get("code") == "conflict" and body.get("error") == "the proposal is no longer pending"
          and body["proposal"]["state"] == "cancelled", f"cancel again: {status} {hide(body)}")
    for denied in (share_view, create_view, invite_view):
        status, body = a.api("POST", f"/v1/peerbox-proposals/{denied['proposal_id']}/approve",
                             {"proposal_sha256": denied["proposal_sha256"], "person_key": None})
        check(status == 409 and body.get("code") == "conflict" and body["proposal"]["state"] in ("denied", "cancelled"),
              f"approve after a decision: {status} {hide(body)}")
        check(not deny(denied["proposal_id"]).ok, "deny after a decision")
    check_view(pia.call("GET", f"/adapter/v1/peerbox/proposals/{share_view['proposal_id']}")[1],
               share_view["proposal_id"], "share", "denied")
    check(policy_version(a, state["alice_public"]) == version and shown() == boxes
          and owner_cli("invite", "--list").stdout == invites, "a denied or cancelled proposal changed something")


@case("person_key_needed", "peerbox Agent proposals, Approving (route refusals): 409 person_key_needed checked before "
                           "anything changes, the proposal left pending; approve again with --person-key")
def _():
    b, bia, bpbx = need("b", "bia", "bpbx")
    view = proposed(bia, "share", {"peerbox_id": bpbx, "principals": [state["alice_p"]]})
    pid = view["proposal_id"]
    version = policy_version(b, state["bob_public"])
    status, body = b.api("POST", f"/v1/peerbox-proposals/{pid}/approve", {"proposal_sha256": view["proposal_sha256"],
                                                                          "person_key": None})
    check(status == 409 and body.get("code") == "person_key_needed", f"approve without the key: {status} {body}")
    without = approve(pid, host=b)
    check(without.code == 1 and "--person-key" in without.stderr, f"the CLI without --person-key: exit {without.code}")
    check(record(pid, b)["state"] == "pending" and policy_version(b, state["bob_public"]) == version,
          "person_key_needed changed something")
    approved(pid, key=state["bob_key"], host=b)
    found = rules_for(bpbx, state["alice_p"], host=b, person_public=state["bob_public"])
    check(len(found) == 1 and found[0]["actions"] == ["peerbox.read"], f"alice's rule on bob's peerbox {found}")


@case("review_changed_branch", "peerbox Agent proposals, Execution (create): the branch moved after the proposal "
                               "fails review_changed; nothing created (PBX-21)")
def _():
    pia = need("pia2")[0]
    repo = init_repo(suite.work / "moving-repo")
    commit_files(repo, {"a.txt": "a\n"}, "one")
    view = proposed(pia, "create", {"repository": str(repo), "branch": "main"})
    commit_files(repo, {"a.txt": "moved\n"}, "moved")
    before = shown()
    failed_approval(view["proposal_id"], "review_changed")
    check(shown() == before, "a failed create left a peerbox")
    check_view(pia.call("GET", f"/adapter/v1/peerbox/proposals/{view['proposal_id']}")[1], view["proposal_id"],
               "create", "failed")


@case("review_changed_access", "peerbox Agent proposals, Execution (share): a recipient's access granted, revoked or "
                               "altered after the proposal fails review_changed, the newer policy left in place")
def _():
    a, pia, pbx_rc = need("a", "pia2", "pbx_rc")
    bob, carol, key = state["bob_p"], state["carol_p"], state["alice_key"]

    def after_change(principals, change, want):
        view = proposed(pia, "share", {"peerbox_id": pbx_rc, "principals": principals, "actions": ["read", "run"]})
        change()
        version = policy_version(a, state["alice_public"])
        failed_approval(view["proposal_id"], "review_changed", key=key)
        check(policy_version(a, state["alice_public"]) == version, "a failed share signed a version")
        for p, actions in want.items():
            got = [r["actions"] for r in rules_for(pbx_rc, p)]
            check(got == ([actions] if actions else []), f"{p}'s rules {got}, want {actions}")
    # granted: carol had no access when the person saw the review.
    after_change([carol], lambda: share(pbx_rc, carol, actions=("read", "submit")),
                 {carol: ["peerbox.read", "peerbox.submit"]})
    # revoked: bob had read.
    after_change([bob], lambda: unshare(pbx_rc, bob), {bob: None})
    share(pbx_rc, bob)
    # altered: bob's read became read and submit.
    after_change([bob, carol], lambda: share(pbx_rc, bob, actions=("read", "submit")),
                 {bob: ["peerbox.read", "peerbox.submit"], carol: ["peerbox.read", "peerbox.submit"]})


@case("review_changed_person", "peerbox Agent proposals, Execution (share): a person removed from the network after "
                               "the proposal fails review_changed; nothing signed")
def _():
    a, pia, pbx, net = need("a", "pia2", "pbx", "net")
    view = proposed(pia, "share", {"peerbox_id": pbx, "principals": [state["carol_p"]]})
    removed = a.cli("network", "remove-person", "--network", net, "--person", state["carol_pid"], "--approve",
                    timeout=90)
    check(removed.ok, f"remove carol: exit {removed.code} {tail(removed.stderr)}")
    state["learners"] = [state["b"]]
    version = policy_version(a, state["alice_public"])
    failed_approval(view["proposal_id"], "review_changed", key=state["alice_key"])
    check(policy_version(a, state["alice_public"]) == version and not rules_for(pbx, state["carol_p"]),
          "a share for a removed person was signed")


@case("untrusted_text", "peerbox Agent proposals, What the person sees: an agent-supplied path and title and a "
                        "repository author's and committer's name and email with control characters and terminal "
                        "escapes, shown quoted and escaped by approvals show and approve; IDs whole")
def _():
    a, pia = need("a", "pia2")
    hostile = hostile_repo(suite.work / "hostile")
    view = proposed(pia, "create", {"repository": str(hostile["repo"]), "branch": "main"})
    pid = view["proposal_id"]
    check(view["args"]["title"] == hostile["repo"].name and view["review"]["identities_total"] == 4
          and view["review"]["identities"] == hostile["identities"],
          f"the hostile review {view['review']}")
    values = (str(hostile["repo"]), hostile["repo"].name, *HOSTILE_AUTHOR, *HOSTILE_COMMITTER)
    shown_text = a.cli("approvals", "show", pid)
    check(shown_text.ok, f"approvals show: exit {shown_text.code}")
    check_display(shown_text.stdout + shown_text.stderr, pia, "create", values=values, plain=(hostile["main"],))
    listed = a.cli("approvals")
    check(listed.ok and pid in listed.stdout and not RAW_CONTROL.findall(listed.stdout + listed.stderr),
          "the approvals line printed raw control characters")
    no = approve(pid, answer="n")
    check(no.code == 1, f"declining: exit {no.code}")
    check_display(no.stderr + no.stdout, pia, "create", values=values, plain=(hostile["main"],))
    check(record(pid)["state"] == "pending", "a declined approve changed the proposal")
    deny(pid)


@case("status_and_pending_work", "peerbox Agent proposals, Approving (Telling the person) and Telling the agent: "
                                 "peerbox_proposals_pending and the peerbox_proposal_pending item; pending_work, "
                                 "GET /adapter/v1/pending and GET /v1/sessions/{id}/pending until seen")
def _():
    a, pbx = need("a", "pbx")
    pwa = credential(a, "pwa")
    deny_all()
    view = proposed(pwa, "invite", invite_args("pending-work"))
    pid = view["proposal_id"]
    status, body = a.api("GET", "/v1/status")
    items = [i for i in body.get("attention") or [] if i.get("kind") == "peerbox_proposal_pending"]
    check(status == 200 and body.get("peerbox_proposals_pending") == 1 and len(items) == 1
          and items[0].get("subject") == "1" and items[0].get("command") == "peerspan approvals"
          and "invite" in str(items[0].get("detail")) and view["expires_at"] in str(items[0].get("detail")),
          f"status: {body.get('peerbox_proposals_pending')} {items}")
    entry = {"proposal_id": pid, "op": "invite", "state": "pending", "expires_at": view["expires_at"],
             "session_id": pwa.session_id, "redelivered": False}

    def listed():
        status, work = pwa.call("GET", "/adapter/v1/pending")
        check(status == 200, f"GET /adapter/v1/pending: {status} {work}")
        status, owner = a.api("GET", f"/v1/sessions/{pwa.session_id}/pending")
        check(status == 200 and owner.get("peerbox_proposals") == work.get("peerbox_proposals"),
              f"the session's pending work on the owner API: {status} {owner}")
        return work.get("peerbox_proposals")
    check(listed() == [entry], f"pending_work while pending: {listed()}")
    check(deny(pid).ok, "deny")
    check(listed() == [dict(entry, state="denied")], f"pending_work with the update unseen: {listed()}")
    status, body = a.api("GET", "/v1/status")
    check(body.get("peerbox_proposals_pending") == 0 and not [i for i in body.get("attention") or []
                                                              if i.get("kind") == "peerbox_proposal_pending"],
          f"status with none pending: {body.get('peerbox_proposals_pending')}")
    check(pwa.call("GET", f"/adapter/v1/peerbox/proposals/{pid}")[0] == 200, "the final view")
    check(listed() == [], f"pending_work after the final view was seen: {listed()}")
    check(updates(pwa) == [], "a seen notification was claimed")


@case("no_budget_no_approving_route", "peerbox Agent proposals, Routes and budgets, Why text from others cannot "
                                      "approve: no route budget consumed; no adapter, peer or channel route approves, "
                                      "creates or lists a proposal")
def _():
    a, b, pia, pbx = need("a", "b", "pia", "pbx")
    added = a.cli("adapter", "route", "add", "--adapter", pia.adapter_id, "--name", "budget", "--peer", b.id,
                  "--action", "runtime.run", "--max-messages", "2", "--expires-in", "1h")
    check(added.ok, f"pia's route: {tail(added.stderr)}")

    def remaining():
        status, rows = a.api("GET", f"/v1/adapters/{pia.adapter_id}/route-status")
        check(status == 200, f"route-status: {status} {rows}")
        return sorted(row["messages_remaining"] for row in rows)
    before = remaining()
    views = [proposed(pia, "invite", invite_args(f"budget-{i}")) for i in range(3)]
    check(remaining() == before, f"proposals used a route budget: {before} -> {remaining()}")
    pid, sha = views[0]["proposal_id"], views[0]["proposal_sha256"]
    body = {"proposal_sha256": sha, "person_key": None}
    for path in (f"/adapter/v1/peerbox/proposals/{pid}/approve", f"/v1/peerbox-proposals/{pid}/approve",
                 f"/adapter/v1/peerbox-proposals/{pid}/approve"):
        status, answer = pia.post(path, body)
        check(not 200 <= status < 300, f"POST {path} on the adapter socket: {status} {answer}")
    for method, path, payload in (("POST", f"/peer/v1/peerbox/proposals/{pid}/approve", body),
                                  ("POST", f"/peer/v1/peerbox-proposals/{pid}/approve", body),
                                  ("POST", f"/v1/peerbox-proposals/{pid}/approve", body),
                                  ("GET", "/peer/v1/peerbox/proposals", None),
                                  ("POST", "/peer/v1/peerbox/proposals", {"proposal_id": new_pid(), "op": "invite",
                                                                          "args": invite_args("peer")})):
        status, answer = peer(b, a, method, path, payload)
        check(not 200 <= status < 300, f"{method} {path} from bob's host: {status} {answer}")
    for op in ({"op": "invite", "peerbox_id": pbx, "label": "by-peer"}, {"op": "propose", "peerbox_id": pbx}):
        status, answer = raw_op(op, sender=b)
        check(not 200 <= status < 300 or answer.get("state") in ("rejected", "failed"), f"a peer {op['op']} task: "
                                                                                       f"{status} {answer}")
    settle(1)
    check(all(record(v["proposal_id"])["state"] == "pending" for v in views)
          and len(pending_ids()) >= 3 and "by-peer" not in json.dumps(a.ok("approvals", "--all", "--json")),
          "a route other than the person's approve decided or created a proposal")
    for v in views:
        deny(v["proposal_id"])


@case("limits", "peerbox Agent proposals, Proposing 3: 5 pending per credential and 20 per host (429 limit), 20 per "
                "credential per hour (429 rate_limited, retry_after); the pending limit answering when both apply; "
                "repeats never counted; nothing persisted")
def _():
    a = need("a")[0]
    need("pia")
    deny_all()
    lim = credential(a, "lim")
    limit_error = {"code": "limit", "error": "too many proposals are waiting for approval",
                   "limit": "max_pending_proposals"}
    made = [proposed(lim, "invite", invite_args(f"lim-{i}")) for i in range(5)]
    status, body, pid = propose(lim, "invite", invite_args("lim-5"))
    refused_and_absent(lim, status, body, 429, "limit", pid)
    check(status == 429 and body == limit_error, f"the sixth pending: {status} {body}")
    others = [credential(a, f"lim{n}") for n in range(1, 5)]
    for other in others[:3]:
        for i in range(5):
            proposed(other, "invite", invite_args(f"{other.name}-{i}"))
    status, body, pid = propose(others[3], "invite", invite_args("host-21"))
    refused_and_absent(others[3], status, body, 429, "limit", pid)
    check(body == limit_error, f"the 21st pending on the host: {body}")
    deny_all()
    for i in range(10):  # lim's 11th to 20th proposals in the hour, none left pending
        view = proposed(lim, "invite", invite_args(f"hour-{i}"))
        check(lim.post(f"/adapter/v1/peerbox/proposals/{view['proposal_id']}/cancel")[0] == 200, "cancel")
    waiting = [proposed(lim, "invite", invite_args(f"wait-{i}")) for i in range(5)]  # the 16th to 20th, pending
    status, body, pid = propose(lim, "invite", invite_args("both-21"))
    refused_and_absent(lim, status, body, 429, "limit", pid)
    check(body == limit_error, f"both limits apply, the pending limit answers: {body}")
    check(lim.post(f"/adapter/v1/peerbox/proposals/{waiting[0]['proposal_id']}/cancel")[0] == 200, "cancel")
    status, body, pid = propose(lim, "invite", invite_args("hour-21"))
    refused_and_absent(lim, status, body, 429, "rate_limited", pid)
    check(isinstance(body.get("retry_after"), int) and body["retry_after"] >= 1 and isinstance(body.get("error"), str),
          f"rate_limited {body}")
    # A repeat sends the arguments exactly as first given (Proposing 2), not the stored args with defaults.
    status, again, _ = propose(lim, "invite", invite_args("lim-0"), made[0]["proposal_id"])
    check(status == 200 and again["proposal_id"] == made[0]["proposal_id"], f"a repeat over the limit: {status}")


@case("restart_interrupted", "peerbox Agent proposals, Execution: the approved note while it runs; a restart while "
                             "approved fails it with interrupted, nothing stored")
def _():
    a, pia = need("a", "pia")
    repo = init_repo(suite.work / "held-repo")
    commit_files(repo, {"h.txt": "h\n"}, "held")
    view = proposed(pia, "create", {"repository": str(repo), "branch": "main"})
    pid = view["proposal_id"]
    before = shown()
    state["hold"].write_text("1")
    run = None
    try:
        run = Prompted(a, "--json", "approve", pid)
        wait_for(lambda: a.api("GET", f"/v1/peerbox-proposals/{pid}")[1].get("state") == "approved", timeout=30,
                 message="the proposal to be approved and held in execution")
        check_view(pia.call("GET", f"/adapter/v1/peerbox/proposals/{pid}")[1], pid, "create", "approved")
        a.stop(kill=True)
    finally:
        state["hold"].unlink(missing_ok=True)
        if run is not None and run.p.poll() is None:
            os.killpg(run.p.pid, signal.SIGKILL)
            run.p.wait()
        if a.process is None:
            a.start()
    wait_for(lambda: record(pid)["state"] != "approved", timeout=30,
             message="the daemon to settle the approved proposal")
    got = record(pid)
    check(got["state"] == "failed" and (got["error"] or {}).get("code") == "interrupted" and got["result"] is None,
          f"after the restart: {got['state']} {got['error']}")
    check(shown() == before, "an interrupted create stored a peerbox")
    status, again = a.api("POST", f"/v1/peerbox-proposals/{pid}/approve", {"proposal_sha256": view["proposal_sha256"],
                                                                           "person_key": None})
    check(status == 409 and again.get("code") == "conflict", f"approving an interrupted proposal: {status}")


@case("updates_and_expiry", "peerbox Agent proposals, Telling the agent and Execution (Expiry): one "
                            "peerbox_proposal_update per executed, failed, denied and expired proposal and none for a "
                            "cancel; expiry after 1 hour (test clock) changing nothing; approve after expiry 409")
def _():
    a, pbx = need("a", "pbx")
    eva = credential(a, "eva")
    executed = proposed(eva, "invite", invite_args("eva-x"))
    approved(executed["proposal_id"])
    repo = init_repo(suite.work / "eva-repo")
    commit_files(repo, {"e.txt": "e\n"}, "one")
    failing = proposed(eva, "create", {"repository": str(repo), "branch": "main"})
    commit_files(repo, {"e.txt": "moved\n"}, "moved")
    failed_approval(failing["proposal_id"], "review_changed")
    denied = proposed(eva, "invite", invite_args("eva-d"))
    check(deny(denied["proposal_id"]).ok, "deny")
    cancelled = proposed(eva, "invite", invite_args("eva-c"))
    check(eva.post(f"/adapter/v1/peerbox/proposals/{cancelled['proposal_id']}/cancel")[0] == 200, "cancel")
    expiring = proposed(eva, "invite", invite_args("eva-e"))
    claimed = updates(eva)
    ids = sorted(d["proposal_id"] for d in claimed)
    want = sorted(v["proposal_id"] for v in (executed, failing, denied))
    check(ids == want, f"proposal-update notifications for {ids}, want one each for {want} and none for the cancel")
    boxes = shown()
    clock.set(clock.offset + HOUR + 30)
    pid = expiring["proposal_id"]
    status, body = a.api("POST", f"/v1/peerbox-proposals/{pid}/approve",
                         {"proposal_sha256": expiring["proposal_sha256"], "person_key": None})
    check(status == 409 and body.get("code") == "conflict", f"approve past expires_at: {status} {hide(body)}")
    wait_for(lambda: a.api("GET", f"/v1/peerbox-proposals/{pid}")[1].get("state") == "expired", timeout=30,
             message="the proposal to expire")
    check(shown() == boxes and "eva-e" not in owner_cli("invite", "--list").stdout and pid not in pending_ids(),
          "an expired proposal changed something")
    eva.connect()  # the clock moved past the lease: renew it and verify the channel again
    claimed = [d["proposal_id"] for d in updates(eva)]
    check(claimed == [pid], f"after the expiry, notifications for {claimed}, want one for {pid} only")
    check(updates(eva) == [], "a notification was claimed twice")
    check_view(eva.call("GET", f"/adapter/v1/peerbox/proposals/{pid}")[1], pid, "invite", "expired")


@case("retry_after_second_network", "peerbox Agent proposals, Proposing 2 (Repeat first, on request_sha256): an "
                                    "identical retry of a create without network_id still returns the proposal after "
                                    "the host joins a second network; a new one is 400 invalid naming network_id")
def _():
    a, pia = need("a", "pia")
    view, retry = need("retry")[0]
    create_network(a, "second", "alice")
    status, again, _ = propose(pia, "create", retry, view["proposal_id"])
    check(status == 200 and again["proposal_id"] == view["proposal_id"] and again["args"] == view["args"]
          and again["proposal_sha256"] == view["proposal_sha256"], f"the identical retry: {status} {hide(again)}")
    status, body, pid = propose(pia, "create", retry)
    refused_and_absent(pia, status, body, 400, "invalid", pid, "network_id")


suite.finish()
