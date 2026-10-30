#!/usr/bin/env python3
"""Slim suite, conversations C6: rate, addressing, and the person's tools.

alice creates a coordinator-free network; bob joins it and allows alice. Each case has a conversation and fixture
agents of its own, so a failure stays in its case. The cases cover the 60-message limit at the author's host and at a
recipient, `addressed_to`, the `about` link, the read cursor, `conversation watch`, the event log, what the recheck
hides, `conversation forget`, `home_unavailable` (a fresh host dave, since it is revoked), terminal escaping, the
activity kinds, the help and, last, the hour passing on the test clock. Its own suite and CI job so the conversations
job stays under 2 minutes. Written from docs/conversations-contract.md, section C6 (cited as "C6 <part>"), and the C1
to C5 sections it builds on, only.
"""
import json
import os
import re
import signal
import subprocess
import threading
import time
from datetime import timedelta
from pathlib import Path

from harness import (Suite, api_error, check, create_network, departed_of, find_message, join_new_person, message_id,
                     peer, refused, rfc3339, show_targets, ssh_key, target_of, view_as, wait_for, wait_view)

suite = Suite("conversations_tools", __doc__)
suite.use_clock()  # C6 Verification Clock: the window case moves the test clock; it must be set before hosts start
a, b = suite.host("alice"), suite.host("bob")
state = {}

CLAIM = "/adapter/v1/conversation-notifications/next"
LIMIT_AUTHOR = "This participant reached its limit of 60 messages per hour in this conversation."
LIMIT_PEER = "This author reached its limit of 60 messages per hour in this conversation."
NO_PARTICIPANT = "No such participant in that conversation."
IN_USE = "Someone on this host is still in that conversation; leave it first."
CONFIRM = "error: confirm: conversation forget needs --yes when not at a terminal."
CONFLICT = "This message_id was already used with different content."
EVENT_KEYS = {"sequence", "kind", "conversation_id", "message_id", "participant", "at"}
WORD = "c6word"  # in every message of this suite: the activity and event checks look for it
TITLE_WORD = "c6title"  # in every title of this suite
RAW_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")  # C6 Terminal escaping; \t and \n: see readable()
RAW_C1 = re.compile(r"[\x7f-\x9f]")
CONV_SUBJECT = re.compile(r"^conv_[0-9a-f]{32}$")
MESSAGE_SUBJECT = re.compile(r"^conv_[0-9a-f]{32}/cmsg_[0-9a-f]{32}$")
EVIL_CONTENT = f"{WORD} \x1b[31m red \x07 \x9b2J \x7f \t \r\nfake line"
EVIL_NAME = "ev\x1b[31mil\x9b2J\nfake-name"
EVIL_NAME_PRINTED = "ev\\u001b[31mil\\u009b2J\\u000afake-name"


def need(*names):
    missing = [n for n in names if n not in state]
    check(not missing, f"an earlier case did not finish ({', '.join(missing)} missing)")
    return [state[n] for n in names]


def policy_version(host):
    status, body = host.api("GET", f"/v2/networks/{state['net']}/access-versions")
    check(status == 200, f"{host.name}: access-versions: {status} {body}")
    return max((p["version"] for p in body["policies"] if p["person_public_key"] == state["bob_public"]), default=0)


def wait_policy(version):
    """C6 Verification Policy: alice must hold the version she is to cite or be refused on."""
    def ready():
        status, body = a.api("POST", f"/v2/networks/{state['net']}/sync", {}, timeout=40)
        check(status == 200, f"alice: sync: {status} {body}")
        return policy_version(a) >= version
    wait_for(ready, timeout=30, interval=1, message=f"alice to hold bob's policy version {version}")


def deny(wait=False):
    b.ok("deny", "alice", "--person-key", state["bob_key"])
    state["denied"] = True
    if wait:
        wait_policy(policy_version(b))


def allow():
    """Undo deny(). Does nothing when alice is already allowed."""
    if state.pop("denied", False):
        wait_policy(b.ok("allow", "alice", "--no-tasks", "--person-key", state["bob_key"])["policy"]["version"])


def new_agent(name, host=b):
    adapter = host.agent(name)
    a.ok("agents", "--refresh", "--json")
    return adapter


def participant(adapter):
    return f"agent:{adapter.host.id}/{adapter.id}"


def text(what):
    return f"{WORD} {what}"


def invites(host):
    status, body = host.api("GET", "/v1/conversations/invites")
    check(status == 200, f"{host.name}: invites: {status} {body}")
    return {i["conversation_id"]: i for i in body["invites"]}


def wait_invite(host, conv):
    return wait_for(lambda: invites(host).get(conv), timeout=20, interval=0.3,
                    message=f"{host.name} to hold the pending invite to {conv}")


def start(*targets, host=a, join=b):
    """HOST's person starts a conversation with TARGETS; a person target's host JOIN joins it."""
    started = host.ok("conversation", "start", *targets, timeout=60)
    conv = started["conversation"]["conversation_id"]
    for outcome in started["invites"]:
        check(outcome["state"] in ("joined", "invited"), f"start {targets}: {outcome}")
        if outcome["state"] == "invited":
            state.setdefault("person_ids", {})[outcome["label"]] = outcome["participant"].split(":", 1)[1]
            if join:
                wait_invite(join, conv)
                join.ok("conversation", "join", conv, timeout=60)
    return conv


def person_p(host, label):
    return f"person:{host.id}/{state['person_ids'][label]}"


def say(conv, what, host=a):
    return host.ok("conversation", "say", conv, text(what))["message"]["message_id"]


def api_say(conv, content, host=a, **fields):
    status, body = host.api("POST", f"/v1/conversations/{conv}/messages", {"content": content, **fields})
    check(status == 200, f"{host.name}: send: {status} {body}")
    return body["message"]["message_id"]


def show(host, conv, *extra):
    view = host.ok("conversation", "show", conv, "--json", "--limit", "100", *extra)
    check(isinstance(view, dict) and isinstance(view.get("messages"), list), f"{host.name}: show --json: {view}")
    return view


def api_messages(host, conv, query=""):
    """A read through the route: no CLI, so it posts no cursor."""
    status, body = host.api("GET", f"/v1/conversations/{conv}/messages?limit=100{query}")
    check(status == 200, f"{host.name}: messages: {status} {body}")
    return body["messages"]


def wait_all_delivered(conv, mids, who):
    last = {}

    def done():
        messages = {m["message_id"]: m for m in api_messages(a, conv)}
        last["t"] = [target_of(messages[m], who) for m in mids]
        return all(t["state"] == "delivered" for t in last["t"])
    try:
        wait_for(done, timeout=40, interval=0.3, message=f"{len(mids)} targets of {who} to be delivered")
    except AssertionError as error:
        bad = [t for t in last.get("t", []) if t["state"] != "delivered"]
        raise AssertionError(f"{error}; not delivered: {bad[:3]}") from None


def claim(adapter):
    status, body = adapter.post(CLAIM, {})
    check(status == 200, f"{adapter.name}: claim: {status} {body}")
    return body


def claim_messages(adapter, *mids):
    """Claim until ADAPTER got every message of MIDS, in any order, passing `added` and others: {id: claim}."""
    got = {}

    def found():
        body = claim(adapter)
        if body and body["notification"].get("message_id") in mids:
            got[body["notification"]["message_id"]] = body
        return len(got) == len(mids)
    wait_for(found, timeout=20, interval=0.1, message=f"{adapter.name} to claim {mids}")
    return got


def claim_message(adapter, mid):
    return claim_messages(adapter, mid)[mid]


def probe_message(conv, version, seq, content, clock=None, sent_at=None, **fields):
    """C6 Verification Raw requests: no prev_seq, a seq alice's host never used, and the roster version bob holds."""
    return {"message_id": message_id(), "conversation_id": conv, "author": state["alice_p"], "seq": seq,
            "clock": clock or seq, "roster_version": version, "sent_at": sent_at or rfc3339(suite.now()),
            "content": content, **fields}


def probe_person(conv, message, target=None):
    return peer(a, b, "POST", f"/peer/v1/conversations/{conv}/messages",
                {"message": message, "target": target or person_p(b, "bob")})


def probe_agent(conv, message, adapter):
    return peer(a, b, "POST", f"/peer/v1/conversations/{conv}/messages",
                {"message": message, "target": participant(adapter),
                 "policy": {"person_id": state["person_ids"]["bob"], "version": policy_version(b)}})


def bob_version(conv):
    return view_as(b, conv, person_p(b, "bob"))["roster_version"]


def summary(host, conv):
    status, body = host.api("GET", "/v1/conversations?state=all")
    check(status == 200, f"{host.name}: list: {status} {body}")
    found = [s for s in body["conversations"] if s["conversation_id"] == conv]
    return found[0] if found else None


def unread(conv):
    entry = summary(b, conv)
    check(entry is not None, f"bob does not list {conv}")
    return entry["unread"]


def status_unread(host=b):
    status, body = host.api("GET", "/v1/status")
    check(status == 200, f"{host.name}: status: {status} {body}")
    return body["conversations"]["unread"]


def events(host, query=""):
    status, body = host.api("GET", f"/v1/conversations/events?limit=1000{query}")
    check(status == 200 and isinstance(body, dict), f"{host.name}: events{query}: {status} {body}")
    return body


def readable(result, *wanted):
    """C6 Terminal escaping: exit 0, no control character but the line ends and any spacing the CLI itself uses."""
    check(result.ok, f"`{' '.join(result.args[:3])}`: exit {result.code}: {result.stderr[-300:]!r}")
    for stream in (result.stdout, result.stderr):
        found = RAW_CONTROL.search(stream)
        check(not found and "\ufffd" not in stream, f"`{' '.join(result.args[:3])}` printed a raw control character: "
                                                    f"{stream[-500:]!r}")
    for piece in wanted:
        check(piece in result.stdout, f"`{' '.join(result.args[:3])}` lacks {piece!r}: {result.stdout[-700:]!r}")
    return result.stdout


def json_output(result):
    """C6 JSON output: U+007F to U+009F written as \\u00XX; parsing returns the original text."""
    check(result.ok, f"`{' '.join(result.args[:3])}`: exit {result.code}: {result.stderr[-300:]!r}")
    found = RAW_C1.search(result.stdout)
    check(not found and "\ufffd" not in result.stdout, f"`{' '.join(result.args[:3])}` JSON holds a raw character: "
                                                       f"{result.stdout[-500:]!r}")
    check(result.json is not None, f"`{' '.join(result.args[:3])}` printed no JSON: {result.stdout[-300:]!r}")
    return result.json


def activity(host):
    status, body = host.api("GET", "/v1/activity?limit=1000")
    check(status == 200, f"{host.name}: activity: {status} {body}")
    entries = body if isinstance(body, list) else next(v for v in body.values() if isinstance(v, list))
    return [e for e in entries if e["kind"].startswith("conversation.")]


class Watch:
    """`conversation watch` through suite.spawn, its output in files so nothing blocks (C6 Verification Watch)."""
    count = 0

    def __init__(self, host, *args):
        Watch.count += 1
        self.out = host.root / f"watch{Watch.count}.out"
        self.err = host.root / f"watch{Watch.count}.err"
        self.args = args
        self.host = host

    def __enter__(self):
        with self.out.open("wb") as out, self.err.open("wb") as err:
            self.process = suite.spawn([str(suite.host_bin), "--state", str(self.host.state), "conversation", "watch",
                                        *self.args], stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                       env=self.host.env, cwd=str(self.host.root))
        try:
            wait_for(lambda: "Watching; press Ctrl-C to stop." in self.err.read_text(errors="replace"), timeout=20,
                     interval=0.1, message="`Watching; press Ctrl-C to stop.` on stderr")
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *_):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=5)

    def text(self):
        return self.out.read_bytes().decode(errors="replace")

    def wait_text(self, piece, timeout=20):
        try:
            wait_for(lambda: piece in self.text(), timeout=timeout, interval=0.1, message=f"watch to print {piece!r}")
        except AssertionError as error:
            raise AssertionError(f"{error}; stdout {self.text()[-500:]!r}") from None

    def stop(self, number=signal.SIGTERM):
        """C6 `conversation watch`: SIGINT or SIGTERM ends it with exit 0."""
        self.process.send_signal(number)
        try:
            code = self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            raise AssertionError(f"watch did not end within 10s of signal {number}") from None
        check(code == 0, f"watch exit {code} on signal {number}, want 0")


@suite.case("setup", "C6 Verification Setup; C1 Verification setup; decentralized-spec 6, 8")
def _():
    net = create_network(a, "tools", "alice")
    state["net"] = net["id"]
    key = ssh_key(b.root, "bob")
    state["bob_key"] = key
    join_new_person(a, b, "bob", key, net["id"])
    status, network = b.api("GET", f"/v2/networks/{net['id']}")
    check(status == 200, f"bob: network: {status} {network}")
    state["bob_public"] = network["person_public_key"]
    allowed = b.ok("allow", "alice", "--no-tasks", "--person-key", key)
    state["alice_person"] = allowed["principal"].split(":", 1)[1]
    state["alice_p"] = f"person:{a.id}/{state['alice_person']}"
    wait_policy(allowed["policy"]["version"])


@suite.case("limit_author", "C6 The rate limit: At the author's host; Verification Limit at the author's host")
def _():
    need("alice_p")
    # `lena` stands for the contract's `bert` here: 60 unclaimed messages would crowd the other cases' claims.
    lena = new_agent("lena")
    conv = start("bob/lena")
    state["limit_conv"], state["limit_agent"] = conv, participant(lena)
    mids = [api_say(conv, text(f"limit {i}")) for i in range(1, 61)]
    wait_all_delivered(conv, mids, participant(lena))
    say_61 = a.cli("conversation", "say", conv, text("limit 61"))
    refused(say_61, "limit", LIMIT_AUTHOR)
    listed = show(a, conv)["messages"]
    check([m["message_id"] for m in listed] == mids, f"show lists {len(listed)} messages, want exactly the 60")
    status, body = a.api("POST", f"/v1/conversations/{conv}/messages", {"content": text("limit 61")})
    api_error(status, body, 429, "limit", LIMIT_AUTHOR)
    # The repeat rule comes first: it is never limited and consumes nothing.
    repeat = a.ok("conversation", "say", conv, text("limit 60"), "--message-id", mids[-1])
    check(repeat["message"]["message_id"] == mids[-1], f"repeat of the 60th: {repeat['message']}")
    a.restart()
    refused(a.cli("conversation", "say", conv, text("limit 61 after restart")), "limit", LIMIT_AUTHOR)
    # Each author is counted alone.
    status, body = lena.post(f"/adapter/v1/conversations/{conv}/messages", {"content": text("lena still sends")})
    check(status == 200, f"lena's send: {status} {body}")
    show_targets(lena.host, conv, body["message"]["message_id"], state["alice_p"], "delivered", as_agent="lena")
    check(len(api_messages(a, conv)) == 61, "alice's 60 and lena's one are not all listed")


@suite.case("limit_local_adapter", "C6 The rate limit: At the author's host (adapter route, local deliveries, "
                                   "separate allowances)")
def _():
    need("alice_p")
    ada = a.agent("ada")
    state["ada"] = ada
    conv = start("alice/ada", join=None)
    state["local_conv"] = conv
    path = f"/adapter/v1/conversations/{conv}/messages"
    last = None
    for i in range(1, 61):
        status, body = ada.post(path, {"content": text(f"ada {i}")})
        check(status == 200, f"ada's send {i}: {status} {body}")
        last = body["message"]["message_id"]
    status, body = ada.post(path, {"content": text("ada 61")})
    api_error(status, body, 429, "limit", LIMIT_AUTHOR)
    status, body = ada.post(path, {"content": text("ada 60"), "message_id": last})
    check(status == 200, f"ada's repeat of the 60th: {status} {body}")
    state["local_message"] = last
    say(conv, "alice's own allowance is separate")


@suite.case("limit_recipient", "C6 The rate limit: At a recipient host; Verification Limit at a recipient")
def _():
    need("alice_p")
    conv = start("person:bob")
    state["full_conv"] = conv
    version = bob_version(conv)
    bob_p = person_p(b, "bob")
    sent = []
    for i in range(1, 61):
        m = probe_message(conv, version, 100_000 + i, text(f"probe {i}"))
        status, answer = probe_person(conv, m)
        check(status == 200, f"probe {i}: {status} {answer}")
        sent.append((m, answer))
    m61 = probe_message(conv, version, 100_061, text("probe 61"))
    for attempt in ("first", "repeated"):
        status, answer = probe_person(conv, m61)
        api_error(status, answer, 429, "limit", LIMIT_PEER)
        check(m61["message_id"] not in {x["message_id"] for x in api_messages(b, conv)},
              f"the 61st was stored ({attempt})")
    # An identical repeat returns the saved receipt and never reaches the limit.
    status, answer = probe_person(conv, sent[-1][0])
    check(status == 200 and answer == sent[-1][1], f"repeat of the 60th: {status} {answer}, want {sent[-1][1]}")
    check(answer["target"] == bob_p and answer["message_id"] == sent[-1][0]["message_id"], f"receipt {answer}")
    # A further target of a held message passes this step and is not counted again.
    tess = new_agent("tess")
    a.ok("conversation", "add", conv, "bob/tess", timeout=60)
    status, answer = probe_agent(conv, sent[-1][0], tess)
    check(status == 200, f"a further target of the 60th: {status} {answer}")
    b.restart()
    status, answer = probe_person(conv, probe_message(conv, version, 100_062, text("probe after restart")))
    api_error(status, answer, 429, "limit", LIMIT_PEER)
    # It counts in its own hour.
    old = probe_message(conv, version, 100_063, text("probe two hours old"),
                        sent_at=rfc3339(suite.now() - timedelta(hours=2)))
    status, answer = probe_person(conv, old)
    check(status == 200 and answer["message_id"] == old["message_id"], f"a probe two hours old: {status} {answer}")
    # And a message refused above counted for nothing: the allowance is exactly as full as it was.
    status, answer = probe_person(conv, m61)
    api_error(status, answer, 429, "limit", LIMIT_PEER)


@suite.case("final_refusal", "C6 The rate limit: At a recipient host (recorded refused, final); `conversation watch` "
                             "target lines; Verification Final refusal")
def _():
    conv = need("full_conv")[0]
    bob_p = person_p(b, "bob")
    with Watch(a, conv) as watch:
        said = a.ok("conversation", "say", conv, text("over the limit at bob"))  # 200 on alice: she stored no probe
        mid = said["message"]["message_id"]
        t = show_targets(a, conv, mid, bob_p, "refused")
        check(t["code"] == "limit", f"target {t}, want refused with limit")
        check(mid not in {m["message_id"] for m in api_messages(b, conv)}, "bob stored the refused message")
        watch.wait_text("(refused: limit)")
        watch.stop()
    state["refused_subject"] = f"{conv}/{mid}"


@suite.case("addressed_to", "C6 `addressed_to`: Local sending, Repeats, Views; C5 `pending_work`; "
                            "Verification `addressed_to`")
def _():
    need("alice_p")
    bert, bea = new_agent("bert"), new_agent("bea")
    bert_p, bea_p = participant(bert), participant(bea)
    conv = start("bob/bert", "bob/bea", "person:bob", join=None)  # bob's person stays invited: no `id` to name yet
    wait_invite(b, conv)
    addressed = a.ok("conversation", "say", conv, text("for bert"), "--to", "bob/bert")["message"]
    mid = addressed["message_id"]
    check(addressed["addressed_to"] == [bert_p] and addressed["addressed_to_labels"] == ["bob/bert"]
          and addressed["addressed"] is False, f"alice's view of the addressed message: {addressed}")
    got = claim_message(bert, mid)["messages"][0]
    check(got["addressed"] is True and got["addressed_to"] == [bert_p] and got["addressed_to_labels"] == ["bob/bert"],
          f"bert's claim: {got}")
    plain = say(conv, "for everyone")
    # bea holds the addressed message unclaimed first: pending_work reads `addressed` from its notifications.
    show_targets(a, conv, plain, bea_p, "delivered")
    show_targets(a, conv, mid, bea_p, "delivered")
    bea_claims = claim_messages(bea, mid, plain)
    got = bea_claims[mid]["messages"][0]
    check(got["addressed"] is False and got["addressed_to"] == [bert_p] and got["addressed_to_labels"] == ["bob/bert"],
          f"bea's claim: {got}")
    got = bea_claims[plain]["messages"][0]
    check(got["addressed"] is True and got["addressed_to"] == [] and got["addressed_to_labels"] == [],
          f"bea's claim of a message with no --to: {got}")
    got = claim_message(bert, plain)["messages"][0]
    check(got["addressed"] is True, f"bert's claim of a message with no --to: {got}")
    # By participant ID; the author may be named; entries for one participant count once; roster order.
    by_id = a.ok("conversation", "say", conv, text("by id"), "--to", bert_p)["message"]
    check(by_id["addressed_to"] == [bert_p], f"--to by ID: {by_id}")
    twice = a.ok("conversation", "say", conv, text("twice"), "--to", "bob/bert", "--to", bert_p)["message"]
    check(twice["addressed_to"] == [bert_p], f"two entries for bert: {twice}")
    order = a.ok("conversation", "say", conv, text("order"), "--to", "bob/bea", "--to", "alice", "--to",
                 "bob/bert")["message"]
    roster = [p["id"] for p in view_as(a, conv, state["alice_p"])["participants"]]
    want = [p for p in roster if p in (bea_p, bert_p, state["alice_p"])]
    check(order["addressed_to"] == want, f"addressed_to {order['addressed_to']}, want roster order {want}")
    check(order["addressed"] is True, f"alice named herself: {order}")
    # Refusals: nothing is stored.
    before = len(api_messages(a, conv))
    refused(a.cli("conversation", "say", conv, text("to nobody"), "--to", "nobody"), "not_found", NO_PARTICIPANT)
    refused(a.cli("conversation", "say", conv, text("to invited"), "--to", "bob"), "not_found", NO_PARTICIPANT)
    path = f"/v1/conversations/{conv}/messages"
    for bad in (["x"] * 17, ["x" * 257], [1]):
        status, body = a.api("POST", path, {"content": text("bad addressed_to"), "addressed_to": bad})
        api_error(status, body, 400, "invalid")
    check(len(api_messages(a, conv)) == before, "a refused --to stored a message")
    # An empty array is the same as none.
    empty = api_say(conv, text("empty"), addressed_to=[])
    check(find_message(show(a, conv), empty)["addressed_to"] == [], "`addressed_to: []` was stored")
    show_targets(a, conv, empty, bert_p, "delivered")
    # Repeats compare it as well.
    refused(a.cli("conversation", "say", conv, text("for bert"), "--message-id", mid, "--to", "bob/bea"), "conflict",
            CONFLICT)
    refused(a.cli("conversation", "say", conv, text("for bert"), "--message-id", mid), "conflict", CONFLICT)
    for to in ("bob/bert", bert_p):
        again = a.ok("conversation", "say", conv, text("for bert"), "--message-id", mid, "--to", to)
        check(again["message"]["message_id"] == mid, f"repeat with --to {to}: {again['message']}")
    refused(a.cli("conversation", "say", conv, text("empty"), "--message-id", empty, "--to", "bob/bert"), "conflict",
            CONFLICT)
    # pending_work reads it from the messages not seen.
    status, pending = bea.call("GET", "/adapter/v1/pending")
    check(status == 200, f"bea: pending: {status} {pending}")
    entry = next(e for e in pending["conversations"] if e["conversation_id"] == conv)
    check(entry["addressed"] is True, f"bea holds an unseen message for everyone: {entry}")
    lone = new_agent("lone")
    conv2 = start("bob/lone", "bob/bea")
    only_lone = a.ok("conversation", "say", conv2, text("only lone"), "--to", "bob/lone")["message"]["message_id"]
    show_targets(a, conv2, only_lone, bea_p, "delivered")
    show_targets(a, conv2, only_lone, participant(lone), "delivered")
    for adapter, want_addressed in ((bea, False), (lone, True)):
        status, pending = adapter.call("GET", "/adapter/v1/pending")
        check(status == 200, f"{adapter.name}: pending: {status} {pending}")
        entry = next(e for e in pending["conversations"] if e["conversation_id"] == conv2)
        check(entry["addressed"] is want_addressed, f"{adapter.name}: pending {entry}, want {want_addressed}")
    # Owner views, and the readable forms.
    own = show(a, conv)
    check(find_message(own, plain)["addressed"] is True, "alice's own unaddressed message is not addressed to her")
    check(find_message(own, mid)["addressed"] is False, "alice's message only to bert is addressed to her")
    readable(a.cli("conversation", "show", conv), "to bob/bert")
    readable(b.cli("conversation", "show", conv, "--as", "bert"), "to bob/bert")
    # The adapter route takes it too, and a repeat still succeeds once the named participant has departed.
    status, body = bert.post(f"/adapter/v1/conversations/{conv}/messages",
                             {"content": text("bert to bea"), "addressed_to": ["bob/bea"]})
    check(status == 200 and body["message"]["addressed_to"] == [bea_p], f"adapter addressed_to: {status} {body}")
    status, body = bea.post(f"/adapter/v1/conversations/{conv}/manage", {"action": "leave"})
    check(status == 200, f"bea leaves: {status} {body}")
    wait_view(a, conv, state["alice_p"], lambda v: bea_p in departed_of(v), "bea in departed")
    again = a.ok("conversation", "say", conv, text("order"), "--message-id", order["message_id"], "--to", "alice",
                 "--to", bea_p, "--to", bert_p)
    check(again["message"]["message_id"] == order["message_id"], f"repeat naming a departed bea: {again['message']}")
    refused(a.cli("conversation", "say", conv, text("to bea"), "--to", bea_p), "not_found", NO_PARTICIPANT)
    b.ok("conversation", "decline", conv)


@suite.case("about", "C6 The `about` task link; Verification `about`")
def _():
    need("alice_p")
    ana = new_agent("ana")
    host_id, task = "host_" + "a" * 64, "task_" + os.urandom(16).hex()  # no host checks that the task exists
    about = {"peer_host_id": host_id, "task_id": task}
    conv = start("bob/ana", "--about", f"{host_id}/{task}")
    check(view_as(a, conv, state["alice_p"])["about"] == about, "alice's view lacks `about`")
    check(view_as(b, conv, participant(ana))["about"] == about, "bob's view lacks `about`")
    check(summary(a, conv)["about"] == about, f"alice's summary: {summary(a, conv)}")
    status, listed = ana.call("GET", "/adapter/v1/conversations")
    check(status == 200, f"ana: list: {status} {listed}")
    entry = next(c for c in listed["conversations"] if c["conversation_id"] == conv)
    check(entry["about"] == about, f"ana's summary: {entry}")
    plain = start("bob/ana")
    check(view_as(a, plain, state["alice_p"])["about"] is None and summary(a, plain)["about"] is None,
          "`about` is not null without one")
    # The invite view.
    pending = start("person:bob", "--about", f"{host_id}/{task}", join=None)
    check(wait_invite(b, pending)["about"] == about, f"invite view: {invites(b)[pending]}")
    b.ok("conversation", "decline", pending)
    # Malformed values.
    for bad in ({"peer_host_id": host_id}, {"task_id": task}, {**about, "extra": 1}, "x", None,
                {"peer_host_id": "host_x", "task_id": task}, {"peer_host_id": host_id, "task_id": "task_x"}):
        status, body = a.api("POST", "/v1/conversations", {"participants": ["bob/ana"], "about": bad})
        api_error(status, body, 400, "invalid")
    # A peer's roster with a malformed `about` fails the shape check.
    status, body = peer(b, a, "GET", f"/peer/v1/conversations/{conv}/roster")
    check(status == 200, f"roster: {status} {body}")
    roster = {**body["roster"], "version": body["roster"]["version"] + 1, "about": {"peer_host_id": "nope"}}
    status, body = peer(a, b, "POST", f"/peer/v1/conversations/{conv}/roster", {"roster": roster})
    api_error(status, body, 400, "invalid")
    # It grants nothing.
    deny(wait=True)
    try:
        status, body = a.api("POST", "/v1/conversations", {"participants": ["bob/ana"], "about": about}, timeout=40)
        # A policy sync does not update alice's directory entry: bob's host refuses the invite.
        check(status == 201, f"a denied start with the earlier directory entry: {status} {body}, want 201")
        outcome = body["invites"][0]
        check(outcome["state"] == "refused" and outcome["code"] == "not_authorized", f"invite outcome {outcome}")
        denied = body["conversation"]["conversation_id"]
        check(participant(ana) not in {p["id"] for p in view_as(a, denied, state["alice_p"])["participants"]},
              f"ana is in the denied conversation: {body['conversation']}")
        status, listed = ana.call("GET", "/adapter/v1/conversations")
        check(status == 200 and denied not in {c["conversation_id"] for c in listed["conversations"]},
              f"ana lists the denied conversation: {status} {listed}")
        # After a refresh the directory no longer lists the agent.
        a.ok("agents", "--refresh", "--json")
        status, body = a.api("POST", "/v1/conversations", {"participants": ["bob/ana"], "about": about}, timeout=40)
        api_error(status, body, 404, "unknown")
    finally:
        allow()


@suite.case("read_cursor", "C6 The read cursor and unread counts; Verification Read cursor")
def _():
    need("alice_p")
    rita = new_agent("rita")
    conv = start("person:bob", "bob/rita")
    state["read_conv"] = conv
    bob_p = person_p(b, "bob")
    before = status_unread()
    m1, m2 = say(conv, "one"), say(conv, "two")
    show_targets(a, conv, m2, bob_p, "delivered")
    show_targets(a, conv, m2, participant(rita), "delivered")
    check(unread(conv) == 2, f"bob's unread {unread(conv)}, want 2")
    check(status_unread() == before + 2, f"status unread {status_unread()}, want {before + 2}")
    line = [x for x in readable(b.cli("conversations")).splitlines() if conv[:13] in x]
    check(len(line) == 1 and "2 unread" in line[0], f"readable `conversations`: {line}")
    api_messages(b, conv)
    check(unread(conv) == 2, "a GET of the messages moved the cursor")
    readable(b.cli("conversation", "show", conv, "--as", "rita"))
    check(unread(conv) == 2, "`show --as` moved the cursor")
    readable(b.cli("conversation", "show", conv), WORD)
    check(unread(conv) == 0, f"unread after `show`: {unread(conv)}, want 0")
    check(status_unread() == before, "status unread did not drop back")
    line = [x for x in readable(b.cli("conversations")).splitlines() if conv[:13] in x]
    check(len(line) == 1 and "unread" not in line[0], f"readable `conversations` at 0: {line}")
    m3 = say(conv, "three")
    show_targets(a, conv, m3, bob_p, "delivered")
    check(unread(conv) == 1, f"unread after a third: {unread(conv)}, want 1")
    # A page reached with --before lists older messages only: the newer one stays unread, and nothing moves back.
    b.ok("conversation", "show", conv, "--json", "--before", m3)
    check(unread(conv) == 1, "`show --before` moved the cursor past a newer message")
    answer = b.ok("conversation", "read", conv)
    check(answer == {"conversation_id": conv, "participant": bob_p, "unread": 0}, f"conversation read: {answer}")
    check(unread(conv) == 0, "`conversation read` left it unread")
    say(conv, "bob's own", host=b)
    check(unread(conv) == 0, "bob's own message counts as unread")
    # Only forward: an older ID still answers 200 and changes nothing.
    status, body = b.api("POST", f"/v1/conversations/{conv}/read", {"message_ids": [m1]})
    check(status == 200 and body["unread"] == 0, f"read of an older ID: {status} {body}")
    # A message that arrives late is unread even if it sorts before those read.
    late = probe_message(conv, bob_version(conv), 200_001, text("late"), clock=1)
    status, answer = probe_person(conv, late)
    check(status == 200, f"late probe: {status} {answer}")
    check(unread(conv) == 1, f"unread after a late arrival: {unread(conv)}, want 1")
    status, body = b.api("POST", f"/v1/conversations/{conv}/read", {"message_ids": [late["message_id"]]})
    check(status == 200 and body["unread"] == 0, f"read of the late one: {status} {body}")
    # Held here, but not visible to bob's person: sent to rita alone. It is not unread for bob either.
    hidden = probe_message(conv, bob_version(conv), 200_002, text("for rita alone"))
    status, answer = probe_agent(conv, hidden, rita)
    check(status == 200, f"probe to rita: {status} {answer}")
    check(unread(conv) == 0, f"a message not visible to bob counts as unread: {unread(conv)}")
    path = f"/v1/conversations/{conv}/read"
    for body in ({"message_ids": [hidden["message_id"]]}, {"message_ids": [m1, hidden["message_id"]]},
                 {"message_ids": [message_id()]}, {"message_ids": []}, {"message_ids": [m1] * 101},
                 {"message_ids": None}, {"message_ids": ["nope"]}, {"extra": 1}):
        status, answer = b.api("POST", path, body)
        api_error(status, answer, 400, "invalid")
    status, answer = b.api("POST", f"/v1/conversations/conv_{'0' * 32}/read", {})
    api_error(status, answer, 404, "not_found")
    only_agent = start("bob/rita")
    status, answer = b.api("POST", f"/v1/conversations/{only_agent}/read", {})
    api_error(status, answer, 403, "not_participant")
    check(summary(b, only_agent)["unread"] == 0, "a conversation bob's person is not in has unread")
    # GET .../messages/{id}: the same 404 either way, and 200 for the participant who may see it.
    status, gone = b.api("GET", f"/v1/conversations/{conv}/messages/{message_id()}")
    api_error(status, gone, 404, "not_found")
    status, body = b.api("GET", f"/v1/conversations/{conv}/messages/{hidden['message_id']}")
    api_error(status, body, 404, "not_found", gone["error"])
    status, body = b.api("GET", f"/v1/conversations/{conv}/messages/{hidden['message_id']}"
                                f"?participant={participant(rita)}")
    check(status == 200 and body["message"]["content"] == hidden["content"], f"rita's fetch: {status} {body}")


@suite.case("watch", "C6 `conversation watch`, What advances it; Verification Watch")
def _():
    need("alice_p")
    conv, other = start("person:bob"), start("person:bob")
    bob_p = person_p(b, "bob")
    earlier = say(conv, "before the watch")
    show_targets(a, conv, earlier, bob_p, "delivered")
    check(unread(conv) == 1, f"unread before the watch: {unread(conv)}")
    with Watch(b, conv[:13]) as watch:
        check(unread(conv) == 1, "starting the watch moved the cursor")
        fresh = say(conv, "during the watch")
        elsewhere = say(other, "in the other conversation")
        watch.wait_text(text("during the watch"))
        show_targets(a, other, elsewhere, bob_p, "delivered")
        wait_for(lambda: unread(conv) == 0, timeout=20, interval=0.2, message="the watch to move the cursor")
        printed = watch.text()
        check(text("before the watch") not in printed, f"watch printed what came before it: {printed!r}")
        check(text("in the other conversation") not in printed, f"watch with an ID printed another: {printed!r}")
        line = next(x for x in printed.splitlines() if text("during the watch") in x)
        check(conv[:13] in line and "alice" in line and re.search(r"\b\d\d:\d\d\b", line), f"watch line {line!r}")
        check(summary(b, other)["unread"] == 1, "a watch of one conversation moved another's cursor")
        watch.stop(signal.SIGINT)
    show_targets(a, conv, fresh, bob_p, "delivered")
    after = say(conv, "after the watch")
    show_targets(a, conv, after, bob_p, "delivered")
    check(unread(conv) == 1, f"unread after the watch ended: {unread(conv)}, want 1")
    b.ok("conversation", "read", other)
    with Watch(b) as watch:
        say(other, "any conversation")
        watch.wait_text(text("any conversation"))
        say(conv, "again in the first")
        watch.wait_text(text("again in the first"))
        # An `invited` and a `roster_changed` line each name their conversation.
        invited = start("person:bob", join=None)
        wait_for(lambda: any(x.startswith(invited[:13]) for x in watch.text().splitlines()), timeout=20, interval=0.1,
                 message="a line starting with the invited conversation's ID")
        lines_before = len(watch.text().splitlines())
        b.ok("conversation", "join", invited, timeout=60)
        wait_for(lambda: len(watch.text().splitlines()) > lines_before, timeout=20, interval=0.2,
                 message="a roster line after joining")
        check(watch.text().splitlines()[-1].startswith(invited[:13]), f"the roster line: {watch.text()[-300:]!r}")
        watch.stop()
    # `--as`: reads as the agent and moves no person's cursor.
    wes = new_agent("wes")
    agent_conv = start("bob/wes", "person:bob")
    b.ok("conversation", "read", agent_conv)
    with Watch(b, "--as", "wes", agent_conv) as watch:
        said = say(agent_conv, "for wes and bob")
        watch.wait_text(text("for wes and bob"))
        show_targets(a, agent_conv, said, bob_p, "delivered")
        time.sleep(0.5)
        check(unread(agent_conv) == 1, "`watch --as` moved the person's cursor")
        check(claim_message(wes, said)["messages"][0]["message_id"] == said, "wes's notification was changed")
        watch.stop()


@suite.case("event_log", "C6 The event log; Verification Event log")
def _():
    need("alice_p")
    eli = new_agent("eli")
    conv = start("person:bob", "bob/eli")
    bob_p, eli_p, alice_p = person_p(b, "bob"), participant(eli), state["alice_p"]
    query = f"&conversation={conv}"
    mid = say(conv, "for the log")
    show_targets(a, conv, mid, bob_p, "delivered")
    show_targets(a, conv, mid, eli_p, "delivered")
    b.ok("conversation", "read", conv)
    body = events(b, query)
    check(set(body) == {"events", "next_after", "latest"}, f"answer keys {set(body)}")
    got = body["events"]
    check(all(set(e) == EVENT_KEYS for e in got), f"entry keys: {got}")
    check([e["sequence"] for e in got] == sorted({e["sequence"] for e in got}), f"sequences: {got}")
    check(WORD not in json.dumps(body), "an entry holds content")
    kinds = {e["kind"] for e in got}
    check({"message_received", "read_changed", "roster_changed"} <= kinds, f"bob's person's kinds {kinds}")
    received = [e for e in got if e["kind"] == "message_received"]
    check([(e["message_id"], e["participant"]) for e in received] == [(mid, bob_p)], f"received {received}")
    read = [e for e in got if e["kind"] == "read_changed"]
    check(len(read) == 1 and read[0]["participant"] == bob_p and read[0]["message_id"] is None, f"read {read}")
    check(all(e["message_id"] is None and e["participant"] is None for e in got if e["kind"] == "roster_changed"),
          f"roster entries {got}")
    # One entry per target: the agent reads its own, and no person's read entries.
    theirs = events(b, f"{query}&participant={eli_p}")["events"]
    check([(e["kind"], e["message_id"], e["participant"]) for e in theirs if e["kind"] != "roster_changed"]
          == [("message_received", mid, eli_p)], f"eli's entries: {theirs}")
    # The author's side.
    sent = events(a, query)["events"]
    check(any(e["kind"] == "message_sent" and e["message_id"] == mid and e["participant"] == alice_p for e in sent),
          f"alice's message_sent: {sent}")
    changed = [e for e in sent if e["kind"] == "target_changed" and e["message_id"] == mid]
    check(len(changed) == 2 and all(e["participant"] == alice_p for e in changed), f"target_changed: {changed}")
    check(not [e for e in sent if e["kind"] == "message_received"], f"alice received her own: {sent}")
    # `invited`.
    pending = start("person:bob", join=None)
    wait_invite(b, pending)
    whom = f"person:{state['person_ids']['bob']}"
    listed = [e for e in events(b)["events"] if e["kind"] == "invited" and e["conversation_id"] == pending]
    check(len(listed) == 1 and listed[0]["participant"] == whom and listed[0]["message_id"] is None,
          f"invited: {listed}")
    b.ok("conversation", "decline", pending)
    # next_after and latest; limit.
    whole = events(b)
    check(whole["next_after"] == whole["latest"] >= whole["events"][-1]["sequence"],
          f"next_after {whole['next_after']} latest {whole['latest']}")
    first, second = got[0]["sequence"], got[1]["sequence"]
    status, page = b.api("GET", f"/v1/conversations/events?limit=1&after={first - 1}{query}")
    check(status == 200 and [e["sequence"] for e in page["events"]] == [first] and page["next_after"] == first,
          f"limit=1: {status} {page}")
    status, page = b.api("GET", f"/v1/conversations/events?limit=1&after={first}{query}")
    check(status == 200 and [e["sequence"] for e in page["events"]] == [second], f"after: {status} {page}")
    high = whole["latest"] + 1000
    status, page = b.api("GET", f"/v1/conversations/events?after={high}")
    check(status == 200 and page["events"] == [] and page["next_after"] == high, f"above latest: {status} {page}")
    # wait: an empty answer after about 2 seconds, and a message ends a longer wait early.
    latest = events(b)["latest"]
    began = time.monotonic()
    status, page = b.api("GET", f"/v1/conversations/events?after={latest}&wait=2")
    took = time.monotonic() - began
    check(status == 200 and page["events"] == [] and 1.5 <= took <= 8, f"wait=2: {status} {page} in {took:.1f}s")
    timer = threading.Timer(1.0, lambda: api_say(conv, text("ends the wait")))
    timer.start()
    began = time.monotonic()
    try:
        status, page = b.api("GET", f"/v1/conversations/events?after={latest}&wait=20&conversation={conv}")
    finally:
        timer.join()
    took = time.monotonic() - began
    check(status == 200 and any(e["kind"] == "message_received" for e in page["events"]) and took < 15,
          f"wait=20 with a message: {status} {page} in {took:.1f}s")
    # Refusals.
    for bad in ("wait=26", "limit=0", "limit=1001", "unknown=1", "after=x", "wait=-1"):
        status, body = b.api("GET", f"/v1/conversations/events?{bad}")
        api_error(status, body, 400, "invalid")
    status, body = b.api("GET", f"/v1/conversations/events?participant={alice_p}")
    api_error(status, body, 400, "invalid")
    status, body = b.api("GET", f"/v1/conversations/events?conversation=conv_{'0' * 32}")
    api_error(status, body, 404, "not_found")


@suite.case("nothing_hidden_leaks", "C6 The event log (What P gets, hidden entries), GET .../messages/{message_id}, "
                                    "Words; C5 The handoff recheck; Verification Nothing hidden leaks")
def _():
    need("alice_p")
    hal = new_agent("hal")
    conv = start("bob/hal")
    hal_p = participant(hal)
    query = f"&participant={hal_p}&conversation={conv}"
    s1 = say(conv, "s1 hidden from hal")
    show_targets(a, conv, s1, hal_p, "delivered")
    check(s1 in {e["message_id"] for e in events(b, query)["events"]}, "the log lacks s1 before the deny")
    deny()
    try:
        hidden = events(b, query + "&after=0")
        check(s1 not in {e["message_id"] for e in hidden["events"]}, f"events show s1: {hidden['events']}")
        status, body = b.api("GET", f"/v1/conversations/{conv}/messages/{s1}?participant={hal_p}")
        api_error(status, body, 404, "not_found")
        reader = hidden["next_after"]
        check(reader == hidden["latest"], f"next_after {reader}, latest {hidden['latest']}")
        with Watch(b, "--as", "hal", conv) as watch:
            s2 = say(conv, "s2 refused at bob")
            t = show_targets(a, conv, s2, hal_p, "refused")
            check(t["code"] == "not_authorized", f"s2's target: {t}")
            time.sleep(1.5)
            printed = watch.text()
            check(WORD not in printed, f"watch printed a hidden or refused message: {printed!r}")
            allow()
            s3 = say(conv, "s3 after the allow")
            watch.wait_text(text("s3 after the allow"))  # the same watch still works: its silence meant something
            printed = watch.text()
            check(text("s1 hidden from hal") not in printed and text("s2 refused at bob") not in printed,
                  f"watch printed s1 or s2 after the allow: {printed!r}")
            watch.stop()
    finally:
        allow()
    # Passed over for a reader already past it, though the claim still returns it (C5).
    after = events(b, f"{query}&after={reader}")
    check(s1 not in {e["message_id"] for e in after["events"]}, f"s1 came back to the stream: {after['events']}")
    check(s3 in {e["message_id"] for e in after["events"]}, f"the stream lacks s3: {after['events']}")
    # A new read from an earlier `after` decides afresh: s1 is visible now.
    check(s1 in {e["message_id"] for e in events(b, query + "&after=0")["events"]}, "after=0 lacks s1 once allowed")
    check(claim_message(hal, s1)["messages"][0]["content"] == text("s1 hidden from hal"), "the claim of s1")


@suite.case("forget_elsewhere", "C6 `conversation forget`: CLI, Checks, What is deleted, Not on home; "
                                "Verification Forget")
def _():
    need("alice_p")
    conv = start("person:bob")
    bob_p = person_p(b, "bob")
    mid = say(conv, "will be forgotten")
    show_targets(a, conv, mid, bob_p, "delivered")
    bobs = b.ok("conversation", "say", conv, text("bob's before forgetting"))["message"]
    show_targets(b, conv, bobs["message_id"], state["alice_p"], "delivered")
    refused(b.cli("conversation", "forget", conv, "--yes"), "in_use", IN_USE)
    status, body = b.api("DELETE", f"/v1/conversations/{conv}")
    api_error(status, body, 409, "in_use", IN_USE)
    no_yes = b.cli("conversation", "forget", conv)
    check(no_yes.code == 1 and CONFIRM in no_yes.stderr, f"no --yes, no terminal: {no_yes.code} {no_yes.stderr!r}")
    check(mid in {m["message_id"] for m in api_messages(b, conv)}, "`forget` without --yes changed something")
    b.ok("conversation", "leave", conv)
    wait_view(a, conv, state["alice_p"], lambda v: bob_p in departed_of(v), "bob in departed")
    for answer in ("n\n", "maybe\n"):
        asked = b.cli("conversation", "forget", conv, input=answer, tty=True)
        check(asked.code == 0 and "Not forgotten." in asked.stdout + asked.stderr,
              f"answer {answer!r}: exit {asked.code}: {asked.stdout!r} {asked.stderr!r}")
    check(mid in {m["message_id"] for m in api_messages(b, conv)}, "`forget` answered no changed something")
    # A current pending invite for it, in a conversation this host holds, counts as still in it.
    a.ok("conversation", "add", conv, "person:bob", timeout=60)
    wait_invite(b, conv)
    refused(b.cli("conversation", "forget", conv, "--yes"), "in_use", IN_USE)
    b.ok("conversation", "decline", conv)
    forgotten = b.ok("conversation", "forget", conv[:13], "--yes")
    check(forgotten == {"conversation_id": conv, "state": "forgotten", "roster_kept": False}, f"forget: {forgotten}")
    refused(b.cli("conversation", "show", conv), "not_found", "")
    check(summary(b, conv) is None, "the list still has it")
    status, body = b.api("GET", f"/v1/conversations/{conv}/messages")
    api_error(status, body, 404, "not_found")
    status, body = b.api("GET", f"/v1/conversations/events?conversation={conv}")
    api_error(status, body, 404, "not_found")
    check(conv not in {e["conversation_id"] for e in events(b)["events"]}, "its entries are still in the log")
    status, body = b.api("DELETE", f"/v1/conversations/{conv}")
    api_error(status, body, 404, "not_found")
    state["forgotten_conv"] = conv
    # A later invite is a new start, and the author's next message never reuses a seq other hosts hold.
    a.ok("conversation", "add", conv, "person:bob", timeout=60)
    wait_invite(b, conv)
    b.ok("conversation", "join", conv, timeout=60)
    again = b.ok("conversation", "say", conv, text("bob's after forgetting"))["message"]
    check(again["seq"] > bobs["seq"], f"seq {again['seq']} after forgetting, want above {bobs['seq']}")
    show_targets(b, conv, again["message_id"], state["alice_p"], "delivered")
    b.ok("conversation", "leave", conv)
    b.ok("conversation", "forget", conv, "--yes")
    # Known only from a pending invite: not held.
    pending = start("person:bob", join=None)
    wait_invite(b, pending)
    status, body = b.api("DELETE", f"/v1/conversations/{pending}")
    api_error(status, body, 404, "not_found")
    b.ok("conversation", "decline", pending)
    # A closed conversation can be forgotten with its participants still listed.
    closed = start("person:bob")
    state["closed_conv"] = closed
    a.ok("conversation", "close", closed)
    wait_for(lambda: summary(b, closed) and summary(b, closed)["state"] == "closed", timeout=20, interval=0.3,
             message="bob to store the closed roster")
    check(b.ok("conversation", "forget", closed, "--yes")["roster_kept"] is False, "forget of a closed conversation")
    # Activity entries stay.
    check(any(e["subject_id"] == f"{conv}/{mid}" for e in activity(b)), "bob's activity lost the forgotten message")


@suite.case("forget_on_home", "C6 `conversation forget`: On home; Verification Forget")
def _():
    need("alice_p")
    fay = new_agent("fay")
    conv = start("person:bob", "bob/fay")
    bob_p, fay_p, alice_p = person_p(b, "bob"), participant(fay), state["alice_p"]
    mid = say(conv, "home forgets this")
    show_targets(a, conv, mid, bob_p, "delivered")
    refused(a.cli("conversation", "forget", conv, "--yes"), "in_use", IN_USE)
    a.ok("conversation", "leave", conv)
    forgotten = a.ok("conversation", "forget", conv, "--yes")
    check(forgotten == {"conversation_id": conv, "state": "forgotten", "roster_kept": True}, f"forget: {forgotten}")
    refused(a.cli("conversation", "show", conv), "not_found", "")
    refused(a.cli("conversation", "say", conv, text("after forget")), "not_found", "")
    check(summary(a, conv) is None, "alice's list still has it")
    status, body = a.api("DELETE", f"/v1/conversations/{conv}")
    api_error(status, body, 404, "not_found")
    # Peer routes keep serving it.
    roster_path = f"/peer/v1/conversations/{conv}/roster"
    status, body = peer(b, a, "GET", roster_path)
    check(status == 200 and body["roster"]["conversation_id"] == conv, f"roster on a forgetting home: {status} {body}")
    status, body = peer(b, a, "GET", f"/peer/v1/conversations/{conv}/heads?target={bob_p}")
    check(status == 200 and body["authors"] == [], f"heads: {status} {body}")
    status, body = peer(b, a, "GET", f"/peer/v1/conversations/{conv}/messages?author={alice_p}&target={bob_p}&after=0")
    api_error(status, body, 404, "not_found")
    status, body = peer(b, a, "POST", f"/peer/v1/conversations/{conv}/acks",
                        {"target": bob_p, "acks": [{"author": alice_p, "through_seq": 1, "refused": []}]})
    check(status == 200 and body == {"acked": 0}, f"acks: {status} {body}")

    def departed():
        status, body = peer(b, a, "GET", roster_path)
        check(status == 200, f"roster: {status} {body}")
        return {d["id"] for d in body["roster"]["departed"]}
    b.ok("conversation", "leave", conv)
    wait_for(lambda: bob_p in departed(), timeout=20, interval=0.5, message="home to list bob's person in departed")
    status, body = fay.post(f"/adapter/v1/conversations/{conv}/manage", {"action": "leave"})
    check(status == 200, f"fay leaves through manage: {status} {body}")
    wait_for(lambda: fay_p in departed(), timeout=20, interval=0.5, message="home to list fay in departed")
    subjects = {(e["kind"], e["subject_id"]) for e in activity(a)}
    check(("conversation.created", conv) in subjects, "alice's activity lost `conversation.created`")
    check(("conversation.message_sent", f"{conv}/{mid}") in subjects, "alice's activity lost the message")


@suite.case("home_unavailable", "C6 `home_unavailable`; C6 Unread (no bound person), The event log (`not_bound`), "
                                "`conversation watch` (no daemon); Verification `home_unavailable`")
def _():
    need("alice_p")
    dave = suite.host("dave")
    state["dave"] = dave
    # Before it joins: a host with no bound person.
    status, body = dave.api("GET", "/v1/conversations/events")
    api_error(status, body, 409, "not_bound")
    check(status_unread(dave) == 0, "unread without a bound person")
    key = ssh_key(dave.root, "dave")
    join_new_person(a, dave, "dave", key, state["net"])
    alice_p = state["alice_p"]

    def resolved():
        result = dave.cli("conversation", "start", "person:alice", timeout=60)
        if result.ok:
            return result.json
        check("unknown" in result.stderr, f"dave's start: {result.stderr[-300:]!r}")
        dave.api("POST", f"/v2/networks/{state['net']}/sync", {}, timeout=40)
        return None
    started = wait_for(resolved, timeout=30, interval=1, message="dave to know alice's person")
    conv = started["conversation"]["conversation_id"]
    wait_invite(a, conv)
    a.ok("conversation", "join", conv, timeout=60)
    check(view_as(a, conv, alice_p)["home_unavailable"] is False, "alice's view before the revocation")
    check(summary(a, conv)["home_unavailable"] is False, "alice's summary before the revocation")
    check(summary(dave, conv)["home_unavailable"] is False, "dave's summary (dave is home)")
    a.ok("network", "revoke", "--network", state["net"], "--host", dave.id, "--approve")
    check(view_as(a, conv, alice_p)["home_unavailable"] is True, "alice's view after the revocation")
    check(summary(a, conv)["home_unavailable"] is True, "alice's summary after the revocation")
    readable(a.cli("conversation", "show", conv), "home unavailable")
    began = time.monotonic()
    a.ok("conversation", "leave", conv)
    check(time.monotonic() - began < 5, f"a local leave took {time.monotonic() - began:.1f}s, want at once")
    # And on the host itself, always false on home.
    check(summary(dave, conv)["home_unavailable"] is False, "home_unavailable on the home host")
    dave.stop()
    stopped = dave.cli("conversation", "watch", timeout=30)
    check(stopped.code == 1, f"watch with no daemon: exit {stopped.code}, want 1: {stopped.stderr[-200:]!r}")


@suite.case("escaping_content", "C6 Terminal escaping: The rule, Readable output, JSON output; "
                                "Verification Escaping (content)")
def _():
    need("alice_p")
    conv = start("person:bob")
    bob_p = person_p(b, "bob")
    with Watch(b, conv) as watch:
        said = a.cli("conversation", "say", conv, EVIL_CONTENT)
        mid = json_output(said)["message"]["message_id"]  # `say` prints JSON: same bytes rule on alice
        check(said.json["message"]["content"] == EVIL_CONTENT, "`say` JSON does not parse back to the content")
        show_targets(a, conv, mid, bob_p, "delivered")
        printed = [r"\u001b[31m", r"\u0007", r"\u009b2J", r"\u007f", r"\u0009", r"\u000d", r"\u000a" + "fake line"]
        for piece in printed:
            watch.wait_text(piece)
        check(not RAW_CONTROL.search(watch.text()), f"watch printed a raw control character: {watch.text()!r}")
        check("\nfake line" not in watch.text(), "watch printed a forged line")
        watch.stop()
    shown = readable(b.cli("conversation", "show", conv), *printed)
    check("\nfake line" not in shown, f"`show` printed a forged line: {shown!r}")
    parsed = json_output(b.cli("conversation", "show", conv, "--json"))
    check(find_message(parsed, mid)["content"] == EVIL_CONTENT, "`show --json` does not parse back to the content")
    # The route answers the original text.
    check(find_message({"messages": api_messages(b, conv)}, mid)["content"] == EVIL_CONTENT, "the route changed it")
    # A title with a control character is refused, on the owner route and in a peer's roster.
    status, body = a.api("POST", "/v1/conversations", {"participants": ["person:bob"],
                                                       "title": f"{TITLE_WORD} \x1b[31m"})
    api_error(status, body, 400, "invalid")
    status, body = peer(b, a, "GET", f"/peer/v1/conversations/{conv}/roster")
    check(status == 200, f"roster: {status} {body}")
    roster = {**body["roster"], "version": body["roster"]["version"] + 1, "title": f"{TITLE_WORD} \x07"}
    status, body = peer(a, b, "POST", f"/peer/v1/conversations/{conv}/roster", {"roster": roster})
    api_error(status, body, 400, "invalid")
    check(view_as(b, conv, bob_p)["title"] is None, "the roster with a control character was stored")
    # U+007F to U+009F are control characters too (C6 Names), from the owner route and in a peer's roster.
    for control in ("\x9b2J", "\x7f", "\x80"):
        status, body = a.api("POST", "/v1/conversations", {"participants": ["person:bob"],
                                                           "title": f"{TITLE_WORD} {control}"})
        api_error(status, body, 400, "invalid")
        status, answer = peer(a, b, "POST", f"/peer/v1/conversations/{conv}/roster",
                              {"roster": {**roster, "title": f"{TITLE_WORD} {control}"}})
        api_error(status, answer, 400, "invalid")
    # A plain title still prints.
    plain_title = f"{TITLE_WORD} plain"
    titled = start("person:bob", "--title", plain_title)
    readable(b.cli("conversation", "show", titled), plain_title)


@suite.case("escaping_peer_text", "C6 Terminal escaping: Names, Readable output (labels, `addressed_to`, `added_by`, "
                                  "notes, error texts), JSON output; Verification Escaping (roster push)")
def _():
    need("alice_p")
    conv = start("person:bob")
    bob_p = person_p(b, "bob")
    evil_id = "agent_" + os.urandom(16).hex()
    evil_p = f"agent:{a.id}/{evil_id}"
    origin = {"agent_id": evil_id, "session_id": "session_" + os.urandom(16).hex()}
    status, body = peer(b, a, "GET", f"/peer/v1/conversations/{conv}/roster")
    check(status == 200, f"roster: {status} {body}")
    now = rfc3339(suite.now())
    evil = {"id": evil_p, "kind": "agent", "host_id": a.id, "person_id": state["alice_person"], "agent_id": evil_id,
            "name": EVIL_NAME, "state": "joined", "added_by": state["alice_p"], "added_at": now}
    version = body["roster"]["version"] + 1
    roster = {**body["roster"], "version": version, "participants": [*body["roster"]["participants"], evil]}
    status, answer = peer(a, b, "POST", f"/peer/v1/conversations/{conv}/roster", {"roster": roster})
    check(status == 200 and answer == {"version": version}, f"a name with control characters: {status} {answer}")
    label = f"alice/{EVIL_NAME_PRINTED}"
    with Watch(b, conv) as watch:
        # The label as participant, as author and in `addressed_to`.
        m = probe_message(conv, version, 300_001, EVIL_CONTENT, author=evil_p, origin=origin, addressed_to=[evil_p])
        status, answer = probe_person(conv, m)
        check(status == 200, f"a message from the named agent: {status} {answer}")
        watch.wait_text(label)
        watch.wait_text(f"to {label}")
        check(not RAW_CONTROL.search(watch.text()), f"watch printed a raw control character: {watch.text()!r}")
        check("\nfake-name" not in watch.text(), f"watch printed a forged line: {watch.text()!r}")
        watch.stop()
    shown = readable(b.cli("conversation", "show", conv), label, f"to {label}")
    check("\nfake-name" not in shown and "\nfake line" not in shown, f"`show` printed a forged line: {shown!r}")
    listed = readable(b.cli("conversations"), label)
    check("\nfake-name" not in listed, f"`conversations` printed a forged line: {listed!r}")
    parsed = json_output(b.cli("conversation", "show", conv, "--json"))
    message = find_message(parsed, m["message_id"])
    check(message["author_label"] == f"alice/{EVIL_NAME}" and message["addressed_to_labels"] == [f"alice/{EVIL_NAME}"],
          f"`show --json` labels: {message}")
    check(json_output(b.cli("conversations", "--json")) is not None, "`conversations --json`")
    # Invite notes and `added_by` labels, from a peer's person invite.
    invite_conv = "conv_" + os.urandom(16).hex()
    note = f"note \x1b]0;evil\x07 \x9b2J\nfake-note"
    person_id = state["person_ids"]["bob"]
    invited = {
        "conversation_id": invite_conv, "home_host_id": a.id, "version": 2, "state": "open",
        "created_by": state["alice_p"], "created_at": now, "departed": [],
        "participants": [
            {"id": state["alice_p"], "kind": "person", "host_id": a.id, "person_id": state["alice_person"],
             "agent_id": None, "name": None, "state": "joined", "added_by": None, "added_at": now},
            evil,
            {"id": None, "kind": "person", "host_id": None, "person_id": person_id, "agent_id": None, "name": None,
             "state": "invited", "added_by": evil_p, "added_at": now}]}
    status, answer = peer(a, b, "POST", "/peer/v1/conversations/invites",
                          {"conversation_id": invite_conv, "roster": invited,
                           "target": {"kind": "person", "person_id": person_id}, "adder": evil_p, "note": note,
                           "origin": origin})
    check(status == 200 and answer == {"state": "invited"}, f"an invite with a note: {status} {answer}")
    shown = readable(b.cli("conversations", "--invites"), f"from {label}")
    check("\nfake" not in shown, f"`conversations --invites` printed a forged line: {shown!r}")
    parsed = json_output(b.cli("conversations", "--invites", "--json"))
    entry = next(i for i in parsed["invites"] if i["conversation_id"] == invite_conv)
    check(entry["note"] == note and entry["added_by_label"] == f"alice/{EVIL_NAME}", f"invite JSON {entry}")
    b.ok("conversation", "decline", invite_conv)
    # `error: CODE: TEXT` on stderr: whatever a failing command echoes is escaped.
    bad = "\x1b[31mbad\x9b2J"
    for args in (("conversation", "show", f"conv_abcdef{bad}"), ("conversation", "start", f"bob/{bad}"),
                 ("conversation", "say", conv, text("to bad"), "--to", bad),
                 ("conversation", "show", conv, "--as", bad)):
        result = b.cli(*args)
        check(result.code != 0 and result.stderr.strip() and not RAW_CONTROL.search(result.stderr)
              and "\ufffd" not in result.stderr,
              f"`{' '.join(args[:2])}`: exit {result.code}, stderr {result.stderr!r}")


@suite.case("activity", "C6 Activity; Verification Activity")
def _():
    conv = need("read_conv")[0]
    # Every case above used these conversations; what they did must all be here, as subjects only.
    limit, local, local_message, refused_subject, closed, _ = need("limit_conv", "local_conv", "local_message",
                                                                   "refused_subject", "closed_conv", "forgotten_conv")
    for host in (a, b):
        result = host.cli("activity", "--limit", "1000")
        check(result.ok, f"{host.name}: activity: exit {result.code}: {result.stderr[-200:]!r}")
        for word in (WORD, TITLE_WORD, "fake line", "fake-name", "ev\\u001b"):
            check(word not in result.stdout, f"{host.name}: activity holds {word!r}")
    entries = {h.name: activity(h) for h in (a, b)}
    for name, listed in entries.items():
        for e in listed:
            check(set(e) >= {"sequence", "kind", "subject_id", "created_at"}, f"{name}: entry {e}")
            pattern = MESSAGE_SUBJECT if ".message_" in e["kind"] else CONV_SUBJECT
            check(pattern.match(e["subject_id"]), f"{name}: {e['kind']} subject {e['subject_id']}")
    for name, kinds in (("alice", ("created", "roster_changed", "closed", "message_sent", "message_received",
                                   "message_refused")),
                        ("bob", ("roster_changed", "closed", "message_sent", "message_received"))):
        have = {e["kind"] for e in entries[name]}
        for kind in kinds:
            check(f"conversation.{kind}" in have, f"{name}: no conversation.{kind} in {sorted(have)}")
    alice = {(e["kind"], e["subject_id"]) for e in entries["alice"]}
    check(("conversation.message_refused", refused_subject) in alice, f"alice lacks the refusal of {refused_subject}")
    check(("conversation.created", conv) in alice and ("conversation.closed", closed) in alice,
          "alice lacks created or closed")
    # Once per message; a local delivery is one message_sent only; a repeat records nothing.
    subject = f"{local}/{local_message}"
    of = [e["kind"] for e in entries["alice"] if e["subject_id"] == subject]
    check(of == ["conversation.message_sent"], f"the local delivery recorded {of}, want one message_sent")
    # (A forgotten conversation's messages may be stored again after a later invite: `conversation forget`.)
    received = [e["subject_id"] for e in entries["bob"] if e["kind"] == "conversation.message_received"
                and not e["subject_id"].startswith(state["forgotten_conv"])]
    check(len(received) == len(set(received)), "bob recorded a message_received twice")
    created = [e["subject_id"] for e in entries["alice"] if e["kind"] == "conversation.created"]
    check(len(created) == len(set(created)), "a conversation was created twice")
    before = len(activity(a))
    status, body = state["ada"].post(f"/adapter/v1/conversations/{local}/messages",
                                     {"content": text("ada 60"), "message_id": local_message})
    check(status == 200, f"repeat: {status} {body}")
    check(len(activity(a)) == before, "a repeat recorded activity")
    # The creating and the closing roster are not `roster_changed`.
    fresh = start("alice/ada", join=None)
    of = [e["kind"] for e in activity(a) if e["subject_id"] == fresh]
    check(of.count("conversation.created") == 1, f"a new conversation recorded {of}")
    a.ok("conversation", "close", fresh)
    after = [e["kind"] for e in activity(a) if e["subject_id"] == fresh]
    check(after.count("conversation.closed") == 1 and after.count("conversation.roster_changed")
          == of.count("conversation.roster_changed"), f"closing recorded {after}, before it {of}")
    check(limit in {e["subject_id"].split("/")[0] for e in entries["bob"]}, "bob's activity lacks the limit one")


@suite.case("help", "C6 Commands (CONV-24); Verification Help")
def _():
    root = a.cli("--help")
    advanced = a.cli("help", "advanced")
    for name, result in (("root", root), ("advanced", advanced)):
        check(result.ok, f"{name} help: exit {result.code}")
        for command in ("conversations", "conversation"):
            check(re.search(rf"^\s*(peerspan\s+)?{command}\b", result.stdout, re.MULTILINE),
                  f"the {name} help lists no `{command}`: {result.stdout!r}")
    check("conversation sync" not in root.stdout, "the root help lists `conversation sync`")
    repo = Path(__file__).resolve().parents[2]
    for path in (repo / "README.md", repo / "docs" / "quick-start.md"):
        words = path.read_text()
        check(re.search(r"\bconversations\b", words) and re.search(r"\bconversation (start|say|show)\b", words),
              f"{path.name} does not list the conversation commands")
        check("conversation sync" not in words, f"{path.name} lists `conversation sync`")


@suite.case("window", "C6 A message's time, The rate limit; a watch survives a daemon restart (`conversation watch`); "
                      "Verification The window, Clock (last)")
def _():
    conv, agent = need("limit_conv", "limit_agent")
    with Watch(b, state["read_conv"]) as watch:
        suite.set_offset(3601)
        a.restart()
        b.restart()
        said = a.ok("conversation", "say", conv, text("an hour later"))["message"]
        check(said["seq"] == 61, f"seq {said['seq']}, want 61: a refused attempt uses none")
        show_targets(a, conv, said["message_id"], agent, "delivered")  # bob's hour has passed too
        # A failure after it started is retried until the daemon answers again.
        say(state["read_conv"], "after the restart")
        watch.wait_text(text("after the restart"), timeout=30)
        watch.stop()


suite.finish()
