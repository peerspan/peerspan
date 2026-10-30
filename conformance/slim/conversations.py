#!/usr/bin/env python3
"""Slim suite, conversations: C1, two hosts and one message each way; C2, membership.

alice creates a coordinator-free network and bob joins it. bob's fixture agent `bert` has a directory
session with a verified channel, and bob allows alice `message.append`. alice starts a conversation with
`bob/bert` and a first message; bert claims it and replies through the adapter route; repeats, a refusal
after `deny alice`, and the edges of the local, adapter and CLI surfaces follow. C2 adds a third host carol
with fixture agent `cara`, local agents on alice, and membership changes (add, remove, leave, close, the
unanswered drop on the test clock, run last). Written from docs/conversations-contract.md, sections C1 and C2
(cited as "C1 <part>" and "C2 <part>"), only.
"""
import json
import os
import re
import subprocess

from harness import Suite, check, create_network, in_future, join_new_person, ssh_key, wait_for

suite = Suite("conversations", __doc__)
suite.use_clock()  # C2 Verification: the unanswered case moves the test clock; it must be set before hosts start
a, b = suite.host("alice"), suite.host("bob")
state = {}

CONV_ID = re.compile(r"^conv_[0-9a-f]{32}$")
MSG_ID = re.compile(r"^cmsg_[0-9a-f]{32}$")
NOT_ID = re.compile(r"^cnot_[0-9a-f]{32}$")
CLAIM = "/adapter/v1/conversation-notifications/next"
NOT_PARTICIPANT = "This participant is not in that conversation."
CONFLICT = "This message_id was already used with different content."
NOT_BOUND = "This host is not bound to a person; conversations need one (peerspan join)."


def refused(result, code, text):
    """A CLI refusal: exit 1 and `error: CODE: TEXT` on stderr (C1 Errors)."""
    want = f"error: {code}: {text}"
    check(result.code == 1 and want in result.stderr,
          f"`{' '.join(result.args[:3])}`: exit {result.code}, stderr {result.stderr.strip()[-300:]!r}, want {want!r}")


def api_error(status, body, http, code, text=None):
    ok = status == http and isinstance(body, dict) and body.get("code") == code
    if text is not None:
        ok = ok and body.get("error") == text
    check(ok, f"answer {status} {body}, want {http} {code} {text or ''}")


def need(*names):
    missing = [n for n in names if n not in state]
    check(not missing, f"an earlier case did not finish ({', '.join(missing)} missing)")
    return [state[n] for n in names]


def message_id():
    return "cmsg_" + os.urandom(16).hex()


def policy_version(host, person_public_key):
    status, body = host.api("GET", f"/v2/networks/{state['net']}/access-versions")
    check(status == 200, f"{host.name}: access-versions: {status} {body}")
    return max((p["version"] for p in body["policies"] if p["person_public_key"] == person_public_key), default=0)


def wait_policy(version, hosts):
    """Sync until every host holds bob's policy at VERSION or later (spec 10), as work.py does."""
    for host in hosts:
        def ready(host=host):
            status, body = host.api("POST", f"/v2/networks/{state['net']}/sync", {}, timeout=40)
            check(status == 200, f"{host.name}: sync: {status} {body}")
            return policy_version(host, state["bob_public"]) >= version
        wait_for(ready, timeout=30, interval=1, message=f"{host.name} to hold bob's policy version {version}")


def show(host, *extra):
    view = host.ok("conversation", "show", state["conv"], "--json", *extra)
    check(isinstance(view, dict) and {"conversation", "messages", "next_before_message_id"} <= set(view),
          f"{host.name}: show --json shape: {view}")
    return view


def find_message(view, mid):
    found = [m for m in view["messages"] if m["message_id"] == mid]
    check(len(found) == 1, f"message {mid} appears {len(found)} times in {[m['message_id'] for m in view['messages']]}")
    return found[0]


def target_of(message, participant):
    check(isinstance(message["targets"], list), f"own message {message['message_id']} has targets {message['targets']}")
    found = [t for t in message["targets"] if t["participant"] == participant]
    check(len(found) == 1, f"target {participant} in {message['targets']}")
    return found[0]


def wait_target(host, mid, participant, want, extra=(), timeout=30):
    """Poll `conversation show --json` until MID's target for PARTICIPANT leaves `sending`; return it."""
    last = {}

    def settled():
        t = target_of(find_message(show(host, *extra), mid), participant)
        last["t"] = t
        return t if t["state"] != "sending" else None
    try:
        t = wait_for(settled, timeout=timeout, interval=0.5, message=f"{mid} target {participant} to be {want}")
    except AssertionError:
        raise AssertionError(f"target of {mid} for {participant} still {last.get('t')}, want {want}") from None
    check(t["state"] == want, f"target of {mid} for {participant}: {t}, want {want}")
    return t


def claim(adapter, timeout=30):
    def got():
        status, body = adapter.post(CLAIM, {})
        check(status == 200, f"{adapter.name}: claim: {status} {body}")
        return body
    return wait_for(got, timeout=timeout, interval=0.3, message=f"a conversation notification for {adapter.name}")


def forwarded(adapter, notification_id):
    status, body = adapter.post(f"/adapter/v1/conversation-notifications/{notification_id}/forwarded", {})
    check(status == 200 and isinstance(body, dict) and body.get("notification", {}).get("id") == notification_id,
          f"{adapter.name}: forwarded {notification_id}: {status} {body}")
    return body["notification"]


def in_display_order(messages):
    keys = [(m["clock"], m["author"].encode(), m["seq"]) for m in messages]
    return keys == sorted(keys)


@suite.case("setup", "C1 Verification setup; decentralized-spec 6, 8")
def _():
    net = create_network(a, "conversations", "alice")
    state["net"] = net["id"]
    key = ssh_key(b.root, "bob")
    state["bob_key"] = key
    join_new_person(a, b, "bob", key, net["id"])
    state["bert"] = b.agent("bert")
    allow = b.ok("allow", "alice", "--no-tasks", "--person-key", key)
    check(allow["actions"] == ["message.append"], f"allow --no-tasks: {allow}")
    state["alice_person"] = allow["principal"].split(":", 1)[1]
    status, network = b.api("GET", f"/v2/networks/{net['id']}")
    check(status == 200, f"bob: network: {status} {network}")
    state["bob_public"] = network["person_public_key"]
    wait_policy(allow["policy"]["version"], (b, a))
    state["alice_participant"] = f"person:{a.id}/{state['alice_person']}"
    state["bert_participant"] = f"agent:{b.id}/{state['bert'].id}"


@suite.case("start_and_deliver", "C1 Starting steps 1-7, Invite outcome, Views, Fan-out and retry")
def _():
    alice_p, bert_p, bert = need("alice_participant", "bert_participant", "bert")
    started = a.ok("conversation", "start", "bob/bert", "--title", "Flaky checkout test", "--message",
                   "hello bert", timeout=60)
    check(isinstance(started, dict) and {"conversation", "invites", "message"} <= set(started), f"start: {started}")
    conv = started["conversation"]
    check(CONV_ID.match(conv["conversation_id"] or ""), f"conversation_id {conv.get('conversation_id')}")
    state["conv"] = conv["conversation_id"]
    check(len(started["invites"]) == 1, f"invites {started['invites']}")
    inv = started["invites"][0]
    check(inv["target"] == "bob/bert" and inv["participant"] == bert_p and inv["state"] == "joined"
          and inv["code"] is None and inv["label"] == "bob/bert", f"invite outcome {inv}")
    check(conv["title"] == "Flaky checkout test" and conv["state"] == "open" and conv["home_host_id"] == a.id
          and conv["roster_version"] == 2 and conv["created_by"] == alice_p, f"conversation view {conv}")
    parts = {p["id"]: p for p in conv["participants"]}
    check(set(parts) == {alice_p, bert_p}, f"participants {sorted(parts)}")
    check(parts[alice_p]["kind"] == "person" and parts[alice_p]["state"] == "joined" and parts[alice_p]["local"] is True
          and parts[alice_p]["added_by"] is None and parts[alice_p]["label"] == "alice", f"alice {parts[alice_p]}")
    check(parts[bert_p]["kind"] == "agent" and parts[bert_p]["state"] == "joined" and parts[bert_p]["local"] is False
          and parts[bert_p]["name"] == "bert" and parts[bert_p]["label"] == "bob/bert"
          and parts[bert_p]["agent_id"] == bert.id and parts[bert_p]["host_id"] == b.id
          and parts[bert_p]["added_by"] == alice_p, f"bert {parts[bert_p]}")
    state["bob_person"] = parts[bert_p]["person_id"]
    msg = started["message"]
    check(isinstance(msg, dict) and MSG_ID.match(msg["message_id"] or ""), f"first message {msg}")
    check(msg["conversation_id"] == state["conv"] and msg["author"] == alice_p and msg["author_kind"] == "person"
          and msg["seq"] == 1 and msg["clock"] == 1 and msg["content"] == "hello bert" and msg["mine"] is True
          and msg["addressed_to"] == [] and msg["roster_version"] == 2, f"first message view {msg}")
    check([t["participant"] for t in msg["targets"]] == [bert_p], f"first message targets {msg['targets']}")
    state["first"] = msg["message_id"]
    t = wait_target(a, msg["message_id"], bert_p, "delivered")
    check(t["code"] is None and t["label"] == "bob/bert" and t["attempts"] >= 1, f"delivered target {t}")
    view = show(a)
    check(view["conversation"]["conversation_id"] == state["conv"] and view["conversation"]["roster_version"] == 2,
          f"show conversation {view['conversation']}")


@suite.case("claim", "C1 Adapter routes: Claiming, Notification, Claim")
def _():
    bert, first, alice_p, alice_person = need("bert", "first", "alice_participant", "alice_person")
    got = claim(bert)
    n = got["notification"]
    check(NOT_ID.match(n["id"] or "") and n["kind"] == "message" and n["conversation_id"] == state["conv"]
          and n["message_id"] == first and n["session_id"] == bert.session_id and n["claimed_at"]
          and n["forwarded_at"] is None, f"notification {n}")
    check(len(got["messages"]) == 1, f"claim messages {got['messages']}")
    m = got["messages"][0]
    check(m["message_id"] == first and m["content"] == "hello bert" and m["author"] == alice_p
          and m["author_kind"] == "person" and m["author_label"] == "alice" and m["seq"] == 1 and m["clock"] == 1
          and m["origin_agent_id"] is None and m["sender_person"] == "alice"
          and m["sender_person_id"] == alice_person and m["addressed"] is True and m["mine"] is False
          and m["addressed_to"] == [], f"claimed message {m}")
    c = got["conversation"]
    check(c["conversation_id"] == state["conv"] and c["unseen"] == 1 and c["creator"] is False
          and c["title"] == "Flaky checkout test" and c["state"] == "open" and c["home_host_id"] == a.id,
          f"claim summary {c}")
    you = [p["id"] for p in c["participants"] if p["you"]]
    check(you == [state["bert_participant"]], f"`you` marks {you}")
    check(got["window"] == [] and got["window_total"] == 0 and got["redelivered"] is False,
          f"window {got['window']} total {got['window_total']} redelivered {got['redelivered']}")
    status, again = bert.post(CLAIM, {})
    check(status == 200 and again is None, f"second claim: {status} {again}")
    one = forwarded(bert, n["id"])
    check(one["forwarded_at"], f"forwarded_at not set: {one}")
    two = forwarded(bert, n["id"])
    check(two == one and two["forwarded_at"] == one["forwarded_at"], f"forwarded is not idempotent: {one} then {two}")
    status, body = bert.post(f"/adapter/v1/conversation-notifications/cnot_{os.urandom(16).hex()}/forwarded", {})
    check(status == 404 and isinstance(body, dict) and body.get("code") == "not_found",
          f"forwarded of an unknown notification: {status} {body}")


@suite.case("reply", "C1 Adapter routes (sending), Message clock, Display order, Who may see what")
def _():
    bert, first, alice_p, bert_p = need("bert", "first", "alice_participant", "bert_participant")
    mid = message_id()
    status, body = bert.post(f"/adapter/v1/conversations/{state['conv']}/messages",
                             {"content": "hello alice", "message_id": mid})
    check(status == 200 and isinstance(body, dict), f"bert send: {status} {body}")
    m = body["message"]
    check(m["message_id"] == mid and m["author"] == bert_p and m["author_kind"] == "agent" and m["seq"] == 1
          and m["clock"] == 2 and m["mine"] is True, f"bert's message {m}")
    check([t["participant"] for t in body["targets"]] == [alice_p], f"bert's targets {body['targets']}")
    state["reply"], state["reply_seq"] = mid, m["seq"]
    wait_target(b, mid, alice_p, "delivered", extra=("--as", "bert"))
    view = show(a)
    ids = [x["message_id"] for x in view["messages"]]
    check(ids == [first, mid], f"alice's show lists {ids}, want [{first}, {mid}]")
    check(in_display_order(view["messages"]), "messages not in (clock, author, seq) order")
    theirs, mine = find_message(view, mid), find_message(view, first)
    check(theirs["clock"] == 2 and theirs["seq"] == 1 and theirs["author_label"] == "bob/bert"
          and theirs["author_kind"] == "agent" and theirs["mine"] is False and theirs["targets"] is None
          and theirs["content"] == "hello alice", f"bert's message on alice {theirs}")
    check(mine["mine"] is True and isinstance(mine["targets"], list) and mine["targets"], f"alice's own {mine}")
    readable = a.cli("conversation", "show", state["conv"])
    check(readable.ok and "hello bert" in readable.stdout and "hello alice" in readable.stdout
          and "(you)" in readable.stdout, f"readable show: {readable.stdout[-600:]}")
    check(readable.stdout.index("hello bert") < readable.stdout.index("hello alice"), "readable show is not in order")


@suite.case("repeats", "C1 Sending: Repeats")
def _():
    bert, mid, seq, bert_p = need("bert", "reply", "reply_seq", "bert_participant")
    path = f"/adapter/v1/conversations/{state['conv']}/messages"
    status, body = bert.post(path, {"content": "hello alice", "message_id": mid})
    check(status == 200 and body["message"]["message_id"] == mid and body["message"]["seq"] == seq,
          f"identical repeat from bert: {status} {body}")
    status, body = bert.post(path, {"content": "something else", "message_id": mid})
    api_error(status, body, 409, "conflict", CONFLICT)
    # The same on alice's host, through `conversation say --message-id`.
    said_id = message_id()
    said = a.ok("conversation", "say", state["conv"], "second from alice", "--message-id", said_id)
    check(said["message"]["message_id"] == said_id and said["message"]["seq"] == 2, f"say {said['message']}")
    again = a.ok("conversation", "say", state["conv"], "second from alice", "--message-id", said_id)
    check(again["message"]["message_id"] == said_id and again["message"]["seq"] == 2
          and len(again["targets"]) == 1, f"identical say repeat {again}")
    clash = a.cli("conversation", "say", state["conv"], "different", "--message-id", said_id)
    refused(clash, "conflict", CONFLICT)
    status, body = a.api("POST", f"/v1/conversations/{state['conv']}/messages",
                         {"content": "different", "message_id": said_id})
    api_error(status, body, 409, "conflict", CONFLICT)
    view = show(a)
    ids = [x["message_id"] for x in view["messages"]]
    check(ids.count(mid) == 1 and ids.count(said_id) == 1 and len(ids) == 3, f"messages after repeats {ids}")
    check(in_display_order(view["messages"]), "messages not in (clock, author, seq) order")
    wait_target(a, said_id, bert_p, "delivered")
    # bert gets exactly one notification for it; it is not the session's first, so no window.
    got = claim(bert)
    check(got["notification"]["message_id"] == said_id and got["messages"][0]["seq"] == 2
          and got["messages"][0]["clock"] == 3 and got["window"] == [] and got["window_total"] == 0 and got["conversation"]["unseen"] == 1,
          f"second claim {got}")
    forwarded(bert, got["notification"]["id"])
    status, none = bert.post(CLAIM, {})
    check(status == 200 and none is None, f"a repeated say made another notification: {status} {none}")


@suite.case("edges", "C1 Adapter routes (directory, claiming), Local API (participant), CLI (ID prefix)")
def _():
    (bert,) = need("bert")
    conv = state.get("conv")
    check(conv, "no conversation was started")
    # A session whose channel is not verified: the claim route answers 409 and claims nothing.
    unverified = b.agent("bix", ready=False)
    status, body = unverified.post(CLAIM, {})
    check(status == 409 and isinstance(body, dict) and body.get("code") == "conflict"
          and body.get("error") == "channel not verified", f"claim before verification: {status} {body}")
    # The adapter sending route works before verification, and bix is not in the conversation.
    status, body = unverified.post(f"/adapter/v1/conversations/{conv}/messages", {"content": "x"})
    api_error(status, body, 403, "not_participant", NOT_PARTICIPANT)
    # A session without directory access: null from the claim route, 403 no_directory from the sending route.
    nodir = b.agent("nodi", directory=False)
    status, body = nodir.post(CLAIM, {})
    check(status == 200 and body is None, f"claim without directory access: {status} {body}")
    status, body = nodir.post(f"/adapter/v1/conversations/{conv}/messages", {"content": "x"})
    check(status == 403 and isinstance(body, dict) and body.get("code") == "no_directory",
          f"send without directory access: {status} {body}")
    # bob's person is not a participant: `conversation say` on bob's host fails with not_participant.
    say = b.cli("conversation", "say", conv, "hi from bob")
    refused(say, "not_participant", NOT_PARTICIPANT)
    status, body = b.api("POST", f"/v1/conversations/{conv}/messages", {"content": "hi from bob"})
    api_error(status, body, 403, "not_participant", NOT_PARTICIPANT)
    # Reads: an unknown conversation is 404, a participant that is not local is 400.
    status, body = a.api("GET", f"/v1/conversations/conv_{os.urandom(16).hex()}")
    check(status == 404 and isinstance(body, dict) and body.get("code") == "not_found", f"unknown: {status} {body}")
    status, body = a.api("GET", f"/v1/conversations/{conv}?participant={state['bert_participant']}")
    check(status == 400 and isinstance(body, dict) and body.get("code") == "invalid",
          f"a remote participant on alice: {status} {body}")
    # `conversations --json` lists it on both hosts (bert is joined on bob's host).
    for host in (a, b):
        listed = host.ok("conversations", "--json")
        check(any(x["conversation_id"] == conv for x in listed["conversations"]),
              f"{host.name}: conversations --json does not list {conv}: {listed}")
    # An ID prefix: `conv_` and 6 hex digits.
    prefix = conv[:11]
    view = a.ok("conversation", "show", prefix, "--json")
    check(view["conversation"]["conversation_id"] == conv, f"show {prefix}: {view['conversation']}")


@suite.case("start_refusals", "C1 Starting steps 1 and 3")
def _():
    need("bert")
    before = {x["conversation_id"] for x in a.ok("conversations", "--json")["conversations"]}
    for body, http, code in (({"participants": ["bob/bert", "bob/bert"]}, 400, "invalid"),
                             ({"participants": ["bob"]}, 400, "invalid"),
                             ({"participants": ["bob/bert"], "note": "hi"}, 400, "invalid"),
                             ({"participants": ["bob/bert"], "title": None}, 400, "invalid"),
                             ({"participants": ["bob/nobody"]}, 404, "unknown")):
        status, answer = a.api("POST", "/v1/conversations", body)
        check(status == http and isinstance(answer, dict) and answer.get("code") == code,
              f"start {body}: {status} {answer}, want {http} {code}")
    after = {x["conversation_id"] for x in a.ok("conversations", "--json")["conversations"]}
    check(after == before, f"a refused start persisted a conversation: {sorted(after - before)}")


@suite.case("not_bound", "C1 Local API (no bound person), Errors")
def _():
    need("bert")
    carol = suite.host("carol")  # never joins a network, so no person is bound
    status, body = carol.api("POST", "/v1/conversations", {"participants": ["bob/bert"]})
    api_error(status, body, 409, "not_bound", NOT_BOUND)
    refused(carol.cli("conversation", "start", "bob/bert"), "not_bound", NOT_BOUND)
    carol.stop()


def probe(sender, receiver, path, body):
    args = [str(suite.probe_bin), "--address", receiver.peer_address, "--alpn", "peerspan-peer/1", "--path", path,
            "--method", "POST", "--state", str(sender.state), "--body-stdin"]
    p = subprocess.run(args, input=json.dumps(body).encode(), capture_output=True, timeout=45)
    return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")


@suite.case("invite_roster_checks", "C1 Peer routes: POST /peer/v1/conversations/invites (roster)")
def _():
    bert, alice_p, bert_p, bob_person = need("bert", "alice_participant", "bert_participant", "bob_person")
    version = policy_version(b, state["bob_public"])
    now = in_future(seconds=0)

    def body(mutate=None):
        conv = "conv_" + os.urandom(16).hex()
        roster = {
            "conversation_id": conv, "home_host_id": a.id, "version": 2, "state": "open", "created_by": alice_p,
            "created_at": now, "departed": [],
            "participants": [
                {"id": alice_p, "kind": "person", "host_id": a.id, "person_id": state["alice_person"],
                 "agent_id": None, "name": None, "state": "joined", "added_by": None, "added_at": now},
                {"id": bert_p, "kind": "agent", "host_id": b.id, "person_id": bob_person, "agent_id": bert.id,
                 "name": "bert", "state": "joined", "added_by": alice_p, "added_at": now}]}
        if mutate:
            mutate(roster)
        return conv, {"conversation_id": conv, "roster": roster, "target": {"kind": "agent", "agent_id": bert.id},
                      "adder": alice_p, "policy": {"person_id": bob_person, "version": version}}

    def send(mutate=None):
        conv, request = body(mutate)
        code, out, err = probe(a, b, "/peer/v1/conversations/invites", request)
        check(code == 0, f"probe: exit {code} {err.strip()[-300:]}")
        answer = json.loads(out)  # the probe prints {status, body}
        return answer["status"], answer["body"]

    # A consistent invite is answered joined, so the refusals below come from the roster rule alone.
    status, answer = send()
    check(status == 200 and answer == {"state": "joined", "name": "bert"},
          f"a consistent invite: {status} {answer}, want 200 joined")
    cases = {
        "a repeated participant id": lambda r: r["participants"].append(dict(r["participants"][0])),
        "agent_id not matching the id": lambda r: r["participants"][1].update(agent_id="agent_" + "0" * 32),
        "kind not matching the id": lambda r: r["participants"][0].update(kind="agent"),
        "host_id not matching the id": lambda r: r["participants"][0].update(host_id=b.id),
    }
    for what, mutate in cases.items():
        status, answer = send(mutate)
        check(status == 400 and isinstance(answer, dict) and answer.get("code") == "invalid",
              f"invite with {what}: {status} {answer}, want 400 invalid")


@suite.case("refused_after_deny", "C1 Fan-out and retry (citation, 403 -> refused not_authorized); CLI show")
def _():
    bert, bert_p, key, _conv = need("bert", "bert_participant", "bob_key", "conv")
    before = policy_version(b, state["bob_public"])
    b.ok("deny", "alice", "--person-key", key)
    version = policy_version(b, state["bob_public"])
    check(version > before, f"deny did not sign a new policy version ({before} -> {version})")
    wait_policy(version, (a,))
    said = a.ok("conversation", "say", state["conv"], "after deny")
    mid = said["message"]["message_id"]
    t = wait_target(a, mid, bert_p, "refused")
    check(t["code"] == "not_authorized", f"refused target {t}")
    state["denied"] = True
    readable = a.cli("conversation", "show", state["conv"])
    check(readable.ok and "not received by bob/bert (refused: not_authorized)" in readable.stdout,
          f"readable show after refusal: {readable.stdout[-600:]}")
    status, body = bert.post(CLAIM, {})
    check(status == 200 and body is None, f"bert got a notification after deny: {status} {body}")


@suite.case("grant_byte_limit", "C1 Peer routes: Authorization citation, Acceptance 1 and 5 (max_message_bytes 403)")
def _():
    bert, bert_p, _deny = need("bert", "bert_participant", "denied")
    # With no rule for alice left, a grant to alice's host with a 16-byte limit is the only thing allowing her.
    status, grant = b.api("POST", "/v1/grants", {"requester_host_id": a.id, "target_agent_id": bert.id,
                                                 "expires_at": in_future(hours=1), "max_message_bytes": 16})
    check(status == 201, f"grant create: {status} {grant}")
    small = a.ok("conversation", "say", state["conv"], "sixteen bytes ok")["message"]["message_id"]
    wait_target(a, small, bert_p, "delivered")
    got = claim(bert)
    check(got["notification"]["message_id"] == small, f"bert claimed {got['notification']}")
    forwarded(bert, got["notification"]["id"])
    big = a.ok("conversation", "say", state["conv"], "seventeen bytes!!")["message"]["message_id"]
    t = wait_target(a, big, bert_p, "refused")
    check(t["code"] == "not_authorized", f"over-limit target {t}")
    status, body = bert.post(CLAIM, {})
    check(status == 200 and body is None, f"bert got the over-limit message: {status} {body}")


# C2: membership. A third host carol (fixture agent cara), local agents on alice, and roster changes.

NOT_CREATOR = "Only the conversation's creator can add, remove, or close."
CLOSED = "This conversation is closed."
FULL = "A conversation has at most 16 participants."
NO_PARTICIPANT = "No such participant in that conversation."
MAX_SAFE = 2 ** 53 - 1


def peer(sender, receiver, method, path, body=None):
    """One raw peer request with `peerspan-peer-probe` from SENDER's state; returns (status, body)."""
    args = [str(suite.probe_bin), "--address", receiver.peer_address, "--alpn", "peerspan-peer/1", "--path", path,
            "--method", method, "--state", str(sender.state)]
    if body is not None:
        args.append("--body-stdin")
    p = subprocess.run(args, input=json.dumps(body).encode() if body is not None else b"", capture_output=True,
                       timeout=45)
    check(p.returncode == 0, f"probe {method} {path}: exit {p.returncode} {p.stderr.decode(errors='replace')[-300:]}")
    answer = json.loads(p.stdout)
    return answer["status"], answer["body"]


def owner_policy(owner, public_key):
    return policy_version(owner, public_key)


def wait_policies(wanted, hosts):
    """Sync until every host holds each {person_public_key: version} (spec 10)."""
    for host in hosts:
        def ready(host=host):
            status, body = host.api("POST", f"/v2/networks/{state['net']}/sync", {}, timeout=40)
            check(status == 200, f"{host.name}: sync: {status} {body}")
            return all(policy_version(host, key) >= version for key, version in wanted.items())
        wait_for(ready, timeout=30, interval=1, message=f"{host.name} to hold the setup policies")


def drain(adapter):
    """Claim and forward every notification ADAPTER has now; return the claims."""
    got = []
    while True:
        status, body = adapter.post(CLAIM, {})
        check(status == 200, f"{adapter.name}: claim: {status} {body}")
        if body is None:
            return got
        forwarded(adapter, body["notification"]["id"])
        got.append(body)


def claim_next(adapter, timeout=30):
    got = claim(adapter, timeout=timeout)
    forwarded(adapter, got["notification"]["id"])
    return got


def claim_until(adapter, match, what, timeout=30):
    """Claim (and forward) ADAPTER's notifications until one MATCHes; return it."""
    seen = []

    def found():
        status, body = adapter.post(CLAIM, {})
        check(status == 200, f"{adapter.name}: claim: {status} {body}")
        if body is None:
            return None
        forwarded(adapter, body["notification"]["id"])
        seen.append((body["notification"]["kind"], body["notification"]["conversation_id"]))
        return body if match(body) else None
    try:
        return wait_for(found, timeout=timeout, interval=0.3, message=what)
    except AssertionError:
        raise AssertionError(f"{adapter.name} never claimed {what}; claimed {seen}") from None


def roster_change(got, conv, change, by):
    n = got["notification"]
    check(n["kind"] == "roster" and n["conversation_id"] == conv and n["message_id"] is None
          and isinstance(n.get("change"), dict) and n["change"]["change"] == change and n["change"]["by"] == by,
          f"want a roster notification {change} by {by} in {conv}, got {n}")
    check(got["messages"] == [] and got["window"] == [] and got["window_total"] == 0 and got["redelivered"] is False,
          f"roster claim body {got}")
    check(got["conversation"]["conversation_id"] == conv, f"roster claim summary {got['conversation']}")
    return n["change"]


def view_as(host, conv, participant):
    status, body = host.api("GET", f"/v1/conversations/{conv}?participant={participant}")
    check(status == 200, f"{host.name}: view of {conv} as {participant}: {status} {body}")
    return body


def departed_of(view):
    return {d["id"]: d for d in view.get("departed") or []}


def wait_view(host, conv, participant, predicate, what, timeout=20):
    last = {}

    def ok():
        last["v"] = view_as(host, conv, participant)
        return last["v"] if predicate(last["v"]) else None
    try:
        return wait_for(ok, timeout=timeout, interval=0.5, message=what)
    except AssertionError:
        raise AssertionError(f"{host.name}: {what} not seen within {timeout}s; last view {last.get('v')}") from None


def show_targets(host, conv, mid, participant, want, as_agent=None, timeout=30):
    """Poll HOST's message view of MID until its target for PARTICIPANT leaves `sending`."""
    extra = ("--as", as_agent) if as_agent else ()
    last = {}

    def settled():
        view = host.ok("conversation", "show", conv, "--json", "--limit", "100", *extra)
        t = target_of(find_message(view, mid), participant)
        last["t"] = t
        return t if t["state"] != "sending" else None
    try:
        t = wait_for(settled, timeout=timeout, interval=0.5, message=f"{mid} target {participant}")
    except AssertionError:
        raise AssertionError(f"target of {mid} for {participant} still {last.get('t')}, want {want}") from None
    check(t["state"] == want, f"target of {mid} for {participant}: {t}, want {want}")
    return t


def peer_message(conv, author, roster_version, clock, seq=1, content="probe", mid=None):
    return {"message_id": mid or message_id(), "conversation_id": conv, "author": author, "seq": seq,
            "clock": clock, "roster_version": roster_version, "sent_at": in_future(seconds=0), "content": content}


def to_agent(message, target, owner_person, version):
    return {"message": message, "target": target, "policy": {"person_id": owner_person, "version": version}}


def highest_clock(host, conv, as_agent=None):
    extra = ("--as", as_agent) if as_agent else ()
    view = host.ok("conversation", "show", conv, "--json", "--limit", "100", *extra)
    return max((m["clock"] for m in view["messages"]), default=0)


@suite.case("c2_setup", "C2 Verification setup")
def _():
    need("bert", "bob_key", "bob_public", "alice_participant", "bob_person")
    c = suite.host("carol-c2")
    state["c"] = c
    key = ssh_key(c.root, "carol")
    state["carol_key"] = key
    join_new_person(a, c, "carol", key, state["net"])
    state["cara"] = c.agent("cara")
    status, network = c.api("GET", f"/v2/networks/{state['net']}")
    check(status == 200, f"carol: network: {status} {network}")
    state["carol_public"] = network["person_public_key"]
    # bob allowed alice in C1 and then denied her; both owners now allow alice's person (and her agents).
    bob_allow = b.ok("allow", "alice", "--no-tasks", "--person-key", state["bob_key"])
    carol_allow = c.ok("allow", "alice", "--no-tasks", "--person-key", key)
    check(carol_allow["actions"] == ["message.append"], f"carol allow --no-tasks: {carol_allow}")
    wait_policies({state["bob_public"]: bob_allow["policy"]["version"],
                   state["carol_public"]: carol_allow["policy"]["version"]}, (a, b, c))
    state["ada"], state["abe"] = a.agent("ada"), a.agent("abe")
    state["ada_p"] = f"agent:{a.id}/{state['ada'].id}"
    state["abe_p"] = f"agent:{a.id}/{state['abe'].id}"
    state["cara_p"] = f"agent:{c.id}/{state['cara'].id}"
    view = a.ok("agents", "--refresh", "--json")
    check(any(r["address"] == "carol/cara" for r in view["reachable"]), f"carol/cara not reachable from alice: {view}")


def invite_body(target_agent, extra):
    """A C1-shaped invite from alice for bob's TARGET_AGENT, with EXTRA participants in its roster."""
    alice_p, bob_person = state["alice_participant"], state["bob_person"]
    now = in_future(seconds=0)
    conv = "conv_" + os.urandom(16).hex()
    roster = {
        "conversation_id": conv, "home_host_id": a.id, "version": 2, "state": "open", "created_by": alice_p,
        "created_at": now, "departed": [],
        "participants": [
            {"id": alice_p, "kind": "person", "host_id": a.id, "person_id": state["alice_person"],
             "agent_id": None, "name": None, "state": "joined", "added_by": None, "added_at": now},
            {"id": f"agent:{b.id}/{target_agent.id}", "kind": "agent", "host_id": b.id, "person_id": bob_person,
             "agent_id": target_agent.id, "name": target_agent.name, "state": "joined", "added_by": alice_p,
             "added_at": now}] + extra}
    return {"conversation_id": conv, "roster": roster, "target": {"kind": "agent", "agent_id": target_agent.id},
            "adder": alice_p, "policy": {"person_id": bob_person, "version": owner_policy(b, state["bob_public"])}}


@suite.case("invite_roster_receiver", "C1 Peer routes: invites (a peer's roster never joins a receiver participant)")
def _():
    bert, _cara = need("bert", "cara")
    alice_p, bob_person = state["alice_participant"], state["bob_person"]
    status, agent = b.api("POST", "/v1/agents", {"name": "bea", "owner": "bob"})
    check(status in (200, 201), f"bob: register bea: {status} {agent}")
    state["bea_id"] = agent["id"]
    now = in_future(seconds=0)
    status, answer = peer(a, b, "POST", "/peer/v1/conversations/invites", invite_body(bert, []))
    check(status == 200 and answer == {"state": "joined", "name": "bert"},
          f"a consistent invite: {status} {answer}, want 200 joined")
    bob_self = {"id": f"person:{b.id}/{bob_person}", "kind": "person", "host_id": b.id, "person_id": bob_person,
                "agent_id": None, "name": None, "state": "inviting", "added_by": alice_p, "added_at": now}
    bea = {"id": f"agent:{b.id}/{agent['id']}", "kind": "agent", "host_id": b.id, "person_id": bob_person,
           "agent_id": agent["id"], "name": "bea", "state": "joined", "added_by": alice_p, "added_at": now}
    for what, extra in (("bob's own person (inviting)", [bob_self]), ("bob's agent bea as joined", [bea])):
        status, answer = peer(a, b, "POST", "/peer/v1/conversations/invites", invite_body(bert, extra))
        check(status == 400 and isinstance(answer, dict) and answer.get("code") == "invalid",
              f"invite roster listing {what}: {status} {answer}, want 400 invalid")
    drain(bert)  # the consistent invite's `added` notification (C2)


@suite.case("message_counters", "C1 Acceptance 1 (2^53 - 1) and 4 (clock jump, person target never joined here)")
def _():
    bert_p, alice_p, conv, bob_person = need("bert_participant", "alice_participant", "conv", "bob_person")
    version = owner_policy(b, state["bob_public"])
    held = view_as(b, conv, bert_p)["roster_version"]
    top = highest_clock(b, conv, "bert")
    path = f"/peer/v1/conversations/{conv}/messages"
    for what, fields in (("seq", {"seq": MAX_SAFE + 1}), ("clock", {"clock": MAX_SAFE + 1}),
                         ("roster_version", {"roster_version": MAX_SAFE + 1})):
        m = peer_message(conv, alice_p, held, top + 1)
        m.update(fields)
        status, answer = peer(a, b, "POST", path, to_agent(m, bert_p, bob_person, version))
        check(status == 400 and isinstance(answer, dict) and answer.get("code") == "invalid",
              f"{what} 2^53: {status} {answer}, want 400 invalid")
    m = peer_message(conv, alice_p, held, top + 2_000_000)
    status, answer = peer(a, b, "POST", path, to_agent(m, bert_p, bob_person, version))
    check(status == 400 and isinstance(answer, dict) and answer.get("code") == "invalid",
          f"a clock 2,000,000 above the highest held: {status} {answer}, want 400 invalid")
    m = peer_message(conv, alice_p, held, top + 1)
    status, answer = peer(a, b, "POST", path, {"message": m, "target": f"person:{b.id}/{bob_person}"})
    api_error(status, answer, 403, "not_participant")
    status, none = state["bert"].post(CLAIM, {})
    check(status == 200 and none is None, f"bert got a notification from a refused probe: {status} {none}")


@suite.case("add_and_push", "C2 Starting (note), Managing add, Invite outcome (reachable_from, reaches), Pushes, "
                            "Notifications")
def _():
    bert, cara, alice_p, bert_p, cara_p = need("bert", "cara", "alice_participant", "bert_participant", "cara_p")
    c = state["c"]
    started = a.ok("conversation", "start", "bob/bert", "--title", "membership", "--note", "please look", timeout=60)
    conv = started["conversation"]["conversation_id"]
    state["conv2"] = conv
    check(started["invites"][0]["state"] == "joined", f"start invite {started['invites']}")
    added = a.ok("conversation", "add", conv[:13], "carol/cara", timeout=60)
    check(isinstance(added, dict) and {"conversation", "invite"} <= set(added), f"add answer {added}")
    inv = added["invite"]
    check(inv["participant"] == cara_p and inv["state"] == "joined" and inv["code"] is None
          and inv["label"] == "carol/cara", f"add outcome {inv}")
    check(inv["reachable_from"] == [alice_p] and inv["reaches"] == [alice_p],
          f"reachable_from {inv['reachable_from']} reaches {inv['reaches']}, want both [{alice_p}]")
    view = added["conversation"]
    parts = {p["id"]: p for p in view["participants"]}
    check(set(parts) == {alice_p, bert_p, cara_p} and all(p["state"] == "joined" for p in parts.values()),
          f"alice's view after add {view['participants']}")
    state["carol_person"] = parts[cara_p]["person_id"]
    version = view_as(a, conv, alice_p)["roster_version"]
    check(version == 4, f"alice's roster version after start and add is {version}, want 4 (C2 Invites)")
    for host, who in ((b, bert_p), (c, cara_p)):
        wait_view(host, conv, who, lambda v: v["roster_version"] == version and len(v["participants"]) == 3
                  and all(p["state"] == "joined" for p in v["participants"]), f"version {version}, three joined")
    got = claim_next(cara)
    change = roster_change(got, conv, "added", alice_p)
    check(change["by_label"] == "alice" and change["note"] is None, f"cara's added change {change}")
    you = [p["id"] for p in got["conversation"]["participants"] if p["you"]]
    check(you == [cara_p] and got["conversation"]["creator"] is False, f"cara's summary {got['conversation']}")
    got = claim_next(bert)
    change = roster_change(got, conv, "added", alice_p)
    check(change["note"] == "please look", f"bert's added change {change}, want the start note")


@suite.case("unreachable_pair", "C2 Invite outcome (reachable_from); C1 Fan-out (403 -> refused not_authorized)")
def _():
    bert, cara, conv, alice_p, cara_p = need("bert", "cara", "conv2", "alice_participant", "cara_p")
    mid = message_id()
    status, body = bert.post(f"/adapter/v1/conversations/{conv}/messages", {"content": "to all", "message_id": mid})
    check(status == 200, f"bert send: {status} {body}")
    check({t["participant"] for t in body["targets"]} == {alice_p, cara_p}, f"bert's targets {body['targets']}")
    show_targets(b, conv, mid, alice_p, "delivered", as_agent="bert")
    t = show_targets(b, conv, mid, cara_p, "refused", as_agent="bert")
    check(t["code"] == "not_authorized", f"cara's target {t}")
    status, none = cara.post(CLAIM, {})
    check(status == 200 and none is None, f"cara got a notification for bert's message: {status} {none}")


@suite.case("remove", "C2 Managing remove, Pushes, Leaving (removed), Notifications; C1 Acceptance 4")
def _():
    bert, cara, conv, alice_p, bert_p, cara_p, carol_person = need(
        "bert", "cara", "conv2", "alice_participant", "bert_participant", "cara_p", "carol_person")
    c = state["c"]
    removed = a.ok("conversation", "remove", conv, "carol/cara")
    gone = departed_of(removed["conversation"])
    check(cara_p in gone and gone[cara_p]["reason"] == "removed" and gone[cara_p]["kind"] == "agent"
          and gone[cara_p]["label"] == "carol/cara" and gone[cara_p]["at"], f"departed after remove {gone}")
    check(cara_p not in {p["id"] for p in removed["conversation"]["participants"]},
          f"cara still a participant {removed['conversation']['participants']}")
    version = removed["conversation"]["roster_version"]
    for host, who in ((b, bert_p), (c, cara_p)):
        wait_view(host, conv, who, lambda v: v["roster_version"] == version
                  and departed_of(v).get(cara_p, {}).get("reason") == "removed", f"version {version}, cara removed")
    got = claim_next(cara)
    roster_change(got, conv, "removed", alice_p)
    m = peer_message(conv, alice_p, version, highest_clock(b, conv, "bert") + 1)
    status, answer = peer(a, c, "POST", f"/peer/v1/conversations/{conv}/messages",
                          to_agent(m, cara_p, carol_person, owner_policy(c, state["carol_public"])))
    api_error(status, answer, 403, "not_participant")
    said = a.ok("conversation", "say", conv, "after remove")
    check([t["participant"] for t in said["targets"]] == [bert_p], f"targets after remove {said['targets']}")
    refused(b.cli("conversation", "remove", conv, bert_p), "not_creator", NOT_CREATOR)
    show_targets(a, conv, said["message"]["message_id"], bert_p, "delivered")
    drain(bert)
    status, none = cara.post(CLAIM, {})
    check(status == 200 and none is None, f"cara got a notification after removal: {status} {none}")


@suite.case("leave", "C2 Leaving, POST /peer/v1/conversations/{id}/leave, adapter manage leave")
def _():
    bert, conv, alice_p, bert_p, bob_person = need("bert", "conv2", "alice_participant", "bert_participant",
                                                    "bob_person")
    status, body = bert.post(f"/adapter/v1/conversations/{conv}/manage", {"action": "leave"})
    check(status == 200 and isinstance(body, dict) and body.get("invite") is None
          and body["conversation"]["conversation_id"] == conv, f"bert leave: {status} {body}")
    version = owner_policy(b, state["bob_public"])

    def probe_refused(c_id):
        held = view_as(a, c_id, alice_p)["roster_version"]
        m = peer_message(c_id, alice_p, held, highest_clock(a, c_id) + 1)
        status, answer = peer(a, b, "POST", f"/peer/v1/conversations/{c_id}/messages",
                              to_agent(m, bert_p, bob_person, version))
        api_error(status, answer, 403, "not_participant")

    probe_refused(conv)
    wait_view(a, conv, alice_p, lambda v: departed_of(v).get(bert_p, {}).get("reason") == "left",
              "bert in departed (left)")
    # The owner form on a fresh conversation, with an unclaimed message for bert that leaving withdraws.
    started = a.ok("conversation", "start", "bob/bert", "--message", "will be withdrawn", timeout=60)
    conv3 = started["conversation"]["conversation_id"]
    show_targets(a, conv3, started["message"]["message_id"], bert_p, "delivered")
    left = b.ok("conversation", "leave", conv3, "--agent", "bert")
    check(isinstance(left, dict) and left["conversation"]["conversation_id"] == conv3, f"leave --agent: {left}")
    probe_refused(conv3)
    wait_view(a, conv3, alice_p, lambda v: departed_of(v).get(bert_p, {}).get("reason") == "left",
              "bert in departed (left) after leave --agent")
    claims = drain(bert)
    check(not any(x["notification"]["kind"] == "message" and x["notification"]["conversation_id"] in (conv, conv3)
                  for x in claims), f"bert was offered a message after leaving: {[x['notification'] for x in claims]}")
    refused(b.cli("conversation", "leave", conv3, "--agent", "bert"), "not_participant", NOT_PARTICIPANT)


@suite.case("close", "C2 Managing close, Closed conversations (acceptance step 5), Pushes, Views")
def _():
    bert, alice_p, bert_p, bob_person = need("bert", "alice_participant", "bert_participant", "bob_person")
    started = a.ok("conversation", "start", "bob/bert", "--message", "before close", timeout=60)
    conv = started["conversation"]["conversation_id"]
    show_targets(a, conv, started["message"]["message_id"], bert_p, "delivered")
    drain(bert)
    closed = a.ok("conversation", "close", conv)
    check(closed["conversation"]["state"] == "closed", f"close answer {closed}")
    version = closed["conversation"]["roster_version"]
    check(version > started["conversation"]["roster_version"], f"close did not make a new version: {version}")
    wait_view(b, conv, bert_p, lambda v: v["state"] == "closed" and v["roster_version"] == version,
              f"closed at version {version} on bob")
    got = claim_next(bert)
    roster_change(got, conv, "closed", alice_p)
    refused(a.cli("conversation", "say", conv, "after close"), "closed", CLOSED)
    status, body = bert.post(f"/adapter/v1/conversations/{conv}/messages", {"content": "after close"})
    api_error(status, body, 409, "closed", CLOSED)
    policy = owner_policy(b, state["bob_public"])
    top = highest_clock(b, conv, "bert")
    m = peer_message(conv, alice_p, version, top + 1)
    status, answer = peer(a, b, "POST", f"/peer/v1/conversations/{conv}/messages",
                          to_agent(m, bert_p, bob_person, policy))
    api_error(status, answer, 409, "closed")
    m = peer_message(conv, alice_p, version - 1, top + 1, content="written before the close")
    status, answer = peer(a, b, "POST", f"/peer/v1/conversations/{conv}/messages",
                          to_agent(m, bert_p, bob_person, policy))
    check(status == 200 and isinstance(answer, dict) and answer.get("message_id") == m["message_id"],
          f"a message with a lower roster_version after close: {status} {answer}, want 200")
    listed = {x["conversation_id"]: x for x in a.ok("conversations", "--all", "--json")["conversations"]}
    check(listed.get(conv, {}).get("state") == "closed", f"conversations --all: {listed.get(conv)}")
    default = {x["conversation_id"] for x in a.ok("conversations", "--json")["conversations"]}
    check(conv not in default, "a closed conversation is in the default (open) list")
    refused(a.cli("conversation", "add", conv, "carol/cara"), "closed", CLOSED)
    drain(bert)


@suite.case("local_participants", "C2 Local participants, Starting (local agents), Notifications (added)")
def _():
    ada, abe, alice_p, ada_p, abe_p = need("ada", "abe", "alice_participant", "ada_p", "abe_p")
    started = a.ok("conversation", "start", "alice/ada", "alice/abe")
    conv = started["conversation"]["conversation_id"]
    outcomes = [(o["target"], o["participant"], o["state"]) for o in started["invites"]]
    check(outcomes == [("alice/ada", ada_p, "joined"), ("alice/abe", abe_p, "joined")], f"outcomes {outcomes}")
    status, body = ada.post(f"/adapter/v1/conversations/{conv}/messages", {"content": "hi abe"})
    check(status == 200, f"ada send: {status} {body}")
    targets = {t["participant"]: t for t in body["targets"]}
    check(set(targets) == {alice_p, abe_p}, f"ada's targets {body['targets']}")
    for who in (alice_p, abe_p):
        check(targets[who]["state"] == "delivered" and targets[who]["attempts"] == 0,
              f"local target {targets[who]}, want delivered with 0 attempts")
    first = claim_next(abe)
    roster_change(first, conv, "added", alice_p)
    second = claim_next(abe)
    check(second["notification"]["kind"] == "message" and second["messages"][0]["content"] == "hi abe"
          and second["messages"][0]["author"] == ada_p, f"abe's second claim {second}")
    roster_change(claim_next(ada), conv, "added", alice_p)


@suite.case("agent_creator", "C2 Starting (as), adapter conversation routes, Managing (not_creator)")
def _():
    ada, bert, ada_p, bert_p = need("ada", "bert", "ada_p", "bert_participant")
    started = a.ok("conversation", "start", "bob/bert", "--as", "ada", timeout=60)
    conv = started["conversation"]["conversation_id"]
    check(started["conversation"]["created_by"] == ada_p and started["invites"][0]["state"] == "joined",
          f"start --as ada: {started}")

    def listed(adapter):
        status, body = adapter.call("GET", "/adapter/v1/conversations")
        check(status == 200, f"{adapter.name}: list: {status} {body}")
        return {x["conversation_id"]: x for x in body["conversations"]}
    check(listed(bert).get(conv, {}).get("creator") is False, f"bert's list entry {listed(bert).get(conv)}")
    check(listed(ada).get(conv, {}).get("creator") is True, f"ada's list entry {listed(ada).get(conv)}")
    status, body = bert.post(f"/adapter/v1/conversations/{conv}/manage", {"action": "close"})
    api_error(status, body, 403, "not_creator", NOT_CREATOR)
    mid = message_id()
    status, body = ada.post("/adapter/v1/conversations", {"participants": ["bob/bert"], "content": "from ada",
                                                          "message_id": mid})
    check(status == 201 and isinstance(body, dict) and body["invites"][0]["state"] == "joined"
          and body["message"]["message_id"] == mid, f"ada starts: {status} {body}")
    got = claim_until(bert, lambda x: x["notification"]["kind"] == "message"
                      and x["notification"]["message_id"] == mid, "ada's first message")
    m = got["messages"][0]
    check(m["author"] == ada_p and m["origin_agent_id"] == ada.id and m["content"] == "from ada", f"bert got {m}")
    drain(bert)


@suite.case("full", "C2 Managing add (16 participants)")
def _():
    need("alice_participant")
    for i in range(1, 17):
        status, body = a.api("POST", "/v1/agents", {"name": f"f{i:02d}", "owner": "alice"})
        check(status in (200, 201), f"alice: register f{i:02d}: {status} {body}")
    started = a.ok("conversation", "start", *[f"alice/f{i:02d}" for i in range(1, 16)])
    conv = started["conversation"]["conversation_id"]
    check(len(started["conversation"]["participants"]) == 16
          and all(p["state"] == "joined" for p in started["conversation"]["participants"]),
          f"16 participants: {started['conversation']['participants']}")
    status, body = a.api("POST", f"/v1/conversations/{conv}/manage", {"action": "add", "participant": "alice/f16"})
    api_error(status, body, 409, "full", FULL)


@suite.case("roster_route_edges", "C2 Peer routes: roster push and fetch, leave")
def _():
    conv1, conv2, cara_p, bert_p, bea_id = need("conv", "conv2", "cara_p", "bert_participant", "bea_id")
    c = state["c"]
    status, body = peer(c, a, "GET", f"/peer/v1/conversations/{conv2}/roster")
    check(status == 200 and isinstance(body, dict) and body["roster"]["conversation_id"] == conv2
          and any(d["id"] == cara_p and d["reason"] == "removed" for d in body["roster"]["departed"]),
          f"GET roster from carol after removal: {status} {body}")
    status, answer = peer(b, c, "POST", f"/peer/v1/conversations/{conv2}/roster", {"roster": body["roster"]})
    api_error(status, answer, 403, "forbidden")
    status, body = peer(b, a, "GET", f"/peer/v1/conversations/{conv1}/roster")
    check(status == 200 and isinstance(body, dict), f"GET roster from bob: {status} {body}")
    roster = body["roster"]
    held = view_as(b, conv1, bert_p)["roster_version"]
    status, answer = peer(a, b, "POST", f"/peer/v1/conversations/{conv1}/roster", {"roster": roster})
    check(status == 200 and answer == {"version": held}, f"a push at the held version: {status} {answer}")
    now = in_future(seconds=0)
    roster = dict(roster, version=held + 1, participants=roster["participants"] + [
        {"id": f"agent:{b.id}/{bea_id}", "kind": "agent", "host_id": b.id, "person_id": state["bob_person"],
         "agent_id": bea_id, "name": "bea", "state": "joined", "added_by": state["alice_participant"],
         "added_at": now}])
    status, answer = peer(a, b, "POST", f"/peer/v1/conversations/{conv1}/roster", {"roster": roster})
    api_error(status, answer, 400, "invalid")
    after = view_as(b, conv1, bert_p)["roster_version"]
    check(after == held, f"bob's version changed from {held} to {after} on a refused push")
    status, answer = peer(b, a, "POST", f"/peer/v1/conversations/{conv2}/leave", {"participant": cara_p})
    api_error(status, answer, 403, "forbidden")


@suite.case("unanswered", "C2 Managing: Unanswered invites (test clock; runs last)")
def _():
    conv1, cara_p, alice_p = need("conv", "cara_p", "alice_participant")
    c = state["c"]
    view = a.ok("agents", "--refresh", "--json")
    check(any(r["address"] == "carol/cara" for r in view["reachable"]), "carol/cara not in alice's directory")
    c.stop()
    added = a.ok("conversation", "add", conv1, "carol/cara", timeout=60)
    check(added["invite"]["state"] == "inviting" and added["invite"]["participant"] == cara_p,
          f"add with carol stopped: {added['invite']}")
    suite.set_offset(suite.offset + 601)
    wait_view(a, conv1, alice_p, lambda v: departed_of(v).get(cara_p, {}).get("reason") == "unanswered",
              "cara in departed (unanswered)", timeout=20)


suite.finish()
