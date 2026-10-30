#!/usr/bin/env python3
"""Slim suite, conversations: C1, two hosts and one message each way.

alice creates a coordinator-free network and bob joins it. bob's fixture agent `bert` has a directory
session with a verified channel, and bob allows alice `message.append`. alice starts a conversation with
`bob/bert` and a first message; bert claims it and replies through the adapter route; repeats, a refusal
after `deny alice`, and the edges of the local, adapter and CLI surfaces follow. Written from
docs/conversations-contract.md, section C1 (cited as "C1 <part>"), only.
"""
import os
import re

from harness import Suite, check, create_network, join_new_person, ssh_key, wait_for

suite = Suite("conversations", __doc__)
a, b = suite.host("alice"), suite.host("bob")
state = {}

CONV_ID = re.compile(r"^conv_[0-9a-f]{32}$")
MSG_ID = re.compile(r"^cmsg_[0-9a-f]{32}$")
NOT_ID = re.compile(r"^cnot_[0-9a-f]{32}$")
CLAIM = "/adapter/v1/conversation-notifications/next"


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
    check(two == one, f"forwarded is not idempotent: {one} then {two}")
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
    check(status == 409 and isinstance(body, dict) and body.get("code") == "conflict",
          f"repeat with other content from bert: {status} {body}")
    # The same on alice's host, through `conversation say --message-id`.
    said_id = message_id()
    said = a.ok("conversation", "say", state["conv"], "second from alice", "--message-id", said_id)
    check(said["message"]["message_id"] == said_id and said["message"]["seq"] == 2, f"say {said['message']}")
    again = a.ok("conversation", "say", state["conv"], "second from alice", "--message-id", said_id)
    check(again["message"]["message_id"] == said_id and again["message"]["seq"] == 2
          and len(again["targets"]) == 1, f"identical say repeat {again}")
    clash = a.cli("conversation", "say", state["conv"], "different", "--message-id", said_id)
    check(clash.code == 1, f"say with reused message_id and other content: {clash}")
    status, body = a.api("POST", f"/v1/conversations/{state['conv']}/messages",
                         {"content": "different", "message_id": said_id})
    check(status == 409 and isinstance(body, dict) and body.get("code") == "conflict",
          f"API repeat with other content: {status} {body}")
    view = show(a)
    ids = [x["message_id"] for x in view["messages"]]
    check(ids.count(mid) == 1 and ids.count(said_id) == 1 and len(ids) == 3, f"messages after repeats {ids}")
    check(in_display_order(view["messages"]), "messages not in (clock, author, seq) order")
    wait_target(a, said_id, bert_p, "delivered")
    # bert gets exactly one notification for it; it is not the session's first, so no window.
    got = claim(bert)
    check(got["notification"]["message_id"] == said_id and got["messages"][0]["seq"] == 2
          and got["messages"][0]["clock"] == 3 and got["window"] == [] and got["conversation"]["unseen"] == 1,
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
    # A session without directory access: null from the claim route, 403 no_directory from the sending route.
    nodir = b.agent("nodi", directory=False)
    status, body = nodir.post(CLAIM, {})
    check(status == 200 and body is None, f"claim without directory access: {status} {body}")
    status, body = nodir.post(f"/adapter/v1/conversations/{conv}/messages", {"content": "x"})
    check(status == 403 and isinstance(body, dict) and body.get("code") == "no_directory",
          f"send without directory access: {status} {body}")
    # bob's person is not a participant: `conversation say` on bob's host fails with not_participant.
    say = b.cli("conversation", "say", conv, "hi from bob")
    check(say.code == 1, f"bob's say: {say}")
    status, body = b.api("POST", f"/v1/conversations/{conv}/messages", {"content": "hi from bob"})
    check(status == 403 and isinstance(body, dict) and body.get("code") == "not_participant",
          f"bob's person sending: {status} {body}")
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


@suite.case("refused_after_deny", "C1 Fan-out and retry (citation, 403 -> refused not_authorized); CLI show")
def _():
    bert, bert_p, key = need("bert", "bert_participant", "bob_key")
    before = policy_version(b, state["bob_public"])
    b.ok("deny", "alice", "--person-key", key)
    version = policy_version(b, state["bob_public"])
    check(version > before, f"deny did not sign a new policy version ({before} -> {version})")
    wait_policy(version, (a,))
    said = a.ok("conversation", "say", state["conv"], "after deny")
    mid = said["message"]["message_id"]
    t = wait_target(a, mid, bert_p, "refused")
    check(t["code"] == "not_authorized", f"refused target {t}")
    readable = a.cli("conversation", "show", state["conv"])
    check(readable.ok and "not received by bob/bert (refused: not_authorized)" in readable.stdout,
          f"readable show after refusal: {readable.stdout[-600:]}")
    status, body = bert.post(CLAIM, {})
    check(status == 200 and body is None, f"bert got a notification after deny: {status} {body}")


suite.finish()
