#!/usr/bin/env python3
"""Slim suite, conversations C4: catch-up.

alice creates a coordinator-free network; bob and carol join it. Every participant is a person (C4
Verification setup). A block on bob makes alice's first message in conversation G refused, and it stays refused
after the unblock. Raw peer requests probe `heads`, `messages` and `acks`. Then the 24-hour world: bob's host stops
while alice writes to W and X (and closes X) and carol writes to Y and V; 24 hours later on the test clock those
targets are `stopped`; bob restarts, catches up W, sees X closed, refuses carol's message in Y because he blocked
carol, and, once unblocked, fetches V's first message when her second reveals the gap. Last, alice closes Z while
carol is down and, 30 days later, reports carol's host `unsynced`. Its own suite and CI job: the clock moves need
hosts of their own.
Written from docs/conversations-contract.md, section C4 (cited as "C4 <part>"), and the C1 to C3 sections it
builds on, only.
"""
import os
import time

from harness import (Suite, api_error, check, create_network, find_message, join_new_person, peer, show_targets,
                     ssh_key, target_of, view_as, wait_for)

suite = Suite("conversations_sync", __doc__)
suite.use_clock()  # C4 Verification: the 24-hour and 30-day moves need the test clock before any host starts
a, b, c = suite.host("alice"), suite.host("bob"), suite.host("carol")
state = {}

DAY = 24 * 3600
STOPPED = "retries stopped 24 hours after sending; the recipient's host fetches it when it syncs"


def need(*names):
    missing = [n for n in names if n not in state]
    check(not missing, f"an earlier case did not finish ({', '.join(missing)} missing)")
    return [state[n] for n in names]


def network_sync(*hosts):
    for host in hosts:
        status, body = host.api("POST", f"/v2/networks/{state['net']}/sync", {}, timeout=40)
        check(status == 200, f"{host.name}: network sync: {status} {body}")


def start_with(home, guest, label):
    """`conversation start person:LABEL` on HOME, then `conversation join` on GUEST (C3 Starting, Joining).

    Returns (conversation ID, home's person participant, guest's person participant)."""
    started = home.ok("conversation", "start", f"person:{label}", timeout=60)
    check(isinstance(started, dict) and len(started.get("invites") or []) == 1,
          f"{home.name}: start {label}: {started}")
    conv = started["conversation"]["conversation_id"]
    person = (started["invites"][0].get("participant") or "").split(":", 1)[-1]
    check(person.startswith("person_"), f"{home.name}: outcome participant {started['invites'][0]}")

    def joined():
        result = guest.cli("conversation", "join", conv, timeout=60)
        return result.json if result.ok else None
    wait_for(joined, timeout=30, interval=1, message=f"{guest.name} to join {conv}")
    guest_p = f"person:{guest.id}/{person}"

    def home_sees():
        v = view_as(home, conv, started["conversation"]["created_by"])
        return any(p["id"] == guest_p and p["state"] == "joined" for p in v["participants"])
    wait_for(home_sees, timeout=20, interval=0.5, message=f"{home.name} to list {guest.name}'s person joined in {conv}")
    return conv, started["conversation"]["created_by"], guest_p


def say(host, conv, text):
    return host.ok("conversation", "say", conv, text)["message"]["message_id"]


def show(host, conv):
    view = host.ok("conversation", "show", conv, "--json", "--limit", "100")
    check(isinstance(view, dict) and isinstance(view.get("messages"), list), f"{host.name}: show {conv}: {view}")
    return view


def wait_state(host, conv, mid, participant, want, code=None, timeout=20):
    """Poll HOST's `conversation show --json` until MID's target for PARTICIPANT is WANT (and CODE when given)."""
    last = {}

    def reached():
        t = target_of(find_message(show(host, conv), mid), participant)
        last["t"] = t
        return t if t["state"] == want and (code is None or t["code"] == code) else None
    try:
        return wait_for(reached, timeout=timeout, interval=0.5, message=f"{mid} target {participant} {want}")
    except AssertionError:
        raise AssertionError(f"{host.name}: target of {mid} for {participant} is {last.get('t')}, want {want} "
                             f"{code or ''} within {timeout}s") from None


def in_display_order(messages):
    keys = [(m["clock"], m["author"].encode(), m["seq"]) for m in messages]
    return keys == sorted(keys)


def sync(host, conv):
    """`conversation sync ID` (C4 Local API and CLI): the answer and its hosts by host ID."""
    answer = host.ok("conversation", "sync", conv, timeout=90)
    check(isinstance(answer, dict) and answer.get("conversation_id") == conv and isinstance(answer.get("hosts"), list),
          f"{host.name}: sync {conv}: {answer}")
    ids = [h["host_id"] for h in answer["hosts"]]
    check(ids == sorted(ids), f"{host.name}: sync hosts not in host ID order: {ids}")
    for h in answer["hosts"]:
        check(h["state"] in ("synced", "failed", "complete", "unsynced") and isinstance(h["fetched"], int)
              and (h["error"] is None) == (h["state"] != "failed"), f"{host.name}: sync host entry {h}")
    return answer, {h["host_id"]: h for h in answer["hosts"]}


def conv_path(conv, rest):
    return f"/peer/v1/conversations/{conv}/{rest}"


@suite.case("setup", "C4 Verification setup; C3 Starting, Joining; decentralized-spec 6, 8")
def _():
    net = create_network(a, "catchup", "alice")
    state["net"] = net["id"]
    join_new_person(a, b, "bob", ssh_key(b.root, "bob"), net["id"])
    join_new_person(a, c, "carol", ssh_key(c.root, "carol"), net["id"])
    network_sync(c, b)
    # Z (alice and carol) is the 30-day case's conversation; started now it also gives carol's person participant.
    z, alice_p, carol_p = start_with(a, c, "carol")
    state.update(z=z, alice_p=alice_p, carol_p=carol_p)
    g, _, bob_p = start_with(a, b, "bob")
    state.update(g=g, bob_p=bob_p)


@suite.case("refused_stays_refused", "C4 Gap detection (a final refusal stays final), Conversation sync; C3 block list")
def _():
    g, bob_p = need("g", "bob_p")
    b.ok("block", "alice")
    try:
        m1 = say(a, g, "m1 while blocked")
        t = show_targets(a, g, m1, bob_p, "refused")
        check(t["code"] == "not_authorized", f"m1 target while blocked: {t}")
    finally:
        b.ok("unblock", "alice")
    m2 = say(a, g, "m2 after unblock")
    state.update(m1=m1, m2=m2)
    wait_state(a, g, m2, bob_p, "delivered")
    sync(b, g)
    ids = [m["message_id"] for m in show(b, g)["messages"]]
    check(m2 in ids and m1 not in ids, f"bob's G lists {ids}, want m2 {m2} and not m1 {m1}")
    t = target_of(find_message(show(a, g), m1), bob_p)
    check(t["state"] == "refused" and t["code"] == "not_authorized", f"m1's target after bob's sync: {t}")


@suite.case("heads_route", "C4 Peer routes (serves), GET /peer/v1/conversations/{id}/heads")
def _():
    g, alice_p, bob_p, carol_p = need("g", "alice_p", "bob_p", "carol_p")
    held = view_as(a, g, alice_p)["roster_version"]
    status, body = peer(b, a, "GET", conv_path(g, f"heads?target={bob_p}"))
    check(status == 200 and body == {"roster_version": held, "authors": [{"author": alice_p, "last_seq": 2}]},
          f"heads for bob on alice: {status} {body}, want roster_version {held} and alice's last_seq 2")
    status, body = peer(c, a, "GET", conv_path(g, f"heads?target={bob_p}"))
    api_error(status, body, 403, "forbidden")
    status, body = peer(c, a, "GET", conv_path(g, f"heads?target={carol_p}"))  # carol's host, not in G
    api_error(status, body, 404, "not_found")


@suite.case("messages_route", "C4 GET /peer/v1/conversations/{id}/messages; C1 Peer routes (strict query)")
def _():
    g, alice_p, bob_p, m1, m2 = need("g", "alice_p", "bob_p", "m1", "m2")
    base = conv_path(g, f"messages?author={alice_p}&target={bob_p}&after=0")
    status, body = peer(b, a, "GET", base)
    check(status == 200 and isinstance(body, dict) and body.get("more") is False
          and len(body.get("messages") or []) == 2, f"messages after 0: {status} {body}")
    first, second = body["messages"]
    # A message refused for the target is named without its content (C4 GET .../messages, ENTRY).
    tombstone = {"message_id": m1, "seq": 1, "refused": "not_authorized"}
    check(first == tombstone, f"m1's entry {first}, want {tombstone}")
    check(set(second) == {"message", "prev_seq"} and second["prev_seq"] == 1 and second["message"]["message_id"] == m2
          and second["message"]["seq"] == 2 and second["message"]["author"] == alice_p
          and second["message"]["conversation_id"] == g, f"m2's entry {second}, want the message with prev_seq 1")
    status, body = peer(b, a, "GET", base + "&limit=1")
    check(status == 200 and body.get("messages") == [tombstone] and body.get("more") is True,
          f"limit=1: {status} {body}")
    for bad in ("&limit=101", "&limit=0", "&color=red"):
        status, body = peer(b, a, "GET", base + bad)
        api_error(status, body, 400, "invalid")
    status, body = peer(c, a, "GET", base)
    api_error(status, body, 403, "forbidden")


@suite.case("acks_route", "C4 POST /peer/v1/conversations/{id}/acks")
def _():
    g, alice_p, bob_p, m1, m2 = need("g", "alice_p", "bob_p", "m1", "m2")
    ack = {"target": bob_p, "acks": [{"author": alice_p, "through_seq": 2, "refused": []}]}
    status, body = peer(c, a, "POST", conv_path(g, "acks"), ack)
    api_error(status, body, 403, "forbidden")
    status, body = peer(b, a, "POST", conv_path(g, "acks"), ack)  # what bob's sync already acked
    check(status == 200 and body == {"acked": 0}, f"repeated ack: {status} {body}, want 200 {{acked: 0}}")
    for mid, want in ((m1, "refused"), (m2, "delivered")):
        t = target_of(find_message(show(a, g), mid), bob_p)
        check(t["state"] == want, f"target of {mid} after the acks: {t}, want {want}")


@suite.case("sync_route_edges", "C4 Local API and CLI (route, prefix, CONV-24)")
def _():
    g, _ = need("g", "m2")
    answer, hosts = sync(a, g)
    check(answer["roster_version"] == view_as(a, g, state["alice_p"])["roster_version"]
          and list(hosts) == [b.id] and hosts[b.id]["state"] == "synced" and hosts[b.id]["fetched"] == 0,
          f"alice's sync of G: {answer}")
    status, body = a.api("POST", f"/v1/conversations/{g}/sync", {})
    check(status == 200 and body.get("conversation_id") == g, f"the sync route: {status} {body}")
    status, body = a.api("POST", f"/v1/conversations/{g}/sync", {"color": "red"})
    check(status == 400, f"the sync route with an unknown field: {status} {body}")
    unknown = "conv_" + os.urandom(16).hex()
    status, body = a.api("POST", f"/v1/conversations/{unknown}/sync", {})
    api_error(status, body, 404, "not_found")
    result = a.cli("conversation", "sync", g[:11])
    check(result.ok and result.json and result.json.get("conversation_id") == g, f"sync by prefix: {result}")
    # Known only from a pending invite: not a conversation bob holds.
    started = a.ok("conversation", "start", "person:bob", timeout=60)
    pending = started["conversation"]["conversation_id"]

    def held():
        return any(i["conversation_id"] == pending for i in b.ok("conversations", "--invites", "--json")["invites"])
    wait_for(held, timeout=20, interval=0.5, message="bob to hold the pending invite")
    status, body = b.api("POST", f"/v1/conversations/{pending}/sync", {})
    api_error(status, body, 404, "not_found")
    check(b.ok("conversation", "decline", pending)["state"] == "declined", "bob could not decline the invite")
    root_help = a.cli("--help")
    check("conversation sync" not in root_help.stdout, f"the root help lists conversation sync: {root_help.stdout!r}")


@suite.case("stopped_24h", "C4 The 24-hour push window and stopped, Target view, Conversation view (unsynced)")
def _():
    bob_p = need("bob_p")[0]
    w, _, _ = start_with(a, b, "bob")
    x, _, _ = start_with(a, b, "bob")
    y, _, bob_y = start_with(c, b, "bob")
    v, _, bob_v = start_with(c, b, "bob")
    check(bob_y == bob_p and bob_v == bob_p, f"bob's person participant differs: {bob_y}, {bob_v}, {bob_p}")
    b.stop()
    sent = {"w": [say(a, w, f"w{i}") for i in (1, 2, 3)], "x": [say(a, x, "x1")]}
    closed = a.ok("conversation", "close", x)["conversation"]
    check(closed["state"] == "closed", f"close X: {closed}")
    sent["y"] = [say(c, y, "y1 from carol")]
    sent["v"] = [say(c, v, "v1 from carol")]
    state.update(w=w, x=x, y=y, v=v, sent=sent, x_version=closed["roster_version"])
    suite.set_offset(suite.offset + DAY + 1)
    state["moved"] = True
    for host, conv, mids in ((a, w, sent["w"]), (a, x, sent["x"]), (c, y, sent["y"]), (c, v, sent["v"])):
        for mid in mids:
            t = wait_state(host, conv, mid, bob_p, "stopped")
            check(t["code"] is None and t["error"] == STOPPED, f"{host.name}: stopped target {t}")
    readable = a.cli("conversation", "show", w)
    check(readable.ok and "not yet received by bob (stopped)" in readable.stdout,
          f"alice's readable show of W: {readable.stdout[-600:]!r}")
    status, view = a.api("GET", f"/v1/conversations/{x}")
    check(status == 200 and view.get("unsynced") == [], f"alice's view of X: {status} unsynced={view.get('unsynced')}")


@suite.case("restart_in_order", "C4 Verification (24 hours: restart order; fresh contacts after a clock move)")
def _():
    need("moved")
    c.stop()
    a.restart()
    b.start()
    state["bob_started"] = time.monotonic()
    b.ok("block", "carol")
    state["carol_blocked"] = True
    state["world"] = True


@suite.case("catch_up", "C4 Conversation sync (startup, on request), Fetched messages, POST .../acks")
def _():
    w, sent, bob_p, _ = need("w", "sent", "bob_p", "world")
    answer, hosts = sync(b, w)
    check(a.id in hosts and hosts[a.id]["state"] == "synced", f"bob's sync of W: {answer}")
    msgs = show(b, w)["messages"]
    ids = [m["message_id"] for m in msgs]
    check(ids == sent["w"] and in_display_order(msgs), f"bob's W lists {ids}, want {sent['w']} in display order")
    for mid in sent["w"]:
        wait_state(a, w, mid, bob_p, "delivered")


@suite.case("close_while_down", "C4 Conversation sync (roster first, after close, complete), Peer routes "
                                "(messages after close), Local API and CLI")
def _():
    x, sent, version, alice_p, bob_p, _ = need("x", "sent", "x_version", "alice_p", "bob_p", "world")

    def closed_on_bob():
        status, view = b.api("GET", f"/v1/conversations/{x}")
        return view if status == 200 and view["state"] == "closed" and view["roster_version"] == version else None
    try:
        wait_for(closed_on_bob, timeout=20, interval=0.5, message="bob to hold X closed")
    except AssertionError:
        sync(b, x)
        status, view = b.api("GET", f"/v1/conversations/{x}")
        raise AssertionError(f"bob's X after its sync: {status} state {view.get('state')} version "
                             f"{view.get('roster_version')}, want closed at {version}") from None
    ids = [m["message_id"] for m in show(b, x)["messages"]]
    check(sent["x"][0] in ids, f"bob's X lists {ids}, want alice's message from before the close")
    wait_state(a, x, sent["x"][0], bob_p, "delivered")
    _, hosts = sync(a, x)
    check(hosts.get(b.id, {}).get("state") in ("synced", "complete"), f"alice's first sync of X: {hosts}")
    _, hosts = sync(a, x)
    check(hosts.get(b.id, {}).get("state") == "complete", f"alice's second sync of X: {hosts}")
    status, body = peer(b, a, "GET", conv_path(x, f"messages?author={alice_p}&target={bob_p}&after=0"))
    api_error(status, body, 404, "not_found")
    status, body = peer(b, a, "GET", conv_path(x, f"heads?target={bob_p}"))
    check(status == 200 and body.get("roster_version") == version, f"heads for X after complete: {status} {body}")


@suite.case("carol_starts", "C4 Conversation sync (When: startup within 15 seconds; a 5-second limit per request)")
def _():
    started, _ = need("bob_started", "world")
    # C4 Verification has bob's startup syncs of Y and V fail, carol being down. They may start up to 15 seconds after
    # bob does and a request may take 5 more: earlier, one can reach carol and refuse v1 under the block, leaving no
    # gap.
    time.sleep(max(0, started + 21 - time.monotonic()))
    c.start()
    state["carol_up"] = True


@suite.case("no_back_door", "C4 Fetched messages (step 6, refused not_authorized), POST .../acks; C3 block list")
def _():
    y, sent, bob_p, _ = need("y", "sent", "bob_p", "carol_up")
    mid = sent["y"][0]
    try:
        answer, hosts = sync(b, y)
        check(hosts.get(c.id, {}).get("state") == "synced" and hosts[c.id]["fetched"] == 0,
              f"bob's sync of Y while carol is blocked: {answer}")
        check(mid not in [m["message_id"] for m in show(b, y)["messages"]],
              "bob lists carol's message from a blocked host")
        wait_state(c, y, mid, bob_p, "refused", code="not_authorized")
    finally:
        b.ok("unblock", "carol")
        state["carol_blocked"] = False
    answer, hosts = sync(b, y)
    check(hosts.get(c.id, {}).get("fetched") == 0, f"bob's sync of Y after unblock fetched: {answer}")
    check(mid not in [m["message_id"] for m in show(b, y)["messages"]], "bob lists the refused message after unblock")
    t = target_of(find_message(show(c, y), mid), bob_p)
    check(t["state"] == "refused" and t["code"] == "not_authorized", f"carol's target after unblock: {t}")


@suite.case("gap_fetch", "C4 Gap detection, Fetched messages, POST .../acks, Verification (Gap fetch)")
def _():
    v, sent, bob_p, _ = need("v", "sent", "bob_p", "carol_up")
    if state.get("carol_blocked"):  # no_back_door did not get as far as its unblock
        b.ok("unblock", "carol")
        state["carol_blocked"] = False
    v1 = sent["v"][0]
    v2 = say(c, v, "v2 from carol")  # no `conversation sync` from here on: the push alone reveals the gap at prev_seq 1
    listed = {}

    def both():
        listed["m"] = show(b, v)["messages"]
        return [m["message_id"] for m in listed["m"]] == [v1, v2]
    try:
        wait_for(both, timeout=20, interval=0.5, message="bob to list v1 and v2")
    except AssertionError:
        target = target_of(find_message(show(c, v), v1), bob_p)
        raise AssertionError(f"bob's V lists {[m['message_id'] for m in listed.get('m', [])]}, want v1 {v1} (fetched "
                             f"after v2's prev_seq 1 revealed the gap), then v2 {v2}; v1's target on carol {target}"
                             ) from None
    check(in_display_order(listed["m"]), f"bob's V order {[(m['clock'], m['seq']) for m in listed['m']]}")
    wait_state(c, v, v2, bob_p, "delivered")
    wait_state(c, v, v1, bob_p, "delivered")  # through bob's acks, from stopped


@suite.case("unsynced_30_days", "C4 Conversation sync (after close, unsynced), Conversation view (runs last)")
def _():
    z, alice_p, _ = need("z", "alice_p", "world")
    c.stop()
    closed = a.ok("conversation", "close", z)["conversation"]
    check(closed["state"] == "closed", f"close Z: {closed}")
    suite.set_offset(suite.offset + 30 * DAY + 1)
    answer, hosts = sync(a, z)
    check(hosts.get(c.id, {}).get("state") == "unsynced", f"alice's sync of Z 30 days after the close: {answer}")
    # Named participant: 30 days on, alice's binding grant has lapsed (no ssh-agent to renew it, C4 Verification setup),
    # so a read without `participant` is 409 not_bound (C1 Local API). See the question on the PR.
    unsynced = view_as(a, z, alice_p).get("unsynced")
    check(unsynced == [c.id], f"alice's view of Z: unsynced={unsynced}, want [{c.id}]")


suite.finish()
