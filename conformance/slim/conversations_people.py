#!/usr/bin/env python3
"""Slim suite, conversations C3: people.

alice creates a coordinator-free network, bob joins it, and a fourth host bob2 is linked to bob's person, so
bob's person is bound to bob and bob2. alice invites bob's person: both bound hosts hold a pending invite, the
attention item appears on bob, bob joins on bob and bob2 drops its copy; messages flow both ways, bob's block
list refuses alice; declines, removals, raw peer edges, the 20-invite limit and, last, the 7-day expiry on the
test clock follow. Its own suite (and CI job) so the conversations job stays under 2 minutes. Written from
docs/conversations-contract.md, section C3 (cited as "C3 <part>"), only.
"""
import os
import re
from datetime import datetime, timedelta

from harness import (Suite, api_error, check, create_network, departed_of, find_message, in_future, join_new_person,
                     link_machine, members, peer, refused, show_targets, ssh_key, view_as, wait_for,
                     wait_view)

suite = Suite("conversations_people", __doc__)
suite.use_clock()  # C3 Verification: the expiry case moves the test clock; it must be set before hosts start
a, b, b2 = suite.host("alice"), suite.host("bob"), suite.host("bob2")
state = {}

NO_INVITE = "No pending invite to that conversation on this host."
LIMIT = "This host holds 20 pending conversation invites from that host."
WEEK = 7 * 24 * 3600


def need(*names):
    missing = [n for n in names if n not in state]
    check(not missing, f"an earlier case did not finish ({', '.join(missing)} missing)")
    return [state[n] for n in names]


def when(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def invites(host):
    """`conversations --invites --json` on HOST: {conversation_id: INVITE VIEW}, in the listed order."""
    listed = host.ok("conversations", "--invites", "--json")
    check(isinstance(listed, dict) and isinstance(listed.get("invites"), list), f"{host.name}: --invites: {listed}")
    return {i["conversation_id"]: i for i in listed["invites"]}


def wait_invite(host, conv, present=True, timeout=20):
    what = f"{host.name} {'to list' if present else 'to drop'} the pending invite to {conv}"
    return wait_for(lambda: (invites(host).get(conv) if present else conv not in invites(host)) or None,
                    timeout=timeout, interval=0.5, message=what)


def person_entry(view, person_id):
    found = [p for p in view["participants"] if p.get("person_id") == person_id and p["kind"] == "person"]
    check(len(found) <= 1, f"more than one entry for {person_id}: {found}")
    return found[0] if found else None


def alice_view(conv):
    return view_as(a, conv, state["alice_p"])


def start_person(target, *extra):
    started = a.ok("conversation", "start", target, *extra, timeout=60)
    check(isinstance(started, dict) and len(started.get("invites") or []) == 1, f"start {target}: {started}")
    return started["conversation"]["conversation_id"], started["invites"][0], started["conversation"]


def check_invited(outcome, target):
    bob_person = state["bob_person"]
    hosts = sorted([b.id, b2.id])
    check(outcome["target"] == target and outcome["participant"] == f"person:{bob_person}"
          and outcome["state"] == "invited" and outcome["code"] is None and outcome["label"] == "bob",
          f"outcome for {target}: {outcome}")
    check([h["host_id"] for h in outcome["hosts"]] == hosts
          and all(h["state"] == "invited" and h["code"] is None for h in outcome["hosts"]),
          f"`hosts` of the outcome for {target}: {outcome['hosts']}, want bob and bob2 invited in host ID order")


def status_of(host):
    status, body = host.api("GET", "/v1/status")
    check(status == 200 and isinstance(body, dict), f"{host.name}: status: {status} {body}")
    return body


def invite_items(body):
    return [i for i in body.get("attention") or [] if i.get("kind") == "conversation_invites"]


def person_invite(conv, person_id, roster_mutate=None, **fields):
    """A person invite from alice (C3 Peer routes), with alice's person as creator and adder."""
    alice_p, now = state["alice_p"], in_future(seconds=0)
    roster = {
        "conversation_id": conv, "home_host_id": a.id, "version": 2, "state": "open", "created_by": alice_p,
        "created_at": now, "departed": [],
        "participants": [
            {"id": alice_p, "kind": "person", "host_id": a.id, "person_id": state["alice_person"], "agent_id": None,
             "name": None, "state": "joined", "added_by": None, "added_at": now},
            {"id": None, "kind": "person", "host_id": None, "person_id": person_id, "agent_id": None, "name": None,
             "state": "invited", "added_by": alice_p, "added_at": now}]}
    if roster_mutate:
        roster_mutate(roster)
    body = {"conversation_id": conv, "roster": roster, "target": {"kind": "person", "person_id": person_id},
            "adder": alice_p}
    body.update(fields)
    return body


def new_conv():
    return "conv_" + os.urandom(16).hex()


@suite.case("setup", "C3 Verification setup; decentralized-spec 6, 8")
def _():
    net = create_network(a, "people", "alice")
    state["net"] = net["id"]
    key = ssh_key(b.root, "bob")
    join_new_person(a, b, "bob", key, net["id"])
    status, network = b.api("GET", f"/v2/networks/{net['id']}")
    check(status == 200, f"bob: network: {status} {network}")
    state["bob_public"] = network["person_public_key"]
    link_machine(b, b2, net["id"], state["bob_public"], key=key, admin=a)  # bob is not an administrator

    def knows_bob2():
        for host in (b2, a):
            status, body = host.api("POST", f"/v2/networks/{net['id']}/sync", {}, timeout=40)
            check(status == 200, f"{host.name}: sync: {status} {body}")
        seen = members(a, net["id"])
        return seen if b2.public_key in seen and b.public_key in seen else None
    seen = wait_for(knows_bob2, timeout=40, interval=1, message="alice to list bob2 as a member")
    check(seen[b2.public_key]["person_public_key"] == seen[b.public_key]["person_public_key"] == state["bob_public"],
          f"bob2 is not bound to bob's person on alice: {seen[b2.public_key]}")
    status, ada = a.api("POST", "/v1/agents", {"name": "ada", "owner": "alice"})
    check(status in (200, 201), f"alice: register ada: {status} {ada}")
    state["ada"] = a.attach(ada)


@suite.case("invite_bound_hosts", "C3 Starting and adding people (resolution, persist and invite, invite outcome), "
                                  "Pending invites, Views, CLI conversations --invites")
def _():
    need("bob_public")
    conv, outcome, view = start_person("person:bob", "--title", "T")
    state["conv"] = conv
    # The person ID (C3 Words) comes from the outcome's `participant`, `person:PERSON_ID` while not joined.
    bob_person = (outcome.get("participant") or "").split(":", 1)[-1]
    check(re.match(r"^person_[0-9a-f]{64}$", bob_person), f"outcome participant {outcome.get('participant')}")
    state["bob_person"] = bob_person
    alice_p = view["created_by"]
    state["alice_p"], state["alice_person"] = alice_p, alice_p.split("/", 1)[1]
    check_invited(outcome, "person:bob")
    entry = person_entry(view, bob_person)
    check(entry and entry["id"] is None and entry["host_id"] is None and entry["state"] == "invited"
          and entry["label"] == "bob" and entry["local"] is False, f"alice's view of bob's person: {entry}")
    # A message sent before the join is never sent to the person (C3 Messages to people, decision 8).
    said = a.ok("conversation", "say", conv, "before the join")
    check(said["targets"] == [], f"targets of a message before the join: {said['targets']}")
    state["before"] = said["message"]["message_id"]
    for host in (b, b2):
        inv = wait_invite(host, conv)
        check(inv["added_by"] == alice_p and inv["added_by_label"] == "alice" and inv["title"] == "T"
              and inv["home_host_id"] == a.id and inv["person_id"] == bob_person and inv["note"] is None,
              f"{host.name}: invite view {inv}")
        check(when(inv["expires_at"]) - when(inv["added_at"]) == timedelta(days=7),
              f"{host.name}: expires_at {inv['expires_at']} is not added_at {inv['added_at']} + 7 days")
        parts = {p["label"]: p for p in inv["participants"]}
        check(set(parts) == {"alice", "bob"} and parts["alice"]["state"] == "joined"
              and parts["alice"]["id"] == alice_p and parts["bob"]["state"] == "invited" and parts["bob"]["id"] is None
              and parts["bob"]["kind"] == "person", f"{host.name}: invite participants {inv['participants']}")
        # A conversation known only through a pending invite is not held: reads are 404.
        status, body = host.api("GET", f"/v1/conversations/{conv}")
        api_error(status, body, 404, "not_found")
    readable = b.cli("conversations", "--invites")
    line = [x for x in readable.stdout.splitlines() if conv[:13] in x]
    check(readable.ok and len(line) == 1 and '"T"' in line[0] and "from alice" in line[0]
          and f"expires {invites(b)[conv]['expires_at']}" in line[0], f"readable --invites: {readable.stdout!r}")
    usage = b.cli("conversations", "--invites", "--all")
    check(usage.code == 2, f"--invites with --all: exit {usage.code}, want 2")
    shown = a.cli("conversation", "show", conv)
    check(shown.ok and "bob (invited)" in shown.stdout, f"alice's readable show header: {shown.stdout[:400]!r}")


@suite.case("attention", "C3 Status (conversations, conversation_invites attention item)")
def _():
    need("conv")
    body = status_of(b)
    conv = body.get("conversations") or {}
    check(conv.get("invites") == 1 and conv.get("open") == 0, f"bob's status conversations {body.get('conversations')}")
    items = invite_items(body)
    check(items == [{"kind": "conversation_invites", "subject": "1", "detail": "pending conversation invites: 1",
                     "command": "peerspan conversations --invites"}], f"bob's conversation_invites item {items}")
    check(body["attention"][-1]["kind"] == "conversation_invites",
          f"conversation_invites does not sort last: {[i['kind'] for i in body['attention']]}")
    status, v2 = b.api("GET", "/v2/status")
    check(status == 200 and v2.get("conversations") == body.get("conversations") and invite_items(v2) == items,
          f"/v2/status differs: {status} {v2.get('conversations')} {invite_items(v2)}")
    result = b.cli("status")
    check(result.code == 1, f"`peerspan status` with a pending invite: exit {result.code}, want 1")


@suite.case("join_one_host", "C3 Joining, POST /peer/v1/conversations/{id}/join, Pushes, Status")
def _():
    conv, bob_person, alice_p = need("conv", "bob_person", "alice_p")
    bob_p = f"person:{b.id}/{bob_person}"
    state["bob_p"] = bob_p
    joined = b.ok("conversation", "join", conv[:11], timeout=60)
    view = joined["conversation"]
    check(view["conversation_id"] == conv, f"join answer {joined}")
    me = [p for p in view["participants"] if p["id"] == bob_p]
    check(len(me) == 1 and me[0]["state"] == "joined" and me[0]["host_id"] == b.id and me[0]["person_id"] == bob_person
          and me[0]["local"] is True, f"bob's entry after join: {view['participants']}")
    wait_view(a, conv, alice_p, lambda v: v["roster_version"] >= view["roster_version"]
              and any(p["id"] == bob_p and p["state"] == "joined" for p in v["participants"]),
              "bob's person joined from bob on alice")
    check(person_entry(alice_view(conv), bob_person)["id"] == bob_p, "alice's view still has a second bob entry")
    wait_invite(b2, conv, present=False)
    status, body = b2.api("POST", f"/v1/conversations/{conv}/join", {})
    api_error(status, body, 404, "not_found", NO_INVITE)
    refused(b2.cli("conversation", "join", conv), "not_found", NO_INVITE)
    refused(b.cli("conversation", "join", conv[:11]), "not_found", NO_INVITE)
    check(conv not in invites(b), "bob still lists the joined invite")
    body = status_of(b)
    check((body.get("conversations") or {}).get("invites") == 0 and (body.get("conversations") or {}).get("open") == 1
          and invite_items(body) == [], f"bob's status after join {body.get('conversations')} {invite_items(body)}")


@suite.case("messages_person", "C3 Messages to people; C1 Fan-out")
def _():
    conv, bob_p, alice_p, before = need("conv", "bob_p", "alice_p", "before")
    said = a.ok("conversation", "say", conv, "hello bob")
    mid = said["message"]["message_id"]
    check([t["participant"] for t in said["targets"]] == [bob_p], f"alice's targets {said['targets']}")
    show_targets(a, conv, mid, bob_p, "delivered")
    mine = b.ok("conversation", "show", conv, "--json", "--limit", "100")
    ids = [m["message_id"] for m in mine["messages"]]
    check(mid in ids, f"bob's show does not list alice's message: {ids}")
    check(before not in ids, f"bob's show lists the message sent before the join: {ids}")
    old = find_message(a.ok("conversation", "show", conv, "--json", "--limit", "100"), before)
    check(not any(t["participant"] == bob_p for t in old["targets"]), f"the earlier message targets bob: {old}")
    reply = b.ok("conversation", "say", conv, "hello alice")
    rid = reply["message"]["message_id"]
    show_targets(b, conv, rid, alice_p, "delivered")
    got = find_message(a.ok("conversation", "show", conv, "--json", "--limit", "100"), rid)
    check(got["author"] == bob_p and got["author_label"] == "bob" and got["content"] == "hello alice",
          f"bob's message on alice {got}")


@suite.case("block", "C3 Messages to people (step 5 block list); C1 Fan-out (403 -> refused not_authorized)")
def _():
    conv, bob_p = need("conv", "bob_p")
    b.ok("block", "alice")
    try:
        mid = a.ok("conversation", "say", conv, "while blocked")["message"]["message_id"]
        t = show_targets(a, conv, mid, bob_p, "refused")
        check(t["code"] == "not_authorized", f"blocked target {t}")
    finally:
        b.ok("unblock", "alice")
    mid = a.ok("conversation", "say", conv, "after unblock")["message"]["message_id"]
    show_targets(a, conv, mid, bob_p, "delivered")


@suite.case("decline", "C3 Declining, POST /peer/v1/conversations/{id}/leave (decline), Pending invites")
def _():
    bob_person, alice_p = need("bob_person", "alice_p")
    conv, outcome, _view = start_person("person:bob")
    state["declined"] = conv
    check_invited(outcome, "person:bob")
    wait_invite(b, conv)
    wait_invite(b2, conv)
    answer = b2.ok("conversation", "decline", conv)
    check(answer == {"conversation_id": conv, "state": "declined"}, f"decline answer {answer}")
    check(conv not in invites(b2), "bob2 still lists the declined invite")
    wait_view(a, conv, alice_p, lambda v: person_entry(v, bob_person) is None, "bob's person dropped on alice")
    check(departed_of(alice_view(conv)) == {}, f"a declined invite left a departed entry: {alice_view(conv)}")
    wait_invite(b, conv, present=False)
    refused(b2.cli("conversation", "decline", conv), "not_found", NO_INVITE)


@suite.case("remove_invited", "C3 Starting (bare label), Removing a person not yet joined")
def _():
    bob_person, alice_p = need("bob_person", "alice_p")
    conv, outcome, _view = start_person("bob")
    check_invited(outcome, "bob")
    for host in (b, b2):
        wait_invite(host, conv)
    removed = a.ok("conversation", "remove", conv, "bob")
    check(person_entry(removed["conversation"], bob_person) is None and departed_of(removed["conversation"]) == {},
          f"after remove {removed['conversation']}")
    for host in (b, b2):
        wait_invite(host, conv, present=False)


@suite.case("peer_edges", "C3 Peer routes: invites with a person target, join, roster push")
def _():
    bob_person, alice_p, alice_person, joined, declined, ada = need(
        "bob_person", "alice_p", "alice_person", "conv", "declined", "ada")
    path = "/peer/v1/conversations/invites"
    # A consistent person invite is answered invited, so the refusals below come from the one change alone.
    status, answer = peer(a, b, "POST", path, person_invite(new_conv(), bob_person))
    check(status == 200 and answer == {"state": "invited"}, f"a consistent person invite: {status} {answer}")
    status, answer = peer(a, b, "POST", path, person_invite(new_conv(), bob_person,
                                                             policy={"person_id": bob_person, "version": 1}))
    api_error(status, answer, 400, "invalid")
    # Alice's person, created by her agent ada: well formed, but bob is not bound to that person.
    ada_p = f"agent:{a.id}/{ada.id}"

    def ada_creates(roster):
        roster["created_by"] = ada_p
        roster["participants"][0] = {"id": ada_p, "kind": "agent", "host_id": a.id, "person_id": alice_person,
                                     "agent_id": ada.id, "name": "ada", "state": "joined", "added_by": None,
                                     "added_at": roster["created_at"]}
        roster["participants"][1]["added_by"] = ada_p
    status, answer = peer(a, b, "POST", path, person_invite(
        new_conv(), alice_person, ada_creates, adder=ada_p, origin={"agent_id": ada.id, "session_id": ada.session_id}))
    api_error(status, answer, 403, "forbidden")
    # Joins from bob2: bob's person already joined from bob; a conversation that no longer lists bob's person.
    status, answer = peer(b2, a, "POST", f"/peer/v1/conversations/{joined}/join", {"person_id": bob_person})
    api_error(status, answer, 409, "conflict")
    status, answer = peer(b2, a, "POST", f"/peer/v1/conversations/{declined}/join", {"person_id": bob_person})
    api_error(status, answer, 404, "not_found")
    # A roster push listing bob's person as joined on bob2, which holds a pending invite and sent no join.
    conv, outcome, _view = start_person("person:bob")
    state["pending"] = conv
    wait_invite(b2, conv)
    status, body = peer(b2, a, "GET", f"/peer/v1/conversations/{conv}/roster")
    check(status == 200 and isinstance(body, dict) and body["roster"]["conversation_id"] == conv,
          f"GET roster from bob2 (push set of a pending invite): {status} {body}")
    roster = body["roster"]
    for p in roster["participants"]:
        if p.get("person_id") == bob_person and p["kind"] == "person":
            p.update(id=f"person:{b2.id}/{bob_person}", host_id=b2.id, state="joined")
    roster["version"] += 1
    status, answer = peer(a, b2, "POST", f"/peer/v1/conversations/{conv}/roster", {"roster": roster})
    api_error(status, answer, 400, "invalid")
    check(conv in invites(b2), "bob2 dropped its pending invite after a refused roster push")


@suite.case("limit", "C3 POST /peer/v1/conversations/invites step 6 (20 pending per sender host), Invite outcome")
def _():
    bob_person, alice_p = need("bob_person", "alice_p")

    def held(host):
        return sum(1 for i in invites(host).values() if i["home_host_id"] == a.id)
    for _ in range(25):
        if held(b) >= 20 and held(b2) >= 20:
            break
        a.ok("conversation", "start", "person:bob", timeout=60)
    check(held(b) == 20 and held(b2) == 20, f"pending invites from alice: bob {held(b)}, bob2 {held(b2)}, want 20 each")
    conv, outcome, _view = start_person("person:bob")
    check(outcome["state"] == "refused" and outcome["code"] == "limit", f"21st invite outcome {outcome}")
    check(len(outcome["hosts"]) == 2 and all(h["state"] == "refused" and h["code"] == "limit"
                                             for h in outcome["hosts"]), f"21st invite hosts {outcome['hosts']}")
    check(person_entry(alice_view(conv), bob_person) is None, f"alice still lists bob's person in {conv}")
    status, answer = peer(a, b, "POST", "/peer/v1/conversations/invites", person_invite(new_conv(), bob_person))
    api_error(status, answer, 429, "limit", LIMIT)


@suite.case("expiry", "C3 Expiry, Pending invites (7 days, test clock; runs last)")
def _():
    conv, bob_person, alice_p = need("pending", "bob_person", "alice_p")
    check(conv in invites(b), "no invite pending on bob before moving the clock")
    suite.set_offset(suite.offset + WEEK + 1)
    check(invites(b) == {}, f"bob still lists pending invites 7 days later: {sorted(invites(b))}")
    readable = b.cli("conversations", "--invites")
    check(readable.ok and "No pending conversation invites." in readable.stdout,
          f"readable --invites with none: {readable.stdout!r}")
    refused(b.cli("conversation", "join", conv), "not_found", NO_INVITE)
    wait_view(a, conv, alice_p, lambda v: person_entry(v, bob_person) is None,
              "the expired invite dropped on alice", timeout=20)


suite.finish()
