#!/usr/bin/env python3
"""Experiment check, no model: with PEERSPAN_EXPERIMENT_WAKE=lead the hosts wake as the lead proposal says.

Run from conformance/slim's harness: python3 experiment/lead_wake_check.py --bin DIR. alice's host has `api`, bob's has
`db` and `release`, the same shape as the comparison. api is the lead, since it is the creator's person's agent.
"""
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "conformance" / "slim"))
from harness import Suite, check, create_network, join_new_person, ssh_key, wait_for  # noqa: E402

suite = Suite("lead_wake_check", __doc__)
a, b = suite.host("alice", start=False), suite.host("bob", start=False)
for host in (a, b):
    host.extra_env["PEERSPAN_EXPERIMENT_WAKE"] = os.environ.get("PEERSPAN_EXPERIMENT_WAKE", "lead")
    host.start()
state = {}


def claim(adapter):
    status, body = adapter.post("/adapter/v1/conversation-notifications/next", {})
    check(status == 200, f"{adapter.name}: claim: {status} {body}")
    return body


def claim_message(adapter):
    """The next message claim, past roster notifications; None when none is on offer."""
    while True:
        body = claim(adapter)
        if body is None or body["notification"]["kind"] == "message":
            return body


def settled(adapter, seconds=2.0):
    """No message claim appears for ADAPTER."""
    end = time.time() + seconds
    while time.time() < end:
        body = claim_message(adapter)
        check(body is None, f"{adapter.name} woke: {body and body['messages']}")
        time.sleep(0.2)


def pid(adapter):
    return f"agent:{adapter.host.id}/{adapter.id}"


def say(conv, text, *extra):
    return a.ok("conversation", "say", conv, text, *extra)["message"]["message_id"]


@suite.case("setup", "two people, three agents, all joined")
def _():
    net = create_network(a, "lead", "alice")
    key = ssh_key(b.root, "bob")
    join_new_person(a, b, "bob", key, net["id"])
    allowed = b.ok("allow", "alice", "--no-tasks", "--person-key", key)

    def held():
        a.api("POST", f"/v2/networks/{net['id']}/sync", {}, timeout=40)
        versions = a.api("GET", f"/v2/networks/{net['id']}/access-versions")[1]
        return any(p["version"] >= allowed["policy"]["version"] for p in versions["policies"])
    wait_for(held, timeout=30, interval=1, message="alice to hold bob's policy")
    allowed_back = a.ok("allow", "bob", "--no-tasks")

    def held_back():
        b.api("POST", f"/v2/networks/{net['id']}/sync", {}, timeout=40)
        versions = b.api("GET", f"/v2/networks/{net['id']}/access-versions")[1]
        return any(p["version"] >= allowed_back["policy"]["version"] for p in versions["policies"])
    wait_for(held_back, timeout=30, interval=1, message="bob to hold alice's policy")
    state.update(api=a.agent("api"), db=b.agent("db"), release=b.agent("release"))
    a.ok("agents", "--refresh", "--json")
    started = a.ok("conversation", "start", f"{a.id}/api", "bob/db", "bob/release", timeout=60)
    check(all(o["state"] == "joined" for o in started["invites"]), f"start: {started['invites']}")
    state["conv"] = started["conversation"]["conversation_id"]
    for name in ("api", "db", "release"):
        while claim(state[name]) is not None:
            pass


@suite.case("unaddressed", "only the lead wakes; the others hold a parked row")
def _():
    say(state["conv"], "one")
    first = wait_for(lambda: claim_message(state["api"]), timeout=20, message="the lead to wake")
    check(first["lead_rule"] == {"lead": first["lead_rule"]["lead"], "you": True}, f"lead_rule: {first['lead_rule']}")
    settled(state["db"])
    settled(state["release"])


@suite.case("parked_visible", "a parked message can be read, and is not pending work")
def _():
    status, body = state["db"].call("GET", f"/adapter/v1/conversations/{state['conv']}/messages")
    check(status == 200 and any(m["content"] == "one" for m in body["messages"]), f"history: {status} {body}")
    pending = state["release"].call("GET", "/adapter/v1/pending")[1]
    check(pending["conversations"] == [], f"pending lists parked: {pending['conversations']}")


@suite.case("addressed", "only the named agent wakes, and gets what it slept through in the window")
def _():
    say(state["conv"], "two", "--to", "bob/db")
    woke = wait_for(lambda: claim_message(state["db"]), timeout=20, message="db to wake")
    check(woke["messages"][0]["content"] == "two", f"new message: {woke['messages']}")
    check([m["content"] for m in woke["window"]] == ["one"], f"window: {woke['window']}")
    check(len(woke["coalesced"]) == 1, f"coalesced: {woke['coalesced']}")
    check(woke["lead_rule"]["you"] is False, f"lead_rule: {woke['lead_rule']}")
    settled(state["api"])
    settled(state["release"])


@suite.case("lead_author", "an unaddressed message from the lead wakes no one")
def _():
    status, body = state["api"].post(f"/adapter/v1/conversations/{state['conv']}/messages", {"content": "three"})
    check(status in (200, 201), f"send: {status} {body}")
    settled(state["db"])
    settled(state["release"])


@suite.case("agent_to_lead", "an unaddressed message from another agent wakes the lead")
def _():
    status, body = state["db"].post(f"/adapter/v1/conversations/{state['conv']}/messages", {"content": "four"})
    check(status in (200, 201), f"send: {status} {body}")
    woke = wait_for(lambda: claim_message(state["api"]), timeout=20, message="the lead to wake")
    check(woke["messages"][0]["content"] == "four", f"new message: {woke['messages']}")
    settled(state["release"])


suite.finish()
