#!/usr/bin/env python3
"""Slim suite 9, live delivery: readiness, seen tracking, redelivery, task adoption and pending work.

alice sends to bob's agents, which are fixture adapters on bob's host that choose when to call
`peerspan_ready` (POST /adapter/v1/ready) and what to report seen. A session is replaced the way an owner
does it: detach it, then set up a fresh session for the same agent. Every host shares one debug test clock,
moved forward once for the 120-second status item. Written from docs/live-delivery-contract.md (slices 1 and
2), with docs/agent-adapter-contract.md and docs/adapter-recovery-contract.md.
"""
import json

from harness import Suite, check, create_network, join_new_person, ssh_key, wait_for

suite = Suite("live", __doc__)
suite.use_clock()
a, b = suite.host("alice"), suite.host("bob")
state = {}
WORK_ROUTES = ("/adapter/v1/next", "/adapter/v1/tasks/next", "/adapter/v1/tasks/cancels/next",
               "/adapter/v1/task-updates/next", "/adapter/v1/replies/next")


def need(*names):
    missing = [n for n in names if n not in state]
    check(not missing, f"an earlier case did not finish ({', '.join(missing)} missing)")
    return [state[n] for n in names]


def connection(adapter):
    status, body = b.api("GET", f"/v1/adapters/{adapter.adapter_id}/connection")
    check(status == 200, f"connection of {adapter.name}: {status} {body}")
    return body


def directory_entry(name):
    status, body = a.api("POST", f"/v1/directory/refresh?network={state['net']}", {}, timeout=30)
    check(status == 200, f"directory refresh: {status} {body}")
    return next((x for x in body["agents"] if x["address"] == f"bob/{name}"), None)


def replace(adapter, ready=True):
    """End ADAPTER's authorization (owner detach) and attach a fresh session of the same agent."""
    adapter.stop()
    status, body = b.api("POST", f"/v1/sessions/{adapter.session_id}/detach", {})
    check(status == 200, f"detach {adapter.session_id}: {status} {body}")
    return b.attach(adapter.agent, ready=ready)


def claim(adapter, route):
    status, body = adapter.post(route)
    check(status == 200, f"{adapter.name} {route}: {status} {body}")
    return body


def send(text):
    sent = a.ok("send", "bob/bert", text)
    check(sent["state"] == "accepted", f"send {text!r}: {sent['state']}")
    return sent["request"]["request_id"]


def submit(text):
    record = a.ok("task", "bob/bert", text)
    check(record["submit_state"] == "accepted", f"task {text!r}: {record['submit_state']}")
    return record["request"]["task_id"]


def task_state(task_id):
    return a.ok("task", "inspect", "--peer", b.id, task_id)


@suite.case("setup", "spec 6, 8; live delivery slice 1")
def _():
    net = create_network(a, "live", "alice")
    state["net"] = net["id"]
    key = ssh_key(b.root, "bob")
    join_new_person(a, b, "bob", key, net["id"])
    b.ok("allow", "alice", "--person-key", key)
    state["bert"] = b.agent("bert", ready=False)


@suite.case("work_waits_for_ready", "live delivery slice 1: work routes, connected and status")
def _():
    (bert,) = need("bert")
    for route in WORK_ROUTES:
        status, body = bert.post(route)
        check(status == 409 and body == {"code": "conflict", "error": "channel not verified"},
              f"{route} before peerspan_ready: {status} {body}")
    status, body = bert.call("GET", "/adapter/v1/destinations")
    check(status == 200, f"outbound tools before verification: {status} {body}")
    view = connection(bert)
    check(view.get("channel") == "unverified" and view.get("channel_verified_at") is None,
          f"connection before ready: channel {view.get('channel')}, verified at {view.get('channel_verified_at')}")
    entry = wait_for(lambda: directory_entry("bert"), timeout=20, message="bob/bert in alice's directory")
    check(entry["connected"] is False and entry.get("channel") == "unverified",
          f"alice's directory before ready: connected {entry['connected']}, channel {entry.get('channel')}")


@suite.case("ready_verifies_the_channel", "live delivery slice 1: handshake, connected")
def _():
    (bert,) = need("bert")
    bert.ready()
    first = connection(bert)
    check(first.get("channel") == "verified" and first.get("channel_verified_at"), f"after ready: {first}")
    bert.ready()  # idempotent; keeps the first time
    check(connection(bert)["channel_verified_at"] == first["channel_verified_at"], "a second ready moved the time")
    status, body = bert.post("/adapter/v1/next")
    check(status == 200 and body is None, f"next after ready with nothing queued: {status} {body}")
    entry = wait_for(lambda: (x := directory_entry("bert")) and x["connected"] and x, timeout=20,
                     message="bob/bert connected in alice's directory")
    check(entry.get("channel") == "verified", f"alice's directory after ready: channel {entry.get('channel')}")
    status, body = b.api("GET", f"/v1/sessions/{bert.session_id}")
    check(status == 200 and body.get("channel") == "verified", f"session view channel: {body.get('channel')}")


@suite.case("protocol_version_recorded", "live delivery slice 1: mcp_protocol")
def _():
    (bert,) = need("bert")
    status, body = bert.call("POST", "/adapter/v1/connect", {
        "adapter_id": bert.adapter_id, "session_id": bert.session_id, "instance_id": bert.instance,
        "protocol_version": "2025-06-18"})
    check(status == 200, f"connect with protocol_version: {status} {body}")
    check(connection(bert).get("protocol_version") == "2025-06-18", "protocol_version not stored")
    status, _ = bert.call("POST", "/adapter/v1/connect", {
        "adapter_id": bert.adapter_id, "session_id": bert.session_id, "instance_id": bert.instance})
    check(status == 200 and connection(bert).get("protocol_version") == "2025-06-18",
          "a connect without protocol_version cleared it")


@suite.case("verification_survives_restart", "live delivery slice 1: recovery; adapter recovery contract")
def _():
    (bert,) = need("bert")
    b.restart()
    # The same instance reconnects within the 15-second window (the fixture's renewal does it every 4 s).
    status = wait_for(lambda: (r := bert.post("/adapter/v1/next"))[0] != 503 and r[0] != 401 and r, timeout=20,
                      message="bert to recover its lease")
    check(status[0] == 200, f"next after recovery: {status}")
    check(connection(bert)["channel"] == "verified", "verification lost across a daemon restart")
    bix = b.agent("bix", ready=False)
    status, body = bix.post("/adapter/v1/next")
    check(status == 409, f"a new attachment's next before ready: {status} {body}")
    state["bix"] = bix


@suite.case("channel_unverified_status_item", "live delivery slice 1: status item 13")
def _():
    (bix,) = need("bix")
    kinds = {i["kind"] for i in b.api("GET", "/v1/status")[1]["attention"]}
    check("channel_unverified" not in kinds, "item 13 before 120 seconds")
    suite.set_offset(suite.offset + 130)

    def item():
        for i in b.api("GET", "/v1/status")[1]["attention"]:
            if i["kind"] == "channel_unverified":
                return i
        return None

    found = wait_for(item, timeout=20, message="channel_unverified after 120 s")
    check(found["subject"] == "bix" and found["command"] == "peerspan session doctor", f"item 13: {found}")
    bix.ready()
    wait_for(lambda: item() is None, timeout=10, message="item 13 to clear after ready")


@suite.case("seen_and_mark_seen", "live delivery slice 2: seen, mark_seen, pending work")
def _():
    (bert,) = need("bert")
    send("one")
    send("two")
    d1 = bert.next_message()
    d2 = bert.next_message()
    check(d1["redelivered"] is False and d2["redelivered"] is False, "a first delivery marked redelivered")
    id1, id2 = d1["delivery"]["id"], d2["delivery"]["id"]
    status, body = bert.post("/adapter/v1/seen", {"ids": [id1]})
    check(status == 200 and body == {"seen": [id1]}, f"mark_seen: {status} {body}")
    status, body = bert.post("/adapter/v1/seen", {"ids": [id1]})
    check(status == 200, f"mark_seen of an already seen ID: {status} {body}")
    status, body = bert.post("/adapter/v1/seen", {"ids": [id2, "delivery_" + "0" * 32]})
    check(status == 404, f"mark_seen with an ID this session does not hold: {status} {body}, want 404")
    status, pending = bert.call("GET", "/adapter/v1/pending")
    check(status == 200 and {"deliveries", "replies", "tasks"} <= set(pending), f"pending: {status} {pending}")
    by_id = {x["delivery_id"]: x for x in pending["deliveries"]}
    check(by_id.get(id1, {}).get("seen") is True and by_id.get(id2, {}).get("seen") is False,
          f"seen flags after the refused mark_seen: {by_id}")
    check({"delivery_id", "request_id", "sender_host_id", "origin_agent_id", "preview", "seen", "deadline",
           "redelivered"} <= set(by_id[id2]), f"pending delivery fields {sorted(by_id[id2])}")
    check(by_id[id2]["preview"] == "two" and [x["delivery_id"] for x in pending["deliveries"]][:2] == [id1, id2],
          f"pending order or preview: {pending['deliveries']}")
    status, _ = bert.post(f"/adapter/v1/deliveries/{id2}/reply", {"content": "ok"})
    check(status == 200, f"reply: {status}")
    status, pending = bert.call("GET", "/adapter/v1/pending")
    check(id2 not in {x["delivery_id"] for x in pending["deliveries"]}, "an answered delivery is still pending")
    status, owner = b.api("GET", f"/v1/sessions/{bert.session_id}/pending")
    check(status == 200 and owner == pending, f"GET /v1/sessions/ID/pending differs: {status} {owner}")
    state["seen_ids"] = {id1, id2}


@suite.case("session_pending_without_attachment", "live delivery slice 2: session pending")
def _():
    for flag in ("--json", "--hook"):
        result = b.cli("session", "pending", flag)
        check(result.ok and result.stdout.strip() == "",
              f"session pending {flag} with no attachment here: exit {result.code} {result.stdout[:200]!r}")


@suite.case("redelivery_after_replacement", "live delivery slice 2: redelivery, events")
def _():
    bert, seen_ids = need("bert", "seen_ids")
    send("three")
    task_id = submit("job")
    message = bert.next_message()
    task = bert.next_task()
    check(task["task"]["task_id"] == task_id, "bert claimed another task")
    fresh = replace(bert)
    state["bert"] = fresh
    again = fresh.next_message()
    check(again["delivery"]["id"] == message["delivery"]["id"] and again["redelivered"] is True,
          f"redelivered message: id {again['delivery']['id']}, redelivered {again.get('redelivered')}")
    check(again["delivery"]["id"] not in seen_ids, "a seen delivery came back")
    task_again = fresh.next_task()
    check(task_again["task"]["task_id"] == task_id and task_again["redelivered"] is True
          and task_again.get("adopted") is False, f"redelivered task: {task_again}")
    status, body = fresh.post("/adapter/v1/next")
    check(status == 200 and body is None, f"a seen or answered message was redelivered: {body}")
    check(task_state(task_id)["submit_state"] == "accepted", "the sender's view of the task changed")
    status, _ = fresh.post("/adapter/v1/seen", {"ids": [again["delivery"]["id"]]})
    check(status == 200, f"mark_seen of the redelivered message: {status}")
    state["task"] = task_id


@suite.case("task_adoption", "live delivery slice 2: adoption")
def _():
    bert, task_id = need("bert", "task")
    for step, body in (("accept", {}), ("progress", {"message": "half way"})):
        status, reply = bert.post(f"/adapter/v1/tasks/{task_id}/{step}", body)
        check(status == 200, f"{step}: {status} {reply}")
    old = bert
    state["bert"] = new = replace(old)
    adopted = new.next_task()
    check(adopted["task"]["task_id"] == task_id and adopted.get("adopted") is True, f"adopted handoff {adopted}")
    check(adopted["status"]["state"] == "running" and adopted.get("progress") == "half way",
          f"adopted state {adopted['status']} progress {adopted.get('progress')}")
    status, _ = old.post(f"/adapter/v1/tasks/{task_id}/progress", {"message": "from the old session"})
    check(status != 200, "the replaced authorization changed an adopted task")
    a.ok("task", "cancel", "--peer", b.id, task_id)
    wait_for(lambda: task_state(task_id)["status"]["cancel_requested"] is True, timeout=20,
             message="cancel_requested on alice's host")
    state["bert"] = newer = replace(new)
    adopted = newer.next_task()
    check(adopted["task"]["task_id"] == task_id and adopted.get("adopted") is True
          and adopted["status"]["state"] == "running" and adopted["status"]["cancel_requested"] is True,
          f"cancel-requested adoption {adopted}")
    cancel = claim(newer, "/adapter/v1/tasks/cancels/next")
    check(cancel and cancel["status"]["task_id"] == task_id, f"the adopting session's cancellation: {cancel}")
    status, body = newer.post(f"/adapter/v1/tasks/{task_id}/cancelled", {})
    check(status == 200, f"the adopting session confirming the cancellation: {status} {body}")


@suite.case("redelivery_limit", "live delivery slice 2: at most 3 redeliveries; blocked and failed")
def _():
    (bert,) = need("bert")
    send("never seen")
    task_id = submit("never seen task")
    first = None
    for round_ in range(4):
        message = bert.next_message()
        task = bert.next_task()
        first = first or message["delivery"]["id"]
        check(message["delivery"]["id"] == first, f"round {round_}: another message {message['delivery']['id']}")
        check(task["task"]["task_id"] == task_id, f"round {round_}: another task")
        check(message["redelivered"] is (round_ > 0), f"round {round_}: redelivered {message['redelivered']}")
        bert = replace(bert)
    state["bert"] = bert
    status, body = bert.post("/adapter/v1/next")
    check(status == 200 and body is None, f"a fifth session got the message: {body}")
    status, body = bert.post("/adapter/v1/tasks/next")
    check(status == 200 and body is None, f"a fifth session got the task: {body}")
    deliveries = b.ok("delivery", "list")
    record = next((d.get("delivery", d) for d in deliveries if first in json.dumps(d)), None)
    check(record and record.get("state") == "blocked",
          f"the never-seen message's delivery: {record if record else str(deliveries)[:600]}")
    final = wait_for(lambda: (r := task_state(task_id))["status"]["state"] == "failed" and r, timeout=20,
                     message="the never-seen task to fail on alice's host")
    events = a.ok("task", "events", "--peer", b.id, task_id)
    check(events[-1]["kind"] == "failed" and "session never saw the task" in json.dumps(events[-1]),
          f"the failed event: {events[-1]}")
    check(final["submit_state"] == "accepted", f"submit state {final['submit_state']}")


suite.finish()
