#!/usr/bin/env python3
"""Slim suite 7, work: messages, tasks and delegation chains on a coordinator-free network.

Three people on three hosts (alice creates, bob and carol join), each with one fixture
agent. Written from docs/peer-messaging-contract.md, docs/task-contract.md,
docs/delegation-chain-contract.md and docs/launch-contract.md (slices 3 and 4).
"""
from harness import Suite, check, create_network, in_future, join_new_person, ssh_key, wait_for

suite = Suite("work", __doc__)
a, b, c = suite.host("alice"), suite.host("bob"), suite.host("carol")
keys = {}
state = {}


@suite.case("setup_three_people", "decentralized-spec 6, 8")
def _():
    net = create_network(a, "work", "alice")
    state["network"] = net["id"]
    keys["bob"], keys["carol"] = ssh_key(b.root, "bob"), ssh_key(c.root, "carol")
    join_new_person(a, b, "bob", keys["bob"], net["id"])
    join_new_person(a, c, "carol", keys["carol"], net["id"])
    state["ada"], state["bert"], state["cleo"] = a.agent("ada"), b.agent("bert"), c.agent("cleo")
    # bob lets alice message him and delegate through him; carol lets alice in without delegation.
    allow = b.ok("allow", "alice", "--delegate", "--person-key", keys["bob"])
    check(set(allow["actions"]) == {"message.append", "task.submit", "task.delegate"}, f"allow --delegate: {allow}")
    state["alice_person"] = allow["principal"].split(":", 1)[1]
    c.ok("allow", "alice", "--person-key", keys["carol"])


def need(*names):
    missing = [n for n in names if n not in state]
    check(not missing, f"setup did not finish ({', '.join(missing)} missing)")
    return [state[n] for n in names]


@suite.case("agent_lookup_by_address", "launch-contract 4: directory, addressing")
def _():
    (bert,) = need("bert")
    view = a.ok("agents", "--refresh", "--json")
    reachable = {r["address"]: r for r in view["reachable"]}
    check("bob/bert" in reachable, f"bob/bert not reachable from alice: {sorted(reachable)}")
    entry = reachable["bob/bert"]
    check(entry["agent_id"] == bert.id and entry["host_id"] == b.id, f"bob/bert resolves to {entry}")
    check({"message.append", "task.submit", "task.delegate"} <= set(entry["actions"]),
          f"bob/bert actions {entry['actions']}")
    check("carol/cleo" in reachable, "carol/cleo not reachable from alice")
    check("task.delegate" not in reachable["carol/cleo"]["actions"], "carol/cleo offers task.delegate")
    check(not any(r["address"].startswith("alice/") for r in view["reachable"]), "own agents listed as reachable")
    check(any(m["address"] == "alice/ada" for m in view["mine"]), f"alice/ada not in mine: {view['mine']}")
    # bob allowed only alice: carol's directory does not list bob's agent.
    carol_view = c.ok("agents", "--refresh", "--json")
    check(not any(r["address"] == "bob/bert" for r in carol_view["reachable"]), "bob/bert reachable from carol")
    for address, code, http in (("nobody/none", "unknown", 404), ("alice/ada", "local", 400)):
        status, body = a.api("POST", "/v1/outbound", {"to": address, "content": "hi", "deadline": in_future(hours=1)})
        check(status == http and isinstance(body, dict) and body.get("code") == code,
              f"sending to {address}: {status} {body}, want {http} {code}")


@suite.case("message_and_reply", "peer-messaging-contract; agent-adapter-contract handoff and reply")
def _():
    ada, bert = need("ada", "bert")
    sent = a.ok("send", "bob/bert", "hello bert", "--from-agent", ada.id)
    check(sent["state"] == "accepted", f"send state {sent['state']}")
    check(sent["request"]["policy"] is not None and sent["request"]["grant_id"] is None,
          f"send did not cite bob's policy: {sent['request']}")
    request_id = sent["request"]["request_id"]
    got = bert.next_message()
    check(got["request"]["content"] == "hello bert", f"bert got {got['request']}")
    check(got["request"]["origin"]["agent_id"] == ada.id, f"origin {got['request'].get('origin')}")
    check(got["sender_person_id"] == state["alice_person"] and got["sender_person"] == "alice",
          f"sender person {got.get('sender_person_id')} {got.get('sender_person')}")
    delivery = got["delivery"]["id"]
    status, _ = bert.post(f"/adapter/v1/deliveries/{delivery}/forwarded")
    check(status == 200, f"forwarded: {status}")
    status, body = bert.post(f"/adapter/v1/deliveries/{delivery}/reply", {"content": "hello ada"})
    check(status == 200, f"reply: {status} {body}")
    reply = wait_for(lambda: (r := a.ok("message", "reply", "--peer", b.id, request_id))["state"] == "replied" and r,
                     timeout=20, message="the reply on alice's host")
    check(reply["reply"]["content"] == "hello ada", f"reply content {reply['reply']}")
    # A retry of the same reply is idempotent; different content conflicts.
    status, _ = bert.post(f"/adapter/v1/deliveries/{delivery}/reply", {"content": "hello ada"})
    check(status == 200, f"identical reply retry: {status}")
    status, _ = bert.post(f"/adapter/v1/deliveries/{delivery}/reply", {"content": "changed"})
    check(status == 409, f"changed reply: {status}")
    # carol never allowed bob: bob's message to carol is refused before anything is persisted.
    refused = b.cli("send", "carol/cleo", "hi")
    check(not refused.ok, f"bob -> carol/cleo without access succeeded: {refused.json}")


@suite.case("task_handoff_with_sender_person", "task-contract: lifecycle; adapter tasks/next")
def _():
    ada, bert = need("ada", "bert")
    record = a.ok("task", "bob/bert", "summarize", "--from-agent", ada.id)
    check(record["submit_state"] == "accepted" and record["status"]["state"] == "queued", f"submit {record}")
    task_id = record["request"]["task_id"]
    claimed = bert.next_task()
    check(claimed["task"]["task_id"] == task_id and claimed["task"]["input"] == "summarize", f"claimed {claimed}")
    check(claimed["sender_person_id"] == state["alice_person"] and claimed["sender_person"] == "alice",
          f"sender person {claimed.get('sender_person_id')} {claimed.get('sender_person')}")
    check(claimed["task"]["origin"]["agent_id"] == ada.id, "task origin is not alice's agent")
    for step, body in (("accept", {}), ("progress", {"message": "half way"}),
                       ("complete", {"status": "succeeded", "output": "summary"})):
        status, reply = bert.post(f"/adapter/v1/tasks/{task_id}/{step}", body)
        check(status == 200, f"{step}: {status} {reply}")
    status, _ = bert.post(f"/adapter/v1/tasks/{task_id}/accept", {})
    check(status == 409, f"accept after completion: {status}")
    done = wait_for(lambda: (r := a.ok("task", "inspect", "--peer", b.id, task_id))["status"]["state"] == "succeeded"
                    and r["events_after"] >= 4 and r, timeout=30, message="succeeded on alice's host")
    events = a.ok("task", "events", "--peer", b.id, task_id)
    kinds = [e["kind"] for e in events]
    check(kinds[:4] == ["queued", "accepted", "progress", "succeeded"], f"events {kinds}")
    check(events[3]["output"] == "summary", f"output {events[3]}")
    check(done["submit_state"] == "accepted", f"final record {done['submit_state']}")


@suite.case("delegation_chain_three_hosts", "delegation-chain-contract: links, verification, depth")
def _():
    ada, bert, cleo = need("ada", "bert", "cleo")
    record = a.ok("task", "submit", "--peer", b.id, "--agent", bert.id, "--input", "plan", "--from-agent", ada.id,
                  "--delegation-depth", "1")
    parent = record["request"]["task_id"]
    check(record["delegation"] and len(record["delegation"]) == 1, f"link 0 missing: {record.get('delegation')}")
    link0 = record["delegation"][0]
    check(link0["issuer_host_id"] == a.id and link0["audience_host_id"] == b.id and link0["depth"] == 1
          and link0["principals"] == ["network"] and link0["originator_agent_id"] == ada.id, f"link 0 {link0}")
    claimed = bert.next_task()
    check(claimed["task"]["task_id"] == parent, f"bert claimed {claimed['task']['task_id']}")
    status, _ = bert.post(f"/adapter/v1/tasks/{parent}/accept")
    check(status == 200, f"accept: {status}")
    # bob's owner forwards the running task to carol's agent (carol authorizes the originator, alice).
    child = b.ok("task", "submit", "--peer", c.id, "--agent", cleo.id, "--input", "part", "--parent-sender", a.id,
                 "--parent-task", parent)
    check(child["parent"] == {"sender_host_id": a.id, "task_id": parent}, f"child parent {child.get('parent')}")
    check(len(child["delegation"]) == 2, f"forward chain has {len(child['delegation'])} links")
    link1 = child["delegation"][1]
    check(link1["index"] == 1 and link1["issuer_host_id"] == b.id and link1["audience_host_id"] == c.id
          and link1["depth"] == 0 and link1["originator_agent_id"] == ada.id, f"link 1 {link1}")
    check(child["request"]["origin"]["agent_id"] == bert.id, f"forward origin {child['request'].get('origin')}")
    got = cleo.next_task()
    task = got["task"]
    check(task["task_id"] == child["request"]["task_id"] and len(task.get("delegation", [])) == 2,
          f"carol got {task}")
    check(task["delegation"][0]["issuer_host_id"] == a.id, "carol cannot see the originator host")
    status, _ = cleo.post(f"/adapter/v1/tasks/{task['task_id']}/accept")
    check(status == 200, f"carol accept: {status}")
    # Depth 0: carol may not pass it on.
    again = c.cli("task", "submit", "--peer", b.id, "--agent", bert.id, "--input", "more", "--parent-sender", b.id,
                  "--parent-task", task["task_id"])
    check(not again.ok, f"a fourth hop at depth 0 was accepted: {again.json}")
    # Cancelling the root propagates a cancellation request down the chain.
    a.ok("task", "cancel", "--peer", b.id, parent)
    wait_for(lambda: (cleo.post("/adapter/v1/tasks/cancels/next")[1] or {}).get("status", {}).get("task_id")
             == task["task_id"], timeout=30, message="the propagated cancellation at carol")


@suite.case("forward_refused_without_delegate", "delegation-chain-contract: who may delegate")
def _():
    ada, cleo, bert = need("ada", "cleo", "bert")
    record = a.ok("task", "submit", "--peer", c.id, "--agent", cleo.id, "--input", "x", "--from-agent", ada.id,
                  "--delegation-depth", "1")
    task_id = record["request"]["task_id"]
    claimed = cleo.next_task()
    check(claimed["task"]["task_id"] == task_id, "carol claimed another task")
    status, _ = cleo.post(f"/adapter/v1/tasks/{task_id}/accept")
    check(status == 200, f"accept: {status}")
    forward = c.cli("task", "submit", "--peer", b.id, "--agent", bert.id, "--input", "y", "--parent-sender", a.id,
                    "--parent-task", task_id)
    check(not forward.ok, f"carol forwarded a task her rule did not make delegable: {forward.json}")


suite.finish()
