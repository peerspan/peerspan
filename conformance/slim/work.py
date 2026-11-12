#!/usr/bin/env python3
"""Slim suite 7, work: messages, tasks and delegation chains on a coordinator-free network.

Three people on three hosts (alice creates, bob and carol join), each with one fixture
agent. Written from docs/peer-messaging-contract.md, docs/task-contract.md,
docs/delegation-chain-contract.md and docs/launch-contract.md (slices 3 and 4), and the readable output of sends
and task submissions from docs/cli-output-contract.md sections 1, 2 and 4.
"""
import os
import re
import time

from harness import Suite, check, create_network, in_future, join_new_person, parses_as_json, ssh_key, wait_for

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
    carol_allow = c.ok("allow", "alice", "--person-key", keys["carol"])
    # Policy publication is asynchronous (spec 10). Raw task submissions cite
    # locally verified policies, so establish that prerequisite on every host.
    policies = {}
    for owner, allowed in ((b, allow), (c, carol_allow)):
        status, network = owner.api("GET", f"/v2/networks/{net['id']}")
        check(status == 200, f"{owner.name}: network: {status} {network}")
        policies[network["person_public_key"]] = allowed["policy"]["version"]
    for host in (a, b, c):
        def ready():
            status, body = host.api("POST", f"/v2/networks/{net['id']}/sync", {}, timeout=40)
            check(status == 200, f"{host.name}: sync: {status} {body}")
            status, body = host.api("GET", f"/v2/networks/{net['id']}/access-versions")
            check(status == 200, f"{host.name}: access-versions: {status} {body}")
            return all(any(p["person_public_key"] == person and p["version"] >= version
                           for p in body["policies"]) for person, version in policies.items())

        wait_for(ready, timeout=30, interval=1, message=f"{host.name} to learn the setup access policies")


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


RESULT_BOUND = 2.0  # task-contract Verification (RUN-14): within 2 seconds of completion
LOOK = 10.0  # how long past completion the case keeps watching, to report how late a result was
TRIALS = 3  # running together: at most 3 held polls run at once (task-contract polling)


@suite.case("result_reaches_submitter_promptly", "task-contract polling: a running task polled with wait=10 "
                                                 "and again at once (RUN-14); Verification",
            known="RUN-14: the sender still polls running tasks on the 1 s to 60 s backoff")
def _():
    (bert,) = need("bert")
    # Three tasks at once, not one: under the backoff schedule how late a single result is depends on where the
    # completion falls between two polls, so one task can come back in time by chance; under RUN-14 all three do.
    tasks = [a.ok("task", "bob/bert", f"slow answer {n}")["request"]["task_id"] for n in range(TRIALS)]
    for _ in tasks:
        claimed = bert.next_task()["task"]["task_id"]
        check(claimed in tasks, f"bert claimed {claimed}, not one of {tasks}")
        status, reply = bert.post(f"/adapter/v1/tasks/{claimed}/accept", {})
        check(status == 200, f"accept: {status} {reply}")

    def local(task_id):
        status, record = a.api("GET", f"/v1/tasks/{b.id}/{task_id}")
        check(status == 200, f"alice's local record of {task_id}: {status} {record}")
        return record["status"]["state"]

    # The 8 seconds count from when alice's host has stored each acceptance, so the task is `running` there: from
    # then on the backoff schedule alone would next poll after the completion (about 7 seconds late), while a held
    # poll returns with it. Real time: the backoff schedule runs on a monotonic clock, not the test clock.
    running = {}
    began = time.monotonic()
    while len(running) < len(tasks):
        for task_id in tasks:
            if task_id not in running and local(task_id) == "running":
                running[task_id] = time.monotonic()
        check(time.monotonic() - began < 20, f"alice's local records never all showed running: {running}")
        time.sleep(0.1)
    completed = {}
    for task_id in sorted(tasks, key=running.get):
        time.sleep(max(0.0, running[task_id] + 8 - time.monotonic()))
        status, reply = bert.post(f"/adapter/v1/tasks/{task_id}/complete", {"status": "succeeded", "output": "late"})
        completed[task_id] = time.monotonic()
        check(status == 200, f"complete: {status} {reply}")
    took = {}
    while len(took) < len(tasks):
        for task_id in tasks:
            if task_id not in took and local(task_id) == "succeeded":
                took[task_id] = time.monotonic() - completed[task_id]
        if time.monotonic() - max(completed.values()) > LOOK:
            break
        time.sleep(0.1)
    seen = ", ".join(f"{took[t]:.1f}s" if t in took else f"not within {LOOK:.0f}s" for t in tasks)
    print(f"  alice's local records showed succeeded after: {seen}", flush=True)
    check(len(took) == len(tasks) and max(took.values()) <= RESULT_BOUND,
          f"alice's local records showed succeeded after {seen} from bob's agent completing each task; want "
          f"within {RESULT_BOUND:.0f}s")


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
    # An uncertain submission is retried automatically (task contract, milestone 5 schedule); wait for acceptance.
    child_id = child["request"]["task_id"]
    try:
        wait_for(lambda: b.ok("task", "inspect", "--peer", c.id, child_id)["submit_state"] == "accepted",
                 timeout=45, interval=1, message="carol's host to accept the forwarded task")
    except AssertionError:
        last = b.ok("task", "inspect", "--peer", c.id, child_id)
        raise AssertionError(f"forwarded task never accepted: submit_state {last['submit_state']}, "
                             f"error {last['error']}, attempts {last['attempts']}") from None
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


DIRECTORY_BOUND = 10.0  # launch-contract directory "When:": within 10 seconds of storing a changed policy
POLL = 0.25  # one poll of access-versions plus GET /v1/directory; the observed store can lag by one poll


def bob_policy_version(host):
    """The newest version of bob's policy stored on HOST (a pure read: GET .../access-versions)."""
    net, bob_person = state["network"], state["bob_person_key"]
    status, body = host.api("GET", f"/v2/networks/{net}/access-versions")
    check(status == 200, f"{host.name}: access-versions: {status} {body}")
    return max((p["version"] for p in body["policies"] if p["person_public_key"] == bob_person), default=0)


def lists_bert(host):
    """Whether HOST's cached directory (GET /v1/directory: never a refresh) lists bob/bert with an authorization."""
    status, body = host.api("GET", f"/v1/directory?network={state['network']}")
    check(status == 200, f"{host.name}: directory: {status} {body}")
    return any(e["address"] == "bob/bert" and e["agent_id"] == state["bert"].id and e["authorizations"]
               for e in body["agents"])


def directory_summary(host):
    _, body = host.api("GET", f"/v1/directory?network={state['network']}")
    hosts = [(h.get("person_label"), h.get("state"), h.get("refreshed_at")) for h in body.get("hosts", [])]
    berts = [(e.get("address"), len(e.get("authorizations") or [])) for e in body.get("agents", [])
             if e.get("agent_id") == state["bert"].id]
    return f"refreshed_at {body.get('refreshed_at')}, hosts {hosts}, bert {berts}"


def directory_follows_policy(version, want_listed, what):
    """Poll carol's stored bob-policy version and her non-refreshing directory; the listing must reach WANT_LISTED
    within DIRECTORY_BOUND seconds of carol's host first storing bob's policy VERSION."""
    began = time.monotonic()
    stored_at = listed_at = None
    while True:
        now = time.monotonic()
        if stored_at is None and bob_policy_version(c) >= version:
            stored_at = now
        if lists_bert(c) == want_listed:
            listed_at = time.monotonic()
            if stored_at is not None:
                break
        elif listed_at is not None:
            listed_at = None  # flapped back; keep waiting for a stable change
        if stored_at is None:
            check(now - began < 75, f"carol's host never stored bob's policy version {version} ({what})")
        elif now - stored_at > DIRECTORY_BOUND + POLL:
            snapshot = directory_summary(c)
            # Diagnostic only, after the verdict: does an explicit refresh see the change bob's host now serves?
            after = any(r["address"] == "bob/bert" for r in c.ok("agents", "--refresh", "--json")["reachable"])
            check(False, f"carol's directory {'did not list' if want_listed else 'still listed'} bob/bert "
                  f"{now - stored_at:.1f}s after her host stored bob's policy version {version} "
                  f"({what}); want within {DIRECTORY_BOUND:.0f}s with no refresh; directory {snapshot}; "
                  f"an explicit refresh then {'lists' if after else 'omits'} bob/bert")
        time.sleep(POLL)
    took = max(0.0, listed_at - stored_at)
    check(took <= DIRECTORY_BOUND + POLL, f"{what}: listing changed {took:.1f}s after the policy was stored")
    return took


@suite.case("directory_follows_synced_policy", "launch-contract directory When: a stored policy received by sync")
def _():
    (bert,) = need("bert")
    net = state["network"]
    status, view = b.api("GET", f"/v2/networks/{net}")
    check(status == 200, f"bob: network: {status} {view}")
    state["bob_person_key"] = view["person_public_key"]
    # One explicit refresh: carol's cache is current, and bob has not allowed carol, so it omits bob/bert.
    fresh = c.ok("agents", "--refresh", "--json")
    check(not any(r["address"] == "bob/bert" for r in fresh["reachable"]), "bob/bert reachable from carol already")
    check(not lists_bert(c), "carol's directory lists bob/bert before bob allows her")
    # From here carol's side only reads: no refresh, no send (an unknown address would refresh), no forced sync.
    allowed = b.ok("allow", "carol", "--person-key", keys["bob"])
    took = directory_follows_policy(allowed["policy"]["version"], True, "bob allow carol")
    listed = c.ok("agents", "--json")
    check(any(r["address"] == "bob/bert" and r["agent_id"] == bert.id for r in listed["reachable"]),
          f"agents --json (no refresh) omits bob/bert after the directory listed it: {listed['reachable']}")
    denied = b.ok("deny", "carol", "--person-key", keys["bob"])
    check(denied["removed"] == 1, f"deny carol removed {denied['removed']}")
    gone = directory_follows_policy(bob_policy_version(b), False, "bob deny carol")
    listed = c.ok("agents", "--json")
    check(not any(r["address"] == "bob/bert" for r in listed["reachable"]),
          "agents --json (no refresh) still lists bob/bert after the directory dropped it")
    print(f"  carol's directory listed bob/bert {took:.1f}s and dropped it {gone:.1f}s after storing the policy",
          flush=True)


# CLI output contract (OUT-1, OUT-2): sends and task submissions. Last, so the messages and tasks they leave in
# bert's queues do not reach the cases above.

def readable_ids(text, prefix):
    """Every whole ID with PREFIX in TEXT."""
    return set(re.findall(rf"\b{prefix}[0-9A-Za-z]+\b", text))


@suite.case("send_json_and_readable", "CLI output contract 1, 2 `send`, 4 (`--json` everywhere, sends)")
def _():
    front = a.cli("--json", "send", "bob/bert", "json before")
    back = a.cli("send", "bob/bert", "json after", "--json")
    for one, text in ((front, "json before"), (back, "json after")):
        check(one.ok and isinstance(one.json, dict) and one.json.get("state") == "accepted"
              and one.json["request"]["content"] == text, f"send --json ({text}): exit {one.code}, {one.stdout[:300]!r}")
    check(set(front.json) == set(back.json) and set(front.json["request"]) == set(back.json["request"]),
          f"send --json fields differ before and after the subcommand: {sorted(front.json)} / {sorted(back.json)}")
    result = a.cli("send", "bob/bert", "readable send")
    check(result.code == front.code, f"readable send: exit {result.code}, with --json {front.code}")
    check(result.stdout.strip() and not parses_as_json(result.stdout),
          f"send printed JSON or nothing by default: {result.stdout[:300]!r}")
    prefix = front.json["request"]["request_id"].split("_", 1)[0] + "_"
    named = [i for i in readable_ids(result.stdout, prefix)
             if (lambda r: r[0] == 200 and r[1]["request"]["content"] == "readable send")(
                 a.api("GET", f"/v1/outbound/{b.id}/{i}"))]
    check(named, f"the readable send does not name its full message ID: {result.stdout[:400]!r}")
    check("delivered" in result.stdout.lower(), f"an accepted send does not say it was delivered: {result.stdout[:400]!r}")


@suite.case("task_submit_json_and_readable", "CLI output contract 1, 2 `task submit`, 4 (`--json` everywhere, sends)")
def _():
    (bert,) = need("bert")
    ids = ["task_" + os.urandom(16).hex() for _ in range(3)]
    submit = ["task", "submit", "--peer", b.id, "--agent", bert.id, "--input"]
    front = a.cli("--json", *submit, "json before", "--task", ids[0])
    back = a.cli(*submit, "json after", "--task", ids[1], "--json")
    record = {"peer_host_id", "request", "submit_state", "status", "events_after", "cancel_state", "adapter_id",
              "route_id", "attempts", "next_attempt_at", "error", "status_queries"}  # task contract, local record
    for one, task_id in ((front, ids[0]), (back, ids[1])):
        check(one.ok and isinstance(one.json, dict) and record <= set(one.json)
              and one.json["request"]["task_id"] == task_id and one.json["submit_state"] == "accepted",
              f"task submit --json: exit {one.code}, {one.stdout[:300]!r}")
    check(set(front.json) == set(back.json), f"task submit --json fields differ: {sorted(front.json)} / {sorted(back.json)}")
    result = a.cli(*submit, "readable task", "--task", ids[2])
    check(result.code == front.code, f"readable task submit: exit {result.code}, with --json {front.code}")
    check(result.stdout.strip() and not parses_as_json(result.stdout),
          f"task submit printed JSON or nothing by default: {result.stdout[:300]!r}")
    check(ids[2] in readable_ids(result.stdout, "task_"), f"the readable task submit lacks its task ID: {result.stdout[:400]!r}")
    follow = [line for line in result.stdout.splitlines() if "peerspan task inspect" in line]
    check(follow and any(ids[2] in line for line in follow),
          f"the readable task submit does not give `peerspan task inspect` for {ids[2]}: {result.stdout[:400]!r}")
    check(a.ok("task", "inspect", "--peer", b.id, ids[2])["request"]["input"] == "readable task",
          "the readable submit did not submit the task")


@suite.case("task_shorthand_json_positions", "CLI output contract 4 (`--json` everywhere: `task TARGET TEXT`)")
def _():
    runs = {"before the subcommand": a.cli("--json", "task", "bob/bert", "short before"),
            "after the subcommand": a.cli("task", "--json", "bob/bert", "short middle"),
            "after TEXT": a.cli("task", "bob/bert", "short after", "--json")}
    keys = set()
    for (where, one), text in zip(runs.items(), ("short before", "short middle", "short after")):
        check(one.ok and isinstance(one.json, dict) and one.json.get("submit_state") == "accepted"
              and one.json["request"]["input"] == text and {"request", "submit_state", "status"} <= set(one.json),
              f"`task bob/bert TEXT` with --json {where}: exit {one.code}, {one.stdout[:300]!r}")
        keys = keys or set(one.json)
        check(set(one.json) == keys, f"--json {where} gives fields {sorted(one.json)}, want {sorted(keys)}")


suite.finish()
