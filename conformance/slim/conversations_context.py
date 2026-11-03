#!/usr/bin/env python3
"""Slim suite, conversations C5: session context.

alice creates a coordinator-free network; bob joins it and allows alice. Each case has a conversation and
fixture agents of its own on bob or alice, so a failure stays in its case. A fixture session claims only when the suite
asks, and is replaced as in live.py. `deny alice` on bob makes alice fail the handoff recheck. The cases cover
catch-up, pending work, the seen paths, the redelivery limit, blocked messages on every surface, `undelivered`
notifications, history pages, C7's lead (waking, parked notifications, the gather, lead changes and agent
descriptions) and, last, a `stopped` target on the test clock. Its own suite and CI job so the conversations job stays
under 2 minutes. Written from docs/conversations-contract.md, sections C5 and C7 (cited as "C5 <part>" and
"C7 <part>"), and the sections they build on, only.
"""
import os

from harness import (Suite, api_error, check, create_network, departed_of, find_message, join_new_person, message_id,
                     peer, refused, show_targets, ssh_key, target_of, view_as, wait_for, wait_view)

suite = Suite("conversations_context", __doc__)
suite.use_clock()  # C5 Verification `stopped`: the 24-hour move needs the test clock before any host starts
a, b = suite.host("alice"), suite.host("bob")
state = {}

CLAIM = "/adapter/v1/conversation-notifications/next"
NOT_PARTICIPANT = "This participant is not in that conversation."
BAD_SEEN = "invalid request: ids must be 1 to 100 delivery, request, task, call, conversation, or conversation message IDs"
BUDGET = 262_144
LARGE = 65_536
DAY = 24 * 3600


def need(*names):
    missing = [n for n in names if n not in state]
    check(not missing, f"an earlier case did not finish ({', '.join(missing)} missing)")
    return [state[n] for n in names]


def policy_version(host):
    status, body = host.api("GET", f"/v2/networks/{state['net']}/access-versions")
    check(status == 200, f"{host.name}: access-versions: {status} {body}")
    return max((p["version"] for p in body["policies"] if p["person_public_key"] == state["bob_public"]), default=0)


def wait_policy(version):
    """bob's policy commands take effect on bob at once (C5 Verification setup); alice must hold the version to cite."""
    def ready():
        status, body = a.api("POST", f"/v2/networks/{state['net']}/sync", {}, timeout=40)
        check(status == 200, f"alice: sync: {status} {body}")
        return policy_version(a) >= version
    wait_for(ready, timeout=30, interval=1, message=f"alice to hold bob's policy version {version}")


def deny():
    """C5 Verification setup: takes effect on bob at once."""
    b.ok("deny", "alice", "--person-key", state["bob_key"])
    state["denied"] = True


def allow():
    """Undo deny(), with the policy wait so alice can cite it. Does nothing when alice is already allowed."""
    if state.pop("denied", False):
        version = b.ok("allow", "alice", "--no-tasks", "--person-key", state["bob_key"])["policy"]["version"]
        wait_policy(version)


def new_agent(name, host=b, **kw):
    adapter = host.agent(name, **kw)
    a.ok("agents", "--refresh", "--json")
    return adapter


def participant(adapter):
    return f"agent:{adapter.host.id}/{adapter.id}"


def replace(adapter):
    """End ADAPTER's authorization and attach a verified session of the same agent (C5 Verification, as live.py)."""
    adapter.stop()
    status, body = adapter.host.api("POST", f"/v1/sessions/{adapter.session_id}/detach", {})
    check(status == 200, f"detach {adapter.session_id}: {status} {body}")
    return adapter.host.attach(adapter.agent)


def claim(adapter):
    status, body = adapter.post(CLAIM, {})
    check(status == 200, f"{adapter.name}: claim: {status} {body}")
    return body


def claim_one(adapter):
    return wait_for(lambda: claim(adapter), timeout=20, interval=0.3, message=f"a claim for {adapter.name}")


def no_claim(adapter, why):
    got = claim(adapter)
    check(got is None, f"{adapter.name}: claim {why}: {got}, want null")


def seen(adapter, *ids):
    return adapter.post("/adapter/v1/seen", {"ids": list(ids)})


def seen_ok(adapter, *ids):
    status, body = seen(adapter, *ids)
    check(status == 200 and body == {"seen": list(ids)}, f"{adapter.name}: seen {ids}: {status} {body}")


def start(*adapters, title=None):
    """alice's person starts a conversation with ADAPTERS; each claims its `added` notification and sees it."""
    args = ["conversation", "start", *[f"{x.host.name}/{x.name}" for x in adapters]]
    args += ["--title", title] if title else []
    started = a.ok(*args, timeout=60)
    conv = started["conversation"]["conversation_id"]
    check(all(i["state"] == "joined" for i in started["invites"]), f"start: {started['invites']}")
    for x in adapters:
        got = claim_one(x)
        check(got["notification"]["kind"] == "roster" and got["notification"]["seen_at"] is None
              and got["notification"]["redeliveries"] == 0 and got["catch_up"] is False and got["coalesced"] == []
              and got["notification"]["undelivered"] is None, f"{x.name}: `added` claim {got}")
        seen_ok(x, conv)
    return conv


def say(conv, adapter, *texts):
    """alice's person sends TEXTS, each after ADAPTER's target for the one before is `delivered`, since a claim's order
    is arrival order and quick sends can arrive in either (C6 Verification Claim order). Returns the message IDs."""
    ids = []
    for text in texts:
        mid = a.ok("conversation", "say", conv, text)["message"]["message_id"]
        ids.append(mid)
        last = {}

        def delivered(mid=mid):
            view = a.ok("conversation", "show", conv, "--json", "--limit", "100")
            last["t"] = target_of(find_message(view, mid), participant(adapter))
            check(last["t"]["state"] in ("sending", "delivered"), f"target {last['t']}")
            return last["t"]["state"] == "delivered"
        try:
            wait_for(delivered, timeout=30, interval=0.1, message="delivery")
        except AssertionError as error:
            raise AssertionError(f"{error}; target {last.get('t')}") from None
    return ids


def send(adapter, conv, text, to=None):
    body = {"content": text, **({"addressed_to": to} if to else {})}
    status, body = adapter.post(f"/adapter/v1/conversations/{conv}/messages", body)
    check(status == 200, f"{adapter.name}: send: {status} {body}")
    return body["message"]["message_id"]


def ids_of(messages):
    return [m["message_id"] for m in messages]


def new_message(got, conv, mid, *, redelivered=False, catch_up=False, redeliveries=0, unseen=None, coalesced=()):
    """The claim's fields shared by every message claim (C5 Claiming)."""
    check(isinstance(got, dict), f"claim of {mid}: {got}")
    n = got["notification"]
    check(n["kind"] == "message" and n["conversation_id"] == conv and n["message_id"] == mid and n["seen_at"] is None
          and n["redeliveries"] == redeliveries and n["undelivered"] is None,
          f"notification {n}, want message {mid} with {redeliveries} redeliveries, unseen")
    check(ids_of(got["messages"]) == [mid], f"`messages` {ids_of(got['messages'])}, want exactly {mid}")
    check(got["redelivered"] is redelivered and got["catch_up"] is catch_up,
          f"redelivered {got['redelivered']} catch_up {got['catch_up']}, want {redelivered} and {catch_up}")
    check(got["coalesced"] == list(coalesced), f"coalesced {got['coalesced']}, want {list(coalesced)}")
    if unseen is not None:
        check(got["conversation"]["unseen"] == unseen, f"claim unseen {got['conversation']['unseen']}, want {unseen}")


def window(got, ids, total=None):
    check(ids_of(got["window"]) == ids and got["window_total"] == (len(ids) if total is None else total),
          f"window {ids_of(got['window'])} of {got['window_total']}, want {ids} of {total}")


def pending(adapter):
    status, body = adapter.call("GET", "/adapter/v1/pending")
    check(status == 200 and isinstance(body, dict) and isinstance(body.get("conversations"), list),
          f"{adapter.name}: pending: {status} {body}")
    return body


def owner_pending(adapter):
    status, body = adapter.host.api("GET", f"/v1/sessions/{adapter.session_id}/pending")
    check(status == 200 and isinstance(body, dict) and isinstance(body.get("conversations"), list),
          f"{adapter.name}: owner pending: {status} {body}")
    return body


def pending_entry(adapter, conv):
    """ADAPTER's `pending_work` entry for CONV on both routes (the same object), or None."""
    theirs, owners = pending(adapter), owner_pending(adapter)
    check(theirs == owners, f"pending differs: adapter {theirs}, owner {owners}")
    found = [e for e in theirs["conversations"] if e["conversation_id"] == conv]
    check(len(found) <= 1, f"more than one entry for {conv}: {found}")
    return found[0] if found else None


def listed(adapter, conv):
    status, body = adapter.call("GET", "/adapter/v1/conversations")
    check(status == 200, f"{adapter.name}: list: {status} {body}")
    found = [x for x in body["conversations"] if x["conversation_id"] == conv]
    return found[0] if found else None


def unseen(adapter, conv):
    entry = listed(adapter, conv)
    check(entry is not None, f"{adapter.name}: {conv} is not listed")
    return entry["unseen"]


def history(adapter, conv, query=""):
    return adapter.call("GET", f"/adapter/v1/conversations/{conv}/messages{query}")


def history_ids(adapter, conv, query="?limit=50"):
    status, body = history(adapter, conv, query)
    check(status == 200 and isinstance(body, dict), f"{adapter.name}: history: {status} {body}")
    return ids_of(body["messages"])


def shown(adapter, conv):
    """`conversation show --as AGENT --json` on the agent's host: a read that marks nothing (C5 Seen)."""
    view = adapter.host.ok("conversation", "show", conv, "--json", "--limit", "100", "--as", adapter.name)
    check(isinstance(view, dict) and isinstance(view.get("messages"), list), f"show --as: {view}")
    return view


@suite.case("setup", "C5 Verification setup; C1, C2 Verification setup; decentralized-spec 6, 8")
def _():
    net = create_network(a, "context", "alice")
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


@suite.case("catch_up", "C5 Claiming step 5, Claim, Notification life, `pending_work`, `forwarded`, Verification")
def _():
    need("alice_p")
    bert = new_agent("bert")
    conv = start(bert, title="Flaky checkout test")
    long_tail = "third " + "é" * 250  # a preview is the first 200 characters, not bytes
    m1, m2, m3 = say(conv, bert, "first", "second", long_tail)
    first = claim_one(bert)
    new_message(first, conv, m1, unseen=3)
    window(first, [])
    check(first["notification"]["forwarded_at"] is None, f"notification {first['notification']}")
    second, third = claim_one(bert), claim_one(bert)
    new_message(second, conv, m2, unseen=3)
    new_message(third, conv, m3, unseen=3)
    window(second, [])
    window(third, [])
    n1, n2, n3 = (x["notification"]["id"] for x in (first, second, third))
    # Forwarding no longer means seen: unseen stays, and it is still redelivered.
    status, body = bert.post(f"/adapter/v1/conversation-notifications/{n1}/forwarded", {})
    check(status == 200 and body["notification"]["forwarded_at"], f"forwarded: {status} {body}")
    check(unseen(bert, conv) == 3, f"unseen after forwarding: {unseen(bert, conv)}, want 3")
    old_session = bert.session_id
    bert = replace(bert)
    state["bert"] = bert
    # The owner route does not return notifications and gives the same list, also first.
    entries = owner_pending(bert)["conversations"]
    check([e["conversation_id"] for e in entries] == [conv], f"owner pending before any adapter call: {entries}")
    entry = pending_entry(bert, conv)
    want = {"conversation_id": conv, "title": "Flaky checkout test", "unseen": 3, "addressed": True,
            "latest": {"message_id": m3, "author_label": "alice", "preview": long_tail[:200]}}
    check(entry == want, f"pending entry {entry}, want {want}")
    got = claim_one(bert)
    new_message(got, conv, m3, redelivered=True, catch_up=True, redeliveries=1, unseen=3, coalesced=[n1, n2])
    check(got["notification"]["id"] == n3 and got["notification"]["session_id"] == bert.session_id
          and got["notification"]["session_id"] != old_session, f"the catch-up's notification {got['notification']}")
    window(got, [m1, m2])
    check(got["messages"][0]["content"] == long_tail, "the new message was changed")
    no_claim(bert, "after the catch-up")
    # Still listed until seen: this session holds them.
    entry = pending_entry(bert, conv)
    check(entry and entry["unseen"] == 3 and entry["latest"]["message_id"] == m3, f"pending after the claim: {entry}")
    check(unseen(bert, conv) == 3, "unseen changed at the claim")
    send(bert, conv, "seen all of it")
    check(pending_entry(bert, conv) is None, "still pending after sending")
    check(pending(bert)["conversations"] == [] and owner_pending(bert)["conversations"] == [], "pending is not empty")
    check(unseen(bert, conv) == 0, f"unseen after sending: {unseen(bert, conv)}, want 0")
    bert = replace(bert)
    no_claim(bert, "after replacing a session whose messages were seen")


@suite.case("catch_up_window_limit", "C5 Claim (window: newest 10, a coalesced message that does not fit stays held)")
def _():
    need("alice_p")
    agent = new_agent("winnie")
    conv = start(agent)
    big = "x" * 3000
    mids = say(conv, agent, big, *[f"m{i}" for i in range(2, 13)])
    for _i in mids:
        claim_one(agent)
    agent = replace(agent)
    got = claim_one(agent)
    check(got["catch_up"] is True and ids_of(got["messages"]) == [mids[-1]] and len(got["coalesced"]) == 11
          and got["conversation"]["unseen"] == 12, f"catch-up of 12: {got['coalesced']} {got['conversation']}")
    window(got, mids[1:11], total=11)
    no_claim(agent, "after the catch-up of 12")
    # m1 did not fit: it stays held and counted, and history reaches it, whole.
    check(unseen(agent, conv) == 12, f"unseen {unseen(agent, conv)}, want 12")
    status, body = history(agent, conv, "?limit=50")
    check(status == 200 and ids_of(body["messages"]) == mids, f"history: {status} {ids_of(body['messages'])}")
    check(body["messages"][0]["content"] == big and body["messages"][0]["truncated"] is False, "m1 in history was cut")
    check(unseen(agent, conv) == 0, "history did not mark the held notifications seen")


@suite.case("pending_order_and_edges", "C5 `pending_work` (order, title null, no directory)")
def _():
    need("alice_p")
    agent = new_agent("penny")
    older, newer = start(agent), start(agent)
    n1 = say(newer, agent, "reaches bob first")[0]
    o1 = say(older, agent, "reaches bob later")[0]
    entries = pending(agent)["conversations"]
    check([e["conversation_id"] for e in entries] == [newer, older],
          f"pending order {entries}, want by when the earliest message reached this host")
    check(entries[0]["title"] is None and entries[0]["latest"]["message_id"] == n1
          and entries[1]["latest"]["message_id"] == o1, f"entries {entries}")
    nodir = new_agent("nodirp", directory=False)
    started = a.ok("conversation", "start", "bob/nodirp", "--message", "no directory access", timeout=60)
    check(started["invites"][0]["state"] == "joined", f"start: {started['invites']}")
    show_targets(a, started["conversation"]["conversation_id"], started["message"]["message_id"], participant(nodir),
                 "delivered")
    check(pending(nodir)["conversations"] == [] and owner_pending(nodir)["conversations"] == [],
          f"pending without directory access: {pending(nodir)}")
    no_claim(nodir, "without directory access")


@suite.case("seen_by_reading", "C5 Seen (GET .../messages marks what this session holds, not unclaimed ones)")
def _():
    need("alice_p")
    agent = new_agent("reader")
    conv = start(agent)
    m1, m2 = say(conv, agent, "held one", "held two")
    claim_one(agent), claim_one(agent)
    m3 = say(conv, agent, "unclaimed")[0]
    check(history_ids(agent, conv) == [m1, m2, m3], "history before the replacement")
    check(unseen(agent, conv) == 1, f"unseen after reading: {unseen(agent, conv)}, want the unclaimed one")
    agent = replace(agent)
    got = claim_one(agent)
    new_message(got, conv, m3, unseen=1)  # m1 and m2 are not returned; m3 was never held
    window(got, [m1, m2])
    no_claim(agent, "after the unclaimed message")


@suite.case("seen_by_sending", "C5 Seen (a send marks, a repeat counts, a refused send does not; other reads do not)")
def _():
    need("alice_p")
    agent = new_agent("sender")
    conv = start(agent)
    m1 = say(conv, agent, "refused send")[0]
    new_message(claim_one(agent), conv, m1)
    path = f"/adapter/v1/conversations/{conv}/messages"
    status, body = agent.post(path, {"content": ""})
    check(status == 400, f"an empty send: {status} {body}, want 400")
    # Neither a list, nor the owner's read as this agent, nor a refused send marks it.
    listed(agent, conv)
    check(ids_of(shown(agent, conv)["messages"]) == [m1], "show --as does not list a held message")
    check(unseen(agent, conv) == 1, f"unseen after a refused send: {unseen(agent, conv)}, want 1")
    agent = replace(agent)
    new_message(claim_one(agent), conv, m1, redelivered=True, catch_up=True, redeliveries=1, unseen=1)
    # A repeat of an earlier message counts as a 200 from the route.
    mid = "cmsg_" + os.urandom(16).hex()
    status, body = agent.post(path, {"content": "mine", "message_id": mid})
    check(status == 200, f"send: {status} {body}")
    m2 = say(conv, agent, "seen by a repeat")[0]
    new_message(claim_one(agent), conv, m2, unseen=1)
    status, body = agent.post(path, {"content": "mine", "message_id": mid})
    check(status == 200 and body["message"]["message_id"] == mid, f"repeat: {status} {body}")
    check(unseen(agent, conv) == 0, f"unseen after a repeat: {unseen(agent, conv)}, want 0")


@suite.case("seen_by_manage", "C5 Seen (a 200 from manage marks, a refused one does not)")
def _():
    need("alice_p")
    boss, otto, extra = new_agent("boss"), new_agent("otto"), new_agent("extra")
    status, body = boss.post("/adapter/v1/conversations", {"participants": ["bob/otto"]})
    check(status == 201, f"boss starts: {status} {body}")
    conv = body["conversation"]["conversation_id"]
    got = claim_one(otto)
    check(got["notification"]["kind"] == "roster", f"otto's first claim {got['notification']}")
    seen_ok(otto, conv)
    m1 = send(otto, conv, "from otto")
    new_message(claim_one(boss), conv, m1, unseen=1)
    # boss created the conversation and is its lead (C7): otto wakes only when addressed.
    m2 = send(boss, conv, "from boss, which marks m1", to=["bob/otto"])
    check(unseen(boss, conv) == 0, f"boss's unseen after sending: {unseen(boss, conv)}")
    new_message(claim_one(otto), conv, m2, unseen=1)
    status, body = otto.post(f"/adapter/v1/conversations/{conv}/manage", {"action": "close"})
    api_error(status, body, 403, "not_creator")
    check(unseen(otto, conv) == 1, f"unseen after a refused manage: {unseen(otto, conv)}, want 1")
    m3 = send(otto, conv, "this send marks m2")
    new_message(claim_one(boss), conv, m3, unseen=1)
    status, body = boss.post(f"/adapter/v1/conversations/{conv}/manage", {"action": "add", "participant": "bob/extra"})
    check(status == 200, f"boss adds extra: {status} {body}")
    check(unseen(boss, conv) == 0, f"unseen after a manage 200: {unseen(boss, conv)}, want 0")
    boss = replace(boss)
    no_claim(boss, "after manage marked the held message seen")
    claim_one(extra)


@suite.case("seen_route", "C5 POST /adapter/v1/seen (cmsg_, conv_, coalesced, not held, malformed)")
def _():
    need("alice_p")
    agent, other = new_agent("sally"), new_agent("sid")
    conv, elsewhere = start(agent), start(other)
    m1, m2, m3 = say(conv, agent, "s1", "s2", "s3")
    other_m = say(elsewhere, other, "held by another agent")[0]
    new_message(claim_one(other), elsewhere, other_m)
    for _i in (m1, m2, m3):
        claim_one(agent)
    agent = replace(agent)
    # Held only by the ended session, and an unclaimed or foreign ID: 404 and nothing marked.
    status, body = seen(agent, m1)
    api_error(status, body, 404, "not_found")
    got = claim_one(agent)
    new_message(got, conv, m3, redelivered=True, catch_up=True, redeliveries=1, unseen=3, coalesced=got["coalesced"])
    check(len(got["coalesced"]) == 2, f"coalesced {got['coalesced']}")
    unknown = "cmsg_" + os.urandom(16).hex()
    for ids in ([unknown], [m3, unknown], [other_m], ["conv_" + os.urandom(16).hex()], [elsewhere], [m3, elsewhere]):
        status, body = seen(agent, *ids)
        api_error(status, body, 404, "not_found")
        check(unseen(agent, conv) == 3, f"seen {ids} marked something: unseen {unseen(agent, conv)}")
    # An unclaimed notification is not held.
    m4 = say(conv, agent, "s4 unclaimed")[0]
    status, body = seen(agent, m4)
    api_error(status, body, 404, "not_found")
    check(unseen(agent, conv) == 4, f"unseen with s4 unclaimed: {unseen(agent, conv)}, want 4")
    for bad in ("nope_" + os.urandom(16).hex(), "cnot_" + os.urandom(16).hex()):
        status, body = seen(agent, bad)
        api_error(status, body, 400, "invalid", BAD_SEEN)  # C5 `seen`: the exact text
    check(unseen(agent, conv) == 4, "a malformed seen marked something")
    # The catch-up's new message marks everything claimed with it.
    seen_ok(agent, m3)
    check(unseen(agent, conv) == 1, f"unseen after seeing the new message: {unseen(agent, conv)}, want s4 only")
    status, body = seen(agent, m3)
    check(status == 200 and body == {"seen": []}, f"an already seen ID: {status} {body}, want {{seen: []}}")
    window(got, [m1, m2])
    new_message(claim_one(agent), conv, m4, unseen=1)
    # The conv_ ID marks the rest.
    seen_ok(agent, conv)
    check(unseen(agent, conv) == 0, f"unseen after the conv_ ID: {unseen(agent, conv)}, want 0")
    check(pending_entry(agent, conv) is None, "still pending after the conv_ ID")
    agent = replace(agent)
    no_claim(agent, "after everything was seen")
    # Another agent's notification was left alone by all of the above.
    check(unseen(other, elsewhere) == 1, f"another agent's unseen {unseen(other, elsewhere)}, want 1")


@suite.case("redelivery_limit", "C5 Returning (3 redeliveries, then exhausted), Notification life, Unseen")
def _():
    need("alice_p")
    agent = new_agent("rita")
    conv = start(agent)
    mid = say(conv, agent, "seen by nobody")[0]
    new_message(claim_one(agent), conv, mid, unseen=1)
    for count in (1, 2, 3):
        agent = replace(agent)
        got = claim_one(agent)
        new_message(got, conv, mid, redelivered=True, catch_up=True, redeliveries=count, unseen=1)
        window(got, [])
    agent = replace(agent)
    # Over the limit, before any claim on this session returns it: not listed, not counted.
    check(pending_entry(agent, conv) is None, "an exhausted notification is listed")
    no_claim(agent, "by a fifth session")
    check(pending_entry(agent, conv) is None, "an exhausted notification is listed after the claim")
    check(unseen(agent, conv) == 0, f"unseen with the notification exhausted: {unseen(agent, conv)}")
    check(history_ids(agent, conv) == [mid], "history does not list an exhausted message")
    # Once seen by its first session, a message is not redelivered.
    agent = new_agent("sean")
    conv = start(agent)
    mid = say(conv, agent, "seen at once")[0]
    new_message(claim_one(agent), conv, mid)
    seen_ok(agent, mid)
    agent = replace(agent)
    no_claim(agent, "after the first session saw it")


@suite.case("ended_by_attachment", "C5 Words (a session ends when replaced by a new attachment of the agent)")
def _():
    need("alice_p")
    agent = new_agent("nora")
    conv = start(agent)
    mid = say(conv, agent, "held by the first attachment")[0]
    new_message(claim_one(agent), conv, mid)
    agent.stop()
    suite.set_offset(suite.offset + 16)  # no detach: a new attachment needs the 15-second lease over (adapter recovery)
    agent = agent.host.attach(agent.agent)
    new_message(claim_one(agent), conv, mid, redelivered=True, catch_up=True, redeliveries=1)


@suite.case("late_arrival", "C5 Returning (arrives with no verified session), Claim (window), the worked example")
def _():
    need("alice_p")
    agent = new_agent("late")
    conv = start(agent)
    m0 = say(conv, agent, "seen before")[0]
    new_message(claim_one(agent), conv, m0)
    seen_ok(agent, m0)
    agent.stop()
    status, body = b.api("POST", f"/v1/sessions/{agent.session_id}/detach", {})
    check(status == 200, f"detach: {status} {body}")
    m = say(conv, agent, "while nobody is attached")[0]
    agent = b.attach(agent.agent)
    got = claim_one(agent)
    new_message(got, conv, m, unseen=1)
    window(got, [m0])
    no_claim(agent, "after the late arrival")
    # C5 Claiming's example: m1 returned, m2 and m3 unclaimed.
    agent = new_agent("exam")
    conv = start(agent)
    m1 = say(conv, agent, "ex1")[0]
    new_message(claim_one(agent), conv, m1)
    agent.stop()
    status, body = b.api("POST", f"/v1/sessions/{agent.session_id}/detach", {})
    check(status == 200, f"detach: {status} {body}")
    m2, m3 = say(conv, agent, "ex2", "ex3")
    agent = b.attach(agent.agent)
    got = claim_one(agent)
    new_message(got, conv, m1, redelivered=True, catch_up=True, redeliveries=1, unseen=3)
    window(got, [])
    for mid in (m2, m3):
        got = claim_one(agent)
        new_message(got, conv, mid, unseen=3)
        window(got, [])


@suite.case("never_offered", "C5 The handoff recheck (fail, blocked is final), What an agent may see")
def _():
    need("alice_p")
    agent = new_agent("nell")
    conv = start(agent)
    s0 = say(conv, agent, "before the deny")[0]
    first = claim_one(agent)
    new_message(first, conv, s0)
    sent_at = first["messages"][0]["sent_at"]
    seen_ok(agent, s0)
    agent = replace(agent)
    s1 = say(conv, agent, "s1 secret text")[0]
    try:
        deny()
        no_claim(agent, "of a message whose author lost access")
        check(pending_entry(agent, conv) is None, "pending lists a blocked message")
        check(history_ids(agent, conv) == [s0], "history lists a blocked message")
        view = shown(agent, conv)
        check(ids_of(view["messages"]) == [s0], f"show --as lists {ids_of(view['messages'])}")
        check(view["conversation"]["last_message_at"] == sent_at, f"show --as last_message_at {view['conversation']}")
        entry = listed(agent, conv)
        check(entry["unseen"] == 0 and entry["last_message_at"] == sent_at, f"list entry {entry}, want unseen 0")
        status, body = history(agent, conv, f"?before={s1}")
        api_error(status, body, 400, "invalid")
        hidden_error = body["error"]
        status, body = history(agent, conv, f"?before=cmsg_{os.urandom(16).hex()}")
        api_error(status, body, 400, "invalid", hidden_error)  # the same text as an unknown ID
        t = target_of(find_message(a.ok("conversation", "show", conv, "--json", "--limit", "100"), s1),
                      participant(agent))
        check(t["state"] == "delivered", f"alice's target {t}, want it to stay delivered")
        allow()
        no_claim(agent, "of a blocked message, after allow")
        check(pending_entry(agent, conv) is None, "pending lists a blocked message after allow")
        check(history_ids(agent, conv) == [s0], "history lists a blocked message after allow")
        check(ids_of(shown(agent, conv)["messages"]) == [s0], "show --as lists a blocked message after allow")
        status, body = history(agent, conv, f"?before={s1}")
        api_error(status, body, 400, "invalid", hidden_error)
        s2 = say(conv, agent, "s2 after allow")[0]
        got = claim_one(agent)
        new_message(got, conv, s2, unseen=1)
        window(got, [s0])  # the session's first message claim here: s1 is neither shown nor counted
    finally:
        allow()


@suite.case("hidden_then_allowed", "C5 The handoff recheck (reads record nothing)")
def _():
    need("alice_p")
    agent = new_agent("hilda")
    conv = start(agent)
    r1 = say(conv, agent, "r1")[0]
    try:
        deny()
        check(pending_entry(agent, conv) is None, "pending lists a message that fails the recheck")
        check(history_ids(agent, conv) == [], "history lists a message that fails the recheck")
        check(unseen(agent, conv) == 0, "unseen counts a message that fails the recheck")
        allow()
        entry = pending_entry(agent, conv)
        check(entry and entry["unseen"] == 1 and entry["latest"]["message_id"] == r1, f"pending after allow: {entry}")
        check(history_ids(agent, conv) == [r1], "history hides it after allow")
        new_message(claim_one(agent), conv, r1, unseen=1)
    finally:
        allow()


@suite.case("blocked_on_return", "C5 What an agent may see (held and seen stay), Claiming step 2, blocked is final")
def _():
    need("alice_p")
    agent = new_agent("tess")
    conv = start(agent)
    t0, t1 = say(conv, agent, "t0 seen", "t1 held")
    new_message(claim_one(agent), conv, t0)
    seen_ok(agent, t0)
    new_message(claim_one(agent), conv, t1)
    try:
        deny()
        # A live session holds t1: not withdrawn. `show --as`, since history would mark it seen.
        check(ids_of(shown(agent, conv)["messages"]) == [t0, t1], "show --as lost a message a live session holds")
        check(unseen(agent, conv) == 1, f"unseen for a held message: {unseen(agent, conv)}, want 1")
        entry = pending_entry(agent, conv)
        check(entry and entry["unseen"] == 1, f"pending for the holder: {entry}")
        agent = replace(agent)
        check(pending_entry(agent, conv) is None, "pending lists a returned message that fails the recheck")
        no_claim(agent, "of a returned message that fails the recheck")
        check(history_ids(agent, conv) == [t0], "history lists a blocked message; a seen one must stay")
        check(unseen(agent, conv) == 0, f"unseen with t1 blocked: {unseen(agent, conv)}")
        allow()
        agent = replace(agent)
        no_claim(agent, "of a blocked message after allow")
        check(history_ids(agent, conv) == [t0], "history lists a blocked message after allow")
        check(pending_entry(agent, conv) is None, "pending lists a blocked message after allow")
    finally:
        allow()


@suite.case("blocked_in_catch_up", "C5 Claiming step 5 (block any that fails), The handoff recheck (same-host author)")
def _():
    need("alice_p")
    agent, peer_agent = new_agent("bea"), new_agent("bel")
    conv = start(agent, peer_agent)
    t1 = say(conv, agent, "from alice")[0]
    new_message(claim_one(agent), conv, t1)
    t2 = send(peer_agent, conv, "from a local agent")
    new_message(claim_one(agent), conv, t2)
    try:
        deny()
        agent = replace(agent)
        got = claim_one(agent)
        new_message(got, conv, t2, redelivered=True, catch_up=True, redeliveries=1, unseen=1)
        window(got, [])
        no_claim(agent, "after the catch-up")
        check(unseen(agent, conv) == 1, f"unseen {unseen(agent, conv)}, want only the local author's")
        check(history_ids(agent, conv) == [t2], "history lists the blocked message")
    finally:
        allow()


@suite.case("left_withdrawn", "C5 Returning (not joined: withdrawn), What an agent may see (added again shows nothing)")
def _():
    need("alice_p")
    agent = new_agent("lia")
    conv = start(agent)
    mid = say(conv, agent, "held when she left")[0]
    new_message(claim_one(agent), conv, mid)
    left = b.ok("conversation", "leave", conv, "--agent", "lia")
    check(left["conversation"]["conversation_id"] == conv, f"leave: {left}")
    agent = replace(agent)
    no_claim(agent, "of a message after leaving")
    status, body = history(agent, conv)
    api_error(status, body, 403, "not_participant", NOT_PARTICIPANT)
    wait_view(a, conv, state["alice_p"], lambda v: participant(agent) in departed_of(v), "lia in alice's departed")
    added = a.ok("conversation", "add", conv, "bob/lia", timeout=60)
    check(added["invite"]["state"] == "joined", f"add again: {added['invite']}")

    def back():
        status, body = history(agent, conv)
        return body if status == 200 else None
    body = wait_for(back, timeout=20, interval=0.5, message="lia to be joined again")
    check(ids_of(body["messages"]) == [], f"history after being added again: {ids_of(body['messages'])}, want nothing")


@suite.case("undelivered", "C5 `conversation_undelivered`, Notification life, Claiming step 4")
def _():
    alice_p, _ = need("alice_p", "alice_person")
    uma, ulf = new_agent("uma"), new_agent("ulf")
    conv = start(uma, ulf)
    a.ok("block", "bob")
    try:
        content = "é" * 300
        u1 = send(uma, conv, content)
        t = show_targets(b, conv, u1, alice_p, "refused", as_agent="uma")
        check(t["code"] == "not_authorized", f"the refused target {t}")
        show_targets(b, conv, u1, participant(ulf), "delivered", as_agent="uma")  # no notification for this one
        got = claim_one(uma)
        n = got["notification"]
        check(n["kind"] == "undelivered" and n["message_id"] == u1 and n["conversation_id"] == conv
              and n["session_id"] == uma.session_id and n["redeliveries"] == 0 and n["seen_at"] is None,
              f"notification {n}")
        want = {"participant": alice_p, "label": "alice", "state": "refused", "code": "not_authorized",
                "error": t["error"], "preview": content[:200]}
        check(n["undelivered"] == want, f"undelivered {n['undelivered']}, want {want}")
        check(got["messages"] == [] and got["window"] == [] and got["window_total"] == 0 and got["coalesced"] == []
              and got["catch_up"] is False and got["redelivered"] is False, f"undelivered claim {got}")
        check(got["conversation"]["unseen"] == 0, f"undelivered counts: {got['conversation']}")
        no_claim(uma, "after the one undelivered notification")
        check(pending_entry(uma, conv) is None and unseen(uma, conv) == 0, "undelivered is pending or counted")
        status, body = uma.post(f"/adapter/v1/conversation-notifications/{n['id']}/forwarded", {})
        check(status == 200 and body["notification"]["forwarded_at"], f"forwarded: {status} {body}")
        uma = replace(uma)
        again = claim_one(uma)
        m = again["notification"]
        check(m["id"] == n["id"] and m["kind"] == "undelivered" and m["redeliveries"] == 1
              and again["redelivered"] is True and again["catch_up"] is False and again["messages"] == []
              and again["window"] == []
              and again["coalesced"] == [] and m["undelivered"] == want, f"redelivered undelivered {again}")
        seen_ok(uma, u1)
        uma = replace(uma)
        no_claim(uma, "after seeing the undelivered notification")
    finally:
        a.ok("unblock", "bob")


@suite.case("history_pages", "C5 Adapter routes: GET /adapter/v1/conversations/{id}/messages (page, query, errors)")
def _():
    alice_p, _ = need("alice_p", "alice_person")
    hal = new_agent("hal", host=a)
    conv = start(hal)

    def by_alice(text):
        status, body = a.api("POST", f"/v1/conversations/{conv}/messages", {"content": text})
        check(status == 200, f"alice: send: {status} {body}")
        return body["message"]["message_id"]
    sent = []
    for i in range(5):
        text = str(i) * LARGE
        sent.append(send(hal, conv, text) if i % 2 == 0 else by_alice(text))
    short = by_alice("short")
    status, page = history(hal, conv)
    check(status == 200 and set(page) >= {"messages", "next_before_message_id", "participants"},
          f"first page: {status} {list(page)}")
    check(ids_of(page["messages"]) == sent[2:] + [short], f"first page {ids_of(page['messages'])}")
    total = sum(len(m["content"].encode()) for m in page["messages"])
    check(total <= BUDGET, f"first page has {total} bytes")
    check(page["next_before_message_id"] == sent[2], f"next {page['next_before_message_id']}, want {sent[2]}")
    check(all(m["truncated"] is False and "content_bytes" not in m for m in page["messages"]), "a whole message is cut")
    mine = find_message(page, sent[2])
    theirs = find_message(page, short)
    check(mine["mine"] is True and target_of(mine, alice_p)["state"] == "delivered", f"own message {mine['targets']}")
    check(theirs["mine"] is False and theirs["targets"] is None, f"another's targets {theirs['targets']}")
    check(page["participants"] == listed(hal, conv)["participants"], f"participants {page['participants']}")
    status, older = history(hal, conv, f"?before={sent[2]}")
    check(status == 200 and ids_of(older["messages"]) == sent[:2] and older["next_before_message_id"] is None,
          f"second page: {status} {ids_of(older['messages'])} next {older['next_before_message_id']}")
    status, two = history(hal, conv, "?limit=2")
    check(status == 200 and ids_of(two["messages"]) == [sent[4], short] and two["next_before_message_id"] == sent[4],
          f"limit=2: {status} {ids_of(two['messages'])} next {two['next_before_message_id']}")
    status, two = history(hal, conv, f"?limit=2&before={sent[4]}")
    check(status == 200 and ids_of(two["messages"]) == sent[2:4] and two["next_before_message_id"] == sent[2],
          f"limit=2 with before: {status} {ids_of(two['messages'])}")
    accepted = []  # checked at the end, so one wrong answer does not hide the rest of the case
    for query in ("?limit=0", "?limit=51", "?limit=abc", "?color=red", "?before=nope",
                  f"?before=cmsg_{os.urandom(16).hex()}"):
        status, body = history(hal, conv, query)
        if not (status == 400 and body.get("code") == "invalid"):
            accepted.append(f"{query}: {status}")
    status, body = history(hal, "conv_nothex")
    api_error(status, body, 400, "invalid")
    status, body = history(hal, "conv_" + os.urandom(16).hex())
    api_error(status, body, 404, "not_found")
    outsider = new_agent("hox", host=a)
    status, body = history(outsider, conv)
    api_error(status, body, 403, "not_participant", NOT_PARTICIPANT)
    nodir = new_agent("hnd", host=a, directory=False)
    for path in (conv, "conv_nothex"):  # directory access is checked first
        status, body = history(nodir, path)
        api_error(status, body, 403, "no_directory")
    # It works before the channel is verified, and an unclaimed message is visible when the recheck passes.
    unverified = new_agent("hun", host=a, ready=False)
    started = a.ok("conversation", "start", "alice/hun", "--message", "before ready")
    status, body = history(unverified, started["conversation"]["conversation_id"])
    check(status == 200 and ids_of(body["messages"]) == [started["message"]["message_id"]],
          f"history before verification: {status} {body}")
    status, body = hal.post(f"/adapter/v1/conversations/{conv}/manage", {"action": "leave"})
    check(status == 200, f"hal leaves: {status} {body}")
    status, body = history(hal, conv)
    api_error(status, body, 403, "not_participant", NOT_PARTICIPANT)
    check(not accepted, f"history queries that must be 400 invalid: {accepted}")


@suite.case("closed_stays", "C5 Adapter routes check 4 (closed stays readable), Unseen (a closed conversation is kept)")
def _():
    need("alice_p")
    cal = new_agent("cal", host=a)
    conv = start(cal)
    status, body = a.api("POST", f"/v1/conversations/{conv}/messages", {"content": "before close"})
    check(status == 200, f"send: {status} {body}")
    mid = body["message"]["message_id"]
    closed = a.ok("conversation", "close", conv)
    check(closed["conversation"]["state"] == "closed", f"close: {closed}")
    entry = listed(cal, conv)
    check(entry and entry["state"] == "closed" and entry["unseen"] == 1, f"list entry when closed: {entry}")
    new_message(claim_one(cal), conv, mid, unseen=1)
    check(history_ids(cal, conv) == [mid], "a closed conversation is not readable")
    check(listed(cal, conv) is None, f"still listed with nothing unseen: {listed(cal, conv)}")


# C7: the lead. Written from docs/conversations-contract.md, section C7 (cited as "C7 <part>"), and its edits in
# docs/launch-contract.md and docs/host-service-contract.md, only. Agent names carry a 7 since this suite already
# registers `bert` and `bea` on bob for C5's cases, and a second agent of one name would not be addressable.

DESCRIPTION_RULE = "description must be 1 to 200 bytes on one line, without control characters"


def invites(host):
    status, body = host.api("GET", "/v1/conversations/invites")
    check(status == 200, f"{host.name}: invites: {status} {body}")
    return {i["conversation_id"]: i for i in body["invites"]}


def join_as_person(host, conv):
    """C3: HOST's person joins CONV from its pending invite."""
    wait_for(lambda: invites(host).get(conv), timeout=20, interval=0.3, message=f"{host.name}'s invite to {conv}")
    host.ok("conversation", "join", conv, timeout=60)


def new_agents(*names, host=b):
    """Fixture agents NAMES on HOST, with one directory refresh on alice for bob's (alice's own resolve locally, C2)."""
    adapters = [host.agent(n) for n in names]
    if host is not a:
        a.ok("agents", "--refresh", "--json")
    return adapters


def delivered(conv, mid, *pids, host=a, as_agent=None):
    """Wait for HOST's targets of MID for PIDS to be `delivered`, all in one view per poll."""
    extra = ("--as", as_agent) if as_agent else ()
    last = {}

    def done():
        view = host.ok("conversation", "show", conv, "--json", "--limit", "100", *extra)
        last["t"] = [target_of(find_message(view, mid), p) for p in pids]
        check(all(t["state"] in ("sending", "delivered") for t in last["t"]), f"targets {last['t']}")
        return all(t["state"] == "delivered" for t in last["t"])
    try:
        wait_for(done, timeout=30, interval=0.1, message="delivery")
    except AssertionError as error:
        raise AssertionError(f"{error}; targets {last.get('t')}") from None


def say_to(conv, text, *to, wait=()):
    """alice's person sends TEXT with `--to` TO (C6), then waits for alice's targets of WAIT to be `delivered`."""
    args = ["conversation", "say", conv, text]
    for entry in to:
        args += ["--to", entry]
    mid = a.ok(*args)["message"]["message_id"]
    if wait:
        delivered(conv, mid, *[participant(x) for x in wait])
    return mid


def lead_of(adapter, conv):
    """The lead fields of ADAPTER's agent summary (C7 Views), and its `parked` and `unseen`."""
    entry = listed(adapter, conv)
    check(entry is not None, f"{adapter.name}: {conv} is not listed")
    flags = [p["id"] for p in entry["participants"] if p.get("lead") is True]
    check(all(isinstance(p.get("lead"), bool) for p in entry["participants"]),
          f"{adapter.name}: participants' `lead` must be booleans: {entry['participants']}")
    check(flags == ([entry["lead"]] if entry.get("lead") else []),
          f"{adapter.name}: summary lead {entry.get('lead')}, participants flagged {flags}")
    return entry


def counts(adapter, conv):
    """(`parked`, `unseen`) from ADAPTER's agent summary (C7 Parked notifications), in one read."""
    entry = listed(adapter, conv)
    check(entry is not None and isinstance(entry.get("parked"), int), f"{adapter.name}: agent summary {entry}")
    return entry["parked"], entry["unseen"]


def parked(adapter, conv):
    return counts(adapter, conv)[0]


def label_in(view, pid):
    found = [p["label"] for p in view["participants"] if p["id"] == pid]
    check(len(found) == 1, f"{pid} in {view['participants']}")
    return found[0]


def agents_in(view):
    """Joined agent participants in `participants` order (C7 The lead, rule 3; Claiming `areas`)."""
    return [p["id"] for p in view["participants"] if p["kind"] == "agent" and p["state"] == "joined"]


def lead_claim(got, lead_p, label, you):
    check(got.get("lead") == {"participant": lead_p, "label": label, "you": you},
          f"claim `lead` {got.get('lead')}, want {lead_p} ({label}) you {you}")


def areas_of(got):
    check(isinstance(got.get("areas"), list), f"claim `areas` {got.get('areas')}")
    return got["areas"]


@suite.case("lead_unaddressed", "C7 The lead (rule 2), Waking, Parked notifications, Claiming (lead, areas), Views; "
                                "Verification Unaddressed wakes the lead only")
def _():
    alice_p, = need("alice_p")
    ann, = new_agents("ann7", host=a)
    bert, bea = new_agents("bert7", "bea7")
    conv = start(ann, bert, bea)
    ann_p, bert_p, bea_p = participant(ann), participant(bert), participant(bea)
    view = view_as(a, conv, alice_p)
    ctx = state["lead"] = {"conv": conv, "ann": ann, "bert": bert, "bea": bea, "view": view}
    m1 = ctx["m1"] = say_to(conv, "m1 for whoever knows", wait=(bert, bea))
    check(view.get("lead") == ann_p, f"view `lead` {view.get('lead')}, want ann {ann_p} (alice's first agent)")
    order = agents_in(view)
    check(sorted(order) == sorted([ann_p, bert_p, bea_p]), f"joined agents {order}")
    status, body = a.api("GET", "/v1/conversations")
    summary = [c for c in body["conversations"] if c["conversation_id"] == conv]
    check(status == 200 and len(summary) == 1 and summary[0].get("lead") == ann_p,
          f"GET /v1/conversations summary `lead`: {status} {summary}")
    ann_label = label_in(view, ann_p)
    header = a.cli("conversation", "show", conv)
    check(header.ok and f"lead {ann_label}" in header.stdout.splitlines()[0],
          f"readable show header {header.stdout.splitlines()[:1]}, want `lead {ann_label}`")
    got = claim_one(ann)
    new_message(got, conv, m1)
    lead_claim(got, ann_p, ann_label, True)
    want = [{"participant": p, "label": label_in(view, p), "description": None} for p in order]
    check(areas_of(got) == want, f"the lead's `areas` {got['areas']}, want {want}")
    no_claim(bert, "of an unaddressed message when not the lead")
    no_claim(bea, "of an unaddressed message when not the lead")
    for x in (bert, bea):
        entry = lead_of(x, conv)
        check(entry["lead"] == ann_p and entry["unseen"] == 0 and entry.get("parked") == 1,
              f"{x.name}: agent summary lead {entry['lead']} unseen {entry['unseen']} parked {entry.get('parked')}, "
              f"want ann, 0 and 1")
        check(pending_entry(x, conv) is None, f"{x.name}: pending lists a parked-only conversation")
    check(history_ids(bert, conv) == [m1], "bert's history does not list the parked m1")
    check(ids_of(shown(bea, conv)["messages"]) == [m1], "show --as bea does not list the parked m1")
    check(parked(bert, conv) == 1 and parked(bea, conv) == 1, "a read changed a parked notification")
    bert = ctx["bert"] = replace(bert)  # a parked notification has no session: never returned
    no_claim(bert, "of a parked notification by a new session")
    check(counts(bert, conv) == (1, 0), f"a new session changed bert's parked m1: {counts(bert, conv)}")


@suite.case("lead_addressed", "C7 Waking (addressed_to naming P, not naming P, only people), The lead (rule 3); "
                              "Verification Addressed wakes those named")
def _():
    alice_p, ctx = need("alice_p", "lead")
    conv, ann, bert, bea, view = (ctx[k] for k in ("conv", "ann", "bert", "bea", "view"))
    m2 = ctx["m2"] = say_to(conv, "m2 for bert", "bob/bert7", wait=(bert, bea))
    got = claim_one(bert)
    new_message(got, conv, m2, coalesced=got.get("coalesced"))
    check(len(got["coalesced"]) == 1, f"bert's claim of m2 gathers its parked m1: coalesced {got['coalesced']}")
    window(got, [ctx["m1"]])
    lead_claim(got, participant(ann), label_in(view, participant(ann)), False)
    check(areas_of(got) == [], f"a non-lead's `areas` {got['areas']}, want []")
    no_claim(ann, "of a message addressed to bert")
    no_claim(bea, "of a message addressed to bert")
    # Its own conversation, with bob's person joined: addressed only to person:bob, it wakes no agent, not even the
    # lead. alice's person has no agent here, so the lead is rule 3's.
    pia = new_agent("pia7")
    started = a.ok("conversation", "start", "bob/pia7", "person:bob", timeout=60)
    other = started["conversation"]["conversation_id"]
    got = claim_one(pia)
    check(got["notification"]["kind"] == "roster", f"pia's `added` claim {got['notification']}")
    seen_ok(pia, other)
    join_as_person(b, other)
    joined = wait_view(a, other, alice_p, lambda v: any(p["kind"] == "person" and p["state"] == "joined"
                                                        and p["host_id"] == b.id for p in v["participants"]),
                       "bob's person joined")
    bob_p = [p["id"] for p in joined["participants"] if p["kind"] == "person" and p["host_id"] == b.id][0]
    check(joined.get("lead") == participant(pia), f"lead {joined.get('lead')}, want pia (rule 3)")
    mid = a.ok("conversation", "say", other, "for bob's person only", "--to", "person:bob")["message"]["message_id"]
    delivered(other, mid, bob_p, participant(pia))
    no_claim(pia, "of a message addressed only to a person, as the lead")
    check(parked(pia, other) == 1, f"pia's parked {parked(pia, other)}, want 1")


@suite.case("lead_own_message", "C7 Waking (an unaddressed message the lead wrote wakes no agent); "
                                "Verification The lead's own message")
def _():
    _, ctx = need("alice_p", "lead")
    check("m2" in ctx, f"an earlier case did not finish: {sorted(ctx)}")
    conv, ann, bert, bea = (ctx[k] for k in ("conv", "ann", "bert", "bea"))
    m3 = ctx["m3"] = send(ann, conv, "m3 from the lead")
    delivered(conv, m3, participant(bert), participant(bea), as_agent="ann7")
    for x in (ann, bert, bea):
        no_claim(x, "of the lead's own unaddressed message")
    check(ids_of(shown(bea, conv)["messages"]) == [ctx["m1"], ctx["m2"], m3], "bea cannot see m1 to m3")
    check(m3 in history_ids(bert, conv), "bert's history does not list m3")
    check(m3 in history_ids(bea, conv), "bea's history does not list m3")
    got = counts(bea, conv)
    check(got == (3, 0), f"bea's (parked, unseen) {got}, want (3, 0)")


@suite.case("lead_gather", "C7 Claiming (step 6 gather, coalesced, window), Parked notifications (unseen, parked); "
                           "Verification Gather and window")
def _():
    _, ctx = need("alice_p", "lead")
    conv, ann, bert, bea, view = (ctx[k] for k in ("conv", "ann", "bert", "bea", "view"))
    check(all(k in ctx for k in ("m1", "m2", "m3")), f"an earlier case did not finish: {sorted(ctx)}")
    m1, m2, m3 = ctx["m1"], ctx["m2"], ctx["m3"]
    m4 = say_to(conv, "m4 for bea", "bob/bea7", wait=(bea,))
    got = claim_one(bea)
    new_message(got, conv, m4, coalesced=got.get("coalesced"))
    n4 = got["notification"]["id"]
    co = got["coalesced"]
    check(len(co) == 3 and len(set(co)) == 3 and n4 not in co and all(str(i).startswith("cnot_") for i in co),
          f"coalesced {co}, want bea's 3 notifications for m1, m2 and m3")
    window(got, [m1, m2, m3])
    lead_claim(got, participant(ann), label_in(view, participant(ann)), False)
    after = counts(bea, conv)
    check(after == (0, 4), f"after the gather: (parked, unseen) {after}, want (0, 4)")
    no_claim(bea, "after the gather")
    seen_ok(bea, m4)
    check(unseen(bea, conv) == 0, f"unseen after seeing m4: {unseen(bea, conv)}, want 0")
    no_claim(ann, "of m4, addressed to bea")
    no_claim(bert, "of m4, addressed to bea")


@suite.case("lead_later_parked", "C7 Claiming step 6 (parked messages sorting after the new one stay parked); "
                                 "Verification Later parked messages stay")
def _():
    _, ctx = need("alice_p", "lead")
    conv, ann, bea = (ctx[k] for k in ("conv", "ann", "bea"))
    m5 = say_to(conv, "m5 for bea", "bob/bea7", wait=(bea,))
    m6 = say_to(conv, "m6 for whoever knows", wait=(bea,))
    got = claim_one(bea)
    new_message(got, conv, m5)
    window(got, [])  # neither the session's first message claim nor a claim that gathered
    check(parked(bea, conv) == 1, f"bea's parked after the claim {parked(bea, conv)}, want m6 still parked")
    no_claim(bea, "of m6, parked")
    got = claim_one(ann)
    check(ids_of(got["messages"]) == [m6], f"the lead's claim {ids_of(got['messages'])}, want m6")


@suite.case("lead_recheck_gather", "C7 Claiming step 6 (fail: block); C5 The handoff recheck; "
                                   "Verification Recheck on gather")
def _():
    need("alice_p")
    lea, = new_agents("lea7", host=a)
    bert, bel = new_agents("bero7", "bel7")
    conv = start(lea, bert, bel)
    x = say_to(conv, "from alice, parked for bero7", wait=(bert, bel))
    check(parked(bert, conv) == 1, f"bero7's parked {parked(bert, conv)}, want 1")
    try:
        deny()
        status, body = bel.post(f"/adapter/v1/conversations/{conv}/messages",
                                {"content": "for bero7", "addressed_to": [participant(bert)]})
        check(status == 200, f"bel7 sends: {status} {body}")
        y = body["message"]["message_id"]
        got = claim_one(bert)
        new_message(got, conv, y)
        window(got, [])
        check(x not in got["coalesced"] and x not in ids_of(got["window"]), f"alice's message was gathered: {got}")
        allow()
        check(parked(bert, conv) == 0, f"parked after allow {parked(bert, conv)}, want 0: it was blocked")
        no_claim(bert, "of a notification blocked at the gather")
        check(history_ids(bert, conv) == [y], "history lists a message blocked at the gather")
    finally:
        allow()


@suite.case("lead_leaving", "C7 Parked notifications (leaving withdraws); C5 What an agent may see; "
                            "Verification Leaving withdraws")
def _():
    need("alice_p")
    lev, = new_agents("lev7", host=a)
    leb, = new_agents("leb7")
    conv = start(lev, leb)
    say_to(conv, "parked, then she leaves", wait=(leb,))
    check(parked(leb, conv) == 1, f"leb7's parked {parked(leb, conv)}, want 1")
    b.ok("conversation", "leave", conv, "--agent", "leb7")
    wait_view(a, conv, state["alice_p"], lambda v: participant(leb) in departed_of(v), "leb7 in alice's departed")
    added = a.ok("conversation", "add", conv, "bob/leb7", timeout=60)
    check(added["invite"]["state"] == "joined", f"add again: {added['invite']}")
    got = claim_one(leb)
    check(got["notification"]["kind"] == "roster", f"leb7's claim after the re-add {got['notification']}")
    check(history_ids(leb, conv) == [], "history lists a parked message withdrawn when she left")
    check(parked(leb, conv) == 0, f"parked after being added again {parked(leb, conv)}, want 0")


@suite.case("lead_changes", "C7 The lead (rule 1, rule 3 after the creator leaves; every host from its roster), "
                            "Waking; Verification Lead changes")
def _():
    alice_p, = need("alice_p")
    cara, = new_agents("cara7", host=a)
    lx, ly = new_agents("lx7", "ly7")
    status, body = cara.post("/adapter/v1/conversations", {"participants": ["bob/lx7", "bob/ly7", "person:alice"]})
    check(status == 201, f"cara7 starts: {status} {body}")
    conv = body["conversation"]["conversation_id"]
    cara_p = participant(cara)
    for x in (lx, ly):
        got = claim_one(x)
        check(got["notification"]["kind"] == "roster", f"{x.name}'s `added` claim {got['notification']}")
        seen_ok(x, conv)
    join_as_person(a, conv)
    view = wait_view(a, conv, alice_p, lambda v: v.get("lead") == cara_p, "alice's view: cara7 the lead")
    wait_view(b, conv, participant(lx), lambda v: v.get("lead") == cara_p, "bob's view: cara7 the lead")
    u1 = say_to(conv, "u1 for whoever knows", wait=(lx, ly))
    got = claim_one(cara)
    new_message(got, conv, u1)
    lead_claim(got, cara_p, label_in(view, cara_p), True)
    no_claim(lx, "of an unaddressed message with the creator the lead")
    no_claim(ly, "of an unaddressed message with the creator the lead")
    status, body = cara.post(f"/adapter/v1/conversations/{conv}/manage", {"action": "leave"})
    check(status == 200, f"cara7 leaves: {status} {body}")
    after = wait_view(a, conv, alice_p, lambda v: cara_p in departed_of(v), "cara7 in alice's departed")
    nxt = agents_in(after)[0] if agents_in(after) else None
    check(nxt in (participant(lx), participant(ly)), f"next agent by rule 3: {nxt} from {after['participants']}")
    check(after.get("lead") == nxt, f"alice's view `lead` {after.get('lead')}, want {nxt}")
    wait_view(b, conv, participant(lx), lambda v: v.get("lead") == nxt, f"bob's view: {nxt} the lead")
    new_lead, rest = (lx, ly) if nxt == participant(lx) else (ly, lx)
    u2 = say_to(conv, "u2 for whoever knows", wait=(lx, ly))
    got = claim_one(new_lead)
    check(ids_of(got["messages"]) == [u2], f"the new lead's claim {ids_of(got['messages'])}, want u2")
    lead_claim(got, nxt, label_in(after, nxt), True)
    no_claim(rest, "of an unaddressed message when not the new lead")


NO_PARTICIPANT = "No such participant in that conversation."
CONFLICT = "This message_id was already used with different content."
NEEDS_CONTENT = "addressed_to needs content"


def conversation_ids(host):
    status, body = host.api("GET", "/v1/conversations?state=all")
    check(status == 200, f"{host.name}: conversations: {status} {body}")
    return {c["conversation_id"] for c in body["conversations"]}


@suite.case("lead_start_addressed", "C7 Starting with `addressed_to` (CONV-35), Waking; "
                                    "Verification Start addressed")
def _():
    need("alice_p")
    sa, = new_agents("sa7", host=a)
    sx, sy, sz = new_agents("sx7", "sy7", "sz7")
    sx_p, sy_p = participant(sx), participant(sy)
    path = "/adapter/v1/conversations"
    targets = ["bob/sx7", "bob/sy7"]
    # Refusals first, each persisting nothing.
    before = conversation_ids(a)
    status, body = sa.post(path, {"participants": targets, "content": "for nobody", "addressed_to": ["bob/sz7"]})
    api_error(status, body, 404, "not_found", NO_PARTICIPANT)
    status, body = sa.post(path, {"participants": targets, "addressed_to": ["bob/sx7"]})
    api_error(status, body, 400, "invalid", NEEDS_CONTENT)
    result = a.cli("conversation", "start", "bob/sx7", "--to", "bob/sx7")
    check(result.code == 1, f"`conversation start --to` without --message: exit {result.code}, want 1")
    check(conversation_ids(a) == before, "a refused start persisted a conversation")
    for x in (sx, sy, sz):
        no_claim(x, "after refused starts")
    # Addressed to one of two targets: only that one wakes.
    mid = message_id()
    content = "start addressed to sx7"
    status, body = sa.post(path, {"participants": targets, "content": content, "message_id": mid,
                                  "addressed_to": ["bob/sx7"]})
    check(status == 201 and body["message"]["message_id"] == mid and body["message"]["addressed_to"] == [sx_p],
          f"addressed start: {status} {body}")
    conv = body["conversation"]["conversation_id"]
    check(all(i["state"] == "joined" for i in body["invites"]), f"invites {body['invites']}")
    delivered(conv, mid, sx_p, sy_p, as_agent="sa7")
    for x in (sx, sy):
        got = claim_one(x)
        check(got["notification"]["kind"] == "roster", f"{x.name}'s `added` claim {got['notification']}")
    got = claim_one(sx)
    new_message(got, conv, mid)
    no_claim(sy, "of a start addressed to sx7")
    no_claim(sa, "of its own start")
    check(parked(sy, conv) == 1, f"sy7's parked {parked(sy, conv)}, want the first message parked")
    # C6's repeat rule on the start's first message: same addressed_to repeats, another conflicts.
    send_path = f"{path}/{conv}/messages"
    status, body = sa.post(send_path, {"content": content, "message_id": mid, "addressed_to": ["bob/sx7"]})
    check(status == 200 and body["message"]["message_id"] == mid, f"repeat with the same addressed_to: {status} {body}")
    status, body = sa.post(send_path, {"content": content, "message_id": mid, "addressed_to": ["bob/sy7"]})
    api_error(status, body, 409, "conflict", CONFLICT)
    # The same start without addressed_to wakes no agent: the creator is the lead.
    status, body = sa.post(path, {"participants": targets, "content": "start, unaddressed"})
    check(status == 201 and body["message"]["addressed_to"] == [], f"unaddressed start: {status} {body}")
    plain, plain_mid = body["conversation"]["conversation_id"], body["message"]["message_id"]
    delivered(plain, plain_mid, sx_p, sy_p, as_agent="sa7")
    for x in (sx, sy):
        got = claim_one(x)
        check(got["notification"]["kind"] == "roster", f"{x.name}'s `added` claim {got['notification']}")
        no_claim(x, "of an unaddressed start by an agent creator")
        check(parked(x, plain) == 1, f"{x.name}'s parked {parked(x, plain)}, want 1")
    # The CLI's --to, for alice's person as creator.
    started = a.ok("conversation", "start", "bob/sx7", "bob/sy7", "--message", "for sy7", "--to", "bob/sy7",
                   timeout=60)
    check(started["message"]["addressed_to"] == [sy_p], f"start --to: {started['message']}")


@suite.case("lead_none", "C7 The lead (no joined agent: no lead), Views; Verification No lead")
def _():
    alice_p, = need("alice_p")
    started = a.ok("conversation", "start", "person:bob", timeout=60)
    conv = started["conversation"]["conversation_id"]
    join_as_person(b, conv)
    view = wait_view(a, conv, alice_p, lambda v: all(p["state"] == "joined" for p in v["participants"]),
                     "bob's person joined")
    check("lead" in view and view["lead"] is None, f"alice's view `lead` {view.get('lead', '(missing)')}, want null")
    status, body = b.api("GET", f"/v1/conversations/{conv}")
    check(status == 200 and "lead" in body and body["lead"] is None, f"bob's view: {status} {body}")
    status, body = a.api("GET", "/v1/conversations")
    summary = [c for c in body["conversations"] if c["conversation_id"] == conv]
    check(len(summary) == 1 and "lead" in summary[0] and summary[0]["lead"] is None, f"summary {summary}")


def directory_entry(host, agent_id):
    status, body = host.api("GET", f"/v1/directory?network={state['net']}")
    check(status == 200, f"{host.name}: directory: {status} {body}")
    found = [x for x in body["agents"] if x["agent_id"] == agent_id]
    check(len(found) == 1, f"{agent_id} in {host.name}'s directory: {found}")
    return found[0]


def agents_json_entry(host, agent_id, part):
    body = host.ok("agents", "--refresh", "--json") if host is a else host.ok("agents", "--json")
    found = [x for x in body[part] if x["agent_id"] == agent_id]
    check(len(found) == 1, f"{agent_id} in {host.name}'s agents --json {part}: {found}")
    return found[0]


def peer_entry(agent_id):
    status, body = peer(a, b, "GET", f"/peer/v1/networks/{state['net']}/agents")
    check(status == 200 and isinstance(body, list), f"peer agents: {status} {body}")
    found = [x for x in body if x["agent_id"] == agent_id]
    check(len(found) == 1, f"{agent_id} in bob's peer answer: {found}")
    return found[0]


@suite.case("lead_descriptions", "C7 Agent descriptions, In the directory, Areas; launch contract Peer route and "
                                 "Discovery; host service contract; Verification Descriptions")
def _():
    need("alice_p")
    dora = new_agent("dora7")
    path = f"/v1/agents/{dora.id}/description"
    got = b.ok("agent", "describe", "dora7", "database")
    check(got.get("id") == dora.id and got.get("description") == "database", f"agent describe: {got}")
    status, body = b.api("GET", f"/v1/agents/{dora.id}")
    check(status == 200 and body.get("description") == "database", f"GET /v1/agents/ID: {status} {body}")
    status, body = b.api("GET", "/v1/agents")
    listed_agents = body if isinstance(body, list) else (body or {}).get("agents", [])
    mine = [x for x in listed_agents if x.get("id") == dora.id]
    check(status == 200 and len(mine) == 1 and mine[0].get("description") == "database", f"GET /v1/agents: {mine}")
    check(agents_json_entry(b, dora.id, "mine").get("description") == "database", "bob's agents --json `mine`")
    check(agents_json_entry(a, dora.id, "reachable").get("description") == "database",
          "alice's agents --json `reachable` after a refresh")
    check(directory_entry(a, dora.id).get("description") == "database", "alice's GET /v1/directory")
    check(peer_entry(dora.id).get("description") == "database", "bob's peer route entry")
    # The lead's claim on alice: areas from this host's records, its own agent's and bob's directory entry.
    dle = new_agent("dle7", host=a)
    status, body = a.api("POST", f"/v1/agents/{dle.id}/description", {"description": "triage"})
    check(status == 200 and body.get("description") == "triage", f"describe dle7 by the route: {status} {body}")
    conv = start(dle, dora)
    view = view_as(a, conv, state["alice_p"])
    check(view.get("lead") == participant(dle), f"lead {view.get('lead')}, want dle7")
    descriptions = {participant(dle): "triage", participant(dora): "database"}
    say_to(conv, "who holds the schema?", wait=(dora,))
    got = claim_one(dle)
    want = [{"participant": p, "label": label_in(view, p), "description": descriptions[p]} for p in agents_in(view)]
    check(areas_of(got) == want, f"areas {got['areas']}, want {want}")
    # Refusals change nothing.
    unchanged = []
    for bad in ({"description": "x" * 201}, {"description": "é" * 100 + "x"}, {"description": "two\nlines"},
                {"description": "c1 \u0085"}, {"description": "   "}, {}, {"description": None},
                {"description": "ok", "extra": 1}):
        status, body = b.api("POST", path, bad)
        if not (status == 400 and isinstance(body, dict) and body.get("code") == "invalid"
                and body.get("error") == DESCRIPTION_RULE):
            unchanged.append(f"{bad}: {status} {body}")
    status, body = b.api("POST", path, {"description": 7})  # "is a string": 400 `invalid`, its text not fixed
    if not (status == 400 and isinstance(body, dict) and body.get("code") == "invalid"):
        unchanged.append(f"a number: {status} {body}")
    status, body = b.api("POST", f"/v1/agents/agent_{os.urandom(16).hex()}/description", {"description": "x"})
    api_error(status, body, 404, "not_found")
    refused(b.cli("agent", "describe", "nobody7", "x"), "not_found", "No such agent on this host.")
    for args in (("dora7", "x", "--clear"), ("dora7",)):
        result = b.cli("agent", "describe", *args)
        if result.code != 1:
            unchanged.append(f"agent describe {args}: exit {result.code}")
    status, body = b.api("GET", f"/v1/agents/{dora.id}")
    check(body.get("description") == "database", f"a refused describe changed it: {body}")
    status, body = b.api("POST", path, {"description": "é" * 100})  # 200 bytes
    check(status == 200 and body.get("description") == "é" * 100, f"200 bytes: {status} {body}")
    got = b.ok("agent", "describe", "dora7", "--clear")
    check("description" in got and got["description"] is None, f"--clear: {got}")
    status, body = b.api("GET", f"/v1/agents/{dora.id}")
    check(status == 200 and "description" in body and body["description"] is None, f"after --clear: {body}")
    check(agents_json_entry(a, dora.id, "reachable").get("description", "missing") is None,
          "alice's agents --json after --clear and a refresh")
    check(directory_entry(a, dora.id).get("description", "missing") is None, "alice's directory after --clear")
    check("description" not in peer_entry(dora.id), "bob's peer entry keeps a `description` key after --clear")
    say_to(conv, "and now?", wait=(dora,))
    got = claim_one(dle)
    want[[w["participant"] for w in want].index(participant(dora))]["description"] = None
    check(areas_of(got) == want, f"areas after --clear {got['areas']}, want {want}")
    check(not unchanged, f"descriptions that must be refused with 400 invalid and the rule's text: {unchanged}")


@suite.case("stopped", "C5 `conversation_undelivered` (stopped), C4 The 24-hour push window; runs last")
def _():
    need("alice_p")
    # C5 Verification has this with carol; this suite has no third host, and bob's host stops for it instead.
    remote, ada = b.agent("rob"), a.agent("ada")
    a.ok("agents", "--refresh", "--json")
    started = a.ok("conversation", "start", "bob/rob", "--as", "ada", timeout=60)
    conv = started["conversation"]["conversation_id"]
    check(started["invites"][0]["state"] == "joined", f"start --as ada: {started['invites']}")
    target = started["invites"][0]["participant"]
    remote.stop()
    b.stop()
    u1 = send(ada, conv, "never reaches bob")
    t = target_of(find_message(a.ok("conversation", "show", conv, "--json", "--as", "ada"), u1), target)
    check(t["state"] == "sending", f"the target with bob stopped: {t}")
    ada.stop()  # its 2-hour authorization expires in the move
    suite.set_offset(suite.offset + DAY + 1)
    t = show_targets(a, conv, u1, target, "stopped", as_agent="ada", timeout=20)
    ada = a.attach(ada.agent)
    got = claim_one(ada)
    n = got["notification"]
    want = {"participant": target, "label": "bob/rob", "state": "stopped", "code": None, "error": t["error"],
            "preview": "never reaches bob"}
    check(n["kind"] == "undelivered" and n["message_id"] == u1 and n["undelivered"] == want
          and got["redelivered"] is False, f"stopped claim {got}, want {want}")
    no_claim(ada, "after the one stopped notification")


suite.finish()
