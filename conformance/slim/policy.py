#!/usr/bin/env python3
"""Slim suite 3, policy: allow, deny, block, bans, versioned policy edits and capability claims.

alice creates a network and bob joins it; each has one fixture agent. Written from
docs/decentralized-spec.md sections 4.4, 5, 5.1 and 12, the wire appendix (sections 5,
16.6, 16.4) and docs/launch-contract.md slice 3 (allow, deny, block).
"""
import base64
import json
import threading
import urllib.parse

from harness import Suite, check, create_network, join_new_person, parse_time, ssh_key

KNOWN = "listed in PR #9; spec-only author does not fix product code"
suite = Suite("policy", __doc__)
a, b = suite.host("alice"), suite.host("bob")
state = {}


def need(*names):
    missing = [n for n in names if n not in state]
    check(not missing, f"setup did not finish ({', '.join(missing)} missing)")
    return [state[n] for n in names]


def bob(*args):
    """A signing command on bob's host, with bob's person key."""
    return b.ok(*args, "--person-key", state["bob_key"])


def send_once(kind, text):
    (bert,) = need("bert")
    if kind == "message":
        result = a.cli("message", "send", "--peer", b.id, "--agent", bert.id, "--content", text)
        field = "state"
    else:
        result = a.cli("task", "submit", "--peer", b.id, "--agent", bert.id, "--input", text)
        field = "submit_state"
    # A sender that already knows bob's policy refuses before persisting anything; otherwise bob refuses.
    return result.json[field] if result.ok else "refused"


def outcome(kind, want, text="hi"):
    """Send alice -> bert until the outcome matches WANT (accepted, or refused/rejected), syncing alice's view
    of bob's policy in between: policy changes reach other hosts by sync (spec 10). Returns the last outcome."""
    deadline = __import__("time").monotonic() + 20
    while True:
        got = send_once(kind, text)
        if (got == "accepted") == (want == "accepted") or __import__("time").monotonic() > deadline:
            return got
        a.api("POST", f"/v2/networks/{state['net']}/sync", {})


def message_to_bert(text="hi", want="accepted"):
    return outcome("message", want, text)


def task_to_bert(want="accepted"):
    return outcome("task", want, "work")


def bob_policy_version():
    versions = b.api("GET", f"/v2/networks/{state['net']}/access-versions")[1]["policies"]
    mine = [p["version"] for p in versions if p["person_public_key"] == state["bob_public"]]
    return mine[0] if mine else 0


@suite.case("setup_two_people", "decentralized-spec 6, 8")
def _():
    net = create_network(a, "policy", "alice")
    state["net"] = net["id"]
    state["bob_key"] = ssh_key(b.root, "bob")
    join_new_person(a, b, "bob", state["bob_key"], net["id"])
    state["bob_public"] = b.api("GET", "/v2/networks")[1][0]["person_public_key"]
    state["ada"], state["bert"] = a.agent("ada"), b.agent("bert")


@suite.case("no_rule_refuses", "spec 5 (policy grants access); peer-messaging-contract 403")
def _():
    check(message_to_bert(want="refused") != "accepted", "bob's agent accepted a message with no policy rule for alice")


@suite.case("allow_person", "launch-contract 3 allow; spec 4.4 (policy lasts at most 24 h)")
def _():
    out = bob("allow", "alice")
    check(out["principal"].startswith("person:person_") and out["agent"] == "*", f"allow output {out}")
    check(out["actions"] == ["message.append", "task.submit"], f"default actions {out['actions']}")
    policy = out["policy"]
    life = (parse_time(policy["valid_until"]) - parse_time(policy["issued_at"])).total_seconds()
    check(0 < life <= 86400, f"policy lives {life:.0f}s; a coordinator-free policy lasts at most 24 hours")
    check(message_to_bert("allowed") == "accepted", "message refused after allow")
    check(task_to_bert() == "accepted", "task refused after allow (tasks are on by default)")
    person = urllib.parse.quote(state["bob_public"], safe="")  # a Base64 key may hold "/" and "+"
    status, body = b.api("GET", f"/v2/networks/{state['net']}/policy/{person}")
    check(status == 200, f"current policy statement: {status}")
    envelope = json.loads(base64.b64decode(body["statement_base64"]))
    payload = json.loads(base64.b64decode(envelope["payload_base64"]))
    signed = (parse_time(payload["not_after"]) - parse_time(payload["issued_at"])).total_seconds()
    check(signed <= 86400 and payload["operation_id"] == "-", f"policy statement lifetime {signed:.0f}s")


@suite.case("allow_no_tasks", "launch-contract 3 allow --no-tasks; task-contract authorization")
def _():
    out = bob("allow", "alice", "--no-tasks")
    check(out["actions"] == ["message.append"], f"actions {out['actions']}")
    check(message_to_bert() == "accepted", "message refused under a message-only rule")
    check(task_to_bert(want="refused") != "accepted", "task accepted under a message-only rule")
    refused = b.cli("allow", "alice", "--no-tasks", "--delegate", "--person-key", state["bob_key"])
    check(not refused.ok, "--delegate with --no-tasks was accepted")


@suite.case("deny_removes_and_reports", "launch-contract 3 deny")
def _():
    out = bob("deny", "alice")
    check(out["removed"] == 1, f"removed {out['removed']}")
    check(message_to_bert(want="refused") != "accepted", "message accepted after deny")
    before = bob_policy_version()
    again = bob("deny", "alice")
    check(again["removed"] == 0 and again.get("note"), f"second deny {again}")
    check(bob_policy_version() == before, "a deny that removed nothing signed a new version")


@suite.case("block_overrides_allow", "launch-contract 3 block/unblock")
def _():
    bob("allow", "everyone")
    check(message_to_bert() == "accepted", "allow everyone did not let alice in")
    b.ok("block", "alice")
    check(message_to_bert(want="refused") != "accepted", "a blocked person's message was accepted")
    b.ok("unblock", "alice")
    check(message_to_bert() == "accepted", "unblock did not restore access")


@suite.case("edit_version_check_and_retry", "spec 12.1 (DEC-S16, DEC-Q18); appendix 16.6", known=KNOWN)
def _():
    before = bob_policy_version()
    results = []

    def run(*args):
        results.append(b.cli(*args, "--person-key", state["bob_key"]))
    threads = [threading.Thread(target=run, args=("allow", "alice", "--agent", "bert")),
               threading.Thread(target=run, args=("allow", "everyone", "--agent", "other", "--no-tasks"))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check(all(r.ok for r in results), f"concurrent edits: {[(r.code, r.stderr.strip()[-150:]) for r in results]}")
    check(bob_policy_version() == before + 2, f"version {bob_policy_version()} after two edits from {before}")
    rules = b.ok("access", "show", "--network", state["net"])
    text = json.dumps(rules)
    check('"bert"' in text and '"other"' in text, "one of the two concurrent edits was lost")
    edits = b.api("GET", f"/v2/networks/{state['net']}/policy-edits")[1]["edits"]
    check(edits and not any(e["state"] == "reserved" for e in edits), f"edit states {[e['state'] for e in edits]}")
    status, _ = b.api("POST", f"/v2/networks/{state['net']}/policy-edits", {})
    check(status in (404, 405), f"the removed reservation route answered {status}")


@suite.case("capability_claim_commits_nothing", "spec 12.2; appendix 16.4 policy-claims")
def _():
    before = bob_policy_version()
    status, body = b.api("POST", f"/v2/networks/{state['net']}/policy-claims", {
        "capability": "fixture-claim", "provider_id": "auto", "signature_format": "auto", "payload_base64": "-",
        "approve": False})
    check(status != 404, "no policy-claims route")
    if status == 200:
        check(body["committed"] is False, f"a policy claim committed: {body}")
    check(bob_policy_version() == before, "preparing a capability claim changed the policy")


@suite.case("ban_revoked_host_loses_access", "spec 5.1 host_revoke; 20 item 61 (ban)")
def _():
    (ada,) = need("ada")
    a.ok("allow", "everyone")
    first = b.ok("message", "send", "--peer", a.id, "--agent", ada.id, "--content", "before")
    check(first["state"] == "accepted", f"bob -> alice before the ban: {first['state']}")
    a.ok("network", "revoke", "--network", state["net"], "--host", b.id, "--approve")
    members = a.api("GET", f"/v2/networks/{state['net']}/members")[1]["members"]
    check(b.public_key not in [m["host_public_key"] for m in members], "alice still lists bob's revoked host")
    after = b.cli("message", "send", "--peer", a.id, "--agent", ada.id, "--content", "after")
    check(not after.ok or after.json["state"] != "accepted", "alice accepted a message from a revoked host")


suite.finish()
