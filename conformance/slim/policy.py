#!/usr/bin/env python3
"""Slim suite 3, policy: allow, deny, block, bans, versioned policy edits and capability claims.

alice creates a network and bob joins it; each has one fixture agent. Written from
docs/decentralized-spec.md sections 4.4, 5, 5.1 and 12, the wire appendix (sections 5,
16.6, 16.4) and docs/launch-contract.md slice 3 (allow, deny, block).
"""
import base64
import json
import subprocess
import threading
import urllib.parse

from harness import Suite, check, create_network, datetime, join_new_person, parse_time, rfc3339, ssh_key, timedelta, timezone

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


@suite.case("edit_version_check_and_retry", "spec 12.1 (DEC-S16, DEC-Q18); appendix 16.6")
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


def sshsig(key, message):
    """An SSHSIG signature (namespace peerspan-person-v1, spec 4.1) by KEY over MESSAGE, as Base64."""
    signed = subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", str(key), "-n", "peerspan-person-v1"],
                            input=message, capture_output=True, check=True).stdout.decode()
    return "".join(line for line in signed.splitlines() if not line.startswith("-----"))


@suite.case("capability_claim_commits_nothing", "spec 12.2; appendix 5, 16.4; capabilities contract Claims")
def _():
    net = state["net"]
    before = bob_policy_version()
    person = state["bob_public"]
    status, current = b.api("GET", f"/v2/networks/{net}/policy/{urllib.parse.quote(person, safe='')}")
    check(status == 200, f"current policy: {status} {current}")
    payload = json.loads(base64.b64decode(json.loads(base64.b64decode(current["statement_base64"]))["payload_base64"]))
    body = json.loads(base64.b64decode(payload["body_base64"]))
    edits = b.api("GET", f"/v2/networks/{net}/policy-edits")[1]["edits"]
    now = datetime.now(timezone.utc).replace(microsecond=0)
    until = now + timedelta(hours=24)
    # The successor of the current head (12.1), with one claim: a capability rule for this host with no principals
    # and the creation defaults (capabilities contract, Claims), and this host's next edit number.
    body.update(version=body["version"] + 1, issued_at=rfc3339(now), valid_until=rfc3339(until),
                capability_rules=body["capability_rules"] + [{
                    "host": b.id, "capability": "fixture-claim", "principals": [], "max_input_bytes": 65536,
                    "allow_disconnected": False, "max_calls_per_hour": 100}],
                edits=sorted([e for e in body["edits"] if e["host"] != b.id] +
                             [{"host": b.id, "seq": max([e["seq"] for e in edits] + [0]) + 1}],
                             key=lambda e: e["host"]))
    payload.update(sequence=payload["sequence"] + 1, predecessors=[current["statement_id"]], resolves=[],
                   issued_at=rfc3339(now), not_before=rfc3339(now), not_after=rfc3339(until),
                   body_base64=base64.b64encode(json.dumps(body, separators=(",", ":")).encode()).decode())
    status, claim = b.api("POST", f"/v2/networks/{net}/policy-claims", {
        "capability": "fixture-claim", "provider_id": person, "signature_format": "sshsig",
        "payload_base64": base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode(),
        "approve": True})
    check(status == 200, f"preparing a valid claim: {status} {claim}")
    while claim["signing_requests"]:
        signatures = [{"slot_id": r["slot_id"], "role": r["role"],
                       "signature": sshsig(state["bob_key"], base64.b64decode(r["message_base64"]))}
                      for r in claim["signing_requests"]]
        status, claim = b.api("POST", f"/v2/networks/{net}/policy-claims/{claim['action_id']}/signed",
                              {"intent_id": claim["signing_requests"][0]["intent_id"], "signatures": signatures})
        check(status == 200, f"signing the claim: {status} {claim}")
    check(claim["committed"] is False and claim["statement_base64"] not in (None, "-"),
          f"a signed claim: committed {claim.get('committed')}")
    check(bob_policy_version() == before, "a prepared capability claim changed the current policy")


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
