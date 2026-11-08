#!/usr/bin/env python3
"""Slim suite, direct dial: a member whose signed contact names an unreachable QUIC address first.

Two people on two hosts (dana creates, eli joins through an invite). Each host's transport file (appendix 17)
advertises its real first-contact listener and two QUIC addresses: `127.0.0.1:1`, where nothing listens and
which sorts before every other loopback port, and its real peer listener. No rendezvous or relay helper is
configured. After both owners allow each other, each host must still reach the other directly: the directory
lists the agent, a message is accepted and delivered, and a task is accepted, each within the 8-second request
bound, with no delivery attention for the peer in status. Both daemons restart before each direction so no connection
from the setup is reused. Written from docs/decentralized-runtime-contract.md section 9 (several signed QUIC
addresses, all dialed together) and its section 10 verification bullet, with docs/peer-messaging-contract.md
(the 8-second request bound) and docs/launch-contract.md (agents, send, task).
"""
import json
import time

from harness import Suite, check, create_network, join_new_person, ssh_key, wait_for

suite = Suite("direct_dial", __doc__)
UNREACHABLE = "127.0.0.1:1"
REQUEST_BOUND = 8.0  # peer-messaging contract: the request bound of one peer request
CLI_SLACK = 0.5  # starting the CLI process and the local socket round trip
state = {}


def transport(host):
    quic = sorted([UNREACHABLE, host.peer_address])
    check(quic[0] == UNREACHABLE, f"{UNREACHABLE} does not sort first beside {host.peer_address}")
    path = host.root / "transport.json"
    path.write_text(json.dumps({"format": 1, "advertise_bootstrap": [f"127.0.0.1:{host.bootstrap_port}"],
                                "advertise_quic": quic, "rendezvous": [], "relays": [], "publish_contacts": False}))
    path.chmod(0o600)
    host.extra_args = ["--transport-config", str(path)]


d, e = suite.host("dana", start=False), suite.host("eli", start=False)
for _h in (d, e):
    transport(_h)
    _h.start()


def need(*names):
    missing = [n for n in names if n not in state]
    check(not missing, f"setup did not finish ({', '.join(missing)} missing)")
    return [state[n] for n in names]


def timed(host, *args):
    began = time.monotonic()
    result = host.cli(*args, timeout=60)
    return result, time.monotonic() - began


def within_bound(what, took):
    check(took <= REQUEST_BOUND + CLI_SLACK, f"{what} took {took:.1f}s, want within the {REQUEST_BOUND:.0f}s bound")


@suite.case("setup_two_people_no_helpers", "decentralized-spec 6, 8; runtime contract 9 transport file")
def _():
    net = create_network(d, "dial", "dana")
    state["net"] = net["id"]
    eli_key = ssh_key(e.root, "eli")
    join_new_person(d, e, "eli", eli_key, net["id"])
    state["dot"], state["ezra"] = d.agent("dot"), e.agent("ezra")
    dana_allow = d.ok("allow", "eli")
    eli_allow = e.ok("allow", "dana", "--person-key", eli_key)
    policies = {}
    for owner, allowed in ((d, dana_allow), (e, eli_allow)):
        status, view = owner.api("GET", f"/v2/networks/{net['id']}")
        check(status == 200, f"{owner.name}: network: {status} {view}")
        policies[view["person_public_key"]] = allowed["policy"]["version"]
    for host in (d, e):
        def ready(host=host):
            status, body = host.api("POST", f"/v2/networks/{net['id']}/sync", {}, timeout=40)
            check(status == 200, f"{host.name}: sync: {status} {body}")
            status, body = host.api("GET", f"/v2/networks/{net['id']}/access-versions")
            check(status == 200, f"{host.name}: access-versions: {status} {body}")
            return all(any(p["person_public_key"] == person and p["version"] >= version
                           for p in body["policies"]) for person, version in policies.items())

        wait_for(ready, timeout=45, interval=1, message=f"{host.name} to learn both access policies")
    state["setup"] = True


def no_delivery_attention(host, other):
    status, body = host.api("GET", "/v2/status")
    check(status == 200, f"{host.name}: status: {status} {body}")
    items = body.get("attention") or []
    marks = (other.id, other.public_key)
    bad = [i for i in items
           if any(m and m in json.dumps(i) for m in marks)
           or any(w in str(i.get("kind", "")) for w in ("deliver", "transport", "unreach", "peer"))]
    check(not bad, f"{host.name}: delivery attention for {other.name}: {bad}")


def direction(sender, receiver, address, agent):
    """SENDER reaches RECEIVER's AGENT directly, though RECEIVER's first signed QUIC address is unreachable."""
    need("setup")
    for h in (sender, receiver):  # fresh daemons: no connection survives from setup or the other direction
        h.restart()
    for adapter in (state["dot"], state["ezra"]):
        adapter.connect()
    listed, took = timed(sender, "agents", "--refresh", "--json")
    check(listed.ok, f"{sender.name}: agents --refresh: {listed}")
    reachable = {r["address"]: r for r in listed.json["reachable"]}
    check(address in reachable and reachable[address]["agent_id"] == agent.id,
          f"{sender.name}'s directory does not list {address}: {sorted(reachable)}")
    within_bound(f"{sender.name}'s directory refresh", took)
    sent, took = timed(sender, "send", address, f"direct to {address}")
    check(sent.ok and sent.json["state"] == "accepted", f"{sender.name} -> {address}: {sent.json or sent}")
    within_bound(f"{sender.name}'s message to {address}", took)
    got = agent.next_message(timeout=20)
    check(got["request"]["content"] == f"direct to {address}", f"{agent.name} got {got['request']}")
    task, took = timed(sender, "task", address, "direct task")
    check(task.ok and task.json["submit_state"] == "accepted", f"{sender.name} task -> {address}: {task.json or task}")
    within_bound(f"{sender.name}'s task to {address}", took)
    claimed = agent.next_task(timeout=20)
    check(claimed["task"]["task_id"] == task.json["request"]["task_id"], f"{agent.name} claimed {claimed}")
    path = sender.ok("peer", "path", receiver.id)
    check(path["path"] in ("direct", "none"), f"{sender.name}'s path to {receiver.name}: {path}, want no relay")
    no_delivery_attention(sender, receiver)


@suite.case("unreachable_first_address_dana_to_eli", "runtime contract 9 several QUIC addresses; 10 verification")
def _():
    direction(d, e, "eli/ezra", state.get("ezra"))


@suite.case("unreachable_first_address_eli_to_dana", "runtime contract 9 several QUIC addresses; 10 verification")
def _():
    direction(e, d, "dana/dot", state.get("dot"))


suite.finish()
