#!/usr/bin/env python3
"""Slim suite, direct dial: a member whose signed contact names an unreachable QUIC address first.

Two people on two hosts (dana creates, eli joins through an invite). Each host's transport file (appendix 17)
advertises its real first-contact listener and three QUIC addresses, in the file's sorted order: a black hole on
`127.0.0.10` (a UDP socket this suite binds, which reads and discards every datagram, so a QUIC handshake there
never completes and nothing is refused; as text it sorts before every `127.0.0.1` address), then `127.0.0.1:1`,
where nothing listens and which sorts before every other `127.0.0.1` port, then an opaque counted UDP carrier
that forwards QUIC bytes unchanged to its real peer listener (`counted_peer.CountedUDP`). No rendezvous or relay
helper is configured. After both owners allow each other, each host must still reach the
other directly: the directory lists the agent, a message is accepted and delivered, and a task is accepted, each
within the 8-second request bound, with no delivery attention for the peer in status. Policy changes must cross
the black hole as fast as without it: when one owner denies, then allows, the other, the other's non-refreshing
directory (`GET /v1/directory`) drops, then lists, the owner's agent within 10 seconds of the deny or allow
command returning. The same must hold when the hosts went more than 300 seconds without exchanging contacts, so
each holds only the other's expired signed contact: both daemons stop while the shared debug test clock moves past
a contact's lifetime, then start, and the first policy change after that (an allow, and after a second such
offline period a deny) must still reach the other's directory within 10 seconds. Both daemons restart before each
direction so no connection from the setup is reused. DIR-1: after the other host stores an owner's deny, one
whole-network `POST /v1/directory/refresh` counts as the refresh owed for it, so nothing more reaches the owner's
counted carrier or black hole for the following 10 seconds (every earlier task is first made final, so no task
polling runs); the allow after that refresh is still reflected within
10 seconds. Written
from docs/decentralized-runtime-contract.md section 9 (several signed QUIC addresses, all dialed together, for
every request including record delivery and catalog sync: a silently dropping address costs no request more
time) and its section 10 verification bullet, with docs/decentralized-spec.md section 10 (new outgoing records are
tried at once; 9.1, contacts valid at most 300 seconds), docs/developer-guide.md (the test clock),
docs/peer-messaging-contract.md (the 8-second request bound) and docs/launch-contract.md (agents,
send, task, allow, deny, the directory's 10-second bound after a stored policy changes, and DIR-1 with its
Discovery verification bullet).
"""
import json
import socket
import threading
import time

from counted_peer import CountedUDP
from harness import Suite, check, create_network, join_new_person, ssh_key, wait_for, with_json

suite = Suite("direct_dial", __doc__)
clock = suite.use_clock()  # both hosts read one debug test clock (developer guide); it stays at +0 until moved
UNREACHABLE = "127.0.0.1:1"
REQUEST_BOUND = 8.0  # peer-messaging contract: the request bound of one peer request
CLI_SLACK = 0.5  # starting the CLI process and the local socket round trip
CONTACT_LIFETIME = 300  # decentralized-spec 9.1: a signed contact is valid at most 300 seconds
DIRECTORY_BOUND = 10.0  # launch contract directory "When:"; runtime contract 10: as with no unreachable address
DIAGNOSTIC_WATCH = 20.0  # past the bound, only to report the real delay of a failure
POLL = 0.25  # one poll of access-versions plus GET /v1/directory
SYNC_FLOOR = 50.0  # decentralized-spec 10: background sync every 60 s with up to 10 s of jitter
state = {}


class BlackHole:
    """A UDP socket that reads and discards every datagram: no reply and no ICMP refusal, so a QUIC handshake to
    it never completes. Bound on 127.0.0.10, which Linux routes to loopback like all of 127.0.0.0/8: as text,
    `127.0.0.10:PORT` sorts before `127.0.0.1:1` and every other `127.0.0.1` address. Unprivileged (an ephemeral
    port) and needs no firewall."""

    def __init__(self):
        self.received = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.10", 0))
        self.address = f"127.0.0.10:{self.sock.getsockname()[1]}"
        threading.Thread(target=self._drain, daemon=True).start()

    def _drain(self):
        while True:
            try:
                self.sock.recv(65536)
                self.received += 1
            except OSError:
                return


def transport(host):
    hole = host.hole = BlackHole()
    counted = host.counted = CountedUDP(("127.0.0.1", host.peer_port))  # opaque: forwards to the real listener
    quic = sorted([UNREACHABLE, hole.address, counted.address])
    check(quic == [hole.address, UNREACHABLE, counted.address],
          f"want the black hole, then {UNREACHABLE}, then the counted real listener; sorted: {quic}")
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
    result = host.cli(*with_json(args), timeout=60)  # each caller reads the object (OUT-2)
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
    state["eli_key"] = eli_key
    dana_allow = d.ok("allow", "eli")
    eli_allow = e.ok("allow", "dana", "--person-key", eli_key)
    policies = {}
    for owner, allowed in ((d, dana_allow), (e, eli_allow)):
        status, view = owner.api("GET", f"/v2/networks/{net['id']}")
        check(status == 200, f"{owner.name}: network: {status} {view}")
        policies[view["person_public_key"]] = allowed["policy"]["version"]
        state[f"{owner.name}_person"] = view["person_public_key"]
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


def policy_version(host, owner):
    """The newest version of OWNER's policy stored on HOST (a pure read)."""
    status, body = host.api("GET", f"/v2/networks/{state['net']}/access-versions")
    check(status == 200, f"{host.name}: access-versions: {status} {body}")
    person = state[f"{owner.name}_person"]
    return max((p["version"] for p in body["policies"] if p["person_public_key"] == person), default=0)


def lists(viewer, address, agent):
    """Whether VIEWER's cached directory (GET /v1/directory, never a refresh) lists ADDRESS with an authorization."""
    status, body = viewer.api("GET", f"/v1/directory?network={state['net']}")
    check(status == 200, f"{viewer.name}: directory: {status} {body}")
    return any(e["address"] == address and e["agent_id"] == agent.id and e["authorizations"] for e in body["agents"])


def follows(owner, viewer, address, agent, want, what, returned):
    """VIEWER's non-refreshing directory must reach WANT for ADDRESS within DIRECTORY_BOUND seconds of OWNER's
    policy command returning at RETURNED. Keeps watching past the bound only to report the real delay."""
    version = policy_version(owner, owner)
    stored_at = changed_at = None
    while True:
        now = time.monotonic()
        if stored_at is None and policy_version(viewer, owner) >= version:
            stored_at = now - returned
        if lists(viewer, address, agent) == want:
            if changed_at is None:
                changed_at = time.monotonic() - returned
            if stored_at is not None:
                break
        else:
            changed_at = None  # flapped back; wait for a stable change
        if now - returned > DIAGNOSTIC_WATCH:
            break
        time.sleep(POLL)
    stored = "never" if stored_at is None else f"{stored_at:.1f}s"
    done = f"not within {DIAGNOSTIC_WATCH:.0f}s" if changed_at is None or stored_at is None else f"{changed_at:.1f}s"
    print(f"  {what}: {viewer.name} stored {owner.name}'s policy v{version} after {stored}; "
          f"its directory {'listed' if want else 'dropped'} {address} after {done}", flush=True)
    check(changed_at is not None and stored_at is not None and changed_at <= DIRECTORY_BOUND + POLL,
          f"{what}: {viewer.name}'s directory {'listed' if want else 'dropped'} {address} {done} after the command "
          f"returned ({viewer.name} stored the policy after {stored}); want within {DIRECTORY_BOUND:.0f}s with no "
          f"refresh, as with no unreachable address")


def restart_both(owner, viewer, offline):
    """Fresh daemons, so no connection survives from earlier cases. With OFFLINE, both are stopped while the shared
    test clock moves more than CONTACT_LIFETIME seconds forward, so when they start again each holds only the
    other's expired signed contact: the hosts went more than 300 s without exchanging contacts, then reconnect."""
    for h in (owner, viewer):
        h.stop()
    if offline:
        clock.set(clock.offset + CONTACT_LIFETIME + 30)
    for h in (owner, viewer):
        h.start()
    for adapter in (state["dot"], state["ezra"]):
        adapter.connect()


def change(owner, viewer, verb, args):
    began = time.monotonic()
    result = owner.ok(verb, *args)
    returned = time.monotonic()
    print(f"  {owner.name} {verb} {viewer.name} returned after {returned - began:.1f}s", flush=True)
    if verb == "deny":
        check(result["removed"] == 1, f"{owner.name}: deny removed {result['removed']}")
    return returned


def policy_direction(owner, viewer, address, agent, deny_args, allow_args):
    """OWNER denies, then allows, VIEWER; VIEWER's directory follows each within the bound across the black holes."""
    need("setup")
    restart_both(owner, viewer, offline=False)
    wait_for(lambda: lists(viewer, address, agent), timeout=60, interval=0.5,
             message=f"{viewer.name}'s directory to list {address} after the restart")
    returned = change(owner, viewer, "deny", deny_args)
    follows(owner, viewer, address, agent, False, f"{owner.name} deny {viewer.name}", returned)
    returned = change(owner, viewer, "allow", allow_args)
    follows(owner, viewer, address, agent, True, f"{owner.name} allow {viewer.name}", returned)


def expired_direction(owner, viewer, address, agent, deny_args, allow_args):
    """Each measured change is the first after an offline period longer than a contact's lifetime: OWNER denies
    VIEWER (fresh contacts, as above), both go offline past 300 s, OWNER allows; both go offline again, OWNER
    denies. VIEWER's non-refreshing directory must follow each within the bound. Ends with VIEWER allowed again."""
    need("setup")
    restart_both(owner, viewer, offline=False)
    wait_for(lambda: lists(viewer, address, agent), timeout=60, interval=0.5,
             message=f"{viewer.name}'s directory to list {address} after the restart")
    returned = change(owner, viewer, "deny", deny_args)
    follows(owner, viewer, address, agent, False, f"{owner.name} deny {viewer.name} (fresh contacts)", returned)
    restart_both(owner, viewer, offline=True)
    returned = change(owner, viewer, "allow", allow_args)
    follows(owner, viewer, address, agent, True, f"{owner.name} allow {viewer.name} after contacts expired",
            returned)
    restart_both(owner, viewer, offline=True)
    returned = change(owner, viewer, "deny", deny_args)
    follows(owner, viewer, address, agent, False, f"{owner.name} deny {viewer.name} after contacts expired",
            returned)
    returned = change(owner, viewer, "allow", allow_args)  # restore for the cases after this one
    follows(owner, viewer, address, agent, True, f"{owner.name} allow {viewer.name} (restore)", returned)


@suite.case("black_hole_policy_dana_to_eli", "runtime contract 9 every request; 10 verification policy changes")
def _():
    policy_direction(d, e, "dana/dot", state.get("dot"), ["eli"], ["eli"])


@suite.case("black_hole_policy_eli_to_dana", "runtime contract 9 every request; 10 verification policy changes")
def _():
    key = state.get("eli_key")
    policy_direction(e, d, "eli/ezra", state.get("ezra"), ["dana", "--person-key", key],
                     ["dana", "--person-key", key])


@suite.case("expired_contacts_policy_dana_to_eli", "runtime contract 9 every request; 10 verification policy "
            "changes; spec 9.1 contacts valid at most 300 s")
def _():
    expired_direction(d, e, "dana/dot", state.get("dot"), ["eli"], ["eli"])


@suite.case("expired_contacts_policy_eli_to_dana", "runtime contract 9 every request; 10 verification policy "
            "changes; spec 9.1 contacts valid at most 300 s")
def _():
    key = state.get("eli_key")
    expired_direction(e, d, "eli/ezra", state.get("ezra"), ["dana", "--person-key", key],
                     ["dana", "--person-key", key])


def toward(owner):
    """Every count of UDP addressed to OWNER: both directions of its counted carrier, and its black hole."""
    return owner.counted.counts() + (owner.hole.received,)


FINAL = {"rejected", "expired", "succeeded", "failed", "cancelled"}  # task contract states


def tasks_final():
    """Every task either host submitted ends final, with all its events stored, so neither polls the other.

    The task contract polls the receiver for each accepted task that is not final; the direction cases leave a
    claimed but queued task each way. Its claiming session rejects it (queued -> rejected, an ordinary adapter
    transition), then the submitter's polling stores the final state and stops."""
    for submitter in (d, e):
        status, listed = submitter.api("GET", "/v1/tasks?limit=100")
        check(status == 200, f"{submitter.name}: task list: {status} {listed}")
        for row in listed:
            record = row["task"]
            if record["submit_state"] != "accepted" or (record["status"] or {}).get("state") in FINAL:
                continue
            task_id = record["request"]["task_id"]
            agent = next(a for a in (state["dot"], state["ezra"]) if a.id == record["request"]["target_agent_id"])
            status, body = agent.post(f"/adapter/v1/tasks/{task_id}/reject", {"reason": "DIR-1 case: no pending work"})
            check(status == 200 and body["state"] in FINAL, f"{agent.name}: reject {task_id}: {status} {body}")

            def stored(submitter=submitter, task_id=task_id):
                code, local = submitter.api("GET", f"/v1/tasks/{record['peer_host_id']}/{task_id}")
                check(code == 200, f"{submitter.name}: task {task_id}: {code} {local}")
                done = local["status"] or {}
                return done.get("state") in FINAL and local["events_after"] == done.get("last_event")
            wait_for(stored, timeout=20, interval=0.25, message=f"{submitter.name} to store task {task_id} as final")


def refresh_counts_for_earlier_change(owner, viewer, address, agent, deny_args, allow_args):
    """DIR-1: OWNER denies VIEWER; once VIEWER's host stores that policy, one whole-network on-demand refresh is the
    refresh owed for it, so VIEWER sends OWNER no further query for 10 seconds (nothing reaches OWNER's counted
    carrier or black hole). OWNER's allow after that refresh is still reflected within 10 seconds."""
    need("setup")
    restart_both(owner, viewer, offline=False)  # fresh daemons: the next background sync is SYNC_FLOOR away
    started = time.monotonic()
    tasks_final()  # no task polling in the window (task contract: polling stops once final)
    wait_for(lambda: lists(viewer, address, agent), timeout=30, interval=0.25,
             message=f"{viewer.name}'s directory to list {address} after the restart")
    version = policy_version(owner, owner) + 1
    change(owner, viewer, "deny", deny_args)
    check(policy_version(owner, owner) >= version, f"{owner.name}'s deny stored no new policy version")
    wait_for(lambda: policy_version(viewer, owner) >= version, timeout=20, interval=0.05,
             message=f"{viewer.name}'s host to store {owner.name}'s deny")
    # The change is stored before the refresh starts, so this refresh counts for it.
    status, view = viewer.api("POST", f"/v1/directory/refresh?network={state['net']}", {}, timeout=12)
    returned = time.monotonic()
    check(status == 200 and view.get("network_id") == state["net"], f"{viewer.name}: refresh: {status} {view}")
    check(not any(e["address"] == address and e["authorizations"] for e in view["agents"]),
          f"{viewer.name}'s refresh after storing the deny still lists {address}")
    # Only the refresh's own trailing datagrams (its last ACKs) may still arrive: the carrier must settle at once.
    previous, since = toward(owner), time.monotonic()
    while time.monotonic() - since < 0.3:
        check(time.monotonic() - returned < 2, f"{owner.name}'s carrier did not settle after {viewer.name}'s refresh")
        time.sleep(0.05)
        if toward(owner) != previous:
            previous, since = toward(owner), time.monotonic()
    while time.monotonic() - returned < DIRECTORY_BOUND + POLL:
        time.sleep(POLL)
        now = toward(owner)
        check(now == previous, f"{viewer.name} queried {owner.name} again {time.monotonic() - returned:.1f}s after "
              f"its on-demand refresh, which counts for the earlier deny (DIR-1): carrier "
              f"(in datagrams, in bytes, back datagrams, back bytes, black hole) {previous} -> {now}")
    check(time.monotonic() - started < SYNC_FLOOR,
          f"the quiet window ended {time.monotonic() - started:.0f}s after the restart, past the first background sync")
    print(f"  no datagram toward {owner.name} for {DIRECTORY_BOUND:.0f}s after {viewer.name}'s refresh", flush=True)
    returned = change(owner, viewer, "allow", allow_args)
    follows(owner, viewer, address, agent, True, f"{owner.name} allow {viewer.name} after the refresh", returned)


@suite.case("on_demand_refresh_counts_for_earlier_change", "launch contract directory When: and Discovery "
            "verification (DIR-1)")
def _():
    refresh_counts_for_earlier_change(d, e, "dana/dot", state.get("dot"), ["eli"], ["eli"])


@suite.case("black_holes_were_dialed", "runtime contract 9: every currently signed QUIC address is dialed")
def _():
    for host in (d, e):
        check(host.hole.received > 0, f"no datagram reached {host.name}'s black hole {host.hole.address}: "
              "it was never dialed, so the cases above did not exercise it")
    print(f"  datagrams discarded: dana's {d.hole.received}, eli's {e.hole.received}", flush=True)


suite.finish()
