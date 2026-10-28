#!/usr/bin/env python3
"""Slim suite 2, renewal: grant lifetimes, automatic renewal, retention, warnings and expiry.

alice creates a network (her host holds the root seed) and bob joins it. Every host and CLI runs on one shared
debug test clock, which the suite moves forward through a week. Written from docs/decentralized-spec.md
sections 4.4, 5, 7 and 16, and the wire appendix sections 4 and 5.
"""
from harness import (Suite, timedelta, attention, check, create_network, join_new_person, members, parse_time, ssh_key,
                     statements, wait_for)  # noqa: F401

DAY, HOUR = 86400, 3600
suite = Suite("renewal", __doc__)
suite.use_clock()
a, b = suite.host("alice"), suite.host("bob")
state = {}


def renewal_wait():
    """How long to wait for a renewal: hosts check every 60 seconds (spec 7.1). Once one expected renewal never
    came, later cases wait briefly, so a product without automatic renewal still finishes within the budget."""
    return 70 if state.get("renewal_seen", True) else 12


def renewed(predicate, message):
    try:
        wait_for(predicate, timeout=renewal_wait(), interval=1, message=message)
    except AssertionError:
        state["renewal_seen"] = False
        raise


def need(*names):
    missing = [n for n in names if n not in state]
    check(not missing, f"an earlier case did not finish ({', '.join(missing)} missing)")
    return [state[n] for n in names]


def left(text):
    """Seconds from the shifted now to TEXT."""
    return (parse_time(text) - suite.now()).total_seconds()


def bob_policy_version():
    versions = b.api("GET", f"/v2/networks/{state['net']}/access-versions")[1]["policies"]
    return max([p["version"] for p in versions if p["person_public_key"] == state["bob_person"]] or [0])


def newest(host, kind, **subject):
    """The highest-sequence payload of KIND whose subject matches."""
    found = [p for k, _, p in statements(host, state["net"], kind)
             if all(p["subject"].get(f) == v for f, v in subject.items())]
    return max(found, key=lambda p: p["sequence"]) if found else None


@suite.case("setup_and_lifetimes", "spec 4.4, 6, 8; appendix 4.3, 5")
def _():
    net = create_network(a, "renewal", "alice")
    state["net"] = net["id"]
    state["bob_key"] = ssh_key(b.root, "bob")
    join_new_person(a, b, "bob", state["bob_key"], net["id"])
    state["bob_person"] = b.api("GET", "/v2/networks")[1][0]["person_public_key"]
    b.ok("allow", "alice", "--person-key", state["bob_key"])
    m = members(a, net["id"])
    state["start"] = {k: dict(v) for k, v in m.items()}
    for key, member in m.items():
        check(6 * DAY < left(member["not_after"]) <= 7 * DAY, f"{member['member']} lasts {left(member['not_after'])}s")
    for kind, _, payload in statements(a, net["id"]):
        if kind.endswith("_lease"):
            life = (parse_time(payload["not_after"]) - parse_time(payload["issued_at"])).total_seconds()
            check(0 < life <= 7 * DAY, f"a {kind} lasts {life:.0f}s, over 7 days")
        if kind in ("policy", "group"):
            life = (parse_time(payload["not_after"]) - parse_time(payload["issued_at"])).total_seconds()
            check(0 < life <= DAY, f"a {kind} lasts {life:.0f}s, over 24 hours")
    state["policy_version"] = bob_policy_version()
    check(state["policy_version"] >= 1, "bob has no policy")
    a.ok("allow", "everyone")
    state["ada"] = a.agent("ada")


@suite.case("policy_renewed_at_8_hours", "spec 7.1 thresholds (DEC-Q24); 20 item 18", known="DEC-S8/DEC-Q24: no automatic renewal")
def _():
    (version,) = need("policy_version")
    suite.set_offset(15 * HOUR + 30 * 60)  # 8.5 hours left: not yet
    b.api("POST", f"/v2/networks/{state['net']}/sync", {})
    check(bob_policy_version() == version, "the policy was renewed before 8 hours were left")
    suite.set_offset(16 * HOUR + 10 * 60)  # 7 h 50 min left
    renewed(lambda: bob_policy_version() > version, "bob's host to renew his 24-hour policy with 8 hours left")
    state["policy_version"] = bob_policy_version()


@suite.case("root_renews_root_signed_grants_4_days_early", "spec 7.1, 7.3 (DEC-Q12); 20 item 18", known="DEC-S11/DEC-Q12: no automatic renewal")
def _():
    (start,) = need("start")
    suite.set_offset(2 * DAY + 23 * HOUR)  # 4 days and 1 hour left
    a.api("POST", f"/v2/networks/{state['net']}/sync", {})
    first = {k: v["host_lease_id"] for k, v in members(a, state["net"]).items()}
    check(first == {k: v["host_lease_id"] for k, v in start.items()}, "host grants were renewed before 4 days were left")
    suite.set_offset(3 * DAY + 1 * HOUR)  # 3 days and 23 hours left
    renewed(lambda: all(m["host_lease_id"] != start[k]["host_lease_id"]
                        for k, m in members(a, state["net"]).items()),
            "the root host to renew both host grants with 4 days left")
    admin = newest(a, "admin_lease")
    check(admin and admin["sequence"] >= 2 and left(admin["not_after"]) > 6 * DAY, "the admin grant was not renewed")
    bob_person = newest(a, "person_lease", person_public_key=state["bob_person"])
    check(bob_person["sequence"] >= 2, "bob's person grant was not renewed")


@suite.case("renewal_keeps_children", "spec 7.2 retention (DEC-S10); 20 item 23", known="DEC-S10: no renewal to keep children")
def _():
    (start,) = need("start")
    bob = start[b.public_key]
    renewed = newest(a, "person_lease", person_public_key=state["bob_person"])
    check(renewed and renewed["sequence"] >= 2, "no renewed person grant for bob")
    kept = set(renewed["retained_statement_ids"])
    for name in ("binding_lease_id", "device_lease_id"):
        check(bob[name] in kept, f"the renewed person grant does not keep bob's {name.replace('_lease_id', '')} grant")
    view = b.api("GET", "/v2/networks")[1][0]
    check(view["authority"]["state"] == "usable", f"bob's authority after the renewal: {view['authority']}")


@suite.case("binding_renewed_by_device_issuer_only", "spec 7.1 (DEC-Q10, DEC-Q28); 20 item 21", known="DEC-Q10/DEC-Q28: no automatic renewal")
def _():
    (start,) = need("start")
    suite.set_offset(5 * DAY + 1 * HOUR)  # bob's binding has under 2 days left
    renewed(lambda: members(a, state["net"])[b.public_key]["binding_lease_id"]
            != start[b.public_key]["binding_lease_id"], "bob's device to renew his binding with 2 days left")
    binding = newest(a, "binding_lease", person_public_key=state["bob_person"])
    roles = None
    for kind, envelope, payload in statements(a, state["net"], "binding_lease"):
        if payload == binding:
            roles = [s["role"] for s in envelope["signatures"]]
    check(binding["operation_id"] == "-" and binding["issuer"]["kind"] == "device", f"binding issuer {binding['issuer']}")
    check(roles == ["issuer"], f"a deadline-only binding renewal carries roles {roles}, want issuer only")


@suite.case("sole_device_warns_signer_unavailable", "spec 7.1 warnings, DEC-Q8; 20 item 24", known="spec 7.1, 16: status fails 409 after the clock moves")
def _():
    # bob's only device may not renew its own grant (DEC-Q8), and his original key is not on any host.
    kinds = {k for k, _ in attention(b)[0]}
    check("person_device_signer_unavailable" in kinds,
          f"inside the renewal threshold with no renewer, bob's status shows {sorted(kinds)}")


@suite.case("creator_device_renews_itself", "spec 6, 7.1 (DEC-Q21, DEC-Q27); 20 item 17", known="DEC-Q21/DEC-Q27")
def _():
    (start,) = need("start")
    alice = members(a, state["net"])[a.public_key]
    check(alice["device_lease_id"].startswith("ds_"), "the creator's host has no device grant to renew (DEC-Q21)")
    check(alice["binding_lease_id"] != start[a.public_key]["binding_lease_id"],
          "the creator device did not renew the creator's binding with 2 days left")


@suite.case("root_offline_countdown", "spec 7.3 (DEC-Q12); 20 item 25", known="DEC-Q12, spec 16: status fails 409 after the clock moves")
def _():
    check("network_root_unreachable" not in {k for k, _ in attention(b)[0]},
          "the root countdown shows while the root host is online")
    admin = newest(a, "admin_lease")
    a.stop()
    deadline = parse_time(admin["not_after"])
    # 3 days and 2 hours left is N = 4: no countdown yet; 2 days and 22 hours left is N = 3.
    target = deadline - timedelta(days=3, hours=2)
    suite.set_offset(suite.offset + int((target - suite.now()).total_seconds()))
    check("network_root_unreachable" not in {k for k, _ in attention(b)[0]}, "the countdown shows with N = 4")
    suite.set_offset(suite.offset + 4 * HOUR)
    items, _ = attention(b)
    texts = [d for k, d in items if k == "network_root_unreachable"]
    check(texts and "root unreachable: network stops in 3 days" in texts[0],
          f"with the root offline and 2 days 22 hours left, bob's status shows {sorted(items)}")


@suite.case("expiry_stops_access", "spec 4.4, 5 (accepted work), 16")
def _():
    (start,) = need("start")
    if a.process is None:
        a.start()
    device_end = parse_time(newest(b, "device_lease", person_public_key=state["bob_person"])["not_after"])
    suite.set_offset(suite.offset + int((device_end - suite.now()).total_seconds()) + 60)
    view = b.api("GET", "/v2/networks")[1][0]
    check(view["authority"]["state"] == "authority_expired", f"after bob's device grant ended: {view['authority']}")
    (ada,) = need("ada")
    sent = b.cli("message", "send", "--peer", a.id, "--agent", ada.id, "--content", "after expiry")
    check(not sent.ok or sent.json["state"] != "accepted", "a host with expired grants still had a message accepted")


suite.finish()
