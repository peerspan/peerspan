#!/usr/bin/env python3
"""Slim suite 2, renewal: grant lifetimes, automatic renewal, retention, warnings and expiry.

Four independent networks run side by side, each with its own debug test clock, so each renewal window gets
the full time the spec allows (hosts check every 60 seconds, spec 7.1) without the suite taking four times as
long. In each, alice creates the network (her host holds the root seed) and bob joins. Written from
docs/decentralized-spec.md sections 4.4, 5, 7 and 16, and the wire appendix sections 4 and 5.
"""
import threading
import traceback

from harness import (Clock, Failure, Suite, attention, check, create_network, join_new_person, members, parse_time, ssh_key,
                     statements, timedelta, wait_for)

DAY, HOUR = 86400, 3600
WINDOW = 75  # one 60-second renewal pass plus the 10-second sync jitter and bounded sync (spec 7.1, 10)
suite = Suite("renewal", __doc__)


class World:
    """One network on its own clock: alice (root) and bob."""

    def __init__(self, tag):
        self.tag = tag
        self.clock = Clock(suite.work / f"clock-{tag}")
        self.a = suite.host(f"alice-{tag}", clock=self.clock)
        self.b = suite.host(f"bob-{tag}", clock=self.clock)
        self.results = {}
        self.errors = {}

    def setup(self):
        net = create_network(self.a, f"renewal-{self.tag}", "alice")
        self.net = net["id"]
        self.bob_key = ssh_key(self.b.root, "bob")
        join_new_person(self.a, self.b, "bob", self.bob_key, self.net)
        self.bob_person = self.b.api("GET", "/v2/networks")[1][0]["person_public_key"]
        self.b.ok("allow", "alice", "--person-key", self.bob_key)
        self.start = {k: dict(v) for k, v in members(self.a, self.net).items()}

    def now(self):
        return self.clock.now()

    def left(self, text):
        return (parse_time(text) - self.now()).total_seconds()

    def policy_version(self):
        versions = self.b.api("GET", f"/v2/networks/{self.net}/access-versions")[1]["policies"]
        return max([p["version"] for p in versions if p["person_public_key"] == self.bob_person] or [0])

    def newest(self, kind, **subject):
        found = [p for k, _, p in statements(self.a, self.net, kind)
                 if all(p["subject"].get(f) == v for f, v in subject.items())]
        return max(found, key=lambda p: p["sequence"]) if found else None

    def step(self, name, function):
        """Run one timed step; its outcome is reported later by the case of the same name."""
        try:
            self.results[name] = function()
        except Exception as error:  # noqa: BLE001 - reported by the case
            self.errors[name] = error
            traceback.print_exc()


worlds = {}


def in_parallel(functions):
    threads = [threading.Thread(target=f) for f in functions]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def outcome(world, name):
    w = worlds.get(world)
    check(w is not None and "setup" not in w.errors, f"network {world} did not set up")
    if name in w.errors:
        raise w.errors[name]
    check(name in w.results, f"step {name} did not run")
    return w.results[name]


def policy_world(w):
    """A 24-hour policy renews with 8 hours left."""
    def renews():
        version = w.policy_version()
        w.clock.set(15 * HOUR + 30 * 60)  # 8.5 hours left: not yet
        w.b.api("POST", f"/v2/networks/{w.net}/sync", {})
        check(w.policy_version() == version, "the policy was renewed before 8 hours were left")
        w.clock.set(16 * HOUR + 10 * 60)  # 7 h 50 min left
        wait_for(lambda: w.policy_version() > version, timeout=WINDOW, interval=1,
                 message="bob's host to renew his 24-hour policy with 8 hours left")
    w.step("policy_renewed_at_8_hours", renews)


def root_world(w):
    """Root-signed grants renew 4 days early and keep their children; the countdown."""
    def renews():
        w.clock.set(2 * DAY + 23 * HOUR)  # 4 days and 1 hour left
        w.a.api("POST", f"/v2/networks/{w.net}/sync", {})
        now = {k: v["host_lease_id"] for k, v in members(w.a, w.net).items()}
        check(now == {k: v["host_lease_id"] for k, v in w.start.items()}, "renewed before 4 days were left")
        w.clock.set(3 * DAY + 1 * HOUR)  # 3 days and 23 hours left
        wait_for(lambda: all(m["host_lease_id"] != w.start[k]["host_lease_id"]
                             for k, m in members(w.a, w.net).items()), timeout=WINDOW, interval=1,
                 message="the root host to renew both host grants with 4 days left")
        admin = w.newest("admin_lease")
        check(admin and admin["sequence"] >= 2 and w.left(admin["not_after"]) > 6 * DAY, "the admin grant was not renewed")
        check(w.newest("person_lease", person_public_key=w.bob_person)["sequence"] >= 2,
              "bob's person grant was not renewed")
    w.step("root_renews_root_signed_grants_4_days_early", renews)

    def keeps():
        renewed = w.newest("person_lease", person_public_key=w.bob_person)
        check(renewed and renewed["sequence"] >= 2, "no renewed person grant for bob")
        kept = set(renewed["retained_statement_ids"])
        for name in ("binding_lease_id", "device_lease_id"):
            check(w.start[w.b.public_key][name] in kept,
                  f"the renewed person grant does not keep bob's {name.replace('_lease_id', '')} grant")
        check(w.b.api("GET", "/v2/networks")[1][0]["authority"]["state"] == "usable", "bob is no longer usable")
    w.step("renewal_keeps_children", keeps)

    def countdown():
        check("network_root_unreachable" not in {k for k, _ in attention(w.b)[0]},
              "the root countdown shows while the root host is online")
        deadline = parse_time(w.newest("admin_lease")["not_after"])
        w.a.stop()
        w.clock.set(w.clock.offset + int((deadline - timedelta(days=3, hours=2) - w.now()).total_seconds()))
        check("network_root_unreachable" not in {k for k, _ in attention(w.b)[0]}, "the countdown shows with N = 4")
        w.clock.set(w.clock.offset + 4 * HOUR)
        items, _ = attention(w.b)
        texts = [d for k, d in items if k == "network_root_unreachable"]
        check(texts and "root unreachable: network stops in 3 days" in texts[0],
              f"with the root offline and 2 days 22 hours left, bob's status shows {sorted(items)}")
    w.step("root_offline_countdown", countdown)


def device_world(w):
    """The device-signed binding renewal, the signer warning, and the creator device's own renewals."""
    def binding_and_creator():
        w.clock.set(5 * DAY + 1 * HOUR)  # every 7-day grant has under 2 days left
        bob_start = w.start[w.b.public_key]["binding_lease_id"]
        alice_start = w.start[w.a.public_key]

        def creator_done(m):
            return (m["device_lease_id"] != alice_start["device_lease_id"]
                    and m["binding_lease_id"] != alice_start["binding_lease_id"])
        # One window for both: each renewal gets the whole of it.
        try:
            wait_for(lambda: (lambda m: m[w.b.public_key]["binding_lease_id"] != bob_start
                              and creator_done(m[w.a.public_key]))(members(w.a, w.net)),
                     timeout=WINDOW, interval=1, message="the renewals")
        except AssertionError:
            pass
        m = members(w.a, w.net)
        return {"bob": m[w.b.public_key]["binding_lease_id"] != bob_start, "creator_has_device":
                alice_start["device_lease_id"].startswith("ds_"), "creator": creator_done(m[w.a.public_key])}
    w.step("window", binding_and_creator)

    def binding():
        seen = outcome("device", "window")
        check(seen["bob"], f"bob's device did not renew his binding within {WINDOW}s of 2 days being left")
        renewed = w.newest("binding_lease", person_public_key=w.bob_person)
        roles = [[s["role"] for s in e["signatures"]] for _, e, p in statements(w.a, w.net, "binding_lease")
                 if p == renewed][0]
        check(renewed["operation_id"] == "-" and renewed["issuer"]["kind"] == "device", f"issuer {renewed['issuer']}")
        check(roles == ["issuer"], f"a deadline-only binding renewal carries roles {roles}, want issuer only")
    w.step("binding_renewed_by_device_issuer_only", binding)

    def warns():
        kinds = {k for k, _ in attention(w.b)[0]}
        check("person_device_signer_unavailable" in kinds,
              f"inside the renewal threshold with no renewer, bob's status shows {sorted(kinds)}")
    w.step("sole_device_warns_signer_unavailable", warns)

    def creator():
        seen = outcome("device", "window")
        check(seen["creator_has_device"], "the creator's host has no device grant (DEC-Q21)")
        check(seen["creator"], "the creator device did not renew both its own device grant and the creator's binding "
                               f"within {WINDOW}s of 2 days being left")
    w.step("creator_device_renews_itself", creator)


def expiry_world(w):
    """Bob's host stays offline past the end of his device grant, while alice's host renews its own grants and
    carol joins fresh, so the receiving host and its policy stay valid; carol's message to alice is the control."""
    def expiry():
        bob_end = parse_time(w.newest("device_lease", person_public_key=w.bob_person)["not_after"])
        alice_start = w.start[w.a.public_key]
        w.b.stop()  # bob's host cannot renew anything of his own from here on
        w.clock.set(5 * DAY + 1 * HOUR)  # inside alice's 4-day (root-signed) and 2-day (device-signed) thresholds
        wait_for(lambda: all(members(w.a, w.net)[w.a.public_key][k] != alice_start[k]
                             for k in ("host_lease_id", "device_lease_id", "binding_lease_id")),
                 timeout=WINDOW, interval=1, message="alice's host to renew its own grants")
        carol = suite.host(f"carol-{w.tag}", clock=w.clock)
        join_new_person(w.a, carol, "carol", ssh_key(carol.root, "carol"), w.net)
        ada = w.a.agent("ada")
        sync_result = []
        syncing = None

        def sync_once():
            try:
                status, reply = carol.api("POST", f"/v2/networks/{w.net}/sync", {})
                error = reply.get("error") if isinstance(reply, dict) else reply
                sync_result[:] = [f"sync status={status} error={error}"]
            except Exception as error:  # noqa: BLE001 - include the repair result in a timeout
                sync_result[:] = [f"sync error={error}"]

        def sync_async():
            nonlocal syncing
            # Sync may spend its whole 30-second bound trying offline bob.
            if syncing is None or not syncing.is_alive():
                syncing = threading.Thread(target=sync_once, daemon=True)
                syncing.start()

        # First admission needs current authority (spec 4.2). Let carol learn
        # alice's renewals while the preceding grants are still live, before
        # moving past their deadlines; cold historical evidence stays inert.
        alice_renewed = members(w.a, w.net)[w.a.public_key]

        def learned_renewals():
            current = members(carol, w.net).get(w.a.public_key, {})
            if all(current.get(k) == alice_renewed[k] for k in
                   ("host_lease_id", "device_lease_id", "binding_lease_id")):
                return True
            sync_async()
            return False

        wait_for(learned_renewals, timeout=30, interval=1, message="carol to admit alice's renewed grants")
        w.clock.set(w.clock.offset + int((bob_end - w.now()).total_seconds()) + 60)
        check(w.a.api("GET", "/v2/networks")[1][0]["authority"]["state"] == "usable",
              "alice's host is not usable after bob's device grant ended")
        w.a.ok("allow", "everyone")  # a fresh policy, issued after the jump
        last = []

        def control():
            sent = carol.cli("message", "send", "--peer", w.a.id, "--agent", ada.id, "--content", "control")
            state = sent.json.get("state") if isinstance(sent.json, dict) else None
            error = sent.stderr.strip().splitlines()[-1] if sent.stderr.strip() else ""
            last[:] = [f"send exit={sent.code} state={state} error={error}"]
            if sent.ok and state == "accepted":
                return True
            # Keep checking acceptance while it learns from online alice.
            sync_async()
            return False
        try:
            wait_for(control, timeout=30, interval=1, message="carol's control message to alice to be accepted")
        except Failure as error:
            raise Failure(f"{error}; {'; '.join(last + sync_result)}; "
                          f"sync running={syncing is not None and syncing.is_alive()}") from error
        w.b.start()
        view = w.b.api("GET", "/v2/networks")[1][0]
        check(view["authority"]["state"] == "authority_expired", f"after bob's device grant ended: {view['authority']}")
        w.b.api("POST", f"/v2/networks/{w.net}/sync", {})
        sent = w.b.cli("message", "send", "--peer", w.a.id, "--agent", ada.id, "--content", "after expiry")
        check(not sent.ok or sent.json["state"] != "accepted", "a host with expired grants had a message accepted")
    w.step("expiry_stops_access", expiry)


@suite.case("setup_and_lifetimes", "spec 4.4, 6, 8; appendix 4.3, 5")
def _():
    for tag in ("policy", "root", "device", "expiry"):
        worlds[tag] = World(tag)
    in_parallel([lambda w=w: w.step("setup", w.setup) for w in worlds.values()])
    for w in worlds.values():
        if "setup" in w.errors:
            raise w.errors["setup"]
    w = worlds["root"]
    for member in members(w.a, w.net).values():
        check(6 * DAY < w.left(member["not_after"]) <= 7 * DAY, f"{member['member']} lasts {w.left(member['not_after'])}s")
    for kind, _, payload in statements(w.a, w.net):
        if kind.endswith("_lease") or kind in ("policy", "group"):
            life = (parse_time(payload["not_after"]) - parse_time(payload["issued_at"])).total_seconds()
            limit = DAY if kind in ("policy", "group") else 7 * DAY
            check(0 < life <= limit, f"a {kind} lasts {life:.0f}s, over {limit}s")
    # The timed steps of the three networks run now, side by side.
    in_parallel([lambda: policy_world(worlds["policy"]), lambda: root_world(worlds["root"]),
                 lambda: device_world(worlds["device"]), lambda: expiry_world(worlds["expiry"])])


CASES = [
    ("policy", "policy_renewed_at_8_hours", "spec 7.1 thresholds (DEC-Q24); 20 item 18",
     None),
    ("root", "root_renews_root_signed_grants_4_days_early", "spec 7.1, 7.3 (DEC-Q12); 20 item 18",
     None),
    ("root", "renewal_keeps_children", "spec 7.2 retention (DEC-S10); 20 item 23",
     None),
    ("device", "binding_renewed_by_device_issuer_only", "spec 7.1 (DEC-Q10, DEC-Q28); 20 item 21",
     None),
    ("device", "sole_device_warns_signer_unavailable", "spec 7.1 warnings, DEC-Q8; 20 item 24",
     None),
    ("device", "creator_device_renews_itself", "spec 6, 7.1 (DEC-Q21, DEC-Q27, DEC-Q30); 20 item 17",
     None),
    ("root", "root_offline_countdown", "spec 7.3 (DEC-Q12); 20 item 25",
     None),
    ("expiry", "expiry_stops_access", "spec 4.4, 5 (accepted work), 7.1, 16",
     None),
]
for _world, _name, _spec, _known in CASES:
    suite.case(_name, _spec, known=_known)(lambda world=_world, name=_name: outcome(world, name))

suite.finish()
