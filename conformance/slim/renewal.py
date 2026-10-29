#!/usr/bin/env python3
"""Slim suite 2, renewal: grant lifetimes, automatic renewal, retention, warnings and expiry.

Independent networks run side by side, each with its own debug test clock, so each renewal window gets
the full time the spec allows (hosts check every 60 seconds, spec 7.1). Alice creates each network and bob
joins; separate networks exercise a delegated admin, an original person key and an external SSH root. Written from
docs/decentralized-spec.md sections 4.4, 5, 7 and 16, and the wire appendix sections 4 and 5.
"""
import base64
import hashlib
import json
import subprocess
import threading
import traceback

from harness import (Clock, Failure, Suite, attention, check, create_network, join_new_person, link_machine, members,
                     parse_time, rfc3339, ssh_key, ssh_public_base64, statements, timedelta, wait_for)

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


def statement_id(envelope):
    """The public statement ID formula (appendix 3.2), independent of its proof/signature."""
    digest = hashlib.sha256(base64.b64decode(envelope["payload_base64"])).hexdigest()
    message = "\n".join(("peerspan-decentralized-statement-v1", envelope["kind"], envelope["context_id"], digest))
    return "ds_" + hashlib.sha256(message.encode()).hexdigest()


def original_provider(host, net, person):
    status, body = host.api("POST", f"/v2/networks/{net}/provider", {
        "provider_id": person, "person_public_key": person, "host_public_key": host.public_key, "approve": True})
    check(status == 200 and body["provider"]["kind"] == "original_person",
          f"{host.name}: selecting the original key: {status} {body}")


def agent_key(host, key):
    """Expose only this fixture's identity through an isolated OpenSSH agent inherited by the daemon."""
    sock = host.root / "ssh-agent.sock"
    log = (host.root / "ssh-agent.log").open("ab")
    suite.spawn(["ssh-agent", "-D", "-a", str(sock)], stdout=log, stderr=log)
    log.close()
    wait_for(sock.exists, timeout=5, message=f"{host.name} ssh-agent")
    host.extra_env["SSH_AUTH_SOCK"] = str(sock)
    added = subprocess.run(["ssh-add", str(key)], env=host.env, capture_output=True, timeout=10)
    check(added.returncode == 0, f"{host.name}: ssh-add: {added.stderr.decode()}")
    host.restart()


def root_renew(host, net, kind, **subject):
    """Give the admin fixture later parents using the public typed action, keeping its live children (7.2)."""
    records = [(statement_id(e), p) for _, e, p in statements(host, net)
               if "not_after" in p and parse_time(p["not_after"]) > host.now()]
    candidates = [(statement_id(e), p) for _, e, p in statements(host, net, kind)
                  if all(p["subject"].get(k) == v for k, v in subject.items())]
    old_id, old = max(candidates, key=lambda record: record[1]["sequence"])
    kept = {old_id}
    while True:
        more = {sid for sid, p in records if any(parent["id"] in kept for parent in p.get("parents", []))}
        if more <= kept:
            break
        kept.update(more)
    now = host.now().replace(microsecond=0)
    payload = dict(old, operation_id="-", sequence=old["sequence"] + 1, predecessors=[old_id], resolves=[],
                   retained_statement_ids=sorted(kept), issuer={"kind": "root", "person_public_key": "-"}, parents=[],
                   issued_at=rfc3339(now), not_before=rfc3339(now), not_after=rfc3339(now + timedelta(days=7)))
    status, body = host.api("POST", f"/v2/networks/{net}/actions", {
        "kind": kind, "provider_id": "network_root", "signature_format": "ed25519",
        "payload_base64": base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode(),
        "approve": True})
    check(status == 200 and body.get("committed"),
          f"preparing {kind} parent: status={status}, committed={body.get('committed')}, "
          f"pending roles={[r['role'] for r in body.get('signing_requests', [])]}, error={body.get('error')}")


class DelegatedWorld(World):
    def setup(self):
        super().setup()
        self.clock.set(DAY)
        person = self.a.api("GET", f"/v2/networks/{self.net}")[1]["person_public_key"]
        for kind, subject in (("admin_lease", {"person_public_key": person}),
                              ("person_lease", {"person_public_key": person}),
                              ("host_lease", {"host_public_key": self.a.public_key})):
            root_renew(self.a, self.net, kind, **subject)
        # The original owner path lets the new device use these later parent deadlines.
        original_provider(self.a, self.net, person)
        self.admin = suite.host("delegated-admin", clock=self.clock)
        link_machine(self.a, self.admin, self.net, person, key=self.a.home / ".config/peerspan/person_ed25519")
        status, body = self.admin.api("POST", f"/v2/networks/{self.net}/sync", {})
        check(status == 200 and self.b.public_key in members(self.admin, self.net),
              f"the delegated admin did not learn bob before the root stopped: {status} {body}")
        self.admin_provider = self.admin.api("GET", f"/v2/networks/{self.net}/provider")[1]
        check(self.admin_provider["kind"] == "device" and self.admin_provider["scopes"] == 15,
              f"delegated admin provider {self.admin_provider}")
        self.target, self.target_person, self.target_member = self.b, self.bob_person, "bob"
        self.initial_person = self.newest("person_lease", person_public_key=self.bob_person)["sequence"]
        self.initial_deadlines = {"person_lease": self.newest("person_lease", person_public_key=self.target_person)["not_after"],
                                  "host_lease": self.newest("host_lease", host_public_key=self.target.public_key)["not_after"]}
        # Root seeds are never transferred by linking (spec 3, 8). Neither root nor target participates below.
        self.a.stop()
        self.b.stop()


class OriginalAdminWorld(World):
    def setup(self):
        super().setup()
        self.clock.set(DAY)
        root_renew(self.a, self.net, "person_lease", person_public_key=self.bob_person)
        self.a.ok("network", "delegate-admin", "--network", self.net, "--person", "bob",
                  "--signer", "network_root", "--approve")
        agent_key(self.b, self.bob_key)
        original_provider(self.b, self.net, self.bob_person)
        self.bob_key.unlink()
        status, body = self.b.api("POST", f"/v2/networks/{self.net}/sync", {})
        check(status == 200, f"the original-key admin could not learn its delegation: {status} {body}")
        self.admin = self.b
        self.admin_provider = self.admin.api("GET", f"/v2/networks/{self.net}/provider")[1]
        self.target, self.target_member = self.a, "alice"
        self.target_person = self.a.api("GET", f"/v2/networks/{self.net}")[1]["person_public_key"]
        self.initial_person = self.newest("person_lease", person_public_key=self.target_person)["sequence"]
        self.initial_deadlines = {"person_lease": self.newest("person_lease", person_public_key=self.target_person)["not_after"],
                                  "host_lease": self.newest("host_lease", host_public_key=self.target.public_key)["not_after"]}
        self.a.stop()


class OriginalWorld(World):
    def setup(self):
        net = create_network(self.a, "renewal-original", "alice")
        self.net = net["id"]
        key = ssh_key(self.b.root, "bob")
        agent_key(self.b, key)
        # A scope-1 device cannot renew a binding or any device grant; the original key must do both.
        join_new_person(self.a, self.b, "bob", key, self.net, scopes=1,
                        not_after=rfc3339(self.now() + timedelta(days=2)))
        self.bob_person = ssh_public_base64(key)
        self.b.ok("allow", "alice", "--person-key", key)
        self.start = {k: dict(v) for k, v in members(self.a, self.net).items()}
        self.initial_policy = self.policy_version()
        self.initial_deadlines = {}
        for kind in ("binding_lease", "device_lease", "policy"):
            rows = [p for _, _, p in statements(self.b, self.net, kind)
                    if p["issuer"]["person_public_key"] == self.bob_person]
            self.initial_deadlines[kind] = max(rows, key=lambda p: p["sequence"])["not_after"]
        original_provider(self.b, self.net, self.bob_person)
        key.unlink()  # the daemon has only SSH_AUTH_SOCK, not a configured or default private-key file
        check(not (self.b.home / ".config/peerspan/person_ed25519").exists(),
              "the original-key fixture accidentally has a default private-key file")


class ExternalRootWorld(World):
    def setup(self):
        super().setup()
        key = ssh_key(self.a.root, "external-root")
        self.root_key = ssh_public_base64(key)
        agent_key(self.a, key)
        self.a.ok("network", "rotate-root", self.net, "--to-ssh", "--root-key", key,
                  input="yes\n", tty=True, timeout=90)
        key.unlink()  # rotation retired the raw seed; the external key remains usable only through the agent
        view = self.a.api("GET", f"/v2/networks/{self.net}")[1]
        check(view["root_public_key"] == self.root_key and view["root_epoch"] == 1,
              "the root did not move to the external SSH identity")
        self.initial = {kind: self.newest(kind)["sequence"]
                        for kind in ("admin_lease", "person_lease", "host_lease")}


def delegated_world(w):
    def renews():
        w.clock.set(5 * DAY + 17 * HOUR)
        w.admin.ok("network", "group", "set", "--network", w.net, "--group", "operators", "--person", w.target_member, "--approve")
        initial = w.admin.api("GET", f"/v2/networks/{w.net}/access-versions")[1]["groups"][0]["version"]
        initial_group = max([p for _, _, p in statements(w.admin, w.net, "group")], key=lambda p: p["sequence"])
        w.initial_deadlines["group"] = initial_group["not_after"]
        w.clock.set(6 * DAY + 8 * HOUR + 30 * 60)  # 8.5 hours left on the group
        check(w.admin.api("GET", f"/v2/networks/{w.net}/access-versions")[1]["groups"][0]["version"] == initial,
              "the delegated admin renewed a group before 8 hours remained")
        # Clear the delegated device's ranked turn even though the original-key/root host is offline (DEC-Q11).
        w.clock.set(6 * DAY + 16 * HOUR + 10 * 60)  # group: 50 min left; bob's person and host: 7 h 50 min

        def done():
            people = [p for _, _, p in statements(w.admin, w.net, "person_lease")
                      if p["subject"]["person_public_key"] == w.target_person]
            groups = w.admin.api("GET", f"/v2/networks/{w.net}/access-versions")[1]["groups"]
            hosts = members(w.admin, w.net)
            return (max([p["sequence"] for p in people] or [0]) > w.initial_person
                    and hosts.get(w.target.public_key, {}).get("host_lease_id", "-") not in ("-", w.start[w.target.public_key]["host_lease_id"])
                    and any(g["name"] == "operators" and g["version"] > initial for g in groups))
        wait_for(done, timeout=WINDOW, interval=1, message="the delegated admin to renew the offline target and group without the root")
        for kind, subject in (("person_lease", {"person_public_key": w.target_person}),
                              ("host_lease", {"host_public_key": w.target.public_key}), ("group", {})):
            rows = [(e, p) for _, e, p in statements(w.admin, w.net, kind)
                    if all(p.get("subject", {}).get(k) == v for k, v in subject.items())]
            envelope, payload = max(rows, key=lambda row: row[1]["sequence"])
            check(payload["sequence"] >= 2 and payload["operation_id"] == "-", f"{kind} did not renew outside a link")
            original = w.admin_provider["kind"] == "original_person"
            signer = w.admin_provider["person_public_key"] if original else w.admin_provider["device_public_key"]
            check(payload["issuer"]["kind"] == ("person" if original else "device")
                  and payload["issuer"]["person_public_key"] == w.admin_provider["person_public_key"],
                  f"{kind} was not renewed through the delegated admin's selected path")
            check([(s["role"], s["public_key"], s["format"]) for s in envelope["signatures"]]
                  == [("issuer", signer, "sshsig" if original else "ed25519")],
                  f"{kind} renewal required a signer other than the delegated admin")
            parents = {"issuer_person", "issuer_admin"} | (set() if original else {"issuer_device"})
            check({p["role"] for p in payload["parents"]} == parents,
                  f"{kind} did not pin its administrator authority")
            check(parse_time(payload["not_after"]) > parse_time(w.initial_deadlines[kind]),
                  f"{kind} got a new generation without extending its deadline")
            records = {statement_id(e): p for _, e, p in statements(w.admin, w.net) if "not_after" in p}
            check(all(parse_time(payload["not_after"]) <= parse_time(records[p["id"]]["not_after"])
                      for p in payload["parents"]), f"{kind} renewal exceeded an administrator parent")
            if kind == "group":
                before = json.loads(base64.b64decode(initial_group["body_base64"]))
                after = json.loads(base64.b64decode(payload["body_base64"]))
                check(after["members"] == before["members"], "group renewal changed its membership")
    name = "original_admin_renews_person_host_and_group_without_root" if w.tag == "original-admin" else "delegated_admin_renews_person_host_and_group_without_root"
    w.step(name, renews)


def original_world(w):
    def renews():
        w.clock.set(16 * HOUR + 10 * 60)
        before = w.start[w.b.public_key]
        wait_for(lambda: (lambda m: m.get("binding_lease_id", "-") not in ("-", before["binding_lease_id"])
                         and m.get("device_lease_id", "-") not in ("-", before["device_lease_id"]))(members(w.b, w.net).get(w.b.public_key, {}))
                 and w.policy_version() > w.initial_policy, timeout=WINDOW, interval=1,
                 message="bob's agent-only original key to renew his binding, device and policy automatically")
        for kind in ("binding_lease", "device_lease", "policy"):
            rows = [(e, p) for _, e, p in statements(w.b, w.net, kind)
                    if p["issuer"]["person_public_key"] == w.bob_person]
            envelope, payload = max(rows, key=lambda row: row[1]["sequence"])
            check(payload["sequence"] >= 2 and payload["issuer"]["kind"] == "person" and payload["operation_id"] == "-",
                  f"{kind} was not automatically renewed with the original key")
            check([(s["role"], s["public_key"], s["format"]) for s in envelope["signatures"]]
                  == [("issuer", w.bob_person, "sshsig")], f"{kind} renewal is not issuer-only SSHSIG")
            check(parse_time(payload["not_after"]) > parse_time(w.initial_deadlines[kind]),
                  f"{kind} got a new generation without extending its deadline")
        check(w.b.api("GET", f"/v2/networks/{w.net}")[1]["authority"]["state"] == "usable",
              "bob lost usable authority after the original-key renewals")
        check("person_device_signer_unavailable" not in {k for k, _ in attention(w.b)[0]},
              "an available original signer still raises person_device_signer_unavailable")
    w.step("original_key_agent_renews_binding_device_and_policy", renews)


def external_root_world(w):
    def renews():
        w.clock.set(3 * DAY + HOUR)
        kinds = ("admin_lease", "person_lease", "host_lease")
        wait_for(lambda: all((lambda p: p and p["sequence"] > w.initial[kind]
                             and w.left(p["not_after"]) > 6 * DAY)(w.newest(kind)) for kind in kinds),
                 timeout=WINDOW, interval=1, message="the daemon's SSH-agent root to renew its root-signed grants")
        for kind in kinds:
            renewed = w.newest(kind)
            envelope = next(e for _, e, p in statements(w.a, w.net, kind) if p == renewed)
            check(renewed["issuer"]["kind"] == "root" and renewed["operation_id"] == "-",
                  f"{kind} renewal did not use the external root")
            check([(s["role"], s["public_key"], s["format"]) for s in envelope["signatures"]]
                  == [("issuer", w.root_key, "sshsig")], f"{kind} renewal did not use issuer-only SSHSIG root proof")
        check("network_root_unreachable" not in {k for k, _ in attention(w.a)[0]}, "the usable external root is reported unreachable")
    w.step("external_root_agent_renews_root_signed_grants", renews)


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
    worlds["delegated"] = DelegatedWorld("delegated")
    worlds["original-admin"] = OriginalAdminWorld("original-admin")
    worlds["original"] = OriginalWorld("original")
    worlds["external"] = ExternalRootWorld("external")
    in_parallel([lambda w=w: w.step("setup", w.setup) for w in worlds.values()])
    w = worlds["root"]
    for member in members(w.a, w.net).values():
        check(6 * DAY < w.left(member["not_after"]) <= 7 * DAY, f"{member['member']} lasts {w.left(member['not_after'])}s")
    for kind, _, payload in statements(w.a, w.net):
        if kind.endswith("_lease") or kind in ("policy", "group"):
            life = (parse_time(payload["not_after"]) - parse_time(payload["issued_at"])).total_seconds()
            limit = DAY if kind in ("policy", "group") else 7 * DAY
            check(0 < life <= limit, f"a {kind} lasts {life:.0f}s, over {limit}s")
    # Every independent timed window gets its full bound; one fixture failure does not suppress the others.
    work = (("policy", policy_world), ("root", root_world), ("device", device_world), ("expiry", expiry_world),
            ("delegated", delegated_world), ("original-admin", delegated_world),
            ("original", original_world), ("external", external_root_world))
    in_parallel([lambda w=worlds[tag], f=function: f(w) for tag, function in work if "setup" not in worlds[tag].errors])
    for w in worlds.values():
        if "setup" in w.errors:
            raise w.errors["setup"]


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
    ("delegated", "delegated_admin_renews_person_host_and_group_without_root", "spec 7.1, 7.2; 20 items 18, 21, 22",
     None),
    ("original-admin", "original_admin_renews_person_host_and_group_without_root", "spec 7.1, 7.2; 20 items 18, 21, 22",
     None),
    ("original", "original_key_agent_renews_binding_device_and_policy", "spec 7.1; 20 items 18, 21, 27",
     None),
    ("external", "external_root_agent_renews_root_signed_grants", "spec 7.3; 20 item 25",
     None),
]
for _world, _name, _spec, _known in CASES:
    suite.case(_name, _spec, known=_known)(lambda world=_world, name=_name: outcome(world, name))

suite.finish()
