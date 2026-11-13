#!/usr/bin/env python3
"""Slim suite 4, sync: propagation between three hosts, catching up after being offline, high-water marks,
bans that a stale peer cannot erase, and the repair route.

alice creates a network, bob and carol join. Each host advertises one QUIC address, an opaque counted UDP
carrier that forwards the bytes unchanged to its real peer listener (`counted_peer.CountedUDP`), so the suite
can count what reaches each host. Written from docs/decentralized-spec.md sections 4.2, 5.1 and 10 (with SYNC-1:
an explicit sync restarts that network's background interval) and its section 20 items 47, 48 and 48a, the
wire appendix sections 15 and 16.7, and docs/launch-contract.md (DIR-1: an on-demand directory refresh counts
for earlier changes).
"""
import json
import os
import sqlite3
import subprocess
import time
from contextlib import closing

from counted_peer import CountedUDP, refresh_owed_directories, sync_networks
from harness import Suite, check, create_network, join_new_person, members, ssh_key, wait_for

suite = Suite("sync", __doc__)
a, b, c = suite.host("alice", start=False), suite.host("bob", start=False), suite.host("carol", start=False)
for _h in (a, b, c):
    _h.counted = CountedUDP(("127.0.0.1", _h.peer_port))
    _path = _h.root / "transport.json"
    _path.write_text(json.dumps({"format": 1, "advertise_bootstrap": [f"127.0.0.1:{_h.bootstrap_port}"],
                                 "advertise_quic": [_h.counted.address], "rendezvous": [], "relays": [],
                                 "publish_contacts": False}))
    _path.chmod(0o600)
    _h.extra_args = ["--transport-config", str(_path)]
    _h.start()
state = {}
QUIET_AFTER_SYNC = 50.0  # spec 20 item 48a: no background sync for at least 50 s after an explicit one
RESUMES_WITHIN = 30.0  # item 48a: without another explicit sync, background sync resumes within 30 s more


def need(*names):
    missing = [n for n in names if n not in state]
    check(not missing, f"an earlier case did not finish ({', '.join(missing)} missing)")
    return [state[n] for n in names]


def sync(host):
    status, body = host.api("POST", f"/v2/networks/{state['net']}/sync", {}, timeout=60)
    check(status == 200, f"{host.name}: sync: {status} {body}")
    return body


def policy_version(host, person):
    status, body = host.api("GET", f"/v2/networks/{state['net']}/access-versions")
    check(status == 200, f"{host.name}: access-versions: {status} {body}")
    return max([p["version"] for p in body["policies"] if p["person_public_key"] == person] or [0])


def learns(host, person, version, timeout=30):
    """HOST reaches PERSON's policy VERSION, syncing on each try (spec 10: sync and background sync)."""
    def done():
        if policy_version(host, person) >= version:
            return True
        sync(host)
        return policy_version(host, person) >= version
    wait_for(done, timeout=timeout, interval=1, message=f"{host.name} to learn policy version {version}")


def probe(state_dir, host, path, alpn, method="GET", body=None):
    args = [str(suite.probe_bin), "--address", host.peer_address, "--alpn", alpn, "--path", path, "--method", method]
    args += ["--state", str(state_dir)] if state_dir else ["--seed-hex", os.urandom(32).hex()]
    if body is not None:
        args.append("--body-stdin")
    p = subprocess.run(args, input=(body or "").encode(), capture_output=True, timeout=30)
    return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")


@suite.case("setup_three_hosts", "spec 6, 8")
def _():
    net = create_network(a, "sync", "alice")
    state["net"] = net["id"]
    state["alice"] = net["person_public_key"]
    for host, name in ((b, "bob"), (c, "carol")):
        state[f"{name}_key"] = ssh_key(host.root, name)
        join_new_person(a, host, name, state[f"{name}_key"], net["id"])
        state[name] = host.api("GET", "/v2/networks")[1][0]["person_public_key"]
    for host in (b, c):
        wait_for(lambda host=host: len(members(host, net["id"])) == 3 or sync(host) and False, timeout=30,
                 interval=1, message=f"{host.name} to list all three members")


@suite.case("sync_route_shape", "spec 10 (network sync); appendix 16.7")
def _():
    body = sync(c)
    check(set(body) == {"network", "attempted", "learned_proof_ids", "unavailable"}, f"sync response keys {sorted(body)}")
    check(body["network"]["id"] == state["net"], "sync returned another network")
    check(body["unavailable"] == [], f"all peers are up, yet unavailable: {body['unavailable']}")


@suite.case("policy_propagates_to_all_hosts", "spec 10 merging and timing")
def _():
    (bob,) = need("bob")
    out = b.ok("allow", "alice", "--person-key", state["bob_key"])
    version = out["policy"]["version"]
    for host in (a, c):
        learns(host, bob, version)
    state["bob_version"] = version


def outbox_empty(host):
    """No delivery owed to a peer (storage contract: dec_outbox), read-only."""
    for path in host.state.glob("*.db"):
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=30)) as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='dec_outbox'").fetchone():
                return db.execute("SELECT count(*) FROM dec_outbox").fetchone()[0] == 0
    check(False, f"{host.name}: no host database with dec_outbox")


def carriers():
    return tuple(h.counted.counts() for h in (a, b, c))


@suite.case("explicit_sync_restarts_background_interval", "spec 10 timing (SYNC-1); 20 item 48a")
def _():
    need("bob_version")  # after the policy change above; before any host is stopped, so nothing is left to retry
    hosts, net = (a, b, c), state["net"]
    for host in hosts:
        wait_for(lambda host=host: outbox_empty(host), timeout=30, interval=0.25,
                 message=f"{host.name}'s deliveries to peers to drain")
    # Every host syncs explicitly, so none has a background sync of this network due for 60 s; then one
    # directory refresh each, which counts for every earlier change (DIR-1), so nothing else is owed.
    began = time.monotonic()
    sync_networks(hosts, (net,))
    refresh_owed_directories(hosts, (net,))
    # Only the trailing datagrams of those exchanges (their last ACKs) may still arrive.
    previous, since = carriers(), time.monotonic()
    while time.monotonic() - since < 0.3:
        check(time.monotonic() - began < 40, "the carriers did not settle after the explicit syncs and refreshes")
        time.sleep(0.05)
        if carriers() != previous:
            previous, since = carriers(), time.monotonic()
    settled = time.monotonic() - began
    while time.monotonic() - began < QUIET_AFTER_SYNC:
        time.sleep(0.25)
        now = carriers()
        check(now == previous, f"UDP reached a host {time.monotonic() - began:.1f}s after the explicit syncs, "
              f"within the {QUIET_AFTER_SYNC:.0f}s with no background sync (SYNC-1); carriers (alice, bob, carol: "
              f"in datagrams, in bytes, back datagrams, back bytes) {previous} -> {now}")
    print(f"  no datagram from {settled:.1f}s to {QUIET_AFTER_SYNC:.0f}s after the explicit syncs", flush=True)
    while carriers() == previous:
        check(time.monotonic() - began < QUIET_AFTER_SYNC + RESUMES_WITHIN,
              f"no background sync within {QUIET_AFTER_SYNC + RESUMES_WITHIN:.0f}s of the explicit syncs (item 48a)")
        time.sleep(0.25)
    print(f"  background traffic resumed {time.monotonic() - began:.1f}s after the explicit syncs", flush=True)


@suite.case("offline_host_catches_up", "spec 10: a host that was offline learns what it missed")
def _():
    bob, version = need("bob", "bob_version")
    c.stop()
    out = b.ok("allow", "everyone", "--person-key", state["bob_key"])
    check(out["policy"]["version"] == version + 1, f"version {out['policy']['version']}")
    learns(a, bob, version + 1)
    b.stop()  # carol must learn it from alice, not from its author
    try:
        c.start()  # carol comes back with the older version (it may pull the newer one at once)
        sync(a)  # alice talks to carol, which held the older version (high-water, below)
        state["alice_after_stale"] = policy_version(a, bob)
        learns(c, bob, version + 1)
        body = sync(c)
        check([u["host_public_key"] for u in body["unavailable"]] == [b.public_key],
              f"with bob stopped, carol's sync reports unavailable {body['unavailable']}")
    finally:
        b.start()
    state["bob_version"] = version + 1


@suite.case("stale_peer_cannot_lower_high_water", "spec 4.2 high-water, 10 merging; 20 item 47")
def _():
    bob, version, seen = need("bob", "bob_version", "alice_after_stale")
    check(seen == version, f"after syncing with a peer that still had version {version - 1}, alice has {seen}")
    heads = [p for p in a.api("GET", f"/v2/networks/{state['net']}/access-versions")[1]["policies"]
             if p["person_public_key"] == bob]
    check(len(heads) == 1 and len(heads[0]["head_ids"]) == 1, f"bob's policy stream has heads {heads}")


@suite.case("repair_route_for_known_hosts_only", "spec 10 repair, 3; appendix 15; 20 item 48")
def _():
    path = f"/repair/v1/networks/{state['net']}/catalog"
    code, out, err = probe(c.state, a, path, "peerspan-state-repair/1")
    check(code == 0 and '"objects"' in out, f"a member fetching on the repair ALPN: exit {code} {err.strip()[-200:]}")
    code, out, err = probe(None, a, path, "peerspan-state-repair/1")
    check('"objects"' not in out, "an unknown key read the catalog on the repair ALPN")
    code, out, err = probe(None, a, f"/peer/v2/networks/{state['net']}/catalog", "peerspan-peer/1")
    check('"objects"' not in out, "an unknown key read the member catalog route")


@suite.case("ban_survives_stale_catalog", "spec 5.1, 10 merging; appendix 15; 20 item 47")
def _():
    net = state["net"]
    stale = c.api("GET", f"/v2/networks/{net}/catalog")[1]["catalog"]  # carol's catalog before the ban
    check(any(o["kind"] == "host_lease" for o in stale["objects"]), "carol's catalog holds no host grants")
    c.stop()  # carol does not hear of the ban directly
    a.ok("network", "revoke", "--network", net, "--host", b.id, "--approve")
    check(b.public_key not in members(a, net), "alice still lists the revoked host")
    c.start()
    wait_for(lambda: b.public_key not in members(c, net) or (sync(c) and False), timeout=30, interval=1,
             message="carol to learn bob's revocation")
    # Replay the pre-ban catalog through hosts that are still authorized, on the member catalog route: carol's key
    # posts it to alice, and alice's key posts it to carol. Each must merge it (200) and keep the ban.
    body = json.dumps({"catalog": stale})
    for sender, receiver in ((c, a), (a, c)):
        code, out, err = probe(sender.state, receiver, f"/peer/v2/networks/{net}/catalog", "peerspan-peer/1",
                               method="POST", body=body)
        check(code == 0 and '"objects"' in out,
              f"{receiver.name} refused {sender.name}'s replayed catalog: exit {code} {err.strip()[-200:]}")
        check(b.public_key not in members(receiver, net),
              f"{sender.name}'s pre-ban catalog brought the revoked host back on {receiver.name}")
    sync(c)
    sync(a)
    for host in (a, c):
        check(b.public_key not in members(host, net), f"after syncing, {host.name} lists the revoked host again")


suite.finish()
