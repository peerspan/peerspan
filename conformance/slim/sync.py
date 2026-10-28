#!/usr/bin/env python3
"""Slim suite 4, sync: propagation between three hosts, catching up after being offline, high-water marks,
bans that a stale peer cannot erase, and the repair route.

alice creates a network, bob and carol join. Written from docs/decentralized-spec.md sections 4.2, 5.1 and
10, and the wire appendix sections 15 and 16.7.
"""
import os
import subprocess

from harness import Suite, check, create_network, join_new_person, members, ssh_key, wait_for

suite = Suite("sync", __doc__)
a, b, c = suite.host("alice"), suite.host("bob"), suite.host("carol")
state = {}


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


def probe(state_dir, host, path, alpn):
    args = [str(suite.probe_bin), "--address", host.peer_address, "--alpn", alpn, "--path", path]
    args += ["--state", str(state_dir)] if state_dir else ["--seed-hex", os.urandom(32).hex()]
    p = subprocess.run(args, capture_output=True, timeout=30)
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


@suite.case("offline_host_catches_up", "spec 10: a host that was offline learns what it missed")
def _():
    bob, version = need("bob", "bob_version")
    c.stop()
    out = b.ok("allow", "everyone", "--person-key", state["bob_key"])
    check(out["policy"]["version"] == version + 1, f"version {out['policy']['version']}")
    learns(a, bob, version + 1)
    b.stop()  # carol must learn it from alice, not from its author
    c.start()
    check(policy_version(c, bob) == version, "carol changed while offline")
    sync(a)  # alice talks to stale carol first (high-water, below)
    state["alice_after_stale"] = policy_version(a, bob)
    learns(c, bob, version + 1)
    body = sync(c)
    check([u["host_public_key"] for u in body["unavailable"]] == [b.public_key],
          f"with bob stopped, carol's sync reports unavailable {body['unavailable']}")
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


@suite.case("ban_survives_stale_catalog", "spec 5.1, 10 merging; 20 item 47")
def _():
    c.stop()  # carol does not hear of the ban directly
    a.ok("network", "revoke", "--network", state["net"], "--host", b.id, "--approve")
    check(b.public_key not in members(a, state["net"]), "alice still lists the revoked host")
    c.start()
    wait_for(lambda: b.public_key not in members(c, state["net"]) or (sync(c) and False), timeout=30, interval=1,
             message="carol to learn bob's revocation")
    sync(b)  # bob, still holding the old catalog, pushes it around
    sync(c)
    check(b.public_key not in members(c, state["net"]), "a stale catalog brought the revoked host back")
    check(b.public_key not in members(a, state["net"]), "a stale catalog brought the revoked host back on alice")


suite.finish()
