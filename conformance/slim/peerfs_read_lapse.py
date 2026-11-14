#!/usr/bin/env python3
"""PF-2: two networks listed separately, lapsed membership with and without allow_disconnected, expiry and renewal.

Written independently from docs/peerfs-read-contract.md section 8 (Discovery's two networks, Authority's lapsed
member, Policy's renewal); fixtures in peerfs_read_common.py. bob joins two of alice's networks; his grants in the
first end after 4 days and 1 hour, and the debug test clock then jumps past that end in one step, so alice's root
never sees them both current and due for renewal (spec 7.1, as in runtime_renewal).
"""
import os

from harness import Suite, check, members, rfc3339, wait_for
import peerfs_read_common as common
from peerfs_read_common import (binding, branches, cite, fetched, fs_rules, head, need, refused, rule, share, signed,
                                simple_graph, sp, state, version)

os.umask(0o077)
suite = Suite("peerfs_read_lapse", __doc__)
clock = suite.use_clock()
common.bind(suite, clock)
DAY, HOUR = 86400, 3600


def entry(space, net):
    return {"host": state["a"].id, "space": space, "branch": "main", "policy": cite(net)}


@suite.case("setup", "decentralized-spec 6, 8 (join --not-after); PF-1 sections 3-4")
def _():
    common.start_hosts({"net1": ("files", True), "net2": ("files-two", True)}, lapsing="net1")
    state["spaces"] = {"one": binding(state["net1"], simple_graph("one")),
                       "net2": binding(state["net2"], simple_graph("net2"))}


@suite.case("two_networks", "read 5 Discovery: a reader sharing two networks with S asks once for each")
def _():
    need("spaces")
    for name, net in (("one", state["net1"]), ("net2", state["net2"])):
        result = share(sp(name), "main", state["bob_p"], net=net)
        check(result.ok, f"fs share in {net['id'][:12]}: exit {result.code} {result.stderr.strip()[-200:]}")
    for name, net in (("one", state["net1"]), ("net2", state["net2"])):
        status, value = branches(net["id"])
        check(status == 200 and value == {"network": net["id"], "branches": [entry(sp(name), net)]},
              f"listing of {net['id'][:12]}: {status} {value}")
    state["shared"] = True


@suite.case("lapsed_membership", "read 3 step 2: lapsed member refused, admitted with allow_disconnected; policy "
                                 "expiry; test clock")
def _():
    need("shared")
    a, b, one = state["a"], state["b"], sp("one")
    g = state["spaces"]["one"]["graph"]
    citation = cite()
    check(head(one, "main")[0] == 200, "control: bob reads before the lapse")
    b.stop()
    clock.set(4 * DAY + 2 * HOUR)
    b.start()
    lapsed = members(a, state["net1"]["id"]).get(b.public_key)
    check(lapsed is None or lapsed["not_after"] <= rfc3339(a.now()), f"fixture: bob is still a member: {lapsed}")
    refused(*head(one, "main", policy=citation), 404, "a citation of an expired policy")
    # The expired policy has no current statement to edit: a fresh one through the CLI first.
    result = share(one, "main", "network")
    check(result.ok, f"fs share after the policy expired: exit {result.code} {result.stderr.strip()[-300:]}")
    signed([rule(one, "main", [state["bob_p"]])])
    refused(*head(one, "main"), 404, "a lapsed member without allow_disconnected")
    status, value = branches(state["net1"]["id"])
    check(status == 200 and value["branches"] == [], f"a lapsed member's listing: {status} {value}")
    signed([rule(one, "main", [state["bob_p"]], allow_disconnected=True)])
    status, value = head(one, "main")
    check(status == 200 and value["head"] == g.branches["main"],
          f"a lapsed member with allow_disconnected: {status} {value}")
    fetched(one, "main", [g.branches["main"]], "a lapsed member with allow_disconnected")
    status, value = branches(state["net1"]["id"])
    check(status == 200 and value["branches"] == [entry(one, state["net1"])],
          f"listing with allow_disconnected: {status} {value}")
    state["lapsed_version"] = version()


@suite.case("renewal_keeps_rules", "read 2 Renewal: automatic renewal copies fs_rules unchanged; test clock")
def _():
    v, = need("lapsed_version")
    before = fs_rules()
    clock.set(clock.offset + 16 * HOUR + 10 * 60)  # 6 h 50 min left on the 23-hour policy (threshold 8 h)
    wait_for(lambda: version() > v, timeout=75, interval=1, message="alice's host to renew its policy")
    check(fs_rules() == before, f"fs_rules after renewal {fs_rules()}, want {before}")
    status, value = head(sp("one"), "main")
    check(status == 200, f"head citing the renewed policy: HTTP {status} {value}")


suite.finish()
