#!/usr/bin/env python3
"""Slim suite 6, root: root rotation, rotation to an SSH root, and a root split.

alice creates the network (her host holds the root seed), bob joins before the rotation and carol after it.
A root split is made the only way an outsider can: a copy of alice's state, run while nobody can reach it,
signs a second successor of the same root state; bob is then handed both. Written from
docs/decentralized-spec.md sections 13 and 14.2, and the wire appendix sections 6, 16.2 and 16.5.
"""
import json
import os
import shutil
import sqlite3
import subprocess

from harness import (Suite, attention, check, create_network, join_new_person, join_request, members, ssh_key,
                     ssh_public_base64, statements, wait_for)

suite = Suite("root", __doc__)
a, b, c = suite.host("alice"), suite.host("bob"), suite.host("carol")
state = {}


def need(*names):
    missing = [n for n in names if n not in state]
    check(not missing, f"an earlier case did not finish ({', '.join(missing)} missing)")
    return [state[n] for n in names]


def view(host, net=None):
    status, body = host.api("GET", f"/v2/networks/{net or state['net']}")
    check(status == 200, f"{host.name}: network view: {status} {body}")
    return body


def sync(host, net=None):
    status, body = host.api("POST", f"/v2/networks/{net or state['net']}/sync", {}, timeout=60)
    check(status == 200, f"{host.name}: sync: {status} {body}")
    return body


def root_seed(host, net):
    """`networks.root_seed` (spec 3, 13.1), read from the host's state database."""
    for path in sorted(host.state.glob("*.db")) + sorted(host.state.glob("*.sqlite*")):
        if path.name.endswith(("-wal", "-shm")):
            continue
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
        try:
            columns = [r[1] for r in db.execute("PRAGMA table_info(networks)")]
            if "root_seed" not in columns:
                continue
            row = db.execute("SELECT root_seed FROM networks WHERE id = ?", (net,)).fetchone()
            return row[0] if row else None
        finally:
            db.close()
    raise AssertionError(f"{host.name}: no state database with networks.root_seed")


def rotate(host, net, *extra):
    for _ in range(3):  # a renewal or sync landing during the review asks for a fresh review (spec 11)
        result = host.cli("network", "rotate-root", net, *extra, input="yes\n", tty=True, timeout=90)
        if result.ok or "changed during review" not in result.stderr + result.stdout:
            break
    check(result.ok, f"{host.name}: rotate-root: exit {result.code}: {(result.stderr + result.stdout).strip()[-400:]}")
    return result.json


def wait_root(host, root_state_id, net=None):
    wait_for(lambda: view(host, net)["root_state_id"] == root_state_id or (sync(host, net) and False), timeout=40,
             interval=1, message=f"{host.name} to adopt root state {root_state_id[:12]}")


@suite.case("setup", "spec 6, 8")
def _():
    net = create_network(a, "root", "alice")
    state["net"] = net["id"]
    state["bob_key"] = ssh_key(b.root, "bob")
    join_new_person(a, b, "bob", state["bob_key"], net["id"])
    state["bert"] = b.agent("bert")
    b.ok("allow", "alice", "--person-key", state["bob_key"])
    check(net["root_epoch"] == 0, f"a new network's root epoch {net['root_epoch']}")


@suite.case("retention_view", "spec 13.1, 7.2; appendix 16.5")
def _():
    (net,) = need("net")
    status, body = a.api("GET", f"/v2/networks/{net}/root-retention")
    check(status == 200, f"root-retention: {status} {body}")
    check({"network_id", "context_id", "decision_time", "root_head_ids", "catalog", "candidates", "excluded"}
          <= set(body), f"root-retention fields {sorted(body)}")
    check(body["network_id"] == net and len(body["root_head_ids"]) == 1, f"root heads {body['root_head_ids']}")
    kinds = {x["kind"] for x in body["candidates"]}
    check(kinds, "no grant is keepable across a rotation")
    for x in body["excluded"]:
        check(x.get("code"), f"an excluded grant without a reason: {x}")
    state["candidates"] = {x["statement_id"] for x in body["candidates"]}


@suite.case("retain_flags_removed", "spec 13.1 (DEC-Q13); 20 item 54", known="DEC-Q13")
def _():
    (net,) = need("net")
    for flags in (["--retain", "ds_" + "0" * 64], ["--retain-none"]):
        result = a.cli("network", "rotate-root", net, *flags, input="n\n")
        check(not result.ok and ("unexpected argument" in result.stderr or "unknown" in result.stderr.lower()),
              f"rotate-root {flags[0]} was not refused as an unknown flag: exit {result.code}: "
              f"{result.stderr.strip()[-200:]}")


@suite.case("rotation_keeps_members_working", "spec 13.1; 20 item 54")
def _():
    net, candidates = need("net", "candidates")
    before = view(a)
    seed_before = root_seed(a, net)
    check(seed_before, "alice's host holds no root seed before the rotation")
    rotate(a, net)
    after = view(a)
    check(after["root_epoch"] == before["root_epoch"] + 1, f"epoch {before['root_epoch']} -> {after['root_epoch']}")
    check(after["root_public_key"] != before["root_public_key"] and after["root_state_id"] != before["root_state_id"],
          "the root key or root state did not change")
    check(after["genesis_root_public_key"] == before["genesis_root_public_key"] and after["id"] == net,
          "the rotation changed the network's identity")
    seed_after = root_seed(a, net)
    check(seed_after and seed_after != seed_before, "the new root seed was not installed in place of the old one")
    roots = [p for _, _, p in statements(a, net, "root_state") if p["epoch"] == after["root_epoch"]]
    check(len(roots) == 1, f"root states at the new epoch: {len(roots)}")
    root = roots[0]
    check(root["root_public_key"] == after["root_public_key"] and len(root["predecessors"]) == 1,
          f"new root state {root}")
    missing = candidates - set(root["retained_statement_ids"])
    check(not missing, f"the rotation dropped keepable grants: {sorted(missing)[:3]}")
    check(set(members(a, net)) == {a.public_key, b.public_key}, "alice's member list changed with the rotation")
    wait_root(b, after["root_state_id"])
    bob = view(b)
    check(bob["root_epoch"] == after["root_epoch"] and bob["authority"]["state"] == "usable",
          f"bob after learning the rotation: epoch {bob['root_epoch']}, authority {bob['authority']}")
    state["epoch1"] = after


@suite.case("work_and_edits_after_rotation", "spec 13.1: kept grants keep working")
def _():
    net, bert, _ = need("net", "bert", "epoch1")
    sent = a.ok("send", "bob/bert", "after the rotation")
    check(sent["state"] == "accepted", f"alice -> bob/bert after the rotation: {sent['state']}")
    got = bert.next_message()
    check(got["request"]["content"] == "after the rotation", f"bert got {got['request']}")
    out = b.ok("allow", "alice", "--delegate", "--person-key", state["bob_key"])
    check("task.delegate" in out["actions"], f"bob's policy edit after the rotation: {out}")


@suite.case("join_under_new_root", "spec 13.1, 8: the new root admits")
def _():
    net, epoch1 = need("net", "epoch1")
    state["carol_key"] = ssh_key(c.root, "carol")
    join_new_person(a, c, "carol", state["carol_key"], net)
    check(view(c)["root_state_id"] == epoch1["root_state_id"], "carol joined under another root state")
    wait_for(lambda: c.public_key in members(b, net) or (sync(b) and False), timeout=40, interval=1,
             message="bob to list carol")
    state["carol"] = True


@suite.case("rotate_to_ssh_root", "spec 13.1: an SSH root leaves the seed column empty")
def _():
    solo = create_network(a, "solo", "alice")
    key = ssh_key(a.root, "solo-root")
    rotate(a, solo["id"], "--to-ssh", "--root-key", key)
    after = view(a, solo["id"])
    check(after["root_public_key"] == ssh_public_base64(key), "the root is not the SSH key after --to-ssh")
    check(after["root_epoch"] == 1, f"epoch after --to-ssh {after['root_epoch']}")
    check(not root_seed(a, solo["id"]), "the host still stores a root seed after rotating to an SSH root")


def probe(state_dir, host, path, method="GET", body=None):
    args = [str(suite.probe_bin), "--address", host.peer_address, "--alpn", "peerspan-peer/1", "--path", path,
            "--method", method, "--state", str(state_dir)]
    if body is not None:
        args.append("--body-stdin")
    p = subprocess.run(args, input=(body or "").encode(), capture_output=True, timeout=45)
    return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")


@suite.case("root_split_freezes_changes", "spec 13.2 (DEC-Q19); 16; 20 item 55")
def _():
    (net,) = need("net")
    # A copy of alice's state, started while bob and carol are down, signs a successor of the current root.
    for h in (b, c):
        h.stop()
    a.stop()
    copy = suite.host("alice-copy", start=False)
    shutil.copytree(a.state, copy.state, dirs_exist_ok=True)
    shutil.copytree(a.home, copy.home, dirs_exist_ok=True)
    for leftover in ("admin.sock", "adapter.sock"):
        (copy.state / leftover).unlink(missing_ok=True)
    copy.start()
    rotate(copy, net)
    split_branch = view(copy)
    copied_catalog = copy.api("GET", f"/v2/networks/{net}/catalog")[1]["catalog"]
    copy.stop()
    for h in (a, b, c):
        h.start()
    rotate(a, net)
    main_branch = view(a)
    check(main_branch["root_epoch"] == split_branch["root_epoch"]
          and main_branch["root_state_id"] != split_branch["root_state_id"], "the two rotations did not diverge")
    wait_root(b, main_branch["root_state_id"])
    # alice's key hands bob the other branch on the member catalog route.
    code, out, err = probe(a.state, b, f"/peer/v2/networks/{net}/catalog", method="POST",
                           body=json.dumps({"catalog": copied_catalog}))
    check(code == 0, f"posting the copy's catalog to bob: exit {code} {err.strip()[-200:]}")

    def split(host):
        v = view(host)
        return v["root_state_id"] == "-" and v

    seen = wait_for(lambda: split(b), timeout=30, interval=1, message="bob to see the root split")
    check(seen["root_public_key"] == "-", f"root_public_key in a split: {seen['root_public_key']}")
    items, _ = attention(b)
    check(any(k == "network_state_conflict" for k, _ in items), f"bob's attention in a root split: {sorted(items)}")
    state["split"] = True
    state["split_items"] = items


@suite.case("split_status_detail", "spec 13.2: status explains the split", known="spec 13.2 status detail")
def _():
    (items,) = need("split_items")
    conflict = [d for k, d in items if k == "network_state_conflict"]
    check(any("root split: changes are frozen; create a new network and run network reinvite" in d for d in conflict),
          f"network_state_conflict details in a root split: {conflict}")


@suite.case("split_keeps_existing_grants", "spec 13.2: existing grants keep working until they expire",
            known="spec 13.2 existing grants")
def _():
    _, bert = need("split", "bert")
    sent = a.ok("send", "bob/bert", "during the split")
    check(sent["state"] == "accepted", f"alice -> bob/bert during the split: {sent['state']}")
    check(bert.next_message()["request"]["content"] == "during the split", "bert did not get the message")
    check(b.public_key in members(b, state["net"]) and a.public_key in members(b, state["net"]),
          "bob's member list lost hosts in the split")


@suite.case("split_refuses_new_grants_and_root_actions", "spec 13.2; 20 item 55")
def _():
    net, _ = need("net", "split")
    edit = b.cli("allow", "alice", "--person-key", state["bob_key"])  # drops --delegate: a new policy
    check(not edit.ok, "bob signed a new policy during a root split")
    def alice_split():
        if view(a)["root_state_id"] == "-":
            return True
        a.api("POST", f"/v2/networks/{net}/sync", {}, timeout=60)  # may answer 409 state_conflict in a split
        return view(a)["root_state_id"] == "-"

    wait_for(alice_split, timeout=30, interval=1, message="alice to see the root split")
    again = a.cli("network", "rotate-root", net, input="y\n", timeout=60)
    check(not again.ok, "alice rotated the root during a root split")


@suite.case("no_resolve_root", "spec 13.2 (DEC-Q19), 15: network resolve-root is removed; 20 item 55",
            known="DEC-Q19")
def _():
    (net,) = need("net")
    result = a.cli("network", "resolve-root", net, "--new-root-key", str(a.root / "none"))
    check(not result.ok and "unrecognized subcommand" in result.stderr,
          f"network resolve-root still exists: exit {result.code}: {result.stderr.strip()[-200:]}")


@suite.case("reinvite_from_split_network", "spec 14.2 (DEC-Q16); 20 item 58", known="DEC-Q16")
def _():
    net, _ = need("net", "split")
    old_catalog = b.api("GET", f"/v2/networks/{net}/catalog")[1]
    fresh = create_network(b, "fresh", "bob")
    result = b.cli("network", "reinvite", net, fresh["id"])
    check(result.ok and isinstance(result.json, list),
          f"network reinvite OLD NEW: exit {result.code}: {result.stderr.strip()[-200:]}")
    entries = {e["host_id"]: e for e in result.json}
    want = {a.id} | ({c.id} if "carol" in state else set())
    check(set(entries) == want, f"reinvite printed invites for {sorted(entries)}, want {sorted(want)}")
    for e in entries.values():
        check({"member", "host_id", "person_public_key", "invitation_id", "invitation", "expires_at"} <= set(e),
              f"reinvite entry fields {sorted(e)}")
        check(e["invitation"].startswith("psi2-"), "a reinvite entry carries no invite code")
    if "carol" not in state:
        return
    check(entries[c.id]["person_public_key"] == ssh_public_base64(state["carol_key"]),
          "carol's invite does not pin her person key")
    check(b.api("GET", f"/v2/networks/{net}/catalog")[1] == old_catalog, "reinvite changed the old network")
    request = join_request(c, entries[c.id]["invitation"], state["carol_key"])
    check(request["person_public_key"] == ssh_public_base64(state["carol_key"]), "carol joins NEW as someone else")


suite.finish()
