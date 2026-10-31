#!/usr/bin/env python3
"""Slim suite 10, basics: info, status and errors, storage and the host service.

alice creates a network and bob joins; carol only makes a join request. Written from
docs/decentralized-spec.md sections 14 to 17, the wire appendix sections 16.1, 16.9 and 19, and
docs/host-service-contract.md and docs/launch-contract.md (status).

Not covered here: the installed-bundle smoke test (packaging a release bundle needs a release build and the
Node integration bundles, several minutes on CI, over this suite's 2-minute budget). Legacy-network
history compatibility (spec 14.1) has no fixture in this suite, so `status_v1_same_as_v2` sees no legacy_history entry.
"""
import json
import shutil
import sqlite3
import subprocess
import time

from harness import (Suite, attention, check, create_network, invite, join_new_person, join_request, members,
                     ssh_key, ssh_public_base64, wait_for)

suite = Suite("basics", __doc__)
a, b = suite.host("alice"), suite.host("bob")
state = {}
ERROR_DETAILS = {"network_id", "context_id", "request_id", "stage", "required_ids", "conflict_ids", "next"}


def need(*names):
    missing = [n for n in names if n not in state]
    check(not missing, f"an earlier case did not finish ({', '.join(missing)} missing)")
    return [state[n] for n in names]


def database(host):
    """The state database (spec 3): the SQLite file in the state directory that holds `networks`."""
    for path in sorted(host.state.glob("*.db")):
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
        try:
            if db.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'networks'").fetchone():
                return path, db
        except sqlite3.DatabaseError:
            pass
        db.close()
    raise AssertionError(f"{host.name}: no state database with a networks table")


@suite.case("setup", "spec 6, 8")
def _():
    net = create_network(a, "basics", "alice")
    state["net"] = net["id"]
    state["bob_key"] = ssh_key(b.root, "bob")
    join_new_person(a, b, "bob", state["bob_key"], net["id"])
    state["bert"] = b.agent("bert")
    b.ok("allow", "alice", "--person-key", state["bob_key"])


@suite.case("info", "spec 16 (Info); appendix 16.9")
def _():
    status, info = a.api("GET", "/v2/info")
    check(status == 200, f"/v2/info: {status} {info}")
    check("default_coordinator" in info and info["default_coordinator"] is None,
          f"default_coordinator {info.get('default_coordinator', '<missing>')}")
    check(info.get("network_protocols") == ["peerspan-decentralized-v1"], f"network_protocols {info.get('network_protocols')}")


@suite.case("status_network_views", "spec 16 (Status); appendix 16.2, 16.9")
def _():
    (net,) = need("net")
    _, body = attention(a)
    networks = body.get("networks") or []
    entry = next((n for n in networks if n.get("id") == net), None)
    check(entry is not None, f"/v2/status lists no entry for the network: {[n.get('id') for n in networks]}")
    check(entry.get("mode") == "decentralized", f"status entry mode {entry.get('mode')}")
    authority, provider = entry.get("authority") or {}, entry.get("provider_state") or {}
    check(authority.get("state") == "usable" and authority.get("not_after"), f"authority {authority}")
    check(provider.get("state") == "available", f"provider_state {provider}")


@suite.case("status_cli_exit_codes", "launch contract: status exit codes")
def _():
    result = a.cli("status", "--json")
    check(result.code in (0, 1) and result.json is not None, f"status --json: exit {result.code}")
    check((result.code == 0) == (not result.json.get("attention")),
          f"exit {result.code} with attention {result.json.get('attention')}")
    a.stop()
    try:
        down = a.cli("status", "--json")
        check(down.code == 2 and isinstance(down.json, dict) and down.json.get("daemon") == "not running"
              and down.json.get("state") == str(a.state),
              f"status with the daemon stopped: exit {down.code} {down.stdout[:200]!r}")
    finally:
        a.start()


@suite.case("errors_have_spec_shape", "spec 16 (Errors); appendix 16.1")
def _():
    (net,) = need("net")
    probes = [("GET", "/v2/networks/net_" + "0" * 64, None, 404, "not_found"),
              ("GET", "/v2/link/requests/link_" + "0" * 64, None, 404, "not_found"),
              ("POST", f"/v2/networks/{net}/invitations",
               {"member": "x", "expected_person_public_key": "-", "expires_at": "2000-01-01T00:00:00Z"}, 400, "invalid")]
    for method, path, body, want_status, want_code in probes:
        status, reply = a.api(method, path, body)
        check(status == want_status and isinstance(reply, dict) and reply.get("code") == want_code,
              f"{method} {path}: {status} {reply}, want {want_status} {want_code}")
        check(isinstance(reply.get("error"), str) and reply["error"], f"{method} {path}: no error text")
        details = reply.get("details")
        check(isinstance(details, dict) and set(details) == ERROR_DETAILS,
              f"{method} {path}: details {sorted(details) if isinstance(details, dict) else details}")
        check(isinstance(details["required_ids"], list) and isinstance(details["conflict_ids"], list),
              f"{method} {path}: id lists {details}")


@suite.case("link_request_waiting", "spec 8.1 step 5, 16 (attention order)")
def _():
    (net,) = need("net")
    c = suite.host("carol")
    state["carol"] = c
    request = join_request(c, invite(a, "carol", net)["invitation"], ssh_key(c.root, "carol"))

    def waiting():
        items, _ = attention(a)
        return [d for k, d in items if k == "link_request_waiting"]

    found = wait_for(waiting, timeout=10, message="link_request_waiting on the inviter")
    check(any("link approve" in d or request["request_id"] in d for d in found), f"item detail {found}")


def differences(one, other, path="status"):
    """The paths at which two JSON values differ, for a readable failure."""
    if isinstance(one, dict) and isinstance(other, dict):
        return [d for k in sorted(one.keys() | other.keys())
                for d in differences(one.get(k, "<missing>"), other.get(k, "<missing>"), f"{path}.{k}")]
    if isinstance(one, list) and isinstance(other, list) and len(one) == len(other):
        return [d for i, pair in enumerate(zip(one, other)) for d in differences(*pair, f"{path}[{i}]")]
    return [] if one == other else [f"{path}: v1 {one!r}, v2 {other!r}"]


def same_status(host):
    """/v1/status and /v2/status as one object. No field is dropped: the contract lets the object change as the
    host's state changes, and names no field that differs by route or by call. A background sync or renewal may
    land between the two requests, so a difference is retried; a real one between the routes persists and fails."""
    found = []
    for _ in range(5):
        v1_status, v1 = host.api("GET", "/v1/status")
        v2_status, v2 = host.api("GET", "/v2/status")
        check(v1_status == 200 and v2_status == 200, f"{host.name}: status answers {v1_status} {v2_status}")
        found = differences(v1, v2)
        if not found:
            return v1
        time.sleep(1)
    raise AssertionError(f"{host.name}: /v1/status and /v2/status differ: {found}")


@suite.case("status_v1_same_as_v2", "launch Status: the same object; DEC-OWN13")
def _():
    net, bert, c, bob_key = need("net", "bert", "carol", "bob_key")
    status = {h.name: same_status(h) for h in (a, b, c)}  # a joiner still waiting, so with no membership, too

    for host, member in ((a, "alice"), (b, "bob")):
        got = status[host.name]
        check(got["host_id"] == host.id, f"{host.name}: host_id {got['host_id']}, want {host.id}")
        entries = [n for n in got["networks"] if n.get("id") == net]
        check(len(entries) == 1, f"{host.name}: {len(entries)} entries for the network: {got['networks']}")
        entry = entries[0]
        check(entry.get("mode") == "decentralized" and entry.get("name") == "basics", f"{host.name}: entry {entry}")
        code, view = host.api("GET", f"/v2/networks/{net}")
        check(code == 200, f"{host.name}: network view: {code} {view}")
        check(entry.get("member") == member, f"{host.name}: member {entry.get('member')}, want {member}")
        check(entry.get("person_public_key") and entry["person_public_key"] == view["person_public_key"],
              f"{host.name}: person_public_key {entry.get('person_public_key')}, want {view['person_public_key']}")
    check(status["bob"]["networks"][0]["person_public_key"] == ssh_public_base64(bob_key),
          "bob's entry does not carry bob's person key")

    agents = [x for x in status["bob"]["agents"] if x["id"] == bert.id]
    check(len(agents) == 1 and agents[0]["name"] == "bert", f"bob's agents: {status['bob']['agents']}")
    sessions = agents[0]["sessions"]
    check([s["id"] for s in sessions] == [bert.session_id] and sessions[0]["adapter_id"] == bert.adapter_id,
          f"bert's sessions: {sessions}")
    kinds = [item["kind"] for item in status["alice"]["attention"]]  # the waiting request from `link_request_waiting`
    check("link_request_waiting" in kinds, f"alice's attention: {kinds}")


@suite.case("removed_commands", "spec 15: network migrate and network resolve-root are removed")
def _():
    (net,) = need("net")
    for args in (["network", "migrate", "status", "--network", net], ["network", "resolve-root", net]):
        result = a.cli(*args)
        check(not result.ok and "unrecognized subcommand" in result.stderr,
              f"`{' '.join(args[:3])}` still exists: exit {result.code}: {result.stderr.strip()[-160:]}")


@suite.case("removed_migration_routes", "spec 15; appendix 15 (DEC-S12)")
def _():
    (net,) = need("net")
    for method, path in (("GET", f"/v2/networks/{net}/migration"), ("POST", f"/v2/networks/{net}/migration")):
        status, body = a.api(method, path, {} if method == "POST" else None)
        check(status in (404, 405), f"{method} {path}: {status} {body}, want 404")


@suite.case("reinvite_refuses_a_current_network", "spec 14.2 (DEC-Q16): OLD is legacy or root-split")
def _():
    (net,) = need("net")
    other = create_network(a, "other", "alice")
    result = a.cli("network", "reinvite", net, other["id"])
    check("unrecognized subcommand" not in result.stderr, "there is no `network reinvite` command")
    check(not result.ok, f"reinvite from a current, usable network succeeded: {result.json}")
    result = a.cli("network", "reinvite", other["id"], "net_" + "0" * 64)
    check(not result.ok, "reinvite into a network this host is not a member of succeeded")


@suite.case("storage_survives_restart", "spec 17; host service contract: persistence")
def _():
    net, bert = need("net", "bert")

    def snapshot(host):
        view = host.api("GET", f"/v2/networks/{net}")[1]
        return {"host": host.api("GET", "/v1/host")[1],
                "view": {k: view[k] for k in ("id", "context_id", "root_state_id", "root_public_key", "member",
                                              "person_public_key", "host_public_key")},
                "members": sorted(members(host, net)),
                "agents": host.api("GET", "/v1/agents")[1],
                "requests": sorted((r["request_id"], r["state"]) for r in host.api("GET", "/v2/link/requests")[1]),
                "catalog": sorted(o.get("proof_id", json.dumps(o, sort_keys=True)) for o in
                                  host.api("GET", f"/v2/networks/{net}/catalog")[1]["catalog"]["objects"])}

    before = {h.name: snapshot(h) for h in (a, b)}
    a.restart(kill=True)  # a crash
    b.restart()  # an orderly stop
    after = {h.name: snapshot(h) for h in (a, b)}
    for name in before:
        for field in ("host", "view", "members", "agents"):
            check(before[name][field] == after[name][field], f"{name}'s {field} changed across a restart")
        check(set(before[name]["requests"]) <= set(after[name]["requests"]), f"{name} lost join requests")
        check(set(before[name]["catalog"]) <= set(after[name]["catalog"]), f"{name} lost records")
    # The fixture adapter recovers its session within the reconnect window; work flows again.
    wait_for(lambda: bert.post("/adapter/v1/next")[0] != 503, timeout=20, message="bert to recover its lease")
    sent = a.ok("send", "bob/bert", "after the restart")
    check(sent["state"] == "accepted", f"send after the restart: {sent['state']}")
    got = bert.next_message(timeout=30)
    check(got["request"]["content"] == "after the restart", f"bert got {got['request']}")


@suite.case("schema_24_tables", "spec 17 (DEC-Q14); appendix 19.1; 20 item 59")
def _():
    path, db = database(a)
    try:
        version = db.execute("PRAGMA user_version").fetchone()[0]
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        migrations = db.execute("SELECT count(*) FROM dec_migrations").fetchone()[0] if "dec_migrations" in tables \
            else None
    finally:
        db.close()
    want = {"dec_contexts", "dec_objects", "dec_admissions", "dec_restrictions", "dec_activations", "dec_heads",
            "dec_highwater", "dec_signers", "dec_clock", "dec_intents", "dec_pending", "dec_frames", "dec_operations",
            "dec_outbox", "dec_contacts", "dec_helpers", "dec_migrations"}
    check(want <= tables, f"missing tables {sorted(want - tables)}")
    check(version == 24, f"{path.name}: schema version {version}, want 24 (conversations C1)")
    check(migrations == 0, f"dec_migrations holds {migrations} rows")


@suite.case("newer_schema_refused", "spec 17: older binaries refuse a newer schema; 20 item 59")
def _():
    copy = suite.host("alice-copy", start=False)
    a.stop()
    try:
        shutil.copytree(a.state, copy.state, dirs_exist_ok=True)
    finally:
        a.start()
    for leftover in ("admin.sock", "adapter.sock"):
        (copy.state / leftover).unlink(missing_ok=True)
    path, db = database(copy)
    db.close()
    db = sqlite3.connect(str(path))
    db.execute("PRAGMA user_version = 25")
    db.commit()
    db.close()
    log = (copy.root / "daemon.log").open("ab")
    p = suite.spawn([str(suite.host_bin), "--state", str(copy.state), "run"], stdout=log, stderr=log, env=copy.env)
    try:
        code = p.wait(timeout=20)
    except subprocess.TimeoutExpired:
        code = None
    check(code not in (None, 0), "a daemon opened a schema 25 database")
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        check(db.execute("PRAGMA user_version").fetchone()[0] == 25, "the refused database was changed")
    finally:
        db.close()


@suite.case("one_daemon_per_state", "host service contract: process exclusivity")
def _():
    identity = a.api("GET", "/v1/host")[1]
    log = (a.root / "second.log").open("ab")
    p = suite.spawn([str(suite.host_bin), "--state", str(a.state), "run"], stdout=log, stderr=log, env=a.env)
    try:
        code = p.wait(timeout=20)
    except subprocess.TimeoutExpired:
        code = None
    check(code not in (None, 0), "a second daemon started on a state directory already in use")
    check(a.api("GET", "/v1/host")[1] == identity, "the running daemon's socket or identity changed")


suite.finish()
