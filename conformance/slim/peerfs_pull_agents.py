#!/usr/bin/env python3
"""PF-3: agents' pulls: grants (fs allow-pull, deny-pull, pull-grants), the grants file, the adapter routes, the
agent's own bound, fs.pulled and cancellation.

Written independently from docs/peerfs-pull-contract.md section 5 and section 7 Agents (cited "pull N"), PF-09,
PF-10 and the PF-3 agent paragraph of docs/host-service-contract.md; fixtures in peerfs_pull_common.py. The
adapter is the harness's fixture adapter on bob's adapter socket, so the MCP tool list itself (which follows `GET
/adapter/v1/fs/pull-grants`) is not exercised here.
"""
import json
import os
import stat

from harness import Suite, UnixHTTPConnection, check, wait_for
import peerfs_read_common as common
from peerfs_read_common import Graph, need, sp, state
from peerfs_pull_common import (MIB, destination, fs_pulled, history, in_thread, proxies, pull, pulled, refused,
                                share_all, source, stalled, start, tracking)

os.umask(0o077)
suite = Suite("peerfs_pull_agents", __doc__)
common.bind(suite, None)
GIB = 1 << 30
GRANT_KEYS = {"agent_id", "agent_name", "space", "max_bytes", "created_at"}


def grants_file():
    return state["b"].state / "fs-pull-grants.json"


def agent_grants(adapter=None):
    status, value = (adapter or state["agent"]).call("GET", "/adapter/v1/fs/pull-grants")
    check(status == 200, f"adapter pull-grants: {status} {value}")
    return value


def owner_grants():
    result = state["b"].cli("--json", "fs", "pull-grants")
    check(result.ok, f"fs pull-grants: exit {result.code} {result.stderr.strip()[-300:]}")
    value = result.json
    return value["grants"] if isinstance(value, dict) else value


def allow(space, *extra, agent="puller"):
    result = state["b"].cli("--json", "fs", "allow-pull", agent, "--space", space, *extra)
    check(result.ok, f"fs allow-pull: exit {result.code} {result.stderr.strip()[-300:]}")
    return result.json


def deny(space, agent="puller"):
    result = state["b"].cli("--json", "fs", "deny-pull", agent, "--space", space)
    check(result.ok, f"fs deny-pull: exit {result.code} {result.stderr.strip()[-300:]}")
    return result.json


@suite.case("setup", "decentralized-spec 6, 8; PF-1 sections 3-4; read 2 (fs_rules); agent registration")
def _():
    start()
    net1, b = state["net1"], state["b"]
    g = Graph()
    for name in ("first", "deny", "cancel", "file"):
        history(g, name)
    history(g, "mid", last=(9 * MIB,) * 2)
    state["spaces"] = {"one": source(net1, g)}
    state["dest"] = {"A": destination(net1), "B": destination(net1), "released": destination(net1)}
    r = state["dest"]["released"]["registration"]
    status, value = b.api("POST", f"/v1/fs/spaces/{r['space_id']}/release", {"binding_id": r["binding_id"]})
    check(status == 200, f"fixture: release: {status} {value}")
    share_all([(sp("one"), n) for n in ("first", "deny", "cancel", "file", "mid")])
    state["agent"], state["other"] = b.agent("puller"), b.agent("bystander")
    state["ready"] = True


@suite.case("no_grant_refused", "pull 5: without a grant the listing is empty and fs_pull is 403, before any fetch")
def _():
    need("ready")
    A = state["dest"]["A"]
    check(agent_grants() == {"grants": []}, f"grants before any allow-pull: {agent_grants()}")
    status, value = pull("first", A["id"], sp("one"), adapter=state["agent"])
    refused(status, value, 403, "forbidden", "an agent without a grant")
    check(not A["provider"].pulls and not proxies(), "a refused agent pull reached the destination")


@suite.case("grant_commands", "pull 5; host-service PF-3 agents: allow-pull by name, pull-grants, the PUT/DELETE "
                              "statuses, the grants file at mode 0600")
def _():
    need("ready")
    b, A, agent = state["b"], state["dest"]["A"], state["agent"]
    allow(A["id"], "--max-bytes", str(5 * MIB))
    listed = owner_grants()
    check(len(listed) == 1 and set(listed[0]) == GRANT_KEYS, f"fs pull-grants: {listed}")
    check({k: listed[0][k] for k in ("agent_id", "agent_name", "space", "max_bytes")} ==
          {"agent_id": agent.id, "agent_name": "puller", "space": A["id"], "max_bytes": 5 * MIB},
          f"the grant: {listed[0]}")
    check(agent_grants() == {"grants": [{"space": A["id"], "max_bytes": 5 * MIB}]}, f"agent: {agent_grants()}")
    check(agent_grants(state["other"]) == {"grants": []}, "another agent sees a grant")
    info = os.lstat(grants_file())
    check(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.geteuid(),
          f"fs-pull-grants.json mode {oct(info.st_mode)}")
    content = json.loads(grants_file().read_text())
    check(set(content) == {"format", "grants"} and content["format"] == 1 and content["grants"] == [
        {"agent_id": agent.id, "space": A["id"], "max_bytes": 5 * MIB, "created_at": listed[0]["created_at"]}],
        f"the grants file: {content}")
    status, value = b.api("GET", "/v1/fs/pull-grants")
    check(status == 200 and value == {"grants": listed}, f"GET /v1/fs/pull-grants: {status} {value}")
    unknown = agent.id[:-4] + ("0000" if not agent.id.endswith("0000") else "1111")
    problems = []
    for label, path, body, want in (
            ("max_bytes 0", f"{agent.id}/{A['id']}", {"max_bytes": 0}, 400),
            ("a malformed agent", f"agent-x/{A['id']}", {}, 400),
            ("a malformed space", f"{agent.id}/space_X", {}, 400),
            ("an unknown agent", f"{unknown}/{A['id']}", {}, 404),
            ("a space with no binding", f"{agent.id}/space_{'0' * 32}", {}, 404),
            ("a released binding", f"{agent.id}/{state['dest']['released']['id']}", {}, 409)):
        status, value = b.api("PUT", f"/v1/fs/pull-grants/{path}", body)
        if status != want:
            problems.append(f"{label}: {status} {value}, want {want}")
    check(not problems, "; ".join(problems))
    check(len(owner_grants()) == 1, f"a refused PUT changed the grants: {owner_grants()}")


@suite.case("own_bound_and_activity", "pull 5, 7 Agents: the grant's bound applies (507), a replaced grant lets the "
                                      "pull complete; fs.pulled with the agent; another destination 403")
def _():
    need("ready")
    A, B, agent, one = state["dest"]["A"], state["dest"]["B"], state["agent"], sp("one")
    g = state["spaces"]["one"]["graph"]
    status, value = pull("mid", A["id"], one, adapter=agent)
    refused(status, value, 507, "too_large", "an agent pull past its grant's 5 MiB")
    check(not A["provider"].remotes, "a bounded agent pull wrote a reference")
    allow(A["id"])
    check(agent_grants() == {"grants": [{"space": A["id"], "max_bytes": GIB}]}, "the replaced grant's default")
    check(len(owner_grants()) == 1, "allow-pull added a second grant for the pair")
    status, value = pull("mid", A["id"], one, adapter=agent)
    pulled(status, value, "mid", A["id"], one, g.branches["mid"], "an agent pull within its grant")
    check(fs_pulled(f"{agent.id}/{A['id']}/{tracking(one, 'mid')}"), "no fs.pulled with the agent's subject")
    status, value = pull("first", B["id"], one, adapter=agent)
    refused(status, value, 403, "forbidden", "a destination the agent has no grant for")
    status, value = pull("first", A["id"], one, adapter=state["other"])
    refused(status, value, 403, "forbidden", "another agent into the granted space")
    check(not B["provider"].pulls, "a refused pull reached the other destination")


@suite.case("deny_pull", "pull 5: a pull already running when its grant is withdrawn finishes; the next is 403")
def _():
    need("ready")
    A, agent, one = state["dest"]["A"], state["agent"], sp("one")
    g, provider = state["spaces"]["one"]["graph"], state["spaces"]["one"]["provider"]
    allow(A["id"])
    release = stalled(provider)
    try:
        out = in_thread(pull, "deny", A["id"], one, adapter=agent)
        wait_for(lambda: provider.held >= 1, timeout=20, interval=.05, message="the agent's pull at S")
        deny(A["id"])
    finally:
        release()
    out["thread"].join(120)
    pulled(*out["value"], "deny", A["id"], one, g.branches["deny"], "a pull running across deny-pull")
    check(agent_grants() == {"grants": []} and owner_grants() == [], "grants after deny-pull")
    status, value = pull("first", A["id"], one, adapter=agent)
    refused(status, value, 403, "forbidden", "a pull after deny-pull")
    status, value = state["b"].api("DELETE", f"/v1/fs/pull-grants/{agent.id}/{A['id']}")
    check(status == 200 and value == {"removed": False}, f"a second DELETE: {status} {value}")


@suite.case("grants_file_rules", "pull 5; host-service PF-3: a malformed or non-0600 grants file holds no grants: "
                                 "agents refused, owner routes 409; removing it recovers")
def _():
    need("ready")
    b, A, agent, one = state["b"], state["dest"]["A"], state["agent"], sp("one")
    allow(A["id"])
    good = grants_file().read_text()
    content = json.loads(good)
    bad = {"format 2": {**content, "format": 2},
           "an unknown field": {**content, "extra": 1},
           "max_bytes 0": {**content, "grants": [{**content["grants"][0], "max_bytes": 0}]},
           "a repeated pair": {**content, "grants": content["grants"] * 2},
           "not JSON": "{"}
    problems = []
    for label, text in [*bad.items(), ("mode 0644", None)]:
        if text is None:
            grants_file().write_text(good)
            grants_file().chmod(0o644)
        else:
            grants_file().write_text(text if isinstance(text, str) else json.dumps(text))
            grants_file().chmod(0o600)
        got = {"GET": b.api("GET", "/v1/fs/pull-grants")[0],
               "PUT": b.api("PUT", f"/v1/fs/pull-grants/{agent.id}/{A['id']}", {})[0],
               "DELETE": b.api("DELETE", f"/v1/fs/pull-grants/{agent.id}/{A['id']}")[0],
               "agent pull": pull("file", A["id"], one, adapter=agent)[0]}
        listing = agent.call("GET", "/adapter/v1/fs/pull-grants")
        if got != {"GET": 409, "PUT": 409, "DELETE": 409, "agent pull": 403}:
            problems.append(f"{label}: {got}")
        if listing != (200, {"grants": []}):
            problems.append(f"{label}: the agent's listing {listing}")
    grants_file().unlink()
    status, value = b.api("GET", "/v1/fs/pull-grants")
    check(status == 200 and value == {"grants": []}, f"after removing the file: {status} {value}")
    check(not problems, "; ".join(problems))
    allow(A["id"])
    status, value = pull("file", A["id"], one, adapter=agent)
    pulled(status, value, "file", A["id"], one, state["spaces"]["one"]["graph"].branches["file"], "after recovery")


@suite.case("agent_cancellation", "pull 4, 5: closing the adapter request ends the pull: proxy removed, no "
                                  "reference; the next pull of the branch is not 409")
def _():
    need("ready")
    A, agent, one = state["dest"]["A"], state["agent"], sp("one")
    g, provider = state["spaces"]["one"]["graph"], state["spaces"]["one"]["provider"]
    allow(A["id"])
    before = len(A["provider"].pulls)
    release = stalled(provider)
    try:
        connection = UnixHTTPConnection(str(state["b"].state / "adapter.sock"), timeout=30)
        body = json.dumps({"peer": state["a"].id, "space": one, "branch": "cancel", "into": A["id"]})
        connection.request("POST", "/adapter/v1/fs/pulls", body=body, headers={
            "Authorization": f"Bearer {agent.token}", "X-Peerspan-Instance": agent.instance,
            "Content-Type": "application/json"})
        wait_for(lambda: provider.held >= 1, timeout=20, interval=.05, message="the agent's pull at S")
        check(len(proxies()) == 1, f"proxy directories while pulling: {proxies()}")
        connection.close()
        wait_for(lambda: not proxies(), timeout=10, interval=.1, message="the proxy removed after the close")
    finally:
        release()
    record = A["provider"].pulls[before]
    wait_for(lambda: record["outcome"] is not None, timeout=20, interval=.1, message="the destination's pull to end")
    check(record["outcome"] != "ok" and tracking(one, "cancel") not in A["provider"].remotes,
          "a cancelled agent pull completed or wrote a reference")
    status, value = pull("cancel", A["id"], one, adapter=agent, timeout=60)
    pulled(status, value, "cancel", A["id"], one, g.branches["cancel"], "a pull after the cancelled one")


suite.finish()
