#!/usr/bin/env python3
"""Slim suite: default agent names from `attach` (docs/launch-contract.md, Naming and Verification; DEC-OWN12).

alice has two linked machines, bob one in the same network, and a fourth host has no network. Every `attach` uses
a small Python integration bundle written here (docs/harness-integration-contract.md, local helper protocol v1), so
the suite needs neither Node nor a real harness. It declares no `launch`, so `attach` prints its output object.
Exact expected names are the main check on DEC-OWN12; `no-host-name` adds the host name and a HOSTNAME sentinel.

Not covered here: a real harness launch, the `endpoint` fields and `session start`/`doctor` from the Attach list.
"""
import json
import os
import pwd
import socket
import sys
import time
from datetime import datetime, timedelta, timezone

from harness import Suite, attention, check, create_network, join_new_person, link_machine, ssh_key, wait_for

HELPER = """import json, sys
json.load(sys.stdin)
print(json.dumps({"version": 1, "checks": [{"name": "fixture", "status": "ok", "detail": "ok"}]}))
"""
HOST_NAME_SENTINEL = "sentinelmachine"
LONG_ID = "a" * 64  # the longest integration ID
MID_ID = "m" * 40

suite = Suite("naming", __doc__)
a, a2, b, solo = suite.host("alice"), suite.host("alice2"), suite.host("bob"), suite.host("solo")
state = {}
default_names = []  # every name `attach` chose by itself, for the host name case


def need(*names):
    missing = [n for n in names if n not in state]
    check(not missing, f"an earlier case did not finish ({', '.join(missing)} missing)")
    return [state[n] for n in names]


def bundles():
    root = suite.work / "integrations"
    if not root.exists():
        for integration in ("claude-code", "second", "builtin", LONG_ID, MID_ID):
            bundle = root / integration
            bundle.mkdir(parents=True)
            (bundle / "helper.py").write_text(HELPER)
            (bundle / "integration.json").write_text(json.dumps({
                "version": 1, "id": integration, "command": [sys.executable, "./helper.py"],
                "operations": ["prepare", "check"]}))
    return root


def project(path):
    """A new directory under this suite's projects; the last part of PATH is the project's base name."""
    directory = suite.work / "projects" / path
    directory.mkdir(parents=True)
    return directory


def attach(host, harness="claude", directory=None, name=None, extra=()):
    args = ["attach", harness, "--integrations", bundles(), *extra]
    if directory is not None:
        args += ["--directory", directory]
    if name is not None:
        args += ["--name", name]
    return host.cli(*args, timeout=90)


def named(host, harness="claude", directory=None, **kw):
    """A successful `attach` with no --name in a new setup: returns its output, recorded for the host name case."""
    result = attach(host, harness, directory, **kw)
    check(result.ok and result.json, f"{host.name}: attach {directory}: {result} {result.stderr.strip()[-300:]}")
    default_names.append(result.json["agent"]["name"])
    return result.json


def expect_name(host, want, directory, harness="claude"):
    out = named(host, harness, directory)
    check(out["agent"]["name"] == want, f"{host.name}: attach {directory}: name {out['agent']['name']!r}, want {want!r}")
    check(out["reused"] is False, f"{host.name}: new agent {want} reports reused {out['reused']}")
    return out


def local_agents(host):
    status, body = host.api("GET", "/v1/agents")
    check(status == 200, f"{host.name}: GET /v1/agents: {status} {body}")
    return body["agents"] if isinstance(body, dict) else body


def register(host, name):
    status, body = host.api("POST", "/v1/agents", {"name": name, "owner": host.name})
    check(status in (200, 201), f"{host.name}: register {name}: {status} {body}")
    return body


def hex_of(host, digits):
    check(host.id.startswith("host_"), f"host ID {host.id}")
    return host.id[len("host_"):][:digits]


def refused(result, host_with_name):
    check(result.code == 1, f"attach: exit {result.code}, want 1: {result.stderr.strip()[-300:]}")
    check(host_with_name.id in result.stderr,
          f"the error does not name {host_with_name.name}'s host: {result.stderr.strip()[-300:]}")


@suite.case("setup", "spec 6, 8")
def _():
    net = create_network(a, "naming", "alice")
    state["net"] = net["id"]
    status, network = a.api("GET", f"/v2/networks/{net['id']}")
    check(status == 200, f"network: {status} {network}")
    key = a.home / ".config/peerspan/person_ed25519"
    state["alice_key"] = key
    join_new_person(a, b, "bob", ssh_key(b.root, "bob"), net["id"])
    link_machine(a, a2, net["id"], network["person_public_key"], key=key)
    for host in (a, a2, b, solo):
        host.extra_env["HOSTNAME"] = HOST_NAME_SENTINEL


@suite.case("bare-name", "launch Naming 1: BASE; Output; Profiles; Registering")
def _():
    need("net")
    out = named(a)  # no --directory: the current directory
    check(out["agent"]["name"] == "claude", f"name {out['agent']['name']!r}, want claude")
    check(out["agent"]["id"].startswith("agent_"), f"agent id {out['agent']['id']}")
    check(out["workspace"] == os.path.realpath(a.root), f"workspace {out['workspace']}")
    check(out["reused"] is False, f"reused {out['reused']}")
    check(out["unchecked_hosts"] == [], f"unchecked_hosts {out['unchecked_hosts']}")
    want = a.home / ".config" / "peerspan" / "sessions" / a.id / "claude"
    check(want.is_dir(), f"no profile at {want}; output says {out['profile']}")
    state["claude"] = out["agent"]


@suite.case("reattach-reuses", "launch Re-attaching: registered, reused true")
def _():
    first, = need("claude")
    before = len(local_agents(a))
    out = named(a)
    check(out["reused"] is True, f"reused {out['reused']}")
    check(out["agent"]["id"] == first["id"] and out["agent"]["name"] == "claude", f"agent {out['agent']}, want {first}")
    check(len(local_agents(a)) == before, "a re-attach registered an agent")


@suite.case("second-project", "launch Naming 2: BASE-PROJECT")
def _():
    need("claude")
    directory = project("one/beta")
    out = expect_name(a, "claude-beta", directory)
    check(out["workspace"] == os.path.realpath(directory), f"workspace {out['workspace']}")
    again = named(a, directory=directory)
    check(again["reused"] is True and again["agent"]["id"] == out["agent"]["id"], f"re-attach gave {again['agent']}")


@suite.case("project-characters", "launch Naming: lowercased, others become -")
def _():
    need("claude")
    expect_name(a, "claude-my-proj-", project("two/My Proj!"))
    expect_name(a, "claude-v1.2_x", project("two/V1.2_x"))


@suite.case("root-directory", "launch Naming: the root directory's empty base name is project; DEC-OWN12")
def _():
    need("claude")
    out = expect_name(a, "claude-project", "/")
    check(out["workspace"] == "/", f"workspace {out['workspace']}")
    again = named(a, directory="/")
    check(again["reused"] is True and again["agent"]["id"] == out["agent"]["id"], f"re-attach gave {again['agent']}")
    state["root_done"] = True


@suite.case("project-no-letters", "launch Naming: no letters or digits gives project; 4: -2, -3")
def _():
    need("root_done")
    expect_name(a, "claude-project-2", project("three/___"))
    expect_name(a, "claude-project-3", project("four/!!!"))


@suite.case("same-project-name", "launch Naming 4: the candidate with -2, -3")
def _():
    need("claude")
    expect_name(a, "claude-dup", project("five/dup"))
    expect_name(a, "claude-dup-2", project("six/dup"))
    expect_name(a, "claude-dup-3", project("seven/dup"))


@suite.case("other-host", "launch Naming 3: BASE-HHHH with this host's ID, used only on another host")
def _():
    need("claude")
    directory = project("alice2/gamma")
    out = expect_name(a2, f"claude-{hex_of(a2, 4)}", directory)
    again = named(a2, directory=directory)
    check(again["reused"] is True and again["agent"]["id"] == out["agent"]["id"], f"re-attach gave {again['agent']}")


@suite.case("other-host-longer", "launch Naming 3: then 6, 8 digits while taken")
def _():
    need("claude")
    expect_name(a2, f"claude-{hex_of(a2, 6)}", project("alice2/delta"))
    expect_name(a2, f"claude-{hex_of(a2, 8)}", project("alice2/epsilon"))


@suite.case("other-host-suffix", "launch Naming 3, 4: 32 digits at most, then -2")
def _():
    need("claude")
    check(len(hex_of(a2, 64)) >= 32, f"host ID {a2.id} has under 32 hex digits")
    for digits in range(10, 33, 2):
        register(a2, f"claude-{hex_of(a2, digits)}")
    expect_name(a2, f"claude-{hex_of(a2, 32)}-2", project("alice2/zeta"))
    expect_name(a2, f"claude-{hex_of(a2, 32)}-3", project("alice2/eta"))


@suite.case("used-on-both", "launch Naming 2: BASE used on this host, whatever others have")
def _():
    need("net")
    register(a, "second")
    register(a2, "second")
    expect_name(a2, "second-omega", project("alice2/omega"), harness="second")


@suite.case("project-name-on-other-host", "launch Naming: free means on no host of this person, after a refresh")
def _():
    need("claude")
    result = attach(a2, directory=project("alice2/holder"), name="claude-shared")
    check(result.ok, f"attach --name on alice2: {result}")
    expect_name(a, "claude-shared-2", project("one/shared"))


@suite.case("cut-to-64", "launch Naming: project, then BASE, cut to fit 64; -HHHH and -N are not cut")
def _():
    need("claude")
    expect_name(a, LONG_ID, project("eight/first"), harness=LONG_ID)  # a 64-character BASE fits whole
    state["long_base"] = True
    expect_name(a, "a" * 62 + "-p", project("eight/project-name"), harness=LONG_ID)
    expect_name(a, "a" * 60 + "-p-2", project("nine/project-name"), harness=LONG_ID)
    expect_name(a, MID_ID, project("ten/first"), harness=MID_ID)
    expect_name(a, MID_ID + "-" + "x" * 23, project("ten/" + "x" * 80), harness=MID_ID)
    expect_name(a, MID_ID + "-" + "x" * 21 + "-2", project("eleven/" + "x" * 80), harness=MID_ID)


@suite.case("cut-to-64-other-host", "launch Naming: BASE cut so -HHHH fits")
def _():
    need("long_base")
    expect_name(a2, "a" * 59 + f"-{hex_of(a2, 4)}", project("alice2/long"), harness=LONG_ID)


@suite.case("builtin-reserved", "launch Naming: builtin is never free; capabilities: attach --name builtin exits 1")
def _():
    need("claude")
    before = len(local_agents(a))
    result = attach(a, directory=project("twelve/x"), name="builtin")
    check(result.code == 1 and "reserved" in result.stderr, f"--name builtin: {result}")
    check(len(local_agents(a)) == before, "--name builtin registered an agent")
    out = named(a, "builtin", project("thirteen/keep"))
    name = out["agent"]["name"]
    check(name != "builtin" and name.startswith("builtin-"), f"integration builtin got the name {name!r}")


@suite.case("name-free-used", "launch Naming: --name used if free")
def _():
    need("claude")
    result = attach(a, directory=project("fourteen/given"), name="chosen")
    check(result.ok and result.json["agent"]["name"] == "chosen", f"attach --name chosen: {result}")
    state["chosen"] = result.json["agent"]


@suite.case("name-taken-here", "launch Refusals: 409 before any registration, naming the host")
def _():
    need("claude")
    before = {x["id"] for x in local_agents(a)}
    directory = project("fifteen/taken")
    refused(attach(a, directory=directory, name="claude"), a)
    check({x["id"] for x in local_agents(a)} == before, "a refused --name registered an agent")


@suite.case("name-taken-sibling", "launch Refusals; Uniqueness: on any of the person's hosts")
def _():
    need("claude")
    before = {x["id"] for x in local_agents(a2)}
    refused(attach(a2, directory=project("alice2/taken"), name="claude"), a)
    check({x["id"] for x in local_agents(a2)} == before, "a refused --name registered an agent")


@suite.case("name-existing-agent", "launch Naming: --name of an agent no profile records is reused")
def _():
    need("claude")
    agent = register(a, "registered-earlier")
    result = attach(a, directory=project("sixteen/old"), name="registered-earlier")
    check(result.ok, f"attach --name registered-earlier: {result}")
    check(result.json["agent"]["id"] == agent["id"], f"agent {result.json['agent']}, want {agent['id']}")


@suite.case("earlier-name-kept", "launch Naming: an agent named under an earlier rule keeps its name")
def _():
    need("claude")
    earlier = "claude-oldrule"
    directory = project("seventeen/kept")
    result = attach(a, directory=directory, name=earlier)
    check(result.ok, f"attach --name {earlier}: {result}")
    again = attach(a, directory=directory)
    check(again.ok and again.json["reused"] is True and again.json["agent"]["name"] == earlier
          and again.json["agent"]["id"] == result.json["agent"]["id"], f"re-attach gave {again} {again.json}")


@suite.case("expired-reattach", "launch Re-attaching: after expiry a new credential for the same agent")
def _():
    need("claude")
    directory = project("eighteen/brief")
    soon = (datetime.now(timezone.utc) + timedelta(seconds=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    result = attach(a, directory=directory, extra=("--expires-at", soon))
    check(result.ok, f"attach --expires-at: {result}")
    first = result.json
    default_names.append(first["agent"]["name"])
    check(first["agent"]["name"] == "claude-brief", f"name {first['agent']['name']}")
    time.sleep(5)
    again = named(a, directory=directory)
    check(again["agent"]["id"] == first["agent"]["id"], f"agent {again['agent']}, want {first['agent']}")
    check(again["reused"] is False, f"reused {again['reused']}: a new setup was expected")
    check(again["adapter_id"] != first["adapter_id"], "the adapter credential was not replaced")


@suite.case("other-person", "launch Names are unique per person: another person's names stay free; Peer route: "
                            "an agent with no authorizations is never listed")
def _():
    key, chosen = need("alice_key", "chosen")

    def reachable():
        return {m["address"]: m for m in b.ok("agents", "--refresh", "--json")["reachable"]}

    check("alice/chosen" not in reachable(), "bob lists alice's chosen before any allow")
    a.ok("allow", "bob", "--person-key", key)
    # Without this the case proves nothing: a name of alice's that bob cannot see could not be wrongly refused.
    # second is on both of alice's hosts, so its addresses use the host ID (launch Discovery).
    held = ("alice/chosen", "alice/claude", "alice/claude-dup", f"{a.id}/second", f"{a2.id}/second")

    def all_held():
        now = reachable()
        return now if all(address in now for address in held) else None

    listed = wait_for(all_held, timeout=25, interval=1, message=f"bob's directory to list {held}")
    seen = listed["alice/chosen"]
    check(seen["agent_id"] == chosen["id"] and seen["host_id"] == a.id, f"bob sees alice/chosen as {seen}")

    # Each of these would be suffixed if alice's agents counted as bob's.
    expect_name(b, "claude", project("bob/any"))  # Naming 1, not 3
    expect_name(b, "claude-dup", project("bob/dup"))  # Naming 2, not 4
    expect_name(b, "second", project("bob/omega"), harness="second")  # Naming 1, not 3

    result = attach(b, directory=project("bob/second"), name="chosen")
    check(result.ok, f"bob's --name chosen: {result}")
    mine = result.json["agent"]
    check(mine["name"] == "chosen" and mine["address"] == "bob/chosen", f"bob's agent {mine}")
    check(mine["id"] != chosen["id"], "bob's chosen is alice's agent")
    view = b.ok("agents", "--refresh", "--json")
    check(any(m["agent_id"] == mine["id"] for m in view["mine"]), f"bob's mine: {view['mine']}")
    check(any(m["address"] == "alice/chosen" for m in view["reachable"]), "bob no longer lists alice/chosen")
    kinds = {kind for kind, _ in attention(b)[0]}
    check("agent_name_conflict" not in kinds, f"another person's name raised a conflict on bob: {kinds}")


@suite.case("unbound-host", "launch Output and Registering: HOST_ID/NAME and the login name with no person")
def _():
    out = expect_name(solo, "claude", project("solo/first"))
    check(out["agent"]["address"] == f"{solo.id}/claude", f"address {out['agent']['address']}")
    owners = [x.get("owner") for x in local_agents(solo) if x["id"] == out["agent"]["id"]]
    check(owners == [pwd.getpwuid(os.geteuid()).pw_name], f"owner {owners}, want the login name")
    expect_name(solo, "claude-second", project("solo/second"))


@suite.case("address-and-owner", "launch Output, Registering: PERSON/NAME and the person's label as owner")
def _():
    first, = need("claude")
    out = attach(a).json  # the re-attach prints the same address
    check(out["agent"]["address"] == "alice/claude", f"address {out['agent']['address']}")
    owners = [x.get("owner") for x in local_agents(a) if x["id"] == first["id"]]
    check(owners == ["alice"], f"owner {owners}, want the bound person's label")


@suite.case("no-host-name", "launch Naming: the machine's host name is never part of a default name; DEC-OWN12")
def _():
    check(default_names, "no default name was recorded")
    machine = socket.gethostname().lower()
    for name in sorted(set(default_names)):
        check(HOST_NAME_SENTINEL not in name, f"{name} has the HOSTNAME value")
        check(machine not in name, f"{name} has the machine's host name")
    view = a2.ok("agents", "--refresh", "--json")
    seen = [m["address"] for m in view["mine"]]
    check(state["claude"]["id"] in [m["agent_id"] for m in view["mine"]], f"alice2 does not list alice's claude: {seen}")
    for address in seen:
        check(HOST_NAME_SENTINEL not in address, f"{address} has the HOSTNAME value")


@suite.case("unchecked-sibling", "launch Uniqueness: a host not reached is in unchecked_hosts and does not block")
def _():
    need("claude")
    a2.stop()
    try:
        out = expect_name(a, "claude-offline", project("nineteen/offline"))
        check(a2.id in out["unchecked_hosts"], f"unchecked_hosts {out['unchecked_hosts']}, want {a2.id}")
    finally:
        a2.start()


suite.finish()
