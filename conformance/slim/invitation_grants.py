#!/usr/bin/env python3
"""Slim suite, invitation_grants: agent access granted with the invite (guided session contract section 55, P5).

Three inviters, each an owner and administrator whose original person key is an OpenSSH key file the daemon is
configured with: rev reviews contact invitations with and without `agent_access` and records them; alice issues the
invitations that new people join through on their own hosts with the ordinary seven-stage join (decentralized-spec
8.1), her `link admit` being the administrator's admission. With alice's device provider selected, an admitted
person's grant is signed without a press; with her original SSH key selected it waits for the owner
(`agent_access_waiting`) until `grant complete`. Then cancellation, an already-member request, a pinned key that does
not match, a project re-attached to another agent and the owner-only routes; last, carol's grants end by each rule
on her own test clock.

Written from docs/guided-session-contract.md sections 9, 31 and 55 and docs/peerbox-contract.md "Invitations for new
participants" only; no production imports. Section 55 names the grant view's contents (invitation ID, flow ID, member
label, agent, state, the requests' person IDs, the bound person ID, the terminal details) but not its field names, so
only `state` is read by name; everything else is looked for as a value anywhere in the view.
"""
import hashlib
import http.client
import json
import re
import socket
import sqlite3
import ssl
import subprocess
from contextlib import closing
from datetime import timedelta

from harness import (Clock, Suite, attention, check, commit, finalize, join_request, link_view, parse_time, pull_until,
                     select, ssh_key, ssh_public_base64, wait_for, wait_linked)
from runtime_common import bind, need, policy_statement, policy_version, run_side_by_side, state

suite = Suite("invitation_grants", __doc__)
bind(suite)
FLOWS = "/v1/onboarding/invitation-flows"
GRANTS = "/v1/onboarding/invitation-grants"
PROJECT = "/v1/onboarding/project-flows"
REVIEW = {"version", "kind", "flow_id", "host_id", "context", "agent", "network", "inviter_host_public_key",
          "member", "expected_person_public_key", "transport", "expires_at", "invitation_expires_at", "effects"}
EFFECTS = {"create_contact_invitation": True, "receive_join_requests": True, "grant_membership": False,
           "grant_agent_access": False, "approve_machine": False, "share_files": False,
           "share_conversation": False, "capability_calls": False}
ACTIONS = ["message.append", "task.submit"]
WAITING = ("waiting_for_request", "waiting_for_admission", "waiting_for_owner")
TERMINAL = ("granted", "cancelled", "expired", "stopped")
HOUR, DAY = 3600, 86400


# Hosts, projects and invitations (sections 3, 9).

def host(name, clock=None, owner_key=False):
    h = suite.host(name, start=False, clock=clock)
    config = h.root / "transport.json"
    config.write_text(json.dumps({"format": 1, "advertise_bootstrap": [f"127.0.0.1:{h.bootstrap_port}"],
                                  "advertise_quic": [h.peer_address], "rendezvous": [], "relays": [],
                                  "publish_contacts": False}))
    config.chmod(0o600)
    h.extra_args = ["--transport-config", config]
    if owner_key:  # section 32: the daemon's configured owner key file; no ssh-agent
        h.owner_key = ssh_key(h.root, "owner")
        h.extra_args += ["--person-key-file", h.owner_key]
        h.extra_env = {"SSH_AUTH_SOCK": str(h.root / "absent-agent")}
    return h.start()


def get(h, path, want=200):
    status, value = h.api("GET", path, timeout=15)
    check(status == want, f"{h.name}: GET {path.split('?')[0][:60]}: HTTP {status} {str(value)[:300]}")
    return value


def project(h, label, replace=None):
    body = {"project_root": str(suite.work / "projects" / label), "native_session_id": "conversation-" + label,
            "integration": "claude-code", "agent": {"kind": "new", "name": "agent-" + label, "owner": "alice"}}
    if replace:
        body["replace_flow_id"] = replace
    status, flow = h.api("POST", PROJECT, body)
    check(status == 201, f"project prepare HTTP {status} {flow}")
    exact = {k: body[k] for k in ("project_root", "native_session_id", "integration")}
    status, flow = h.api("POST", f"{PROJECT}/{flow['flow_id']}/decision",
                         {**exact, "review_id": flow["review_id"], "decision": "approve"})
    check(status == 200 and flow["state"] == "attached", f"project attachment {status} {flow}")
    return flow


def context(parent):
    return {"project_flow_id": parent["flow_id"], "project_review_id": parent["review_id"],
            **{k: parent["review"][k] for k in ("project_root", "native_session_id", "integration")}}


def proposal(parent, member, pin="-", access=True, replace=None):
    body = {"context": context(parent), "network_id": state["net"], "member": member,
            "expected_person_public_key": pin}
    if access is not None:
        body["agent_access"] = access
    if replace:
        body["replace_flow_id"] = replace
    return body


def prepare(h, body, want=201, code=None):
    status, value = h.api("POST", FLOWS, body)
    check(status == want and (code is None or value.get("code") == code),
          f"prepare HTTP {status} {value.get('code') if isinstance(value, dict) else value}, want {want} {code}")
    return value


def decide(h, flow, choice="approve", want=200):
    status, value = h.api("POST", f"{FLOWS}/{flow['flow_id']}/decision",
                          {"context": flow["review"]["context"], "review_id": flow["review_id"], "decision": choice})
    check(status == want, f"decision {choice}: HTTP {status} {value}")
    return value


def digest(review):
    canonical = json.dumps(review, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return "review_" + hashlib.sha256(b"peerspan-invitation-review-v1\n" + canonical).hexdigest()


def issue(parent, member, pin="-", access=True):
    """Prepare, approve and privately hand off one invitation: (issued flow, psi2- code, invitation ID). A later
    invitation in the same project context explicitly replaces the latest issued one (section 9)."""
    a = need("a")[0]
    latest = state.setdefault("latest", {})
    issued = decide(a, prepare(a, proposal(parent, member, pin, access, replace=latest.get(parent["flow_id"]))))
    latest[parent["flow_id"]] = issued["flow_id"]
    check(issued["state"] == "issued", f"approval did not issue: {issued['state']}")
    status, private = a.api("POST", f"{FLOWS}/{issued['flow_id']}/handoff",
                            {"context": issued["review"]["context"], "review_id": issued["review_id"]})
    check(status == 200 and private["invitation"].startswith("psi2-"), f"handoff HTTP {status}")
    return issued, private["invitation"], issued["invitation"]["invitation_id"]


# The grant routes (section 55, Lifetime and owner controls).

def grant(inv, h=None, want=200):
    return get(h or need("a")[0], f"{GRANTS}/{inv}", want)


def grants(h=None):
    value = get(h or need("a")[0], GRANTS)
    return value


def mentions(value, needle):
    """Whether NEEDLE appears as a value (or inside a string value) anywhere in VALUE."""
    if isinstance(value, dict):
        return any(mentions(v, needle) for v in value.values())
    if isinstance(value, list):
        return any(mentions(v, needle) for v in value)
    if isinstance(needle, str) and isinstance(value, str):
        return needle in value
    return value == needle and type(value) is type(needle)


def listed(inv, h=None):
    return [g for g in walk_list(grants(h)) if mentions(g, inv)]


def leaves(value, path=()):
    """Every (path, leaf value) of a JSON value."""
    if isinstance(value, dict):
        return [x for k, v in value.items() for x in leaves(v, path + (k,))]
    if isinstance(value, list):
        return [x for i, v in enumerate(value) for x in leaves(v, path + (i,))]
    return [(path, value)]


def new_words(before, after):
    """The string values AFTER gained over BEFORE, other than its state and timestamps: a terminal record's details."""
    old = dict(leaves(before))
    return {v for p, v in leaves(after) if isinstance(v, str) and old.get(p) != v and v not in TERMINAL
            and not re.fullmatch(r"\d{4}-\d\d-\d\dT[0-9:]+Z", v)}


def walk_list(value):
    if isinstance(value, list):
        return value
    lists = [v for v in value.values() if isinstance(v, list)] if isinstance(value, dict) else []
    check(len(lists) == 1, f"grant list is neither a list nor one object holding a list: {str(value)[:300]}")
    return lists[0]


def state_of(view):
    check(isinstance(view, dict) and view.get("state") in WAITING + TERMINAL, f"grant view state: {str(view)[:400]}")
    return view["state"]


def wait_state(inv, want, timeout=60, h=None):
    found = {}

    def reached():
        found["view"] = grant(inv, h)
        return state_of(found["view"]) == want
    try:
        wait_for(reached, timeout=timeout, interval=0.5, message=f"grant state {want}")
    except AssertionError:
        check(False, f"grant {inv[:12]} did not reach {want}: {str(found.get('view'))[:500]}")
    return found["view"]


def act(method, inv, h=None):
    return (h or need("a")[0]).api(method, f"{GRANTS}/{inv}" + ("/complete" if method == "POST" else ""),
                                   {} if method == "POST" else None, timeout=60)


# Joining (decentralized-spec 8.1, the harness's join_new_person split at the request).

def request(joiner, code, key):
    made = join_request(joiner, code, key)
    rid, reply = made["request_id"], made.get("display_code")
    check(reply, "join printed no request code")
    a = need("a")[0]
    wait_for(lambda: any(r["request_id"] == rid for r in get(a, "/v2/link/requests")), timeout=60, interval=0.5,
             message=f"{joiner.name}'s request to come back to alice")
    return rid, reply


def admit(joiner, rid, reply, key, before_admission=None):
    a, net = need("a", "net")
    joiner.ok_incomplete("link", "approve", "--network", net, "--person-key", key, "--code-stdin", "--approve",
                         input=reply + "\n")
    view = pull_until(joiner, rid, "owner_offer_id")
    select(joiner, view)
    view = link_view(joiner, rid)
    if before_admission:
        before_admission()
    a.ok_incomplete("link", "admit", "--network", net, "--owner-offer", view["owner_offer_id"], "--selection",
                    view["selection_id"], "--person", view["person_public_key"], "--expect-host-key",
                    view["host_public_key"], "--expect-device-key", view["device_public_key"], "--code-stdin",
                    "--approve", input=reply + "\n")
    view = pull_until(joiner, rid, "administrator_offer_id")
    finalize(joiner, view, key)
    view = pull_until(joiner, rid, "owner_finalization_id")
    commit(joiner, view)
    wait_linked(joiner, a, rid)


def person(h, key):
    return h.ok("person", "show", "--person-key", key)["person_id"]


def rules():
    return policy_statement(need("a")[0], state["alice_public"])[3]["rules"]


def rules_naming(principal):
    return [r for r in rules() if principal in r["principals"]]


def select_provider(provider_id):
    a, net = need("a", "net")
    status, value = a.api("POST", f"/v2/networks/{net}/provider", {
        "provider_id": provider_id, "person_public_key": state["alice_public"], "host_public_key": a.public_key,
        "approve": True})
    check(status == 200, f"selecting provider: {status} {value}")
    return value["provider"]


def waiting_items(inv):
    _, body = attention(need("a")[0])
    return [i for i in body.get("attention") or [] if i.get("kind") == "agent_access_waiting" and mentions(i, inv)]


def inviter(name, clock=None):
    """An inviter's world: a host with its own owner key file and network (decentralized-spec 6). Helpers act on
    the world `use` selected. Each inviter keeps few invitations open: an inviter reads every open invitation's
    return mailbox (decentralized-spec 8.1, step 4), and many open invitations on one loopback source slow it."""
    h = host(name, clock=clock, owner_key=True)
    net = h.ok("network", "create", name, "--as", name, "--person-key-file", h.owner_key)
    world = {"a": h, "net": net["id"], "alice_public": ssh_public_base64(h.owner_key)}
    check(net["person_public_key"] == world["alice_public"], f"{name}'s person is not her configured key file")
    provider = get(h, f"/v2/networks/{net['id']}")["provider"]
    check(provider.get("kind") == "device", f"fixture: {name}'s selected provider after network create: {provider}")
    state.setdefault("worlds", {})[name] = world
    return world


def use(name):
    state.update(state["worlds"][name])


@suite.case("setup", "section 9, 55: inviters with an SSH key file and a device provider; one attached project")
def _():
    inviter("rev")
    inviter("alice")
    use("alice")
    state["parent"] = project(state["a"], "main")
    state["agent"] = state["parent"]["review"]["agent"]
    state["cancel_parent"] = project(state["a"], "cancelled")


# The review (section 55, The review; section 9).

@suite.case("review_exact_with_and_without_agent_access", "section 55 The review; section 9 exact shape")
def _():
    use("rev")
    a = need("a")[0]
    parent = state["rparent"] = project(a, "review")  # a context of its own: no replacement in the retried body
    plain = prepare(a, proposal(parent, "plain teammate", access=None))
    review = plain["review"]
    check(set(plain) == {"version", "flow_id", "state", "review_id", "review", "invitation", "next_action"}
          and set(review) == REVIEW and review["effects"] == EFFECTS and plain["review_id"] == digest(review),
          f"without agent_access the review is not section 9's exact shape: {sorted(review)} {review.get('effects')}")
    issued = decide(a, plain)
    check(set(issued["review"]) == REVIEW and issued["state"] == "issued", "the plain approval changed shape")
    check(not listed(issued["invitation"]["invitation_id"]), "an invitation without agent_access recorded a grant")
    grant(issued["invitation"]["invitation_id"], want=404)
    other = state["rparent2"] = project(a, "review-access")
    body = proposal(other, "access teammate")
    flow = prepare(a, body)
    review = flow["review"]
    agent = other["review"]["agent"]
    check(set(review) == REVIEW | {"agent_access"} and review["agent_access"] == {
        "policy_scope": "owner_agent_name", "agent_id": agent["id"], "agent_name": agent["name"], "actions": ACTIONS,
        "max_message_bytes": 65536, "max_artifact_bytes": 0, "allow_disconnected": False, "policy_hours": 24},
          f"agent_access review terms: {review.get('agent_access')}")
    check(review["effects"] == {**EFFECTS, "grant_agent_access_after_admission": True}
          and review["effects"]["grant_agent_access"] is False, f"effects: {review['effects']}")
    check(flow["review_id"] == digest(review) and flow["state"] == "review" and flow["invitation"] is None,
          "agent_access is not part of the canonical digest, or preparation issued")
    status, again = a.api("POST", FLOWS, body)
    check(status == 200 and again == flow, f"identical retry with agent_access: HTTP {status}")
    without_access = {k: v for k, v in body.items() if k != "agent_access"}
    prepare(a, without_access, 409, "flow_conflict")
    for bad in (False, "true", 1, None, {}):
        prepare(a, {**body, "agent_access": bad}, 400, "invalid")
    check(get(a, f"{FLOWS}/{flow['flow_id']}") == flow, "a refused or conflicting prepare changed the review")
    state["review_flow"] = flow
    use("alice")


@suite.case("recording_atomic_with_approval_none_on_decline", "section 55 Recording")
def _():
    use("rev")
    a, parent, flow = need("a", "rparent2", "review_flow")
    before = walk_list(grants())
    declined = decide(a, flow, "decline")
    check(declined["state"] == "declined" and walk_list(grants()) == before, "declining recorded a grant")
    flow = prepare(a, proposal(parent, "rollback teammate", replace=flow["flow_id"]))
    db = []
    for path in a.state.glob("*.db"):
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as conn:
            if conn.execute("SELECT 1 FROM sqlite_master WHERE name='onboarding_invitation_flows'").fetchone():
                db.append(path)
    check(len(db) == 1, "fixture: one host database")
    with closing(sqlite3.connect(db[0])) as conn, conn:  # schema-only fault on the flow's issued update (section 9)
        conn.execute("CREATE TRIGGER conformance_abort_issue BEFORE UPDATE ON onboarding_invitation_flows "
                     "WHEN NEW.state='issued' BEGIN SELECT RAISE(ABORT,'conformance-abort'); END")
    try:
        status, _ = a.api("POST", f"{FLOWS}/{flow['flow_id']}/decision",
                          {"context": flow["review"]["context"], "review_id": flow["review_id"],
                           "decision": "approve"})
        check(status >= 500 or status == 409, f"approval with a failing flow update: HTTP {status}")
        check(walk_list(grants()) == before, "a rolled-back approval left a pending grant")
    finally:
        with closing(sqlite3.connect(db[0])) as conn, conn:
            conn.execute("DROP TRIGGER conformance_abort_issue")
    issued = decide(a, flow)
    inv = issued["invitation"]["invitation_id"]
    view = grant(inv)
    check(state_of(view) == "waiting_for_request" and mentions(view, flow["flow_id"])
          and mentions(view, "rollback teammate") and mentions(view, parent["review"]["agent"]["name"]),
          f"the approved grant: {view}")
    check(listed(inv) == [view], f"the list does not show the pending grant as inspect does: {listed(inv)}")
    a.restart()
    check(grant(inv) == view, "startup did not keep the pending grant")
    use("alice")


def first_join():
    """dan's split join through a pinned invitation: a request alone grants nothing; admission binds and signs."""
    a, parent = need("a", "parent")
    d = state["d"] = host("dan")
    key = state["dan_key"] = ssh_key(d.root, "dan")
    _, code, inv = issue(parent, "dan", pin=ssh_public_base64(key))
    state["dan_inv"] = inv
    rid, reply = request(d, code, key)
    pid = state["dan_pid"] = person(d, key)
    view = wait_state(inv, "waiting_for_admission", timeout=30)
    check(mentions(view, rid) or mentions(view, pid), f"the grant does not record dan's request: {view}")

    def unbound():
        seen = grant(inv)
        check(state_of(seen) == "waiting_for_admission" and not rules_naming("person:" + pid),
              f"the grant bound or signed before the administrator's admission: {seen}")
    admit(d, rid, reply, key, before_admission=unbound)


def other_joins():
    """erin joins through a cancelled grant's invitation."""
    e = state["e"] = host("erin")
    key = state["erin_key"] = ssh_key(e.root, "erin")
    rid, reply = request(e, need("cancel_code")[0], key)
    admit(e, rid, reply, key)


@suite.case("automatic_signing_with_device_provider", "section 55 Binding, Signing (Automatic); section 31 profile")
def _():
    a, parent = need("a", "parent")
    check(get(a, f"/v2/networks/{state['net']}")["provider"]["kind"] == "device", "fixture: device provider")
    # Cancel one pending grant first (owner controls); its invitation stays usable for erin below.
    state["cancel_flow"], _, inv = issue(state["cancel_parent"], "erin")
    status, cancelled = act("DELETE", inv)
    check(status == 200 and state_of(cancelled) == "cancelled", f"cancel: HTTP {status} {cancelled}")
    status, again = act("DELETE", inv)
    check(status == 200 and again == cancelled == grant(inv), "a cancelled (terminal) grant changed on cancel")
    status, refused = act("POST", inv)
    check(status == 409 and mentions(refused, "cancelled"), f"complete of a cancelled grant: HTTP {status} {refused}")
    status, private = a.api("POST", f"{FLOWS}/{state['cancel_flow']['flow_id']}/handoff",
                            {"context": state["cancel_flow"]["review"]["context"],
                             "review_id": state["cancel_flow"]["review_id"]})
    check(status == 200, "the cancelled grant's invitation is no longer retrievable")
    state["cancel_code"] = private["invitation"]
    before = rules()
    run_side_by_side((first_join, (), {}), (other_joins, (), {}))
    dan = "person:" + state["dan_pid"]
    view = wait_state(state["dan_inv"], "granted", timeout=60)
    version = policy_version(a, state["alice_public"])
    found = state["dan_rules"] = rules_naming(dan)
    check([{**r, "max_artifact_bytes": r.get("max_artifact_bytes", 0)} for r in found] == [
        {"agent": state["agent"]["name"], "principals": [dan], "actions": ACTIONS, "max_message_bytes": 65536,
         "max_artifact_bytes": 0, "allow_disconnected": False}], f"dan's rule: {found}")
    check([r for r in rules() if dan not in r["principals"]] == before, "the grant changed another rule")
    check(mentions(view, version) and mentions(view, state["dan_pid"]), f"granted record without version/person: {view}")
    _, _, payload, _ = policy_statement(a, state["alice_public"])
    check(parse_time(payload["not_after"]) <= a.now() + timedelta(hours=24, minutes=1), "policy longer than 24 hours")
    status, same = act("POST", state["dan_inv"])
    check(status == 200 and same == view and policy_version(a, state["alice_public"]) == version,
          f"repeated complete after granted: HTTP {status}, or signed again")
    status, same = act("DELETE", state["dan_inv"])
    check(status == 200 and same == view, "cancel of a granted grant changed it")
    erin = "person:" + person(state["e"], state["erin_key"])
    check(state["e"].public_key in [m["host_public_key"] for m in get(a, f"/v2/networks/{state['net']}/members")
                                     ["members"]], "the cancelled grant's invitation did not stay usable")
    check(not rules_naming(erin) and state_of(grant(inv)) == "cancelled", "a cancelled grant granted erin access")
    cli = a.cli("--json", "onboarding", "invitation", "grant", "inspect", state["dan_inv"])
    check(cli.ok and cli.json == view, f"grant inspect CLI parity: exit {cli.code}")
    cli = a.cli("--json", "onboarding", "invitation", "grant", "list")
    check(cli.ok and cli.json == grants(), f"grant list CLI parity: exit {cli.code}")


@suite.case("appended_rule_keeps_explicit_artifact_bound", "section 55 Signing: exactly as section 31; section 31: a "
                                                           "newly appended profile rule includes raw max_artifact_bytes:0")
def _():
    found = need("dan_rules")[0]
    check(len(found) == 1 and "max_artifact_bytes" in found[0] and found[0]["max_artifact_bytes"] == 0,
          f"the appended profile rule has no explicit max_artifact_bytes:0: {found}")


def join_all(*joins):
    """Each (joiner, code, key): the requests one after another, then the admissions side by side."""
    made = [(joiner, *request(joiner, code, key), key) for joiner, code, key in joins]
    run_side_by_side(*[(admit, item, {}) for item in made])


def attempt(joiner, rid, reply, key):
    """An admission that the hosts may refuse: whether it completed."""
    try:
        admit(joiner, rid, reply, key)
        return "admitted"
    except AssertionError as error:
        return "not admitted: " + " ".join(str(error).split())[:120]


@suite.case("already_member_and_unmatched_pin_bind_nothing", "section 55 Binding: a person already in the network is "
                                                             "not recorded and binds nothing; the pin must match")
def _():
    a, parent, dan_key = need("a", "parent", "dan_key")
    before = rules()
    d2 = state["d2"] = host("dan2")  # another machine of dan, already a member, joining with dan's key
    _, member_code, member_inv = issue(parent, "dan again")
    f = state["f"] = host("fay")
    fay_key, other = ssh_key(f.root, "fay"), ssh_key(f.root, "not-fay")
    _, pin_code, pin_inv = issue(parent, "fay", pin=ssh_public_base64(other))
    outcome = {"member": attempt(d2, *request(d2, member_code, dan_key), dan_key)}
    made = f.cli("--json", "join", "--invite-stdin", "--person-key", fay_key, input=pin_code + "\n", timeout=90)
    if made.json and made.json.get("request_id"):
        outcome["pin"] = attempt(f, made.json["request_id"], made.json["display_code"], fay_key)
    else:
        outcome["pin"] = "refused by the joiner"
    print(f"  NOTE already-member admission: {outcome['member']}; unmatched pin: {outcome['pin']}", flush=True)
    state["member_inv"] = member_inv
    member = grant(member_inv)
    check(state_of(member) == "waiting_for_request" and not mentions(member, state["dan_pid"]),
          f"an already-member's request was recorded or bound: {member}")
    pin = grant(pin_inv)
    fay = "person:" + person(f, fay_key)
    check(state_of(pin) not in ("granted", "waiting_for_owner") and not rules_naming(fay),
          f"a request whose key does not match the pin bound the grant ({outcome['pin']}): {pin}")
    check(rules() == before, "an already-member request or an unmatched pin changed alice's policy")


@suite.case("waiting_for_owner_with_ssh_key_then_complete", "section 55 Signing (Waiting), owner controls, same-key "
                                                            "merge; status agent_access_waiting")
def _():
    a, parent = need("a", "parent")
    check(select_provider(state["alice_public"])["kind"] == "original_person", "alice's SSH key is not selected")
    stop_parent = state["stop_parent"] = project(a, "stop")
    g, h = host("gus"), host("hal")
    keys = {x.name: ssh_key(x.root, x.name) for x in (g, h)}
    codes = {"gus": issue(parent, "gus"), "hal": issue(stop_parent, "hal")}
    state.update(g=g, h=h, keys=keys, invs={n: c[2] for n, c in codes.items()})
    join_all(*[(x, codes[x.name][1], keys[x.name]) for x in (g, h)])
    invs = state["invs"]
    before, version = rules(), policy_version(a, state["alice_public"])
    for name in invs:
        view = wait_state(invs[name], "waiting_for_owner", timeout=60)
        check(mentions(view, person(state[name[0]], keys[name])), f"{name}'s bound person ID is not shown: {view}")
        check(waiting_items(invs[name]), f"status has no agent_access_waiting item naming {name}'s invitation")
    a.restart()
    check(state_of(grant(invs["gus"])) == "waiting_for_owner" and rules() == before
          and policy_version(a, state["alice_public"]) == version, "the waiting grant changed or signed itself")
    cli = a.cli("--json", "onboarding", "invitation", "grant", "complete", invs["gus"], timeout=60)
    check(cli.ok and cli.json and cli.json.get("state") == "granted", f"grant complete: exit {cli.code} {cli.json}")
    granted = grant(invs["gus"])
    check(granted == cli.json and mentions(granted, policy_version(a, state["alice_public"])),
          f"granted record: {granted}")
    check(not waiting_items(invs["gus"]) and waiting_items(invs["hal"]), "agent_access_waiting not updated")
    dan, gus = "person:" + state["dan_pid"], "person:" + person(g, keys["gus"])
    merged = [r for r in rules() if r["agent"] == state["agent"]["name"] and r["actions"] == ACTIONS]
    check(len(merged) == 1 and merged[0]["principals"] == [dan, gus], f"same-key merge: {merged}")
    check([dict(r, principals=[p for p in r["principals"] if p != gus]) for r in rules()] == before,
          f"complete changed anything but appending gus to the same-key rule: {before} -> {rules()}")
    status, again = act("POST", invs["gus"])
    check(status == 200 and again == granted, f"repeated complete after granted: HTTP {status}")


@suite.case("complete_refused_outside_waiting_for_owner", "section 55: any other state returns 409 with the state")
def _():
    inv = need("member_inv")[0]  # an already-member's request left it waiting_for_request
    status, refused = act("POST", inv)
    check(status == 409 and mentions(refused, "waiting_for_request"), f"complete of waiting_for_request: {status} "
                                                                      f"{refused}")
    check(state_of(grant(inv)) == "waiting_for_request", "a refused complete changed the grant")
    cli = need("a")[0].cli("--json", "onboarding", "invitation", "grant", "cancel", inv)
    check(cli.ok and cli.json and state_of(cli.json) == "cancelled" and grant(inv) == cli.json,
          f"grant cancel of a waiting_for_request grant: exit {cli.code} {cli.json}")


@suite.case("reattached_project_keeps_the_reviewed_agent", "section 55 Signing: the grant names its reviewed agent "
                                                             "ID and name; re-attaching the project to another agent "
                                                             "does not stop it")
def _():
    a, stop_parent, invs, h, keys = need("a", "stop_parent", "invs", "h", "keys")
    waiting = grant(invs["hal"])
    check(state_of(waiting) == "waiting_for_owner", f"fixture: hal's grant {waiting}")
    a.ok("session", "detach", stop_parent["review"]["session_id"])
    body = {"project_root": stop_parent["review"]["project_root"],
            "native_session_id": stop_parent["review"]["native_session_id"], "integration": "claude-code",
            "agent": {"kind": "new", "name": "agent-stop-replacement", "owner": "alice"},
            "replace_flow_id": stop_parent["flow_id"]}
    status, flow = a.api("POST", PROJECT, body)
    check(status == 201, f"replacing the stop project's agent: {status} {flow}")
    exact = {k: body[k] for k in ("project_root", "native_session_id", "integration")}
    status, flow = a.api("POST", f"{PROJECT}/{flow['flow_id']}/decision",
                         {**exact, "review_id": flow["review_id"], "decision": "approve"})
    check(status == 200 and flow["state"] == "attached", f"replacement attachment {status}")
    before = rules()
    status, value = act("POST", invs["hal"])
    granted = grant(invs["hal"])
    check(status == 200 and state_of(granted) == "granted" and value == granted,
          f"complete after the project was re-attached to another agent: HTTP {status} {value}; grant {granted}")
    hal = "person:" + person(h, keys["hal"])
    found = rules_naming(hal)
    check([{**r, "max_artifact_bytes": r.get("max_artifact_bytes", 0)} for r in found] == [
        {"agent": stop_parent["review"]["agent"]["name"], "principals": [hal], "actions": ACTIONS,
         "max_message_bytes": 65536, "max_artifact_bytes": 0, "allow_disconnected": False}],
          f"hal's rule does not name the reviewed agent: {found}")
    check([r for r in rules() if hal not in r["principals"]] == before, "the grant changed another rule")
    status, same = act("DELETE", invs["hal"])
    check(status == 200 and same == granted, "cancel of a granted grant changed it")


@suite.case("owner_routes_refused_on_scoped_peer_and_bootstrap", "section 55: refused by peer, bootstrap and "
                                                                  "credential-scoped routers")
def _():
    a, invs = need("a", "invs")
    p = host("probe")
    for local, remote in ((a, p), (p, a)):
        local.ok("peer", "add", "--id", remote.id, "--public-key", remote.public_key, "--address", remote.peer_address)
    adapter = a.agent("boundary-fixture", directory=False, ready=False)
    inv = invs["gus"]
    before = grant(inv)
    routes = (("GET", GRANTS, None), ("GET", f"{GRANTS}/{inv}", None), ("POST", f"{GRANTS}/{inv}/complete", {}),
              ("DELETE", f"{GRANTS}/{inv}", None))
    cert, key = suite.work / "boundary-cert.pem", suite.work / "boundary-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-subj", "/CN=grant-boundary", "-days",
                    "1", "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True, timeout=5)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.check_hostname, tls.verify_mode = False, ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key))
    tls.set_alpn_protocols(["peerspan-bootstrap/1"])
    try:
        for method, path, payload in routes:
            status, _ = adapter.call(method, path, payload)
            check(status == 404, f"scoped {method} {path[len(GRANTS):][:20]} HTTP {status}")
            args = [str(suite.probe_bin), "--state", str(p.state), "--address", a.peer_address, "--alpn",
                    "peerspan-peer/1", "--method", method, "--path", path]
            if payload is not None:
                args.append("--body-stdin")
            result = subprocess.run(args, input=(json.dumps(payload) if payload is not None else "").encode(),
                                    capture_output=True, timeout=15)
            check(result.returncode == 0 and json.loads(result.stdout).get("status") == 404,
                  f"peer {method} {path[len(GRANTS):][:20]}: {result.stdout[:200]}")
            data = b"" if payload is None else json.dumps(payload).encode()
            with socket.create_connection(("127.0.0.1", a.bootstrap_port), timeout=5) as raw:
                with tls.wrap_socket(raw, server_hostname="peerspan") as stream:
                    stream.sendall((f"{method} {path} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\n"
                                    f"Content-Type: application/json\r\nContent-Length: {len(data)}\r\n\r\n").encode()
                                   + data)
                    response = http.client.HTTPResponse(stream)
                    response.begin()
                    response.read()
                    check(response.status == 404, f"bootstrap {method} HTTP {response.status}")
    finally:
        adapter.stop()
    check(grant(inv) == before, "a refused remote call changed the grant")


# Each ending rule, on carol's own test clock (her authority lapses after the 7-day jump).

@suite.case("ending_rules_on_the_test_clock", "section 55 Lifetime: invitation expiry with no request, one hour after "
                                               "the last request, 7 days even while waiting; terminal expired records")
def _():
    clock = Clock(suite.work / "carol.clock")
    inviter("carol", clock=clock)
    use("carol")
    a = need("a")[0]
    parent = project(a, "ending")
    _, _, quiet = issue(parent, "never requests")
    _, code, asked = issue(parent, "requests only")
    _, ian_code, ian_inv = issue(parent, "ian")
    invs = {"ian": ian_inv}
    check(select_provider(state["alice_public"])["kind"] == "original_person", "carol's SSH key is not selected")
    i = host("ian")
    ian_key = ssh_key(i.root, "ian")
    join_all((i, ian_code, ian_key))
    ian = wait_state(ian_inv, "waiting_for_owner", timeout=60)
    version = policy_version(a, state["alice_public"])
    j = host("jan", clock=clock)  # jan's clock moves with carol's
    jan_key = ssh_key(j.root, "jan")
    clock.set(30 * 60)
    request(j, code, jan_key)
    wait_state(asked, "waiting_for_admission", timeout=30)
    waiting = {quiet: grant(quiet), asked: grant(asked)}
    clock.set(61 * 60)
    expired_quiet = wait_state(quiet, "expired", timeout=60)
    check(state_of(grant(asked)) == "waiting_for_admission", "a requested grant ended at the invitation's expiry")
    check(state_of(grant(invs["ian"])) == "waiting_for_owner", "a bound grant ended at the invitation's expiry")
    clock.set(91 * 60)
    expired_asked = wait_state(asked, "expired", timeout=60)
    check(state_of(grant(invs["ian"])) == "waiting_for_owner", "a bound grant ended one hour after its request")
    clock.set(7 * DAY - 10 * 60)
    check(state_of(grant(invs["ian"])) == "waiting_for_owner", "a waiting grant ended before 7 days")
    clock.set(7 * DAY + 5 * 60)
    expired_ian = wait_state(invs["ian"], "expired", timeout=60)
    check(not waiting_items(invs["ian"]), "agent_access_waiting outlived the grant")
    check(policy_version(a, state["alice_public"]) == version, "an ending grant signed a policy")
    rules_seen = [new_words(waiting[quiet], expired_quiet), new_words(waiting[asked], expired_asked),
                  new_words(ian, expired_ian)]
    check(all(rules_seen) and len({frozenset(x) for x in rules_seen}) == 3,
          f"the expired records do not say which ending rule applied: {rules_seen}")
    status, same = act("DELETE", quiet)
    check(status == 200 and same == expired_quiet, "cancel of an expired grant changed it")


suite.finish()
