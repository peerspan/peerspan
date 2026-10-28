#!/usr/bin/env python3
"""Slim suite 1, join: create, invite, join a new person, link a second machine, refusals.

Written from docs/decentralized-spec.md sections 6 and 8 and the wire appendix
(docs/decentralized-wire-formats.md sections 9, 10, 16 and 20.2) only.
"""
import base64
import hashlib
import math
import time

from harness import (Failure, Suite, b64url_json, check, commit, create_network, finalize, invite, join_request, link_view,
                     parse_time, pull_until, rfc3339, select, ssh_key, ssh_public_base64, wait_for, wait_linked,
                     datetime, timedelta, timezone)

suite = Suite("join", __doc__)
a, b, a2 = suite.host("alice"), suite.host("bob"), suite.host("alice2")
# A joiner whose clock the suite moves (debug-build test clock, DEC-OWN9; developer guide).
c = suite.host("clocked", start=False)
clock = c.root / "clock-offset"
c.extra_env = {"PEERSPAN_TEST_CLOCK_OFFSET_FILE": str(clock)}
c.start()
state = {}


def need(*names):
    missing = [n for n in names if n not in state]
    check(not missing, f"an earlier case did not finish ({', '.join(missing)} missing)")
    return [state[n] for n in names]


def long_invite(net_id, member):
    """An invite valid 24 hours, so it outlives the clocked joiner's jumps."""
    status, body = a.api("POST", f"/v2/networks/{net_id}/invitations", {
        "member": member, "expected_person_public_key": "-",
        "expires_at": rfc3339(datetime.now(timezone.utc) + timedelta(hours=24))})
    check(status == 201, f"invitation: {status} {body}")
    return body


def set_clock(moment):
    """Shift the clocked joiner (daemon and CLI) so that its now is MOMENT."""
    offset = math.ceil((moment - datetime.now(timezone.utc)).total_seconds())  # never short of MOMENT
    temporary = clock.with_suffix(".new")
    temporary.write_text(("-" if offset < 0 else "+") + f"{abs(offset)}s\n")
    temporary.replace(clock)


def no_secret(text, code):
    return text.replace(code, "<code>") if code else text


@suite.case("create_network", "spec 6")
def _():
    net = create_network(a, "join-suite", "alice")
    state["net"] = net
    check(net["authority"]["state"] == "usable", f"authority {net['authority']}")
    check(net["member"] == "alice" and net["name"] == "join-suite" and net["root_epoch"] == 0, f"view {net}")
    genesis = base64.b64decode(net["genesis_root_public_key"])
    check(net["id"] == "net_" + hashlib.sha256(genesis).hexdigest(), "network ID is not net_ + SHA-256 of the genesis key")
    check(net["context_id"].startswith("ctx_"), f"context {net['context_id']}")
    check(net["root_public_key"] == net["genesis_root_public_key"], "a new network's root is not its genesis key")
    members = a.api("GET", f"/v2/networks/{net['id']}/members")[1]["members"]
    check([m["host_public_key"] for m in members] == [a.public_key], f"members {members}")
    check((a.home / ".config/peerspan/person_ed25519").exists(), "create generated no person key")
    state["alice_key"] = a.home / ".config/peerspan/person_ed25519"


@suite.case("create_gives_creator_device_grant", "spec 6 creator device grant, DEC-Q21; 20 item 16")
def _():
    (net,) = need("net")
    provider = a.api("GET", f"/v2/networks/{net['id']}/provider")[1]
    members = a.api("GET", f"/v2/networks/{net['id']}/members")[1]["members"]
    check(members[0]["device_lease_id"].startswith("ds_"),
          f"the creator's host has no device grant (device_lease_id {members[0]['device_lease_id']})")
    check(provider["kind"] == "device" and provider["scopes"] == 15,
          f"provider is {provider['kind']} with scopes {provider['scopes']}, want the scope-15 creator device")


def invitation_within_one_second(net_id, seconds):
    """POST an invitation expiring SECONDS after now, retried until the request starts and finishes within one
    wall-clock second, so the daemon's decision time is the same whole second the suite used (whole UTC seconds,
    spec 4.4) and a boundary case cannot slip across a second. alice's host runs on the real clock."""
    for _ in range(10):
        now = datetime.now(timezone.utc)
        if now.microsecond > 600_000:  # too close to the next second: wait for it
            time.sleep(1.02 - now.microsecond / 1e6)
            now = datetime.now(timezone.utc)
        status, body = a.api("POST", f"/v2/networks/{net_id}/invitations", {
            "member": "x", "expected_person_public_key": "-",
            "expires_at": rfc3339(now.replace(microsecond=0) + timedelta(seconds=seconds))})
        if datetime.now(timezone.utc).replace(microsecond=0) == now.replace(microsecond=0):
            return status, body
    raise Failure("no invitation request finished within one wall-clock second in 10 tries")


@suite.case("invite_lifetime", "spec 8.1, 8.5; appendix 10.1, 16.7 (DEC-Q2, DEC-Q3)")
def _():
    (net,) = need("net")
    made = invite(a, "bob", net["id"])
    check(made["invitation"].startswith("psi2-") and made["invitation_id"].startswith("di_"), f"invite {list(made)}")
    left = (parse_time(made["expires_at"]) - datetime.now(timezone.utc)).total_seconds()
    check(3500 <= left <= 3610, f"default lifetime {left:.0f}s, want 1 hour")
    code = b64url_json(made["invitation"], "psi2-")
    payload = __import__("json").loads(base64.b64decode(code["payload_base64"]))
    check((parse_time(payload["expires_at"]) - parse_time(payload["issued_at"])).total_seconds() == 3600,
          "signed lifetime is not 3600 s")
    state["return_secret"] = payload.get("return_secret_base64")
    check(payload["member"] == "bob" and payload["descriptor"], f"payload {sorted(payload)}")
    for seconds, accepted in ((59, False), (60, True), (86400, True), (86401, False)):
        status, body = invitation_within_one_second(net["id"], seconds)
        check((status == 201) == accepted, f"lifetime {seconds}s: {status} {body if status != 201 else ''}")
        if not accepted:
            check(body.get("code") == "invalid", f"lifetime {seconds}s refused with {body}")
    longer = a.cli("invite", "x", "--network", net["id"], "--expires-in", "2h")
    check(longer.ok, f"invite --expires-in 2h: {longer.stderr.strip()[-200:]}")
    left = (parse_time(longer.json["expires_at"]) - datetime.now(timezone.utc)).total_seconds()
    check(7100 <= left <= 7210, f"--expires-in 2h gave {left:.0f}s")


@suite.case("join_new_person", "spec 8.1, 8.2, 8.4, 8.7; 20 items 28, 36, 37")
def _():
    (net,) = need("net")
    key = ssh_key(b.root, "bob")
    state["bob_key"] = key
    request = join_request(b, invite(a, "bob", net["id"])["invitation"], key)
    rid, code = request["request_id"], request["display_code"]
    state["bob_request"] = request
    # The request should reach the inviter through the invite's return path, with no code (DEC-Q3).
    try:
        wait_for(lambda: any(v["request_id"] == rid for v in a.api("GET", "/v2/link/requests")[1]), timeout=5)
        state["returned"] = True
    except AssertionError:
        state["returned"] = False
    check(rid.startswith("link_") and request["mode"] == "new" and request["role"] == "requester", f"request {request}")
    window = (parse_time(request["expires_at"]) - parse_time(request["created_at"])).total_seconds()
    check(window == 3600, f"request window {window:.0f}s, want created_at + 3600")
    check(request["person_public_key"] == ssh_public_base64(key), "request names another person key")
    b.ok_incomplete("link", "approve", "--network", net["id"], "--person-key", key, "--code-stdin", "--approve",
                    input=code + "\n")
    view = pull_until(b, rid, "owner_offer_id")
    state["bob_single_offer_state"] = view["state"]
    if view["state"] == "needs_selection":
        select(b, view)
    b.restart(kill=True)  # crash after selection: the same request continues (8.7)
    view = link_view(b, rid)
    check(view["selection_id"].startswith("dpk_"), f"selection lost across a restart: {view['selection_id']}")
    a.ok_incomplete("link", "admit", "--network", net["id"], "--owner-offer", view["owner_offer_id"], "--selection",
                    view["selection_id"], "--person", view["person_public_key"], "--expect-host-key",
                    view["host_public_key"], "--expect-device-key", view["device_public_key"], "--code-stdin",
                    "--approve", input=code + "\n")
    a.restart(kill=True)  # crash after the administrator stage
    view = pull_until(b, rid, "administrator_offer_id")
    finalize(b, view, key)
    view = pull_until(b, rid, "owner_finalization_id")
    check(view["state"] == "needs_commit" and not view["commit_approved"], f"before commit: {view['state']}")
    # The one consent prompt: blank means no (8.4).
    declined = b.cli("link", "resume", rid, tty=True, input="\n", timeout=60)
    check(not declined.ok, "a blank answer at commit exited 0")
    check("Commit this exact machine link?" in declined.stderr + declined.stdout,
          f"no commit prompt: {no_secret(declined.stderr[-300:], code)}")
    view = link_view(b, rid)
    check(view["state"] == "needs_commit" and not view["commit_approved"], f"blank answer changed state: {view['state']}")
    check(b.api("GET", "/v2/networks")[1] == [], "a declined commit applied the network")
    accepted = b.cli("link", "resume", rid, tty=True, input="yes\n", timeout=60)
    check(accepted.ok, f"answering yes: exit {accepted.code}: {no_secret(accepted.stderr[-300:], code)}")
    wait_linked(b, a, rid)
    view = link_view(b, rid)
    check(view["completed"][-1] == "locally_applied" and view["activation_id"].startswith("da_"), f"linked {view}")
    members = {m["host_public_key"]: m for m in a.api("GET", f"/v2/networks/{net['id']}/members")[1]["members"]}
    check(b.public_key in members and members[b.public_key]["member"] == "bob", "alice does not list bob's host")
    check(members[b.public_key]["person_public_key"] == ssh_public_base64(key), "bob's host is bound to another person")
    networks = b.api("GET", "/v2/networks")[1]
    check(len(networks) == 1 and networks[0]["id"] == net["id"], f"bob's networks {networks}")
    check(networks[0]["authority"]["state"] == "usable", f"bob's authority {networks[0]['authority']}")
    check(networks[0]["provider"]["kind"] == "device" and networks[0]["provider"]["scopes"] == 7,
          f"bob's provider {networks[0]['provider']} (new person default scopes 7)")
    state["bob_joined"] = True


@suite.case("join_request_returns_without_code", "spec 8.1 step 4 (DEC-Q3); appendix 10.1; 20 item 29", known="DEC-Q3")
def _():
    secret, returned = need("return_secret", "returned")
    check(secret and len(base64.b64decode(secret)) == 16, "the invite payload carries no 16-byte return_secret_base64")
    check(returned, "the inviter never received the join request through the invite's return path; "
                    "join printed a psl2- code at once")


@suite.case("single_offer_selected_without_prompt", "spec 8.4 (DEC-S5, DEC-Q5); 20 item 34")
def _():
    (seen,) = need("bob_single_offer_state")
    check(seen != "needs_selection", "with exactly one owner offer the request still waited in needs_selection "
                                      "(link resume asks 'Select this exact owner offer?')")


@suite.case("link_second_machine", "spec 8.1 (link), 8.2, 8.7")
def _():
    net, key = need("net", "alice_key")
    person = net["person_public_key"]
    request = a2.cli("link", "--network", net["id"], "--expect-person", person, timeout=90).json
    check(request and request.get("display_code", "").startswith("psl2-"), "link printed no psl2- request code")
    rid, code = request["request_id"], request["display_code"]
    a.ok_incomplete("link", "approve", "--network", net["id"], "--person", person, "--expect-host-key",
                    request["host_public_key"], "--expect-device-key", request["device_public_key"], "--code-stdin",
                    "--approve", "--person-key", key, input=code + "\n")
    view = pull_until(a2, rid, "owner_offer_id")
    if view["state"] == "needs_selection":
        select(a2, view)
    a2.restart(kill=True)
    view = link_view(a2, rid)
    state["folded"] = view["state"] != "needs_administrator"
    if view["state"] == "needs_administrator":
        a.ok_incomplete("link", "admit", "--network", net["id"], "--owner-offer", view["owner_offer_id"], "--selection",
                        view["selection_id"], "--person", person, "--expect-host-key", view["host_public_key"],
                        "--expect-device-key", view["device_public_key"], "--code-stdin", "--approve",
                        "--person-key", key, input=code + "\n")
        view = pull_until(a2, rid, "administrator_offer_id")
        a.ok_incomplete("link", "finalize", rid, "--network", net["id"], "--context", view["context_id"],
                        "--expect-person", person, "--expect-host-key", view["host_public_key"],
                        "--expect-device-key", view["device_public_key"], "--owner-offer", view["owner_offer_id"],
                        "--selection", view["selection_id"], "--administrator-offer", view["administrator_offer_id"],
                        "--approve", "--person-key", key)
    a.restart(kill=True)
    view = pull_until(a2, rid, "owner_finalization_id", timeout=40)
    commit(a2, view)
    wait_linked(a2, a, rid)
    view = link_view(a2, rid)
    state["link_view"] = view
    members = {m["host_public_key"]: m for m in a.api("GET", f"/v2/networks/{net['id']}/members")[1]["members"]}
    check(a2.public_key in members and members[a2.public_key]["person_public_key"] == person,
          "the second machine is not bound to alice's person")
    mine = a2.api("GET", "/v2/networks")[1][0]
    check(mine["person_public_key"] == person and mine["provider"]["kind"] == "device", f"alice2 view {mine['provider']}")
    check(mine["provider"]["scopes"] == 15, f"admitted owner's default scopes {mine['provider']['scopes']}, want 15")
    check(not (a2.home / ".config/peerspan/person_ed25519").exists(), "linking generated an original key on alice2")


@suite.case("owner_admin_link_folds_admin_stage", "spec 8.2 fold (DEC-S7, DEC-Q4); 20 item 35")
def _():
    view, folded = need("link_view", "folded")
    check(folded and view["administrator_offer_id"] == "-",
          "alice (root and admin) linking her own machine still needed a separate administrator stage "
          f"(administrator_offer_id {view['administrator_offer_id'][:12]}...)")


@suite.case("refuse_bad_codes", "spec 8.1, 8.5; appendix 10, 16.1")
def _():
    (net,) = need("net")
    key = ssh_key(c.root, "carol")
    state["carol_key"] = key
    before = c.api("GET", "/v2/link/requests")[1]
    garbage = c.cli("join", "--invite-stdin", "--person-key", key, input="psi2-AAAA\n")
    check(not garbage.ok and "invalid" in garbage.stderr, f"garbage invite: {garbage}")
    # An invite pinned to another person key.
    other = ssh_key(c.root, "other")
    status, pinned = a.api("POST", f"/v2/networks/{net['id']}/invitations", {
        "member": "carol", "expected_person_public_key": ssh_public_base64(other),
        "expires_at": rfc3339(datetime.now(timezone.utc) + timedelta(hours=1))})
    check(status == 201, f"pinned invite: {status} {pinned}")
    mismatch = c.cli("join", "--invite-stdin", "--person-key", key, input=pinned["invitation"] + "\n")
    check(not mismatch.ok and not (mismatch.json or {}).get("request_id"), "a join with a key the invite does not pin "
          "created a request")
    check(c.api("GET", "/v2/link/requests")[1] == before, "refused joins left join requests behind")
    # A request code approved for the wrong network.
    request = join_request(c, invite(a, "carol", net["id"])["invitation"], key)
    refused = a.cli("link", "admit", "--network", "net_" + "0" * 64, "--owner-offer", "dpk_" + "0" * 64, "--selection",
                    "dpk_" + "0" * 64, "--code-stdin", input=request["display_code"] + "\n")
    check(not refused.ok, "a request code was accepted for another network")


@suite.case("expired_invite_refused", "spec 8.1, 8.5; appendix 10.1; 20 item 32; test clock")
def _():
    net, key = need("net", "carol_key")
    made = invite(a, "carol", net["id"])
    expires = parse_time(made["expires_at"])
    set_clock(expires - timedelta(seconds=1))
    last = c.cli("join", "--invite-stdin", "--person-key", key, input=made["invitation"] + "\n")
    check((last.json or {}).get("request_id"), f"join at expires_at - 1 s: exit {last.code} {last.stderr.strip()[-200:]}")
    made = invite(a, "carol", net["id"])  # a fresh invite: re-joining the first one resumes its request
    expires = parse_time(made["expires_at"])
    set_clock(expires)
    late = c.cli("join", "--invite-stdin", "--person-key", key, input=made["invitation"] + "\n")
    check(not late.ok and "expired" in late.stderr and not (late.json or {}).get("request_id"),
          f"join at expires_at: exit {late.code} {late.stderr.strip()[-200:]}")
    state["clock_at"] = expires


@suite.case("stage_inactivity_limit", "spec 8.5 (600 s per stage); 20 item 33; test clock", known="spec 8.5")
def _():
    net, key, start = need("net", "carol_key", "clock_at")
    # The clock only moves forward, so the 600 s case comes first, on a fresh request.
    made = long_invite(net["id"], "carol")
    set_clock(start)
    first = join_request(c, made["invitation"], key)
    set_clock(start + timedelta(seconds=600))
    c.ok_incomplete("link", "approve", "--network", net["id"], "--person-key", key, "--code-stdin", "--approve",
                    input=first["display_code"] + "\n")
    check(link_view(c, first["request_id"])["owner_offer_id"].startswith("dpk_"), "a stage at 600 s was not signed")
    made = long_invite(net["id"], "carol")
    second = join_request(c, made["invitation"], key)
    made_at = parse_time(second["created_at"])
    check(abs((made_at - start).total_seconds() - 600) <= 2, f"second request created at {second['created_at']}")
    set_clock(made_at + timedelta(seconds=601))
    late = c.cli("link", "approve", "--network", net["id"], "--person-key", key, "--code-stdin", "--approve",
                 input=second["display_code"] + "\n")
    view = link_view(c, second["request_id"])
    check(view["owner_offer_id"] == "-", f"the owner offer was signed 601 s after the request (created "
                                         f"{second['created_at']}); want refusal and state expired, got {view['state']}")
    check(view["state"] == "expired", f"request state {view['state']} after the 601 s refusal, want expired")


suite.finish()
