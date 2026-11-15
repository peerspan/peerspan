#!/usr/bin/env python3
"""Slim suite, peerbox_invites: peerbox invites for new participants, and a sender whose grants lapsed (peerbox
Invitations for new participants, Checks 1; PBX-5, PBX-7, PBX-8).

alice creates a coordinator-free network and bob joins as another person, all on the suite's debug test clock;
alice's peerbox serves a Git fixture repository whose `main` is the protected branch, shared with bob. dan and erin
join through alice's peerbox invites (`peerbox join` on a terminal and `join`), and gus through an invite to bob's
own peerbox, whose share waits for bob's SSH person key. Then the test clock: an invite expiring one hour on ends its
pending share; fay joins through a cancelled invite with grants that end after four days, gets membership and no
access, and is stopped; after a jump of four days (which lapses alice's own policy too, renewed with `access renew`)
a rule for fay is refused without `allow_disconnected` and accepted with it. The rules themselves are
peerbox_rules.py; the shared fixtures are peerbox_common.py and peerbox_fixtures.py.

Written from docs/peerbox-contract.md only (cited as "peerbox <section>"), with the runtime task, task, artifact and
coordinator-free contracts it extends. No VM, no KVM, no model calls.
"""
from datetime import timedelta

from harness import Suite, attention, check, members, rfc3339, ssh_key, wait_for
from runtime_common import (bind, learn, need, policy_statement, policy_version, refused, run_side_by_side,
                            sign_policy, state)
from peerbox_fixtures import owner_repo
from peerbox_common import (DEFAULT_BUNDLE, REASON, Prompted, admit_waiting, commit_files, create, init_repo,
                            invite_code, join_with_code, op_ok, owner_cli, pbx_rules, peerbox_network,
                            pending_shares, person_id, principal, raw_op, rev, rule, rules_for, settle, share, tail,
                            with_peerbox_rules)

suite = Suite("peerbox_invites", __doc__)
bind(suite)
clock = suite.use_clock()
DAY, HOUR = 86400, 3600


def case(name, spec, known=REASON):
    return suite.case(name, spec, known=known)

def pbx():
    return need("pbx")[0]

@suite.case("setup", "decentralized-spec 6, 8 (create, join); a Git fixture repository; peerbox CLI create and share")
def _():
    peerbox_network(suite, ("bob",))
    owner = owner_repo(suite.work / "alice-repo")
    state.update(repo=owner["repo"], main=owner["main"])
    state["pbx"] = create(state["repo"], title="Alice's project")
    share(pbx(), state["bob_p"], actions=("read", "submit"), extra=("--max-pending", "2", "--max-bundle-bytes",
                                                                    "65536"))


# Invitations (peerbox Invitations for new participants).

@case("invite_code_and_refusals", "peerbox Invitations 1, 2: the psb1- code; a code as an argument refused; a "
                                  "member refused; the pending share kept across a home restart", known=None)
def _():
    a, b = need("a", "b")
    code, inner, invitation = invite_code(pbx(), "dan", "--action", "read", "--action", "submit", "--max-pending",
                                          "2")
    check(set(inner) == {"invite", "peerbox_id", "title", "home_host_id", "actions"}
          and inner["invite"].startswith("psi2-") and inner["peerbox_id"] == pbx() and inner["home_host_id"] == a.id
          and inner["title"] == "Alice's project"
          and inner["actions"] == ["peerbox.read", "peerbox.submit"], f"psb1 body {inner}")
    check(invitation and invitation in pending_shares(), "peerbox invite --list does not show the pending share")
    d = state["d"] = suite.host("dan")
    for argv in (("peerbox", "join", code), ("join", code)):
        result = d.cli(*argv, timeout=60)
        check(not result.ok, f"`{argv[0]} {argv[1]} CODE` was accepted as a command argument")
    check(not d.api("GET", "/v2/link/requests")[1], "a refused code made a join request")
    for argv in (("peerbox", "join", "--invite-stdin"), ("join", "--invite-stdin", "--person-key", state["bob_key"])):
        result = b.cli(*argv, input=code + "\n", timeout=60)
        check(not result.ok and "peerbox share" in result.stdout + result.stderr,
              f"a member's `{' '.join(argv[:2])}` with a peerbox code: exit {result.code} {tail(result.stderr)}")
    a.restart()
    check(invitation in pending_shares(), "the pending share was lost across a restart of the home host")
    state.update(dan_code=code, dan_invitation=invitation)


@case("invite_join", "peerbox Invitations 2 to 5: peerbox join and join accept the code; the rule signed for "
                     "exactly the admitted person; other rules unchanged; the joiner lists and fetches", known=None)
def _():
    a, d, code, net = need("a", "d", "dan_code", "net")
    e = state["e"] = suite.host("erin")
    erin_code, _, erin_invitation = invite_code(pbx(), "erin")
    before = pbx_rules()
    state["erin_key"], state["dan_key"] = ssh_key(e.root, "erin"), ssh_key(d.root, "dan")
    joined = {}

    def dan():
        run = Prompted(d, "--json", "peerbox", "join", "--invite-stdin", "--repository", d.root / "repo", "--as",
                       "dan", "--person-key-file", need("dan_key")[0], first_line=code)
        admit_waiting(a, d)
        joined["dan"] = (run.wait(240), run.text)
    run_side_by_side((dan, (), {}), (join_with_code, (a, e, erin_code, need("erin_key")[0], net), {}))
    check(joined["dan"][0] == 0, f"peerbox join exited {joined['dan'][0]}")
    state["dan_pid"] = person_id(d, need("dan_key")[0])
    state["erin_pid"] = person_id(e, need("erin_key")[0])
    wait_for(lambda: rules_for(pbx(), principal(need("erin_pid")[0])), timeout=60, message="erin's rule")
    dan_rules, erin_rules = rules_for(pbx(), principal(need("dan_pid")[0])), rules_for(pbx(), principal(need("erin_pid")[0]))
    check(len(dan_rules) == 1 and dan_rules[0]["actions"] == ["peerbox.read", "peerbox.submit"]
          and dan_rules[0]["max_pending"] == 2 and dan_rules[0]["max_bundle_bytes"] == DEFAULT_BUNDLE,
          f"dan's rule {dan_rules}")
    check(len(erin_rules) == 1 and erin_rules[0]["actions"] == ["peerbox.read"] and erin_rules[0]["max_pending"] == 0,
          f"erin's rule {erin_rules}")
    strip = {principal(need("dan_pid")[0]), principal(need("erin_pid")[0])}
    after = [dict(r, principals=[p for p in r["principals"] if p not in strip]) for r in pbx_rules()]
    check([r for r in after if r["principals"]] == before, "an invitation changed another principal's rule")
    check(rev(d.root / "repo", f"refs/peerbox/{pbx()}/main") == state["main"], "peerbox join --repository fetched "
                                                                               "nothing")
    value, _, _ = op_ok({"op": "list"}, sender=e)
    check(pbx() in [x["peerbox_id"] for x in value["peerboxes"]], "erin does not list the peerbox")
    op_ok({"op": "fetch", "peerbox_id": pbx()}, sender=e)
    listed = pending_shares()
    check(need("dan_invitation")[0] not in listed and (erin_invitation or "-") not in listed, "a signed share is "
                                                                                           "still pending")


def select_provider(host, net, person_public, provider_id):
    """Select a person's provider on HOST (decentralized-spec 11, `POST /v2/networks/{id}/provider`)."""
    status, value = host.api("POST", f"/v2/networks/{net}/provider", {
        "provider_id": provider_id, "person_public_key": person_public, "host_public_key": host.public_key,
        "approve": True})
    check(status == 200 and value["provider"]["person_public_key"] == person_public,
          f"{host.name}: selecting provider {provider_id}: {status} {value}")
    return value["provider"]


def waited_and_signed(a, b, net, bpbx, code, invitation):
    g = suite.host("gus")
    key = ssh_key(g.root, "gus")
    join_with_code(a, g, code, key, net)
    gus = principal(person_id(g, key))

    def waiting():
        kinds, body = attention(b)
        return [i for i in body.get("attention") or [] if i.get("kind") == "peerbox_share_waiting"
                and f"peerbox share --pending {invitation}" in str(i.get("command"))]
    wait_for(waiting, timeout=60, message="peerbox_share_waiting on bob's host")
    b.restart()
    check(waiting() and invitation in pending_shares(host=b)
          and not rules_for(bpbx, gus, host=b, person_public=state["bob_public"]),
          "the waiting share was lost across a restart, or signed without the owner")
    owner_cli("share", "--pending", invitation, "--person-key", state["bob_key"], host=b)
    found = rules_for(bpbx, gus, host=b, person_public=state["bob_public"])
    check(len(found) == 1 and found[0]["actions"] == ["peerbox.read"] and not waiting()
          and invitation not in pending_shares(host=b), f"gus's rule {found}")
    learn(g, state["bob_public"], policy_version(b, state["bob_public"]))
    value, _, _ = op_ok({"op": "list"}, sender=g, receiver=b)
    check([x["peerbox_id"] for x in value["peerboxes"]] == [bpbx], f"gus's list {value}")


@case("share_waiting_for_owner", "peerbox Invitations 4: with the owner's provider an SSH person key, "
                                 "peerbox_share_waiting, kept across a restart, completed by peerbox share --pending", known=None)
def _():
    a, b, net = need("a", "b", "net")
    brepo = init_repo(suite.work / "bob-repo")
    commit_files(brepo, {"tool.sh": "echo tool\n"}, "tool")
    bpbx = create(brepo, host=b, title="Bob's tools")
    code, _, invitation = invite_code(bpbx, "gus", host=b)
    # A device provider with a host-held seed signs the share automatically; an SSH person key needs the owner. The
    # suite's hosts use device providers, so bob selects his original SSH key, and gets his device back afterwards.
    device = b.api("GET", f"/v2/networks/{net}")[1]["provider"]
    check(device["kind"] == "device" and device.get("lease_id"), f"fixture: bob's selected provider {device}")
    check(select_provider(b, net, state["bob_public"], state["bob_public"])["kind"] == "original_person",
          "bob's original SSH person key is not his selected provider")
    try:
        waited_and_signed(a, b, net, bpbx, code, invitation)
    finally:
        select_provider(b, net, state["bob_public"], device["lease_id"])


# Test-clock cases last: they move every host ahead, and fay is stopped, her grants left to lapse.

@case("invite_expired_and_cancelled", "peerbox Invitations: a share ending with its invite's expiry (test clock); "
                                      "a cancelled share giving membership and no access", known=None)
def _():
    a, net = need("a", "net")
    _, _, late = invite_code(pbx(), "late", "--expires-in", "1h")
    check(late in pending_shares(), "the pending share is not listed")
    clock.set(clock.offset + 2 * HOUR)
    wait_for(lambda: late not in pending_shares(), timeout=30, message="the expired pending share to end")
    f = state["f"] = suite.host("fay")
    state["fay_key"] = ssh_key(f.root, "fay")
    code, _, invitation = invite_code(pbx(), "fay", "--action", "read")
    owner_cli("invite", "--cancel", invitation)
    check(invitation not in pending_shares(), "a cancelled pending share is still listed")
    state["fay_offset"] = clock.offset
    join_with_code(a, f, code, need("fay_key")[0], net, not_after=rfc3339(clock.now() + timedelta(days=4, hours=1)))
    state["fay_pid"] = person_id(f, need("fay_key")[0])
    check(f.public_key in members(a, net), "fay is not a member")
    settle(3)
    check(not rules_for(pbx(), principal(need("fay_pid")[0])), "a cancelled share granted fay a rule")
    status, body = raw_op({"op": "fetch", "peerbox_id": pbx()}, sender=f)
    refused(status, body, 404, "unknown")
    f.stop()  # fay's grants are left to lapse (lapsed_sender)


@case("lapsed_sender", "peerbox Checks 1: a sender whose grants lapsed (test clock), refused without "
                       "allow_disconnected and accepted with it", known=None)
def _():
    a, f = need("a", "f")
    clock.set(need("fay_offset")[0] + 4 * DAY + 2 * HOUR)
    fay = principal(need("fay_pid")[0])
    # The jump lapses alice's own policy too: it lasts at most 24 hours with no grace (decentralized-spec 4.4), and
    # automatic renewal skips a policy already expired; only `access renew` revives it (coordination contract,
    # Expired policies; launch contract, policy_expired). Fay's grants stay lapsed.
    renewed = a.cli("access", "renew", "--network", state["net"], "--person-key", state["alice_key"], timeout=60)
    check(renewed.ok, f"access renew after alice's policy expired: exit {renewed.code} {tail(renewed.stderr)}")
    policy_statement(a, state["alice_public"])  # alice's policy is current again (fails with 404 otherwise)

    def sign(allow):
        status, response = sign_policy(lambda body: with_peerbox_rules(body, [
            r for r in pbx_rules() if fay not in r["principals"]] + [rule(pbx(), [fay], allow_disconnected=allow)]))
        check(status == 200 and response.get("committed"), f"the rule for fay: {status} {response}")
    sign(False)
    f.start()
    status, body = raw_op({"op": "fetch", "peerbox_id": pbx()}, sender=f)
    refused(status, body, 404, "unknown")
    sign(True)
    status, body = raw_op({"op": "fetch", "peerbox_id": pbx()}, sender=f)
    check(status == 200 and body.get("state") == "queued", f"a lapsed sender with allow_disconnected: {status} {body}")


suite.finish()
