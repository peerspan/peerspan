#!/usr/bin/env python3
"""Slim suite, runtime_renewal: runtime rules over days of test-clock time (RUN-1 to RUN-6).

rhea creates a coordinator-free network and sam joins as another person, both on the suite's debug test clock;
rhea's host has a fake runtime (conformance/slim/fake_runtime.py, RUN-4) with the peerfs workspace `agent`, so her
runtime rule names a peerfs workspace. Two cases need days to pass: a sender whose grants lapsed, refused without
`allow_disconnected` and accepted with it, and runtime rules, `peerfs_workspaces` included, kept across an
automatic policy renewal. The rest of the runtime contract is runtime.py, runtime_policy.py, runtime_runs.py,
runtime_results.py and runtime_peerfs.py; the shared fixtures are runtime_common.py. Both cases are Rust-test
candidates if this suite's job grows past its budget.

Written from docs/runtime-task-contract.md only (cited as "runtime <section>"), with the task and coordinator-free
contracts it builds on. No VM, no KVM, no model calls.
"""
from datetime import timedelta

from harness import Suite, check, create_network, join_new_person, members, peer, rfc3339, ssh_key, wait_for
from runtime_common import (FakeRuntime, bind, need, new_task_id, policy_statement, policy_version, sign_policy,
                            state, with_runtime_rules)

suite = Suite("runtime_renewal", __doc__)
bind(suite)
clock = suite.use_clock()
DAY, HOUR = 86400, 3600
WINDOW = 75  # one 60-second renewal pass plus sync jitter (spec 7.1, 10), as in the renewal suite


def sign(allow_disconnected=False):
    """rhea's runtime rule for her host with sam as its principal. sam's person grant has lapsed with his host grant,
    so `runtime enable --for person:sam` would refuse him as no current person: the CLI signs a rule for rhea
    herself (making the policy current and the rule this host's), and the action route then names sam."""
    r, rt = need("r", "rt")
    extra = ["--peerfs-workspace", "agent"] + (["--allow-disconnected"] if allow_disconnected else [])
    result = r.cli("runtime", "enable", "--socket", str(rt.socket), "--person-key", state["rhea_key"], *extra,
                   timeout=90)
    check(result.ok, f"rhea: runtime enable: exit {result.code} {result.stderr.strip()[-300:]}")
    status, response = sign_policy(
        lambda body: with_runtime_rules(body, [dict(rule, principals=[f"person:{state['sam_pid']}"])
                                               if rule["host"] == r.id else rule
                                               for rule in body["runtime_rules"]]),
        host=r, net=state["net"], person_public=state["rhea_public"], key=state["rhea_key"])
    check(status == 200 and response.get("committed"), f"rhea: the rule naming sam: {status} {response}")
    return policy_version(r, state["rhea_public"], state["net"])


def rules():
    return policy_statement(state["r"], state["rhea_public"], state["net"])[3].get("runtime_rules")


def lapse():
    """Move the clock one step past the end of sam's grants, once."""
    if clock.offset < 4 * DAY:
        clock.set(4 * DAY + 2 * HOUR)


@suite.case("setup", "decentralized-spec 6, 8 (join --not-after); runtime Runtime administration")
def _():
    """Spec 7.1: the root renews a host grant deadline-only, without the target's consent (DEC-Q28), from 4 days
    before its end, but only while it is still current. So sam joins with host and person grants that end after
    4 days and 1 hour, which is not yet inside the root's threshold, and the clock then jumps past that end in one
    step: rhea's root never sees sam's grant both current and due, and it lapses. rhea's own 7-day grants stay
    current throughout."""
    r, s = suite.host("rhea"), suite.host("sam")
    state["rt"] = FakeRuntime("rhea").start(peerfs_workspace=["agent"])
    net = state["net"] = create_network(r, "runtime-lapse", "rhea")["id"]
    key = ssh_key(s.root, "sam")
    sam_end = clock.now().replace(microsecond=0) + timedelta(days=4, hours=1)
    join_new_person(r, s, "sam", key, net, not_after=rfc3339(sam_end))
    state["rhea_public"] = r.api("GET", f"/v2/networks/{net}")[1]["person_public_key"]
    state["rhea_key"] = r.home / ".config/peerspan/person_ed25519"
    state["rhea_pid"] = r.ok("person", "show", "--person-key", state["rhea_key"])["person_id"]
    state["sam_pid"] = s.ok("person", "show", "--person-key", key)["person_id"]
    joined = members(r, net).get(s.public_key)
    check(joined is not None and joined["not_after"] <= rfc3339(sam_end),
          f"fixture: sam's host grant on rhea's host ends {joined and joined['not_after']}, want at most "
          f"{rfc3339(sam_end)} (join --not-after)")
    s.stop()
    state.update(r=r, s=s)


@suite.case("lapsed_sender_needs_allow_disconnected", "runtime Checks step 2: a sender whose grants lapsed; "
                                                      "allow_disconnected; test clock")
def _():
    r, s = need("r", "s")
    lapse()
    sam = members(r, state["net"]).get(s.public_key)
    check(sam is None or sam["not_after"] <= rfc3339(r.now()),
          f"fixture: sam's host is still a current member on rhea's host: {sam}")
    sign()
    s.start()

    def attempt():
        body = {"task_id": new_task_id(), "executor": "runtime", "run": {"argv": ["echo", "lapsed"]},
                "deadline": rfc3339(r.now() + timedelta(minutes=30)), "input": "lapsed sender",
                "policy": {"person_id": state["rhea_pid"],
                           "version": policy_version(r, state["rhea_public"], state["net"])}}
        return peer(s, r, "POST", "/peer/v1/tasks", body)
    status, answer = attempt()
    check(status == 403, f"a lapsed sender without allow_disconnected: {status} {answer}")
    sign(allow_disconnected=True)
    status, answer = attempt()
    check(status == 200 and answer["state"] == "queued", f"a lapsed sender with allow_disconnected: {status} {answer}")


@suite.case("renewal_keeps_runtime_rules", "runtime Policy body (Renewal and edits): automatic renewal copies "
                                           "runtime_rules, peerfs_workspaces included; test clock")
def _():
    r, = need("r")
    lapse()
    version = sign(allow_disconnected=True)
    before = rules()
    check(before and before[0]["principals"] == [f"person:{state['sam_pid']}"]
          and before[0]["peerfs_workspaces"] == ["agent"], f"rhea's runtime rules {before}")
    clock.set(clock.offset + 16 * HOUR + 10 * 60)  # 7 h 50 min left on the 24-hour policy (threshold 8 h)
    wait_for(lambda: policy_version(r, state["rhea_public"], state["net"]) > version, timeout=WINDOW, interval=1,
             message="rhea's host to renew its policy automatically")
    check(rules() == before, f"runtime_rules after renewal {rules()}, want {before}")


suite.finish()
