#!/usr/bin/env python3
"""Scoped MCP sends and automatic replies across every Go/Rust pairing."""

import argparse
import concurrent.futures
import json
from pathlib import Path
import subprocess
import tempfile
import time

from agent_adapter import Channel, adapter_call, credential, sql
from host_service import ARTIFACT_TABLES, DELEGATION_TABLES, POLICY_DELIVERY_TABLES, TASK_TABLES
from peer_messaging import PeerHost, request_id, timestamp, DropResponse
from coordination import Coordinator, CoordHost


def route(
    host,
    secret,
    peer,
    agent,
    grant,
    name="remote",
    budget=100,
    size=65536,
    expiration=None,
):
    return host.cli(
        "adapter",
        "route",
        "add",
        "--adapter",
        secret["adapter"]["id"],
        "--name",
        name,
        "--peer",
        peer["id"],
        "--agent",
        agent["id"],
        "--grant",
        grant["id"],
        "--expires-at",
        expiration or timestamp(900),
        "--max-messages",
        str(budget),
        "--max-message-bytes",
        str(size),
    )


def send(host, secret, content="hello", name="remote", rid=None, timeout=3):
    return adapter_call(
        host,
        secret["token"],
        "POST",
        "/adapter/v1/send",
        {"destination": name, "request_id": rid or request_id(), "content": content},
        timeout=timeout,
    )


def wait_for(check, seconds=10):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        value = check()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("condition timed out")


def check(go, rust, node, label):
    script = (
        Path(__file__).resolve().parents[1] / "integrations/claude-channel/channel.mjs"
    )
    with tempfile.TemporaryDirectory(prefix="capsule-outbound-") as directory:
        root = Path(directory)
        a, b, c = (
            PeerHost(go, root / "a"),
            PeerHost(rust, root / "b"),
            PeerHost(rust, root / "c"),
        )
        ca = cb = None
        try:
            ai, bi = a.start(), b.start()
            a.configure(b, bi)
            b.configure(a, ai)
            aa = a.cli("agent", "register", "--name", "alice", "--owner", "alice")
            ba = b.cli("agent", "register", "--name", "bob", "--owner", "bob")
            other = a.cli("agent", "register", "--name", "other", "--owner", "alice")
            ass = a.cli(
                "session", "attach", "--agent", aa["id"], "--integration", "test"
            )
            bss = b.cli(
                "session", "attach", "--agent", ba["id"], "--integration", "test"
            )
            oss = a.cli(
                "session", "attach", "--agent", other["id"], "--integration", "test"
            )
            ac, bc, oc = credential(a, ass), credential(b, bss), credential(a, oss)
            ag, bg = a.grant(bi, aa), b.grant(ai, ba)
            assert send(a, ac)[0] == 403
            r = route(a, ac, bi, ba, bg)
            reverse = route(b, bc, ai, aa, ag)
            assert a.cli(
                "adapter", "route", "list", "--adapter", ac["adapter"]["id"]
            ) == [r]
            body = {
                key: value
                for key, value in r.items()
                if key not in ("id", "revoked_at")
            }
            assert a.call("POST", "/v1/adapter-routes", body)[0] == 409
            for fields in [
                {"name": "Bad"},
                {"name": "-bad"},
                {"max_messages": 0},
                {"max_messages": 10001},
                {"max_message_bytes": 65537},
                {"expires_at": timestamp(1300)},
                {"extra": "invalid"},
            ]:
                assert (
                    a.call("POST", "/v1/adapter-routes", {**body, **fields})[0] == 400
                )
            assert (
                adapter_call(a, oc["token"], "GET", "/adapter/v1/destinations")[1] == []
            )
            assert send(a, oc)[0] == 403
            assert (
                adapter_call(a, ac["token"], "GET", "/adapter/v1/destinations")[1][0][
                    "messages_remaining"
                ]
                == 100
            )
            for raw in [
                "null",
                '{"destination":"remote","content":"hi","request_id":null}',
                '{"destination":"remote","content":"hi","request_id":"bad"}',
                "{} {}",
                '{"destination":"remote","request_id":"'
                + request_id()
                + '","content":"hi","peer_host_id":"bad"}',
            ]:
                assert (
                    adapter_call(a, ac["token"], "POST", "/adapter/v1/send", raw=raw)[0]
                    == 400
                )
            assert (
                adapter_call(a, ac["token"], "POST", "/v1/adapter-routes", {})[0] == 404
            )

            ca = Channel(node, script, a, ac, root / "ca")
            cb = Channel(node, script, b, bc, root / "cb")
            destinations = ca.call(
                "tools/call", {"name": "list_destinations", "arguments": {}}
            )
            assert json.loads(destinations["content"][0]["text"])[0]["name"] == "remote"
            result = ca.call(
                "tools/call",
                {
                    "name": "send",
                    "arguments": {"destination": "remote", "content": "from agent A"},
                },
            )
            assert not result.get("isError"), result
            sent = json.loads(result["content"][0]["text"])
            assert sent["state"] == "accepted"
            request = cb.notification()
            assert (
                request["meta"]["kind"] == "message"
                and request["content"] == "from agent A"
            )
            # The route's session is the origin; these hosts are unbound.
            assert request["meta"]["origin_agent_id"] == aa["id"], request
            assert request["meta"]["origin_session_id"] == ass["id"], request
            # Null fields are absent from Claude channel meta.
            assert "sender_person_id" not in request["meta"], request
            assert "sender_person" not in request["meta"], request
            assert not cb.reply(
                request["meta"]["delivery_id"], "reply from agent B"
            ).get("isError")
            notification = ca.notification()
            assert (
                notification["meta"]["kind"] == "reply"
                and notification["content"] == "reply from agent B"
            )
            assert notification["meta"]["request_id"] == sent["request_id"]
            assert notification["meta"]["session_id"] == ass["id"]
            assert "delivery_id" not in notification["meta"]
            # The reply names the remote agent and session that replied.
            assert notification["meta"]["origin_agent_id"] == ba["id"], notification
            assert notification["meta"]["origin_session_id"] == bss["id"], notification
            assert (
                adapter_call(
                    a,
                    oc["token"],
                    "POST",
                    "/adapter/v1/replies/"
                    + notification["meta"]["notification_id"]
                    + "/forwarded",
                    {},
                )[0]
                == 404
            )
            assert ca.reply(notification["meta"]["notification_id"], "do not echo").get(
                "isError"
            )
            assert adapter_call(
                a, ac["token"], "POST", "/adapter/v1/replies/next", {}
            ) == (200, None)

            # The other real MCP client independently initiates the reverse exchange.
            result = cb.call(
                "tools/call",
                {
                    "name": "send",
                    "arguments": {"destination": "remote", "content": "from agent B"},
                },
            )
            assert not result.get("isError")
            request = ca.notification()
            assert request["meta"]["kind"] == "message"
            assert request["meta"]["origin_agent_id"] == ba["id"]
            assert request["meta"]["origin_session_id"] == bss["id"]
            assert not ca.reply(request["meta"]["delivery_id"], "reply from A").get(
                "isError"
            )
            assert cb.notification()["content"] == "reply from A"
            ca.close()
            cb.close()
            ca = cb = None

            # Concurrent stable-ID retries consume exactly one unit and one inbox message.
            rid = request_id()
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                results = list(
                    pool.map(lambda _: send(a, ac, "duplicate", rid=rid), range(6))
                )
            assert all(
                status == 200 and out["state"] == "accepted" for status, out in results
            )
            assert (
                len(
                    [
                        m
                        for m in b.cli("message", "list")
                        if m["request"]["request_id"] == rid
                    ]
                )
                == 1
            )
            assert (
                adapter_call(a, ac["token"], "GET", "/adapter/v1/destinations")[1][0][
                    "messages_remaining"
                ]
                == 98
            )
            assert send(a, ac, "changed", rid=rid)[0] == 409
            ci = c.start()
            a.configure(c, ci)
            route(a, ac, ci, ba, bg, name="other-host")
            assert send(a, ac, "duplicate", name="other-host", rid=rid)[0] == 409
            assert not sql(
                a, "SELECT request_id FROM adapter_outbound WHERE peer=?", (ci["id"],)
            )
            route(a, oc, bi, ba, bg)
            assert send(a, oc, "duplicate", rid=rid)[0] == 403
            # Owner-CLI operations cannot be adopted by a scoped credential.
            owned = a.submit(bi, ba, bg, content="owner request")
            assert (
                send(a, ac, "owner request", rid=owned["request"]["request_id"])[0]
                == 409
            )

            small = route(a, ac, bi, ba, bg, name="small", budget=1, size=8)
            assert send(a, ac, "x" * 9, name="small")[0] == 403
            assert send(a, ac, "ok", name="small")[1]["state"] == "accepted"
            assert send(a, ac, "another", name="small")[0] == 403
            a.cli("adapter", "route", "revoke", small["id"])
            assert send(a, ac, "ok", name="small")[0] == 403
            assert all(
                x["name"] != "small"
                for x in adapter_call(
                    a, ac["token"], "GET", "/adapter/v1/destinations"
                )[1]
            )

            # Different IDs racing for one remaining unit cannot overrun its quota.
            route(a, ac, bi, ba, bg, name="race", budget=1)
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                results = list(pool.map(lambda _: send(a, ac, name="race"), range(6)))
            assert sum(status == 200 for status, _ in results) == 1
            assert sum(status == 403 for status, _ in results) == 5

            # Atomic request + origin + quota + activity; no partial queued request.
            sql(
                a,
                "CREATE TRIGGER fail_origin BEFORE INSERT ON events WHEN NEW.kind='adapter.message_queued' BEGIN SELECT RAISE(ABORT,'injected'); END",
            )
            rid2 = request_id()
            assert send(a, ac, "atomic", rid=rid2)[0] == 500
            assert not sql(
                a,
                "SELECT request_id FROM outbound_messages WHERE request_id=?",
                (rid2,),
            )
            assert not sql(
                a, "SELECT request_id FROM adapter_outbound WHERE request_id=?", (rid2,)
            )
            sql(a, "DROP TRIGGER fail_origin")
            assert send(a, ac, "atomic", rid=rid2)[1]["state"] == "accepted"

            # Lose a real acceptance response; reply retrieval never resubmits work.
            # Keep background GETs out of this fixture's single dropped connection.
            sql(a, "UPDATE adapter_outbound SET next_poll_at=9223372036854775807")
            sql(
                a,
                "CREATE TRIGGER pause_reply_poll AFTER INSERT ON adapter_outbound BEGIN UPDATE adapter_outbound SET next_poll_at=9223372036854775807 WHERE peer=NEW.peer AND request_id=NEW.request_id; END",
            )
            time.sleep(0.3)
            lost = request_id()
            relay = DropResponse(b, lost)
            a.configure(b, bi, address=relay.address)
            # Over QUIC a lost response surfaces after the 8-second request timeout.
            assert send(a, ac, "lost receipt", rid=lost, timeout=15)[1]["state"] == "unknown"
            relay.close()
            a.configure(b, bi)
            sql(a, "DROP TRIGGER pause_reply_poll")
            sql(
                a,
                "UPDATE adapter_outbound SET next_poll_at=0 WHERE request_id=?",
                (lost,),
            )
            # Claim all outstanding messages deterministically and reply to the lost one.
            while True:
                status, h = adapter_call(b, bc["token"], "POST", "/adapter/v1/next", {})
                assert status == 200
                if h is None:
                    break
                if h["request"]["request_id"] == lost:
                    assert (
                        adapter_call(
                            b,
                            bc["token"],
                            "POST",
                            "/adapter/v1/deliveries/" + h["delivery"]["id"] + "/reply",
                            {"content": "recovered"},
                        )[0]
                        == 200
                    )
            wait_for(
                lambda: sql(
                    a, "SELECT record FROM outbound_replies WHERE request_id=?", (lost,)
                )
            )
            assert (
                len(
                    [
                        m
                        for m in b.cli("message", "list")
                        if m["request"]["request_id"] == lost
                    ]
                )
                == 1
            )
            # Reply retrieval did not resubmit it; the daemon's automatic retry
            # resolves the lost receipt with the same request ID, still one copy.
            wait_for(
                lambda: a.cli("message", "inspect", "--peer", bi["id"], lost)["state"]
                == "accepted",
                seconds=30,
            )
            assert (
                len([m for m in b.cli("message", "list") if m["request"]["request_id"] == lost])
                == 1
            )
            a.cli("adapter", "route", "revoke", r["id"])
            assert send(a, ac, "lost receipt", rid=lost)[0] == 403

            # Claim/ack rollback and an unacknowledged notification survives without redelivery.
            sql(
                a,
                "CREATE TRIGGER fail_notice BEFORE INSERT ON events WHEN NEW.kind='reply.handoff' BEGIN SELECT RAISE(ABORT,'injected'); END",
            )
            assert (
                adapter_call(a, ac["token"], "POST", "/adapter/v1/replies/next", {})[0]
                == 500
            )
            sql(a, "DROP TRIGGER fail_notice")
            status, h = adapter_call(
                a, ac["token"], "POST", "/adapter/v1/replies/next", {}
            )
            assert status == 200 and h["reply"]["content"] == "recovered"
            notice = h["delivery"]
            origin = a.cli("message", "origin", "--peer", bi["id"], lost)
            assert (
                origin["reply_delivery"] == notice and origin["session_id"] == ass["id"]
            )
            assert adapter_call(
                a, ac["token"], "POST", "/adapter/v1/replies/next", {}
            ) == (200, None)
            sql(
                a,
                "CREATE TRIGGER fail_notice_ack BEFORE INSERT ON events WHEN NEW.kind='reply.forwarded' BEGIN SELECT RAISE(ABORT,'injected'); END",
            )
            assert (
                adapter_call(
                    a,
                    ac["token"],
                    "POST",
                    "/adapter/v1/replies/" + notice["id"] + "/forwarded",
                    {},
                )[0]
                == 500
            )
            assert (
                json.loads(
                    sql(
                        a,
                        "SELECT reply_delivery FROM adapter_outbound WHERE request_id=?",
                        (lost,),
                    )[0][0]
                )["state"]
                == "unknown"
            )
            sql(a, "DROP TRIGGER fail_notice_ack")

            # Route expiry and credential withdrawal stop new sends independently.
            expiring = route(a, ac, bi, ba, bg, name="expires", expiration=timestamp(1))
            time.sleep(1.1)
            assert send(a, ac, name="expires")[0] == 403
            a.cli("adapter", "revoke", oc["adapter"]["id"])
            assert send(a, oc)[0] == 403

            a.stop(crash=True)
            b.stop(crash=True)
            a.binary, b.binary = str(rust), str(go)
            assert a.start() == ai and b.start() == bi
            assert sql(a, "PRAGMA user_version")[0][0] == 14
            assert send(a, ac)[0] == 503
            a.cli("session", "detach", ass["id"])
            assert (
                json.loads(
                    sql(
                        a,
                        "SELECT reply_delivery FROM adapter_outbound WHERE request_id=?",
                        (lost,),
                    )[0][0]
                )
                == notice
            )
            assert any(
                item["id"] == r["id"] and item["revoked_at"]
                for item in a.cli(
                    "adapter", "route", "list", "--adapter", ac["adapter"]["id"]
                )
            )
            # A fresh session gets no replies belonging to the previous session.
            ss2 = a.cli(
                "session", "attach", "--agent", aa["id"], "--integration", "test"
            )
            c2 = credential(a, ss2)
            assert adapter_call(
                a, c2["token"], "POST", "/adapter/v1/replies/next", {}
            ) == (200, None)
        finally:
            if ca:
                ca.close()
            if cb:
                cb.close()
            a.stop()
            b.stop()
            c.stop()
    print(
        label
        + ": scoped sends, budgets, ownership, MCP return path, lost receipt, rollback and restart passed",
        flush=True,
    )


def migration_check(original_binary, replacement_binary, label):
    """Reopen populated v4 state and fail halfway through its v5 extension."""
    with tempfile.TemporaryDirectory(prefix="capsule-outbound-migration-") as directory:
        root = Path(directory)
        a = PeerHost(original_binary, root / "a")
        b = PeerHost(original_binary, root / "b")
        try:
            ai, bi = a.start(), b.start()
            a.configure(b, bi)
            b.configure(a, ai)
            aa = a.cli("agent", "register", "--name", "migration", "--owner", "test")
            ba = b.cli("agent", "register", "--name", "migration", "--owner", "test")
            ac = credential(
                a,
                a.cli(
                    "session", "attach", "--agent", aa["id"], "--integration", "test"
                ),
            )
            bc = credential(
                b,
                b.cli(
                    "session", "attach", "--agent", ba["id"], "--integration", "test"
                ),
            )
            bg = b.grant(ai, ba)
            out = a.submit(bi, ba, bg)
            status, h = adapter_call(b, bc["token"], "POST", "/adapter/v1/next", {})
            assert status == 200 and h
            assert (
                adapter_call(
                    b,
                    bc["token"],
                    "POST",
                    "/adapter/v1/deliveries/" + h["delivery"]["id"] + "/reply",
                    {"content": "v4 reply"},
                )[0]
                == 200
            )
            assert (
                a.cli(
                    "message", "reply", "--peer", bi["id"], out["request"]["request_id"]
                )["state"]
                == "replied"
            )
            a.stop(crash=True)
            b.stop(crash=True)
            for host in (a, b):
                for table in [*POLICY_DELIVERY_TABLES, *DELEGATION_TABLES, *ARTIFACT_TABLES, *TASK_TABLES]:
                    sql(host, "DROP TABLE " + table)
                sql(host, "DROP TABLE access_blocks")
                sql(host, "DROP TABLE network_statements")
                sql(host, "DROP TABLE adapter_connections")
                sql(host, "DROP TABLE adapter_outbound")
                sql(host, "DROP TABLE adapter_routes")
                sql(host, "PRAGMA user_version = 4")
                # First table creation must roll back if the second fails.
                sql(host, "CREATE TABLE adapter_outbound (broken TEXT)")
                result = subprocess.run(
                    [str(replacement_binary), "--state", str(host.state), "run"],
                    capture_output=True,
                    timeout=5,
                )
                assert result.returncode != 0
                assert sql(host, "PRAGMA user_version")[0][0] == 4
                assert not sql(
                    host, "SELECT name FROM sqlite_master WHERE name='adapter_routes'"
                )
                sql(host, "DROP TABLE adapter_outbound")
                host.binary = str(replacement_binary)
            assert a.start() == ai and b.start() == bi
            assert (
                sql(a, "PRAGMA user_version")[0][0]
                == sql(b, "PRAGMA user_version")[0][0]
                == 14
            )
            assert a.cli("adapter", "list") == [ac["adapter"]] and b.cli(
                "adapter", "list"
            ) == [bc["adapter"]]
            assert (
                a.cli(
                    "message",
                    "inspect",
                    "--peer",
                    bi["id"],
                    out["request"]["request_id"],
                )
                == out
            )
            assert (
                a.cli(
                    "message", "reply", "--peer", bi["id"], out["request"]["request_id"]
                )["reply"]["content"]
                == "v4 reply"
            )
            assert (
                b.cli("delivery", "inspect", h["delivery"]["id"])["state"] == "replied"
            )
            assert (
                adapter_call(a, ac["token"], "POST", "/adapter/v1/replies/next", {})[0]
                == 403
            )
            assert (
                a.cli("adapter", "route", "list", "--adapter", ac["adapter"]["id"])
                == []
            )
        finally:
            a.stop()
            b.stop()
    print(
        label + ": populated v4→v11 migration and partial-schema rollback passed",
        flush=True,
    )


def network_check(coord_binary, sender_binary, receiver_binary, label):
    with tempfile.TemporaryDirectory(prefix="capsule-outbound-network-") as directory:
        root = Path(directory)
        coord = Coordinator(coord_binary, root / "coord")
        a = CoordHost(sender_binary, root / "a")
        b = CoordHost(receiver_binary, root / "b")
        try:
            ci = coord.start()
            ai, bi = a.start(), b.start()
            n = a.cli(
                "network",
                "create",
                "--name",
                "team",
                "--member",
                "alice",
                "--coordinator",
                coord.address,
                "--coordinator-key",
                ci["public_key"],
            )
            invite = a.cli(
                "network",
                "invite",
                "--network",
                n["id"],
                "--member",
                "bob",
                "--expires-at",
                timestamp(),
            )
            b.cli("network", "join", "--token", invite["token"])
            a.cli("network", "sync", n["id"])
            b.cli("network", "sync", n["id"])
            aa = a.cli("agent", "register", "--name", "alice", "--owner", "alice")
            ba = b.cli("agent", "register", "--name", "bob", "--owner", "bob")
            ass = a.cli(
                "session", "attach", "--agent", aa["id"], "--integration", "test"
            )
            bss = b.cli(
                "session", "attach", "--agent", ba["id"], "--integration", "test"
            )
            ac, bc = credential(a, ass), credential(b, bss)
            bg = b.cli(
                "grant",
                "create",
                "--peer",
                ai["id"],
                "--agent",
                ba["id"],
                "--expires-at",
                timestamp(1200),
            )
            route(a, ac, bi, ba, bg)
            assert a.cli("peer", "list") == [] and b.cli("peer", "list") == []
            status, out = send(a, ac)
            assert status == 200 and out["state"] == "accepted", out
            status, h = adapter_call(b, bc["token"], "POST", "/adapter/v1/next", {})
            assert status == 200 and h
            assert (
                adapter_call(
                    b,
                    bc["token"],
                    "POST",
                    "/adapter/v1/deliveries/" + h["delivery"]["id"] + "/reply",
                    {"content": "network reply"},
                )[0]
                == 200
            )
            wait_for(
                lambda: sql(
                    a,
                    "SELECT record FROM outbound_replies WHERE request_id=?",
                    (out["request"]["request_id"],),
                )
            )
            assert (
                adapter_call(a, ac["token"], "POST", "/adapter/v1/replies/next", {})[1][
                    "reply"
                ]["content"]
                == "network reply"
            )
        finally:
            a.stop()
            b.stop()
            coord.stop()
    print(
        label
        + ": enrolled peers receive automatic replies without manual peer pins passed",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--go", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--coord", type=Path, required=True)
    args = parser.parse_args()
    for a, b, label in [
        (args.go, args.go, "Go→Go"),
        (args.rust, args.rust, "Rust→Rust"),
        (args.go, args.rust, "Go→Rust"),
        (args.rust, args.go, "Rust→Go"),
    ]:
        check(a.resolve(), b.resolve(), args.node.resolve(), label)
        network_check(args.coord.resolve(), a.resolve(), b.resolve(), label)
    migration_check(args.go.resolve(), args.rust.resolve(), "Go→Rust")
    migration_check(args.rust.resolve(), args.go.resolve(), "Rust→Go")


if __name__ == "__main__":
    main()
