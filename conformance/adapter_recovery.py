#!/usr/bin/env python3
"""Adapter leases, instance continuity, rotation and populated v5 migration."""

import argparse
import concurrent.futures
from datetime import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time

from agent_adapter import Channel, adapter_call, credential, instance_for, sql
from host_service import ARTIFACT_TABLES, TASK_TABLES
from adapter_outbound import route, send, wait_for
from peer_messaging import PeerHost, timestamp


def connect(host, secret, key=None):
    return adapter_call(
        host,
        secret["token"],
        "POST",
        "/adapter/v1/connect",
        {"instance_id": key or instance_for(host, secret["token"])["instance"]},
    )


def atomic_credential(path, secret):
    temporary = path.with_suffix(".next")
    temporary.write_text(json.dumps(secret))
    temporary.chmod(0o600)
    temporary.replace(path)


def check(a_binary, b_binary, node, label):
    script = (
        Path(__file__).resolve().parents[1] / "integrations/claude-channel/channel.mjs"
    )
    with tempfile.TemporaryDirectory(prefix="capsule-recovery-") as directory:
        root = Path(directory)
        a = PeerHost(a_binary, root / "a")
        b = PeerHost(b_binary, root / "b")
        channel = None
        try:
            ai, bi = a.start(), b.start()
            a.configure(b, bi)
            b.configure(a, ai)
            aa = a.cli("agent", "register", "--name", "alice", "--owner", "alice")
            ba = b.cli("agent", "register", "--name", "bob", "--owner", "bob")
            ass = a.cli(
                "session", "attach", "--agent", aa["id"], "--integration", "test"
            )
            bss = b.cli(
                "session", "attach", "--agent", ba["id"], "--integration", "test"
            )
            ac, bc = credential(a, ass), credential(b, bss)
            other_agent = a.cli(
                "agent", "register", "--name", "other", "--owner", "alice"
            )
            other_session = a.cli(
                "session",
                "attach",
                "--agent",
                other_agent["id"],
                "--integration",
                "test",
            )
            other_secret = credential(a, other_session)
            assert (
                adapter_call(
                    a,
                    other_secret["token"],
                    "POST",
                    "/adapter/v1/connect",
                    {
                        "adapter_id": ac["adapter"]["id"],
                        "session_id": ass["id"],
                        "instance_id": instance_for(a, ac["token"])["instance"],
                    },
                )[0]
                == 403
            )
            assert (
                a.cli("adapter", "connection", other_secret["adapter"]["id"])["state"]
                == "registered"
            )
            key = instance_for(a, ac["token"])["instance"]
            assert (
                a.cli("adapter", "connection", ac["adapter"]["id"])["state"]
                == "registered"
            )
            assert (
                adapter_call(
                    a, ac["token"], "POST", "/adapter/v1/next", {}, auto_connect=False
                )[0]
                == 403
            )
            for raw in [
                "null",
                "{}",
                '{"instance_id":null}',
                '{"instance_id":"bad"}',
                '{"instance_id":"' + key + '","extra":true}',
            ]:
                assert (
                    adapter_call(
                        a, ac["token"], "POST", "/adapter/v1/connect", raw=raw
                    )[0]
                    == 400
                )
            # A failed first bind must not reserve the instance or produce readiness.
            sql(
                a,
                "CREATE TRIGGER fail_connect BEFORE INSERT ON events WHEN NEW.kind='adapter.connected' BEGIN SELECT RAISE(ABORT,'injected'); END",
            )
            assert connect(a, ac)[0] == 500
            assert sql(
                a,
                "SELECT instance_hash,lease_until_ms,recoverable FROM adapter_connections WHERE adapter_id=?",
                (ac["adapter"]["id"],),
            )[0] == (None, 0, 0)
            sql(a, "DROP TRIGGER fail_connect")
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                results = list(pool.map(lambda _: connect(a, ac), range(6)))
            assert all(status == 200 and c["state"] == "ready" for status, c in results)
            assert (
                len([e for e in a.cli("activity") if e["kind"] == "adapter.connected"])
                == 1
            )
            assert (
                sql(
                    a,
                    "SELECT instance_hash FROM adapter_connections WHERE adapter_id=?",
                    (ac["adapter"]["id"],),
                )[0][0]
                == hashlib.sha256(key.encode()).hexdigest()
            )
            assert key not in json.dumps(
                a.cli("adapter", "connection", ac["adapter"]["id"])
            )
            wrong = "instance_" + "f" * 64
            assert connect(a, ac, wrong)[0] == 409
            assert (
                adapter_call(
                    a,
                    ac["token"],
                    "GET",
                    "/adapter/v1/session",
                    instance="",
                    auto_connect=False,
                )[0]
                == 403
            )
            assert (
                adapter_call(
                    a,
                    ac["token"],
                    "GET",
                    "/adapter/v1/session",
                    instance=wrong,
                    auto_connect=False,
                )[0]
                == 403
            )
            sql(a, "UPDATE adapter_connections SET lease_until_ms=0")
            assert (
                a.cli("adapter", "connection", ac["adapter"]["id"])["state"]
                == "offline"
            )
            assert (
                adapter_call(
                    a, ac["token"], "POST", "/adapter/v1/next", {}, auto_connect=False
                )[0]
                == 503
            )
            assert connect(a, ac, wrong)[0] == 409
            assert connect(a, ac)[0] == connect(b, bc)[0] == 200

            bg = b.grant(ai, ba)
            r = route(a, ac, bi, ba, bg, budget=2)
            first = send(a, ac, "reply after restart")[1]
            d = adapter_call(b, bc["token"], "POST", "/adapter/v1/next", {})[1][
                "delivery"
            ]
            second = send(a, ac, "uncertain handoff")[1]
            unknown = adapter_call(b, bc["token"], "POST", "/adapter/v1/next", {})[1][
                "delivery"
            ]
            assert (
                d["request_id"] == first["request"]["request_id"]
                and unknown["request_id"] == second["request"]["request_id"]
            )
            channel = Channel(node, script, a, ac, root / "channel")
            pid = channel.process.pid
            a.stop(crash=True)
            b.stop(crash=True)
            a.binary, b.binary = str(b_binary), str(a_binary)
            assert a.start() == ai and b.start() == bi
            wait_for(
                lambda: a.cli("adapter", "connection", ac["adapter"]["id"])["state"]
                == "ready"
            )
            assert channel.process.pid == pid and channel.process.poll() is None
            assert (
                b.cli("adapter", "connection", bc["adapter"]["id"])["state"]
                == "offline"
            )
            assert (
                adapter_call(
                    b, bc["token"], "POST", "/adapter/v1/next", {}, auto_connect=False
                )[0]
                == 503
            )
            assert connect(b, bc, wrong)[0] == 409
            sibling = b.cli(
                "session", "attach", "--agent", ba["id"], "--integration", "test"
            )

            assert connect(b, bc)[0] == 200
            assert (
                b.call(
                    "POST",
                    "/v1/adapters",
                    {"session_id": sibling["id"], "expires_at": timestamp()},
                )[0]
                == 409
            )
            assert b.cli("session", "inspect", bss["id"])["state"] == "attached"
            assert b.cli("delivery", "inspect", unknown["id"]) == unknown
            assert adapter_call(b, bc["token"], "POST", "/adapter/v1/next", {}) == (
                200,
                None,
            )
            assert a.cli(
                "adapter", "route", "list", "--adapter", ac["adapter"]["id"]
            ) == [r]

            # Rotation is atomic and leaves authorization, limits and source IDs intact.
            before_hash = sql(
                a,
                "SELECT token_hash FROM adapter_credentials WHERE id=?",
                (ac["adapter"]["id"],),
            )[0][0]
            sql(
                a,
                "CREATE TRIGGER fail_rotate BEFORE INSERT ON events WHEN NEW.kind='adapter.credential_rotated' BEGIN SELECT RAISE(ABORT,'injected'); END",
            )
            assert (
                a.call("POST", "/v1/adapters/" + ac["adapter"]["id"] + "/rotate")[0]
                == 500
            )
            assert (
                sql(
                    a,
                    "SELECT token_hash FROM adapter_credentials WHERE id=?",
                    (ac["adapter"]["id"],),
                )[0][0]
                == before_hash
            )
            sql(a, "DROP TRIGGER fail_rotate")
            rotated = a.cli("adapter", "rotate", ac["adapter"]["id"])
            assert (
                rotated["adapter"] == ac["adapter"] and rotated["token"] != ac["token"]
            )
            assert (
                adapter_call(
                    a, ac["token"], "GET", "/adapter/v1/session", auto_connect=False
                )[0]
                == 403
            )
            assert (
                adapter_call(
                    a,
                    rotated["token"],
                    "POST",
                    "/adapter/v1/connect",
                    {"instance_id": wrong},
                )[0]
                == 409
            )
            atomic_credential(
                channel.credential_path, {**rotated, "test_instance": key}
            )

            def destinations():
                result = channel.call(
                    "tools/call", {"name": "list_destinations", "arguments": {}}
                )
                return (
                    None
                    if result.get("isError")
                    else json.loads(result["content"][0]["text"])
                )

            assert wait_for(destinations)[0]["messages_remaining"] == 0
            assert a.cli(
                "adapter", "route", "list", "--adapter", ac["adapter"]["id"]
            ) == [r]
            assert (
                adapter_call(
                    a,
                    rotated["token"],
                    "POST",
                    "/adapter/v1/send",
                    {
                        "destination": "remote",
                        "request_id": "request_" + "a" * 32,
                        "content": "over budget",
                    },
                    instance=key,
                    auto_connect=False,
                )[0]
                == 403
            )
            assert (
                adapter_call(
                    b,
                    bc["token"],
                    "POST",
                    "/adapter/v1/deliveries/" + d["id"] + "/reply",
                    {"content": "recovered original session"},
                )[0]
                == 200
            )
            event = channel.notification()
            assert (
                event["meta"]["kind"] == "reply"
                and event["meta"]["session_id"] == ass["id"]
            )
            assert (
                event["meta"]["request_id"] == first["request"]["request_id"]
                and event["content"] == "recovered original session"
            )
            assert (
                channel.process.pid == pid
                and len(sql(a, "SELECT request_id FROM adapter_outbound")) == 2
            )
            wait_for(
                lambda: json.loads(
                    sql(
                        a,
                        "SELECT reply_delivery FROM adapter_outbound WHERE request_id=?",
                        (first["request"]["request_id"],),
                    )[0][0]
                )["state"]
                == "forwarded"
            )

            other_session = a.cli(
                "session",
                "attach",
                "--agent",
                other_agent["id"],
                "--integration",
                "test",
            )
            other_secret = credential(a, other_session)
            # A token for another authorization cannot bind it under forged file IDs.
            atomic_credential(
                channel.credential_path,
                {**rotated, "token": other_secret["token"], "test_instance": key},
            )
            wait_for(
                lambda: channel.call(
                    "tools/call", {"name": "list_destinations", "arguments": {}}
                ).get("isError")
            )
            assert (
                a.cli("adapter", "connection", other_secret["adapter"]["id"])["state"]
                == "registered"
            )
            atomic_credential(
                channel.credential_path, {**rotated, "test_instance": key}
            )
            assert wait_for(destinations)[0]["messages_remaining"] == 0
            # Selecting a different session explicitly stops the channel and tools.
            atomic_credential(
                channel.credential_path, {**other_secret, "test_instance": key}
            )

            def retarget_denied():
                result = channel.call(
                    "tools/call", {"name": "list_destinations", "arguments": {}}
                )
                return (
                    result.get("isError")
                    and "different authorization or session"
                    in result["content"][0]["text"]
                )

            wait_for(retarget_denied)
            assert (
                a.cli("adapter", "connection", other_secret["adapter"]["id"])["state"]
                == "registered"
            )
            origin = a.cli(
                "message", "origin", "--peer", bi["id"], first["request"]["request_id"]
            )
            assert (
                origin["adapter_id"] == ac["adapter"]["id"]
                and origin["session_id"] == ass["id"]
                and origin["route_id"] == r["id"]
            )
            assert origin["reply_delivery"]["state"] == "forwarded"
            assert (
                adapter_call(
                    a,
                    rotated["token"],
                    "GET",
                    "/v1/outbound/"
                    + bi["id"]
                    + "/"
                    + first["request"]["request_id"]
                    + "/origin",
                    instance=key,
                    auto_connect=False,
                )[0]
                == 404
            )
            # Owner detach during the offline state is terminal, including after restart.
            b.stop(crash=True)
            b.start()
            assert (
                b.cli("adapter", "connection", bc["adapter"]["id"])["state"]
                == "offline"
            )
            b.cli("session", "detach", bss["id"])
            assert (
                b.cli("adapter", "connection", bc["adapter"]["id"])["state"]
                == "detached"
            )
            assert connect(b, bc)[0] == 403
            assert (
                b.call("POST", "/v1/adapters/" + bc["adapter"]["id"] + "/rotate")[0]
                == 403
            )
            b.stop(crash=True)
            b.start()
            assert connect(b, bc)[0] == 403
            sibling = b.cli(
                "session", "attach", "--agent", ba["id"], "--integration", "test"
            )
            fresh = credential(b, sibling)
            assert connect(b, fresh)[0] == 200
            assert adapter_call(b, fresh["token"], "POST", "/adapter/v1/next", {}) == (
                200,
                None,
            )
            assert (
                adapter_call(
                    b,
                    fresh["token"],
                    "POST",
                    "/adapter/v1/deliveries/" + unknown["id"] + "/reply",
                    {"content": "wrong session"},
                )[0]
                == 403
            )
            b.cli("adapter", "revoke", fresh["adapter"]["id"])
            assert connect(b, fresh)[0] == 403
            assert (
                b.call("POST", "/v1/adapters/" + fresh["adapter"]["id"] + "/rotate")[0]
                == 403
            )
            expiring = b.cli(
                "adapter",
                "create",
                "--session",
                sibling["id"],
                "--expires-at",
                timestamp(1),
            )
            assert connect(b, expiring)[0] == 200
            assert datetime.fromisoformat(
                b.cli("adapter", "connection", expiring["adapter"]["id"])[
                    "lease_expires_at"
                ].replace("Z", "+00:00")
            ) <= datetime.fromisoformat(
                expiring["adapter"]["expires_at"].replace("Z", "+00:00")
            )
            time.sleep(1.1)
            assert connect(b, expiring)[0] == 403
            assert (
                b.cli("adapter", "connection", expiring["adapter"]["id"])["state"]
                == "expired"
            )
            assert (
                b.call("POST", "/v1/adapters/" + expiring["adapter"]["id"] + "/rotate")[
                    0
                ]
                == 403
            )
        finally:
            if channel:
                channel.close()
            a.stop()
            b.stop()
    print(
        label
        + ": leases, instance fencing, restart, pending replies, rotation, budgets and owner withdrawal passed",
        flush=True,
    )


def replacement_check(original, replacement, node, label):
    """Creating a fresh owner-authorized session replaces a bound offline one."""
    with tempfile.TemporaryDirectory(prefix="capsule-offline-replace-") as directory:
        root = Path(directory)
        a = PeerHost(original, root / "a")
        b = PeerHost(replacement, root / "b")
        try:
            ai, bi = a.start(), b.start()
            a.configure(b, bi)
            b.configure(a, ai)
            aa = a.cli("agent", "register", "--name", "alice", "--owner", "alice")
            ba = b.cli("agent", "register", "--name", "bob", "--owner", "bob")
            old_session = a.cli(
                "session", "attach", "--agent", aa["id"], "--integration", "test"
            )
            bs = b.cli(
                "session", "attach", "--agent", ba["id"], "--integration", "test"
            )
            old, bc = credential(a, old_session), credential(b, bs)
            assert connect(a, old)[0] == connect(b, bc)[0] == 200
            bg = b.grant(ai, ba)
            ag = a.grant(bi, aa)
            old_route = route(a, old, bi, ba, bg, budget=2)
            outgoing = send(a, old, "old outbound")[1]
            b_delivery = adapter_call(b, bc["token"], "POST", "/adapter/v1/next", {})[
                1
            ]["delivery"]
            incoming = b.submit(ai, aa, ag, content="claimed in old session")
            old_delivery = adapter_call(
                a, old["token"], "POST", "/adapter/v1/next", {}
            )[1]["delivery"]
            candidate = a.cli(
                "session", "attach", "--agent", aa["id"], "--integration", "test"
            )
            body = {"session_id": candidate["id"], "expires_at": timestamp(1200)}
            status, error = a.call("POST", "/v1/adapters", body)
            assert status == 409 and "live lease until" in error["error"]
            # Ordinary lease expiry also permits replacement, while reusing the
            # old session ID remains forbidden. Inject expiry rather than sleep.
            sql(
                a,
                "UPDATE adapter_connections SET lease_until_ms=0 WHERE adapter_id=?",
                (old["adapter"]["id"],),
            )
            assert (
                a.cli("adapter", "connection", old["adapter"]["id"])["state"]
                == "offline"
            )
            assert (
                a.call(
                    "POST",
                    "/v1/adapters",
                    {"session_id": old_session["id"], "expires_at": timestamp(1200)},
                )[0]
                == 409
            )
            before = {
                table: sql(a, "SELECT * FROM " + table)
                for table in [
                    "adapter_credentials",
                    "adapter_connections",
                    "sessions",
                    "events",
                ]
            }
            # Fail after fencing the old authorization, during the new creation.
            sql(
                a,
                "CREATE TRIGGER fail_replacement BEFORE INSERT ON events WHEN NEW.kind='adapter.created' BEGIN SELECT RAISE(ABORT,'injected'); END",
            )
            assert a.call("POST", "/v1/adapters", body)[0] == 500
            for table, rows in before.items():
                assert sql(a, "SELECT * FROM " + table) == rows
            sql(a, "DROP TRIGGER fail_replacement")
            assert connect(a, old)[0] == 200
            withdrawals = []
            for action in ["detach", "revoke"]:
                agent = a.cli("agent", "register", "--name", action, "--owner", "alice")
                session = a.cli(
                    "session", "attach", "--agent", agent["id"], "--integration", "test"
                )
                secret = credential(a, session)
                assert connect(a, secret)[0] == 200
                withdrawals.append((action, agent, session, secret))
            # Restart clears leases but must leave the original instance a
            # bounded opportunity to reconnect before replacement is possible.
            a.stop(crash=True)
            a.binary = str(replacement)
            assert a.start() == ai
            restarted_at = time.monotonic()
            candidate = a.cli(
                "session", "attach", "--agent", aa["id"], "--integration", "test"
            )
            body = {"session_id": candidate["id"], "expires_at": timestamp(1200)}
            connection = a.cli("adapter", "connection", old["adapter"]["id"])
            assert connection["state"] == "offline"
            assert connection["lease_expires_at"] is None and connection["recoverable"]
            assert sql(
                a,
                "SELECT lease_until_ms FROM adapter_connections WHERE adapter_id=?",
                (old["adapter"]["id"],),
            ) == [(0,)]
            assert (
                adapter_call(
                    a, old["token"], "POST", "/adapter/v1/next", {}, auto_connect=False
                )[0]
                == 503
            )
            before = {
                table: sql(a, "SELECT * FROM " + table)
                for table in [
                    "adapter_credentials",
                    "adapter_connections",
                    "sessions",
                    "events",
                ]
            }
            status, error = a.call("POST", "/v1/adapters", body)
            assert status == 409, f"restart replacement returned {status}, expected 409"
            assert "restart reconnect window until" in error["error"]
            for table, rows in before.items():
                assert sql(a, "SELECT * FROM " + table) == rows
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                recovering = pool.submit(connect, a, old)
                replacing = pool.submit(a.call, "POST", "/v1/adapters", body)
                assert recovering.result()[0] == 200
                assert replacing.result()[0] == 409
            assert a.cli("session", "inspect", old_session["id"])["state"] == "attached"
            assert (
                a.cli("adapter", "inspect", old["adapter"]["id"])["revoked_at"] is None
            )
            # The window is independent of liveness: expiring the recovered
            # lease does not shorten it or turn it into authority for operations.
            sql(
                a,
                "UPDATE adapter_connections SET lease_until_ms=0 WHERE adapter_id=?",
                (old["adapter"]["id"],),
            )
            status, error = a.call("POST", "/v1/adapters", body)
            assert status == 409 and "restart reconnect window until" in error["error"]
            # An explicit owner withdrawal bypasses protection immediately.
            for action, agent, session, secret in withdrawals:
                if action == "detach":
                    a.cli("session", "detach", session["id"])
                else:
                    a.cli("adapter", "revoke", secret["adapter"]["id"])
                next_session = a.cli(
                    "session", "attach", "--agent", agent["id"], "--integration", "test"
                )
                next_secret = credential(a, next_session)
                assert "replaced_adapter_ids" not in next_secret
                assert (
                    connect(a, secret)[0] == 403 and connect(a, next_secret)[0] == 200
                )
            # Only bindings present at startup are protected by this window.
            new_agent = a.cli(
                "agent", "register", "--name", "post-restart", "--owner", "alice"
            )
            new_session = a.cli(
                "session", "attach", "--agent", new_agent["id"], "--integration", "test"
            )
            new_secret = credential(a, new_session)
            assert connect(a, new_secret)[0] == 200
            sql(
                a,
                "UPDATE adapter_connections SET lease_until_ms=0 WHERE adapter_id=?",
                (new_secret["adapter"]["id"],),
            )
            next_session = a.cli(
                "session", "attach", "--agent", new_agent["id"], "--integration", "test"
            )
            assert credential(a, next_session)["replaced_adapter_ids"] == [
                new_secret["adapter"]["id"]
            ]
            # A dead adapter can still be replaced after the real 15-second
            # window. At that point reconnect and create serialize normally.
            time.sleep(max(0, 15.1 - (time.monotonic() - restarted_at)))
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                recovering = pool.submit(connect, a, old)
                replacing = pool.submit(a.call, "POST", "/v1/adapters", body)
                recovered = recovering.result()
                created = replacing.result()
            if recovered[0] == 200:
                assert created[0] == 409
                assert (
                    a.cli("adapter", "inspect", old["adapter"]["id"])["revoked_at"]
                    is None
                )
                sql(
                    a,
                    "UPDATE adapter_connections SET lease_until_ms=0 WHERE adapter_id=?",
                    (old["adapter"]["id"],),
                )
                # Concurrent new setups must not repeatedly replace a credential
                # that has just been issued and has not connected yet.
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                    outcomes = list(
                        pool.map(
                            lambda _: a.call("POST", "/v1/adapters", body), range(4)
                        )
                    )
                assert [status for status, _ in outcomes].count(201) == 1
                assert [status for status, _ in outcomes].count(409) == 3
                created = next(out for out in outcomes if out[0] == 201)
            else:
                assert recovered[0] == 403 and created[0] == 201
            fresh = created[1]
            assert fresh["replaced_adapter_ids"] == [old["adapter"]["id"]]
            assert fresh["adapter"]["session_id"] == candidate["id"]
            assert (
                a.cli("adapter", "connection", old["adapter"]["id"])["state"]
                == "revoked"
            )
            assert a.cli("session", "inspect", old_session["id"])["state"] == "detached"
            assert connect(a, old)[0] == 403
            assert (
                a.call("POST", "/v1/adapters/" + old["adapter"]["id"] + "/rotate")[0]
                == 403
            )
            assert connect(a, fresh)[0] == 200
            assert a.cli("delivery", "inspect", old_delivery["id"]) == old_delivery
            assert adapter_call(a, fresh["token"], "POST", "/adapter/v1/next", {}) == (
                200,
                None,
            )
            assert (
                adapter_call(a, fresh["token"], "GET", "/adapter/v1/destinations")[1]
                == []
            )
            assert a.cli(
                "adapter", "route", "list", "--adapter", old["adapter"]["id"]
            ) == [old_route]
            assert len(sql(a, "SELECT request_id FROM adapter_outbound")) == 1
            # A final reply for old work remains owner-inspectable and never
            # becomes a notification to the replacement session.
            assert (
                adapter_call(
                    b,
                    bc["token"],
                    "POST",
                    "/adapter/v1/deliveries/" + b_delivery["id"] + "/reply",
                    {"content": "old final reply"},
                )[0]
                == 200
            )
            assert (
                a.cli(
                    "message",
                    "reply",
                    "--peer",
                    bi["id"],
                    outgoing["request"]["request_id"],
                )["reply"]["content"]
                == "old final reply"
            )
            assert adapter_call(
                a, fresh["token"], "POST", "/adapter/v1/replies/next", {}
            ) == (200, None)
            origin = a.cli(
                "message",
                "origin",
                "--peer",
                bi["id"],
                outgoing["request"]["request_id"],
            )
            assert (
                origin["adapter_id"] == old["adapter"]["id"]
                and origin["session_id"] == old_session["id"]
            )
            assert origin["reply_delivery"] is None
            assert incoming["request"]["request_id"] == old_delivery["request_id"]
            events = a.cli("activity")
            assert (
                len(
                    [
                        e
                        for e in events
                        if e["kind"] == "adapter.replaced"
                        and e["subject_id"] == old["adapter"]["id"]
                    ]
                )
                == 1
            )
            # New agent-addressed work can reach the new session normally.
            new_message = b.submit(ai, aa, ag, content="new session work")
            new_handoff = adapter_call(
                a, fresh["token"], "POST", "/adapter/v1/next", {}
            )[1]
            assert new_handoff["delivery"]["session_id"] == candidate["id"]
            assert (
                new_handoff["request"]["request_id"]
                == new_message["request"]["request_id"]
            )
            a.stop(crash=True)
            a.binary = str(original)
            assert a.start() == ai
            assert connect(a, old)[0] == 403 and connect(a, fresh)[0] == 200
            assert a.cli("delivery", "inspect", old_delivery["id"]) == old_delivery
        finally:
            a.stop()
            b.stop()
    print(
        label
        + ": offline replacement, restart grace, owner withdrawal, rollback, reconnect race and original-work isolation passed",
        flush=True,
    )


def migration(original, replacement, label):
    with tempfile.TemporaryDirectory(prefix="capsule-v5-recovery-") as directory:
        root = Path(directory)
        a = PeerHost(original, root / "a")
        b = PeerHost(original, root / "b")
        try:
            ai, bi = a.start(), b.start()
            a.configure(b, bi)
            b.configure(a, ai)
            aa = a.cli("agent", "register", "--name", "a", "--owner", "test")
            ba = b.cli("agent", "register", "--name", "b", "--owner", "test")
            ss = a.cli(
                "session", "attach", "--agent", aa["id"], "--integration", "test"
            )
            bs = b.cli(
                "session", "attach", "--agent", ba["id"], "--integration", "test"
            )
            ac, bc = credential(a, ss), credential(b, bs)
            g = b.grant(ai, ba)
            r = route(a, ac, bi, ba, g)
            out = send(a, ac)[1]
            h = adapter_call(b, bc["token"], "POST", "/adapter/v1/next", {})[1]
            assert (
                adapter_call(
                    b,
                    bc["token"],
                    "POST",
                    "/adapter/v1/deliveries/" + h["delivery"]["id"] + "/reply",
                    {"content": "persisted v5 reply"},
                )[0]
                == 200
            )
            wait_for(lambda: sql(a, "SELECT record FROM outbound_replies"))
            a.stop(crash=True)
            for table in [*ARTIFACT_TABLES, *TASK_TABLES]:
                sql(a, "DROP TABLE " + table)
            sql(a, "DROP TABLE access_blocks")
            sql(a, "DROP TABLE network_statements")
            sql(a, "DROP TABLE adapter_connections")
            sql(a, "PRAGMA user_version=5")
            rows = {
                table: sql(a, "SELECT * FROM " + table)
                for table in [
                    "adapter_credentials",
                    "adapter_routes",
                    "adapter_outbound",
                    "outbound_messages",
                    "outbound_replies",
                ]
            }
            # Fail during population, after the new connection table is created.
            sql(
                a,
                "ALTER TABLE adapter_credentials RENAME TO adapter_credentials_fixture",
            )
            sql(
                a,
                "CREATE VIEW adapter_credentials AS SELECT * FROM adapter_credentials_fixture",
            )
            result = subprocess.run(
                [str(replacement), "--state", str(a.state), "run"],
                capture_output=True,
                timeout=5,
            )
            assert result.returncode != 0 and sql(a, "PRAGMA user_version")[0][0] == 5
            assert not sql(
                a, "SELECT name FROM sqlite_master WHERE name='adapter_connections'"
            )
            sql(a, "DROP VIEW adapter_credentials")
            sql(
                a,
                "ALTER TABLE adapter_credentials_fixture RENAME TO adapter_credentials",
            )
            a.binary = str(replacement)
            assert a.start() == ai
            assert sql(a, "PRAGMA user_version")[0][0] == 10
            for table, records in rows.items():
                assert sql(a, "SELECT * FROM " + table) == records
            assert (
                a.cli("adapter", "connection", ac["adapter"]["id"])["state"]
                == "detached"
            )
            assert connect(a, ac)[0] == 403
            assert (
                a.cli(
                    "message", "reply", "--peer", bi["id"], out["request"]["request_id"]
                )["reply"]["content"]
                == "persisted v5 reply"
            )
            assert a.cli(
                "adapter", "route", "list", "--adapter", ac["adapter"]["id"]
            ) == [r]
        finally:
            a.stop()
            b.stop()
    print(
        label
        + ": populated v5→v10 migration/rollback preserves original state without substituting a session",
        flush=True,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for flag in ["go", "rust", "node"]:
        p.add_argument("--" + flag, type=Path, required=True)
    args = p.parse_args()
    go, rust, node = args.go.resolve(), args.rust.resolve(), args.node.resolve()
    for a, b, label in [
        (go, go, "Go→Go"),
        (rust, rust, "Rust→Rust"),
        (go, rust, "Go→Rust"),
        (rust, go, "Rust→Go"),
    ]:
        check(a, b, node, label)
        replacement_check(a, b, node, label)
    migration(go, rust, "Go→Rust")
    migration(rust, go, "Rust→Go")


if __name__ == "__main__":
    main()
