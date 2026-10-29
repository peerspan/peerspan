#!/usr/bin/env python3
"""Owner-local onboarding observation (GU-01a/GU-02a).

Written independently from docs/guided-session-contract.md, the public status,
linking and adapter contracts, and existing slim fixtures. All authority and
consent are established through public commands. SQLite is inspected read-only
for the bounded no-write check; protocol records are never changed.

Snapshot atomicity has indirect black-box coverage. Legacy history has no public
creation fixture here. Real existing-session model receipt, cross-machine
reachability and the future interactive frontend require separate live checks.
Each automatic return uses an independent inviter with one invitation; concurrent
return contention and transport retry behavior require separate transport checks.
"""
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import sqlite3
import ssl
import subprocess
from contextlib import closing
from datetime import datetime, timedelta, timezone

from harness import (Adapter, Failure, Suite, check, create_network, invite, join_new_person,
                     join_request, rfc3339, ssh_key, wait_for)

suite = Suite("onboarding", __doc__)
a, b, c = suite.host("alice"), suite.host("bob"), suite.host("carol")
state = {}
secrets = []
TOP = {"version", "observed_at", "host_id", "networks", "agents", "requests", "attention"}
SESSION = {"id", "integration", "adapter_id", "connection", "expires_at", "renewable"}
CONNECTION = {"adapter_id", "session_id", "state", "recoverable", "lease_expires_at",
              "last_seen_at", "channel", "channel_verified_at", "protocol_version"}
PRIVATE = {"invitation", "display_code", "token", "instance_id", "private_key", "secret", "seed",
           "pairing_secret", "pairing_secret_base64", "return_secret_base64", "template_base64",
           "message_base64", "signing_requests", "request_packet", "owner_packet", "selection_packet",
           "administrator_packet", "commit_packet", "approval"}


def need(*names):
    check(all(n in state for n in names), "an earlier onboarding fixture did not finish")
    return [state[n] for n in names]


def get(host, path):
    status, body = host.api("GET", path, timeout=10)
    check(status == 200, f"{host.name} GET {path}: HTTP {status}")
    return body


def no_private(value):
    if isinstance(value, dict):
        check(not PRIVATE.intersection(value), "private fields appeared in the observation")
        for item in value.values():
            no_private(item)
    elif isinstance(value, list):
        for item in value:
            no_private(item)


def observation(host, value=None):
    began = datetime.now(timezone.utc)
    value = get(host, "/v1/onboarding") if value is None else value
    ended = datetime.now(timezone.utc)
    check(isinstance(value, dict) and set(value) == TOP, "onboarding top-level shape differs from contract")
    check(type(value["version"]) is int and value["version"] == 1, "observation format version is not integer 1")
    check(value["host_id"] == host.id, "observation identifies a different host")
    text = value["observed_at"]
    check(isinstance(text, str) and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)", text),
        "observed_at is not UTC RFC3339")
    moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    check(began - timedelta(seconds=2) <= moment <= ended + timedelta(seconds=2),
          "observed_at does not describe this read")
    for field in ("networks", "agents", "requests", "attention"):
        check(isinstance(value[field], list), f"{field} is not an array")
    check(value["networks"] == sorted(value["networks"], key=lambda x: x["id"]), "network ordering")
    check(value["requests"] == sorted(value["requests"], key=lambda x: x["request_id"]), "request ordering")
    check(value["agents"] == sorted(value["agents"], key=lambda x: (x["name"], x["id"])), "agent ordering")
    for agent in value["agents"]:
        check(set(agent) == {"id", "name", "sessions"}, "agent shape differs from contract")
        check(isinstance(agent["sessions"], list), "agent sessions is not an array")
        check(agent["sessions"] == sorted(agent["sessions"], key=lambda x: x["id"]), "session ordering")
        for session in agent["sessions"]:
            check(set(session) == SESSION, "session shape differs from contract")
            check(type(session["renewable"]) is bool, "renewable is not a boolean")
            connection = session["connection"]
            if session["adapter_id"] is None:
                check(connection is None and session["expires_at"] is None and not session["renewable"],
                      "metadata-only attachment claims an adapter credential or connection")
            else:
                check(isinstance(connection, dict) and set(connection) == CONNECTION,
                      "adapter connection is not the full public connection record")
                check(connection["adapter_id"] == session["adapter_id"]
                      and connection["session_id"] == session["id"], "connection belongs to another attachment")
    no_private(value)
    encoded = json.dumps(value)
    check(not any(secret and secret in encoded for secret in secrets), "observation disclosed a fixture secret")
    return value


def matches_status(host, view):
    status = get(host, "/v2/status")
    check(view["networks"] == status["networks"], "network views differ from status")
    check(view["attention"] == status["attention"], "attention differs from status or its order")
    agents = json.loads(json.dumps(view["agents"]))
    for agent in agents:
        for session in agent["sessions"]:
            if session["connection"] is not None:
                session["connection"] = session["connection"]["state"]
    check(agents == status["agents"], "agent/session inclusion or public metadata differs from status")


def public_request_diagnostics(host):
    """Read only named public fields; never print CLI output, packets or display codes."""
    try:
        status, body = host.api("GET", "/v2/link/requests", timeout=3)
        result = {"host": host.name, "requests_http_status": status}
        if status == 200 and isinstance(body, list):
            fields = ("request_id", "role", "state", "network_id", "completed", "attention", "next",
                      "selection_approved", "commit_approved")
            result["requests"] = [{key: record[key] for key in fields if key in record} for record in body]
        status, body = host.api("GET", "/v2/status", timeout=3)
        result["status_http_status"] = status
        if status == 200 and isinstance(body, dict):
            result["attention"] = body.get("attention")
        return result
    except OSError as error:
        return {"host": host.name, "unavailable": type(error).__name__}


def automatic_return(inviter, requester, request_id):
    # The public automatic-return attempt is bounded at 30 seconds (spec 8.1).
    # This fixture supplies one invitation and no competing mailbox conversation.
    try:
        wait_for(lambda: request_id in {r["request_id"] for r in get(inviter, "/v2/link/requests")},
                 timeout=30, message=f"automatic introduction return to {inviter.name}")
    except Failure as error:
        diagnostics = {"expected_request_id": request_id,
                       "observations": [public_request_diagnostics(host) for host in (inviter, requester)]}
        raise Failure(f"{error}; public observations: {json.dumps(diagnostics, sort_keys=True)}") from error


def logical_records(host):
    """All SQLite table rows in one read transaction, including guards and intent records.

    Keep record contents out of diagnostics: some are deliberately private.
    This fixture has no invitations, pending work, live adapters or remote peers.
    """
    paths = sorted(host.state.glob("*.db"))
    check(paths, "no host state database")
    result = {}
    for path in paths:
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)) as db, db:
            db.execute("BEGIN")
            tables = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
            result[path.name] = {"schema": tuple(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name")),
                                 "version": db.execute("PRAGMA user_version").fetchone()}
            for table in tables:
                quoted = '"' + table.replace('"', '""') + '"'
                result[path.name][table] = tuple(sorted(db.execute(f"SELECT * FROM {quoted}"), key=repr))
    return result


def files(root):
    result = {}
    for path in [root, *sorted(root.rglob("*"))]:
        info = path.lstat()
        content = (os.readlink(path) if path.is_symlink() else
                   hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None)
        result[str(path.relative_to(root))] = (info.st_mode, info.st_mtime_ns, content)
    return result


@suite.case("empty_api_and_cli", "guided onboarding verification 1; CLI")
def _():
    view = observation(a)
    check(all(view[field] == [] for field in ("networks", "agents", "requests", "attention")),
          "empty host has nonempty onboarding collections")
    result = a.cli("onboarding", timeout=10)
    check(result.ok and isinstance(result.json, dict), "onboarding CLI failed on an incomplete empty host")
    cli = observation(a, result.json)
    check({k: v for k, v in cli.items() if k != "observed_at"}
          == {k: v for k, v in view.items() if k != "observed_at"}, "empty CLI and API observations differ")
    matches_status(a, view)
    root, advanced, command = a.cli("--help"), a.cli("help", "advanced"), a.cli("onboarding", "--help")
    check(root.ok and "onboarding" not in root.stdout, "reduced root help exposes the advanced command")
    check(advanced.ok and "onboarding" in advanced.stdout, "advanced help omits onboarding")
    check(command.ok and "onboarding" in command.stdout, "onboarding --help failed")
    check(not a.cli("onboarding", "--approve").ok, "onboarding accepts an approval flag")


@suite.case("networks_and_read_only_records", "guided onboarding verification 2, 5, 6, 7")
def _():
    first = create_network(a, "onboarding-one", "alice")
    second = create_network(a, "onboarding-two", "alice")
    state["networks"] = [first, second]
    view = observation(a)
    matches_status(a, view)
    check({n["id"] for n in view["networks"]} == {first["id"], second["id"]}, "network identity or count changed")
    for network in view["networks"]:
        original = next(n for n in (first, second) if n["id"] == network["id"])
        check(network["name"] == original["name"] and network["person_public_key"] == original["person_public_key"],
              "observation changed the created network's name or identity")
        check(network["authority"]["state"] == "usable", "created network lacks usable authority")
    before = logical_records(a)
    # No background traffic or adapter renewal has been introduced in this host.
    for _ in range(6):
        matches_status(a, observation(a))
        result = a.cli("onboarding", timeout=10)
        check(result.ok, "CLI read of two networks failed")
        observation(a, result.json)
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        status, _ = a.api(method, "/v1/onboarding", {"approve": True}, timeout=10)
        check(400 <= status < 500, f"{method} /v1/onboarding was not refused: HTTP {status}")
    check(logical_records(a) == before, "onboarding reads or refused mutations changed durable logical records")


@suite.case("metadata_and_adapter_evidence", "guided onboarding verification 4")
def _():
    agents = []
    for name in ("zeta", "alpha"):
        status, agent = b.api("POST", "/v1/agents", {"name": name, "owner": "bob"})
        check(status == 201, f"register {name}: HTTP {status}")
        agents.append(agent)
    for _ in range(2):
        status, _ = b.api("POST", "/v1/sessions", {"agent_id": agents[1]["id"], "integration": "metadata-only"})
        check(status == 201, f"attach metadata-only session: HTTP {status}")
    view = observation(b)
    matches_status(b, view)
    check([x["name"] for x in view["agents"]] == ["alpha", "zeta"], "registered agents were omitted")
    check(len(view["agents"][0]["sessions"]) == 2 and view["agents"][1]["sessions"] == [],
          "metadata attachments or agent without sessions was omitted")
    # Bind through the public fixture protocol without a renewing background thread.
    sid = "session_" + os.urandom(16).hex()
    status, setup = b.api("POST", "/v1/adapters/setup", {
        "agent_id": agents[0]["id"], "session_id": sid, "integration": "fixture"})
    check(status == 201, f"adapter setup: HTTP {status}")
    adapter = Adapter(b, agents[0], sid, setup["credential"])
    secrets.extend([adapter.token, adapter.instance])
    state["adapter"] = adapter
    status, _ = adapter.call("POST", "/adapter/v1/connect", {
        "adapter_id": adapter.adapter_id, "session_id": sid, "instance_id": adapter.instance,
        "protocol_version": "2025-06-18"})
    check(status == 200, f"fixture adapter connect: HTTP {status}")
    for verified in (False, True):
        if verified:
            adapter.ready()
        view = observation(b)
        matches_status(b, view)
        session = next(s for agent in view["agents"] for s in agent["sessions"] if s["id"] == sid)
        record = get(b, f"/v1/adapters/{adapter.adapter_id}/connection")
        check(session["connection"] == record, "onboarding did not preserve the public connection record")
        check(record["state"] == "ready" and record["channel"] == ("verified" if verified else "unverified"),
              "live adapter lease and verified channel were conflated")
        check(bool(record["channel_verified_at"]) is verified and record["protocol_version"] == "2025-06-18",
              "verification evidence or negotiated protocol was lost")
        check(session["renewable"] is True and session["expires_at"] == setup["credential"]["adapter"]["expires_at"],
              "session credential metadata was lost")


@suite.case("pending_requests_and_terminal_history", "guided onboarding verification 3, 6")
def _():
    (networks,) = need("networks")
    # Mailbox GETs share a 1/s actual-source/key bucket across locators. Observe
    # each normal return on an inviter with one invitation, before adding traffic.
    other_inviter = suite.host("other-inviter")
    introductions = [(a, networks[0]),
                     (other_inviter, create_network(other_inviter, "onboarding-other", "dana"))]
    key = ssh_key(c.root, "carol")
    pending = []
    for inviter, network in introductions:
        made = invite(inviter, "carol", network["id"])
        secrets.append(made["invitation"])
        request = join_request(c, made["invitation"], key)
        secrets.append(request.get("display_code"))
        pending.append(request["request_id"])
        automatic_return(inviter, c, request["request_id"])
    state["pending"] = pending
    for host in (a, other_inviter, c):
        before = get(host, "/v2/link/requests")
        view = observation(host)
        check(view["requests"] == before, "observation differs from retained public request records")
        matches_status(host, view)
        for _ in range(3):
            check(observation(host)["requests"] == before, "reading selected, approved or resumed a request")
        check(get(host, "/v2/link/requests") == before, "reading changed public request records")
        check(all(r["role"] == ("requester" if host is c else "approver")
                  for r in view["requests"] if r["request_id"] in pending), "pending request role changed")
    check(get(c, "/v2/networks") == [], "reading pending introductions adopted a network")
    requests = observation(c)["requests"]
    check({r["network_id"] for r in requests if r["request_id"] in pending}
          == {network["id"] for _, network in introductions},
          "pending introductions for different networks were merged")
    check(all(r["state"] == "pending" for r in requests if r["request_id"] in pending),
          "both introductions were not retained simultaneously as pending")
    check(all(not r["selection_approved"] and not r["commit_approved"] for r in requests),
          "reading pending requests granted consent")
    status, _ = c.api("POST", f"/v2/link/requests/{pending[0]}/cancel", {})
    check(status == 200, f"owner cancellation: HTTP {status}")
    final = observation(c)["requests"]
    check(final == get(c, "/v2/link/requests"), "terminal history differs from public request API")
    check(any(r["request_id"] == pending[0] and r["state"] == "cancelled" for r in final),
          "cancelled request was removed from the observation")
    # Only now add a complete public join for completed history and an admitted peer caller.
    joined = join_new_person(a, b, "bob", ssh_key(b.root, "bob"), networks[0]["id"])
    state["joined"] = joined
    for host in (a, b):
        view = observation(host)
        check(view["requests"] == get(host, "/v2/link/requests"), "completed history differs from public request API")
        check(any(r["request_id"] == joined and r["state"] == "linked" for r in view["requests"]),
              "completed membership history was omitted")


@suite.case("owner_local_boundary", "guided onboarding verification 7")
def _():
    need("joined")
    # The actual daemon-owned host key authenticates a current network member.
    result = subprocess.run([str(suite.probe_bin), "--state", str(b.state), "--address", a.peer_address,
                             "--alpn", "peerspan-peer/1", "--path", "/v1/onboarding", "--method", "GET"],
                            capture_output=True, timeout=15)
    try:
        peer = json.loads(result.stdout)
    except ValueError:
        peer = {}
    check(peer.get("status") == 404, "authenticated peer router did not refuse the owner onboarding route")
    (adapter,) = need("adapter")
    # Refresh the same known instance to ensure the scoped caller has a live lease.
    status, _ = adapter.call("POST", "/adapter/v1/connect", {
        "adapter_id": adapter.adapter_id, "session_id": adapter.session_id, "instance_id": adapter.instance})
    check(status == 200, "fixture could not refresh its existing adapter lease")
    check(adapter.call("GET", "/adapter/v1/session")[0] == 200, "scoped adapter fixture is not authorized")
    check(adapter.call("GET", "/v1/onboarding")[0] == 404, "credential-scoped adapter exposed onboarding")
    # Bootstrap GET attempts share an actual-source bucket across keys and connections
    # (public bootstrap contract). Isolate routing from the other hosts' mailbox polls.
    bootstrap = suite.host("bootstrap-boundary")
    observation(bootstrap)  # The endpoint exists on this host's owner interface.
    # Bootstrap accepts any possession-proving key, including this independent throwaway certificate.
    cert, key = suite.work / "bootstrap-cert.pem", suite.work / "bootstrap-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-subj", "/CN=onboarding",
                    "-days", "1", "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True, timeout=5)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
    context.load_cert_chain(str(cert), str(key))
    context.set_alpn_protocols(["peerspan-bootstrap/1"])
    with socket.create_connection(("127.0.0.1", bootstrap.bootstrap_port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="peerspan") as stream:
            check(stream.selected_alpn_protocol() == "peerspan-bootstrap/1", "bootstrap protocol not negotiated")
            stream.sendall(b"GET /v1/onboarding HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            response = http.client.HTTPResponse(stream)
            response.begin()
            response.read()
            check(response.status == 404, f"bootstrap listener exposed onboarding: HTTP {response.status}, want 404")


@suite.case("unavailable_daemon_is_inert", "guided onboarding verification 8")
def _():
    a.stop()
    before = files(a.root)
    check(not a.cli("onboarding", timeout=10).ok, "CLI succeeded with a stopped daemon")
    check(files(a.root) == before, "CLI changed files with a stopped daemon")
    absent = suite.host("absent", start=False)
    shutil.rmtree(absent.state)
    before = files(absent.root)
    check(not absent.cli("onboarding", timeout=10).ok, "CLI succeeded with a missing daemon and state")
    check(not absent.state.exists() and files(absent.root) == before, "CLI created state or files for a missing daemon")


suite.finish()
