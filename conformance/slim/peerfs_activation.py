#!/usr/bin/env python3
"""PF-1(c): provider activation/lifetime and historical HostKeys.

Written independently from docs/peerfs-local-contract.md sections 3, 4, 6, 7
and 8. CI has no PeerFS binary, so a small in-suite fake provider serves
`GET /v1/host-bridge` on `<prepared directory>/peerfs.sock`, genuinely or with
contract-violating variants. Real public binaries/APIs and read-only SQLite
observations only; no product-row or identity-file edits.

Purity compares every host table except dec_outbox/dec_clock, which a live
two-host network moves on its own; the admitted-history case stops the second
host and waits for rows to settle first. Damaged retained HostKeys proof (409)
is not covered: producing it would require editing product rows.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import subprocess
import sys
import threading
import time

from harness import (Clock, Skip, Suite, UnixHTTPConnection, check, create_network, join_new_person,
                     members, parse_time, peer, rfc3339, ssh_key)
from counted_peer import CountedUDP

os.umask(0o077)
suite = Suite("peerfs_activation", __doc__)
BASE = "/v1/fs/spaces"
DOMAIN = b"peerfs 2026-10-27 commit signature\0"
VIEW = set("format space_id binding_id network_id context_id host_id public_key directory state created_at".split())
ERRORS = {400: ("invalid", "invalid request"), 403: ("forbidden", "forbidden"),
          404: ("not_found", "not found"), 409: ("conflict", "conflict"),
          413: ("too_large", "too large"), 503: ("unavailable", "unavailable")}
state = {}
# Background delivery/clock bookkeeping that a live two-host network moves on its own.
BACKGROUND = {"dec_outbox", "dec_clock"}


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def request(h, method, path, body=None, raw=None):
    began = time.monotonic()
    connection = UnixHTTPConnection(str(h.state / "admin.sock"), timeout=7)
    try:
        payload = raw if raw is not None else None if body is None else compact(body)
        connection.request(method, path, body=payload,
                           headers={} if payload is None else {"Content-Type": "application/json"})
        response = connection.getresponse()
        data = response.read()
    finally:
        connection.close()
    took = time.monotonic() - began
    check(took < 5.5, f"PF operation took {took:.1f}s, past its five-second bound")
    try:
        return response.status, json.loads(data)
    except ValueError:
        check(False, "PF operation returned non-JSON")


def expect(h, method, path, status=200, body=None, raw=None):
    statuses = status if isinstance(status, tuple) else (status,)
    got, value = request(h, method, path, body, raw)
    check(got in statuses, f"PF {method} {path.rsplit('/', 1)[-1]} returned HTTP{got}, expected HTTP{status} ({state.get('variant', '')})")
    if got in ERRORS:
        code, error = ERRORS[got]
        check(value == {"code": code, "error": error}, f"PF HTTP{got} did not use its fixed safe error envelope")
    return value


def fixture():
    if "host" not in state:
        clock = Clock(suite.work / "clock-offset")
        h = suite.host("owner", clock=clock)
        net = create_network(h, "local-files", "owner")
        contact = suite.host("contact", clock=clock)
        counted = CountedUDP(("127.0.0.1", contact.peer_port))
        # Contact only: a transport address and pinned key, never an admission.
        h.ok("peer", "add", "--id", contact.id, "--public-key", contact.public_key, "--address", counted.address)
        roots = suite.work / "roots"
        roots.mkdir(mode=0o700)
        state.update(host=h, net=net, clock=clock, roots=roots, counter=0, contact=contact, counted=counted)
    return state["host"], state["net"]


def terms(net=None):
    _, network = fixture()
    net = net or network
    state["counter"] += 1
    directory = state["roots"] / f"d{state['counter']}"
    directory.mkdir(mode=0o700)
    return {"space_id": "space_" + os.urandom(16).hex(), "network_id": net["id"],
            "context_id": net["context_id"], "directory": str(directory)}


def view(value, body, h, live):
    check(isinstance(value, dict) and set(value) == VIEW, "private registration view fields differ")
    check(value["format"] == 1 and type(value["format"]) is int and value["state"] == live
          and all(value[k] == v for k, v in body.items()), f"registration view is not the exact {live} binding")
    check(re.fullmatch(r"fsbind_[0-9a-f]{32}", value["binding_id"]) and value["host_id"] == h.id
          and value["public_key"] == h.public_key, "binding did not pin the actual daemon host")
    parse_time(value["created_at"])
    return value


def prepare(net=None):
    h, _ = fixture()
    body = terms(net)
    return view(expect(h, "POST", BASE, 201, body), body, h, "prepared")


def route(registration, operation=""):
    return BASE + "/" + registration["space_id"] + ("/" + operation if operation else "")


def binding(registration, **extra):
    return {"binding_id": registration["binding_id"], **extra}


def records(h):
    result = {}
    for path in sorted(h.state.glob("*.db")):
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)) as db:
            db.execute("BEGIN")
            tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
            result[path.name] = {"schema": tuple(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name")),
                                 "version": db.execute("PRAGMA user_version").fetchone()}
            for table in tables:
                if table in BACKGROUND:
                    continue
                quoted = '"' + table.replace('"', '""') + '"'
                result[path.name][table] = tuple(sorted(db.execute("SELECT * FROM " + quoted), key=repr))
    check(result, "fixture has no observable host database")
    return result


def files(h):
    result = {}
    for path in sorted(h.root.rglob("*")):
        if path.name == "daemon.log" or ".db" in path.name or not path.is_file() or path.is_symlink():
            continue
        result[str(path.relative_to(h.root))] = (stat.S_IMODE(path.stat().st_mode), hashlib.sha256(path.read_bytes()).hexdigest())
    return result


def pure(h, operation):
    """OPERATION changes no durable rows, host key files or contact-only peer traffic."""
    before = records(h), files(h), state["counted"].counts()
    result = operation()
    after = records(h), files(h), state["counted"].counts()
    if after != before:
        tables = [(d, t) for d in before[0] for t in before[0][d] if before[0][d][t] != after[0].get(d, {}).get(t)]
        print("pure diff:", tables, before[1] != after[1], before[2], after[2], file=sys.stderr)
    check((records(h), files(h), state["counted"].counts()) == before,
          "operation changed durable rows, key files or contact-only peer traffic")
    return result


def settle(h, quiet=1.5, limit=20):
    """Wait until the host's own background work leaves its rows still for QUIET seconds."""
    deadline, last = time.monotonic() + limit, records(h)
    while time.monotonic() < deadline:
        time.sleep(quiet)
        now = records(h)
        if now == last:
            return
        last = now
    check(False, "fixture: host rows never settled")


def unchanged(h, registration, operation):
    """OPERATION is pure and leaves the exact retained registration (section4: refusal changes nothing)."""
    pure(h, operation)
    check(expect(h, "GET", route(registration)) == registration, "refused activation changed the registration")


def identity(registration, **changes):
    value = {"format": 1, "protocol": "peerfs-host-v1", **{k: registration[k] for k in (
        "space_id", "binding_id", "network_id", "context_id", "host_id", "public_key", "directory")}}
    value.update(changes)
    return {k: v for k, v in value.items() if v is not REMOVE}


REMOVE = object()


def http(status, body, extra=b""):
    reason = {200: b"OK", 302: b"Found", 404: b"Not Found"}.get(status, b"X")
    return (b"HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n"
            % (status, reason, len(body)) + extra + b"\r\n" + body)


class Provider:
    """A fake PeerFS provider on a Unix socket. REPLY is response bytes, or None to never answer."""

    def __init__(self, path, reply, mode=0o600, gate=None):
        self.path, self.reply, self.gate = Path(path), reply, gate
        self.requests, self.done = [], threading.Event()
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(self.path))
        self.path.chmod(mode)
        self.listener.listen(8)
        self.listener.settimeout(.05)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.done.is_set():
            try:
                connection, _ = self.listener.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self.answer, args=(connection,), daemon=True).start()

    def answer(self, connection):
        with connection:
            connection.settimeout(6)
            head = b""
            try:
                while b"\r\n\r\n" not in head and len(head) < 65536:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    head += chunk
            except OSError:
                return
            self.requests.append(head.split(b"\r\n", 1)[0])
            if self.gate is not None:
                self.gate.wait(10)
            if self.reply is None:
                self.done.wait(8)
                return
            try:
                connection.sendall(self.reply)
            except OSError:
                pass

    def stop(self, unlink=True):
        self.done.set()
        self.listener.close()
        self.thread.join(timeout=1)
        if unlink and self.path.exists():
            self.path.unlink()


def socket_path(registration):
    return Path(registration["directory"]) / "peerfs.sock"


def genuine(registration, **kw):
    return Provider(socket_path(registration), http(200, compact(identity(registration))), **kw)


def activated(h, registration, value, before):
    check(isinstance(value, dict) and set(value) == {"registration", "provider"}
          and isinstance(value["provider"], dict) and set(value["provider"]) == {"state", "observed_at"}
          and value["provider"]["state"] == "verified", "activation result fields differ")
    check(value["registration"] == {**registration, "state": "registered"},
          "activation changed immutable terms or did not register")
    observed = parse_time(value["provider"]["observed_at"])
    check(before - timedelta(seconds=2) <= observed <= h.now() + timedelta(seconds=2), "observed_at does not identify this probe")
    return value["registration"]


def activate(h, registration, provider):
    began, count = h.now(), len(provider.requests)
    value = activated(h, registration, expect(h, "POST", route(registration, "activate"), body=binding(registration)), began)
    check(provider.requests[count:] == [b"GET /v1/host-bridge HTTP/1.1"], "activation did not probe GET /v1/host-bridge once")
    return value


def uleb(number):
    data = bytearray()
    while True:
        byte, number = number & 127, number >> 7
        data.append(byte | (128 if number else 0))
        if not number:
            return bytes(data)


def string(value):
    value = value.encode()
    return uleb(len(value)) + value


def initial(host):
    return (DOMAIN + b"\3\1" + b"\x11" * 32 + b"\0" + uleb(16) + b"\x22" * 16 + string(host)
            + b"\0\0\0" + string("Create the space") + b"\0\0")


def signs(h, registration):
    value = expect(h, "POST", route(registration, "sign-commit"),
                   body=binding(registration, message_base64=base64.b64encode(initial(h.id)).decode()))
    check(value["host_id"] == h.id and value["public_key"] == h.public_key, "local signing changed identity")


@suite.case("genuine_activation_and_replay", "PF-1 sections3/4: prepared->registered, exact replay probes again")
def _():
    h, _ = fixture()
    registration = prepare()
    provider = genuine(registration)
    try:
        before = records(h)
        registered = activate(h, registration, provider)
        after = records(h)
        changed = [(db, t) for db in before for t in before[db] if before[db][t] != after[db][t]]
        check(len(changed) == 1, "activation changed state outside its one binding collection")
        check(expect(h, "GET", route(registration)) == registered and registered in expect(h, "GET", BASE),
              "lookup/list does not show the registered binding")
        pure(h, lambda: activate(h, registered, provider))
        pure(h, lambda: check(expect(h, "GET", route(registration)) == registered, "lookup changed"))
        check(len(provider.requests) == 2, "pure lookup/list probed the provider")
        signs(h, registered)
    finally:
        provider.stop()
    # A provider identity body of exactly 8 KiB is within its bound.
    body = compact(identity(registration))
    exact = Provider(socket_path(registration), http(200, body + b" " * (8192 - len(body))))
    try:
        pure(h, lambda: activate(h, registered, exact))
    finally:
        exact.stop()
    state["registered"] = registered


def refusals(registration):
    body = compact(identity(registration))
    wrong = [identity(registration, **{k: v}) for k, v in (
        ("binding_id", "fsbind_" + "e" * 32), ("space_id", "space_" + "e" * 32),
        ("network_id", "net_" + "e" * 64), ("context_id", "ctx_" + "e" * 64),
        ("host_id", "host_" + "e" * 64), ("public_key", base64.b64encode(b"\7" * 32).decode()),
        ("directory", registration["directory"] + "x"), ("protocol", "peerfs-host-v2"),
        ("format", 2), ("format", "1"), ("directory", REMOVE), ("protocol", REMOVE))]
    wrong.append({**identity(registration), "host_socket": registration["directory"] + "/peerfs.sock"})
    wrong.append({**identity(registration), "extra": True})
    replies = [(http(200, compact(value)), 409) for value in wrong]
    replies += [(http(404, compact({"error": "not found"})), 409),  # an old file-key provider
                (http(302, b"", b"Location: http://localhost/v1/host-bridge\r\n"), 409),
                (http(500, body), 409), (http(200, body + b" {}"), 409), (http(200, b"[]"), 409),
                # Section4 bounds the response at 8 KiB; section7 lists no separate status for it.
                (http(200, body + b" " * (8193 - len(body))), (409, 503)),
                (b"not an http response\r\n\r\n", (409, 503))]
    return replies


@suite.case("malformed_identity_leaves_state", "PF-1 sections4/7: wrong/extra fields, old provider, bounds")
def _():
    h, _ = fixture()
    prepared = prepare()
    targets = [prepared] + ([state["registered"]] if "registered" in state else [])
    for registration in targets:
        for index, (reply, status) in enumerate(refusals(registration)):
            state["variant"] = f"provider variant {index} on {registration['state']}"
            provider = Provider(socket_path(registration), reply)
            try:
                unchanged(h, registration, lambda: expect(h, "POST", route(registration, "activate"), status,
                                                          binding(registration)))
                check(len(provider.requests) == 1, "activation did not probe exactly once")
            finally:
                provider.stop()
    state["prepared"] = prepared


@suite.case("duplicate_identity_field", "PF-1 section4: a duplicated response field is an extra field, 409")
def _():
    h, _ = fixture()
    state["variant"] = "duplicate space_id"
    registration = prepare()
    body = compact(identity(registration))
    provider = Provider(socket_path(registration),
                        http(200, body[:-1] + b',"space_id":' + compact(registration["space_id"]) + b"}"))
    try:
        unchanged(h, registration, lambda: expect(h, "POST", route(registration, "activate"), 409, binding(registration)))
    finally:
        provider.stop()


@suite.case("socket_file_fences", "PF-1 sections4/7/8: public, non-socket, symlinked and missing sockets")
def _():
    h, _ = fixture()
    registration = state.get("prepared") or prepare()
    path = socket_path(registration)
    elsewhere = state["roots"] / "elsewhere.sock"
    real = Provider(elsewhere, http(200, compact(identity(registration))))
    try:
        for mode in (0o644, 0o660, 0o666, 0o700):
            provider = genuine(registration, mode=mode)
            try:
                unchanged(h, registration, lambda: expect(h, "POST", route(registration, "activate"), 409,
                                                          binding(registration)))
            finally:
                provider.stop()
        path.write_bytes(compact(identity(registration)))
        path.chmod(0o600)
        unchanged(h, registration, lambda: expect(h, "POST", route(registration, "activate"), 409, binding(registration)))
        path.unlink()
        path.mkdir(mode=0o700)
        unchanged(h, registration, lambda: expect(h, "POST", route(registration, "activate"), 409, binding(registration)))
        path.rmdir()
        path.symlink_to(elsewhere)
        unchanged(h, registration, lambda: expect(h, "POST", route(registration, "activate"), 409, binding(registration)))
        check(not real.requests, "activation followed a symlinked provider socket")
        path.unlink()
    finally:
        real.stop()
    # No provider at all, and a stale socket nobody listens on: unavailable.
    unchanged(h, registration, lambda: expect(h, "POST", route(registration, "activate"), 503, binding(registration)))
    stale = socket.socket(socket.AF_UNIX)
    stale.bind(str(path))
    path.chmod(0o600)
    try:
        unchanged(h, registration, lambda: expect(h, "POST", route(registration, "activate"), 503, binding(registration)))
    finally:
        stale.close()
        path.unlink()
    # A changed private directory fences activation even with a genuine provider.
    directory = Path(registration["directory"])
    provider = genuine(registration)
    try:
        directory.chmod(0o750)
        unchanged(h, registration, lambda: expect(h, "POST", route(registration, "activate"), 409, binding(registration)))
        directory.chmod(0o700)
        check(not provider.requests, "activation probed a provider in a changed private directory")
    finally:
        directory.chmod(0o700)
        provider.stop()


@suite.case("socket_account_mismatch", "PF-1 sections4/7: socket owner and SO_PEERCRED account, 403")
def _():
    if os.geteuid() != 0:
        raise Skip("needs root to own or serve a socket as another account")
    h, _ = fixture()
    registration = prepare()
    path = socket_path(registration)
    provider = genuine(registration)
    try:
        os.chown(path, 65534, 65534)
        unchanged(h, registration, lambda: expect(h, "POST", route(registration, "activate"), 403, binding(registration)))
        check(not provider.requests, "activation spoke to a socket owned by another account")
    finally:
        provider.stop()
    # Socket file owned by the daemon's account and mode 0600, but listening/served by another account.
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(path))
    path.chmod(0o600)
    reply = http(200, compact(identity(registration)))
    child = ("import socket,sys\ns=socket.socket(fileno=int(sys.argv[1]));s.listen(8)\n"
             "while True:\n c,_=s.accept();c.recv(65536);c.sendall(bytes.fromhex(sys.argv[2]));c.close()\n")
    process = suite.spawn([sys.executable, "-I", "-c", child, str(listener.fileno()), reply.hex()],
                          pass_fds=[listener.fileno()], user=65534, group=65534, cwd="/",
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    listener.close()
    try:
        time.sleep(.5)
        check(process.poll() is None, "foreign-account fixture provider did not start")
        unchanged(h, registration, lambda: expect(h, "POST", route(registration, "activate"), 403, binding(registration)))
    finally:
        process.kill()
        process.wait(timeout=5)
        path.unlink()
    provider = genuine(registration)
    try:
        activate(h, registration, provider)
    finally:
        provider.stop()


@suite.case("silent_provider_bounded", "PF-1 sections4/7: never-answering provider, 503 within 5s, no transition")
def _():
    h, _ = fixture()
    for registration in [prepare()] + ([state["registered"]] if "registered" in state else []):
        provider = Provider(socket_path(registration), None)
        try:
            began = time.monotonic()
            unchanged(h, registration, lambda: expect(h, "POST", route(registration, "activate"), 503, binding(registration)))
            check(time.monotonic() - began < 5.5, "silent provider was not bounded")
        finally:
            provider.stop()


@suite.case("concurrent_release_prevents_commit", "PF-1 section4: release during the probe wins")
def _():
    h, _ = fixture()
    registration = prepare()
    gate = threading.Event()
    provider = genuine(registration, gate=gate)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(request, h, "POST", route(registration, "activate"), binding(registration))
            deadline = time.monotonic() + 3
            while not provider.requests:
                check(time.monotonic() < deadline, "activation did not probe")
                time.sleep(.02)
            released = expect(h, "POST", route(registration, "release"), body=binding(registration))
            check(released == {**registration, "state": "released"}, "release during the probe did not commit")
            gate.set()
            status, value = pending.result(timeout=7)
        check(status == 409 and value == {"code": "conflict", "error": "conflict"},
              f"activation after a concurrent release returned HTTP{status}")
        check(expect(h, "GET", route(registration)) == released, "activation overwrote the concurrent release")
        # A tombstone never activates again, even with a genuine provider.
        unchanged(h, released, lambda: expect(h, "POST", route(registration, "activate"), 409, binding(registration)))
    finally:
        gate.set()
        provider.stop()


@suite.case("stopped_provider_and_restart", "PF-1 sections4/8: stays registered; no startup probe; recreation")
def _():
    h, _ = fixture()
    registration = prepare()
    provider = genuine(registration)
    registered = activate(h, registration, provider)
    provider.stop()
    unchanged(h, registered, lambda: expect(h, "POST", route(registered, "activate"), 503, binding(registered)))
    signs(h, registered)
    provider = genuine(registered)
    try:
        h.restart(kill=True)
        time.sleep(1)
        check(not provider.requests, "host probed a provider at startup")
        check(expect(h, "GET", route(registered)) == registered, "restart lost or changed the registered binding")
        check(not provider.requests, "lookup probed the provider")
        activate(h, registered, provider)
    finally:
        provider.stop()


@suite.case("strict_activation_requests", "PF-1 sections3/7: exact body, 400/404/409/413")
def _():
    h, _ = fixture()
    registration = prepare()
    provider = genuine(registration)
    try:
        valid = binding(registration)
        duplicate = compact(valid)[:-1] + b',"binding_id":' + compact(valid["binding_id"]) + b"}"
        def refuse():
            for raw in (b"", b"null", b"[]", b"{}", compact({**valid, "extra": 1}), compact({"binding_id": None}),
                        compact({"binding_id": "alias"}), compact({"binding_id": "fsbind_" + "A" * 32}),
                        duplicate, compact(valid) + b" {}", b'{"binding_id":"\xff"}'):
                expect(h, "POST", route(registration, "activate"), 400, raw=raw)
            expect(h, "POST", route(registration, "activate"), 409, {"binding_id": "fsbind_" + "e" * 32})
            expect(h, "POST", BASE + "/space_" + "0" * 32 + "/activate", 404, valid)
            expect(h, "POST", route(registration, "activate"), 413, raw=compact(valid) + b" " * (8193 - len(compact(valid))))
        unchanged(h, registration, refuse)
        check(not provider.requests, "a refused request probed the provider")
        activate(h, registration, provider)
    finally:
        provider.stop()


def check_key(h, registration, host_id, public_key, recognized=None, status=200):
    state["variant"] = f"HostKeys {host_id[:12]}/{public_key[:6]} on {registration['state']}"
    value = expect(h, "POST", route(registration, "host-keys/check"), status,
                   binding(registration, host_id=host_id, public_key=public_key))
    if status == 200:
        check(value == {"host_id": host_id, "public_key": public_key, "recognized": recognized},
              f"HostKeys answered {value.get('recognized')!r}, expected {recognized}")
    return value


def keypair():
    """A genuine, never-admitted Ed25519 public key and its self-consistent host ID."""
    private = subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519"], capture_output=True, check=True, timeout=5).stdout
    der = subprocess.run(["openssl", "pkey", "-pubout", "-outform", "DER"], input=private,
                         capture_output=True, check=True, timeout=5).stdout
    key = der[-32:]
    return "host_" + hashlib.sha256(key).hexdigest(), base64.b64encode(key).decode()


@suite.case("host_keys_local_and_malformed", "PF-1 sections6/7: local key, mismatches, 400/404/409")
def _():
    h, _ = fixture()
    prepared = prepare()
    targets = [prepared] + ([state["registered"]] if "registered" in state else [])
    other_id, other_key = keypair()
    raw_key = base64.b64decode(h.public_key)
    def checks():
        for registration in targets:
            check_key(h, registration, h.id, h.public_key, True)
            check_key(h, registration, other_id, other_key, False)  # self-consistent, never admitted
            check_key(h, registration, h.id, other_key, False)  # a valid different key
            check_key(h, registration, other_id, h.public_key, False)
            contact = state["contact"]
            check_key(h, registration, contact.id, contact.public_key, False)  # contact only
            for host_id, key in (("owner", h.public_key), (h.id.upper().replace("HOST_", "host_"), h.public_key),
                                 (h.id + "0", h.public_key), (h.id[:-1], h.public_key), ("", h.public_key),
                                 (h.id, h.public_key.rstrip("=")), (h.id, "-" * 43 + "="),
                                 (h.id, base64.b64encode(raw_key[:31]).decode()), (h.id, base64.b64encode(raw_key + b"\0").decode()),
                                 (h.id, h.public_key + "\n"), (h.id, h.public_key[:-2] + "B=")):
                check_key(h, registration, host_id, key, status=400)
            valid = binding(registration, host_id=h.id, public_key=h.public_key)
            for raw in (b"{}", compact({**valid, "extra": 1}), compact({**valid, "host_id": None}),
                        compact({**valid, "public_key": 1}), compact(valid) + b" {}",
                        compact({k: v for k, v in valid.items() if k != "binding_id"})):
                expect(h, "POST", route(registration, "host-keys/check"), 400, raw=raw)
            expect(h, "POST", route(registration, "host-keys/check"), 409, {**valid, "binding_id": "fsbind_" + "e" * 32})
            expect(h, "POST", BASE + "/space_" + "0" * 32 + "/host-keys/check", 404, valid)
            expect(h, "POST", route(registration, "host-keys/check"), 413,
                   raw=compact(valid) + b" " * (8193 - len(compact(valid))))
    pure(h, checks)
    released = expect(h, "POST", route(prepared, "release"), body=binding(prepared))
    pure(h, lambda: check_key(h, released, h.id, h.public_key, status=409))


@suite.case("host_keys_directory_fences", "PF-1 sections2/7: public or replaced pinned root is 409")
def _():
    h, _ = fixture()
    registration = prepare()
    directory = Path(registration["directory"])
    def fenced():
        directory.chmod(0o755)
        check_key(h, registration, h.id, h.public_key, status=409)
        directory.chmod(0o700)
        check_key(h, registration, h.id, h.public_key, True)  # same inode, privacy restored
        directory.rename(directory.with_name(directory.name + "-original"))
        directory.mkdir(mode=0o700)
        check_key(h, registration, h.id, h.public_key, status=409)  # new inode stays refused
    pure(h, fenced)


@suite.case("host_keys_admitted_history", "PF-1 sections6/8: admitted remote host, other context, removal, expiry")
def _():
    h, net = fixture()
    clock = state["clock"]
    bob = suite.host("bob", clock=clock)
    join_new_person(h, bob, "bob", ssh_key(bob.root, "bob"), net["id"],
                    not_after=rfc3339(clock.now() + timedelta(hours=1)))
    check(bob.public_key in members(h, net["id"]), "fixture: bob's host was not admitted")
    registration = state.get("registered") or prepare()
    other = create_network(h, "other-files", "owner")
    elsewhere = prepare(other)
    _, unrelated_key = keypair()
    # Both owner routes are absent on the admitted peer's router and the adapter router.
    for operation, body in (("activate", binding(registration)),
                            ("host-keys/check", binding(registration, host_id=bob.id, public_key=bob.public_key))):
        check(peer(bob, h, "POST", route(registration, operation), body)[0] == 404, "peer router exposed a PF route")
    adapter = h.agent("boundary")
    try:
        for operation, body in (("activate", binding(registration)),
                                ("host-keys/check", binding(registration, host_id=h.id, public_key=h.public_key))):
            check(adapter.call("POST", route(registration, operation), body)[0] == 404, "adapter exposed a PF route")
    finally:
        adapter.stop()
    # Stop bob so his background sync cannot move the owner's rows during the purity windows.
    bob.stop()
    def checks():
        check_key(h, registration, bob.id, bob.public_key, True)
        check_key(h, elsewhere, bob.id, bob.public_key, False)  # admitted only in another context
        check_key(h, elsewhere, h.id, h.public_key, True)
        check_key(h, registration, bob.id, unrelated_key, False)  # a valid different key for that host
    settle(h)
    pure(h, checks)
    # Removal, then expiry, do not erase an established historical identity.
    h.ok("network", "revoke", "--network", net["id"], "--host", bob.id, "--approve")
    check(bob.public_key not in members(h, net["id"]), "fixture: revoked host is still a member")
    settle(h)
    pure(h, lambda: check_key(h, registration, bob.id, bob.public_key, True))
    clock.set(2 * 3600)
    settle(h)
    pure(h, lambda: check_key(h, registration, bob.id, bob.public_key, True))
    pure(h, lambda: check_key(h, elsewhere, bob.id, bob.public_key, False))

suite.finish()
