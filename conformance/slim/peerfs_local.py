#!/usr/bin/env python3
"""PF-1(a): owner-local preparation, release and typed host commit signing.

Written independently from docs/peerfs-local-contract.md and its public vectors.
Uses real public binaries/APIs and read-only SQLite observations. Activation,
PeerFS initialization and historical HostKeys belong to subsequent pieces.
No direct product-row edits or identity-file edits.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import stat
import subprocess
import threading
import time

from harness import (Clock, Suite, UnixHTTPConnection, check, create_network,
                     free_port, join_new_person, parse_time, ssh_key)
from counted_peer import CountedUDP

os.umask(0o077)
suite = Suite("peerfs_local", __doc__)
BASE = "/v1/fs/spaces"
DOMAIN = b"peerfs 2026-10-27 commit signature\0"
VIEW = set("format space_id binding_id network_id context_id host_id public_key directory state created_at".split())
ERRORS = {400: ("invalid", "invalid request"), 403: ("forbidden", "forbidden"),
          404: ("not_found", "not found"), 409: ("conflict", "conflict"),
          413: ("too_large", "too large"), 429: ("limit", "limit exceeded")}
state = {}


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def request(h, method, path, body=None, raw=None):
    began = time.monotonic()
    connection = UnixHTTPConnection(str(h.state / "admin.sock"), timeout=5.8)
    try:
        payload = raw if raw is not None else None if body is None else compact(body)
        connection.request(method, path, body=payload,
                           headers={} if payload is None else {"Content-Type": "application/json"})
        response = connection.getresponse()
        data = response.read()
    finally:
        connection.close()
    check(time.monotonic() - began < 5.5, "PF operation exceeded its five-second bound")
    try:
        value = json.loads(data)
    except ValueError:
        check(False, "PF operation returned non-JSON")
    return response.status, value


def expect(h, method, path, status=200, body=None, raw=None):
    got, value = request(h, method, path, body, raw)
    check(got == status, f"PF {method} returned HTTP{got}, expected HTTP{status}")
    if status in ERRORS:
        code, error = ERRORS[status]
        expected = {"code": code, "error": error}
        if status == 429:
            expected["limit"] = "fs_spaces"
        check(value == expected, f"PF HTTP{status} did not use its fixed safe error envelope")
    return value


def fixture():
    if "host" not in state:
        h = suite.host("owner")
        net = create_network(h, "local-files", "owner")
        outsider = suite.host("outsider")
        counted = CountedUDP(("127.0.0.1", outsider.peer_port))
        h.ok("peer", "add", "--id", outsider.id, "--public-key", outsider.public_key, "--address", counted.address)
        directory = suite.work / "roots"
        directory.mkdir(mode=0o700)
        state.update(host=h, net=net, roots=directory, counter=0, outsider=outsider, counted=counted)
    return state["host"], state["net"]


def terms(h=None, net=None, directory=None):
    owner, network = fixture()
    h, net = h or owner, net or network
    state["counter"] += 1
    if directory is None:
        directory = state["roots"] / f"d{state['counter']}"
        directory.mkdir(mode=0o700)
    return {"space_id": "space_" + os.urandom(16).hex(), "network_id": net["id"],
            "context_id": net["context_id"], "directory": str(directory)}


def view(value, body, h, live="prepared"):
    check(isinstance(value, dict) and set(value) == VIEW, "private registration view fields differ")
    check(value["format"] == 1 and type(value["format"]) is int, "registration format differs")
    check(all(value[k] == v for k, v in body.items()), "registration changed immutable terms")
    check(value["state"] == live and re.fullmatch(r"fsbind_[0-9a-f]{32}", value["binding_id"]),
          "registration state or binding identifier differs")
    key = base64.b64decode(value["public_key"], validate=True)
    check(len(key) == 32 and base64.b64encode(key).decode() == value["public_key"], "noncanonical host public key")
    check(value["host_id"] == h.id == "host_" + hashlib.sha256(key).hexdigest()
          and value["public_key"] == h.public_key, "binding did not pin the actual daemon host")
    parse_time(value["created_at"])
    return value


def prepare(body=None, h=None):
    owner, _ = fixture()
    h, body = h or owner, body or terms()
    return body, view(expect(h, "POST", BASE, 201, body), body, h)


def signing(registration, message):
    return {"binding_id": registration["binding_id"],
            "message_base64": base64.b64encode(message).decode()}


def route(registration, operation=""):
    return BASE + "/" + registration["space_id"] + ("/" + operation if operation else "")


def uleb(number):
    data = bytearray()
    while True:
        byte, number = number & 127, number >> 7
        data.append(byte | (128 if number else 0))
        if not number:
            return bytes(data)


def string(value):
    value = value.encode() if isinstance(value, str) else value
    return uleb(len(value)) + value


def optional(value):
    return b"\0" if value is None else b"\1" + string(value)


def message(host, *, parents=(), agent=None, session=None, text="Create the space", timestamp=0,
            predecessor=None, change=b"\x22" * 16, tree=b"\1" + b"\x11" * 32):
    return (DOMAIN + b"\3" + tree + uleb(len(parents)) + b"".join(parents) + string(change)
            + string(host) + optional(agent) + optional(session) + uleb(timestamp) + string(text)
            + (b"\0" if predecessor is None else b"\1" + predecessor) + b"\0")


def openssl(*arguments):
    result = subprocess.run(["openssl", *map(str, arguments)], capture_output=True, timeout=5)
    check(result.returncode == 0, "independent OpenSSL signature operation failed")


def verify(key, signature, data):
    key, signature = base64.b64decode(key, validate=True), base64.b64decode(signature, validate=True)
    check(len(key) == 32 and len(signature) == 64, "signature/key width differs")
    root = suite.work / "verify"
    root.mkdir(mode=0o700, exist_ok=True)
    for name, content in (("key.der", bytes.fromhex("302a300506032b6570032100") + key),
                          ("signature", signature), ("message", data)):
        (root / name).write_bytes(content)
        (root / name).chmod(0o600)
    openssl("pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", root / "key.der",
            "-rawin", "-in", root / "message", "-sigfile", root / "signature")


def sign(h, registration, data):
    result = expect(h, "POST", route(registration, "sign-commit"), body=signing(registration, data))
    check(set(result) == {"host_id", "public_key", "signature"}
          and result["host_id"] == h.id and result["public_key"] == h.public_key,
          "signature result did not use exact host identity fields")
    signature = base64.b64decode(result["signature"], validate=True)
    check(base64.b64encode(signature).decode() == result["signature"], "noncanonical result signature")
    verify(result["public_key"], result["signature"], data)
    return result


def records(h):
    result = {}
    for path in sorted(h.state.glob("*.db")):
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)) as db:
            db.execute("BEGIN")
            tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
            result[path.name] = {"schema": tuple(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name")),
                                 "version": db.execute("PRAGMA user_version").fetchone()}
            for table in tables:
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
    def roots():
        result = {}
        if "roots" in state:
            for path in sorted(state["roots"].rglob("*")):
                info = path.lstat()
                result[str(path)] = (info.st_mode, os.readlink(path) if path.is_symlink() else
                                     hashlib.sha256(path.read_bytes()).hexdigest() if stat.S_ISREG(info.st_mode) else None)
        return result
    before = records(h), files(h), roots(), state["counted"].counts()
    result = operation()
    check((records(h), files(h), roots(), state["counted"].counts()) == before,
          "pure operation changed durable rows, keys, filesystem contents or selected peer traffic")
    return result


@suite.case("public_vectors", "PF-1 sections5/8; independent exact bytes and signatures")
def _():
    vectors = json.loads((Path(__file__).resolve().parents[2] / "docs/vectors/peerfs-local-signing.json").read_text())
    material = vectors["public_test_material"]
    check(DOMAIN.hex() == vectors["signing_context_hex"], "public signing domain differs")
    for vector in vectors["positive"]:
        f = vector["fields"]
        data = message(f["author"]["host"], parents=[bytes.fromhex(p) for p in f["parents"]],
                       agent=f["author"]["agent"], session=f["author"]["session"], text=f["message"],
                       timestamp=f["time_ms"], predecessor=bytes.fromhex(f["predecessor"]) if f["predecessor"] else None,
                       change=bytes.fromhex(f["change"]), tree=bytes.fromhex(f["tree"]))
        check(data == DOMAIN + bytes.fromhex(vector["unsigned_commit_hex"])
              and base64.b64encode(data).decode() == vector["message_base64"]
              and hashlib.sha256(data).hexdigest() == vector["message_sha256"], "public vector codec differs")
        verify(material["public_key_base64"], vector["signature_base64"], data)
        signed = data[len(DOMAIN):-1] + b"\1" + string(base64.b64decode(material["public_key_base64"]))
        signed += string(base64.b64decode(vector["signature_base64"]))
        check(signed.hex() == vector["signed_commit_hex"], "public signed-object bytes differ")


@suite.case("preparation_replay_and_pure_reads", "PF-1 sections2/3/7")
def _():
    h, _ = fixture()
    body = terms()
    before, keys = records(h), files(h)
    _, registration = prepare(body)
    after = records(h)
    changed = [(db, table) for db in before for table in before[db] if before[db][table] != after[db][table]]
    binding_changes = [(db, table) for db, table in changed if table != "dec_clock"]
    check(len(binding_changes) == 1 and body["space_id"] in repr(after[binding_changes[0][0]][binding_changes[0][1]]),
          "preparation changed state outside its one binding collection")
    check(files(h) == keys and not list(Path(body["directory"]).iterdir()), "preparation created keys or filesystem contents")
    (Path(body["directory"]) / "ordinary-object").write_text("retained")
    def reads():
        check(expect(h, "POST", BASE, body=body) == registration, "exact replay did not retain original view")
        check(expect(h, "GET", route(registration)) == registration, "exact lookup changed registration")
        listing = expect(h, "GET", BASE)
        check(listing == sorted(listing, key=lambda v: v["space_id"])
              and registration in listing and all(v["state"] != "released" for v in listing), "list order or live membership differs")
    pure(h, reads)
    state["retained"] = body, registration


@suite.case("preparation_conflicts_and_membership", "PF-1 sections2/3: exact context and current admission")
def _():
    h, net = fixture()
    body, registration = prepare()
    other = create_network(h, "other-files", "owner")
    for changed in ({**body, "directory": terms()["directory"]}, {**body, "context_id": other["context_id"]},
                    {**body, "network_id": other["id"], "context_id": other["context_id"]},
                    {**body, "space_id": terms()["space_id"]}):
        expect(h, "POST", BASE, 409, changed)
    for changed in ({**terms(), "context_id": other["context_id"]},
                    {**terms(), "network_id": "net_" + "e" * 64},
                    {**terms(), "context_id": "ctx_" + "e" * 64}):
        expect(h, "POST", BASE, 403, changed)
    clock = Clock(suite.work / "expiry-clock")
    expired = suite.host("expiry", clock=clock)
    network = create_network(expired, "expires", "owner")
    earlier, retained = prepare(terms(expired, network), expired)
    expires = parse_time(network["authority"]["not_after"])
    expired.stop()
    clock.set((expires - clock.now()).total_seconds() + 3)
    expired.start()
    expect(expired, "POST", BASE, 403, terms(expired, network))
    check(expect(expired, "POST", BASE, body=earlier) == retained, "membership expiry changed historical preparation")
    sign(expired, retained, message(expired.id))
    expired.stop()


@suite.case("strict_json_and_id_bounds", "PF-1 sections2/3/7: exact objects and safe errors")
def _():
    h, _ = fixture()
    body, registration = prepare()
    duplicate = compact(body)[:-1] + b',"space_id":' + compact(body["space_id"]) + b"}"
    mutations = [b"null", b"[]", b"{}", compact({**body, "extra": True}), duplicate,
                 compact(body) + b" {}", compact(body).replace(b"directory", b"\xffdirectory", 1)]
    for field in body:
        mutations += [compact({k: v for k, v in body.items() if k != field}), compact({**body, field: None}),
                      compact({**body, field: 1})]
    for field, value in (("space_id", "space_" + "A" * 32), ("space_id", "space_" + "1" * 31),
                         ("network_id", "net_" + "a" * 63), ("context_id", "ctx_" + "a" * 63),
                         ("directory", "relative"), ("directory", "/"), ("directory", "/" + "a" * 4096),
                         ("directory", body["directory"] + "/"), ("directory", body["directory"] + "/."),
                         ("directory", body["directory"] + "/.."), ("directory", body["directory"] + "//x"),
                         ("directory", body["directory"] + "\0")):
        mutations.append(compact({**body, field: value}))
    pure(h, lambda: [expect(h, "POST", BASE, 400, raw=raw) for raw in mutations])
    for path in (BASE, route(registration)):
        expect(h, "GET", path + "?unexpected=1", 400)
        expect(h, "GET", path, 400, raw=b"{}")
    for operation, valid in (("release", {"binding_id": registration["binding_id"]}),
                             ("sign-commit", signing(registration, message(h.id)))):
        for bad in (None, [], {}, {**valid, "extra": 1}, {**valid, "binding_id": None},
                    {**valid, "binding_id": "alias"}):
            expect(h, "POST", route(registration, operation), 400, raw=compact(bad))
        duplicate = compact(valid)[:-1] + b',"binding_id":' + compact(valid["binding_id"]) + b"}"
        expect(h, "POST", route(registration, operation), 400, raw=duplicate)
        expect(h, "POST", route(registration, operation), 409, {**valid, "binding_id": "fsbind_" + "e" * 32})
    absent = {**registration, "space_id": "space_" + "0" * 32}
    expect(h, "GET", route(absent), 404)
    expect(h, "POST", route(absent, "release"), 404, {"binding_id": registration["binding_id"]})
    expect(h, "POST", route(absent, "sign-commit"), 404, signing(registration, message(h.id)))
    encoded = compact(terms())
    expect(h, "POST", BASE, 201, raw=encoded + b" " * (8192 - len(encoded)))
    expect(h, "POST", BASE, 413, raw=encoded + b" " * (8193 - len(encoded)))


@suite.case("private_paths_and_inode_fences", "PF-1 section2: root, ancestors and immutable directory")
def _():
    h, _ = fixture()
    public = Path(terms()["directory"])
    public.chmod(0o755)
    nonempty = Path(terms()["directory"])
    (nonempty / "do-not-delete").write_text("retained")
    target = Path(terms()["directory"])
    symlink = state["roots"] / "symlink"
    symlink.symlink_to(target, target_is_directory=True)
    unsafe = state["roots"] / "unsafe"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    child = unsafe / "child"
    child.mkdir(mode=0o700)
    ancestor = state["roots"] / "ancestor-link"
    ancestor.symlink_to(target, target_is_directory=True)
    (target / "child").mkdir(mode=0o700)
    regular = state["roots"] / "regular"
    regular.write_text("retained")
    missing = state["roots"] / "absent"
    for directory in (public, nonempty, symlink, child, ancestor / "child", regular, missing):
        expect(h, "POST", BASE, 409, terms(directory=directory))
    # The socket path, including /peerfs.sock, has exactly107 pathname bytes.
    base = state["roots"]
    exact = base / ("p" * (107 - len(str(base).encode()) - len(b"/peerfs.sock") - 1))
    exact.mkdir(mode=0o700)
    prepare(terms(directory=exact))
    longer = base / (exact.name + "x")
    longer.mkdir(mode=0o700)
    expect(h, "POST", BASE, 400, terms(directory=longer))
    name_bytes = len(exact.name.encode())
    unicode_name = "é" * (name_bytes // 2) + "u" * (name_bytes % 2)
    utf8_exact = base / unicode_name
    utf8_exact.mkdir(mode=0o700)
    prepare(terms(directory=utf8_exact))
    utf8_over = base / (unicode_name + "x")
    utf8_over.mkdir(mode=0o700)
    expect(h, "POST", BASE, 400, terms(directory=utf8_over))
    if os.geteuid() == 0:
        foreign = Path(terms()["directory"])
        os.chown(foreign, 65534, -1)
        try:
            expect(h, "POST", BASE, 403, terms(directory=foreign))
        finally:
            os.chown(foreign, os.geteuid(), -1)
        foreign_parent = state["roots"] / "foreign-ancestor"
        foreign_parent.mkdir(mode=0o700)
        owned_child = foreign_parent / "space"
        owned_child.mkdir(mode=0o700)
        os.chown(foreign_parent, 65534, -1)
        try:
            expect(h, "POST", BASE, 409, terms(directory=owned_child))
        finally:
            os.chown(foreign_parent, os.geteuid(), -1)
        body, registration = prepare()
        directory = Path(body["directory"])
        os.chown(directory, 65534, -1)
        try:
            expect(h, "POST", route(registration, "sign-commit"), 409, signing(registration, message(h.id)))
        finally:
            os.chown(directory, os.geteuid(), -1)
    for mutation in ("mode", "replace", "ancestor", "ancestor-mode"):
        parent = state["roots"] / ("fence-" + mutation)
        parent.mkdir(mode=0o700)
        directory = parent / "space"
        directory.mkdir(mode=0o700)
        body, registration = prepare(terms(directory=directory))
        if mutation == "mode":
            directory.chmod(0o750)
        elif mutation == "replace":
            directory.rename(parent / "original")
            directory.mkdir(mode=0o700)
        elif mutation == "ancestor-mode":
            parent.chmod(0o777)
        else:
            parent.rename(parent.with_name(parent.name + "-original"))
            parent.symlink_to(parent.with_name(parent.name + "-original"), target_is_directory=True)
        expect(h, "POST", route(registration, "sign-commit"), 409, signing(registration, message(h.id)))
        check(expect(h, "GET", route(registration)) == registration
              and expect(h, "POST", BASE, body=body) == registration, "damaged-directory replay changed immutable history")
        expect(h, "POST", route(registration, "release"), body={"binding_id": registration["binding_id"]})


@suite.case("actual_signatures_and_offline_purity", "PF-1 section5: exact runtime key, bytes, determinism, no IO")
def _():
    h, _ = fixture()
    _, registration = prepare()
    directory = Path(registration["directory"])
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(directory / "peerfs.sock"))
    listener.listen()
    listener.settimeout(.05)
    calls, done = [], threading.Event()
    def collect():
        while not done.is_set():
            try:
                connection, _ = listener.accept()
                calls.append(1)
                connection.close()
            except socket.timeout:
                pass
    thread = threading.Thread(target=collect, daemon=True)
    thread.start()
    try:
        with (directory / "space.lock").open("wb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            def signatures():
                initial = message(h.id)
                first = sign(h, registration, initial)
                check(sign(h, registration, initial) == first, "exact signing retry changed deterministic signature")
                responses = []
                parents = [b"\1" + bytes([n]) * 32 for n in (1, 2)]
                for data in (message(h.id, agent="", session=""),
                             message(h.id, parents=parents, agent="agent α", session="session 東京", timestamp=2**64 - 1,
                                     text="Merge α\nPreserve parent order", predecessor=parents[0]),
                             message(h.id, parents=parents[::-1])):
                    responses.append(sign(h, registration, data)["signature"])
                check(len(set([first["signature"], *responses])) == 4, "different canonical messages gained one signature")
            pure(h, signatures)
        check(not calls, "local signing called the provider")
    finally:
        done.set()
        thread.join(timeout=1)
        listener.close()
    (directory / "peerfs.sock").unlink()
    pure(h, lambda: sign(h, registration, message(h.id)))


@suite.case("typed_parser_and_encoding_refusals", "PF-1 section5: full canonical decoding before host key use")
def _():
    h, _ = fixture()
    _, registration = prepare()
    data = message(h.id)
    start = len(DOMAIN)
    parent = start + 1 + 33
    change = parent + 1
    author = change + 17
    agent = author + 1 + len(h.id)
    timestamp = agent + 2
    text = timestamp + 1
    bad = [(data[:start - 1] + b"\n" + data[start:], 400),
           (data[:start] + b"\4" + data[start + 1:], 400),
           (data[:start + 1] + b"\2" + data[start + 2:], 400),
           (data[:parent] + b"\x80\0" + data[parent + 1:], 400),
           (data[:parent] + uleb(65) + data[parent + 1:], 400),
           (data[:parent] + b"\xff" * 9 + b"\2" + data[parent + 1:], 400),
           (data[:change] + b"\x10" + b"\x22" * 15, 400),
           (data[:change] + b"\x0f" + data[change + 1:], 400),
           (data[:change] + b"\x90\0" + data[change + 1:], 400),
           (data[:author] + b"\xff" * 10 + b"\0", 400),
           (data[:agent] + b"\2" + data[agent + 1:], 400),
           (data[:agent + 1] + b"\2" + data[agent + 2:], 400),
           (data[:author] + bytes([len(h.id) | 128]) + b"\0" + data[author + 1:], 400),
           (data[:timestamp] + b"\x80\0" + data[timestamp + 1:], 400),
           (data[:timestamp] + b"\xff" * 9 + b"\2" + data[timestamp + 1:], 400),
           (data[:text] + b"\x80\0" + data[text + 1:], 400),
           (data[:text + 1] + b"\xff" + data[text + 2:], 400),
           (data[:-2] + b"\2\0", 400), (data[:-1] + b"\1", 400), (data + b"\0", 400),
           (message("host_" + "f" * 64), 403),
           (message(h.id, parents=[b"\2" + b"\0" * 32]), 400),
           (message(h.id, predecessor=b"\2" + b"\0" * 32), 400),
           (message(h.id, agent=b"\xff"), 400), (message(h.id, session=b"\xff"), 400)]
    bad += [(data[:n], 400) for n in (0, start - 1, start, parent, change + 1, author + 1, agent, text, len(data) - 1)]
    signed = sign(h, registration, data)
    bad.append((data[:-1] + b"\1" + string(base64.b64decode(signed["public_key"]))
                + string(base64.b64decode(signed["signature"])), 400))
    def refuse():
        for mutated, status in bad:
            expect(h, "POST", route(registration, "sign-commit"), status, signing(registration, mutated))
        valid = signing(registration, data)
        encoded = valid["message_base64"]
        for malformed in (None, 1, [], encoded.rstrip("="), encoded + "\n", encoded + "=", "_" + encoded[1:],
                          encoded[:-3] + "B=="):
            expect(h, "POST", route(registration, "sign-commit"), 400, {**valid, "message_base64": malformed})
    pure(h, refuse)


@suite.case("inclusive_commit_and_body_limits", "PF-1 section5/7: realizable maxima and one over")
def _():
    h, _ = fixture()
    _, registration = prepare()
    parents = [b"\1" + bytes([n]) * 32 for n in range(64)]
    largest = message(h.id, parents=parents, agent="α" * 128, session="s" * 256,
                      text="m" * 16384, timestamp=2**64 - 1, predecessor=parents[0])
    pure(h, lambda: sign(h, registration, largest))
    for data in (message(h.id, parents=parents + [parents[0]]), message(h.id, agent="α" * 128 + "a"),
                 message(h.id, session="s" * 257), message(h.id, text="m" * 16385)):
        expect(h, "POST", route(registration, "sign-commit"), 400, signing(registration, data))
    #65536 cannot be a valid commit under the stricter individual-field limits.
    expect(h, "POST", route(registration, "sign-commit"), 400, signing(registration, b"\0" * 65536))
    expect(h, "POST", route(registration, "sign-commit"), 413, signing(registration, b"\0" * 65537))
    payload = compact(signing(registration, largest))
    result = expect(h, "POST", route(registration, "sign-commit"), raw=payload + b" " * (96 * 1024 - len(payload)))
    verify(h.public_key, result["signature"], largest)
    expect(h, "POST", route(registration, "sign-commit"), 413, raw=payload + b" " * (96 * 1024 + 1 - len(payload)))


@suite.case("concurrent_prepare_and_release", "PF-1 sections3/5: one lifetime and serialized release")
def _():
    h, _ = fixture()
    body = terms()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: request(h, "POST", BASE, body), range(8)))
    check(sorted(status for status, _ in results) == [200] * 7 + [201]
          and all(value == results[0][1] for _, value in results), "concurrent exact preparation created divergent bindings")
    registration = results[0][1]
    retained_object = Path(body["directory"]) / "retained-object"
    retained_object.write_bytes(b"release does not erase objects")
    barrier = threading.Barrier(9)
    def racing(index):
        barrier.wait(timeout=5)
        if index == 0:
            return request(h, "POST", route(registration, "release"), {"binding_id": registration["binding_id"]})
        return request(h, "POST", route(registration, "sign-commit"), signing(registration, message(h.id)))
    with ThreadPoolExecutor(max_workers=9) as pool:
        results = list(pool.map(racing, range(9)))
    released = results[0][1]
    check(results[0][0] == 200 and released["state"] == "released", "concurrent release did not commit")
    for status, value in results[1:]:
        check(status in (200, 409), "sign/release race produced an unexpected result")
        if status == 200:
            verify(h.public_key, value["signature"], message(h.id))
        else:
            check(value == {"code": "conflict", "error": "conflict"}, "release race leaked an unsafe error")
    def history():
        for _ in range(4):
            expect(h, "POST", route(registration, "sign-commit"), 409, signing(registration, message(h.id)))
        check(expect(h, "POST", route(registration, "release"), body={"binding_id": registration["binding_id"]}) == released
              and expect(h, "GET", route(registration)) == released
              and expect(h, "POST", BASE, body=body) == released, "released replay did not retain the tombstone")
        check(released not in expect(h, "GET", BASE), "released tombstone appeared in live list")
    pure(h, history)
    check(retained_object.read_bytes() == b"release does not erase objects", "release deleted or changed filesystem contents")
    retained_object.unlink()
    # A new logical ID may prepare the same now-empty directory; neither old ID is reused.
    _, replacement = prepare({**body, "space_id": "space_" + os.urandom(16).hex()})
    check(replacement["binding_id"] != registration["binding_id"], "release reused a binding lifetime")
    pure(h, lambda: check(expect(h, "POST", BASE, body=body) == released,
                          "new directory lifetime hid exact released history"))
    competing = terms()
    proposals = [{**competing, "space_id": "space_" + os.urandom(16).hex()} for _ in range(6)]
    with ThreadPoolExecutor(max_workers=6) as pool:
        outcomes = list(pool.map(lambda proposed: request(h, "POST", BASE, proposed), proposals))
    check(sorted(status for status, _ in outcomes) == [201] + [409] * 5,
          "competing concurrent logical IDs did not fence one live directory binding")
    # Dispatch a complete request and discard its response. Either commit result
    # is recovered by one exact replay, rather than inferred from disconnection.
    unknown = terms()
    payload = compact(unknown)
    with socket.socket(socket.AF_UNIX) as abandoned:
        abandoned.settimeout(5)
        abandoned.connect(str(h.state / "admin.sock"))
        abandoned.sendall(f"POST {BASE} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\n\r\n".encode() + payload)
    status, recovered = request(h, "POST", BASE, unknown)
    check(status in (200, 201), "unknown-response exact replay did not recover/create one binding")
    view(recovered, unknown, h)
    pure(h, lambda: check(expect(h, "GET", route(recovered)) == recovered
                          and expect(h, "POST", BASE, body=unknown) == recovered,
                          "unknown-response recovery did not retain one immutable outcome"))
    state["tombstone"] = body, released


@suite.case("live_limit_and_restart", "PF-1 sections3/7:256 live rows, replay, release and durable state")
def _():
    h, _ = fixture()
    live = expect(h, "GET", BASE)
    for _ in range(256 - len(live)):
        _, registration = prepare()
        live.append(registration)
    rejected = terms()
    pure(h, lambda: expect(h, "POST", BASE, 429, rejected))
    retained = live[0]
    body = {key: retained[key] for key in ("space_id", "network_id", "context_id", "directory")}
    pure(h, lambda: check(expect(h, "POST", BASE, body=body) == retained, "limit blocked exact replay"))
    expect(h, "POST", route(retained, "release"), body={"binding_id": retained["binding_id"]})
    _, restart_binding = prepare(rejected)
    before = expect(h, "GET", BASE)
    old_host, old_key, key_files = h.id, h.public_key, files(h)
    h.restart(kill=True)
    check(h.id == old_host and h.public_key == old_key and files(h) == key_files, "restart changed host identity/private keys")
    pure(h, lambda: check(expect(h, "GET", BASE) == before, "restart changed live binding history"))
    if "tombstone" in state:
        body, tombstone = state["tombstone"]
        check(expect(h, "GET", route(tombstone)) == tombstone and expect(h, "POST", BASE, body=body) == tombstone,
              "restart lost released tombstone")
    pure(h, lambda: sign(h, restart_binding, message(h.id)))


def tls_request(context, port, method, path, body=None):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="peerspan") as stream:
            payload = b"" if body is None else compact(body)
            stream.sendall(f"{method} {path} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\n\r\n".encode() + payload)
            response = http.client.HTTPResponse(stream)
            response.begin()
            response.read()
            return response.status


@suite.case("owner_router_isolation", "PF-1 section3: authenticated peer, pairing, adapter and helper404")
def _():
    h, net = fixture()
    outsider = state["outsider"]
    join_new_person(h, outsider, "visitor", ssh_key(outsider.root, "visitor"), net["id"])
    # Use an already prepared binding, so this case also works after the limit gate.
    bindings = expect(h, "GET", BASE)
    registration = bindings[0] if bindings else prepare()[1]
    paths = [("GET", BASE, None), ("GET", route(registration), None),
             ("POST", BASE, {k: registration[k] for k in ("space_id", "network_id", "context_id", "directory")})]
    paths += [("POST", route(registration, action), {"binding_id": registration["binding_id"]})
              for action in ("activate", "release", "sign-commit", "host-keys/check")]
    def peer(method, path, body=None):
        arguments = [str(suite.probe_bin), "--state", str(outsider.state), "--address", h.peer_address,
                     "--alpn", "peerspan-peer/1", "--method", method, "--path", path]
        if body is not None:
            arguments.append("--body-stdin")
        result = subprocess.run(arguments, input=b"" if body is None else compact(body), capture_output=True, timeout=6)
        check(result.returncode == 0, "authenticated peer probe transport failed")
        return json.loads(result.stdout)["status"]
    check(peer("GET", f"/peer/v2/networks/{net['id']}/catalog") == 200,
          "genuine outsider mTLS principal did not reach the admitted normal peer router")
    for method, path, body in paths:
        check(peer(method, path, body) == 404, "normal authenticated peer exposed a PF owner route")
    adapter = h.agent("boundary")
    try:
        check(adapter.call("GET", "/adapter/v1/session")[0] == 200, "adapter fixture is not authorized")
        for method, path, body in paths:
            check(adapter.call(method, path, body)[0] == 404, "credential-scoped adapter exposed a PF owner route")
    finally:
        adapter.stop()
    # A configured real external host gets no message grant from registration/signing.
    denied = {"request_id": "request_" + os.urandom(16).hex(), "target_agent_id": adapter.id,
              "deadline": (h.now() + timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "content": "no filesystem preparation grants message access", "grant_id": "grant_" + "e" * 32}
    result = subprocess.run([str(suite.probe_bin), "--state", str(outsider.state), "--address", h.peer_address,
                             "--alpn", "peerspan-peer/1", "--method", "POST", "--path", "/peer/v1/messages", "--body-stdin"],
                            input=compact(denied), capture_output=True, timeout=6)
    check(result.returncode == 0 and json.loads(result.stdout).get("status") == 403,
          "prepared bindings/signatures granted external message access")
    cert, key = suite.work / "tls-cert", suite.work / "tls-key"
    openssl("req", "-x509", "-newkey", "ed25519", "-nodes", "-subj", "/CN=pf-boundary",
            "-days", "1", "-keyout", key, "-out", cert)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
    context.load_cert_chain(str(cert), str(key))
    context.set_alpn_protocols(["peerspan-bootstrap/1"])
    for method, path, body in paths:
        check(tls_request(context, h.bootstrap_port, method, path, body) == 404, "pairing/bootstrap exposed a PF owner route")
    helper = suite.host_bin.parent / "peerspan-helper"
    helper_state = suite.work / "helper"
    helper_state.mkdir(mode=0o700)
    port = free_port(socket.SOCK_STREAM)
    log = (suite.work / "helper.log").open("wb")
    process = suite.spawn([str(helper), "--state", str(helper_state), "serve", "--listen", f"127.0.0.1:{port}"],
                          stdout=log, stderr=log)
    log.close()
    deadline = time.monotonic() + 5
    while True:
        try:
            status = tls_request(context, port, "GET", BASE)
            break
        except (OSError, ssl.SSLError):
            check(time.monotonic() < deadline and process.poll() is None, "helper boundary fixture did not become ready")
            time.sleep(.05)
    check(status == 404, "helper exposed the PF owner list")
    for method, path, body in paths[1:]:
        check(tls_request(context, port, method, path, body) == 404, "helper exposed a PF owner route")
    # No separate MCP HTTP router exists: its scoped tools use adapter.sock.
    text = h.log.read_text(errors="replace")
    check(str(state["roots"]) not in text and "message_base64" not in text and "fsbind_" not in text,
          "routine daemon logs contain private registration/signing material")


suite.finish()
