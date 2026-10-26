#!/usr/bin/env python3
"""Independent optional-helper wire cases from the merged public DEC contracts.

This program imports only our independently authored crypto fixtures.  It does
not build a product, inspect helper storage contents or import existing tests.
TLS certificates, keys, tokens and pairing secrets belong only to this fixture.
The first bounded slice covers opaque mailbox persistence/portability and relay4
framing/identity; it does not claim host enrollment, QUIC, NAT or installed use.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import http.client
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import ssl
import stat
import struct
import subprocess
import tempfile
import time

from decentralized_fixtures import PIN, FixtureKeys, b64, lines, raw_json, sha, unb64
from decentralized_vectors import same_json, strict_output


PROTOCOLS = ["peerspan-bootstrap/1", "peerspan-relay/4"]
CONTRACT_PIN = "24ccdc34833798d2f67d3c7206d3c0419daa3569"
BOOTSTRAP, RELAY = PROTOCOLS
NODE_AEAD = r"""
const fs = require('node:fs'), crypto = require('node:crypto');
const v = JSON.parse(fs.readFileSync(0, 'utf8'));
const key = crypto.hkdfSync('sha256', Buffer.from(v.secret, 'base64'),
  Buffer.from(v.salt, 'base64'), Buffer.from(v.info, 'base64'), 32);
const c = crypto.createCipheriv('aes-256-gcm', key, Buffer.from(v.nonce, 'base64'));
c.setAAD(Buffer.from(v.ad, 'base64'));
const ciphertext = Buffer.concat([c.update(Buffer.from(v.plaintext, 'base64')),
  c.final(), c.getAuthTag()]);
const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(v.nonce, 'base64'));
d.setAAD(Buffer.from(v.ad, 'base64')); d.setAuthTag(ciphertext.subarray(-16));
const recovered = Buffer.concat([d.update(ciphertext.subarray(0,-16)),d.final()]);
if (!recovered.equals(Buffer.from(v.plaintext, 'base64'))) process.exit(2);
process.stdout.write(JSON.stringify({ciphertext_base64:ciphertext.toString('base64')}));
"""


class CheckFailure(Exception):
    pass


def require(condition: bool, description: str) -> None:
    if not condition:
        raise CheckFailure(description)


def utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def recv_exact(stream: ssl.SSLSocket, count: int) -> bytes:
    result = b""
    while len(result) < count:
        chunk = stream.recv(count - len(result))
        if not chunk:
            raise EOFError("transport closed")
        result += chunk
    return result


@dataclass
class Response:
    status: int
    headers: list[tuple[str, str]]
    body: bytes

    def json(self) -> dict:
        return strict_output(self.body)


class ClientIdentity:
    def __init__(self, keys: FixtureKeys, name: str) -> None:
        self.public = keys.public(name)
        self.host_id = bytes.fromhex(sha(unb64(self.public)))
        key_path, _ = keys._key(name)  # Our fixture-owned primitive, never product storage.
        self.pem = keys.directory / (name + ".pem")
        self.cert = keys.directory / (name + ".crt")
        subprocess.run(["openssl", "pkey", "-inform", "DER", "-in", str(key_path),
                        "-out", str(self.pem)], check=True, capture_output=True)
        self.pem.chmod(0o600)
        subprocess.run(["openssl", "req", "-new", "-x509", "-key", str(self.pem),
                        "-out", str(self.cert), "-days", "2", "-subj", "/CN=owned-helper-fixture"],
                       check=True, capture_output=True)
        self.cert.chmod(0o600)

    def connect(self, address: str, expected_key: str, alpn: str) -> ssl.SSLSocket:
        self.last_tls_completed = False
        host, port = address.rsplit(":", 1)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols([alpn])
        context.load_cert_chain(self.cert, self.pem)
        raw = socket.create_connection((host.strip("[]"), int(port)), timeout=5)
        stream = None
        try:
            stream = context.wrap_socket(raw, server_hostname="owned-helper-fixture")
            self.last_tls_completed = True
            stream.settimeout(10)
            # Extract SPKI from the actual TLS certificate before sending a bearer
            # or token.  A successful unverified TLS handshake is not the pin.
            cert_pem = ssl.DER_cert_to_PEM_cert(stream.getpeercert(binary_form=True)).encode()
            public_pem = subprocess.run(["openssl", "x509", "-pubkey", "-noout"],
                                        input=cert_pem, check=True, capture_output=True).stdout
            public_der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"],
                                        input=public_pem, check=True, capture_output=True).stdout
            prefix = bytes.fromhex("302a300506032b6570032100")
            require(public_der == prefix + unb64(expected_key), "actual helper TLS key differs from configured pin")
            require(stream.selected_alpn_protocol() == alpn, "unexpected negotiated ALPN")
            return stream
        except BaseException:
            (stream if stream is not None else raw).close()
            raise


class HelperProcess:
    def __init__(self, binary: Path, root: Path, name: str, token: bytes | None = None) -> None:
        self.binary, self.root, self.name, self.token = binary, root, name, token
        self.state = root / (name + "-state")
        self.stdout_path = root / (name + ".stdout")
        self.stderr_path = root / (name + ".stderr")
        self.process: subprocess.Popen | None = None
        self.metadata: dict | None = None
        self.initial_stdout_tail = b""
        self.last_mutation = self.last_get = 0.0
        self.tokens_file = root / (name + "-tokens.json")
        if token is not None:
            self.tokens_file.write_bytes(raw_json({"format": 1, "accounts": [{"id": "fixture", "tokens": [b64(token)]}]}))
            self.tokens_file.chmod(0o600)

    def start(self) -> dict:
        command = [str(self.binary), "--state", str(self.state), "serve", "--listen", "127.0.0.1:0"]
        if self.token is not None:
            command += ["--tokens-file", str(self.tokens_file)]
        self.stderr = self.stderr_path.open("ab")
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=self.stderr, bufsize=0,
                                        start_new_session=True, env=isolated_env(self.root / (self.name + "-home")))
        selector = selectors.DefaultSelector()
        selector.register(self.process.stdout, selectors.EVENT_READ)
        try:
            deadline, data = time.monotonic() + 10, b""
            while b"\n" not in data:
                remaining = deadline - time.monotonic()
                require(remaining > 0 and bool(selector.select(remaining)),
                        "helper listen metadata did not arrive within10s")
                chunk = os.read(self.process.stdout.fileno(), 8193 - len(data))
                require(bool(chunk), "helper closed before complete listen metadata")
                data += chunk
                require(len(data) <= 8192, "helper metadata exceeds8192bytes")
            line, self.initial_stdout_tail = data.split(b"\n", 1)
            line += b"\n"
            require(line.endswith(b"\n") and len(line) <= 8192, "helper metadata is not one bounded JSON line")
            value = strict_output(line)
            require(set(value) == {"public_key", "address", "protocols"}, "helper listen metadata fields differ")
            require(value["protocols"] == PROTOCOLS, "helper advertised protocols differ")
            require(b64(unb64(value["public_key"])) == value["public_key"] and len(unb64(value["public_key"])) == 32,
                    "helper metadata key is not canonical Ed25519")
            require(isinstance(value["address"], str) and value["address"].startswith("127.0.0.1:"),
                    "helper did not report actual loopback endpoint")
            require(int(value["address"].rsplit(":", 1)[1]) > 0, "helper reported unbound port")
            self.metadata = value
            with self.stdout_path.open("ab") as output:
                output.write(line)
            return value
        finally:
            selector.close()

    def stop(self) -> None:
        if self.process is None:
            return
        process, self.process = self.process, None
        try:
            if process.poll() is None:
                # Only this tracked fixture-owned process group is signalled.
                require(os.getpgid(process.pid) == process.pid, "helper PGID ownership changed")
                os.killpg(process.pid, signal.SIGTERM)
            try:
                tail, _ = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                tail, _ = process.communicate(timeout=5)
                raise CheckFailure("helper failed its 10s fixture shutdown deadline")
            with self.stdout_path.open("ab") as output:
                output.write(tail)
            require(not self.initial_stdout_tail and not tail,
                    "helper wrote application logs or additional metadata to stdout")
            require(process.returncode == 0, "helper exited nonzero on ordinary shutdown")
        finally:
            self.stderr.close()

    def pace(self, method: str) -> None:
        # One source bucket is shared by every fixture TLS identity.  Deliberate
        # malformed requests are charged too; ordinary cases never swallow429.
        field, interval = ("last_get", 1.05) if method == "GET" else ("last_mutation", 0.55)
        delay = getattr(self, field) + interval - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        setattr(self, field, time.monotonic())

    def request(self, identity: ClientIdentity, method: str, path: str, *, body: bytes = b"",
                capability: str | None = None, headers: list[tuple[str, str]] | None = None,
                resource: bytes | None | str = "configured", expected_pin: str | None = None) -> Response:
        self.pace(method)
        token = self.token if resource == "configured" else resource
        pairs = [("Host", self.metadata["address"]), ("Connection", "close")]
        if capability is not None:
            pairs.append(("Authorization", "Bearer " + capability))
        if token is not None:
            require(isinstance(token, bytes), "fixture resource token type")
            pairs.append(("X-Peerspan-Resource-Token", b64(token)))
        pairs += headers or []
        if method == "POST" or body:
            pairs.append(("Content-Length", str(len(body))))
            pairs.append(("Content-Type", "application/json"))
        wire = (method + " " + path + " HTTP/1.1\r\n").encode("ascii")
        wire += b"".join((key + ": " + value + "\r\n").encode("ascii") for key, value in pairs) + b"\r\n" + body
        stream = identity.connect(self.metadata["address"], expected_pin or self.metadata["public_key"], BOOTSTRAP)
        try:
            stream.sendall(wire)
            response = http.client.HTTPResponse(stream)
            response.begin()
            data = response.read(48 * 1024 * 1024 + 1)
            require(len(data) <= 48 * 1024 * 1024, "helper response exceeded48MiB")
            result = Response(response.status, response.getheaders(), data)
            # The contract permits exactly one request per TLS connection.
            require(not stream.recv(1), "helper kept bootstrap connection open after response")
            return result
        finally:
            stream.close()

    def info(self) -> subprocess.CompletedProcess:
        return subprocess.run([str(self.binary), "--state", str(self.state), "info"],
                              env=isolated_env(self.root / (self.name + "-home")),
                              capture_output=True, timeout=10)


def isolated_env(home: Path) -> dict:
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    result = dict(os.environ)
    for key in list(result):
        if key.startswith("PEERSPAN_") or key == "SSH_AUTH_SOCK":
            del result[key]
    result.update(HOME=str(home), XDG_CONFIG_HOME=str(home / "config"),
                  XDG_STATE_HOME=str(home / "state"), XDG_DATA_HOME=str(home / "data"))
    return result


class Mailbox:
    def __init__(self, keys: FixtureKeys, label: str, *, remaining: int = 280) -> None:
        self.keys = keys
        self.secret = os.urandom(16)
        self.locator = sha(lines("peerspan-decentralized-locator-v1", b64(self.secret)))
        self.capability = sha(lines("peerspan-decentralized-read-cap-v1", b64(self.secret)))
        now = datetime.now(timezone.utc).replace(microsecond=0)
        self.created = now - timedelta(seconds=300 - remaining)
        self.created_at, self.expires_at = utc(self.created), utc(self.created + timedelta(seconds=300))
        # A helper does not inspect inner membership/packet bodies.  A valid
        # encrypted catalog-only component is enough to exercise opaque storage.
        self.request_id = "link_" + sha(lines("owned-helper-fixture", label, os.urandom(32).hex()))
        self.frames: list[dict] = []
        self.frame_bytes: list[bytes] = []
        self.first = self.frame("request", "helper-client-a")

    def frame(self, role: str, writer: str, plaintext: bytes | None = None) -> bytes:
        frame_id = os.urandom(32).hex()
        public = self.keys.public(writer)
        if plaintext is None:
            # The helper must not parse this independently encrypted inner proof
            # carrier.  It still has the public fixed plaintext object shape.
            plaintext = raw_json({"packet_base64": "-", "catalog_base64": b64(b'{"opaque_fixture_only":true}'), "contacts": []})
        ad = lines("peerspan-decentralized-frame-v1", self.request_id, self.locator,
                   role, public, frame_id, self.created_at, self.expires_at)
        crypto_input = {"secret": b64(self.secret),
                        "salt": b64(bytes.fromhex(sha(lines("peerspan-decentralized-frame-salt-v1", self.request_id)))),
                        "info": b64(lines("peerspan-decentralized-frame-key-v1", self.request_id, role, public)),
                        "nonce": b64(bytes.fromhex(sha(lines("peerspan-decentralized-frame-nonce-v1", frame_id)))[:12]),
                        "ad": b64(ad), "plaintext": b64(plaintext)}
        output = subprocess.run(["/usr/bin/node", "-e", NODE_AEAD], input=raw_json(crypto_input),
                                capture_output=True, check=True, timeout=10)
        ciphertext = strict_output(output.stdout)["ciphertext_base64"]
        signature = b64(self.keys.sign(writer, lines("peerspan-decentralized-frame-envelope-v1",
                                                    ad.decode(), sha(unb64(ciphertext)))))
        frame = {"format": 1, "request_id": self.request_id, "locator": self.locator,
                 "role": role, "writer_host_public_key": public, "frame_id": frame_id,
                 "created_at": self.created_at, "expires_at": self.expires_at,
                 "ciphertext_base64": ciphertext, "signature": signature}
        self.frames.append(frame)
        value = raw_json(frame)
        self.frame_bytes.append(value)
        return value

    def create(self, first: bytes | None = None, *, alias: bool = False) -> bytes:
        terms = {"format": 1, "request_id": self.request_id, "locator": self.locator,
                 "read_cap_hash": sha(self.capability.encode()), "created_at": self.created_at,
                 "expires_at": self.expires_at}
        # Insert the ORIGINAL first-frame bytes; outer JSON aliases cannot alter
        # the typed creation identity or silently reserialize the nested frame.
        if alias:
            prefix = json.dumps(terms, sort_keys=True, indent=2).encode()[:-1] + b',\n "frame": '
        else:
            prefix = raw_json(terms)[:-1] + b',"frame":'
        return prefix + (self.first if first is None else first) + b"}"

    def expected(self, frames: list[dict] | None = None) -> dict:
        return {"format": 1, "request_id": self.request_id, "created_at": self.created_at,
                "expires_at": self.expires_at,
                "frames": sorted(self.frames if frames is None else frames,
                                 key=lambda f: (f["role"], f["writer_host_public_key"], f["frame_id"]))}


class RelayClient:
    def __init__(self, helper: HelperProcess, identity: ClientIdentity) -> None:
        self.stream = identity.connect(helper.metadata["address"], helper.metadata["public_key"], RELAY)
        self.stream.settimeout(5)

    def send(self, kind: int, payload: bytes = b"") -> None:
        self.stream.sendall(struct.pack(">BH", kind, len(payload)) + payload)

    def read(self) -> tuple[int, bytes]:
        kind, length = struct.unpack(">BH", recv_exact(self.stream, 3))
        return kind, recv_exact(self.stream, length)

    def auth(self, token: bytes = b"") -> None:
        self.send(0, token)
        require(self.read() == (7, b""), "relay AUTH did not return exact AUTH_OK")

    def closed(self) -> None:
        try:
            require(self.stream.recv(1) == b"", "relay protocol error returned unexpected data")
        except (ssl.SSLEOFError, ConnectionResetError):
            pass

    def close(self) -> None:
        self.stream.close()


class Suite:
    def __init__(self, keys: FixtureKeys, binary: Path, root: Path) -> None:
        self.keys, self.binary, self.root = keys, binary, root
        self.rows: list[dict] = []
        self.a = ClientIdentity(keys, "helper-client-a")
        self.b = ClientIdentity(keys, "helper-client-b")
        self.helper_a = HelperProcess(binary, root, "anonymous")
        self.token = os.urandom(32).hex().encode()
        self.helper_b = HelperProcess(binary, root, "credentialed", self.token)
        self.sensitive: set[bytes] = {self.token, b64(self.token).encode()}

    def case(self, name: str, function) -> None:
        start = time.monotonic()
        try:
            function()
        except BaseException as error:
            self.rows.append({"name": name, "passed": False, "error_type": type(error).__name__,
                              "detail": str(error) if isinstance(error, CheckFailure) else "fixture/transport failure; see retained public diagnostics",
                              "seconds": round(time.monotonic() - start, 3)})
            print("FAIL " + name, flush=True)
            raise
        self.rows.append({"name": name, "passed": True, "seconds": round(time.monotonic() - start, 3)})
        print("PASS " + name, flush=True)

    def response(self, response: Response, status: int, expected: dict | None = None,
                 code: str | set[str] | None = None) -> None:
        require(response.status == status, f"HTTP status {response.status}, expected {status}; body_sha256={sha(response.body)}")
        if status == 204:
            require(not response.body, "204 response had a body")
        elif expected is not None:
            require(same_json(response.json(), expected), "HTTP success shape/content differs; body_sha256=" + sha(response.body))
        elif code is not None:
            value = response.json()
            require(set(value) == {"code", "error", "required_ids"}, "error envelope fields differ")
            require(value["code"] in ({code} if isinstance(code, str) else code), "error code differs")
            require(isinstance(value["error"], str) and bool(value["error"]) and value["required_ids"] == [],
                    "opaque helper returned malformed error/proof requirements")

    def box(self, label: str, *, remaining: int = 280) -> Mailbox:
        value = Mailbox(self.keys, label, remaining=remaining)
        self.sensitive.add(value.capability.encode())
        self.sensitive.add(value.first)
        self.sensitive.update(f["ciphertext_base64"].encode() for f in value.frames)
        return value

    def lifecycle(self) -> None:
        h = self.helper_a
        def missing() -> None:
            result = h.info()
            require(result.returncode != 0 and b"not_found" in result.stderr + result.stdout,
                    "missing helper info did not refuse not_found")
            require(not h.state.exists(), "read-only info created helper identity/state")
        self.case("operator/info_missing_is_read_only", missing)
        self.case("operator/first_serve_metadata", h.start)
        first_key = h.metadata["public_key"]
        def info() -> None:
            result = h.info()
            require(result.returncode == 0, "helper info failed")
            require(same_json(strict_output(result.stdout), {"public_key": first_key, "protocols": PROTOCOLS}),
                    "helper info differs from actual persistent transport identity")
        self.case("operator/info_matches_persisted_identity", info)
        def private_modes() -> None:
            require(stat.S_IMODE(h.state.stat().st_mode) == 0o700, "helper private state directory mode is not0700")
            for item in h.state.rglob("*"):
                require(not item.is_symlink(), "fixture helper created a state symlink")
                expected = 0o700 if item.is_dir() else 0o600
                require(stat.S_IMODE(item.stat().st_mode) == expected, "helper private state mode differs")
        self.case("operator/private_state_modes", private_modes)
        def exclusive() -> None:
            other = subprocess.run([str(self.binary), "--state", str(h.state), "serve", "--listen", "127.0.0.1:0"],
                                   env=isolated_env(self.root / "exclusive-home"), capture_output=True, timeout=10)
            require(other.returncode != 0, "second server acquired the same helper state")
        self.case("operator/exclusive_server_owner", exclusive)
        self.case("operator/second_independent_credentialed_helper", self.helper_b.start)
        require(first_key != self.helper_b.metadata["public_key"], "separate helper states unexpectedly share identity")

    def mailbox(self) -> None:
        h, box = self.helper_a, self.box("portable")
        path = "/bootstrap/v1/mailboxes/" + box.locator
        expected_create = {"request_id": box.request_id, "locator": box.locator}
        self.case("mailbox/create201", lambda: self.response(h.request(self.a, "POST", "/bootstrap/v1/mailboxes", body=box.create(), capability=box.capability), 201, expected_create))
        self.case("mailbox/exact_create_retry200", lambda: self.response(h.request(self.a, "POST", "/bootstrap/v1/mailboxes", body=box.create(), capability=box.capability), 200, expected_create))
        self.case("mailbox/outer_json_alias_keeps_original_frame", lambda: self.response(h.request(self.a, "POST", "/bootstrap/v1/mailboxes", body=box.create(alias=True), capability=box.capability), 200, expected_create))
        frame_alias = json.dumps(box.frames[0], sort_keys=True, indent=1).encode()
        self.case("mailbox/reserialized_first_frame_conflicts", lambda: self.response(h.request(self.a, "POST", "/bootstrap/v1/mailboxes", body=box.create(frame_alias), capability=box.capability), 409, code="operation_conflict"))
        self.case("mailbox/other_tls_host_can_read_exact_capability", lambda: self.response(h.request(self.b, "GET", path, capability=box.capability), 200, box.expected()))
        self.case("mailbox/wrong_capability403", lambda: self.response(h.request(self.b, "GET", path, capability="0" * 64), 403, code="forbidden"))
        self.case("mailbox/missing_bearer403", lambda: self.response(h.request(self.a, "GET", path), 403, code="forbidden"))
        for label, headers in [
            ("duplicate", [("Authorization", "Bearer " + box.capability)] * 2),
            ("alternate_scheme", [("Authorization", "bearer " + box.capability)]),
            ("extra_space", [("Authorization", "Bearer  " + box.capability)]),
            ("comma_joined", [("Authorization", "Bearer " + box.capability + ", Bearer " + box.capability)]),
        ]:
            self.case("mailbox/invalid_bearer_" + label, lambda headers=headers: self.response(h.request(self.a, "GET", path, headers=headers), 400, code="invalid"))
        self.case("mailbox/query_capability_alias_invalid", lambda: self.response(h.request(self.a, "GET", path + "?read_cap=" + box.capability, capability=box.capability), 400, code="invalid"))
        next_frame = box.frame("proofs", "helper-client-b")
        self.sensitive.add(box.frames[-1]["ciphertext_base64"].encode())
        self.case("mailbox/actual_tls_writer_required", lambda: self.response(h.request(self.a, "POST", path + "/frames", body=b'{"frame":' + next_frame + b'}', capability=box.capability), 403, code="forbidden"))
        forged = dict(box.frames[-1])
        signature = bytearray(unb64(forged["signature"])); signature[0] ^= 1
        forged["signature"] = b64(signature)
        self.case("mailbox/forged_outer_signature400_no_storage", lambda: self.response(h.request(self.b, "POST", path + "/frames", body=raw_json({"frame": forged}), capability=box.capability), 400, code="invalid"))
        self.case("mailbox/append_actual_other_writer", lambda: self.response(h.request(self.b, "POST", path + "/frames", body=b'{"frame":' + next_frame + b'}', capability=box.capability), 200, {"frame_id": box.frames[-1]["frame_id"]}))
        self.case("mailbox/exact_append_retry", lambda: self.response(h.request(self.b, "POST", path + "/frames", body=b'{"frame":' + next_frame + b'}', capability=box.capability), 200, {"frame_id": box.frames[-1]["frame_id"]}))
        alias = json.dumps(box.frames[-1], indent=1).encode()
        self.case("mailbox/frame_id_different_exact_bytes_conflict", lambda: self.response(h.request(self.b, "POST", path + "/frames", body=b'{"frame":' + alias + b'}', capability=box.capability), 409, code={"state_conflict", "operation_conflict"}))
        self.case("mailbox/sorted_frames_and_no_partial_bad_append", lambda: self.response(h.request(self.a, "GET", path, capability=box.capability), 200, box.expected()))
        # The SAME ciphertext crosses two independently pinned operators.  No
        # network grants, original keys or renewed operation bytes are involved.
        other = self.helper_b
        self.case("mailbox/required_resource_credential_missing403", lambda: self.response(other.request(self.a, "POST", "/bootstrap/v1/mailboxes", body=box.create(), capability=box.capability, resource=None), 403, code="forbidden"))
        self.case("mailbox/required_resource_credential_wrong403", lambda: self.response(other.request(self.a, "POST", "/bootstrap/v1/mailboxes", body=box.create(), capability=box.capability, resource=b"wrong-owned-fixture"), 403, code="forbidden"))
        self.case("mailbox/same_exact_ciphertext_on_replaceable_helper", lambda: self.response(other.request(self.a, "POST", "/bootstrap/v1/mailboxes", body=box.create(), capability=box.capability), 201, expected_create))
        self.case("mailbox/replacement_delivery_no_resign", lambda: self.response(other.request(self.b, "GET", path, capability=box.capability), 200, box.expected([box.frames[0]])))
        def restart() -> None:
            key = h.metadata["public_key"]
            h.stop(); h.start()
            require(h.metadata["public_key"] == key, "ordinary restart replaced helper transport pin")
            self.response(h.request(self.b, "GET", path, capability=box.capability), 200, box.expected())
        self.case("mailbox/exact_frames_and_pin_survive_restart", restart)
        self.case("mailbox/delete204", lambda: self.response(h.request(self.b, "DELETE", path, capability=box.capability), 204))
        self.case("mailbox/deleted_get404", lambda: self.response(h.request(self.a, "GET", path, capability=box.capability), 404, code="not_found"))
        self.case("mailbox/delete_tombstone_idempotent204", lambda: self.response(h.request(self.a, "DELETE", path, capability=box.capability), 204))
        self.case("mailbox/tombstone_create_cannot_revive410", lambda: self.response(h.request(self.a, "POST", "/bootstrap/v1/mailboxes", body=box.create(), capability=box.capability), 410, code="expired"))
        self.case("mailbox/tombstone_append_cannot_revive410", lambda: self.response(h.request(self.b, "POST", path + "/frames", body=b'{"frame":' + next_frame + b'}', capability=box.capability), 410, code="expired"))
        def erased_restart() -> None:
            h.stop(); h.start()
            self.response(h.request(self.a, "GET", path, capability=box.capability), 404, code="not_found")
            self.response(h.request(self.a, "POST", "/bootstrap/v1/mailboxes", body=box.create(), capability=box.capability), 410, code="expired")
        self.case("mailbox/deletion_tombstone_survives_restart", erased_restart)
        for route in ["/bootstrap/v1/activations", "/v1/status", "/v1/capabilities", "/v1/networks"]:
            self.case("isolation/helper_absent_" + route.strip("/").replace("/", "_"),
                      lambda route=route: self.response(h.request(self.a, "POST", route, body=b"{}", capability=box.capability), 404, code="not_found"))
        self.case("isolation/helper_has_no_participant_outcome", lambda: self.response(h.request(self.a, "GET", "/bootstrap/v1/operations/" + box.request_id, capability=box.capability), 404, code="not_found"))
        def wrong_method() -> None:
            response = h.request(self.a, "HEAD", path, capability=box.capability)
            require(response.status == 405, "implicit HEAD was accepted or returned wrong status")
            methods = {m.strip() for key, value in response.headers if key.lower() == "allow" for m in value.split(",")}
            require(methods == {"GET", "DELETE"}, "named mailbox route Allow methods differ")
        self.case("isolation/implicit_head405_exact_allow", wrong_method)
        # Pin substitution must fail BEFORE bearer/token is sent.  The client
        # deliberately supplies the OTHER operator's independently observed pin.
        def substitution() -> None:
            try:
                h.request(self.a, "GET", path, capability=box.capability, expected_pin=other.metadata["public_key"])
            except CheckFailure as error:
                require(str(error) == "actual helper TLS key differs from configured pin", "unexpected pin diagnostic")
            else:
                raise CheckFailure("substituted actual TLS key received a secret-derived capability")
        self.case("isolation/actual_tls_pin_checked_before_bearer", substitution)

    def expiry(self) -> None:
        h, box = self.helper_a, self.box("expiry", remaining=3)
        path = "/bootstrap/v1/mailboxes/" + box.locator
        self.case("expiry/create_short_remaining_signed_window", lambda: self.response(h.request(self.a, "POST", "/bootstrap/v1/mailboxes", body=box.create(), capability=box.capability), 201, {"request_id": box.request_id, "locator": box.locator}))
        deadline = (box.created + timedelta(seconds=300)).timestamp() + 0.05
        if deadline > time.time():
            time.sleep(deadline - time.time())
        self.case("expiry/at_actual_signed_deadline_get410", lambda: self.response(h.request(self.a, "GET", path, capability=box.capability), 410, code="expired"))
        self.case("expiry/elapsed_exact_create_retry410", lambda: self.response(h.request(self.a, "POST", "/bootstrap/v1/mailboxes", body=box.create(), capability=box.capability), 410, code="expired"))
        self.case("expiry/expired_delete204", lambda: self.response(h.request(self.a, "DELETE", path, capability=box.capability), 204))

    def relay(self) -> None:
        h = self.helper_a
        clients: list[RelayClient] = []
        def client(identity: ClientIdentity, helper: HelperProcess = h) -> RelayClient:
            value = RelayClient(helper, identity); clients.append(value); return value
        try:
            a, b = client(self.a), client(self.b)
            self.case("relay4/anonymous_auth_actual_tls_keys", lambda: (a.auth(), b.auth()))
            payload = os.urandom(64)
            def forwarding() -> None:
                a.send(1, self.b.host_id + payload)
                require(b.read() == (2, self.a.host_id + payload), "relay did not preserve actual source digest and opaque datagram")
            self.case("relay4/opaque_datagram_actual_source_identity", forwarding)
            def unknown() -> None:
                unknown_id = bytes.fromhex(sha(b"unregistered-owned-fixture"))
                a.send(1, unknown_id + payload)
                require(a.read() == (3, unknown_id), "relay unknown destination is not exact UNREACHABLE")
            self.case("relay4/unknown_destination_unreachable", unknown)
            def replacement() -> None:
                fresh = client(self.a); fresh.auth()
                a.closed()
                b.send(1, self.a.host_id + payload)
                require(fresh.read() == (2, self.b.host_id + payload), "successful replacement did not become sole actual host registration")
            self.case("relay4/successful_same_key_replacement_closes_old", replacement)
            for name, kind, body in [("send_before_auth", 1, self.b.host_id + payload),
                                     ("client_auth_ok_wrong_direction", 7, b""),
                                     ("auth_invalid_utf8", 0, b"\xff"),
                                     ("auth_control_character", 0, b"fixture\n"),
                                     ("unknown_type", 0x55, b"")]:
                def malformed(kind=kind, body=body) -> None:
                    c = client(self.a); c.send(kind, body); c.closed()
                self.case("relay4/" + name, malformed)
            for name, kind, body in [("client_receive_wrong_direction", 2, self.b.host_id + payload),
                                     ("datagram1501_rejected", 1, self.b.host_id + b"x" * 1501)]:
                def registered_bad(kind=kind, body=body) -> None:
                    c = client(self.a); c.auth(); c.send(kind, body); c.closed()
                self.case("relay4/" + name, registered_bad)
            # Failed credential AUTH on a NEW same-key connection cannot remove
            # the already authenticated registration on a separate operator.
            secure_a, secure_b = client(self.a, self.helper_b), client(self.b, self.helper_b)
            self.case("relay4/resource_credential_auth", lambda: (secure_a.auth(self.token), secure_b.auth(self.token)))
            def refused_replacement() -> None:
                bad = client(self.a, self.helper_b)
                bad.send(0, b"wrong-owned-fixture")
                require(bad.read() == (8, b""), "unauthorized AUTH did not return exact AUTH_REFUSED")
                bad.closed()
                secure_b.send(1, self.a.host_id + payload)
                require(secure_a.read() == (2, self.b.host_id + payload), "failed replacement evicted valid old registration")
            self.case("relay4/failed_replacement_does_not_evict", refused_replacement)
        finally:
            for value in clients:
                value.close()

    def logs_are_private(self) -> None:
        for helper in (self.helper_a, self.helper_b):
            value = helper.stderr_path.read_bytes() if helper.stderr_path.exists() else b""
            require(not any(secret and secret in value for secret in self.sensitive), "helper stderr disclosed fixture bearer/token/ciphertext")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", type=Path)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--results", type=Path)
    parser.add_argument("--self-check-only", action="store_true")
    args = parser.parse_args()
    if not args.self_check_only and (args.helper is None or args.work_dir is None or args.results is None):
        parser.error("--helper, --work-dir and --results are required for an actual helper run")
    keys = FixtureKeys()
    suite = None
    started = time.monotonic()
    try:
        keys.self_check()
        if args.self_check_only:
            mailbox = Mailbox(keys, "primitive-self-check")
            require(len(unb64(mailbox.frames[0]["ciphertext_base64"])) >= 16, "AEAD fixture omitted tag")
            print("PASS independent OpenSSL/OpenSSH and Node AES-GCM fixture primitives")
            return 0
        args.work_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        suite = Suite(keys, args.helper.resolve(), args.work_dir.resolve())
        failure = None
        try:
            suite.lifecycle(); suite.mailbox(); suite.expiry(); suite.relay()
        except BaseException as error:
            failure = type(error).__name__
        finally:
            for helper in (suite.helper_a, suite.helper_b):
                try:
                    helper.stop()
                except BaseException as error:
                    suite.rows.append({"name": "cleanup/" + helper.name, "passed": False,
                                       "error_type": type(error).__name__, "detail": "tracked helper shutdown failed"})
            try:
                suite.case("operator/no_bearer_token_or_ciphertext_logs", suite.logs_are_private)
            except BaseException:
                failure = "private_log_disclosure"
        receipt = {"contract_pin": CONTRACT_PIN, "fixture_contract_pin": PIN,
                   "implementation_source_read": False,
                   "suite_sha256": sha(Path(__file__).read_bytes()),
                   "fixture_sha256": sha(Path(__file__).with_name("decentralized_fixtures.py").read_bytes()),
                   "helper": str(args.helper.resolve()), "helper_sha256": sha(args.helper.read_bytes()),
                   "scope": "independent local opaque mailbox and relay4 direct wire; no host enrollment/QUIC/NAT/installed claim",
                   "production_resource_clock": True, "fixture_signatures": keys.signatures,
                   "seconds": round(time.monotonic() - started, 3), "rows": suite.rows,
                   "completed": failure is None and all(row["passed"] for row in suite.rows)}
        args.results.parent.mkdir(parents=True, exist_ok=True)
        args.results.write_text(json.dumps(receipt, indent=2) + "\n")
        return 0 if receipt["completed"] else 1
    finally:
        keys.close()


if __name__ == "__main__":
    raise SystemExit(main())
