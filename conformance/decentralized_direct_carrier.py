#!/usr/bin/env python3
"""Independent initial requester <-> isolated direct mailbox interoperability.

Only public DEC contracts and our independent fixture helpers are used. Exact
first-frame/ciphertext persistence, pinned TLS, initial publication/retry and
router isolation are evaluated. No owner approval, requester consent, network
adoption, relay client, normal data path or full linking is claimed.
"""

from __future__ import annotations

import argparse
from contextlib import closing
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import time

from decentralized_fixtures import FixtureKeys, b64, lines, raw_json, sha, unb64
from decentralized_helper import ClientIdentity, HelperProcess
from decentralized_requester import Requester
from decentralized_storage import Host, require
from decentralized_vectors import strict_output


NODE_DECRYPT = r"""
const fs=require('node:fs'), c=require('node:crypto');
const v=JSON.parse(fs.readFileSync(0,'utf8')), b=x=>Buffer.from(x,'base64');
const key=c.hkdfSync('sha256',b(v.secret),b(v.salt),b(v.info),32);
const d=c.createDecipheriv('aes-256-gcm',key,b(v.nonce)), ct=b(v.ciphertext);
d.setAAD(b(v.ad)); d.setAuthTag(ct.subarray(-16));
const p=Buffer.concat([d.update(ct.subarray(0,-16)),d.final()]);
process.stdout.write(JSON.stringify({plaintext_base64:p.toString('base64')}));
"""


class CarrierWire:
    """Reuse only our public raw TLS/HTTP client, never helper process control."""
    pace = HelperProcess.pace
    request = HelperProcess.request

    def __init__(self, endpoint: dict) -> None:
        self.metadata, self.token = endpoint, None
        self.last_mutation = self.last_get = 0.0


def stored_request_frame(requester: Requester, request_id: str) -> bytes:
    frames = []
    for path in requester.host.state.rglob("*"):
        if not path.is_file():
            continue
        with path.open("rb") as stream:
            if stream.read(16) != b"SQLite format 3\x00":
                continue
        with closing(sqlite3.connect("file:"+str(path)+"?mode=ro", uri=True)) as db, db, closing(db.cursor()) as cursor:
            if cursor.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='dec_frames'").fetchone():
                frames += [unb64(strict_output(row[0].encode())["frame_base64"]) for row in cursor.execute(
                    "SELECT record FROM dec_frames WHERE request_id=? AND role='request'", (request_id,))]
    require(len(frames) == 1, "initial requester does not retain one exact normative request frame")
    return frames[0]


class DirectCarrier:
    def __init__(self, requester_binary: Path, server_binary: Path, root: Path, keys: FixtureKeys) -> None:
        self.root, self.keys = root, keys
        (root/"requester").mkdir(mode=0o700)
        (root/"server").mkdir(mode=0o700)
        self.requester = Requester(requester_binary, root/"requester", keys)
        self.server = Host(server_binary, root/"server"/"state", root/"server", "direct-carrier")
        # The port is a fixture-owned loopback bind choice, not discovered from
        # product state or an advertised authority hint. Actual TLS pins follow.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.address = "127.0.0.1:"+str(reservation.getsockname()[1])
        self.server.run_arguments = ["--bootstrap-listen", self.address]
        self.rows, self.trace = self.requester.rows, []

    def read_box(self) -> dict:
        # All loopback clients share the documented source GET bucket. Space
        # this observer after any explicit owner-local delivery/poll operation;
        # do not rely on another TLS key providing a separate rate allowance.
        time.sleep(1.05)
        response = self.wire.request(self.observer, "GET", "/bootstrap/v1/mailboxes/"+self.locator,
                                     capability=self.capability)
        require(response.status == 200, "published first frame unavailable on actual direct mailbox: "+str(response.status))
        result = strict_output(response.body)
        require(set(result) == {"format", "request_id", "created_at", "expires_at", "frames"} and
                result["format"] == 1 and result["request_id"] == self.created["request_id"] and
                result["created_at"] == self.payload["created_at"] and result["expires_at"] == self.payload["expires_at"] and
                result["frames"] == [strict_output(self.frame)],
                "direct mailbox changed the exact initial frame fields/ciphertext or request window")
        return result

    def run(self) -> None:
        self.server.start()
        self.server_identity = self.server.api("GET", "/v1/host")
        endpoint = {"address": self.address, "public_key": self.server_identity["public_key"]}
        self.wire = CarrierWire(endpoint)
        self.observer = ClientIdentity(self.keys, "independent-direct-observer")
        r = self.requester
        r.host.start(); r.identity = r.host.api("GET", "/v1/host")
        self.invitation, _ = r.invitation()
        self.body = {"mode": "new", "network_id": r.world.descriptor["network_id"],
                     "person_public_key": self.keys.public("alice"), "migration_proposal_id": "-",
                     "contact_invitation": self.invitation, "helpers": [endpoint]}

        def publish() -> None:
            self.created, _ = r.api("POST", "/v2/link/requests", self.body, status=201)
            self.payload, secret = r.decode_request(self.created, helpers=[endpoint])
            self.frame = stored_request_frame(r, self.created["request_id"])
            self.locator = sha(lines("peerspan-decentralized-locator-v1", b64(secret)))
            self.capability = sha(lines("peerspan-decentralized-read-cap-v1", b64(secret)))
            r.sensitive.update({self.capability.encode(), self.frame})
            frame = strict_output(self.frame)
            require(set(frame) == set("format request_id locator role writer_host_public_key frame_id "
                    "created_at expires_at ciphertext_base64 signature".split()) and frame["format"] == 1 and
                    frame["request_id"] == self.created["request_id"] and frame["locator"] == self.locator and
                    frame["role"] == "request" and frame["writer_host_public_key"] == r.identity["public_key"] and
                    frame["created_at"] == self.payload["created_at"] and frame["expires_at"] == self.payload["expires_at"] and
                    len(frame["frame_id"]) == 64 and bytes.fromhex(frame["frame_id"]).hex() == frame["frame_id"],
                    "retained sealed frame differs from the exact request/writer/window")
            ad = lines("peerspan-decentralized-frame-v1", frame["request_id"], self.locator, "request",
                       frame["writer_host_public_key"], frame["frame_id"], frame["created_at"], frame["expires_at"])
            r.verify_raw(frame["writer_host_public_key"], lines("peerspan-decentralized-frame-envelope-v1",
                ad.decode(), sha(unb64(frame["ciphertext_base64"]))), frame["signature"])
            decrypted = subprocess.run(["/usr/bin/node", "-e", NODE_DECRYPT], input=raw_json({
                "secret": b64(secret), "salt": b64(bytes.fromhex(sha(lines("peerspan-decentralized-frame-salt-v1", frame["request_id"])))),
                "info": b64(lines("peerspan-decentralized-frame-key-v1", frame["request_id"], "request", frame["writer_host_public_key"])),
                "nonce": b64(bytes.fromhex(sha(lines("peerspan-decentralized-frame-nonce-v1", frame["frame_id"])))[:12]),
                "ad": b64(ad), "ciphertext": frame["ciphertext_base64"]}), capture_output=True, check=True, timeout=10)
            inner = strict_output(unb64(strict_output(decrypted.stdout)["plaintext_base64"]))
            require(set(inner) == {"packet_base64", "catalog_base64", "contacts"} and
                    inner["packet_base64"] == strict_output(r.pending(frame["request_id"])[0])["request_packet_base64"] and
                    isinstance(inner["contacts"], list), "first carrier AEAD does not recover the exact independently verified request packet")
            # Explicit resume is the public delivery driver. Do not infer that
            # create201 alone promises synchronous remote storage completion.
            resumed, _ = r.api("POST", "/v2/link/requests/"+self.created["request_id"]+"/resume", {})
            r.view(resumed, display=True)
            self.first_box = self.read_box()  # Acknowledge actual wire storage, not a local view.
            require(r.api("GET", "/v2/networks")[0] == [] and self.server.api("GET", "/v2/networks") == [],
                    "initial direct carrier caused network adoption")
            self.trace.append({"request_id": self.created["request_id"], "actual_server_public_key": endpoint["public_key"],
                "original_frame_sha256": sha(self.frame), "mailbox_get_observed": True,
                "independent_aead_request_packet_verified": True, "explicit_resume_before_wire_observation": True,
                "selection_approved": False, "commit_approved": False, "context_adopted": False})
        r.case("direct_carrier/initial_request_published_to_actual_other_host", publish)

        def reopen_retry() -> None:
            pending = r.pending(self.created["request_id"])
            self.server.stop(); self.server.start()
            require(self.server.api("GET", "/v1/host") == self.server_identity,
                    "ordinary carrier restart replaced its exact transport identity")
            require(self.read_box() == self.first_box, "carrier restart changed stored initial ciphertext")
            r.host.stop(); r.host.start()
            retried, _ = r.api("POST", "/v2/link/requests", self.body, status=200)
            r.decode_request(retried, helpers=[endpoint])
            require(retried["display_code"] == self.created["display_code"] and
                    retried["request_packet_id"] == self.created["request_packet_id"] and
                    r.pending(self.created["request_id"])[1:] == pending[1:] and
                    stored_request_frame(r, self.created["request_id"]) == self.frame,
                    "retry after either reopen regenerated secret, packet, device or sealed frame")
            require(self.read_box() == self.first_box and r.api("GET", "/v2/networks")[0] == [],
                    "exact live retry duplicated/changed remote ciphertext or adopted context")
        r.case("direct_carrier/either_host_reopen_preserves_exact_initial_retry", reopen_retry)

        def isolated() -> None:
            response = self.wire.request(self.observer, "GET", "/v1/host")
            error = strict_output(response.body)
            require(response.status == 404 and set(error) == {"code", "error", "required_ids"} and
                    error["code"] == "not_found" and isinstance(error["error"], str) and error["error"] and error["required_ids"] == [],
                    "isolated bootstrap listener exposed owner-local host API")
        r.case("direct_carrier/isolated_listener_never_exposes_owner_host_api", isolated)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requester", type=Path, required=True)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args(); args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    keys = FixtureKeys(); suite = DirectCarrier(args.requester.resolve(), args.server.resolve(), args.work_dir.resolve(), keys)
    started, failure = time.monotonic(), None
    try:
        suite.run()
    except BaseException as error:
        failure = type(error).__name__
    finally:
        for label, host in [("requester", suite.requester.host), ("server", suite.server)]:
            try:
                host.stop()
                logs = host.log_path.read_bytes() if host.log_path.exists() else b""
                require(not any(v and v in logs for v in suite.requester.sensitive),
                        "direct carrier host log exposed private pairing code or secret")
            except BaseException as error:
                suite.rows.append({"name": "cleanup/"+label, "passed": False, "error_type": type(error).__name__})
                failure = failure or type(error).__name__
        keys.close()
    result = {"contract_pin": "a5bdb84afb54f75c3870ca04f17e3223298b0769", "implementation_source_read": False,
        "suite_sha256": sha(Path(__file__).read_bytes()),
        "support_sha256": {name: sha(Path(__file__).with_name(name).read_bytes()) for name in (
            "decentralized_fixtures.py", "decentralized_helper.py", "decentralized_storage.py",
            "decentralized_requester.py", "decentralized_runtime.py", "decentralized_vectors.py")},
        "requester": str(args.requester.resolve()), "requester_sha256": sha(args.requester.read_bytes()),
        "server": str(args.server.resolve()), "server_sha256": sha(args.server.read_bytes()),
        "rows": suite.rows, "trace": suite.trace, "failure": failure, "seconds": round(time.monotonic()-started, 3),
        "scope": "initial actual cross-host pinned direct mailbox publication, ciphertext persistence/exact retry, router isolation only; no later stages or network adoption",
        "passed": failure is None and all(row["passed"] for row in suite.rows)}
    args.results.parent.mkdir(parents=True, exist_ok=True)
    args.results.write_text(json.dumps(result, indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
