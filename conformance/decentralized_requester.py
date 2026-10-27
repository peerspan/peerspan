#!/usr/bin/env python3
"""Independent initial requester and durable reviewed-invitation lifecycle.

Only public contracts and our own fixture helpers are used. This slice does
not claim owner/admin offers, requester selection/final consent, admission,
helper-client delivery, complete linking or integration readiness.
"""

from __future__ import annotations

import argparse
from contextlib import closing
import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import socket
import time

from decentralized_fixtures import FixtureKeys, World, b64, lines, raw_json, sha, unb64
from decentralized_runtime import CreationSuite
from decentralized_storage import require, all_database_snapshots as snapshot
from decentralized_vectors import same_json, strict_output


PIN = "2f8ff787bc5364ac148b2564142f39707c87d1da"
VIEW = set("request_id role mode state network_id context_id migration_proposal_id person_public_key "
    "host_public_key device_public_key created_at expires_at request_packet_id owner_offer_id selection_id "
    "administrator_offer_id owner_finalization_id manifest_id activation_id outcome_id selection_approved "
    "commit_approved completed attention next".split())


def private_token(prefix: str, value: bytes) -> str:
    return prefix+base64.urlsafe_b64encode(value).decode().rstrip("=")


class Requester(CreationSuite):
    def __init__(self, binary: Path, root: Path, keys: FixtureKeys) -> None:
        super().__init__(binary, root, keys)
        self.clock = root/"clock"
        # Local authority is deterministic; the optional/default carrier still
        # uses real resource time. Begin near real time so its exact request
        # envelope is live, then advance only this daemon's decision clock.
        self.base = datetime.now(timezone.utc).replace(microsecond=0)
        self.set_time(self.at(0))
        self.host.environment.update(PEERSPAN_DEC_TEST_MODE="1", PEERSPAN_DEC_TEST_CLOCK_FILE=str(self.clock))
        self.sensitive: set[bytes] = set()
        self.trace: list[dict] = []
        self.world = World(keys)

    def at(self, seconds: int) -> str:
        return (self.base+timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def set_time(self, value: str) -> None:
        self.clock.write_text(value)
        self.clock.chmod(0o600)

    def invitation(self) -> tuple[str, bytes]:
        w = self.world
        payload = raw_json({"descriptor": w.descriptor, "expected_person_public_key": self.keys.public("alice"),
            "member": "Reviewed Alice", "issued_at": self.at(-200), "expires_at": self.at(100),
            "contacts": [], "helpers": []})
        message = lines("peerspan-decentralized-contact-invitation-v1", w.context_id,
                        self.keys.public("inviter"), sha(payload))
        value = raw_json({"format": 1, "context_id": w.context_id,
            "inviter_host_public_key": self.keys.public("inviter"), "payload_base64": b64(payload),
            "signature": b64(self.keys.sign("inviter", message))})
        return private_token("psi2-", value), value

    def pending(self, request_id: str) -> tuple[bytes, bytes | None, bytes | None]:
        # Locate a normative table in actual observed SQLite databases. No
        # guessed product filename, legacy columns or schema-source access.
        matches = []
        for path in self.host.state.rglob("*"):
            if not path.is_file():
                continue
            with path.open("rb") as stream:
                if stream.read(16) != b"SQLite format 3\x00":
                    continue
            with closing(sqlite3.connect("file:"+str(path)+"?mode=ro", uri=True)) as db, db, closing(db.cursor()) as cursor:
                if not cursor.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='dec_pending'").fetchone():
                    continue
                row = cursor.execute("SELECT record,secret,terminal_read_cap FROM dec_pending WHERE request_id=?", (request_id,)).fetchone()
                if row is not None:
                    matches.append((row[0].encode(), row[1], row[2]))
        require(len(matches) == 1, "exact requester pending row is absent or duplicated across observed databases")
        return matches[0]

    def view(self, value: dict, *, display: bool = False) -> None:
        require(set(value) == VIEW|({"display_code"} if display else set()), "flat requester view fields differ")
        require(value["role"] == "requester" and value["mode"] == "new" and value["migration_proposal_id"] == "-",
                "initial requester changed role/mode/migration pin")
        require(not value["selection_approved"] and not value["commit_approved"] and
                value["owner_offer_id"] == value["selection_id"] == value["administrator_offer_id"] ==
                value["owner_finalization_id"] == value["manifest_id"] == value["activation_id"] == value["outcome_id"] == "-",
                "initial requester invented an approval or later durable stage")
        require(value["completed"] == ["request_created"], "initial requester completed stages differ")
        require(value["host_public_key"] == self.identity["public_key"] and
                value["person_public_key"] == self.keys.public("alice") and
                value["network_id"] == self.world.descriptor["network_id"] and value["context_id"] == self.world.context_id,
                "requester view changed immutable reviewed identity pins")

    def decode_request(self, value: dict, *, helpers: list[dict] | None = None) -> tuple[dict, bytes]:
        self.view(value, display=True)
        code = value["display_code"]
        require(code.startswith("psl2-") and len(code.encode()) <= 32768, "requester display is not a bounded psl2 token")
        encoded = code[5:]
        decoded = base64.urlsafe_b64decode(encoded+"="*((-len(encoded))%4))
        require(private_token("psl2-", decoded) == code, "requester token is not canonical unpadded Base64URL")
        token = strict_output(decoded)
        require(set(token) == {"format", "request_id", "secret_base64", "request_packet_base64", "contacts", "helpers"}
                and token["format"] == 1 and token["request_id"] == value["request_id"] and token["helpers"] == (helpers or [])
                and isinstance(token["contacts"], list), "requester private token fields/pins differ")
        secret = unb64(token["secret_base64"])
        require(len(secret) == 16, "requester pairing secret is not128 bits")
        packet_bytes = unb64(token["request_packet_base64"])
        packet = strict_output(packet_bytes)
        require(set(packet) == set("format context_id request_id role writer_host_public_key signer_public_key "
            "person_public_key issuer_id payload_base64 host_signature device_signature authority_signature_format authority_signature".split()),
            "request packet fields differ")
        payload_bytes = unb64(packet["payload_base64"]); payload = strict_output(payload_bytes)
        require(set(payload) == set("mode host_public_key device_public_key request_nonce expected_network_id expected_context_id "
            "expected_person_public_key migration_proposal_id renewed_device_lease_id created_at expires_at".split()),
            "request payload fields differ")
        request_id = "link_"+sha(lines("peerspan-decentralized-request-id-v1", sha(payload_bytes)))
        require(request_id == packet["request_id"] == value["request_id"] and
                packet["format"] == 1 and packet["role"] == "request" and
                packet["context_id"] == packet["person_public_key"] == packet["issuer_id"] ==
                packet["authority_signature_format"] == packet["authority_signature"] == "-",
                "request packet identity or fixed request roles differ")
        require(payload["host_public_key"] == packet["writer_host_public_key"] == value["host_public_key"] and
                payload["device_public_key"] == packet["signer_public_key"] == value["device_public_key"] and
                payload["mode"] == "new" and payload["migration_proposal_id"] == payload["renewed_device_lease_id"] == "-" and
                payload["expected_network_id"] == value["network_id"] and payload["expected_context_id"] == value["context_id"] and
                payload["expected_person_public_key"] == value["person_public_key"] and len(unb64(payload["request_nonce"])) == 32,
                "request payload changed reviewed target/device/person/context")
        message = lines("peerspan-decentralized-packet-v1", "-", request_id, "request", packet["writer_host_public_key"],
            packet["signer_public_key"], "-", "-", "-", sha(payload_bytes))
        require(value["request_packet_id"] == "dpk_"+sha(message), "public request packet ID differs")
        self.verify_raw(packet["writer_host_public_key"], message, packet["host_signature"])
        self.verify_raw(packet["signer_public_key"], message, packet["device_signature"])
        self.sensitive.update({code.encode(), secret, token["secret_base64"].encode()})
        return payload, secret

    def run_delivery(self) -> None:
        self.host.start()
        self.identity = self.host.api("GET", "/v1/host")
        def failed_carrier() -> None:
            invitation, _ = self.invitation()
            # Keep this exact owned port bound but NOT listening. Connection
            # refusal is immediate and another process cannot take the port.
            # No false TLS pin success, bearer transmission or remote traffic.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as unavailable:
                unavailable.bind(("127.0.0.1", 0))
                address = "127.0.0.1:"+str(unavailable.getsockname()[1])
                helpers = [{"address": address, "public_key": self.keys.public("unavailable-helper")}]
                body = {"mode": "new", "network_id": self.world.descriptor["network_id"],
                    "person_public_key": self.keys.public("alice"), "migration_proposal_id": "-",
                    "contact_invitation": invitation, "helpers": helpers}
                created, _ = self.api("POST", "/v2/link/requests", body, status=201)
                _, secret = self.decode_request(created, helpers=helpers)
                require(created["attention"] and created["next"] and
                        all(isinstance(v, str) and 0 < len(v) <= 4096 for v in created["attention"]+created["next"]),
                        "postcommit failed carrier lacks bounded public attention/recovery guidance")
                pending = self.pending(created["request_id"])
                require(pending[1] == secret and strict_output(pending[0])["terminal"] == "-",
                        "optional delivery failure erased or completed the durable request")
                route = "/v2/link/requests/"+created["request_id"]
                read, _ = self.api("GET", route)
                self.view(read)
                require(read["request_id"] == created["request_id"] and read["request_packet_id"] == created["request_packet_id"],
                        "delivery failure hid or replaced its already committed request")
                retry, _ = self.api("POST", "/v2/link/requests", body)
                require(retry["display_code"] == created["display_code"] and retry["request_id"] == created["request_id"] and
                        retry["request_packet_id"] == created["request_packet_id"] and self.pending(created["request_id"])[1] == secret,
                        "exact retry after carrier refusal created a replacement identity/secret/packet")
                self.view(retry, display=True)
                self.trace.append({"request_id": created["request_id"], "unavailable_owned_helper": address,
                    "transport_fault": "owned bound nonlistening loopback port", "status": 201,
                    "exact_retry_status": 200, "completed": created["completed"],
                    "selection_approved": False, "commit_approved": False})
        self.case("requester/optional_carrier_refusal_preserves_committed_view_and_private_display", failed_carrier)

    def run(self, *, after_malformed: bool = False) -> None:
        self.host.start()
        self.identity = self.host.api("GET", "/v1/host")
        invitation, invitation_bytes = self.invitation()
        # Public signed introduction only: retain exact original bytes for an
        # independent parser diagnosis. No requester code/secret exists yet.
        (self.root/"reviewed-invitation.public.json").write_bytes(invitation_bytes)
        body = {"mode": "new", "network_id": self.world.descriptor["network_id"],
            "person_public_key": self.keys.public("alice"), "migration_proposal_id": "-",
            "contact_invitation": invitation, "helpers": []}
        (self.root/"initial-request.public.json").write_bytes(raw_json(body))
        def malformed() -> None:
            before = snapshot(self.host.state)
            bad = strict_output(invitation_bytes); bad["signature"] = b64(bytes(64))
            request = dict(body, contact_invitation=private_token("psi2-", raw_json(bad)))
            value, _ = self.api("POST", "/v2/link/requests", request, status=400)
            self.error(value, "invalid")
            require(same_json(before, snapshot(self.host.state)), "bad invitation mutated durable state before review")
        if not after_malformed:
            self.case("requester/malformed_invitation_refuses_before_identity_or_intent", malformed)
        def create() -> None:
            self.created, _ = self.api("POST", "/v2/link/requests", body, status=201)
            payload, secret = self.decode_request(self.created)
            require(payload["created_at"] == self.created["created_at"] == self.at(0) and
                    payload["expires_at"] == self.created["expires_at"] == self.at(300),
                    "request did not preserve its own guarded300s window")
            self.route = "/v2/link/requests/"+self.created["request_id"]
            self.original_pending = self.pending(self.created["request_id"])
            record = strict_output(self.original_pending[0])
            require(record["contact_invitation_base64"] == b64(invitation_bytes) and
                    record["request_packet_base64"] != "-" and self.original_pending[1] == secret and
                    self.original_pending[2] is None, "invitation/request/secret were not retained exactly before publication")
            require(record["owner_packet_base64"] == record["selection_packet_base64"] == record["commit_packet_base64"] == "-",
                    "initial requester invented later signed packets")
            networks, _ = self.api("GET", "/v2/networks")
            require(networks == [], "contact introduction adopted a network before complete consent")
        self.case("requester/reviewed_invitation_and_signed_request_persist_without_adoption", create)
        def retry_read() -> None:
            retry, _ = self.api("POST", "/v2/link/requests", body)
            require(same_json(retry, self.created), "identical live creation changed request or private display")
            before = snapshot(self.host.state)
            expected = {k:v for k,v in self.created.items() if k != "display_code"}
            read, _ = self.api("GET", self.route); listed, _ = self.api("GET", "/v2/link/requests")
            require(same_json(read, expected) and same_json(listed, [expected]), "read/list leaked display or changed exact public request")
            require(same_json(before, snapshot(self.host.state)), "read/list mutated private request or clock")
        self.case("requester/exact_live_retry_and_public_reads_preserve_attempt", retry_read)
        def reopen() -> None:
            self.host.stop(); self.set_time(self.at(101)); self.host.start()
            read, _ = self.api("GET", self.route)
            self.view(read)
            current_pending = self.pending(read["request_id"])
            def fixed(record_bytes: bytes) -> dict:
                record = strict_output(record_bytes)
                # Carrier addresses/acknowledgments are explicitly mutable
                # transport state, unlike signed packets, review and consent.
                record.pop("carrier_endpoints")
                for frame in record["outbound_frames"]:
                    frame.pop("acknowledged_by")
                return record
            require(read["state"] == self.created["state"] and read["created_at"] == self.created["created_at"] and
                    read["expires_at"] == self.created["expires_at"] and
                    same_json(fixed(current_pending[0]), fixed(self.original_pending[0])) and
                    current_pending[1:] == self.original_pending[1:],
                    "expired introduction erased/rewrote review or extended still-live request on reopen")
            self.trace.append({"request_id": read["request_id"], "retained_invitation_sha256": sha(invitation_bytes),
                "requester_created_at": read["created_at"], "requester_expires_at": read["expires_at"],
                "reopened_after_invitation_expiry": True, "selection_approved": False, "commit_approved": False})
        self.case("requester/reopen_after_introduction_expiry_keeps_original_review", reopen)
        def cancel() -> None:
            cancelled, _ = self.api("POST", self.route+"/cancel", {})
            self.view(cancelled)
            require(cancelled["state"] == "cancelled", "precommit cancel did not expose its tombstone")
            retained, secret, cap = self.pending(cancelled["request_id"])
            require(secret is None and cap is None and strict_output(retained)["terminal"] == "cancelled",
                    "precommit cancellation retained private pairing material or terminal outcome capability")
            networks, _ = self.api("GET", "/v2/networks")
            require(networks == [], "precommit cancel invented network adoption")
        self.case("requester/precommit_cancel_erases_pairing_secret_without_adoption", cancel)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--delivery-only", action="store_true")
    parser.add_argument("--after-malformed", action="store_true", help="continue only the failed valid intro and not-yet-evaluated lifecycle")
    args = parser.parse_args()
    args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    keys = FixtureKeys(); suite = Requester(args.host.resolve(), args.work_dir.resolve(), keys)
    started, failure = time.monotonic(), None
    try:
        suite.run_delivery() if args.delivery_only else suite.run(after_malformed=args.after_malformed)
    except BaseException as error:
        failure = type(error).__name__
    finally:
        try:
            suite.host.stop()
            logs = suite.host.log_path.read_bytes() if suite.host.log_path.exists() else b""
            require(not any(value and value in logs for value in suite.sensitive), "requester daemon log leaked private display/secret")
        except BaseException as error:
            suite.rows.append({"name": "requester/cleanup_and_secret_log_boundary", "passed": False, "error_type": type(error).__name__})
            failure = failure or type(error).__name__
        keys.close()
    result = {"contract_pin": PIN, "implementation_source_read": False,
        "suite_sha256": sha(Path(__file__).read_bytes()), "host": str(args.host.resolve()), "host_sha256": sha(args.host.read_bytes()),
        "rows": suite.rows, "trace": suite.trace, "failure": failure, "seconds": round(time.monotonic()-started, 3),
        "scope": ("postcommit optional carrier refusal/exact retry only" if args.delivery_only else
                  "initial requester/invitation/exact retry/reopen/cancel only")+"; no offer/selection/final consent/helper-client success/linking authority claim",
        "passed": failure is None and all(row["passed"] for row in suite.rows)}
    args.results.parent.mkdir(parents=True, exist_ok=True)
    args.results.write_text(json.dumps(result, indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
