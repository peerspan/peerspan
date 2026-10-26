#!/usr/bin/env python3
"""New contract-only full relay renewal and final mailbox expiry boundaries."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import time

from decentralized_fixtures import FixtureKeys, sha
from decentralized_helper import BOOTSTRAP, ClientIdentity, HelperProcess, Mailbox, RelayClient, require
from decentralized_helper_concurrency import RelaySuite
from decentralized_vectors import strict_output


PIN = "2f8ff787bc5364ac148b2564142f39707c87d1da"


class Boundaries(RelaySuite):
    def late_body(self) -> None:
        helper = self.helper("late-body")
        identity = ClientIdentity(self.keys, "helper-client-a")
        mailbox = Mailbox(self.keys, "late-body", remaining=3)
        body = mailbox.create()
        expiry = datetime.fromisoformat(mailbox.expires_at.replace("Z", "+00:00")).timestamp()
        stream = identity.connect(helper.metadata["address"], helper.metadata["public_key"], BOOTSTRAP)
        try:
            require(time.time() < expiry, "slow-body fixture did not begin within its signed resource window")
            header = ("POST /bootstrap/v1/mailboxes HTTP/1.1\r\nHost: " + helper.metadata["address"] +
                      "\r\nAuthorization: Bearer " + mailbox.capability +
                      "\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)) + "\r\n\r\n").encode()
            started = time.monotonic()
            stream.sendall(header+body[:-1])
            time.sleep(max(0, expiry+0.05-time.time()))
            require(time.monotonic()-started < 10, "slow body exceeded the actual10s body deadline")
            stream.sendall(body[-1:])
            response = http.client.HTTPResponse(stream); response.begin()
            raw = response.read(65537)
            require(response.status == 410, "creation completed after signed expiry returned"+str(response.status)+", expected410")
            value = strict_output(raw)
            require(set(value) == {"code", "error", "required_ids"} and value["code"] == "expired" and
                    value["required_ids"] == [], "late mailbox creation lacked exact expired diagnostic")
            require(not stream.recv(1), "late-body bootstrap connection did not close")
            self.trace.append({"case": "late-body", "created_at": mailbox.created_at, "expires_at": mailbox.expires_at,
                "body_receive_seconds": round(time.monotonic()-started, 3), "final_body_after_expiry": True,
                "body_sha256": sha(body), "status": response.status})
        finally:
            stream.close()

    def full_renewals(self) -> None:
        token = os.urandom(32).hex().encode()
        helper = HelperProcess(self.binary, self.root, "full-renewals", token)
        self.helpers.append(helper); helper.start()
        identities, clients = [], []
        extra = None
        phase, registered, pressure_sent = "initial-registration", 0, 0
        try:
            last_auth = last_ping = time.monotonic()-1
            for index in range(64):
                # Source AUTH accounting is shared by all these TLS keys:
                # 2/s sustained, burst8. Populate the occupancy precondition
                # within that public ceiling, keeping earlier clients alive.
                delay = last_auth+0.55-time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                if time.monotonic()-last_ping >= 12:
                    for connected in clients:
                        connected.send(4)
                    last_ping = time.monotonic()
                identity = ClientIdentity(self.keys, "registered-source-account-"+str(index))
                identities.append(identity)
                client = RelayClient(helper, identity)
                clients.append(client)
                client.send(0, token)
                last_auth = time.monotonic()
                kind, payload = client.read()
                if (kind, payload) != (7, b""):
                    self.trace.append({"case": "full-renewals", "phase": "initial-registration",
                        "acknowledged_initial_registrations": index,
                        "observed_frame_type": kind, "observed_payload_bytes": len(payload)})
                require((kind, payload) == (7, b""),
                        "initial registration "+str(index+1)+" returned frame "+str(kind)+", expected AUTH_OK")
                registered += 1
            slow, sender, control, peer = clients[:4]
            phase = "datagram-pressure"
            slow.stream.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            started = time.monotonic()
            count = 2200
            for index in range(count):
                delay = started+index/800-time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                sender.send(1, identities[0].host_id+b"x"*1500)
                pressure_sent += 1
            # Establish that the source/account is STILL full after pressure.
            # If pressure closed the recipient this precondition fails, and the
            # case cannot claim to have exercised a full registration bucket.
            identity = ClientIdentity(self.keys, "registered-source-account-overflow")
            phase = "overflow-tls-handshake"
            try:
                extra = RelayClient(helper, identity)
            except (ssl.SSLError, EOFError, ConnectionResetError):
                require(identity.last_tls_completed is False,
                        "overflow closed after completed TLS without an AUTH_REFUSED observation")
                overflow_control = "transport saturation before TLS completed; no AUTH submitted"
            else:
                phase = "overflow-auth-send"
                extra.send(0, token)
                phase = "overflow-auth-response"
                require(extra.read() == (8, b""), "64-registration occupancy precondition lost or overflow AUTH not refused")
                phase = "overflow-auth-refused-close"
                extra.closed(); extra.close(); extra = None
                overflow_control = "valid AUTH_REFUSED after pinned TLS and AUTH"
            # Existing registrations are net-zero renewals. The nonreader's
            # renewal must not consume a new source/account registration slot.
            phase = "nonreading-registration-renewal"
            slow.send(0, token)
            phase = "unrelated-registration-renewal"
            control.auth(token)
            phase = "unrelated-registration-delivery"
            payload = b"independent full-bucket renewal progress"
            control.send(1, identities[3].host_id+payload)
            require(peer.read() == (2, identities[2].host_id+payload), "pending slow renewal blocked unrelated authenticated progress")
            self.trace.append({"case": "full-renewals", "actual_source": "127.0.0.1", "operator_accounts": 1,
                "acknowledged_initial_registrations": 64, "overflow_saturation_control": overflow_control,
                "pressure_datagrams": count, "pressure_datagram_bytes": count*1500,
                "slow_client_read_after_initial_AUTH_OK": False, "control_renewal_and_delivery": True,
                "limitation": "observes nonreading client pressure and full buckets; does not inspect an internal pending-write lock"})
        except BaseException:
            self.trace.append({"case": "full-renewals", "phase": phase,
                "acknowledged_initial_registrations": registered, "pressure_datagrams_sent": pressure_sent})
            raise
        finally:
            if extra is not None:
                extra.close()
            for client in clients:
                client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--case", action="append", choices=["late-body", "full-renewals"])
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()
    args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    keys = FixtureKeys(); suite = Boundaries(args.helper.resolve(), args.work_dir.resolve(), keys)
    started, failure = time.monotonic(), None
    try:
        for name in args.case or ["late-body", "full-renewals"]:
            suite.case("helper/"+name, suite.late_body if name == "late-body" else suite.full_renewals)
    except BaseException as error:
        failure = type(error).__name__
    finally:
        suite.close(); keys.close()
    result = {"contract_pin": PIN, "implementation_source_read": False,
        "suite_sha256": sha(Path(__file__).read_bytes()), "helper": str(args.helper.resolve()),
        "helper_sha256": sha(args.helper.read_bytes()), "rows": suite.rows, "trace": suite.trace,
        "failure": failure, "seconds": round(time.monotonic()-started, 3),
        "scope": "new relay full-source/account renewal and post-upload mailbox expiry only; no host authority/live-network claim",
        "passed": failure is None and all(row["passed"] for row in suite.rows)}
    args.results.parent.mkdir(parents=True, exist_ok=True)
    args.results.write_text(json.dumps(result, indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
