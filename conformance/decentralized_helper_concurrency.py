#!/usr/bin/env python3
"""Independent relay4 progress/state boundaries from public DEC contracts.

Only our fixture helpers are imported.  A nonreading registered receiver is
local transport pressure, never a network identity/revocation assertion.  No
helper implementation, storage schema or implementer test is inspected.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import ssl
import struct
import threading
import time

from decentralized_fixtures import FixtureKeys, sha
from decentralized_helper import (CheckFailure, ClientIdentity, HelperProcess,
                                  RelayClient, require)


PIN = "24ccdc34833798d2f67d3c7206d3c0419daa3569"


class RelaySuite:
    def __init__(self, binary: Path, root: Path, keys: FixtureKeys) -> None:
        self.binary, self.root, self.keys = binary, root, keys
        self.rows: list[dict] = []
        self.helpers: list[HelperProcess] = []
        self.trace: list[dict] = []

    def helper(self, name: str) -> HelperProcess:
        value = HelperProcess(self.binary, self.root, name)
        self.helpers.append(value)
        value.start()
        return value

    def case(self, name: str, function) -> None:
        started = time.monotonic()
        try:
            function()
        except BaseException as error:
            self.rows.append({"name": name, "passed": False, "error_type": type(error).__name__,
                              "detail": str(error) if isinstance(error, (CheckFailure, TimeoutError)) else
                              "fixture/transport failure; see retained trace/stderr",
                              "seconds": round(time.monotonic() - started, 3)})
            print("FAIL " + name, flush=True)
            raise
        self.rows.append({"name": name, "passed": True, "seconds": round(time.monotonic() - started, 3)})
        print("PASS " + name, flush=True)

    def buffered_send(self) -> None:
        helper = self.helper("buffered")
        sender = ClientIdentity(self.keys, "relay-buffered-sender")
        recipient = ClientIdentity(self.keys, "relay-buffered-recipient")
        a, b = RelayClient(helper, sender), RelayClient(helper, recipient)
        try:
            b.auth()
            datagram = b"independent premature SEND"
            auth = struct.pack(">BH", 0, 0)
            payload = recipient.host_id + datagram
            send = struct.pack(">BH", 1, len(payload)) + payload
            # One actual TLS write, before this client reads any AUTH result.
            # The SEND cannot have followed receipt of AUTH_OK.
            a.stream.sendall(auth + send)
            self.trace.append({"case": "buffered", "submitted_before_read": ["AUTH", "SEND"],
                               "wire_sha256": sha(auth + send)})
            try:
                reply = a.read()
            except (EOFError, ssl.SSLEOFError, ConnectionResetError):
                reply = None
            if reply is not None:
                self.trace.append({"case": "buffered", "first_response_type": reply[0], "first_response_length": len(reply[1])})
                require(reply == (7, b""), "buffered premature sender received an unrelated/fabricated control result")
                a.closed()
            b.stream.settimeout(1)
            try:
                observed = b.read()
            except TimeoutError:
                observed = None
            require(observed is None, "SEND submitted before AUTH_OK was forwarded")
            self.trace.append({"case": "buffered", "recipient_received_datagram": False})
        finally:
            a.close(); b.close()

    def slow_reader(self) -> None:
        helper = self.helper("slow-reader")
        identities = [ClientIdentity(self.keys, "relay-pressure-" + label) for label in ("slow", "sender", "other-a", "other-b")]
        slow, sender = RelayClient(helper, identities[0]), RelayClient(helper, identities[1])
        clients = [slow, sender]
        stop, filled = threading.Event(), threading.Event()
        sent = {"count": 0, "error_type": None}
        worker = None
        try:
            slow.auth(); sender.auth()
            slow.stream.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            payload = b"x" * 1500
            def fill() -> None:
                started = time.monotonic()
                try:
                    for index in range(3072):
                        if stop.is_set():
                            break
                        # Below the shared 1024/s frame ceiling, far below the
                        # 32MiB/minute actual-host/source datagram budget.
                        delay = started + index / 800 - time.monotonic()
                        if delay > 0 and stop.wait(delay):
                            break
                        sender.send(1, identities[0].host_id + payload)
                        sent["count"] += 1
                        if sent["count"] >= 2048:
                            filled.set()
                except BaseException as error:
                    sent["error_type"] = type(error).__name__
                    filled.set()
            worker = threading.Thread(target=fill, name="owned-relay-pressure")
            worker.start()
            require(filled.wait(8) and sent["count"] >= 2048, "owned slow-reader pressure did not reach its bounded precondition")
            # This is a legal renewal on the SAME actual TLS key.  Its client
            # deliberately does not read RECEIVE or this renewal's AUTH_OK.
            slow.send(0)
            time.sleep(0.05)
            started = time.monotonic()
            other_a, other_b = RelayClient(helper, identities[2]), RelayClient(helper, identities[3])
            clients += [other_a, other_b]
            other_a.auth(); other_b.auth()
            datagram = b"independent unrelated progress"
            other_a.send(1, identities[3].host_id + datagram)
            require(other_b.read() == (2, identities[2].host_id + datagram),
                    "nonreading renewed client blocked unrelated relay registration/delivery")
            self.trace.append({"case": "slow-reader", "sent_datagrams": sent["count"],
                               "sent_datagram_bytes": sent["count"] * len(payload),
                               "sender_error_type": sent["error_type"],
                               "unrelated_registration_and_delivery_seconds": round(time.monotonic() - started, 3),
                               "slow_reader_consumed_after_initial_AUTH_OK": False})
        finally:
            stop.set()
            for client in clients:
                client.close()
            if worker is not None:
                worker.join(timeout=6)
                require(not worker.is_alive(), "owned pressure sender did not stop")
            self.trace.append({"case": "slow-reader-final", "sent_datagrams": sent["count"], "sender_error_type": sent["error_type"]})

    def replacement(self) -> None:
        """The existing helper60 same-key replacement boundary, selectable."""
        helper = self.helper("replacement")
        a_id, b_id = [ClientIdentity(self.keys, "relay-replace-" + label) for label in ("a", "b")]
        clients = []
        try:
            for identity in (a_id, b_id, a_id):
                client = RelayClient(helper, identity)
                clients.append(client)
                client.auth()
            old, peer, current = clients
            old.closed()
            payload = b"exact owned replacement delivery"
            current.send(1, b_id.host_id + payload)
            require(peer.read() == (2, a_id.host_id + payload), "replacement lost exact actual source/delivery")
            peer.send(1, a_id.host_id + payload)
            require(current.read() == (2, b_id.host_id + payload), "replacement did not retain the stable host-ID route")
        finally:
            for client in clients:
                client.close()

    def close(self) -> None:
        for helper in self.helpers:
            try:
                helper.stop()
            except BaseException as error:
                self.rows.append({"name": "cleanup/" + helper.name, "passed": False, "error_type": type(error).__name__})
            stderr = helper.stderr_path.read_bytes() if helper.stderr_path.exists() else b""
            self.trace.append({"helper": helper.name, "stderr_bytes": len(stderr), "stderr_sha256": sha(stderr)})
            if b"WARNING: DATA RACE" in stderr:
                self.rows.append({"name": "race/" + helper.name, "passed": False, "detail": "race detector report retained in helper stderr"})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--case", choices=["buffered", "slow", "replacement", "all"], default="all")
    args = parser.parse_args()
    args.work_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    keys = FixtureKeys(); suite = RelaySuite(args.helper.resolve(), args.work_dir.resolve(), keys)
    started, failure = time.monotonic(), None
    try:
        keys.self_check()
        if args.case in {"buffered", "all"}:
            suite.case("relay4/buffered_SEND_before_AUTH_OK_is_not_forwarded", suite.buffered_send)
        if args.case in {"slow", "all"}:
            suite.case("relay4/slow_reader_renewal_does_not_block_unrelated_progress", suite.slow_reader)
        if args.case in {"replacement", "all"}:
            suite.case("relay4/successful_same_key_replacement_closes_old_and_routes_current", suite.replacement)
    except BaseException as error:
        failure = type(error).__name__
    finally:
        suite.close(); keys.close()
    receipt = {"contract_pin": PIN, "implementation_source_read": False,
               "suite_sha256": sha(Path(__file__).read_bytes()),
               "helper": str(args.helper.resolve()), "helper_sha256": sha(args.helper.read_bytes()),
               "scope": "local relay4 state/progress under owned buffered and nonreading clients; no host/QUIC/NAT/enrollment claim",
               "rows": suite.rows, "trace": suite.trace, "seconds": round(time.monotonic() - started, 3),
               "failure": failure, "passed": failure is None and all(row["passed"] for row in suite.rows)}
    args.results.parent.mkdir(parents=True, exist_ok=True)
    args.results.write_text(json.dumps(receipt, indent=2) + "\n")
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
