#!/usr/bin/env python3
"""Independent post-TLS bootstrap request bounds and strict HTTP framing.

Uses only our public-wire fixture support. Actual TLS host keys/socket source
are fixed by owned connections; no forwarded headers, helper storage schema,
implementation source or implementer tests supply expected behavior.
"""

from __future__ import annotations

import argparse
import http.client
import json
from pathlib import Path
import socket
import ssl
import time

from decentralized_fixtures import FixtureKeys, sha
from decentralized_helper import BOOTSTRAP, CheckFailure, ClientIdentity, HelperProcess, require
from decentralized_vectors import strict_output


PIN = "2f8ff787bc5364ac148b2564142f39707c87d1da"


class BoundsSuite:
    def __init__(self, binary: Path, root: Path, keys: FixtureKeys) -> None:
        self.binary, self.root, self.keys = binary, root, keys
        self.helpers, self.rows, self.trace = [], [], []

    def helper(self, label: str) -> HelperProcess:
        helper = HelperProcess(self.binary, self.root, label)
        self.helpers.append(helper); helper.start()
        return helper

    def case(self, name: str, function) -> None:
        started = time.monotonic()
        try:
            function()
        except BaseException as failure:
            self.rows.append({"name": name, "passed": False, "error_type": type(failure).__name__,
                "detail": str(failure) if isinstance(failure, (CheckFailure, TimeoutError)) else "fixture/transport failure",
                "seconds": round(time.monotonic()-started, 3)})
            print("FAIL " + name, flush=True)
            raise
        self.rows.append({"name": name, "passed": True, "seconds": round(time.monotonic()-started, 3)})
        print("PASS " + name, flush=True)

    def connect(self, helper: HelperProcess, identity: ClientIdentity):
        return identity.connect(helper.metadata["address"], helper.metadata["public_key"], BOOTSTRAP)

    def wire(self, helper: HelperProcess, *, fields: list[tuple[str, str]] | None = None,
             method: str = "GET", finished: bool = True) -> bytes:
        path = "/bootstrap/v1/mailboxes/" + "0"*64 if method == "GET" else "/bootstrap/v1/mailboxes"
        headers = [("Host", helper.metadata["address"]), ("Authorization", "Bearer " + "0"*64)] + (fields or [])
        return (method + " " + path + " HTTP/1.1\r\n" +
                "".join(k+": "+v+"\r\n" for k,v in headers) + ("\r\n" if finished else "")).encode()

    def response(self, stream, *, may_close: bool = False):
        try:
            response = http.client.HTTPResponse(stream)
            response.begin()
            raw = response.read(65537)
            require(len(raw) <= 65536, "bounded transport result exceeds64KiB")
            require(not stream.recv(1), "bootstrap HTTP carried more than one response/connection")
            value = strict_output(raw)
            require(set(value) == {"code", "error", "required_ids"} and value["required_ids"] == [] and
                    isinstance(value["error"], str), "transport error is not strict secret-free helper JSON")
            return response.status, value["code"]
        except (http.client.RemoteDisconnected, EOFError, ssl.SSLEOFError, ConnectionResetError, BrokenPipeError):
            if may_close:
                return None
            raise

    def quiet(self, stream) -> None:
        stream.settimeout(0.02)
        try:
            observed = stream.recv(1)
        except TimeoutError:
            return
        raise CheckFailure("a permitted incomplete-header connection already closed/responded: " + str(len(observed)))
        
    def slots(self, *, per_source: bool = False) -> None:
        helper = self.helper("source-active" if per_source else "key-active")
        identities = [ClientIdentity(self.keys, ("source-slot-" if per_source else "key-slot-")+str(i))
                      for i in range(5 if per_source else 1)]
        held, extra = [], None
        limit = 16 if per_source else 4
        try:
            for index in range(limit):
                identity = identities[index//4] if per_source else identities[0]
                stream = self.connect(helper, identity)
                held.append(stream)
                stream.sendall(self.wire(helper, finished=False))
                self.quiet(stream)
            require(len(held) == limit, "active header-slot precondition incomplete")
            overflow_identity = identities[-1] if per_source else identities[0]
            try:
                extra = self.connect(helper, overflow_identity)
                extra.settimeout(2)
                extra.sendall(self.wire(helper))
                refusal = self.response(extra, may_close=True)
            except (ssl.SSLError, ConnectionResetError, BrokenPipeError, EOFError):
                refusal = None
            require(refusal in {None, (409, "quota_exceeded")}, "post-TLS active overflow was not refused by close/quota")
            self.trace.append({"case": "source-slots" if per_source else "key-slots", "held": limit,
                "overflow": "closed" if refusal is None else list(refusal), "actual_source": "127.0.0.1"})
            # Complete one real permitted request and observe its final EOF,
            # establishing release without assuming an internal worker count.
            first = held.pop(0)
            first.settimeout(2); first.sendall(b"\r\n")
            require(self.response(first) == (404, "not_found"), "permitted slot did not complete its exact unknown locator read")
            first.close()
            # Respect the documented source GET rate before a second read.
            time.sleep(1.05)
            replacement = self.connect(helper, overflow_identity)
            held.append(replacement)
            replacement.settimeout(2); replacement.sendall(self.wire(helper))
            require(self.response(replacement) == (404, "not_found"), "completed request did not release active capacity")
        finally:
            if extra is not None:
                extra.close()
            for stream in held:
                stream.close()

    def headers(self) -> None:
        helper = self.helper("header-fields")
        identity = ClientIdentity(self.keys, "header-field-client")
        for total, expected in [(64, (404, "not_found")), (65, (400, "invalid"))]:
            if total == 65:
                time.sleep(1.05)
            stream = self.connect(helper, identity)
            try:
                stream.sendall(self.wire(helper, fields=[("X-Owned-"+str(i), "v") for i in range(total-2)]))
                require(self.response(stream) == expected, "exact header-field count boundary differs: " + str(total))
                self.trace.append({"case": "header-fields", "total_header_fields": total, "expected": list(expected)})
            finally:
                stream.close()

    def header_deadline(self) -> None:
        helper = self.helper("header-deadline")
        identity = ClientIdentity(self.keys, "header-deadline-client")
        stream = self.connect(helper, identity)
        try:
            started = time.monotonic()
            stream.sendall(self.wire(helper, finished=False))
            stream.settimeout(5.25)
            try:
                observed = stream.recv(1)
            except (ssl.SSLEOFError, ConnectionResetError):
                observed = b""
            elapsed = time.monotonic()-started
            require(observed == b"", "stalled header timeout returned an authority/protocol result")
            require(elapsed <= 5.25, "header close exceeded5s plus0.25s observation tolerance")
            self.trace.append({"case": "header-deadline", "protocol_seconds": 5,
                "observation_tolerance_seconds": 0.25, "elapsed_seconds": round(elapsed, 3)})
        finally:
            stream.close()

    def framing(self, selected: str) -> None:
        helper = self.helper("framing-" + selected)
        identity = ClientIdentity(self.keys, "http-framing-client")
        variants = {"missing-length": [], "duplicate-length": [("Content-Length", "0"), ("Content-Length", "0")],
                    "leading-zero-length": [("Content-Length", "00")],
                    "transfer-encoding": [("Content-Length", "0"), ("Transfer-Encoding", "identity")]}
        stream = self.connect(helper, identity)
        try:
            if selected == "pipeline":
                request = self.wire(helper) + self.wire(helper)
            else:
                request = self.wire(helper, method="POST", fields=variants[selected])
            stream.sendall(request)
            require(self.response(stream) == (400, "invalid"), "ambiguous/invalid HTTP framing was not strict400 invalid")
            self.trace.append({"case": selected, "submitted_wire_sha256": sha(request)})
        finally:
            stream.close()

    def close(self) -> None:
        for helper in self.helpers:
            try:
                helper.stop()
            except BaseException as failure:
                self.rows.append({"name": "cleanup/"+helper.name, "passed": False, "error_type": type(failure).__name__})
            stderr = helper.stderr_path.read_bytes() if helper.stderr_path.exists() else b""
            self.trace.append({"helper": helper.name, "stderr_bytes": len(stderr), "stderr_sha256": sha(stderr)})
            if b"WARNING: DATA RACE" in stderr:
                self.rows.append({"name": "race/"+helper.name, "passed": False, "detail": "retained detector report"})


def main() -> int:
    choices = ["key-slots", "source-slots", "header-fields", "header-deadline", "missing-length",
               "duplicate-length", "leading-zero-length", "transfer-encoding", "pipeline"]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--case", action="append", choices=choices)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()
    args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    keys = FixtureKeys(); suite = BoundsSuite(args.helper.resolve(), args.work_dir.resolve(), keys)
    started, failure = time.monotonic(), None
    try:
        for name in args.case or choices:
            function = {"key-slots": suite.slots, "source-slots": lambda: suite.slots(per_source=True),
                "header-fields": suite.headers, "header-deadline": suite.header_deadline}.get(name,
                    lambda n=name: suite.framing(n))
            suite.case("bootstrap/"+name, function)
    except BaseException as error:
        failure = type(error).__name__
    finally:
        suite.close(); keys.close()
    result = {"contract_pin": PIN, "implementation_source_read": False,
        "suite_sha256": sha(Path(__file__).read_bytes()), "helper": str(args.helper.resolve()),
        "helper_sha256": sha(args.helper.read_bytes()), "rows": suite.rows, "trace": suite.trace,
        "failure": failure, "seconds": round(time.monotonic()-started, 3),
        "scope": "local post-TLS active key/source caps, header count/deadline and strict HTTP framing only; no global saturation/host enrollment claim",
        "passed": failure is None and all(row["passed"] for row in suite.rows)}
    args.results.parent.mkdir(parents=True, exist_ok=True)
    args.results.write_text(json.dumps(result, indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
