#!/usr/bin/env python3
"""Independent PR103 clock and real creation-crash boundaries, API only.

This uses only our public API/crypto fixtures.  It does not read implementation
code, guessed private columns or implementation tests.  Clock/barrier controls
are explicitly configured on each owned daemon; no CLI/helper inherits them.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import sqlite3
import stat
import threading
import time

from decentralized_fixtures import FixtureKeys, NOW, raw_json, sha
from decentralized_runtime import CreationSuite
from decentralized_storage import CheckFailure, require, all_database_snapshots as snapshot
from decentralized_vectors import same_json


PIN = "4ce8aabebf90acd2240c9226de726838336009b3"


class Call:
    def __init__(self, function) -> None:
        self.value, self.error = None, None
        def run() -> None:
            try:
                self.value = function()
            except BaseException as error:
                self.error = type(error).__name__
        self.thread = threading.Thread(target=run, name="owned-creation-RPC")
        self.thread.start()

    def join(self) -> None:
        self.thread.join(timeout=5)
        require(not self.thread.is_alive(), "owned creation RPC did not finish")


class Controls:
    def __init__(self, binary: Path, root: Path, keys: FixtureKeys) -> None:
        self.binary, self.root, self.keys = binary, root, keys
        self.rows, self.instances, self.trace = [], [], []

    def new(self, label: str, *, enabled: bool = True) -> CreationSuite:
        target = self.root / label
        target.mkdir(mode=0o700)
        value = CreationSuite(self.binary, target, self.keys)
        value.clock = target / "clock"
        value.markers = target / "markers"
        value.markers.mkdir(mode=0o700)
        self.clock(value, NOW)
        if enabled:
            value.host.environment["PEERSPAN_DEC_TEST_MODE"] = "1"
        value.host.environment["PEERSPAN_DEC_TEST_CLOCK_FILE"] = str(value.clock)
        value.host.environment["PEERSPAN_DEC_TEST_BARRIER_DIR"] = str(value.markers)
        self.instances.append(value)
        value.host.start()
        value.identity = value.host.api("GET", "/v1/host")
        return value

    def clock(self, value: CreationSuite, text: str) -> None:
        value.clock.write_text(text)
        value.clock.chmod(0o600)

    def prepare(self, value: CreationSuite) -> dict:
        value.preview, _ = value.api("POST", "/v2/networks", {"name": value.name, "member": value.member,
            "person_public_key": self.keys.public("alice"), "approve": False})
        value.creation_shape(value.preview, False)
        require(value.preview["review"]["not_after"] == "2026-11-02T12:00:00Z", "explicit DEC clock was not used for fixed creation terms")
        value.route = "/v2/network-creations/" + value.preview["creation_id"]
        return value.preview

    def approve(self, value: CreationSuite) -> tuple[dict, bytes]:
        return value.api("POST", value.route + "/approve", {
            "context_id": value.context_id, "root_state_id": value.preview["review"]["root_state_id"],
            "person_public_key": self.keys.public("alice"), "host_public_key": value.identity["public_key"], "approve": True})

    def arm(self, value: CreationSuite, name: str, operation: str) -> Path:
        path = value.markers / (name + ".arm")
        path.write_text(operation); path.chmod(0o600)
        return value.markers / (name + ".entered")

    def wait(self, value: CreationSuite, name: str, call: Call, operation: str) -> str | None:
        marker, deadline = value.markers / (name + ".entered"), time.monotonic() + 8
        while time.monotonic() < deadline:
            if marker.exists():
                require(marker.is_file() and not marker.is_symlink() and stat.S_IMODE(marker.stat().st_mode) == 0o600,
                        "entered barrier is not a regular protected marker")
                actual = marker.read_text().removesuffix("\n")
                require(actual.startswith("create_") and len(actual) == 71 and
                        (operation == "-" or actual == operation), "entered barrier changed operation identity")
                self.trace.append({"barrier": name, "operation_id": actual})
                return actual
            if not call.thread.is_alive():
                call.join()
                require(call.error is None, "creation RPC failed before its requested durable barrier: " + str(call.error))
                return None
            time.sleep(0.02)
        raise CheckFailure("requested real creation barrier was not reached within8s")

    def crash(self, value: CreationSuite, call: Call) -> dict:
        durable = snapshot(value.host.state)
        process = value.host.process
        require(process is not None and process.poll() is None and os.getpgid(process.pid) == process.pid,
                "creation crash target is not the tracked live fixture PGID")
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        value.host.process = None
        value.host.log.close()
        call.join()
        require(call.error is not None, "crashed barrier unexpectedly returned a completed response")
        for path in value.markers.iterdir():
            require(path.is_file() and not path.is_symlink(), "unexpected barrier directory object")
            path.unlink()
        value.host.start()
        require(same_json(snapshot(value.host.state), durable), "crash/reopen changed the durably committed rows")
        return durable

    def finish(self, value: CreationSuite, ready: dict, *, last_request: dict | None = None) -> tuple[dict, bytes, dict]:
        raw = b""
        for _ in range(8):
            if ready["committed"]:
                break
            slots = ready["signing_requests"]
            if slots:
                require(len({s["intent_id"] for s in slots}) == 1, "resumed slots changed intent")
                last_request = {"intent_id": slots[0]["intent_id"], "signatures": [value.slot_signature(s) for s in slots]}
            elif last_request is None:
                # Approval may have committed before owned raw dependencies
                # were signed.  Repeat the SAME explicit approval operation;
                # a read-only GET cannot manufacture those signatures.
                ready, raw = self.approve(value)
                value.creation_shape(ready, ready["committed"])
                continue
            require(last_request is not None, "fully signed fixed creation has no exact retry request")
            ready, raw = value.api("POST", value.route + "/signed", last_request)
        require(ready["committed"], "resumed creation did not apply exact approved fixed work")
        if not raw:
            ready, raw = value.api("GET", value.route)
        value.creation_shape(ready, True)
        value.verify_catalog()
        events = value.host.api("GET", "/v1/activity?limit=1000")
        require(sum(e["kind"] == "network.created" for e in events) == 1, "crash/resume duplicated or lost creation event")
        require(last_request is not None, "applied creation lost its exact last signing request")
        return ready, raw, last_request

    def ignored(self) -> None:
        value = self.new("ignored", enabled=False)
        self.clock(value, "not a time")
        self.arm(value, "dec.intent.after_commit", "-")
        result, _ = value.api("POST", "/v2/networks", {"name": value.name, "member": value.member,
            "person_public_key": self.keys.public("alice"), "approve": False})
        value.creation_shape(result, False)
        require(not (value.markers / "dec.intent.after_commit.entered").exists(), "daemon enabled a barrier without explicit DEC mode")

    def bad_clock(self, missing: bool) -> None:
        value = self.new("missing-clock" if missing else "invalid-clock")
        if missing:
            value.clock.unlink()
        else:
            self.clock(value, NOW.replace("00Z", "00.1Z"))
        result, _ = value.api("POST", "/v2/networks", {"name": value.name, "member": value.member,
            "person_public_key": self.keys.public("alice"), "approve": False}, status=500)
        value.error(result, "internal")
        require(result["error"] == "internal error" and result["details"]["stage"] == "clock", "configured invalid clock did not fail with the generic clock diagnostic")
        self.clock(value, NOW)
        require(value.api("GET", "/v2/networks")[0] == [], "invalid clock created an active network")

    def fixed_intent(self, value: CreationSuite) -> dict:
        """Read only the exact normative private intent row of this owned fixture.

        A host may own several actual SQLite files. Discover by their real
        headers and normative dec_intents table, not a guessed file name.
        Private records/seeds are compared in memory and never emitted.
        """
        matches = []
        for path in value.host.state.iterdir():
            if not path.is_file() or path.is_symlink():
                continue
            with path.open("rb") as stream:
                if stream.read(16) != b"SQLite format 3\x00":
                    continue
            connection = sqlite3.connect(path.as_uri()+"?mode=ro", uri=True)
            try:
                connection.execute("BEGIN")
                if not connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='dec_intents'").fetchone():
                    continue
                for intent_id, kind, raw, secret in connection.execute("SELECT intent_id,kind,record,secret FROM dec_intents"):
                    record = json.loads(raw)
                    if record["operation_id"] == value.preview["creation_id"]:
                        matches.append({"intent_id": intent_id, "kind": kind, "record": record,
                                        "secret_sha256": sha(secret) if secret is not None else "-"})
            finally:
                connection.close()
        require(len(matches) == 1 and matches[0]["kind"] == "create", "fixed creation lacks one exact normative private intent")
        return matches[0]

    def rereview(self) -> None:
        """Only explicit unchanged review can refresh local CREATE approval."""
        value = self.new("explicit-rereview")
        self.prepare(value)
        ready, _ = self.approve(value)
        require(bool(ready["signing_requests"]), "approved creation has no external original work")
        slot = ready["signing_requests"][0]
        signed = {"intent_id": slot["intent_id"], "signatures": [value.slot_signature(slot)]}
        original = self.fixed_intent(value)
        require(original["record"]["approved"] and original["record"]["approved_at"] == NOW and
                not original["record"]["completed"], "initial creation approval/completion differs")
        self.clock(value, "2026-10-26T12:05:01Z")
        before = snapshot(value.host.state)
        expired, _ = value.api("GET", value.route)
        value.creation_shape(expired, False)
        require(expired["review"] == ready["review"] and same_json(snapshot(value.host.state), before),
                "read-only expired review changed terms, authority or approval")
        error, _ = value.api("POST", value.route+"/signed", signed, status=409)
        value.error(error, "review_required")
        require(same_json(self.fixed_intent(value), original) and value.api("GET", "/v2/networks")[0] == [],
                "expired signature submission changed fixed intent or applied authority")
        refreshed, _ = self.approve(value)
        value.creation_shape(refreshed, False)
        current = self.fixed_intent(value)
        require(current["record"]["approved_at"] == "2026-10-26T12:05:01Z", "explicit review did not record actual guarded approval time")
        old_record, new_record = dict(original["record"]), dict(current["record"])
        old_record.pop("approved_at"); new_record.pop("approved_at")
        require(same_json(old_record, new_record) and original["secret_sha256"] == current["secret_sha256"] and
                original["intent_id"] == current["intent_id"], "re-review changed something other than approved_at")
        require(refreshed["review"] == ready["review"] and refreshed["signing_requests"] == ready["signing_requests"],
                "re-review regenerated exact review/templates/signing messages")
        self.clock(value, "2026-10-26T12:05:02Z")
        repeated, _ = self.approve(value)
        require(same_json(self.fixed_intent(value), current), "still-fresh approval retry refreshed approval time or intent")
        self.finish(value, repeated)
        self.trace.append({"case": "explicit-rereview", "initial_approved_at": NOW,
            "refreshed_approved_at": current["record"]["approved_at"],
            "initial_created_at": original["record"]["created_at"], "fixed_expires_at": original["record"]["expires_at"],
            "only_approved_at_changed": True, "new_original_signature_after_explicit_rereview_only": True})

    def fully_signed_late(self) -> None:
        """Exact completed signatures survive the unsigned preview age limit."""
        value = self.new("fully-signed-late")
        self.prepare(value)
        ready, _ = self.approve(value)
        operation = value.preview["creation_id"]
        barrier = "dec.signature.after_commit"
        active_call = None
        last_request = None
        try:
            for _ in range(8):
                slots = ready["signing_requests"]
                require(slots and len({s["intent_id"] for s in slots}) == 1,
                        "creation has no ready fixed signature batch before completed barrier")
                last_request = {"intent_id": slots[0]["intent_id"],
                    "signatures": [value.slot_signature(s) for s in slots]}
                self.arm(value, barrier, operation)
                active_call = Call(lambda body=last_request: value.api("POST", value.route+"/signed", body))
                require(self.wait(value, barrier, active_call, operation) == operation,
                        "signature completed without its durable pre-apply barrier")
                fixed = self.fixed_intent(value)
                if fixed["record"]["completed"]:
                    break
                continuation = value.markers/(barrier+".continue")
                continuation.write_text(operation); continuation.chmod(0o600)
                active_call.join()
                require(active_call.error is None, "intermediate exact signature batch failed")
                ready, _ = active_call.value
                active_call = None
                for suffix in (".arm", ".entered", ".continue"):
                    (value.markers/(barrier+suffix)).unlink()
            else:
                raise CheckFailure("no fully signed durable creation reached within8 exact batches")
            require(value.api("GET", "/v2/networks")[0] == [] and
                    fixed["record"]["approved"] and fixed["record"]["approved_at"] == NOW,
                    "completed signature barrier is after apply or changed original approval")
            pending, _ = value.api("GET", value.route)
            value.creation_shape(pending, False)
            require(pending["signing_requests"] == [], "completed fixed proofs still expose unsigned work")
            self.clock(value, "2026-10-26T12:05:01Z")
            continuation = value.markers/(barrier+".continue")
            continuation.write_text(operation); continuation.chmod(0o600)
            active_call.join()
            require(active_call.error is None, "fully signed pending creation refused solely after unsigned300s window")
            final, raw = active_call.value
            value.creation_shape(final, True)
            current = self.fixed_intent(value)
            old_record, new_record = dict(fixed["record"]), dict(current["record"])
            for name in ("terminal", "result_base64"):
                old_record.pop(name); new_record.pop(name)
            require(same_json(old_record, new_record), "late apply regenerated proofs or refreshed approval/identity/window")
            _, retained, _ = self.finish(value, final, last_request=last_request)
            require(retained == raw, "late application did not retain its exact original response")
            self.trace.append({"case": "fully-signed-late", "completed_before_apply": True,
                "approved_at": fixed["record"]["approved_at"], "fixed_created_at": fixed["record"]["created_at"],
                "fixed_expires_at": fixed["record"]["expires_at"], "actual_apply_clock": "2026-10-26T12:05:01Z",
                "new_approval_or_signature_after_original_window": False})
        finally:
            if active_call is not None and active_call.thread.is_alive():
                continuation = value.markers/(barrier+".continue")
                continuation.write_text(operation); continuation.chmod(0o600)
                active_call.join()
            for suffix in (".arm", ".entered", ".continue"):
                path = value.markers/(barrier+suffix)
                if path.exists():
                    path.unlink()

    def boundary(self, stage: str) -> None:
        name = "dec." + stage
        value = self.new(stage.replace(".", "-"))
        last_request = None
        if stage == "intent.after_commit":
            self.arm(value, name, "-")
            call = Call(lambda: value.api("POST", "/v2/networks", {"name": value.name, "member": value.member,
                "person_public_key": self.keys.public("alice"), "approve": False}))
            operation = self.wait(value, name, call, "-")
            require(operation is not None, "intent completed without its actual commit barrier")
            require(value.api("GET", "/v2/networks")[0] == [], "unsigned preparation applied authority")
            self.crash(value, call)
            value.route = "/v2/network-creations/" + operation
            value.preview, _ = value.api("GET", value.route)
            value.creation_shape(value.preview, False)
            require(value.preview["signing_requests"] == [] and value.api("GET", "/v2/networks")[0] == [],
                    "restart invented approval/signing/application")
            return
        self.prepare(value)
        operation = value.preview["creation_id"]
        if stage == "approval.after_commit":
            self.arm(value, name, operation)
            call = Call(lambda: self.approve(value))
            require(self.wait(value, name, call, operation) == operation, "approval completed without its commit barrier")
        else:
            ready, _ = self.approve(value)
            self.arm(value, name, operation)
            for _ in range(8):
                slots = ready["signing_requests"]
                require(slots, "creation exhausted signatures without reaching its applicable barrier")
                selected = slots[:1] if stage == "signature.after_commit" else slots
                last_request = {"intent_id": selected[0]["intent_id"], "signatures": [value.slot_signature(s) for s in selected]}
                call = Call(lambda body=last_request: value.api("POST", value.route + "/signed", body))
                if self.wait(value, name, call, operation) is not None:
                    break
                ready, _ = call.value
                require(not ready["committed"], "creation applied without its configured actual barrier")
            else:
                raise CheckFailure("creation did not reach its applicable barrier within8 dependency batches")
        active = value.api("GET", "/v2/networks")[0]
        require(len(active) == (1 if stage == "apply.after_commit" else 0), "barrier implied a different actual application boundary")
        self.crash(value, call)
        ready, _ = value.api("GET", value.route)
        if not ready["committed"]:
            # GET may expose an approved, dependency-ready owned root slot;
            # it cannot sign that slot.  Explicitly resume the exact stored
            # approval before invoking only the fixture's original-person key.
            ready, _ = self.approve(value)
        # An already approved fully signed intent may be resumed by a worker;
        # the marker asserts the pre-crash state, not global unobservedness.
        _, original, retry = self.finish(value, ready, last_request=last_request)
        before = snapshot(value.host.state)
        self.clock(value, "2026-10-26T12:00:10Z")
        for barrier in ("dec.intent.after_commit", "dec.approval.after_commit", "dec.signature.after_commit",
                        "dec.apply.before_transaction", "dec.apply.after_commit"):
            self.arm(value, barrier, operation)
        require(value.api("GET", value.route)[1] == original and value.api("POST", value.route + "/signed", retry)[1] == original,
                "completed historical retry changed the fixed response")
        require(same_json(snapshot(value.host.state), before), "completed historical retry changed rows/clock")
        require(not list(value.markers.glob("*.entered")), "completed historical result revisited a mutating barrier")

    def close(self) -> None:
        for value in self.instances:
            try:
                value.host.stop()
            except BaseException as error:
                self.rows.append({"name": "cleanup/" + value.root.name, "passed": False, "error_type": type(error).__name__})

    def case(self, name: str, function) -> None:
        started = time.monotonic()
        try:
            function()
        except BaseException as error:
            self.rows.append({"name": name, "passed": False, "error_type": type(error).__name__,
                              "detail": str(error) if isinstance(error, CheckFailure) else "fixture/transport failure",
                              "seconds": round(time.monotonic() - started, 3)})
            print("FAIL " + name, flush=True)
            raise
        self.rows.append({"name": name, "passed": True, "seconds": round(time.monotonic() - started, 3)})
        print("PASS " + name, flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--case", action="append", help="only named clock case or literal creation barrier suffix")
    args = parser.parse_args()
    args.work_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
    keys = FixtureKeys(); suite = Controls(args.host.resolve(), args.work_dir.resolve(), keys)
    started, failure = time.monotonic(), None
    cases = [("clock/ignored_without_explicit_mode", suite.ignored),
             ("clock/missing_file_fails_closed", lambda: suite.bad_clock(True)),
             ("clock/fractional_file_fails_closed", lambda: suite.bad_clock(False))]
    cases += [(name, lambda name=name: suite.boundary(name)) for name in
              ("intent.after_commit", "approval.after_commit", "signature.after_commit", "apply.before_transaction", "apply.after_commit")]
    cases += [("timing/explicit_unchanged_creation_rereview", suite.rereview)]
    cases += [("timing/fully_signed_creation_applies_after_original_preview_window", suite.fully_signed_late)]
    try:
        keys.self_check()
        require(not args.case or set(args.case) <= {name for name, _ in cases}, "unknown selected creation-control case")
        for name, function in cases:
            if not args.case or name in args.case:
                suite.case(name, function)
    except BaseException as error:
        failure = type(error).__name__
    finally:
        suite.close(); keys.close()
    args.results.parent.mkdir(parents=True, exist_ok=True)
    args.results.write_text(json.dumps({"contract_pin": PIN,
        "additional_oracle_pins": ["57b0aed9553fa1d49bb237b1caee6a4c6ed451f9"] if
            any(row["name"].startswith("timing/") for row in suite.rows) else [], "implementation_source_read": False,
        "suite_sha256": sha(Path(__file__).read_bytes()), "host": str(args.host.resolve()),
        "host_sha256": sha(args.host.read_bytes()), "rows": suite.rows, "trace": suite.trace,
        "scope": "explicit daemon-only clock and actual creation crash/restart boundaries; no CLI/peer/link/adoption claim",
        "seconds": round(time.monotonic() - started, 3), "failure": failure,
        "passed": failure is None and all(r["passed"] for r in suite.rows)}, indent=2) + "\n")
    return 0 if failure is None and all(r["passed"] for r in suite.rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
