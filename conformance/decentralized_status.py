#!/usr/bin/env python3
"""Independent bounded DEC and genuine legacy-history status acceptance.

Public runtime section9 and merged120 supply the oracles. We use our own
creation helpers and a stopped COPY of genuine OAuth22 product state; no
implementation, schema source or implementer tests are imported. This slice
claims no peer, native up, installed package or complete linking behavior.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import socket
import threading
import time

from decentralized_create_controls import Controls
from decentralized_fixtures import FixtureKeys, NOW, raw_json, sha
from decentralized_owner_preview import create
from decentralized_runtime import CreationSuite, NETWORK_FIELDS
from decentralized_storage import CheckFailure, Host, all_database_snapshots, public_diff_paths, require, tree_hashes
from decentralized_vectors import same_json

PIN = "dada7fcedc4a215f79a78e08f2bedfa14e374931"
LEGACY = {"id", "name", "coordinator", "last_sync_at", "last_sync_error", "members", "person", "policy", "policy_deliveries_pending"}


class StatusSuite:
    def __init__(self, binary: Path, baseline: Path, baseline_state: Path, root: Path, keys: FixtureKeys) -> None:
        self.binary, self.baseline, self.baseline_state, self.root, self.keys = binary, baseline, baseline_state, root, keys
        self.rows, self.instances, self.trace = [], [], []

    def case(self, name, function) -> None:
        started = time.monotonic()
        try:
            function()
        except BaseException as error:
            self.rows.append({"name": name, "passed": False, "error_type": type(error).__name__,
                "detail": str(error) if isinstance(error, CheckFailure) else "fixture/transport failure", "seconds": round(time.monotonic()-started, 3)})
            print("FAIL "+name, flush=True); raise
        self.rows.append({"name": name, "passed": True, "seconds": round(time.monotonic()-started, 3)})
        print("PASS "+name, flush=True)

    def current_dec(self) -> None:
        controls = Controls(self.binary, self.root, self.keys)
        value = controls.new("current-dec")
        self.instances.append(value.host)
        network, _ = create(value, "Independent status current view")
        controls.clock(value, "2026-10-26T12:01:00Z")
        before = all_database_snapshots(value.host.state)
        # The current requested time differs from the last committed creation
        # time. Merely evaluating it must not advance dec_clock or any signer.
        view, _ = value.api("GET", "/v2/networks/"+network["id"])
        status, _ = value.api("GET", "/v2/status")
        require(set(view) == NETWORK_FIELDS and view["mode"] == "decentralized" and
                view["id"] == network["id"] and view["context_id"] == network["context_id"] and
                view["host_public_key"] == value.identity["public_key"] and view["person_public_key"] == self.keys.public("alice") and
                view["root_state_id"] == network["root_state_id"] and view["root_epoch"] == 0 and view["authority"]["state"] == "usable",
                "current DEC network view changed independently verified creation identity/authority")
        require(isinstance(status, dict) and status["networks"] == [view] and
                status["host_id"] == value.identity["id"] and isinstance(status["version"], str),
                "status does not expose the exact coherent current DEC NETWORK_VIEW")
        require(all(set(item) == {"kind", "subject", "detail", "command"} for item in status["attention"]),
                "status attention fabricated extra public authority fields")
        again, _ = value.api("GET", "/v2/status")
        require(same_json(again, status) and same_json(all_database_snapshots(value.host.state), before),
                "status/network reads changed durable guards, authority, signer, signatures or keys")
        self.trace.append({"network_id": network["id"], "mode": "decentralized", "requested_time": "2026-10-26T12:01:00Z",
            "committed_creation_time": NOW, "all_durable_database_rows_unchanged": True,
            "status_matches_current_network_view": True})

    def legacy(self) -> None:
        original = self.baseline_state.resolve()
        require(not (original/"admin.sock").exists(), "genuine baseline is not stopped")
        original_files = tree_hashes(original)
        original_rows = all_database_snapshots(original)
        folder = self.root/"legacy-history"; folder.mkdir(mode=0o700)
        state = folder/"state"; shutil.copytree(original, state)
        old = Host(self.baseline, state, folder/"old", "old-oauth22")
        self.instances.append(old)
        # Reserve an exact owned address without listening. Legacy create is
        # publicly local-first and succeeds with a connection-refused history.
        # The same address then becomes an observation-only connection trap.
        observer = socket.socket(); observer.bind(("127.0.0.1", 0))
        address = "127.0.0.1:"+str(observer.getsockname()[1])
        stop, attempts = threading.Event(), []
        thread = None
        try:
            old.start()
            identity = old.api("GET", "/v1/host")
            old.cli("network", "create", "--name", "Independent legacy status history", "--member", "Historical owner",
                "--coordinator", address, "--coordinator-key", self.keys.public("status-legacy-coordinator"), "--no-person")
            previous = old.api("GET", "/v1/status")
            old_capture = folder/"old-status.public.json"
            old_capture.write_bytes(raw_json(previous)); old_capture.chmod(0o600)
            require(len(previous["networks"]) == 1, "legacy setup lacks one actual old public network status")
            old_entry = previous["networks"][0]
            require(set(old_entry) == LEGACY and old_entry["last_sync_at"] is None and
                    isinstance(old_entry["last_sync_error"], str) and old_entry["person"] is None and old_entry["policy"] is None,
                    "genuine legacy history lacks the known nullable/error precondition")
            old.stop()
            observer.listen(16); observer.settimeout(.1)
            def observe() -> None:
                while not stop.is_set():
                    try: connection, _ = observer.accept()
                    except socket.timeout: continue
                    except OSError: break
                    attempts.append(time.monotonic()); connection.close()
            thread = threading.Thread(target=observe, name="owned-legacy-coordinator-observer"); thread.start()
            current = Host(self.binary, state, folder/"current", "current-status")
            self.instances.append(current); current.start()
            actual_identity = current.api("GET", "/v1/host")
            require(actual_identity["id"] == identity["id"] and actual_identity["public_key"] == identity["public_key"],
                    "opening legacy history replaced the actual owned host identity")
            before, count = all_database_snapshots(state), len(attempts)
            status = current.api("GET", "/v2/status")
            current_capture = folder/"current-status.public.json"
            current_capture.write_bytes(raw_json(status)); current_capture.chmod(0o600)
            expected = {"mode": "legacy_history", "migration_required": True, **old_entry}
            require(status["networks"] == [expected] and set(status["networks"][0]) == LEGACY|{"mode", "migration_required"},
                    "legacy status changed exact existing fields/types; paths="+",".join(public_diff_paths([expected], status["networks"])))
            for field, value in previous.items():
                if field in {"networks", "attention", "version"}: continue
                require(field in status and same_json(status[field], value), "legacy status lost retained nonnetwork product field "+field)
            again = current.api("GET", "/v2/status")
            time.sleep(.05)
            require(same_json(again, status) and same_json(all_database_snapshots(state), before) and len(attempts) == count,
                    "legacy status mutated durable history or contacted the configured old coordinator")
            current.stop()
            require(tree_hashes(original) == original_files and same_json(all_database_snapshots(original), original_rows),
                    "status fixture modified its untouched genuine OAuth22 baseline")
            self.trace.append({"network_id": old_entry["id"], "mode": "legacy_history", "migration_required": True,
                "nine_retained_legacy_fields_exact": True, "nullable_person_policy_retained": True,
                "all_durable_database_rows_unchanged_during_status": True, "coordinator_connections_during_reads": 0,
                "original_baseline_unchanged": True})
        finally:
            stop.set(); observer.close()
            if thread: thread.join(timeout=2)

    def run(self, *, legacy_only: bool = False) -> None:
        if not legacy_only:
            self.case("status/current_DEC_view_coherent_and_read_only_without_guard_advance", self.current_dec)
        self.case("status/genuine_legacy_history_exact_and_read_only", self.legacy)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-only", action="store_true", help="evaluate only the already-failed legacy status case")
    parser.add_argument("--host", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--baseline-state", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args(); args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    keys = FixtureKeys(); suite = StatusSuite(args.host.resolve(), args.baseline.resolve(), args.baseline_state.resolve(), args.work_dir.resolve(), keys)
    failure = detail = None; started = time.monotonic()
    try: suite.run(legacy_only=args.legacy_only)
    except BaseException as error:
        failure = type(error).__name__; detail = str(error) if isinstance(error, CheckFailure) else "fixture/transport failure"
    finally:
        for host in reversed(suite.instances):
            try: host.stop()
            except BaseException as error:
                failure = failure or type(error).__name__
                suite.rows.append({"name": "cleanup", "passed": False, "error_type": type(error).__name__})
        keys.close()
    result = {"contract_pin": PIN, "implementation_source_read": False, "suite_sha256": sha(Path(__file__).read_bytes()),
        "support_sha256": {name: sha(Path(__file__).with_name(name).read_bytes()) for name in
            ("decentralized_create_controls.py", "decentralized_owner_preview.py", "decentralized_runtime.py", "decentralized_storage.py", "decentralized_fixtures.py", "decentralized_vectors.py")},
        "host": str(args.host.resolve()), "host_sha256": sha(args.host.read_bytes()),
        "baseline": str(args.baseline.resolve()), "baseline_sha256": sha(args.baseline.read_bytes()),
        "baseline_state": str(args.baseline_state.resolve()), "rows": suite.rows, "trace": suite.trace,
        "failure": failure, "detail": detail, "seconds": round(time.monotonic()-started, 3),
        "scope": "two native Go public status cases only: current DEC view coherence/read purity and exact legacy-history response over a genuine baseline copy; no peer/native up/installed claim",
        "legacy_only": args.legacy_only,
        "passed": failure is None and len(suite.rows) == (1 if args.legacy_only else 2) and all(row["passed"] for row in suite.rows)}
    args.results.parent.mkdir(parents=True, exist_ok=True); args.results.write_text(json.dumps(result, indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
