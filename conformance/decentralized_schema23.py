#!/usr/bin/env python3
"""Independent actual OAuth22 -> DEC23 additive opening and refusal checks.

Only the reviewed public schema contract and our actual public-API-created
OAuth baselines supply expectations. Experimental DEC22 originals are never
relabelled. Generic read-only table/cell hashes preserve tokens without exposing
them; stopped COPY fault injections use only normative table/version names.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sqlite3
import time

from decentralized_fixtures import raw_json, sha
from decentralized_storage import (CheckFailure, Host, old_rows_equal, public_diff_paths,
    public_snapshot, refuse, require, retain_public, running, snapshot, sqlite_file, tree_hashes)
from decentralized_vectors import same_json


PIN = "e38910db7d06f5d86dfa3b90d53825ba2975b363"
DEC_TABLES = {"dec_contexts", "dec_objects", "dec_admissions", "dec_restrictions", "dec_activations",
    "dec_heads", "dec_highwater", "dec_signers", "dec_clock", "dec_intents", "dec_pending", "dec_frames",
    "dec_operations", "dec_outbox", "dec_migrations", "dec_contacts", "dec_helpers"}


def require_network_info(host: Host) -> dict:
    """Public runtime section9 applies to current schema23 binaries as well."""
    value = host.api("GET", "/v2/info")
    require(type(value) is dict and value.get("network_protocols") == ["peerspan-decentralized-v1"] and
            "default_coordinator" in value and value["default_coordinator"] is None,
            "current owner-local info omitted DEC network_protocols or retained a default coordinator")
    return value


def named(value: str) -> tuple[str, Path]:
    name, separator, path = value.partition("=")
    if not separator or name not in {"go", "rust"}:
        raise argparse.ArgumentTypeError("expected go=/absolute/path or rust=/absolute/path")
    return name, Path(path).resolve()


class OpeningSuite:
    def __init__(self, root: Path) -> None:
        self.root, self.rows = root, []

    def case(self, name: str, function) -> None:
        started = time.monotonic()
        try:
            data = function() or {}
        except BaseException as failure:
            self.rows.append({"name": name, "passed": False, "error_type": type(failure).__name__,
                "detail": str(failure) if isinstance(failure, CheckFailure) else "fixture/transport failure",
                "seconds": round(time.monotonic()-started, 3)})
            print("FAIL " + name, flush=True)
            raise
        self.rows.append({"name": name, "passed": True, "seconds": round(time.monotonic()-started, 3), **data})
        print("PASS " + name, flush=True)

    def refusal(self, binary: Path, original: Path, root: Path, fault: str) -> dict:
        require(not (original / "admin.sock").exists(), "refusal original is not stopped")
        original_snapshot, original_files = snapshot(original), tree_hashes(original)
        state = root / "copy"
        shutil.copytree(original, state)
        with sqlite3.connect(sqlite_file(state)) as connection:
            if fault == "future24":
                connection.execute("PRAGMA user_version=24")
            elif fault == "reserved_view":
                connection.execute("CREATE VIEW dec_contexts AS SELECT 1 AS fixture_collision")
            elif fault == "generated_column":
                connection.execute("ALTER TABLE dec_clock ADD COLUMN fixture_extra INTEGER GENERATED ALWAYS AS (1) VIRTUAL")
            elif fault != "unchanged":
                raise CheckFailure("unknown owned-copy fault")
        before, files = snapshot(state), tree_hashes(state)
        try:
            refuse(binary, state, root / "logs", fault)
            require(same_json(snapshot(state), before), "refusal changed original rows/DDL/version")
            require(tree_hashes(state) == files, "refusal changed copied file bytes")
            require(same_json(snapshot(original), original_snapshot) and tree_hashes(original) == original_files,
                    "refusal changed the untouched original")
        finally:
            observed = snapshot(state)
            facts = {"initial_version": before["user_version"], "final_version": observed["user_version"],
                "snapshot_unchanged": same_json(observed, before), "file_bytes_unchanged": tree_hashes(state) == files}
            receipt = root / "refusal-observation.json"
            receipt.write_bytes(raw_json(facts)); receipt.chmod(0o600)
        return facts

    def pair(self, label: str, old: Path, new: Path, original22: Path, public_file: Path) -> None:
        root = self.root / label
        root.mkdir(mode=0o700)
        original, original_files = snapshot(original22), tree_hashes(original22)
        require(original["user_version"] == 22 and not (DEC_TABLES & original["tables"].keys()),
                "baseline is not genuine OAuth22 without experimental DEC tables")
        require(original["tables"].get("oauth_clients", {}).get("rows") and
                original["tables"].get("oauth_credentials", {}).get("rows"), "baseline has no actual persisted OAuth state")
        require(not (original22 / "admin.sock").exists(), "baseline22 original is not stopped")
        expected = json.loads(public_file.read_bytes())
        caller_file = original22.parent / "owned-adapter-creation.json"
        caller_sha = sha(caller_file.read_bytes())
        state = root / "upgrade23"
        shutil.copytree(original22, state)
        initial_files = tree_hashes(state)
        def opening() -> dict:
            host = Host(new, state, root / "opening", "actual23")
            with running(host):
                require_network_info(host)
                current = public_snapshot(host, {})
                retain_public(root, "actual23", current)
                require(same_json(current, expected), "actual23 changed public product views; paths="+
                        ",".join(public_diff_paths(expected, current)[:32]))
            after = snapshot(state)
            require(after["user_version"] == 23, "opening did not set actual DEC23")
            old_rows_equal(original, after)
            require(after["tables"].keys()-original["tables"].keys() == DEC_TABLES,
                    "OAuth22 opening did not add exactly the17 normative DEC tables")
            database = str(sqlite_file(state).relative_to(state))
            sqlite_files = {database, database+"-wal", database+"-shm"}
            require({k:v for k,v in initial_files.items() if k not in sqlite_files} ==
                    {k:v for k,v in tree_hashes(state).items() if k not in sqlite_files},
                    "opening changed existing non-database private files")
            require(sha(caller_file.read_bytes()) == caller_sha, "opening changed caller-owned adapter credential bytes")
            return {"old_table_count": len(original["tables"]), "new_table_count": len(after["tables"]),
                    "old_snapshot_sha256": sha(raw_json(original)), "new_snapshot_sha256": sha(raw_json(after)),
                    "private_file_sha256": caller_sha}
        self.case(label+"/actual22_to23_exact_old_rows_tokens_headers_files_public_views", opening)
        after = snapshot(state)
        def restart() -> None:
            host = Host(new, state, root / "restart", "actual23-restart")
            with running(host):
                require_network_info(host)
                require(same_json(public_snapshot(host, {}), expected), "23 restart changed old public views")
            require(same_json(snapshot(state), after), "23 restart changed durable table/row/version state")
        self.case(label+"/restart23_exact", restart)
        self.case(label+"/old_oauth22_binary_refuses23", lambda: self.refusal(old, state, root / "downgrade", "unchanged"))
        self.case(label+"/future24_refuses_without_mutation", lambda: self.refusal(new, state, root / "future", "future24"))
        self.case(label+"/pre23_reserved_view_refuses_without_oauth_rewrite", lambda: self.refusal(new, original22, root / "reserved", "reserved_view"))
        self.case(label+"/extra_generated23_column_refuses_without_mutation", lambda: self.refusal(new, state, root / "generated", "generated_column"))
        require(same_json(snapshot(original22), original) and tree_hashes(original22) == original_files,
                "pair changed untouched actual22 baseline")

    def legacy21(self, label: str, new: Path, original21: Path, public_file: Path) -> None:
        """Preserve real21 while both already specified migrations run together."""
        root = self.root / label
        root.mkdir(mode=0o700)
        original, files = snapshot(original21), tree_hashes(original21)
        require(original["user_version"] == 21 and not DEC_TABLES & original["tables"].keys() and
                not {"oauth_clients", "oauth_credentials"} & original["tables"].keys(),
                "legacy original is not untouched genuine21")
        expected = json.loads(public_file.read_bytes())
        # PR86 explicitly adds these public fields with null/empty defaults for
        # old stdio definitions and capabilities. Every original value is exact.
        for agent in expected["sources"]["agents"]:
            for server in agent["servers"]:
                require(server["transport"] == "stdio", "this21 fixture does not model a remote source")
                server.setdefault("remote", None)
                server.setdefault("headers", {})
                server.setdefault("auth", None)
        expected["capability"].setdefault("auth", None)
        state = root / "from21"
        shutil.copytree(original21, state)
        initial_files = tree_hashes(state)
        def opening() -> dict:
            with running(Host(new, state, root / "open", "legacy21-to23")) as host:
                require_network_info(host)
                observed = public_snapshot(host, {})
                retain_public(root, "legacy21-after23", observed)
                require(same_json(observed, expected), "legacy21 product views changed beyond documented OAuth defaults; paths="+
                        ",".join(public_diff_paths(expected, observed)[:32]))
            after = snapshot(state)
            require(after["user_version"] == 23, "legacy21 opening did not set23")
            old_rows_equal(original, after)
            require(after["tables"].keys()-original["tables"].keys() == DEC_TABLES | {"oauth_clients", "oauth_credentials"},
                    "legacy21 did not receive exactly OAuth2 plus DEC17 tables")
            database = str(sqlite_file(state).relative_to(state))
            sqlite_files = {database, database+"-wal", database+"-shm"}
            require({k:v for k,v in initial_files.items() if k not in sqlite_files} ==
                    {k:v for k,v in tree_hashes(state).items() if k not in sqlite_files},
                    "legacy21 opening changed non-database private files")
            return {"old_table_count": len(original["tables"]), "new_table_count": len(after["tables"]),
                    "old_snapshot_sha256": sha(raw_json(original)), "new_snapshot_sha256": sha(raw_json(after)),
                    "source21": str(original21), "public21_sha256": sha(public_file.read_bytes()),
                    "documented_public_additions": ["stdio.remote:null", "stdio.headers:{}", "stdio.auth:null", "capability.auth:null"]}
        self.case(label+"/genuine21_receives_oauth22_and_dec23_with_all_old_facts", opening)
        self.case(label+"/reserved21_refuses_before_either_migration_changes_state",
                  lambda: self.refusal(new, original21, root / "reserved", "reserved_view"))
        require(same_json(snapshot(original21), original) and tree_hashes(original21) == files,
                "legacy21 continuation changed untouched original")

    def late_ddl(self, label: str, new: Path, original: Path) -> None:
        root = self.root / label
        root.mkdir(mode=0o700)
        initial, original_files = snapshot(original), tree_hashes(original)
        require(initial["user_version"] in {21, 22} and not DEC_TABLES & initial["tables"].keys(),
                "late-DDL original must be genuine21 or OAuth22")
        state = root / "controlled"
        shutil.copytree(original, state)
        files = tree_hashes(state)
        enabled = {"PEERSPAN_DEC_TEST_MODE": "1", "PEERSPAN_DEC_TEST_FAIL_AFTER_SCHEMA_DDL": "1"}
        def failure() -> dict:
            refuse(new, state, root / "failed", "late-ddl", environment_extra=enabled)
            require(b"test schema migration failure" in (root / "failed/late-ddl.refusal.log").read_bytes(),
                    "opening failed for a reason other than the exact opt-in post-DDL failure")
            require(same_json(snapshot(state), initial), "late-DDL failure left version, DDL or rows changed")
            require(tree_hashes(state) == files, "late-DDL failure changed original file bytes")
            return {"source_version": initial["user_version"], "rolled_back_all_oauth_and_dec_ddl": True,
                    "snapshot_sha256": sha(raw_json(initial)), "all_file_bytes_unchanged": True}
        self.case(label+"/actual_post_ddl_failure_rolls_back_exact_original", failure)
        def normal() -> dict:
            with running(Host(new, state, root / "normal", "after-late-failure")):
                pass
            after = snapshot(state)
            require(after["user_version"] == 23, "same failed copy cannot open normally without the flag")
            old_rows_equal(initial, after)
            expected_additions = DEC_TABLES | ({"oauth_clients", "oauth_credentials"} if initial["user_version"] == 21 else set())
            require(after["tables"].keys()-initial["tables"].keys() == expected_additions,
                    "normal continuation after late rollback added wrong tables")
            return {"source_version": initial["user_version"], "normal_version": 23,
                    "new_table_count": len(after["tables"]), "same_copy_opened_normally": True}
        self.case(label+"/same_copy_opens_normally_after_rollback", normal)
        def current() -> None:
            before = snapshot(state)
            host = Host(new, state, root / "current", "current23-control-ignored")
            host.environment.update(enabled)
            with running(host):
                pass
            require(same_json(snapshot(state), before), "current23 flag failed or rewrote history")
        self.case(label+"/current23_ignores_both_flags_without_rewrite", current)
        require(same_json(snapshot(original), initial) and tree_hashes(original) == original_files,
                "late-DDL controlled copy changed original")

    def disabled_ddl(self, label: str, new: Path, original22: Path) -> None:
        for suffix, settings in [
            ("without_mode", {"PEERSPAN_DEC_TEST_FAIL_AFTER_SCHEMA_DDL": "1"}),
            ("nonliteral_value", {"PEERSPAN_DEC_TEST_MODE": "1", "PEERSPAN_DEC_TEST_FAIL_AFTER_SCHEMA_DDL": "true"})]:
            root = self.root / (label+"-"+suffix)
            root.mkdir(mode=0o700)
            state = root / "copy"
            shutil.copytree(original22, state)
            before = snapshot(state)
            def opening() -> None:
                host = Host(new, state, root / "open", suffix)
                host.environment.update(settings)
                with running(host):
                    pass
                after = snapshot(state)
                require(after["user_version"] == 23, "disabled late-DDL control refused normal opening")
                old_rows_equal(before, after)
            self.case(label+"/fail_flag_ignored_"+suffix, opening)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-binary", action="append", type=named, required=True)
    parser.add_argument("--baseline-state", action="append", type=named, required=True)
    parser.add_argument("--baseline-public", action="append", type=named, required=True)
    parser.add_argument("--upgrade", action="append", type=named, required=True)
    parser.add_argument("--pair", action="append", choices=["go-go", "go-rust", "rust-go", "rust-rust"])
    parser.add_argument("--experimental-state", type=Path)
    parser.add_argument("--legacy21-state", type=Path)
    parser.add_argument("--legacy21-public", type=Path)
    parser.add_argument("--legacy21-only", action="store_true")
    parser.add_argument("--late-ddl-only", action="store_true")
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()
    old, states, publics, new = map(dict, (args.baseline_binary, args.baseline_state, args.baseline_public, args.upgrade))
    for mapping in (old, states, publics, new):
        require(set(mapping) == {"go", "rust"}, "actual all4 matrix requires named Go and Rust inputs")
    args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    suite, failures = OpeningSuite(args.work_dir.resolve()), []
    started = time.monotonic()
    if bool(args.legacy21_state) != bool(args.legacy21_public) or args.legacy21_only and not args.legacy21_state:
        parser.error("legacy21 requires both its untouched state and original public snapshot")
    for label in ([] if args.legacy21_only or args.late_ddl_only else args.pair or ["go-go", "go-rust", "rust-go", "rust-rust"]):
        source, target = label.split("-")
        try:
            suite.pair(label, old[source], new[target], states[source], publics[source])
        except BaseException as error:
            failures.append({"pair": label, "type": type(error).__name__,
                             "detail": str(error) if isinstance(error, CheckFailure) else "fixture/transport failure"})
    if args.experimental_state:
        for name, binary in new.items():
            try:
                prior = snapshot(args.experimental_state)
                require(prior["user_version"] == 22 and DEC_TABLES <= prior["tables"].keys(),
                        "experimental original is not the retained historical DEC22 layout")
                suite.case(name+"/experimental_dec22_is_not_reinterpreted_as_oauth22", lambda b=binary, n=name:
                    suite.refusal(b, args.experimental_state, args.work_dir / (n+"-experimental"), "unchanged"))
            except BaseException as error:
                failures.append({"pair": name+"-experimental", "type": type(error).__name__,
                    "detail": str(error) if isinstance(error, CheckFailure) else "fixture/transport failure"})
    if args.legacy21_state and not args.late_ddl_only:
        for name, binary in new.items():
            try:
                suite.legacy21("legacy21-"+name, binary, args.legacy21_state, args.legacy21_public)
            except BaseException as error:
                failures.append({"pair": "legacy21-"+name, "type": type(error).__name__,
                    "detail": str(error) if isinstance(error, CheckFailure) else "fixture/transport failure"})
    if args.late_ddl_only:
        require(args.legacy21_state is not None, "late-DDL scope requires untouched genuine21 source")
        for name, binary in new.items():
            try:
                suite.late_ddl(name+"-late21", binary, args.legacy21_state)
                suite.late_ddl(name+"-late22", binary, states[name])
                suite.disabled_ddl(name+"-disabled", binary, states[name])
            except BaseException as error:
                failures.append({"pair": name+"-late-ddl", "type": type(error).__name__,
                    "detail": str(error) if isinstance(error, CheckFailure) else "fixture/transport failure"})
    result = {"contract_pin": PIN, "implementation_source_read": False,
        "additional_oracle_pins": ["31bd400823d6b69643ea948ee9215bfe418e35ff"] if args.late_ddl_only else [],
        "suite_sha256": sha(Path(__file__).read_bytes()),
        "baseline_artifacts": {n: {"path": str(p), "sha256": sha(p.read_bytes())} for n,p in old.items()},
        "upgrade_artifacts": {n: {"path": str(p), "sha256": sha(p.read_bytes())} for n,p in new.items()},
        "rows": suite.rows, "failures": failures, "seconds": round(time.monotonic()-started, 3),
        "scope": ("explicit per-process real post-DDL opening rollback on genuine21/OAuth22 copies, normal same-copy recovery and ignored controls"
                  if args.late_ddl_only else
                  "genuine21 receives existingOAuth22 plus DEC23; reserved-name preflight refusal only, no post-DDL fault claim"
                  if args.legacy21_only else
                  "actual mergedOAuth22 additiveDEC23 opening/restart/refusal on owned stopped copies only; no protocol migration/runtime claim"),
        "passed": not failures and all(r["passed"] for r in suite.rows)}
    args.results.parent.mkdir(parents=True, exist_ok=True)
    args.results.write_text(json.dumps(result, indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
