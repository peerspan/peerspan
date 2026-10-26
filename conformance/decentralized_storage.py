#!/usr/bin/env python3
"""Independent additive schema21→22 opening/preservation acceptance.

Create genuine schema21 data using supplied immutable OLD binaries and public
owner-local APIs/CLI.  Stop before copying/upgrading.  No implementation or
preexisting tests are imported; no guessed legacy SQL columns are populated.
Generic snapshots hash actual fixture-created old tables/rows without exposing
private cells.  This first slice does not claim new DEC runtime behavior.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import http.client
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import sqlite3
import subprocess
import time

from decentralized_fixtures import PIN, FixtureKeys, b64, raw_json, sha, unb64
from decentralized_vectors import same_json, strict_output


MCP_FIXTURE = '''#!/usr/bin/env python3
import json,sys
for line in sys.stdin:
    value=json.loads(line)
    if "id" not in value: continue
    method=value["method"]
    if method=="initialize":
        result={"protocolVersion":value["params"]["protocolVersion"],"capabilities":{"tools":{},"resources":{}},"serverInfo":{"name":"independent-schema-fixture","version":"1"}}
    elif method=="tools/list":
        result={"tools":[{"name":"inspect","description":"Fixture metadata only","inputSchema":{"type":"object","properties":{"repo":{"type":"string"}},"required":["repo"]},"annotations":{"readOnlyHint":True}}]}
    elif method=="resources/list":
        result={"resources":[{"uri":"fixture://schema/catalog","name":"Fixture catalog","description":"No real account or network","mimeType":"application/json"}]}
    else:
        print(json.dumps({"jsonrpc":"2.0","id":value["id"],"error":{"code":-32601,"message":"fixture method absent"}}),flush=True); continue
    print(json.dumps({"jsonrpc":"2.0","id":value["id"],"result":result}),flush=True)
'''


class CheckFailure(Exception):
    pass


def require(condition: bool, detail: str) -> None:
    if not condition:
        raise CheckFailure(detail)


def isolated_env(home: Path) -> dict:
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    result = dict(os.environ)
    for key in list(result):
        if key.startswith("PEERSPAN_") or key == "SSH_AUTH_SOCK":
            del result[key]
    result.update(HOME=str(home), XDG_CONFIG_HOME=str(home / "config"),
                  XDG_STATE_HOME=str(home / "state"), XDG_DATA_HOME=str(home / "data"))
    return result


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path: Path, timeout: float = 10) -> None:
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))


class Host:
    def __init__(self, binary: Path, state: Path, root: Path, label: str) -> None:
        self.binary, self.state, self.root, self.label = binary, state, root, label
        self.environment = isolated_env(root / "home")
        for key in ("GH_TOKEN", "GITHUB_TOKEN", "GH_HOST", "GH_ENTERPRISE_TOKEN",
                    "GITHUB_ENTERPRISE_TOKEN", "PYTHONPATH"):
            self.environment.pop(key, None)
        self.environment["GH_CONFIG_DIR"] = str(root / "home" / "gh")
        self.environment["CODEX_HOME"] = str(root / "home" / "codex")
        # No ambient account-facing tools are discovered.  The one fake MCP
        # source below is invoked by its absolute fixture-owned Python path.
        tool_path = root / "empty-path"
        tool_path.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.environment["PATH"] = str(tool_path)
        self.process: subprocess.Popen | None = None
        self.log_path = root / (label + ".daemon.log")

    def start(self) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(len(str(self.state / "admin.sock").encode()) <= 103,
                "fixture owner-local socket path exceeds portable Unix limit")
        self.log = self.log_path.open("ab")
        self.process = subprocess.Popen([str(self.binary), "--state", str(self.state), "run"],
                                        stdout=self.log, stderr=subprocess.STDOUT,
                                        env=self.environment, start_new_session=True)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            require(self.process.poll() is None, "host exited before public owner-local readiness; exit="
                    + str(self.process.returncode) + "; log=" + str(self.log_path))
            try:
                self.api("GET", "/v1/host")
                return
            except (ConnectionError, FileNotFoundError, TimeoutError, OSError):
                time.sleep(0.05)
        raise CheckFailure("host owner-local readiness exceeded10s")

    def stop(self) -> None:
        if self.process is None:
            return
        process, self.process = self.process, None
        try:
            if process.poll() is None:
                require(os.getpgid(process.pid) == process.pid, "tracked host PGID changed")
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
                raise CheckFailure("tracked fixture host did not stop within10s")
            require(process.returncode == 0, "host ordinary shutdown failed")
        finally:
            self.log.close()

    def api(self, method: str, route: str, body: dict | None = None, status: int = 200) -> object:
        connection = UnixHTTP(self.state / "admin.sock", timeout=40 if "tool-servers" in route else 10)
        try:
            wire = None if body is None else raw_json(body)
            connection.request(method, route, body=wire, headers={} if body is None else {"Content-Type": "application/json"})
            response = connection.getresponse()
            data = response.read(32 * 1024 * 1024 + 1)
            require(response.status == status, f"owner API {method} {route} returned{response.status}, expected{status}; body_sha256={sha(data)}")
            return json.loads(data)
        finally:
            connection.close()

    def cli(self, *arguments: str) -> dict | list:
        result = subprocess.run([str(self.binary), "--state", str(self.state), *arguments],
                                capture_output=True, env=self.environment, timeout=40)
        require(result.returncode == 0, "public fixture CLI failed: " + " ".join(arguments[:2])
                + "; stderr_sha256=" + sha(result.stderr))
        return json.loads(result.stdout)


@contextmanager
def running(host: Host):
    try:
        host.start()
        yield host
    except BaseException as original:
        try:
            host.stop()
        except BaseException as cleanup:
            # Preserve the primary startup/API assertion.  The shutdown result
            # is separate evidence, not a replacement for the original error.
            original.add_note("owned cleanup also failed: " + str(cleanup))
        raise
    else:
        host.stop()


def sqlite_file(state: Path) -> Path:
    candidates = []
    for path in state.iterdir():
        if path.is_file() and not path.is_symlink():
            with path.open("rb") as value:
                if value.read(16) == b"SQLite format 3\x00":
                    candidates.append(path)
    require(len(candidates) == 1, "fixture state does not contain exactly one identifiable SQLite database")
    return candidates[0]


def quoted(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def snapshot(state: Path) -> dict:
    """Actual generated database records only; never log private row contents."""
    database = sqlite_file(state)
    connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
    try:
        connection.execute("BEGIN")
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        tables = {}
        for name, ddl in connection.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"):
            rows = []
            for values in connection.execute("SELECT * FROM " + quoted(name)):
                row = [["blob", b64(value)] if isinstance(value, bytes) else [type(value).__name__, value]
                       for value in values]
                rows.append(sha(raw_json(row)))
            tables[name] = {"ddl_sha256": sha(ddl.encode()), "rows": sorted(rows)}
        return {"user_version": version, "tables": tables}
    finally:
        connection.close()


def tree_hashes(state: Path) -> dict:
    result = {}
    for path in sorted(state.rglob("*")):
        require(not path.is_symlink(), "fixture state unexpectedly contains symlink")
        if path.is_file():
            result[str(path.relative_to(state))] = sha(path.read_bytes())
    return result


def old_rows_equal(before: dict, after: dict) -> None:
    for name, value in before["tables"].items():
        require(name in after["tables"], "additive opening dropped old table " + name)
        require(same_json(value, after["tables"][name]), "additive opening changed old table/records " + name)


def public_snapshot(host: Host, facts: dict) -> dict:
    return {"identity": host.api("GET", "/v1/host"), "agents": host.api("GET", "/v1/agents"),
            "peers": host.api("GET", "/v1/peers"), "grants": host.api("GET", "/v1/grants"),
            "sessions": host.api("GET", "/v1/sessions"), "adapters": host.api("GET", "/v1/adapters"),
            "sources": host.api("GET", "/v1/sources"), "capability": host.api("GET", "/v1/capabilities/schema-fixture"),
            "networks": host.api("GET", "/v1/networks")}


def public_diff_paths(before: object, after: object, prefix: str = "") -> list[str]:
    if type(before) is not type(after):
        return [prefix]
    if isinstance(before, dict):
        keys = sorted(before.keys() | after.keys())
        return [path for key in keys for path in
                ([prefix + "/" + key] if key not in before or key not in after else
                 public_diff_paths(before[key], after[key], prefix + "/" + key))]
    if isinstance(before, list):
        if len(before) != len(after):
            return [prefix + "/length"]
        return [path for i, (a, b) in enumerate(zip(before, after))
                for path in public_diff_paths(a, b, prefix + "/" + str(i))]
    return [] if before == after else [prefix]


def retain_public(root: Path, name: str, value: object) -> None:
    path = root / (name + ".public.json")
    path.write_bytes(raw_json(value)); path.chmod(0o600)


def make_baseline(binary: Path, root: Path, keys: FixtureKeys, *,
                  expected_version: int = 21) -> tuple[Path, dict, dict]:
    state = root / ("state" + str(expected_version))
    host = Host(binary, state, root, "baseline21")
    with running(host):
        identity = host.api("GET", "/v1/host")
        require(identity["id"] == "host_" + sha(unb64(identity["public_key"])), "old fixture host identity digest differs")
        agent = host.api("POST", "/v1/agents", {"name": "schema-fixture", "owner": "Fixture owner", "capabilities": ["metadata-only"]}, 201)
        peer_key = keys.public("schema-fixture-peer")
        peer_id = "host_" + sha(unb64(peer_key))
        host.cli("peer", "add", "--id", peer_id, "--public-key", peer_key, "--address", "127.0.0.1:9")
        host.cli("grant", "create", "--peer", peer_id, "--agent", agent["id"], "--expires-in", "1h", "--allow-disconnected")
        session = host.api("POST", "/v1/sessions", {"agent_id": agent["id"], "integration": "independent-storage-fixture"}, 201)
        adapter = host.cli("adapter", "create", "--session", session["id"], "--expires-in", "1h")
        # Caller-owned token file outside the database mirrors the existing
        # credential boundary without assuming any internal record/column name.
        credential_path = root / "owned-adapter-creation.json"
        credential_path.write_bytes(raw_json(adapter)); credential_path.chmod(0o600)
        host.api("POST", "/v1/sessions/" + session["id"] + "/detach", {})
        server_path = root / "owned_mcp_fixture.py"
        server_path.write_text(MCP_FIXTURE); server_path.chmod(0o700)
        secret = os.urandom(32).hex()
        host.api("PUT", "/v1/agents/" + agent["id"] + "/tool-servers",
                 {"workspace": str(root), "servers": [{"name": "fixture", "transport": "stdio",
                   "command": os.path.realpath(os.sys.executable), "args": [str(server_path)],
                   "env": {"FIXTURE_SECRET": {"source": "literal"}}, "url": None,
                   "source": "claude-code:project"}], "values": {"fixture": {"env.FIXTURE_SECRET": secret}}})
        host.cli("capability", "create", "schema-fixture", "--from", "schema-fixture/fixture",
                 "--operations", "inspect", "--resources", "fixture://schema/catalog",
                 "--bound", "repo=fixture/repository", "--approval", "changing")
        views = public_snapshot(host, {})
        require(secret not in json.dumps(views), "public source/capability view disclosed fixture secret")
        require(views["capability"]["bounds"] == {"arguments": [{"repo": "fixture/repository"}]}, "schema21 fixture did not create actual resource bounds")
        require(views["capability"]["resources"] == ["fixture://schema/catalog"], "schema21 fixture did not create actual resource selection")
        require(views["networks"] == [], "baseline fixture unexpectedly enrolled a network")
        facts = {"agent_id": agent["id"], "session_id": session["id"],
                 "private_file": str(credential_path), "private_file_sha256": sha(credential_path.read_bytes())}
    before = snapshot(state)
    require(before["user_version"] == expected_version,
            "supplied OLD binary did not produce schema" + str(expected_version))
    return state, views, facts


def refuse(binary: Path, state: Path, root: Path, label: str, *, environment_extra: dict | None = None) -> None:
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    log = root / (label + ".refusal.log")
    environment = isolated_env(root / "home")
    environment.update(environment_extra or {})
    with log.open("wb") as output:
        process = subprocess.Popen([str(binary), "--state", str(state), "run"],
                                   stdout=output, stderr=subprocess.STDOUT,
                                   env=environment, start_new_session=True)
        try:
            code = process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            require(os.getpgid(process.pid) == process.pid, "refusal fixture PGID changed")
            os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=5)
            raise CheckFailure("unsupported/corrupt schema opening did not refuse within10s")
    require(code != 0, "unsupported/corrupt schema opening exited successfully")
    require(not (state / "admin.sock").exists(), "refused opening left an owner-local socket")


def malformed_schema_copy(new: Path, original21: Path, root: Path, rows: list[dict]) -> None:
    """Authorized malformed normative-name fault on a stopped owned COPY.

    SQLite may skip a colliding view under IF NOT EXISTS, so this checks the
    mandatory schema kind/shape refusal.  It does not claim that the view must
    itself produce an SQLite DDL exception or prove a mid-DDL rollback.
    """
    require(not (original21 / "admin.sock").exists(), "genuine21 original is not stopped")
    original_snapshot = snapshot(original21)
    require(original_snapshot["user_version"] == 21, "fault original is not genuine schema21")
    collision = root / "malformed21"
    shutil.copytree(original21, collision)
    with sqlite3.connect(sqlite_file(collision)) as connection:
        connection.execute("CREATE VIEW dec_contexts AS SELECT 1 AS fixture_collision")
    before = snapshot(collision)
    before_files = tree_hashes(collision)
    row = {"name": "malformed_normative_schema_refuses_without_mutation", "passed": False,
           "original21_snapshot_sha256": sha(raw_json(original_snapshot))}
    rows.append(row)
    try:
        refuse(new, collision, root / "malformed-logs", "normative-view")
        require(same_json(snapshot(collision), before), "malformed-schema refusal changed old rows or schema version")
        require(tree_hashes(collision) == before_files, "malformed-schema refusal changed fixture files")
        require(same_json(snapshot(original21), original_snapshot), "untouched genuine21 original changed")
        row["passed"] = True
    finally:
        after = snapshot(collision)
        with sqlite3.connect(sqlite_file(collision).as_uri() + "?mode=ro", uri=True) as connection:
            kind = connection.execute("SELECT type FROM sqlite_master WHERE name='dec_contexts'").fetchone()
        row.update(result_user_version=after["user_version"],
                   normative_object_type=kind[0] if kind else "-",
                   file_bytes_unchanged=tree_hashes(collision) == before_files,
                   old_rows_unchanged=all(after["tables"].get(k) == v for k, v in before["tables"].items()))


def final_schema_reopen(new: Path, original22: Path, expected_public: Path,
                        root: Path, rows: list[dict]) -> None:
    """Final opening artifact on a stopped retained22 COPY, no upgrade repeat."""
    require(not (original22 / "admin.sock").exists(), "final reopen original22 is not stopped")
    original = snapshot(original22)
    require(original["user_version"] == 22, "final reopen original is not schema22")
    state = root / "reopen22"
    shutil.copytree(original22, state)
    before_files = tree_hashes(state)
    expected = json.loads(expected_public.read_bytes())
    host = Host(new, state, root / "reopen-logs", "final-schema22")
    with running(host):
        observed = public_snapshot(host, {})
        retain_public(root, "final22", observed)
        require(same_json(observed, expected), "final22 public old views differ; paths=" +
                ",".join(public_diff_paths(expected, observed)[:32]))
    require(same_json(snapshot(state), original), "final22 reopen changed table definitions/rows/version")
    after_files = tree_hashes(state)
    database = str(sqlite_file(state).relative_to(state))
    sqlite_files = {database, database + "-wal", database + "-shm"}
    require({k:v for k,v in before_files.items() if k not in sqlite_files} ==
            {k:v for k,v in after_files.items() if k not in sqlite_files}, "final22 reopen changed non-database fixture files")
    require(same_json(snapshot(original22), original), "untouched retained22 original changed")
    rows.append({"name": "final22_reopen_exact_public_views_and_all_rows", "passed": True,
                 "table_count": len(original["tables"]), "snapshot_sha256": sha(raw_json(original)),
                 "expected_public_sha256": sha(expected_public.read_bytes()),
                 "all_file_bytes_unchanged": before_files == after_files,
                 "non_database_file_bytes_unchanged": True})


def generated_schema_column_copy(new: Path, original22: Path, root: Path, rows: list[dict]) -> None:
    """Authorized extra generated column on a stopped normative-table COPY."""
    require(not (original22 / "admin.sock").exists(), "generated-column original22 is not stopped")
    original = snapshot(original22)
    require(original["user_version"] == 22, "generated-column original is not schema22")
    state = root / "generated22"
    shutil.copytree(original22, state)
    with sqlite3.connect(sqlite_file(state)) as connection:
        connection.execute("ALTER TABLE dec_clock ADD COLUMN fixture_extra INTEGER GENERATED ALWAYS AS (1) VIRTUAL")
    before, before_files = snapshot(state), tree_hashes(state)
    row = {"name": "extra_generated_normative_column_refuses_without_mutation", "passed": False}
    rows.append(row)
    try:
        refuse(new, state, root / "generated-logs", "extra-column")
        require(same_json(snapshot(state), before), "generated-column refusal changed schema/rows/version")
        require(tree_hashes(state) == before_files, "generated-column refusal changed fixture file bytes")
        require(same_json(snapshot(original22), original), "untouched retained22 original changed")
        row["passed"] = True
    finally:
        row.update(result_user_version=snapshot(state)["user_version"], file_bytes_unchanged=tree_hashes(state) == before_files)


def pair(old_name: str, old: Path, new_name: str, new: Path, root: Path, keys: FixtureKeys,
         rows: list[dict], continuation: tuple[Path, Path, Path] | None = None) -> None:
    root.mkdir(parents=True, mode=0o700)
    existing22 = None
    if continuation is None:
        state21, views21, facts = make_baseline(old, root / "baseline", keys)
        rows.append({"name": "genuine21_public_setup", "passed": True})
    else:
        state21, existing22, public_file = continuation
        require(not (state21 / "admin.sock").exists() and not (existing22 / "admin.sock").exists(),
                "retained continuation states are not stopped")
        require(snapshot(state21)["user_version"] == 21 and snapshot(existing22)["user_version"] == 22,
                "retained continuation versions differ")
        views21 = json.loads(public_file.read_bytes())
        credential = state21.parent / "owned-adapter-creation.json"  # Our own caller fixture, not product layout.
        facts = {"private_file": str(credential), "private_file_sha256": sha(credential.read_bytes())}
        rows.append({"name": "retained_stopped21_and22_reused_without_original_mutation", "passed": True,
                     "expected_public_sha256": sha(public_file.read_bytes())})
    retain_public(root, "before21", views21)
    old_snapshot = snapshot(state21)
    state22 = root / "upgrade22"
    shutil.copytree(state21 if existing22 is None else existing22, state22)
    stored22_before = None if existing22 is None else snapshot(state22)
    host = Host(new, state22, root / "upgraded", "schema22")
    with running(host):
        views22 = public_snapshot(host, facts)
        retain_public(root, "after22", views22)
        require(same_json(views22, views21), "public old views changed on additive schema22 opening; paths="
                + ",".join(public_diff_paths(views21, views22)[:32]))
        require(not any(key.startswith("dec_") for key in views22), "DEC storage leaked through old public view")
    after = snapshot(state22)
    require(after["user_version"] == 22, "new host did not atomically set schema22")
    old_rows_equal(old_snapshot, after)
    if stored22_before is not None:
        require(same_json(stored22_before, after), "public-view continuation changed the retained22 rows")
    require(sha(Path(facts["private_file"]).read_bytes()) == facts["private_file_sha256"], "caller-owned private adapter file changed")
    rows.append({"name": "additive22_exact_old_rows_and_public_views" if existing22 is None else
                 "fixed_public_views_and_unchanged_existing22_rows", "passed": True,
                 "old_table_count": len(old_snapshot["tables"]), "added_table_count": len(after["tables"]) - len(old_snapshot["tables"]),
                 "old_snapshot_sha256": sha(raw_json(old_snapshot)), "new_snapshot_sha256": sha(raw_json(after))})
    # Read-only reopened state is verified by the other native implementation;
    # its public old data and every private old cell must remain exact again.
    reopen = Host(new, state22, root / "reopened", "schema22-reopen")
    with running(reopen):
        require(same_json(public_snapshot(reopen, facts), views21), "schema22 ordinary reopen changed public old data")
    require(same_json(snapshot(state22), after), "schema22 ordinary reopen changed durable stored rows")
    rows.append({"name": "schema22_restart_exact", "passed": True})
    downgrade = root / "downgrade-refused"
    shutil.copytree(state22, downgrade)
    original_files = tree_hashes(downgrade)
    refuse(old, downgrade, root / "downgrade-logs", "old21")
    require(tree_hashes(downgrade) == original_files, "older binary changed schema22 files before refusal")
    rows.append({"name": "old21_refuses22_without_mutation", "passed": True})
    future = root / "future-refused"
    shutil.copytree(state21, future)
    with sqlite3.connect(sqlite_file(future)) as connection:
        connection.execute("PRAGMA user_version=23")
    original_files = tree_hashes(future)
    refuse(new, future, root / "future-logs", "future23")
    require(tree_hashes(future) == original_files, "new binary changed version23 files before refusal")
    rows.append({"name": "version_above22_refuses_without_mutation", "passed": True})
    malformed_schema_copy(new, state21, root, rows)


def binary_argument(value: str) -> tuple[str, Path]:
    name, separator, filename = value.partition("=")
    if not separator or name not in {"go", "rust"}:
        raise argparse.ArgumentTypeError("expected go=/absolute/binary or rust=/absolute/binary")
    return name, Path(filename).resolve()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", action="append", type=binary_argument, required=True)
    parser.add_argument("--upgrade", action="append", type=binary_argument, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--fault-state21", type=Path,
                        help="only recheck the unchanged normative-view fault using a retained stopped genuine21 original")
    parser.add_argument("--continue-state21", type=Path)
    parser.add_argument("--continue-state22", type=Path)
    parser.add_argument("--reopen-state22", type=Path,
                        help="bounded final-artifact reopen/public-view plus malformed21 and extra-column22 copies")
    parser.add_argument("--expected-public", type=Path,
                        help="retained original public view for a fixed-view continuation on copies; no baseline/upgrade repeat")
    args = parser.parse_args()
    if args.fault_state21 is not None and (len(args.baseline) != 1 or len(args.upgrade) != 1):
        parser.error("--fault-state21 requires one baseline and one upgrade provenance entry")
    continuation_fields = (args.continue_state21, args.continue_state22, args.expected_public)
    if args.reopen_state22 is not None:
        if args.expected_public is None or args.fault_state21 is None or args.continue_state21 is not None or args.continue_state22 is not None or len(args.baseline) != 1:
            parser.error("final reopen requires retained22/public/malformed21 originals, one baseline and no continuation")
    elif any(v is not None for v in continuation_fields):
        if not all(v is not None for v in continuation_fields) or args.fault_state21 is not None or len(args.baseline) != 1 or len(args.upgrade) != 1:
            parser.error("continuation requires all three retained-state/public arguments, one pair and no fault-only option")
    args.work_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    keys, runs = FixtureKeys(), []
    try:
        for old_name, old in args.baseline:
            for new_name, new in args.upgrade:
                name = old_name + "21-to-" + new_name + "22"
                started = time.monotonic()
                run = {"pair": name, "baseline": str(old), "baseline_sha256": sha(old.read_bytes()),
                       "upgrade": str(new), "upgrade_sha256": sha(new.read_bytes()), "rows": []}
                try:
                    if args.reopen_state22 is not None:
                        run["scope"] = "final-artifact stopped22 copy reopen/public views plus unchanged normative-view and generated-column refusal; no upgrade repeat"
                        target = args.work_dir / name
                        target.mkdir(mode=0o700)
                        final_schema_reopen(new, args.reopen_state22.resolve(), args.expected_public.resolve(), target, run["rows"])
                        malformed_schema_copy(new, args.fault_state21.resolve(), target, run["rows"])
                        generated_schema_column_copy(new, args.reopen_state22.resolve(), target, run["rows"])
                    elif args.fault_state21 is None:
                        continuation = tuple(p.resolve() for p in continuation_fields) if args.expected_public is not None else None
                        if continuation is not None:
                            run["scope"] = "unchanged public-view continuation plus previously unreached restart/refusal gates on copies"
                        pair(old_name, old, new_name, new, args.work_dir / name, keys, run["rows"], continuation)
                    else:
                        run["scope"] = "unchanged malformed normative schema refusal only; original five passed gates not repeated"
                        target = args.work_dir / name
                        target.mkdir(mode=0o700)
                        malformed_schema_copy(new, args.fault_state21.resolve(), target, run["rows"])
                    run["passed"] = True
                    print("PASS " + name, flush=True)
                except BaseException as error:
                    run["passed"] = False
                    run["error_type"] = type(error).__name__
                    run["detail"] = str(error) if isinstance(error, CheckFailure) else "fixture/transport failure; see owned log paths"
                    run["notes"] = getattr(error, "__notes__", [])
                    print("FAIL " + name + ": " + run["detail"], flush=True)
                run["seconds"] = round(time.monotonic() - started, 3)
                runs.append(run)
                args.results.parent.mkdir(parents=True, exist_ok=True)
                args.results.write_text(json.dumps({"contract_pin": PIN, "implementation_source_read": False,
                    "suite_sha256": sha(Path(__file__).read_bytes()),
                    "scope": "actual additive schema21-to22 opening/refusal only; no new DEC enrollment/runtime claim",
                    "runs": runs}, indent=2) + "\n")
                if not run["passed"]:
                    break
            if runs and not runs[-1]["passed"]:
                break
        return 0 if runs and all(r["passed"] for r in runs) else 1
    finally:
        keys.close()


if __name__ == "__main__":
    raise SystemExit(main())
