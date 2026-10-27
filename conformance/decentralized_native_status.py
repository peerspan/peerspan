#!/usr/bin/env python3
"""One pending native status exit/purity control from public runtime section6.

Use a stopped, independently created pending fixture in place. This runs no
creation, request, approval, selection, signature, cancellation or application.
An old unsigned request may now be expired; that does not make it completed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import time
from types import SimpleNamespace

from decentralized_complete_link import table_rows
from decentralized_fixtures import raw_json, sha
from decentralized_owner_preview import authority_rows
from decentralized_requester import VIEW
from decentralized_storage import CheckFailure, Host, all_database_snapshots, require
from decentralized_vectors import strict_output


PIN = "b491b6a35935f9320a15d90f69ee6aba43cd96ef"
CASE = "native_pending_single_status_is_incomplete_nonzero_flat_and_readonly"


def snapshot(host):
    result = {"authority": authority_rows(SimpleNamespace(host=host))}
    for table, columns in (("dec_pending", "request_id,record,secret"),
                           ("dec_intents", "intent_id,record,secret"),
                           ("dec_clock", "network_id,record")):
        result[table] = table_rows(host, table, columns)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("daemon", "cli", "fixture-dir", "work-dir", "results"):
        parser.add_argument("--"+name, type=Path, required=True)
    args = parser.parse_args()
    for name in ("daemon", "cli", "fixture_dir", "work_dir", "results"):
        setattr(args, name, getattr(args, name).resolve())
    args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    state = args.fixture_dir/"requester"/"state"
    require(not (state/"admin.sock").exists(), "original native fixture is not stopped")
    host = Host(args.daemon, state, args.work_dir, "pending-status")
    host.environment["PATH"] = "/usr/bin:/bin"
    rows, trace, failure, detail = [], [], None, None
    began = time.monotonic()
    try:
        pending = table_rows(host, "dec_pending", "request_id,record")
        require(len(pending)==1, "fixture lacks one independently created pending request")
        identifier, encoded = pending[0]
        record = strict_output(encoded.encode())
        require(record["terminal"]=="-" and not record["commit_approved"], "fixture is completed or final-committed")
        host.start()
        before = snapshot(host)
        generic_before = all_database_snapshots(state)
        current = host.api("GET", "/v2/link/requests/"+identifier)
        result = subprocess.run([str(args.cli), "--state", str(state), "link", "status", identifier],
                                capture_output=True, env=host.environment, timeout=30)
        for name, data in (("stdout", result.stdout), ("stderr", result.stderr)):
            path=args.work_dir/("status."+name); path.write_bytes(data); path.chmod(0o600)
        (args.work_dir/"status.meta.json").write_bytes(raw_json({"exit":result.returncode,
            "stdout_sha256":sha(result.stdout), "stderr_sha256":sha(result.stderr)}))
        require(result.returncode!=0, "pending single status incorrectly reports completed exit0")
        value = strict_output(result.stdout)
        require(type(value) is dict and set(value)==VIEW and value==current and
                value["request_id"]==identifier and value["state"]!="linked" and
                not value["commit_approved"] and value["outcome_id"]=="-",
                "native status changes flat pending view or discloses a display code")
        require(snapshot(host)==before, "native status changed authority, pending identity/consent, intent or clock")
        (args.work_dir/"database-before.json").write_bytes(raw_json(generic_before))
        (args.work_dir/"database-after.json").write_bytes(raw_json(all_database_snapshots(state)))
        trace.append({"request_id":identifier, "state":value["state"],
            "selection_approved":value["selection_approved"], "commit_approved":False,
            "native_exit":result.returncode, "no_request_or_consent_repeated":True,
            "snapshot_scope":"exact normative authority, pending records/secrets, intents/secrets and clock"})
        rows.append({"name":CASE, "passed":True})
    except BaseException as error:
        failure=type(error).__name__; detail=str(error) if isinstance(error,CheckFailure) else "fixture/transport failure"
        rows.append({"name":CASE, "passed":False, "error_type":failure, "detail":detail})
    finally:
        try: host.stop()
        except BaseException as error:
            failure=failure or type(error).__name__;rows.append({"name":"cleanup", "passed":False, "error_type":type(error).__name__})
    receipt={"contract_pin":PIN, "implementation_source_read":False,
        "suite_sha256":sha(Path(__file__).read_bytes()),
        "artifacts":{name:{"path":str(getattr(args,name)),"sha256":sha(getattr(args,name).read_bytes())} for name in ("daemon","cli")},
        "fixture_dir":str(args.fixture_dir), "rows":rows, "trace":trace,
        "failure":failure, "detail":detail, "seconds":round(time.monotonic()-began,3),
        "scope":"one pending/expired single-status exit and read purity control; no native flow, provider, relay, service/up or installed repeat",
        "passed":failure is None and len(rows)==1 and rows[0]["passed"]}
    args.results.parent.mkdir(parents=True,exist_ok=True)
    args.results.write_text(json.dumps(receipt,indent=2)+"\n")
    return 0 if receipt["passed"] else 1


if __name__=="__main__":
    raise SystemExit(main())
