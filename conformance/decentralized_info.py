#!/usr/bin/env python3
"""One new current-schema23 /v2/info assertion, without repeating opening26.

Use an already initialized, stopped owned schema23 state in place. No creation,
enrollment, schema fault, signer or consent operation is performed. All earlier
opening receipts retain their exact original suite hash and expectations.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import time

from decentralized_fixtures import sha
from decentralized_schema23 import require_network_info
from decentralized_storage import CheckFailure, Host, all_database_snapshots, require, running


PIN = "b36bc2ec8b947419a63388f7ab3a8cfa0aca32d8"
CASE = "current23_info_declares_exact_DEC_protocol_and_no_default_coordinator_readonly"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("host", "state", "work-dir", "results"): parser.add_argument("--"+name, type=Path, required=True)
    parser.add_argument("--source", required=True)
    args = parser.parse_args()
    for name in ("host", "state", "work_dir", "results"): setattr(args, name, getattr(args, name).resolve())
    args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    rows = []; failure = detail = None; began = time.monotonic(); value = None
    try:
        databases = all_database_snapshots(args.state)["databases"]
        current = [value for value in databases.values() if {"dec_contexts", "dec_clock"} <= set(value["tables"])]
        require(not (args.state/"admin.sock").exists() and len(current) == 1 and current[0]["user_version"] == 23,
                "single info control requires an initialized stopped current23 state")
        host = Host(args.host, args.state, args.work_dir, "current-info")
        with running(host):
            before = all_database_snapshots(args.state)
            value = require_network_info(host)
            require(all_database_snapshots(args.state) == before, "/v2/info changed durable authority or local state")
        rows.append({"name":CASE, "passed":True})
    except BaseException as error:
        failure = type(error).__name__; detail = str(error) if isinstance(error, CheckFailure) else "fixture/transport failure"
        rows.append({"name":CASE, "passed":False, "error_type":failure, "detail":detail})
    result = {"contract_pin":PIN, "implementation_source_read":False, "source":args.source,
        "artifact":{"path":str(args.host), "sha256":sha(args.host.read_bytes())}, "state":str(args.state),
        "suite_sha256":sha(Path(__file__).read_bytes()), "schema_suite_sha256":sha(Path(__file__).with_name("decentralized_schema23.py").read_bytes()),
        "rows":rows, "info":value, "failure":failure, "detail":detail, "seconds":round(time.monotonic()-began, 3),
        "scope":"one required public current-info assertion only; no opening26 or prior positive replay", "passed":failure is None}
    args.results.parent.mkdir(parents=True, exist_ok=True); args.results.write_text(json.dumps(result, indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__": raise SystemExit(main())
