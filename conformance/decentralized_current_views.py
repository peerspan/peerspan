#!/usr/bin/env python3
"""Independent merged131 current-person/policy and native read controls.

Reopen the actual independently admitted creator state in place. Only public
receipt identities and original encoded catalog statements supply expectations.
No old enrollment case, daemon key, signer selection or authority mutation.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import time
from urllib.parse import quote

from decentralized_complete_link import statement_id
from decentralized_fixtures import FixtureKeys, b64, raw_json, sha, unb64
from decentralized_runtime import CreationSuite
from decentralized_storage import CheckFailure, all_database_snapshots, require
from decentralized_vectors import strict_output

PIN = "e7cb49bdec5dbaa254abfb2417d6bc695d65d88d"
SPEC = Path(__file__).with_name("decentralized_current_views_cases.json")
CASES = [c["name"] for c in json.loads(SPEC.read_bytes())["cases"]]


class CurrentViews:
    def __init__(self, args, keys):
        self.args = args
        created = strict_output((args.fixture_dir/"cli-001.stdout").read_bytes())
        completed = strict_output(args.completion_receipt.read_bytes())
        finals = [v for v in completed["trace"] if v.get("two_original_people") and v.get("normal_direct_catalog_observed")]
        require(completed["passed"] and len(finals) == 1 and finals[0]["inviter_person"] == created["person_public_key"],
                "current-view fixture lacks the exact independent two-person completion")
        self.network, self.context = created["id"], created["context_id"]
        self.alice, self.bob = finals[0]["inviter_person"], finals[0]["invitee_person"]
        self.actual_host = created["host_public_key"]
        self.suite = CreationSuite(args.host, args.work_dir, keys)
        self.suite.host.state = args.fixture_dir/"owner"/"state"
        require(not (self.suite.host.state/"admin.sock").exists(), "actual creator state is not stopped")
        self.suite.host.environment["PATH"] = "/usr/bin:/bin"
        self.trace = []

    def run(self):
        self.suite.host.start()
        identity = self.suite.host.api("GET", "/v1/host")
        require(identity["public_key"] == self.actual_host, "read fixture opening replaced actual A host")
        network = self.suite.api("GET", "/v2/networks/"+self.network)[0]
        require(network["context_id"] == self.context and network["person_public_key"] == self.alice and
                network["authority"]["state"] == "usable", "read fixture lacks independently usable admitted creator")
        before = all_database_snapshots(self.suite.host.state)
        catalog = self.suite.api("GET", "/v2/networks/"+self.network+"/catalog")[0]["catalog"]
        statements = {}
        for entry in catalog["objects"]:
            if entry["kind"] not in {"person_lease", "policy"}: continue
            original = unb64(entry["body_base64"]); statement = strict_output(original)
            require(statement["kind"] == entry["kind"] and statement["context_id"] == self.context,
                    "retained ordinary catalog statement context/kind differs")
            statements[statement_id(statement)] = (statement, strict_output(unb64(statement["payload_base64"])), original)
        persons = {}
        for identifier, (statement, payload, _) in statements.items():
            if statement["kind"] != "person_lease": continue
            subject = payload["subject"]
            if subject["person_public_key"] in (self.alice, self.bob):
                require(subject["person_public_key"] not in persons, "fixture has multiple admitted person candidates; no hash-selected oracle")
                persons[subject["person_public_key"]] = {"person_public_key":subject["person_public_key"], "member":subject["member"],
                    "person_lease_id":identifier, "not_after":payload["not_after"]}
        require(set(persons) == {self.alice, self.bob}, "public fixture catalog does not supply both exact admitted P bodies")

        def person_read():
            actual = self.suite.api("GET", "/v2/networks/"+self.network+"/persons")[0]
            require(actual == {"context_id":self.context, "persons":[persons[k] for k in sorted(persons)]},
                    "current persons differs from exact admitted original people/P labels/deadlines")
            require(all_database_snapshots(self.suite.host.state) == before, "current person/catalog reads changed durable state")
        self.suite.case(CASES[0], person_read)

        def policy_read():
            policies = [(identifier, original) for identifier, (statement, payload, original) in statements.items()
                if statement["kind"] == "policy" and payload["issuer"]["person_public_key"] == self.alice]
            require(len(policies) == 1, "public fixture lacks one exact current Alice policy")
            identifier, original = policies[0]
            value = self.suite.api("GET", "/v2/networks/"+self.network+"/policy/"+quote(self.alice, safe=""))[0]
            require(value == {"statement_id":identifier, "statement_base64":b64(original)} and len(original) <= 1024*1024,
                    "current policy changed ORIGINAL signed bytes/DS or returned a legacy variant")
            denied = self.suite.api("GET", "/v2/networks/"+self.network+"/policy/"+quote(self.bob, safe=""), status=404)[0]
            self.suite.error(denied, "not_found")
            require(all_database_snapshots(self.suite.host.state) == before, "policy read/absence check changed durable state")
        self.suite.case(CASES[1], policy_read)

        def native_reads():
            commands = [("agents", "--network", self.network, "--json"),
                ("access", "show", "--network", self.network, "--person", persons[self.alice]["member"])]
            for index, command in enumerate(commands, 1):
                result = subprocess.run([str(self.args.host), "--state", str(self.suite.host.state), *command],
                    capture_output=True, env=self.suite.host.environment, timeout=30)
                for suffix, data in (("stdout", result.stdout), ("stderr", result.stderr)):
                    path = self.args.work_dir/("native-%02d." % index+suffix); path.write_bytes(data); path.chmod(0o600)
                require(result.returncode == 0 and result.stdout.strip(), "native current DEC read failed; see protected native captures")
                if index == 1: require(type(strict_output(result.stdout)) is dict, "agents --json is not a directory object")
            after_network = self.suite.api("GET", "/v2/networks/"+self.network)[0]
            require(after_network["provider"] == network["provider"] and after_network["provider_state"] == network["provider_state"] and
                    after_network["authority"] == network["authority"] and self.suite.host.api("GET", "/v1/host") == identity and
                    all_database_snapshots(self.suite.host.state) == before, "native reads changed identity/authority/provider/guard or other durable state")
            self.trace.append({"network_id":self.network, "context_id":self.context, "two_admitted_people":sorted(persons),
                "actual_provider_state":after_network["provider_state"], "original_key_not_passed_to_daemon":True,
                "no_enrollment_function_or_signing_replayed":True, "native_internal_HTTP_path_not_traced":True})
        self.suite.case(CASES[2], native_reads)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("host", "fixture-dir", "completion-receipt", "work-dir", "results"): parser.add_argument("--"+name, type=Path, required=True)
    parser.add_argument("--source", required=True)
    args = parser.parse_args()
    for name in ("host", "fixture_dir", "completion_receipt", "work_dir", "results"): setattr(args, name, getattr(args, name).resolve())
    args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    keys = FixtureKeys(); suite = None; failure = detail = None; began = time.monotonic()
    try:
        suite = CurrentViews(args, keys); suite.run()
    except BaseException as error:
        failure = type(error).__name__; detail = str(error) if isinstance(error, CheckFailure) else "fixture/transport failure"
    finally:
        if suite is not None: suite.suite.host.stop()
        keys.close()
    result = {"contract_pin":PIN, "source":args.source, "implementation_source_read":False,
        "artifact":{"path":str(args.host), "sha256":sha(args.host.read_bytes())}, "suite_sha256":sha(Path(__file__).read_bytes()),
        "spec_sha256":sha(SPEC.read_bytes()), "rows":[] if suite is None else suite.suite.rows,
        "trace":[] if suite is None else suite.trace, "failure":failure, "detail":detail,
        "seconds":round(time.monotonic()-began, 3), "scope":"current cached v2 person/policy +native reads only; no new A, info, installed or final-head gate",
        "passed":failure is None and suite is not None and len(suite.suite.rows) == 3 and all(v["passed"] for v in suite.suite.rows)}
    args.results.parent.mkdir(parents=True, exist_ok=True); args.results.write_text(json.dumps(result, indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__": raise SystemExit(main())
