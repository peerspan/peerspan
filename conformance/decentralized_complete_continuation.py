#!/usr/bin/env python3
"""Failed participant-application continuation on the SAME owned stopped pair.

Reuses only our original public fixture/oracles. Actual daemon keys stay in
place. No first-four-case repeat, new consent, key copying or implementation
read; evaluate the failed application, then only its unevaluated dependents.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import time

from decentralized_complete_link import CompleteLink, packet_message, statement_id, table_rows
from decentralized_direct_carrier import CarrierWire
from decentralized_fixtures import FixtureKeys, b64, lines, raw_json, sha, unb64
from decentralized_helper import ClientIdentity
from decentralized_owner_preview import authority_rows
from decentralized_requester import Requester, VIEW
from decentralized_runtime import CreationSuite
from decentralized_storage import CheckFailure, all_database_snapshots, require
from decentralized_vectors import strict_output


class Continuation(CompleteLink):
    def __init__(self, owner_binary: Path, requester_binary: Path, retained: Path, root: Path, keys: FixtureKeys) -> None:
        self.root, self.keys, self.retained = root, keys, retained
        for label in ("owner", "requester"):
            (root/label).mkdir(mode=0o700)
        self.owner = CreationSuite(owner_binary, root/"owner", keys)
        self.requester = Requester(requester_binary, root/"requester", keys)
        self.rows, self.trace, self.signatures = self.owner.rows, [], {}
        self.endpoints = {}
        # Keep each host's actual state/key files in their original directory.
        # Only API captures/logs live in the new continuation receipt directory.
        for label, instance in (("owner", self.owner), ("requester", self.requester)):
            instance.host.state = retained/label/"state"
            require(not (instance.host.state/"admin.sock").exists(), "retained fixture is not stopped")
            instance.host.environment.update(PEERSPAN_DEC_TEST_MODE="1", PEERSPAN_DEC_TEST_CLOCK_FILE=str(retained/"requester"/"clock"))
        self.original_clock = (retained/"requester"/"clock").read_bytes()
        self.requester.clock = retained/"requester"/"clock"
        self.requester.base = datetime.fromisoformat(self.original_clock.decode().replace("Z", "+00:00"))

    def prepare(self) -> None:
        a, b = self.owner, self.requester
        records = table_rows(b.host, "dec_pending", "request_id,record,secret")
        require(len(records) == 1 and records[0][2] is None, "retained requester is not one already-applied secret-retired operation")
        identifier, encoded, _ = records[0]
        pending = strict_output(encoded.encode())
        require(pending["terminal"] == "applied", "original requester application is not complete")
        activation_record = table_rows(b.host, "dec_operations", "record", " WHERE request_id=?", (identifier,))
        require(len(activation_record) == 1, "retained requester outcome is missing")
        record = strict_output(activation_record[0][0].encode())
        activation = strict_output(unb64(record["activation_base64"]))
        self.request = {**strict_output(unb64(activation["request"]["payload_base64"])), "request_id": identifier,
            "host_public_key": activation["request"]["writer_host_public_key"],
            "device_public_key": activation["request"]["signer_public_key"]}
        self.request_route = "/v2/link/requests/"+identifier
        descriptor = strict_output(unb64(pending["descriptor_base64"]))
        b.world.descriptor, b.world.context_id = descriptor, activation["context_id"]
        self.network = {"id": descriptor["network_id"], "context_id": activation["context_id"],
            "root_state_id": strict_output(unb64(activation["administrator"]["payload_base64"]))["root_state_id"]}
        for label, packet in (("owner", activation["owner"]), ("requester", activation["request"])):
            public = packet["writer_host_public_key"]
            endpoints = [item for item in pending["carrier_endpoints"] if item["kind"] == "participant" and item["public_key"] == public]
            require(len(endpoints) == 1, "original pinned participant listener is not unique")
            self.endpoints[label] = {key:endpoints[0][key] for key in ("address", "public_key")}
            instance = a if label == "owner" else b
            instance.identity = {"public_key": public}
            instance.host.run_arguments = ["--bootstrap-listen", endpoints[0]["address"]]
        for role in ("owner", "administrator", "owner_finalization"):
            packet = activation[role]; message = packet_message(packet)
            # Our original signer is reproducible fixture-owned Alice. Derive
            # the exact expected SSHSIG again; never trust a supplied signature.
            self.signatures[("dpk_"+sha(message), "authority")] = b64(self.keys.sshsig("alice", message))
        for entry in strict_output(unb64(record["catalog_base64"]))["objects"]:
            if entry["kind"] == "activation":
                continue
            statement = strict_output(unb64(entry["body_base64"])); identifier_ds = statement_id(statement)
            for signature in statement["signatures"]:
                if signature["format"] != "sshsig":
                    continue
                require(signature["public_key"] == self.keys.public("alice"), "retained fixture changed its original-person signer")
                message = lines("peerspan-decentralized-signature-v1", identifier_ds, signature["role"], signature["public_key"])
                self.signatures[(identifier_ds, signature["role"])] = b64(self.keys.sshsig("alice", message))
        self.requester_operation = self.operation(b)
        self.manifest = self.verify_complete(self.requester_operation, b.identity["public_key"])
        self.commit_terms = {"network_id": self.network["id"], "context_id": self.network["context_id"],
            "person_public_key": self.keys.public("alice"), "host_public_key": self.request["host_public_key"],
            "device_public_key": self.request["device_public_key"],
            **{name:self.manifest[name] for name in ("owner_offer_id", "selection_id", "administrator_offer_id", "owner_finalization_id")}}
        require(not table_rows(a.host, "dec_operations", "request_id", " WHERE request_id=?", (identifier,)),
                "retained failed approver already has an outcome")
        before = {label:all_database_snapshots(instance.host.state) for label,instance in (("owner", a), ("requester", b))}
        (self.root/"before-state-hashes.json").write_bytes(raw_json(before))
        # Start the receiver first. This does not create approval or signatures.
        for label, instance in (("owner", a), ("requester", b)):
            public = instance.identity["public_key"]
            instance.host.start(); instance.identity = instance.host.api("GET", "/v1/host")
            require(instance.identity["public_key"] == public, "restart replaced the original actual daemon host key")
        require(self.operation(b) == self.requester_operation, "replacement changed original applied requester outcome")
        value, _ = b.api("POST", self.request_route+"/resume", {})
        require(value["state"] == "linked" and value["activation_id"] == self.requester_operation[3] and
                self.operation(b) == self.requester_operation, "historical transport resume reapplied or changed original requester operation")
        time.sleep(2.05)

    def run(self) -> None:
        self.prepare()
        a, b = self.owner, self.requester
        def publish_participant() -> None:
            for _ in range(4):
                a.api("POST", self.request_route+"/resume", {})
                found = table_rows(a.host, "dec_operations", "request_id", " WHERE request_id=?", (self.request["request_id"],))
                if found: break
                time.sleep(2.05)
            self.owner_operation = self.operation(a)
            manifest = self.verify_complete(self.owner_operation, a.identity["public_key"])
            require(manifest == self.manifest and self.owner_operation[3:5] == self.requester_operation[3:5],
                    "actual owner participant received a different complete operation")
            members, _ = a.api("GET", "/v2/networks/"+self.network["id"]+"/members")
            target = [m for m in members["members"] if m["host_public_key"] == self.request["host_public_key"]]
            require(len(target) == 1 and target[0]["person_public_key"] == self.keys.public("alice") and
                    target[0]["binding_lease_id"] == self.manifest["binding_lease_id"] and
                    target[0]["device_lease_id"] == self.manifest["device_lease_id"], "real owner did not apply exact complete target membership")
            self.trace.append({"actual_owner_participant_local_apply_observed": True, "delivery_mechanism_not_inferred_from_requester_view": True})
        a.case("complete_link/actual_other_participant_applies_same_complete_operation", publish_participant)

        def historical_reopen() -> None:
            identities = {"owner": a.identity, "requester": b.identity}
            operations = {"owner": self.owner_operation, "requester": self.requester_operation}
            before = {label: authority_rows(instance) for label, instance in (("owner", a), ("requester", b))}
            for label, instance in (("owner", a), ("requester", b)):
                instance.host.stop(); instance.host.start()
                require(instance.host.api("GET", "/v1/host") == identities[label], "restart replaced actual host identity")
                resumed, _ = instance.api("POST", self.request_route+"/resume", {})
                require(set(resumed) == VIEW and resumed["state"] == "linked" and resumed["activation_id"] == self.requester_operation[3] and
                        self.operation(instance) == operations[label] and authority_rows(instance) == before[label],
                        "completed restart/retry changed original outcome, public authority or identity")
            retry, _ = b.api("POST", self.request_route+"/commit", dict(self.commit_terms, approve=True))
            require(retry["request"]["activation_id"] == self.requester_operation[3] and self.operation(b) == self.requester_operation and
                    authority_rows(b) == before["requester"], "exact committed retry reapplied or changed its historical outcome")
        a.case("complete_link/either_restart_and_exact_retry_preserve_original_local_outcomes", historical_reopen)

        def isolated() -> None:
            observer = ClientIdentity(self.keys, "complete-link-nonparticipant")
            for label in ("owner", "requester"):
                wire = CarrierWire(self.endpoints[label])
                response = wire.request(observer, "GET", "/v1/host")
                error = strict_output(response.body)
                require(response.status == 404 and error["code"] == "not_found", "bootstrap exposed owner-local host router")
                response = wire.request(observer, "GET", "/bootstrap/v1/operations/"+self.request["request_id"])
                error = strict_output(response.body)
                require(response.status == 403 and error["code"] == "forbidden", "nonparticipant retrieved a private local operation outcome")
        a.case("complete_link/bootstrap_router_and_participant_outcome_auth_remain_isolated", isolated)
        require((self.retained/"requester"/"clock").read_bytes() == self.original_clock, "continuation changed original DEC clock")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("owner", "requester", "retained-dir", "work-dir", "results"):
        parser.add_argument("--"+name, type=Path, required=True)
    args = parser.parse_args(); args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    keys = FixtureKeys(); suite = Continuation(args.owner.resolve(), args.requester.resolve(), args.retained_dir.resolve(), args.work_dir.resolve(), keys)
    failure = detail = None; started = time.monotonic()
    try: suite.run()
    except BaseException as error:
        failure, detail = type(error).__name__, str(error) if isinstance(error, CheckFailure) else "fixture/transport failure"
    finally:
        for instance in (suite.requester, suite.owner):
            try: instance.host.stop()
            except BaseException as error:
                failure = failure or type(error).__name__; suite.rows.append({"name":"cleanup","passed":False,"error_type":type(error).__name__})
        keys.close()
    result = {"contract_pin":"7c5a483aa01d87a5d3715bc8fef902f4839ba214", "implementation_source_read":False,
        "suite_sha256":sha(Path(__file__).read_bytes()),
        "support_sha256":{name:sha(Path(__file__).with_name(name).read_bytes()) for name in
            ("decentralized_complete_link.py","decentralized_owner_preview.py","decentralized_direct_carrier.py","decentralized_fixtures.py","decentralized_helper.py","decentralized_storage.py","decentralized_requester.py","decentralized_runtime.py","decentralized_vectors.py")},
        "owner":str(args.owner.resolve()),"owner_sha256":sha(args.owner.read_bytes()),
        "requester":str(args.requester.resolve()),"requester_sha256":sha(args.requester.read_bytes()),
        "retained_dir":str(args.retained_dir.resolve()),"rows":suite.rows,"trace":suite.trace,"failure":failure,"detail":detail,
        "seconds":round(time.monotonic()-started,3),"scope":"only failed other-participant application plus two previously unevaluated history/router cases on SAME stopped pair, no daemon host-key copies or first-four repeat; no malformed ACK/phase/installed claim",
        "passed":failure is None and len(suite.rows)==3 and all(row["passed"] for row in suite.rows)}
    args.results.parent.mkdir(parents=True,exist_ok=True);args.results.write_text(json.dumps(result,indent=2)+"\n")
    return 0 if result["passed"] else 1

if __name__=="__main__":raise SystemExit(main())
