#!/usr/bin/env python3
"""NEW inherited access floors after ordinary R1; public contract only.

Emit/freeze first. The separate exact-source probe must be explicitly offered
for this scope. This is neither implicit version generation nor M07 replay.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import time

from decentralized_fixtures import NOW, UNTIL, FixtureKeys, PublicObject, World, b64, changed, lines, raw_json, sha, unb64
from decentralized_migration_device_bans_pure import fixture as inherited_source_fixture
from decentralized_storage import CheckFailure, require
from decentralized_vectors import Probe, maximum, same_json, strict_output


SPEC = Path(__file__).with_name("decentralized_migration_root_floor_cases.json")
ROOT_TIME = "2026-10-26T12:00:01Z"
ACCESS_TIME = "2026-10-26T12:00:02Z"
GROUP = "rotation-floor"
GROUP_FLOOR = 2**53+7


def origin(w):
    # Reuse only the separately authored public signing/graph constructor.
    # No M07 case or oracle is run, and no actual runtime state/key is read.
    old, _ = inherited_source_fixture(w)
    original = strict_output(old.body)
    old_proposal = strict_output(unb64(original["proposal"]["payload_base64"]))
    snapshot = strict_output(unb64(original["source_state_base64"]))
    snapshot["access_maxima"].append({"kind":"group", "subject":GROUP, "version":GROUP_FLOOR, "message_hash":"-"})
    snapshot["access_maxima"].sort(key=lambda row:(row["kind"], row["subject"]))
    state = raw_json(snapshot)
    proposal = w.statement("migration_proposal", changed(old_proposal, source_state_sha256=sha(state)), [("issuer", "root", "ed25519")])
    r0 = w.statement("root_state", changed(w.genesis_payload, migration_proposal_id=proposal.statement_id), [("issuer", "root", "ed25519")])
    h0 = w.statement("host_lease", w.lease_payload("host_lease", root_state_id=r0.statement_id,
        operation_id=proposal.statement_id), [("issuer", "root", "ed25519"), ("host", "host-a", "ed25519")])
    people = {name:w.statement("person_lease", w.lease_payload("person_lease", person=name, root_state_id=r0.statement_id),
        [("issuer", "root", "ed25519")]) for name in ("alice", "carol")}
    prepared_old = strict_output(unb64(original["prepared_catalog_base64"]))
    old_copy = next(strict_output(unb64(row["body_base64"])) for row in prepared_old["objects"] if row["kind"] == "device_revoke")
    copied = w.statement("device_revoke", changed(strict_output(unb64(old_copy["payload_base64"])),
        root_state_id=r0.statement_id, parents=[{"role":"issuer_person", "id":people["carol"].statement_id}]),
        [("issuer", "carol", "sshsig")])
    prepared = w.catalog([proposal, r0, h0, *people.values(), copied])
    ack = w.statement("migration_ack", {"proposal_id":proposal.statement_id, "root_state_id":r0.statement_id,
        "prepared_catalog_sha256":sha(prepared), "host_public_key":w.keys.public("host-a"),
        "person_public_key":"-", "device_public_key":"-", "host_lease_id":h0.statement_id,
        "binding_lease_id":"-", "device_lease_id":"-", "activation_id":"-", "acknowledged_at":NOW}, [("host", "host-a", "ed25519")])
    commit = w.statement("migration_commit", {"proposal_id":proposal.statement_id, "root_state_id":r0.statement_id,
        "prepared_catalog_sha256":sha(prepared), "acknowledgment_ids":[ack.statement_id], "committed_at":NOW}, [("issuer", "root", "ed25519")])
    body = raw_json({"format":1, "proposal":strict_output(proposal.body), "source_catalog_base64":original["source_catalog_base64"],
        "source_state_base64":b64(state), "prepared_catalog_base64":b64(prepared),
        "acknowledgments":[strict_output(ack.body)], "commit":strict_output(commit.body)})
    migration = PublicObject("migration", w.context_id, b"", body, "")
    retained = sorted([h0.statement_id, *(person.statement_id for person in people.values())])
    r1 = w.statement("root_state", {"epoch":1, "predecessors":[r0.statement_id], "resolves":[],
        "migration_proposal_id":"-", "root_public_key":w.keys.public("next-root"), "issued_at":ROOT_TIME,
        "retained_statement_ids":retained}, [("issuer", "root", "ed25519"), ("new_root", "next-root", "ed25519")])
    floors = [{"stream":[row["kind"], row["subject"]], "sequence":row["version"], "statement_ids":[], "head_ids":[]}
        for row in snapshot["access_maxima"]]
    metadata = ([maximum(["root"], 1, [r1]), maximum(["host", w.keys.public("host-a")], 1, [h0])]+
        [maximum(["person", w.keys.public(name)], 1, [person]) for name, person in people.items()]+floors)
    prior = w.prior([migration, r1], metadata, root_ids=[r1.statement_id], clock_guard=ROOT_TIME,
        admitted_ids=[r0.statement_id, r1.statement_id, h0.statement_id, *(person.statement_id for person in people.values())],
        restrictions=[copied.statement_id])
    prior["migration_proposal_id"] = proposal.statement_id
    evidence = {"migration_entry":migration.entry(), "source_state_sha256":sha(state), "proposal_id":proposal.statement_id,
        "R0":r0.statement_id, "R1":r1.statement_id, "R1_migration_proposal_id":"-", "R1_actual_key":w.keys.public("next-root"),
        "retained_finite_ids":retained, "all_floors":floors, "Alice_person_lease_id":people["alice"].statement_id}
    return prior, r1, people["alice"], evidence


def cases(w, plan):
    prior, r1, person, evidence = origin(w)
    result = []
    for row in plan["matrix"]:
        kind, sequence = row["kind"], row["sequence"]
        if kind == "policy":
            candidate = w.access("policy", sequence=sequence, person_lease=person, root_state_id=r1.statement_id, issued_at=ACCESS_TIME)
            stream = ["policy", w.keys.public("alice")]
        else:
            body = {"network_id":w.descriptor["network_id"], "name":GROUP, "version":sequence, "defined_at":ACCESS_TIME,
                "members":["person_"+sha(unb64(w.keys.public("alice")))]}
            payload = {"root_state_id":r1.statement_id, "operation_id":"-", "sequence":sequence,
                "predecessors":[], "resolves":[], "issuer":{"kind":"root", "person_public_key":"-"}, "parents":[],
                "issued_at":ACCESS_TIME, "not_before":ACCESS_TIME, "not_after":UNTIL, "body_base64":b64(raw_json(body))}
            candidate = w.statement("group", payload, [("issuer", "next-root", "ed25519")]); stream = ["group", GROUP]
        result.append({"name":"root_successor_floor/"+kind+"/"+row["case"],
            "request":{"format":1, "kind":"projection", "descriptor_base64":b64(w.descriptor_bytes), "prior":prior,
                "candidate_catalog_base64":b64(w.catalog([candidate])), "now":ACCESS_TIME, "operation":"fresh"},
            "oracle":{"must_admit":row["must_admit"], "candidate_id":candidate.statement_id,
                "stream":stream, "candidate_sequence":sequence, "context_id":w.context_id, "evidence":evidence}})
    return result


def check(case, actual):
    expected = case["oracle"]; candidate = expected["candidate_id"]
    if actual.get("ok") is False:
        require(not expected["must_admit"], "complete floor+1 candidate was denied after ordinary R1")
        require(set(actual) == {"ok", "code", "required_ids"} and isinstance(actual["code"], str) and actual["code"] and
            actual["required_ids"] == sorted(set(actual["required_ids"])), "rejection is not the public structured pure error")
        return  # No exact global error category is invented for these denials.
    require(actual.get("ok") is True and actual["context_id"] == expected["context_id"], "projection omitted its actual authority observation")
    prior, evidence = actual["next_prior"], expected["evidence"]
    require(prior["root_head_ids"] == [evidence["R1"]] and actual["root"]["selected_id"] == evidence["R1"] and
        prior["migration_proposal_id"] == evidence["proposal_id"], "ordinary root successor lost exact current root or authenticated original origin")
    catalog = strict_output(unb64(prior["catalog_base64"]))
    require(evidence["migration_entry"] in catalog["objects"], "access projection rewrote/dropped original complete M/source proof bytes")
    maxima = {tuple(row["stream"]):row for row in prior["maxima"]}
    for original in evidence["all_floors"]:
        stream = tuple(original["stream"]); observed = maxima.get(stream)
        require(observed is not None, "ordinary R1 erased an inherited unrelated or target stream floor")
        positive_target = expected["must_admit"] and stream == tuple(expected["stream"])
        require(type(observed["sequence"]) is int and observed["sequence"] == (expected["candidate_sequence"] if positive_target else original["sequence"]),
            "ordinary R1/access lowered, rounded or reset an authenticated inherited floor")
        require(observed["statement_ids"] == observed["head_ids"] == ([candidate] if positive_target else []),
            "lower/equal candidate became a head, or first valid floor+1 did not become the exact sole head")
    target = [row for row in actual["streams"] if row["stream"] == expected["stream"]]
    if expected["must_admit"]:
        require(candidate in prior["admitted_statement_ids"] and len(target) == 1 and
            target[0]["selected_id"] == candidate and target[0]["head_ids"] == [candidate] and target[0]["active"] is True,
            "valid first floor+1 did not become current under its actual R1 issuer")
    else:
        require(candidate not in prior["admitted_statement_ids"] and all(row["selected_id"] != candidate and row["active"] is False for row in target),
            "lower/equal candidate gained admission or active authority after R1")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit-dir", type=Path)
    parser.add_argument("--probe", type=Path)
    parser.add_argument("--source")
    parser.add_argument("--frozen-manifest", type=Path)
    parser.add_argument("--results", type=Path)
    parser.add_argument("--case", action="append")
    args = parser.parse_args()
    if args.probe and not (args.source and args.frozen_manifest and args.results):
        parser.error("execution requires separately offered exact source, frozen manifest and results")
    keys = FixtureKeys()
    try:
        plan = strict_output(SPEC.read_bytes()); selected = cases(World(keys), plan)
        manifest = {"implementation_source_read":False, "suite_sha256":sha(Path(__file__).read_bytes()),
            "fixture_sha256":sha(Path(__file__).with_name("decentralized_fixtures.py").read_bytes()),
            "source_constructor_sha256":sha(Path(__file__).with_name("decentralized_migration_device_bans_pure.py").read_bytes()),
            "case_count":len(selected), "cases":[{"name":case["name"], "request_sha256":sha(raw_json(case["request"])),
                "oracle_sha256":sha(raw_json(case["oracle"]))} for case in selected],
            "scope":plan["scope"], "no_exact_negative_global_code_or_implicit_generation_claim":True}
        if args.emit_dir:
            args.emit_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
            (args.emit_dir/"input.jsonl").write_bytes(b"".join(raw_json(case["request"])+b"\n" for case in selected))
            (args.emit_dir/"oracles.jsonl").write_bytes(b"".join(raw_json(case["oracle"])+b"\n" for case in selected))
            (args.emit_dir/"manifest.json").write_text(json.dumps(manifest, indent=2)+"\n")
        if not args.probe:
            print("FROZEN "+str(len(selected))+" NEW root-successor floor inputs; no implementation executed")
            return 0
        require(same_json(strict_output(args.frozen_manifest.read_bytes()), manifest), "root-successor fixture/oracle changed after freeze")
        if args.case:
            require(set(args.case) <= {case["name"] for case in selected}, "unknown selected floor case")
            selected = [case for case in selected if case["name"] in args.case]
        args.results.parent.mkdir(parents=True, exist_ok=True); rows = []; failure = None
        client = Probe(str(args.probe), args.results.parent/"probe.stderr.log", 30); began = time.monotonic()
        try:
            for case in selected:
                actual = None
                try:
                    actual = client.ask(case["request"]); check(case, actual)
                except (CheckFailure, RuntimeError, KeyError, TypeError) as error:
                    failure = str(error); rows.append({"name":case["name"], "passed":False, "detail":failure,
                        **({"actual":actual} if actual is not None else {})}); break
                rows.append({"name":case["name"], "passed":True, "response_sha256":sha(raw_json(actual))})
        finally: exit_code, extra_stdout = client.close()
        value = {"source":args.source, "artifact":{"path":str(args.probe.resolve()), "sha256":sha(args.probe.read_bytes())},
            "manifest_sha256":sha(args.frozen_manifest.read_bytes()), "implementation_source_read":False, "rows":rows,
            "failure":failure, "exit_code":exit_code, "extra_stdout":extra_stdout, "seconds":round(time.monotonic()-began, 3),
            "scope":plan["scope"], "passed":failure is None and len(rows) == len(selected) and exit_code == 0 and not extra_stdout}
        args.results.write_text(json.dumps(value, indent=2)+"\n")
        print(str(sum(row["passed"] for row in rows))+"/"+str(len(selected))+" NEW inherited root-successor floor cases passed")
        return 0 if value["passed"] else 1
    finally: keys.close()


if __name__ == "__main__": raise SystemExit(main())
