#!/usr/bin/env python3
"""Complete literal proof closure never grants an unrelated new issuer power.

The security observation intentionally permits denial of Alice's finite B2.
It requires Bob's policy to remain unadmitted/inert with no policy stream,
even if every Bob body is present in Alice's signed manifest closure. It does
not generalize the public root-rotation exception to finite binding validity.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from decentralized_fixtures import FixtureKeys, NOW, World, b64, raw_json, sha, unb64, PublicObject
from decentralized_vectors import (Probe, activation_observation, known_simple_prior,
                                   matches, Case, same_json, unique_objects)


PIN = "fe79e59ff79d51cb0d6abec9d77c5f9b2496ce1c"


def fixtures(w: World) -> tuple[Case, dict, dict]:
    person = w.statement("person_lease", w.lease_payload("person_lease"), [("issuer", "root", "ed25519")])
    host = w.statement("host_lease", w.lease_payload("host_lease", host="host-b"),
        [("issuer", "root", "ed25519"), ("host", "host-b", "ed25519")])
    binding = w.statement("binding_lease", w.lease_payload("binding_lease", host="host-b",
        issuer={"kind": "person", "person_public_key": w.keys.public("alice")}, parents=[
            {"role": "issuer_person", "id": person.statement_id},
            {"role": "subject_person", "id": person.statement_id},
            {"role": "subject_host", "id": host.statement_id}]),
        [("issuer", "alice", "sshsig"), ("host", "host-b", "ed25519")])
    control = w.original_link(current_host=host, binding_predecessor=binding)
    source, prior = known_simple_prior(w, control.source_objects)
    expected, bounds = activation_observation(w, control)
    positive = Case("retention_isolation/complete_alice_binding_successor_without_unrelated_list", {
        "format": 1, "kind": "activation", "descriptor_base64": b64(w.descriptor_bytes), "prior": prior,
        "catalog_base64": b64(w.catalog(unique_objects(control.source_objects+control.new_objects))),
        "activation_base64": b64(control.body), "now": NOW, "expected": control.expected}, expected, array_bounds=bounds)
    bob = w.statement("person_lease", w.lease_payload("person_lease", person="bob"), [("issuer", "root", "ed25519")])
    policy = w.access("policy", person="bob", person_lease=bob)
    linked = w.original_link(current_host=host, binding_predecessor=binding, binding_retained=[bob, policy])
    objects = unique_objects(linked.source_objects+linked.new_objects+[
        PublicObject("activation", w.context_id, b"", linked.body, "")])
    request = {"format": 1, "kind": "projection", "descriptor_base64": b64(w.descriptor_bytes), "prior": prior,
        "candidate_catalog_base64": b64(w.catalog(objects)), "now": NOW, "operation": "fresh"}
    constraints = {"policy_id": policy.statement_id, "policy_stream": ["policy", w.keys.public("bob")],
        "context_id": w.context_id, "decision_time": NOW,
        "retained_ids": sorted([bob.statement_id, policy.statement_id]),
        "signed_manifest_ancestor_ids": json.loads(linked.manifest)["ancestor_statement_ids"],
        "allowed_finite_binding_denial": True,
        "scope": "Bob policy cannot be admitted through Alice's unrelated signed literal references; Bob's independently root-issued P may follow normal cold admission"}
    if not set(constraints["retained_ids"]) <= set(constraints["signed_manifest_ancestor_ids"]):
        raise RuntimeError("isolation fixture omitted signed literal retention closure")
    return positive, request, constraints


def isolated(actual: dict, request: dict, constraint: dict) -> bool:
    if actual.get("ok") is False:
        # This case asserts no authority/admission on refusal. Exact finite-B2
        # acceptance/error category is not a settled positive in this case.
        return (set(actual) == {"ok", "code", "required_ids"} and isinstance(actual["code"], str) and
                actual["code"] in {"invalid", "forbidden", "proof_required", "state_conflict", "operation_conflict",
                    "quota_exceeded", "authority_would_be_invalidated", "device_revoked", "authority_expired",
                    "not_yet_valid", "expired", "clock_rollback"} and
                isinstance(actual["required_ids"], list) and all(isinstance(v, str) for v in actual["required_ids"]) and
                actual["required_ids"] == sorted(set(actual["required_ids"])))
    if actual.get("ok") is not True or set(actual) != {"ok", "context_id", "decision_time", "root", "streams",
                                                    "restrictions", "inert_statement_ids", "next_prior"}:
        return False
    try:
        prior = actual["next_prior"]
        target, stream = constraint["policy_id"], constraint["policy_stream"]
        before = request["prior"]
        if (actual["context_id"] != constraint["context_id"] or actual["decision_time"] != NOW or
            target not in actual["inert_statement_ids"] or target in prior["admitted_statement_ids"] or
            any(row["stream"] == stream for row in actual["streams"]+prior["maxima"]) or
            not set(before["admitted_statement_ids"]) <= set(prior["admitted_statement_ids"]) or
            prior["migration_proposal_id"] != before["migration_proposal_id"] or prior["clock_guard"] != NOW):
            return False
        # Whole proof bytes remain retained. Do not silently erase the Bob
        # policy to make nonadmission appear to pass.
        expected = {}
        for encoded in (before["catalog_base64"], request["candidate_catalog_base64"]):
            for entry in json.loads(unb64(encoded))["objects"]:
                expected[entry["id"]] = entry
        catalog = json.loads(unb64(prior["catalog_base64"]))
        return same_json(catalog, {"format": 1, "context_id": constraint["context_id"],
                                  "objects": [expected[k] for k in sorted(expected)]})
    except (KeyError, TypeError, ValueError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", action="append", required=True)
    parser.add_argument("--emit-dir", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()
    args.emit_dir.mkdir(parents=True, exist_ok=False)
    args.results.parent.mkdir(parents=True, exist_ok=True)
    keys = FixtureKeys()
    try:
        w = World(keys); positive, request, constraints = fixtures(w)
        (args.emit_dir/"input.jsonl").write_bytes(raw_json(positive.request)+b"\n"+raw_json(request)+b"\n")
        (args.emit_dir/"constraints.json").write_text(json.dumps(constraints, indent=2)+"\n")
        runs = []
        for index, binary in enumerate(args.probe):
            client = Probe(binary, args.results.parent/f"probe-{index}.stderr.log", 30)
            run = {"binary": str(Path(binary).resolve()), "binary_sha256": sha(Path(binary).read_bytes()), "rows": []}
            runs.append(run)
            try:
                actual = client.ask(positive.request)
                run["rows"].append({"name": positive.name, "passed": matches(positive, actual), "actual": actual})
                actual = client.ask(request)
                run["rows"].append({"name": "retention_isolation/unrelated_bob_policy_stays_unadmitted", "passed": isolated(actual, request, constraints), "actual": actual})
            finally:
                run["exit_code"], run["extra_stdout"] = client.close()
            print(Path(binary).name+": "+str(sum(row["passed"] for row in run["rows"]))+"/2 passed", flush=True)
        result = {"contract_pin": PIN, "implementation_source_read": False, "fixture_sha256": sha(Path(__file__).with_name("decentralized_fixtures.py").read_bytes()),
            "suite_sha256": sha(Path(__file__).read_bytes()), "constraints": constraints, "runs": runs,
            "passed": all(r["exit_code"] == 0 and not r["extra_stdout"] and all(x["passed"] for x in r["rows"]) for r in runs)}
        args.results.write_text(json.dumps(result, indent=2)+"\n")
        return 0 if result["passed"] else 1
    finally:
        keys.close()


if __name__ == "__main__":
    raise SystemExit(main())
