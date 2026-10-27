#!/usr/bin/env python3
"""Three NEW M07 pure companions; public contracts and fixture-owned keys only.

Emit/freeze before probing. These synthetic high-u64 inputs make no claim that
runtime writers produced those values, and are not root-successor floor tests.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import time

from decentralized_fixtures import BEFORE, NOW, UNTIL, FixtureKeys, PublicObject, World, b64, changed, lines, raw_json, sha, unb64
from decentralized_storage import CheckFailure, require
from decentralized_vectors import Probe, error, same_json, strict_output


PIN = "802d16b8b129e510590ac2cca45bb7ab8abed251"
DIAGNOSTIC_PIN = "dada7fcedc4a215f79a78e08f2bedfa14e374931"
SPEC = Path(__file__).with_name("decentralized_migration_device_bans_cases.json")
PROJECT_FIELDS = set("ok context_id decision_time root streams restrictions inert_statement_ids next_prior".split())
PRIOR_FIELDS = set("format context_id catalog_base64 admitted_statement_ids admitted_restriction_ids admitted_activation_ids root_head_ids maxima migration_proposal_id clock_guard".split())


@dataclass
class Companion:
    name: str
    request: dict
    oracle: dict
    provenance: dict


def fixture(w: World, *, missing_original=False, copy_ban=True):
    """One unbound host, two admitted hostless people and an original-only ban.

    The group maximum has no surviving body/hash: it models the expressly
    allowed endorsed durable floor. Both policy maxima have exact independent
    original signatures, and their integer values cross the double boundary.
    """
    base = w.unbound_migration(nonce_name="new-M07-pure-companions")
    network = w.descriptor["network_id"]
    source = strict_output(base.source_catalog)
    records = []

    def legacy(kind, body, message, key, raw=False):
        value = dict(body, signature=b64(w.keys.sign(key, message) if raw else w.keys.sshsig(key, message)))
        encoded = raw_json(value)
        entry = {"id":"pf_"+sha(lines("peerspan-link-proof-v1", kind, sha(encoded))), "kind":kind, "body_base64":b64(encoded)}
        records.append(entry)
        return entry

    for person in ("alice", "carol"):
        public = w.keys.public(person)
        legacy("person_admission", {"network_id":network, "epoch":0, "person_public_key":public,
            "member":person.capitalize(), "admitted_at":BEFORE},
            lines("peerspan-person-admit-v1", network, 0, public, person.capitalize(), BEFORE), "root", raw=True)

    person, host, device = w.keys.public("carol"), w.keys.public("host-a"), w.keys.public("M07-retired-target")
    request = "link_"+sha(lines("peerspan-link-request-id-v1", w.keys.public("legacy-coordinator"), host, device,
        b64(bytes.fromhex(sha(b"new-M07-public-pending-target-nonce")))))
    certificate_message = lines("peerspan-device-certificate-v1", network, person, device, host, "root", 7, BEFORE, UNTIL, request)
    certificate_id = "dc_"+sha(certificate_message)
    certificate = legacy("certificate", {"format":1, "network_id":network, "person_public_key":person,
        "device_public_key":device, "host_public_key":host, "parent_id":"root", "scopes":7,
        "issued_at":BEFORE, "not_after":UNTIL, "request_id":request}, certificate_message, "carol")
    revocation = legacy("device_revocation", {"format":1, "network_id":network, "person_public_key":person,
        "target_device_public_key":device, "target_certificate_id":certificate_id,
        "issuer_certificate_id":"root", "revoked_at":BEFORE},
        lines("peerspan-device-revoke-v1", network, person, device, certificate_id, "root", BEFORE), "carol")

    floors = [{"kind":"group", "subject":"m07-history", "version":2**64-1, "message_hash":"-"}]
    for name, version in (("alice", 2**53+1), ("carol", 2**64-1)):
        public = w.keys.public(name)
        message = lines("peerspan-policy-v1", network, public, version, BEFORE, UNTIL)
        legacy("policy", {"network_id":network, "person_public_key":public, "version":version,
            "issued_at":BEFORE, "valid_until":UNTIL, "rules":[]}, message, name)
        floors.append({"kind":"policy", "subject":public, "version":version, "message_hash":sha(message)})
    floors.sort(key=lambda row:(row["kind"], row["subject"]))
    source["objects"] += [row for row in records if not (missing_original and row["id"] == revocation["id"])]
    source["objects"].sort(key=lambda row:row["id"])
    source_catalog = raw_json(source)
    source_state = raw_json({"format":1, "network_id":network, "legacy_root_highwater":0,
        "known_admitted_hosts":[host], "access_maxima":floors,
        "admitted_restrictions":[{"proof_id":revocation["id"], "kind":"device_revocation",
            "person_public_key":person, "host_public_key":"-", "device_public_key":device}]})
    proposal = w.statement("migration_proposal", changed(strict_output(base.proposal.payload),
        source_catalog_sha256=sha(source_catalog), source_state_sha256=sha(source_state)), [("issuer", "root", "ed25519")])
    root = w.statement("root_state", changed(w.genesis_payload, migration_proposal_id=proposal.statement_id), [("issuer", "root", "ed25519")])
    host_lease = w.statement("host_lease", w.lease_payload("host_lease", root_state_id=root.statement_id,
        operation_id=proposal.statement_id), [("issuer", "root", "ed25519"), ("host", "host-a", "ed25519")])
    people = {name:w.statement("person_lease", w.lease_payload("person_lease", person=name, root_state_id=root.statement_id),
        [("issuer", "root", "ed25519")]) for name in ("alice", "carol")}
    copied = w.statement("device_revoke", {"root_state_id":root.statement_id,
        "issuer":{"kind":"person", "person_public_key":person},
        "parents":[{"role":"issuer_person", "id":people["carol"].statement_id}], "issued_at":NOW,
        "target":{"statement_id":"-", "person_public_key":person, "host_public_key":"-", "device_public_key":device},
        "kept_statement_ids":[], "ratifies":"-"}, [("issuer", "carol", "sshsig")])
    prepared = w.catalog([proposal, root, host_lease, *people.values()]+([copied] if copy_ban else []))
    acknowledgment = w.statement("migration_ack", {"proposal_id":proposal.statement_id, "root_state_id":root.statement_id,
        "prepared_catalog_sha256":sha(prepared), "host_public_key":host, "person_public_key":"-", "device_public_key":"-",
        "host_lease_id":host_lease.statement_id, "binding_lease_id":"-", "device_lease_id":"-", "activation_id":"-",
        "acknowledged_at":NOW}, [("host", "host-a", "ed25519")])
    commit = w.statement("migration_commit", {"proposal_id":proposal.statement_id, "root_state_id":root.statement_id,
        "prepared_catalog_sha256":sha(prepared), "acknowledgment_ids":[acknowledgment.statement_id], "committed_at":NOW},
        [("issuer", "root", "ed25519")])
    body = raw_json({"format":1, "proposal":strict_output(proposal.body), "source_catalog_base64":b64(source_catalog),
        "source_state_base64":b64(source_state), "prepared_catalog_base64":b64(prepared),
        "acknowledgments":[strict_output(acknowledgment.body)], "commit":strict_output(commit.body)})
    proof = PublicObject("migration", w.context_id, b"", body, "")
    require(all(type(row["version"]) is int and 0 < row["version"] <= 2**64-1 for row in strict_output(source_state)["access_maxima"]),
        "independent source snapshot lost full-u64 integer type")
    provenance = {"proposal_id":proposal.statement_id, "root_state_id":root.statement_id,
        "source_catalog_sha256":sha(source_catalog), "source_state_sha256":sha(source_state),
        "prepared_catalog_sha256":sha(prepared), "migration_proof_id":proof.proof_id,
        "target_certificate_id":certificate_id, "target_certificate_proof_id":certificate["id"],
        "original_device_revocation_proof_id":revocation["id"], "copied_statement_id":copied.statement_id,
        "all_subject_floors":floors, "missing_exact_original":missing_original, "copy_present":copy_ban,
        "unbound_roster_only":True, "no_runtime_writer_or_physical_custody_claim":True}
    return proof, provenance


def cases(w: World):
    proof, facts = fixture(w)
    projection = {"format":1, "kind":"projection", "descriptor_base64":b64(w.descriptor_bytes), "prior":"-",
        "candidate_catalog_base64":b64(w.catalog([proof])), "now":NOW, "operation":"repair"}
    expected = {"assertion":"authenticated_all_subject_floors", "context_id":w.context_id, "decision_time":NOW,
        "proposal_id":facts["proposal_id"], "root_state_id":facts["root_state_id"],
        "original_migration_entry":proof.entry(), "floors":facts["all_subject_floors"],
        "required_copied_restriction_id":facts["copied_statement_id"]}
    result = [Companion("M07_source_full_u64_floors_and_all_subjects_survive_inherited_device_copies", projection, expected, facts)]
    for missing, copied, name, code in ((True, True, "M07_complete_source_missing_exact_inherited_device_proof_requires_that_proof", "proof_required"),
            (False, False, "M07_complete_source_and_prepared_bytes_omitting_required_device_copy_are_forbidden", "forbidden")):
        proof, facts = fixture(w, missing_original=missing, copy_ban=copied)
        result.append(Companion(name, {"format":1, "kind":"migration", "descriptor_base64":b64(w.descriptor_bytes),
            "legacy_prior":"-", "prior":"-", "migration_base64":b64(proof.body), "now":NOW, "purpose":"evidence",
            "local_host_public_key":"-"}, error(code, [facts["original_device_revocation_proof_id"]] if missing else []), facts))
    return result


def check(case, actual):
    oracle = case.oracle
    if oracle.get("assertion") != "authenticated_all_subject_floors":
        require(same_json(actual, oracle), "complete-M exact category/repair ID differs")
        return
    require(set(actual) == PROJECT_FIELDS and actual["ok"] is True and actual["context_id"] == oracle["context_id"] and
        actual["decision_time"] == oracle["decision_time"], "complete-M floor projection failed or changed its public carrier")
    prior = actual["next_prior"]
    require(set(prior) == PRIOR_FIELDS and prior["format"] == 1 and prior["context_id"] == oracle["context_id"] and
        prior["migration_proposal_id"] == oracle["proposal_id"] and prior["clock_guard"] == oracle["decision_time"],
        "inherited floors lost complete origin/context or actual clock")
    catalog = strict_output(unb64(prior["catalog_base64"]))
    require(set(catalog) == {"format", "context_id", "objects"} and catalog["format"] == 1 and
        catalog["context_id"] == oracle["context_id"] and catalog["objects"] == [oracle["original_migration_entry"]],
        "projection rewrote original M/source bytes or invented nested standalone proof objects")
    require(prior["root_head_ids"] == [oracle["root_state_id"]] and actual["root"]["head_ids"] == prior["root_head_ids"] and
        actual["root"]["selected_id"] == oracle["root_state_id"] and type(actual["root"]["maximum"]) is int and actual["root"]["maximum"] == 0,
        "floor projection lost actual authenticated migrated root")
    maxima = prior["maxima"]
    require(all(set(row) == {"stream", "sequence", "statement_ids", "head_ids"} for row in maxima) and
        [row["stream"] for row in maxima] == [list(stream) for stream in sorted({tuple(row["stream"]) for row in maxima})],
        "projection maxima are malformed, duplicated or not in exact stream order")
    observed = {tuple(row["stream"]):row for row in maxima if row["stream"][0] in {"policy", "group"}}
    wanted = {(row["kind"], row["subject"]):row["version"] for row in oracle["floors"]}
    require(set(observed) == set(wanted), "projection filtered an unrelated source floor or invented another access floor")
    for stream, version in wanted.items():
        row = observed[stream]
        require(type(row["sequence"]) is int and row["sequence"] == version and row["statement_ids"] == row["head_ids"] == [],
            "source floor was rounded, reset, lowered or made into a fabricated active new-context head")
    for row in actual["streams"]:
        if tuple(row["stream"]) in wanted:
            require(row["selected_id"] == "-" and row["head_ids"] == [] and row["active"] is False,
                "headless source floor supplied an active access body")
    require(oracle["required_copied_restriction_id"] in actual["restrictions"] and
        oracle["required_copied_restriction_id"] in prior["admitted_restriction_ids"], "complete M lost required original-person ban copy")


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
        parser.error("probe execution requires exact source, existing frozen manifest and results")
    keys = FixtureKeys()
    try:
        world = World(keys); selected = cases(world)
        manifest = {"contract_pin":PIN, "diagnostic_pin":DIAGNOSTIC_PIN, "implementation_source_read":False,
            "suite_sha256":sha(Path(__file__).read_bytes()), "fixture_sha256":sha(Path(__file__).with_name("decentralized_fixtures.py").read_bytes()),
            "case_count":len(selected), "cases":[{"name":case.name, "request_sha256":sha(raw_json(case.request)),
                "oracle_sha256":sha(raw_json(case.oracle)), "public_provenance":case.provenance} for case in selected],
            "scope":"new M07 current-root pure inputs only; no runtime high-u64, root-successor/generation, physical-custody or adoption-controller claim",
            "bounded_floor_oracle":"Exact all-subject next_prior floors/empty new-head IDs/original M+source bytes; no unspecified headless-floor display category asserted."}
        if args.emit_dir:
            args.emit_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
            (args.emit_dir/"input.jsonl").write_bytes(b"".join(raw_json(case.request)+b"\n" for case in selected))
            (args.emit_dir/"oracles.jsonl").write_bytes(b"".join(raw_json(case.oracle)+b"\n" for case in selected))
            (args.emit_dir/"manifest.json").write_text(json.dumps(manifest, indent=2)+"\n")
        if not args.probe:
            print("FROZEN "+str(len(selected))+" NEW M07 pure inputs; no implementation executed")
            return 0
        require(same_json(strict_output(args.frozen_manifest.read_bytes()), manifest), "generated pure inputs/oracles changed after freeze")
        if args.case:
            require(set(args.case) <= {case.name for case in selected}, "unknown selected M07 companion")
            selected = [case for case in selected if case.name in args.case]
        args.results.parent.mkdir(parents=True, exist_ok=True)
        client = Probe(str(args.probe), args.results.parent/"probe.stderr.log", 30)
        rows = []; failure = None; began = time.monotonic()
        try:
            for case in selected:
                start = time.monotonic()
                try: actual = client.ask(case.request)
                except Exception as error:
                    failure = "probe transport: "+str(error)
                    rows.append({"name":case.name, "passed":False, "error_type":type(error).__name__, "detail":failure}); break
                try: check(case, actual)
                except (CheckFailure, KeyError, TypeError) as error:
                    rows.append({"name":case.name, "passed":False, "error_type":type(error).__name__, "detail":str(error), "actual":actual}); failure = str(error); break
                rows.append({"name":case.name, "passed":True, "response_sha256":sha(raw_json(actual)), "seconds":round(time.monotonic()-start, 3)})
        finally:
            exit_code, extra_stdout = client.close()
        value = {"contract_pin":PIN, "source":args.source, "artifact":{"path":str(args.probe.resolve()), "sha256":sha(args.probe.read_bytes())},
            "manifest_sha256":sha(args.frozen_manifest.read_bytes()), "implementation_source_read":False,
            "rows":rows, "failure":failure, "exit_code":exit_code, "extra_stdout":extra_stdout,
            "seconds":round(time.monotonic()-began, 3), "scope":manifest["scope"],
            "passed":failure is None and len(rows) == len(selected) and exit_code == 0 and not extra_stdout}
        args.results.write_text(json.dumps(value, indent=2)+"\n")
        print(str(sum(row["passed"] for row in rows))+"/"+str(len(selected))+" NEW M07 pure companions passed")
        return 0 if value["passed"] else 1
    finally: keys.close()


if __name__ == "__main__": raise SystemExit(main())
