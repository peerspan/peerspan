#!/usr/bin/env python3
"""Independent state-free DEC verifier cases from merged public contracts only.

Run with Python3.12.  --emit-dir creates public JSONL vectors/expectations and a
manifest.  --probe runs those same cases against --decentralized-verify; it does
not build, discover, or inspect the implementation.  No existing test modules
are imported.  Case names describe only the coverage actually authored here.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import selectors
import subprocess
import time
from dataclasses import dataclass

from decentralized_fixtures import (
    BEFORE, NOW, PIN, UNTIL, FixtureKeys, PublicObject, World, b64, changed,
    lines, raw_json, sha, unb64,
)


@dataclass
class Case:
    name: str
    request: dict | bytes
    expected: dict
    final_unterminated: bool = False


def request_bytes(request: dict | bytes) -> bytes:
    return request if isinstance(request, bytes) else raw_json(request)


def error(code: str, required_ids: list[str] | None = None) -> dict:
    return {"ok": False, "code": code, "required_ids": sorted(required_ids or [])}


def same_json(actual: object, expected: object) -> bool:
    """JSON number, boolean and null types are part of the public response."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(same_json(actual[k], v) for k, v in expected.items())
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(same_json(a, e) for a, e in zip(actual, expected))
    return actual == expected


def strict_output(line: bytes) -> dict:
    def object_pairs(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate response JSON key")
            result[key] = value
        return result
    def bad_constant(value: str) -> None:
        raise ValueError(f"non-JSON response constant {value}")
    result = json.loads(line, object_pairs_hook=object_pairs, parse_constant=bad_constant)
    if not isinstance(result, dict):
        raise ValueError("response is not an object")
    return result


def matches(case: Case, actual: dict) -> bool:
    if isinstance(case.request, dict) and case.request.get("kind") == "projection" and case.request.get("operation") != "read" and case.expected.get("ok"):
        # Only the outer catalog carrier may be serialized differently.  Every
        # original signed body/proof ID, ordering, prior field and value is exact.
        try:
            observed = copy.deepcopy(actual)
            encoded = observed["next_prior"]["catalog_base64"]
            decoded = unb64(encoded)
            if b64(decoded) != encoded:
                return False
            expected_catalog = strict_output(unb64(case.expected["next_prior"]["catalog_base64"]))
            if not same_json(strict_output(decoded), expected_catalog):
                return False
            observed["next_prior"]["catalog_base64"] = case.expected["next_prior"]["catalog_base64"]
            return same_json(observed, case.expected)
        except (KeyError, TypeError, ValueError):
            return False
    return same_json(actual, case.expected)


def statement_expected(obj: PublicObject) -> dict:
    body = json.loads(obj.body)
    return {"ok": True, "context_id": obj.context_id, "statement_kind": obj.kind,
            "statement_id": obj.statement_id, "proof_id": obj.proof_id,
            "payload_base64": b64(obj.payload),
            "signers": [{"role": s["role"], "public_key": s["public_key"], "signature_format": s["format"]}
                        for s in body["signatures"]]}


def descriptor_cases(w: World) -> list[Case]:
    result = []
    def add(name: str, value: bytes, expected: dict) -> None:
        result.append(Case("descriptor/" + name,
                           {"format": 1, "kind": "descriptor", "descriptor_base64": b64(value)}, expected))
    positive = {"ok": True, "context_id": w.context_id,
                "network_id": w.descriptor["network_id"],
                "genesis_root_public_key": w.keys.public("root")}
    add("valid", w.descriptor_bytes, positive)
    add("outer_json_alias", json.dumps(w.descriptor, indent=2, sort_keys=True).encode(), positive)
    for name, field, value in [
        ("wrong_protocol", "protocol", "peerspan-decentralized-v2"),
        ("wrong_network_id", "network_id", "net_" + "0" * 64),
        ("blank_name", "name", ""), ("untrimmed_name", "name", " Independent DEC"),
        ("control_in_name", "name", "Independent\nDEC"), ("name_129bytes", "name", "x" * 129),
        ("noncanonical_key", "genesis_root_public_key", w.keys.public("root").rstrip("=")),
        ("short_key", "genesis_root_public_key", b64(b"short")),
        ("boolean_format", "format", True), ("future_format", "format", 2),
    ]:
        add(name, raw_json(changed(w.descriptor, **{field: value})), error("invalid"))
    add("unknown_coordinator_field", raw_json(changed(w.descriptor, coordinator_address="unused:443")), error("invalid"))
    add("duplicate_field", w.descriptor_bytes[:-1] + b',"name":"Independent DEC"}', error("invalid"))
    add("invalid_utf8", b'{"name":"\xff"}', error("invalid"))
    add("null", b"null", error("invalid"))
    add("missing_field", raw_json({k: v for k, v in w.descriptor.items() if k != "protocol"}), error("invalid"))
    return result


def statement_cases(w: World) -> list[Case]:
    result = []
    def add(name: str, obj: PublicObject, expected: dict | None = None) -> None:
        result.append(Case("statement/" + name,
                           {"format": 1, "kind": "statement", "descriptor_base64": b64(w.descriptor_bytes),
                            "statement_base64": b64(obj.body)},
                           statement_expected(obj) if expected is None else expected))
    add("genesis", w.genesis)
    add("same_ds_exact_envelope_alias", w.alias(w.genesis))
    payload_alias = json.dumps(w.genesis_payload, indent=1, sort_keys=True).encode()
    add("payload_alias_has_distinct_ds", w.statement("root_state", payload_alias, [("issuer", "root", "ed25519")]))
    for kind in ["admin_lease", "person_lease", "host_lease"]:
        signers = [("issuer", "root", "ed25519")]
        if kind == "host_lease":
            signers.append(("host", "host-a", "ed25519"))
        add(kind, w.statement(kind, w.lease_payload(kind), signers))
    person = w.statement("person_lease", w.lease_payload("person_lease"), [("issuer", "root", "ed25519")])
    host = w.statement("host_lease", w.lease_payload("host_lease"),
                       [("issuer", "root", "ed25519"), ("host", "host-a", "ed25519")])
    binding_payload = w.lease_payload("binding_lease", parents=[
        {"role": "subject_person", "id": person.statement_id},
        {"role": "issuer_person", "id": person.statement_id},
        {"role": "subject_host", "id": host.statement_id}],
        issuer={"kind": "person", "person_public_key": w.keys.public("alice")})
    binding = w.statement("binding_lease", binding_payload,
                          [("issuer", "alice", "sshsig"), ("host", "host-a", "ed25519")])
    add("complete_original_binding_sshsig", binding)
    expired = w.lease_payload("person_lease", issued_at="2026-10-01T00:00:00Z",
                              not_before="2026-10-01T00:00:00Z", not_after="2026-10-02T00:00:00Z")
    add("expired_complete_evidence_decodes", w.statement("person_lease", expired, [("issuer", "root", "ed25519")]))
    max_payload = w.lease_payload("person_lease", sequence=2**64-1,
                                  predecessors=["ds_" + "a" * 64])
    add("full_u64_max_decoder_not_admission", w.statement("person_lease", max_payload, [("issuer", "root", "ed25519")]))
    for name, field, value in [
        ("negative_sequence", "sequence", -1), ("float_sequence", "sequence", 1.0),
        ("boolean_sequence", "sequence", True), ("overflow_sequence", "sequence", 2**64),
        ("zero_sequence", "sequence", 0), ("fractional_time", "issued_at", "2026-10-26T12:00:00.1Z"),
        ("offset_time", "issued_at", "2026-10-26T12:00:00+00:00"),
        ("invalid_day", "issued_at", "2026-02-30T12:00:00Z"),
        ("past_deadline", "not_after", BEFORE), ("unknown_field", "extra", True),
        ("eight_day_management", "not_after", "2026-11-03T12:00:00Z"),
    ]:
        obj = w.statement("person_lease", changed(w.lease_payload("person_lease"), **{field: value}),
                          [("issuer", "root", "ed25519")])
        add(name, obj, error("invalid"))
    for name, payload in [
        ("duplicate_payload_field", raw_json(w.genesis_payload)[:-1] + b',"epoch":0}'),
        ("invalid_utf8_payload", b'{"epoch":0,"bad":"\xff"}'),
        ("null_payload", b"null"),
    ]:
        add(name, w.statement("root_state", payload, [("issuer", "root", "ed25519")]), error("invalid"))
    envelope = json.loads(w.genesis.body)
    variants = []
    forged = copy.deepcopy(envelope)
    signature = bytearray(unb64(forged["signatures"][0]["signature"]))
    signature[0] ^= 1
    forged["signatures"][0]["signature"] = b64(signature)
    variants.append(("forged_signature", forged))
    duplicate = copy.deepcopy(envelope)
    duplicate["signatures"] *= 2
    variants.append(("duplicate_role", duplicate))
    variants.append(("missing_role", changed(envelope, signatures=[])))
    extra_role = copy.deepcopy(envelope)
    extra_role["signatures"][0]["role"] = "host"
    variants.append(("wrong_role", extra_role))
    variants.append(("unknown_envelope_field", changed(envelope, extra="-")))
    for name, value in variants:
        add(name, PublicObject(w.genesis.kind, w.context_id, w.genesis.payload, raw_json(value), w.genesis.statement_id), error("invalid"))
    draft = json.loads(binding.body)
    draft["signatures"] = [s for s in draft["signatures"] if s["role"] != "host"]
    add("missing_binding_host_consent", PublicObject(binding.kind, w.context_id, binding.payload,
                                                      raw_json(draft), binding.statement_id), error("invalid"))
    return result


def catalog_cases(w: World) -> list[Case]:
    result = []
    def add(name: str, catalog: bytes, expected: dict) -> None:
        result.append(Case("catalog/" + name,
                           {"format": 1, "kind": "catalog", "descriptor_base64": b64(w.descriptor_bytes),
                            "catalog_base64": b64(catalog)}, expected))
    def valid(objects: list[PublicObject]) -> dict:
        return {"ok": True, "context_id": w.context_id, "proof_ids": sorted(o.proof_id for o in objects)}
    add("empty_not_authority", w.catalog([]), valid([]))
    add("genesis", w.catalog([w.genesis]), valid([w.genesis]))
    alias = w.alias(w.genesis)
    add("two_exact_aliases_one_statement", w.catalog([w.genesis, alias]), valid([w.genesis, alias]))
    value = json.loads(w.catalog([w.genesis, alias]))
    add("unsorted_proofs", raw_json(changed(value, objects=list(reversed(value["objects"])))), error("invalid"))
    add("duplicate_proof_id", raw_json(changed(value, objects=[value["objects"][0]] * 2)), error("invalid"))
    entry = w.genesis.entry()
    add("wrong_proof_id", raw_json({"format": 1, "context_id": w.context_id,
                                   "objects": [changed(entry, id="dp_" + "0" * 64)]}), error("invalid"))
    add("wrong_kind", raw_json({"format": 1, "context_id": w.context_id,
                               "objects": [changed(entry, kind="person_lease")]}), error("invalid"))
    add("unknown_metadata", raw_json(changed(json.loads(w.catalog([])), admitted=True)), error("invalid"))
    add("wrong_context", raw_json(changed(json.loads(w.catalog([])), context_id="ctx_" + "0" * 64)), error("invalid"))
    ordinary_as_composite = changed(entry, kind="activation")
    add("ordinary_activation_lookalike", raw_json({"format": 1, "context_id": w.context_id,
                                                  "objects": [ordinary_as_composite]}), error("invalid"))
    return result


def statement_more_cases(w: World) -> list[Case]:
    result = []
    def add(name: str, obj: PublicObject, observation: dict | None = None) -> None:
        result.append(Case("statement_more/" + name, {"format": 1, "kind": "statement",
            "descriptor_base64": b64(w.descriptor_bytes), "statement_base64": b64(obj.body)},
            statement_expected(obj) if observation is None else observation))
    person = w.statement("person_lease", w.lease_payload("person_lease"), [("issuer", "root", "ed25519")])
    host = w.statement("host_lease", w.lease_payload("host_lease"),
                       [("issuer", "root", "ed25519"), ("host", "host-a", "ed25519")])
    admin = w.statement("admin_lease", w.lease_payload("admin_lease"), [("issuer", "root", "ed25519")])
    binding = w.statement("binding_lease", w.lease_payload("binding_lease",
        issuer={"kind": "person", "person_public_key": w.keys.public("alice")}, parents=[
            {"role": "issuer_person", "id": person.statement_id},
            {"role": "subject_person", "id": person.statement_id},
            {"role": "subject_host", "id": host.statement_id}]),
        [("issuer", "alice", "sshsig"), ("host", "host-a", "ed25519")])
    add("policy", w.access("policy", person_lease=person))
    add("group", w.access("group"))
    add("policy_one_second", w.access("policy", person_lease=person, not_after="2026-10-26T12:00:01Z"))
    transition_payload = {"epoch": 1, "predecessors": [w.genesis.statement_id], "resolves": [],
                          "migration_proposal_id": "-", "root_public_key": w.keys.public("next-root"),
                          "issued_at": NOW, "retained_statement_ids": []}
    transition = w.statement("root_state", transition_payload,
                             [("issuer", "root", "ed25519"), ("new_root", "next-root", "ed25519")])
    add("root_transition", transition)
    alternate = w.statement("root_state", changed(transition_payload, root_public_key=w.keys.public("other-root")),
                            [("issuer", "root", "ed25519"), ("new_root", "other-root", "ed25519")])
    branches = sorted([transition.statement_id, alternate.statement_id])
    resolver = w.statement("root_state", changed(transition_payload, epoch=2, predecessors=branches, resolves=branches,
        root_public_key=w.keys.public("resolved-root")),
        [("root_branch:" + transition.statement_id, "next-root", "ed25519"),
         ("root_branch:" + alternate.statement_id, "other-root", "ed25519"),
         ("new_root", "resolved-root", "ed25519")])
    add("all_branch_root_resolution", resolver)
    add("root_full_u64_decoder", w.statement("root_state", changed(transition_payload, epoch=2**64-1),
        [("issuer", "root", "ed25519"), ("new_root", "next-root", "ed25519")]))
    ssh_root = w.statement("root_state", w.genesis_payload, [("issuer", "root", "sshsig")])
    if ssh_root.statement_id != w.genesis.statement_id:
        raise RuntimeError("fixture root signature aliases changed semantic ID")
    add("sshsig_root_same_ds", ssh_root)
    restriction_payload = {"root_state_id": w.genesis.statement_id,
        "issuer": {"kind": "root", "person_public_key": "-"}, "parents": [], "issued_at": NOW,
        "target": {"statement_id": admin.statement_id, "person_public_key": w.keys.public("alice"),
                   "host_public_key": "-", "device_public_key": "-"}, "kept_statement_ids": [], "ratifies": "-"}
    add("admin_withdraw", w.statement("admin_withdraw", restriction_payload, [("issuer", "root", "ed25519")]))
    add("person_remove", w.restriction("person_remove"))
    add("host_revoke", w.restriction("host_revoke"))
    owner_restriction = changed(restriction_payload,
        issuer={"kind": "person", "person_public_key": w.keys.public("alice")},
        parents=[{"role": "issuer_person", "id": person.statement_id}])
    unbind = changed(owner_restriction, target={"statement_id": binding.statement_id,
        "person_public_key": w.keys.public("alice"), "host_public_key": w.keys.public("host-a"), "device_public_key": "-"})
    add("host_unbind", w.statement("host_unbind", unbind, [("issuer", "alice", "sshsig")]))
    revoke = changed(owner_restriction, target={"statement_id": "-", "person_public_key": w.keys.public("alice"),
                                               "host_public_key": "-", "device_public_key": w.keys.public("device-b")})
    add("device_revoke", w.statement("device_revoke", revoke, [("issuer", "alice", "sshsig")]))
    device_payload = w.lease_payload("device_lease", operation_id="link_" + "a" * 64,
        issuer={"kind": "person", "person_public_key": w.keys.public("alice")}, parents=[
            {"role": "issuer_person", "id": person.statement_id}, {"role": "subject_person", "id": person.statement_id},
            {"role": "subject_host", "id": host.statement_id}, {"role": "subject_binding", "id": binding.statement_id}])
    add("operation_bound_device_decoder_is_not_activation", w.statement("device_lease", device_payload,
        [("issuer", "alice", "sshsig")]))
    add("unbound_device_has_no_issuance_bypass", w.statement("device_lease", changed(device_payload, operation_id="-"),
        [("issuer", "alice", "sshsig")]), error("invalid"))
    for scopes in [0, 16]:
        bad = copy.deepcopy(device_payload);bad["subject"]["scopes"] = scopes
        add(f"device_invalid_scope_{scopes}", w.statement("device_lease", bad,
            [("issuer", "alice", "sshsig")]), error("invalid"))
    add("management_exact_seven_days", w.statement("person_lease",
        w.lease_payload("person_lease", not_after="2026-11-02T12:00:00Z"), [("issuer", "root", "ed25519")]))
    add("delayed_start_does_not_shift_ceiling", w.statement("person_lease",
        w.lease_payload("person_lease", not_before="2026-10-27T12:00:00Z", not_after="2026-11-03T12:00:00Z"),
        [("issuer", "root", "ed25519")]), error("invalid"))
    add("full_u64_high_half", w.statement("person_lease", w.lease_payload("person_lease", sequence=2**63,
        predecessors=[person.statement_id]), [("issuer", "root", "ed25519")]))
    for name, namespace, hash_algorithm in [("wrong_sshsig_namespace", b"not-peerspan", b"sha512"),
                                           ("wrong_sshsig_hash", b"peerspan-person-v1", b"sha256")]:
        value = json.loads(binding.body)
        signature = next(s for s in value["signatures"] if s["role"] == "issuer")
        message = lines("peerspan-decentralized-signature-v1", binding.statement_id, "issuer", w.keys.public("alice"))
        signature["signature"] = b64(w.keys.sshsig("alice", message, namespace=namespace, hash_algorithm=hash_algorithm))
        add(name, PublicObject(binding.kind, w.context_id, binding.payload, raw_json(value), binding.statement_id), error("invalid"))
    mismatched_host = w.statement("host_lease", w.lease_payload("host_lease"),
                                  [("issuer", "root", "ed25519"), ("host", "host-b", "ed25519")])
    add("valid_signature_wrong_host_subject", mismatched_host, error("invalid"))
    unknown = w.statement("person_lease", w.lease_payload("person_lease", parents=[{"role": "unlisted", "id": person.statement_id}]),
                          [("issuer", "root", "ed25519")])
    add("unknown_parent_role", unknown, error("invalid"))
    forged = json.loads(w.alias(w.genesis).body)
    raw_sig = bytearray(unb64(forged["signatures"][0]["signature"]));raw_sig[0] ^= 1
    forged["signatures"][0]["signature"] = b64(raw_sig)
    forged_obj = PublicObject("root_state", w.context_id, w.genesis.payload, raw_json(forged), w.genesis.statement_id)
    result.append(Case("statement_more/forged_unused_catalog_alias", {"format": 1, "kind": "catalog",
        "descriptor_base64": b64(w.descriptor_bytes), "catalog_base64": b64(w.catalog([w.genesis, forged_obj]))}, error("invalid")))
    result.append(Case("statement_more/raw_sshsig_root_alias_catalog", {"format": 1, "kind": "catalog",
        "descriptor_base64": b64(w.descriptor_bytes), "catalog_base64": b64(w.catalog([w.genesis, ssh_root]))},
        {"ok": True, "context_id": w.context_id, "proof_ids": sorted([w.genesis.proof_id, ssh_root.proof_id])}))
    return result


def clock_cases() -> list[Case]:
    result = []
    def add(name: str, now: str, guard: str, expected: dict) -> None:
        result.append(Case("clock/" + name,
                           {"format": 1, "kind": "clock", "now": now, "clock_guard": guard}, expected))
    def valid(now: str) -> dict:
        return {"ok": True, "decision_time": now, "next_guard": now}
    add("initial", NOW, "-", valid(NOW))
    add("equal", NOW, NOW, valid(NOW))
    add("forward", NOW, BEFORE, valid(NOW))
    add("rollback_299", "2026-10-26T11:55:01Z", NOW, valid(NOW))
    add("rollback_300_inclusive", "2026-10-26T11:55:00Z", NOW, valid(NOW))
    add("rollback_301", "2026-10-26T11:54:59Z", NOW, error("clock_rollback"))
    add("year_0001", "0001-01-01T00:00:00Z", "-", valid("0001-01-01T00:00:00Z"))
    add("year_9999", "9999-12-31T23:59:59Z", "-", valid("9999-12-31T23:59:59Z"))
    for name, bad in [("fraction", "2026-10-26T12:00:00.1Z"),
                      ("offset", "2026-10-26T12:00:00+00:00"), ("leap_second", "2026-10-26T12:00:60Z"),
                      ("year_zero", "0000-01-01T00:00:00Z"), ("invalid_day", "2026-02-30T12:00:00Z")]:
        add(name, bad, "-", error("invalid"))
    add("bad_guard", NOW, "broken", error("invalid"))
    return result


def carrier_cases(w: World) -> list[Case]:
    valid = {"format": 1, "kind": "clock", "now": NOW, "clock_guard": "-"}
    positive = {"ok": True, "decision_time": NOW, "next_guard": NOW}
    result = [Case("carrier/valid_before_invalid", valid, positive)]
    for name, request in [
        ("empty_line", b""), ("whitespace_line", b" \t "), ("invalid_utf8", b"\xff"),
        ("truncated_json", b"{"), ("two_json_values", b"{} {}"), ("array", b"[]"), ("null", b"null"),
        ("duplicate_key", raw_json(valid)[:-1] + b',"now":"2026-10-26T12:00:00Z"}'),
        ("boolean_format", raw_json(changed(valid, format=True))),
        ("float_format", raw_json(changed(valid, format=1.0))),
        ("unknown_kind", raw_json(changed(valid, kind="unknown"))),
        ("unknown_budget", raw_json(changed(valid, budget=2**64-1))),
        ("missing_guard", raw_json({k: v for k, v in valid.items() if k != "clock_guard"})),
    ]:
        result.append(Case("carrier/" + name, request, error("invalid")))
    result.append(Case("carrier/valid_after_invalid_lines", valid, positive))
    return result


def budget_cases(w: World) -> list[Case]:
    """Opt-in decoded boundaries; no lowered caller budget or oversized filler field."""
    result = []
    mib = 1024 * 1024
    def statement(name: str, obj: PublicObject, observation: dict) -> None:
        result.append(Case("budget/" + name, {"format": 1, "kind": "statement",
                           "descriptor_base64": b64(w.descriptor_bytes), "statement_base64": b64(obj.body)}, observation))
    payload = raw_json(w.genesis_payload)
    full_payload = payload + b" " * (256 * 1024 - len(payload))
    exact = w.statement("root_state", full_payload, [("issuer", "root", "ed25519")])
    statement("payload_exact_256KiB", exact, statement_expected(exact))
    excess = w.statement("root_state", full_payload + b" ", [("issuer", "root", "ed25519")])
    statement("payload_plus_one", excess, error("quota_exceeded"))
    exact_body = w.genesis.body + b" " * (mib - len(w.genesis.body))
    exact_object = PublicObject("root_state", w.context_id, w.genesis.payload, exact_body, w.genesis.statement_id)
    statement("statement_exact_1MiB", exact_object, statement_expected(exact_object))
    statement("statement_plus_one", PublicObject("root_state", w.context_id, w.genesis.payload,
                                                 exact_body + b" ", w.genesis.statement_id), error("quota_exceeded"))
    def catalog(name: str, data: bytes, objects: list[PublicObject] | None) -> None:
        observation = error("quota_exceeded") if objects is None else {
            "ok": True, "context_id": w.context_id, "proof_ids": sorted(o.proof_id for o in objects)}
        result.append(Case("budget/" + name, {"format": 1, "kind": "catalog",
                           "descriptor_base64": b64(w.descriptor_bytes), "catalog_base64": b64(data)}, observation))
    one = w.catalog([w.genesis])
    full_catalog = one + b" " * (16 * mib - len(one))
    catalog("catalog_exact_16MiB", full_catalog, [w.genesis])
    catalog("catalog_plus_one", full_catalog + b" ", None)
    aliases = [PublicObject("root_state", w.context_id, w.genesis.payload,
                            b" " * i + w.genesis.body + b" " * (mib-i-len(w.genesis.body)), w.genesis.statement_id)
               for i in range(8)]
    catalog("decoded_exact_8MiB", w.catalog(aliases), aliases)
    shorter = aliases[:-1] + [PublicObject("root_state", w.context_id, w.genesis.payload,
                           aliases[-1].body[:-(len(w.genesis.body)-1)], w.genesis.statement_id), w.genesis]
    if sum(len(o.body) for o in shorter) != 8 * mib + 1:
        raise RuntimeError("independent decoded boundary fixture has wrong size")
    catalog("decoded_plus_one", w.catalog(shorter), None)
    many = []
    for index in range(4097):
        prefix = bytes(32 if index & (1 << bit) else 9 for bit in range(13))
        many.append(PublicObject("root_state", w.context_id, w.genesis.payload,
                                 prefix + w.genesis.body, w.genesis.statement_id))
    catalog("objects_exact_4096", w.catalog(many[:4096]), many[:4096])
    catalog("objects_plus_one", w.catalog(many), None)
    return result


def carrier_limit_cases(w: World) -> list[Case]:
    valid = raw_json({"format": 1, "kind": "clock", "now": NOW, "clock_guard": "-"})
    positive = {"ok": True, "decision_time": NOW, "next_guard": NOW}
    exact = valid + b" " * (64 * 1024 * 1024 - 1 - len(valid))
    return [Case("carrier_limits/exact_64MiB_including_LF", exact, positive),
            Case("carrier_limits/plus_one_drains_line", exact + b" ", error("quota_exceeded")),
            Case("carrier_limits/valid_after_oversized", valid, positive)]


def carrier_final_cases(w: World) -> list[Case]:
    return [Case("carrier_final/unterminated_valid_input", {
        "format": 1, "kind": "clock", "now": NOW, "clock_guard": "-"},
        {"ok": True, "decision_time": NOW, "next_guard": NOW}, final_unterminated=True)]


GROUPS = {"descriptor": descriptor_cases, "statement": statement_cases, "catalog": catalog_cases,
          "statement_more": statement_more_cases, "carrier": carrier_cases, "budget": budget_cases,
          "carrier_limits": carrier_limit_cases, "carrier_final": carrier_final_cases}


class Probe:
    def __init__(self, path: str, stderr_path: Path, timeout: float):
        self.stderr = stderr_path.open("wb")
        self.process = subprocess.Popen([path, "--decentralized-verify"], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=self.stderr)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        os.set_blocking(self.process.stdin.fileno(), False)
        self.buffer = b""
        self.timeout = timeout

    def ask(self, request: dict | bytes, *, final_unterminated: bool = False) -> dict:
        frame = memoryview(request_bytes(request) + (b"" if final_unterminated else b"\n"))
        written = 0
        deadline = time.monotonic() + self.timeout
        self.selector.register(self.process.stdin, selectors.EVENT_WRITE)
        writing = True
        try:
            while written < len(frame) or b"\n" not in self.buffer:
                remaining = deadline - time.monotonic()
                ready = self.selector.select(max(0, remaining)) if remaining > 0 else []
                if not ready:
                    raise RuntimeError(f"probe request/response exceeded {self.timeout:g}s")
                for key, _ in ready:
                    if key.fileobj is self.process.stdin:
                        try:
                            written += os.write(self.process.stdin.fileno(), frame[written:written+65536])
                        except BlockingIOError:
                            continue
                        if written == len(frame):
                            self.selector.unregister(self.process.stdin)
                            writing = False
                            if final_unterminated:
                                self.process.stdin.close()
                    else:
                        chunk = os.read(self.process.stdout.fileno(), 65536)
                        if not chunk:
                            raise RuntimeError(f"probe exited before response (status {self.process.poll()})")
                        self.buffer += chunk
                        if len(self.buffer) > 64 * 1024 * 1024:
                            raise RuntimeError("probe output exceeded pinned64MiB carrier")
        finally:
            if writing:
                self.selector.unregister(self.process.stdin)
        line, self.buffer = self.buffer.split(b"\n", 1)
        return strict_output(line)

    def close(self) -> tuple[int, bool]:
        if not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.selector.close()
        self.stderr.close()
        extra_stdout = bool(self.buffer) or bool(self.process.stdout.read(1))
        self.process.stdout.close()
        return self.process.returncode, extra_stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", action="append", default=[], help="immutable verification binary; repeat for both implementations")
    parser.add_argument("--group", action="append", choices=[*GROUPS, "clock"])
    parser.add_argument("--emit-dir", type=Path)
    parser.add_argument("--results", type=Path)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--self-check", action="store_true", help="check only fixture crypto with installed OpenSSH")
    args = parser.parse_args()
    keys = FixtureKeys()
    try:
        if args.self_check:
            keys.self_check()
        w = World(keys)
        groups = args.group or [g for g in GROUPS if g not in {"budget", "carrier_limits", "carrier_final"}] + ["clock"]
        cases = []
        for group in groups:
            cases.extend(clock_cases() if group == "clock" else GROUPS[group](w))
        if any(c.final_unterminated for c in cases) and len(cases) != 1:
            parser.error("carrier_final is a separate one-stream case; select it alone")
        names = [c.name for c in cases]
        if len(names) != len(set(names)):
            raise RuntimeError("duplicate independent case name")
        manifest = {"contract_pin": PIN, "implementation_source_read": False,
                    "suite_sha256": sha(Path(__file__).read_bytes()),
                    "fixture_sha256": sha(Path(__file__).with_name("decentralized_fixtures.py").read_bytes()),
                    "groups": groups, "case_count": len(cases), "fixture_signatures": keys.signatures,
                    "cases": [{"name": c.name, "request_sha256": sha(request_bytes(c.request)),
                               "final_unterminated": c.final_unterminated} for c in cases]}
        if args.emit_dir:
            args.emit_dir.mkdir(parents=True, exist_ok=True)
            (args.emit_dir / "input.jsonl").write_bytes(b"".join(
                request_bytes(c.request) + (b"" if c.final_unterminated else b"\n") for c in cases))
            (args.emit_dir / "expected.jsonl").write_bytes(b"".join(raw_json(c.expected) + b"\n" for c in cases))
            (args.emit_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        runs = []
        for index, binary in enumerate(args.probe):
            log_dir = args.results.parent if args.results else (args.emit_dir or Path.cwd())
            log_dir.mkdir(parents=True, exist_ok=True)
            run = {"binary": str(Path(binary).resolve()), "binary_sha256": sha(Path(binary).read_bytes()),
                   "passed": 0, "failures": [], "observations": []}
            runs.append(run)
            client = Probe(binary, log_dir / f"probe-{index}.stderr.log", args.timeout)
            try:
                for case in cases:
                    try:
                        actual = client.ask(case.request, final_unterminated=case.final_unterminated)
                    except Exception as exc:
                        run["failures"].append({"name": case.name, "transport_error": str(exc)})
                        break
                    if not matches(case, actual):
                        run["failures"].append({"name": case.name, "expected": case.expected, "actual": actual})
                        print(f"FAIL {Path(binary).name} {case.name}", flush=True)
                    else:
                        run["passed"] += 1
                    run["observations"].append({"name": case.name, "response_sha256": sha(raw_json(actual))})
            finally:
                exit_code, extra_stdout = client.close()
                run["exit_code"] = exit_code
                if exit_code != 0 or extra_stdout:
                    run["failures"].append({"name": "carrier/clean_exit", "exit_code": exit_code,
                                            "extra_stdout": extra_stdout})
            print(f"{Path(binary).name}: {run['passed']}/{len(cases)} passed; {len(run['failures'])} failures", flush=True)
        receipt = {**manifest, "runs": runs}
        if args.results:
            args.results.write_text(json.dumps(receipt, indent=2) + "\n")
        if not args.probe:
            print(f"authored {len(cases)} public cases; fixture signatures {keys.signatures}; no product probe run")
        return int(any(run["failures"] for run in runs))
    finally:
        keys.close()


if __name__ == "__main__":
    raise SystemExit(main())
