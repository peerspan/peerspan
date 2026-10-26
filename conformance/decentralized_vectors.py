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
    array_bounds: dict[str, tuple[list[str], list[str]]] | None = None
    oracle_pin: str | None = None


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
    if case.array_bounds is not None:
        # Complete activation returns conservative verified source subsets.  It
        # must include every required dependency without inventing an ID or
        # imposing a preferred alias/minimal closure absent from the contract.
        try:
            observed = copy.deepcopy(actual)
            for field, (required, permitted) in case.array_bounds.items():
                values = observed[field]
                if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                    return False
                if values != sorted(set(values)) or not set(required) <= set(values) <= set(permitted):
                    return False
                observed[field] = case.expected[field]
            return same_json(observed, case.expected)
        except (KeyError, TypeError, ValueError):
            return False
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


def maximum(stream: list[str], sequence: int, objects: list[PublicObject], *, heads: list[PublicObject | str] | None = None) -> dict:
    return {"stream": stream, "sequence": sequence,
            "statement_ids": sorted({obj.statement_id for obj in objects}),
            "head_ids": sorted({obj if isinstance(obj, str) else obj.statement_id for obj in
                                (objects if heads is None else heads)})}


def stream_row(stream: list[str], sequence: int, heads: list[PublicObject | str], *,
               code: str = "-", required: list[str] | None = None,
               selected: str | None = None) -> dict:
    ids = sorted({h if isinstance(h, str) else h.statement_id for h in heads})
    selected_id = (ids[0] if len(ids) == 1 else "-") if selected is None else selected
    return {"stream": stream, "head_ids": ids, "maximum": sequence,
            "selected_id": selected_id, "active": code == "-", "code": code,
            "required_ids": sorted(required or [])}


def projection_cases(w: World) -> list[Case]:
    result = []
    root_max = maximum(["root"], 0, [w.genesis])
    root_row = {"head_ids": [w.genesis.statement_id], "maximum": 0,
                "selected_id": w.genesis.statement_id, "conflicted": False, "code": "-", "required_ids": []}
    root_prior = w.prior([w.genesis], [root_max])
    def expected(next_prior: dict, streams: list[dict], *, now: str = NOW,
                 restrictions: list[str] | None = None, inert: list[str] | None = None,
                 root: dict | None = None) -> dict:
        return {"ok": True, "context_id": w.context_id, "decision_time": now,
                "root": root if root is not None else root_row,
                "streams": sorted(streams, key=lambda r: r["stream"]),
                "restrictions": sorted(restrictions or []), "inert_statement_ids": sorted(inert or []),
                "next_prior": next_prior}
    def add(name: str, prior: dict | str, objects: list[PublicObject] | str, observation: dict,
            *, now: str = NOW, operation: str = "fresh") -> None:
        result.append(Case("projection/" + name,
                           {"format": 1, "kind": "projection", "descriptor_base64": b64(w.descriptor_bytes),
                            "prior": prior, "candidate_catalog_base64": objects if isinstance(objects, str) else b64(w.catalog(objects)),
                            "now": now, "operation": operation}, observation))
    add("cold_genesis", "-", [w.genesis], expected(root_prior, []))
    add("exact_root_epoch_zero_read", root_prior, "-", expected(root_prior, []), operation="read")
    add("read_does_not_advance_guard", root_prior, "-",
        expected(root_prior, [], now="2026-10-26T12:00:10Z"), now="2026-10-26T12:00:10Z", operation="read")
    root_alias = w.alias(w.genesis)
    alias_prior = w.prior([w.genesis, root_alias], [root_max])
    add("root_alias_no_extra_head", root_prior, [root_alias], expected(alias_prior, []))
    add("clock_rollback_before_admission", root_prior, [], error("clock_rollback"), now="2026-10-26T11:54:59Z")
    add("clock_rollback_300_keeps_guarded_authority", root_prior, [], expected(root_prior, []), now="2026-10-26T11:55:00Z")
    person = w.statement("person_lease", w.lease_payload("person_lease"), [("issuer", "root", "ed25519")])
    host = w.statement("host_lease", w.lease_payload("host_lease"),
                       [("issuer", "root", "ed25519"), ("host", "host-a", "ed25519")])
    person_stream, host_stream = ["person", w.keys.public("alice")], ["host", w.keys.public("host-a")]
    person_max, host_max = maximum(person_stream, 1, [person]), maximum(host_stream, 1, [host])
    base_objects, base_maxima = [w.genesis, person, host], [root_max, person_max, host_max]
    base_prior = w.prior(base_objects, base_maxima)
    base_rows = [stream_row(person_stream, 1, [person]), stream_row(host_stream, 1, [host])]
    add("root_issued_person_and_consented_host", root_prior, [person, host], expected(base_prior, base_rows))
    add("admitted_person_host_read", base_prior, "-", expected(base_prior, base_rows), operation="read")
    alias = w.alias(person)
    add("person_alias_no_extra_head", base_prior, [alias],
        expected(w.prior(base_objects + [alias], base_maxima), base_rows))
    p2 = w.statement("person_lease", w.lease_payload("person_lease", sequence=2,
                     predecessors=[person.statement_id]), [("issuer", "root", "ed25519")])
    p3 = w.statement("person_lease", w.lease_payload("person_lease", sequence=3,
                     predecessors=[person.statement_id]), [("issuer", "root", "ed25519")])
    fork_objects = base_objects + [p2, p3]
    fork_prior = w.prior(fork_objects, [root_max, host_max, maximum(person_stream, 3, [p3], heads=[p2, p3])])
    fork_rows = [stream_row(host_stream, 1, [host]), stream_row(person_stream, 3, [p2, p3], code="state_conflict")]
    add("different_sequence_siblings_fork", base_prior, [p2, p3], expected(fork_prior, fork_rows))
    same_version = w.statement("person_lease", json.dumps(json.loads(p2.payload), indent=2).encode(),
                               [("issuer", "root", "ed25519")])
    equal_prior = w.prior(base_objects + [p2, same_version],
                         [root_max, host_max, maximum(person_stream, 2, [p2, same_version])])
    add("same_sequence_different_payload_bytes_fork", base_prior, [p2, same_version],
        expected(equal_prior, [stream_row(host_stream, 1, [host]),
                              stream_row(person_stream, 2, [p2, same_version], code="state_conflict")]))
    resolver = w.statement("person_lease", w.lease_payload("person_lease", sequence=4,
                            predecessors=sorted([p2.statement_id, p3.statement_id]),
                            resolves=sorted([p2.statement_id, p3.statement_id])), [("issuer", "root", "ed25519")])
    resolved_prior = w.prior(fork_objects + [resolver], [root_max, host_max, maximum(person_stream, 4, [resolver])])
    add("complete_current_root_resolution", fork_prior, [resolver],
        expected(resolved_prior, [stream_row(host_stream, 1, [host]), stream_row(person_stream, 4, [resolver])]))
    missing_id = "ds_" + "a" * 64
    missing_parent = w.statement("person_lease", w.lease_payload("person_lease", sequence=2,
                                  predecessors=[missing_id]), [("issuer", "root", "ed25519")])
    add("missing_predecessor_no_partial", base_prior, [missing_parent], error("proof_required", [missing_id]))
    high = w.statement("person_lease", w.lease_payload("person_lease", sequence=2**64-1,
                      predecessors=[person.statement_id]), [("issuer", "root", "ed25519")])
    high_prior = w.prior(base_objects + [high], [root_max, host_max, maximum(person_stream, 2**64-1, [high])])
    add("authorized_literal_max_u64_is_retained", base_prior, [high],
        expected(high_prior, [stream_row(host_stream, 1, [host]), stream_row(person_stream, 2**64-1, [high])]))
    add("max_u64_read_no_signed_integer_loss", high_prior, "-",
        expected(high_prior, [stream_row(host_stream, 1, [host]), stream_row(person_stream, 2**64-1, [high])]), operation="read")
    policy = w.access("policy", person_lease=person)
    policy_stream = ["policy", w.keys.public("alice")]
    policy_max = maximum(policy_stream, 1, [policy])
    policy_prior = w.prior(base_objects + [policy], base_maxima + [policy_max])
    policy_rows = base_rows + [stream_row(policy_stream, 1, [policy])]
    add("original_policy_current_parent", base_prior, [policy], expected(policy_prior, policy_rows))
    short = w.access("policy", sequence=77, predecessors=[policy.statement_id], person_lease=person,
                     not_after="2026-10-26T12:00:01Z")
    short_prior = w.prior(base_objects + [policy, short], base_maxima + [maximum(policy_stream, 77, [short])])
    add("shorter_than_day_access_interval", policy_prior, [short],
        expected(short_prior, base_rows + [stream_row(policy_stream, 77, [short])]))
    add("expired_latest_policy_no_lower_fallback", short_prior, "-",
        expected(short_prior, base_rows + [stream_row(policy_stream, 77, [short], code="expired")],
                 now="2026-10-26T12:00:02Z"), now="2026-10-26T12:00:02Z", operation="read")
    group = w.access("group")
    group_stream = ["group", "operators"]
    group_prior = w.prior(base_objects + [group], base_maxima + [maximum(group_stream, 1, [group])])
    add("root_group_current", base_prior, [group],
        expected(group_prior, base_rows + [stream_row(group_stream, 1, [group])]))
    deny = w.restriction("host_revoke", host="host-a")
    deny_prior = w.prior(base_objects + [deny], base_maxima, restrictions=[deny.statement_id])
    add("current_root_host_revoke", base_prior, [deny],
        expected(deny_prior, [stream_row(person_stream, 1, [person]),
                              stream_row(host_stream, 1, [host], code="forbidden")], restrictions=[deny.statement_id]))
    add("admitted_deny_stays_on_read", deny_prior, "-",
        expected(deny_prior, [stream_row(person_stream, 1, [person]),
                              stream_row(host_stream, 1, [host], code="forbidden")], restrictions=[deny.statement_id]), operation="read")
    # A missing SELECTED access body is the narrow domain-local exception.  The
    # remembered ID/floor stays exact while an unrelated root deny progresses.
    bob = w.statement("person_lease", w.lease_payload("person_lease", person="bob"), [("issuer", "root", "ed25519")])
    bob_stream = ["person", w.keys.public("bob")]
    bob_max = maximum(bob_stream, 1, [bob])
    incomplete_objects = base_objects + [policy, bob]
    incomplete_maxima = base_maxima + [maximum(policy_stream, 77, [short]), bob_max]
    incomplete_admitted = [o.statement_id for o in incomplete_objects] + [short.statement_id]
    incomplete_prior = w.prior(incomplete_objects, incomplete_maxima, admitted_ids=incomplete_admitted)
    bob_deny = w.restriction("person_remove", person="bob")
    incomplete_next = w.prior(incomplete_objects + [bob_deny], incomplete_maxima,
                              restrictions=[bob_deny.statement_id], admitted_ids=incomplete_admitted)
    add("missing_alice_policy_does_not_block_bob_deny", incomplete_prior, [bob_deny],
        expected(incomplete_next,
                 base_rows + [stream_row(policy_stream, 77, [short], code="proof_required", required=[short.statement_id]),
                              stream_row(bob_stream, 1, [bob], code="forbidden")], restrictions=[bob_deny.statement_id]))
    repaired_prior = w.prior(incomplete_objects + [short], incomplete_maxima)
    add("repair_exact_missing_selected_body", incomplete_prior, [short],
        expected(repaired_prior, base_rows + [stream_row(policy_stream, 77, [short]), stream_row(bob_stream, 1, [bob])]),
        operation="repair")
    # Cold root facts cannot turn a new P into another same-pass issuer.
    cold_objects = base_objects + [policy]
    cold_prior = w.prior(cold_objects, base_maxima, admitted_ids=[o.statement_id for o in base_objects])
    add("new_person_cannot_issue_unrelated_same_pass_policy", root_prior, [person, host, policy],
        expected(cold_prior, base_rows, inert=[policy.statement_id]))
    add("subsequent_legitimate_prior_allows_same_policy", cold_prior, [policy], expected(policy_prior, policy_rows))
    # Remembered fork heads survive loss of the body at the numeric maximum.
    q2 = w.access("policy", sequence=2, predecessors=[policy.statement_id], person_lease=person)
    q3 = w.access("policy", sequence=3, predecessors=[policy.statement_id], person_lease=person)
    missing_fork_maxima = base_maxima + [maximum(policy_stream, 3, [q3], heads=[q2, q3])]
    missing_fork_objects = base_objects + [policy, q2]
    missing_fork_ids = [o.statement_id for o in missing_fork_objects] + [q3.statement_id]
    missing_fork_prior = w.prior(missing_fork_objects, missing_fork_maxima, admitted_ids=missing_fork_ids)
    missing_fork_rows = base_rows + [stream_row(policy_stream, 3, [q2, q3], code="state_conflict")]
    add("missing_higher_fork_body_keeps_both_heads", missing_fork_prior, "-",
        expected(missing_fork_prior, missing_fork_rows), operation="read")
    full_fork_prior = w.prior(missing_fork_objects + [q3], missing_fork_maxima)
    add("repair_fork_body_does_not_resolve_fork", missing_fork_prior, [q3],
        expected(full_fork_prior, missing_fork_rows), operation="repair")
    # Root DAGs use branch ancestry, never the numerically largest epoch.
    def transition(predecessor: PublicObject, issuer_key: str, next_key: str, epoch: int, *, issued_at: str = NOW) -> PublicObject:
        payload = {"epoch": epoch, "predecessors": [predecessor.statement_id], "resolves": [],
                   "migration_proposal_id": "-", "root_public_key": w.keys.public(next_key),
                   "issued_at": issued_at, "retained_statement_ids": []}
        return w.statement("root_state", payload, [("issuer", issuer_key, "ed25519"), ("new_root", next_key, "ed25519")])
    def roots(heads: list[PublicObject], top: int) -> dict:
        ids = sorted(o.statement_id for o in heads)
        return {"head_ids": ids, "maximum": top, "selected_id": ids[0] if len(ids) == 1 else "-",
                "conflicted": len(ids) > 1, "code": "state_conflict" if len(ids) > 1 else "-", "required_ids": []}
    r1 = transition(w.genesis, "root", "next-root", 1)
    r1_other = transition(w.genesis, "root", "other-root", 1)
    r2_other = transition(r1_other, "other-root", "third-root", 2)
    root_branch_objects = [w.genesis, r1, r1_other, r2_other]
    root_fork_prior = w.prior(root_branch_objects, [maximum(["root"], 2, [r2_other], heads=[r1, r2_other])],
                              root_ids=[r1.statement_id, r2_other.statement_id])
    add("root_different_epoch_branches_freeze", root_prior, [r1, r1_other, r2_other],
        expected(root_fork_prior, [], root=roots([r1, r2_other], 2)))
    branch_ids = sorted([r1.statement_id, r2_other.statement_id])
    resolver_root = w.statement("root_state", {"epoch": 3, "predecessors": branch_ids, "resolves": branch_ids,
        "migration_proposal_id": "-", "root_public_key": w.keys.public("resolved-root"), "issued_at": NOW,
        "retained_statement_ids": []},
        [("root_branch:"+r1.statement_id, "next-root", "ed25519"),
         ("root_branch:"+r2_other.statement_id, "third-root", "ed25519"), ("new_root", "resolved-root", "ed25519")])
    resolved_root_prior = w.prior(root_branch_objects+[resolver_root], [maximum(["root"], 3, [resolver_root])],
                                  root_ids=[resolver_root.statement_id])
    add("all_branch_root_resolution", root_fork_prior, [resolver_root],
        expected(resolved_root_prior, [], root=roots([resolver_root], 3)))
    late_branch = transition(w.genesis, "root", "late-root", 1)
    reopened_prior = w.prior(root_branch_objects+[resolver_root, late_branch],
        [maximum(["root"], 3, [resolver_root], heads=[resolver_root, late_branch])],
        root_ids=[resolver_root.statement_id, late_branch.statement_id])
    add("later_unknown_root_branch_reopens_dispute", resolved_root_prior, [late_branch],
        expected(reopened_prior, [], root=roots([resolver_root, late_branch], 3)))
    r1_prior = w.prior([w.genesis, r1], [maximum(["root"], 1, [r1])], root_ids=[r1.statement_id])
    def retired(name: str, objects: list[PublicObject]) -> None:
        next_prior = w.prior([w.genesis, r1]+objects, [maximum(["root"], 1, [r1])],
                             root_ids=[r1.statement_id], admitted_ids=[w.genesis.statement_id, r1.statement_id])
        add(name, r1_prior, objects, expected(next_prior, [], root=roots([r1], 1), inert=[o.statement_id for o in objects]))
    retired("retired_root_grant_inert", [person])
    retired("retired_root_new_deny_inert", [w.restriction("person_remove")])
    retired("retired_root_max_u64_cannot_poison_stream", [person, high])
    current_person = w.statement("person_lease", w.lease_payload("person_lease", root_state_id=r1.statement_id),
                                 [("issuer", "next-root", "ed25519")])
    current_prior = w.prior([w.genesis, r1, current_person], [maximum(["root"], 1, [r1]), maximum(person_stream, 1, [current_person])],
                            root_ids=[r1.statement_id])
    add("current_root_grant_positive_control", r1_prior, [current_person],
        expected(current_prior, [stream_row(person_stream, 1, [current_person])], root=roots([r1], 1)))
    future = transition(w.genesis, "root", "future-root", 1, issued_at="2026-10-26T12:00:01Z")
    future_prior = w.prior([w.genesis, future], [root_max], admitted_ids=[w.genesis.statement_id])
    add("future_root_cannot_advance_head_or_clock", root_prior, [future], expected(future_prior, [], inert=[future.statement_id]))
    future_active = w.prior([w.genesis, future], [maximum(["root"], 1, [future])], root_ids=[future.statement_id],
                            clock_guard="2026-10-26T12:00:01Z")
    add("root_reconsidered_at_actual_local_time", future_prior, [future],
        expected(future_active, [], now="2026-10-26T12:00:01Z", root=roots([future], 1)),
        now="2026-10-26T12:00:01Z", operation="repair")
    future_deny = w.restriction("host_revoke", host="host-a", issued_at="2026-10-26T12:00:01Z")
    future_deny_prior = w.prior(base_objects+[future_deny], base_maxima, admitted_ids=[o.statement_id for o in base_objects])
    add("future_deny_cannot_be_sticky_or_advance_clock", base_prior, [future_deny],
        expected(future_deny_prior, base_rows, inert=[future_deny.statement_id]))
    active_deny_prior = w.prior(base_objects+[future_deny], base_maxima,
                               restrictions=[future_deny.statement_id], clock_guard="2026-10-26T12:00:01Z")
    add("deny_reconsidered_at_actual_local_time", future_deny_prior, [future_deny],
        expected(active_deny_prior, [stream_row(person_stream, 1, [person]), stream_row(host_stream, 1, [host], code="forbidden")],
                 now="2026-10-26T12:00:01Z", restrictions=[future_deny.statement_id]), now="2026-10-26T12:00:01Z", operation="repair")
    return result


def activation_objects_prior(w: World, activation) -> tuple[list[PublicObject], dict]:
    composite = PublicObject("activation", w.context_id, b"", activation.body, "")
    objects = activation.source_objects + activation.new_objects + [composite]
    maxima = []
    for obj in objects:
        if obj.kind == "root_state":
            maxima.append(maximum(["root"], 0, [obj]))
        elif obj.kind in {"person_lease", "host_lease", "binding_lease", "device_lease"}:
            payload = json.loads(obj.payload)
            subject = payload["subject"]
            stream = {"person_lease": ["person", subject["person_public_key"]],
                      "host_lease": ["host", subject["host_public_key"]],
                      "binding_lease": ["binding", subject["host_public_key"]],
                      "device_lease": ["device", subject["person_public_key"], subject["device_public_key"]]}[obj.kind]
            maxima.append(maximum(stream, payload["sequence"], [obj]))
    return objects, w.prior(objects, maxima, activations=[activation.activation_id])


def unique_objects(objects: list[PublicObject]) -> list[PublicObject]:
    return sorted({o.proof_id:o for o in objects}.values(), key=lambda o:o.proof_id)


def known_simple_prior(w: World, objects: list[PublicObject], *, activations: list[str] | None = None,
                       restrictions: list[str] | None = None) -> tuple[list[PublicObject], dict]:
    """Model a known nonforked fixture history; never infer trust at runtime."""
    objects = unique_objects(objects)
    streams = {}
    for o in objects:
        if not o.statement_id or o.kind in {"admin_withdraw","person_remove","host_revoke","host_unbind","device_revoke"}:
            continue
        p = json.loads(o.payload)
        if o.kind == "root_state":
            stream, sequence = ("root",), p["epoch"]
        elif o.kind in {"admin_lease","person_lease","host_lease","binding_lease","device_lease"}:
            s = p["subject"]
            stream = {"admin_lease":("admin",s["person_public_key"]),"person_lease":("person",s["person_public_key"]),
                "host_lease":("host",s["host_public_key"]),"binding_lease":("binding",s["host_public_key"]),
                "device_lease":("device",s["person_public_key"],s["device_public_key"])}[o.kind]
            sequence = p["sequence"]
        elif o.kind in {"policy","group"}:
            body = json.loads(unb64(p["body_base64"]))
            stream = ("policy",body["person_public_key"]) if o.kind=="policy" else ("group",body["name"])
            sequence = p["sequence"]
        else:
            continue
        previous = streams.get(stream)
        if previous is None or sequence > previous[0]:
            streams[stream] = (sequence,[o])
        elif sequence == previous[0] and o.statement_id not in {a.statement_id for a in previous[1]}:
            previous[1].append(o)
    maxima = [maximum(list(stream),n,heads) for stream,(n,heads) in streams.items()]
    return objects,w.prior(objects,maxima,activations=activations,restrictions=restrictions)


def activation_observation(w: World, a, *, matched: bool = True, additional_required: list[str] | None = None):
    manifest = json.loads(a.manifest)
    required_ds = sorted(set(manifest["ancestor_statement_ids"]+[a.device.statement_id]+(additional_required or [])))
    required_dp = manifest["proof_ids"]
    all_objects = unique_objects(a.source_objects+a.new_objects)
    a_dp = PublicObject("activation",w.context_id,b"",a.body,"").proof_id
    value = {"ok":True,"context_id":w.context_id,"request_id":a.request_id,"manifest_id":a.manifest_id,
        "activation_id":a.activation_id,"person_public_key":a.expected["person_public_key"],
        "host_public_key":a.expected["host_public_key"],"device_public_key":a.expected["device_public_key"],
        "device_lease_id":a.device.statement_id,"scopes":a.expected["scopes"],"effective_not_after":a.expected["not_after"],
        "required_statement_ids":required_ds,"required_proof_ids":required_dp,"review_pins_matched":matched}
    bounds = {"required_statement_ids":(required_ds,sorted({o.statement_id for o in all_objects if o.statement_id})),
        "required_proof_ids":(required_dp,sorted({o.proof_id for o in all_objects}|{a_dp}))}
    return value,bounds


def retention_cases(w: World) -> list[Case]:
    """Portable finite retention and every-alias provenance under PR91."""
    result = []
    p = w.statement("person_lease", w.lease_payload("person_lease"), [("issuer", "root", "ed25519")])
    h = w.statement("host_lease", w.lease_payload("host_lease"),
                    [("issuer", "root", "ed25519"), ("host", "host-a", "ed25519")])
    b = w.statement("binding_lease", w.lease_payload("binding_lease",
        issuer={"kind": "person", "person_public_key": w.keys.public("alice")}, parents=[
            {"role": "issuer_person", "id": p.statement_id}, {"role": "subject_person", "id": p.statement_id},
            {"role": "subject_host", "id": h.statement_id}]),
        [("issuer", "alice", "sshsig"), ("host", "host-a", "ed25519")])
    policy = w.access("policy", person_lease=p)
    streams = {"person": ["person", w.keys.public("alice")], "host": ["host", w.keys.public("host-a")],
               "binding": ["binding", w.keys.public("host-a")], "policy": ["policy", w.keys.public("alice")]}
    root_max = maximum(["root"], 0, [w.genesis])
    maxima = [root_max]+[maximum(streams[k], 1, [o]) for k, o in
                           [("person", p), ("host", h), ("binding", b), ("policy", policy)]]
    objects = [w.genesis, p, h, b, policy]
    prior = w.prior(objects, maxima)
    def observation(next_prior: dict, person: PublicObject = p, *, binding_code: str = "-", policy_code: str = "-",
                    root: PublicObject | None = None, now: str = NOW) -> dict:
        selected_root = w.genesis if root is None else root
        root_epoch = json.loads(selected_root.payload)["epoch"]
        return {"ok": True, "context_id": w.context_id, "decision_time": now,
            "root": {"head_ids": [selected_root.statement_id], "maximum": root_epoch,
                     "selected_id": selected_root.statement_id, "conflicted": False, "code": "-", "required_ids": []},
            "streams": sorted([stream_row(streams["person"], json.loads(person.payload)["sequence"], [person]),
                stream_row(streams["host"], 1, [h]), stream_row(streams["binding"], 1, [b], code=binding_code),
                stream_row(streams["policy"], 1, [policy], code=policy_code)], key=lambda row: row["stream"]),
            "restrictions": [], "inert_statement_ids": [], "next_prior": next_prior}
    def add(name: str, expected: dict, candidates: list[PublicObject] | str, *, local_prior: dict | str = prior,
            operation: str = "fresh", now: str = NOW) -> None:
        result.append(Case("retention/"+name, {"format": 1, "kind": "projection", "descriptor_base64": b64(w.descriptor_bytes),
            "prior": local_prior, "candidate_catalog_base64": candidates if isinstance(candidates, str) else b64(w.catalog(candidates)),
            "now": now, "operation": operation}, expected))
    add("complete_original_binding_and_policy_prior", observation(prior), "-", operation="read")
    p2 = w.statement("person_lease", w.lease_payload("person_lease", sequence=2, predecessors=[p.statement_id],
        retained_statement_ids=sorted([p.statement_id, b.statement_id, policy.statement_id])), [("issuer", "root", "ed25519")])
    renewed_maxima = [m for m in maxima if m["stream"] != streams["person"]]+[maximum(streams["person"], 2, [p2])]
    renewed_prior = w.prior(objects+[p2], renewed_maxima)
    add("person_successor_retains_exact_old_parent_binding_policy", observation(renewed_prior, p2), [p2])
    add("portable_retention_valid_for_cold_receiver", observation(renewed_prior, p2), objects+[p2], local_prior="-")
    no_child = w.statement("person_lease", w.lease_payload("person_lease", sequence=2,
        predecessors=[p.statement_id], retained_statement_ids=[p.statement_id]), [("issuer", "root", "ed25519")])
    no_child_max = [m for m in maxima if m["stream"] != streams["person"]]+[maximum(streams["person"], 2, [no_child])]
    no_child_prior = w.prior(objects+[no_child], no_child_max)
    add("retaining_parent_does_not_implicitly_retain_children",
        observation(no_child_prior, no_child, binding_code="forbidden", policy_code="forbidden"), [no_child])
    root1 = w.statement("root_state", {"epoch": 1, "predecessors": [w.genesis.statement_id], "resolves": [],
        "migration_proposal_id": "-", "root_public_key": w.keys.public("next-root"), "issued_at": NOW,
        "retained_statement_ids": sorted([p.statement_id, h.statement_id, b.statement_id, policy.statement_id])},
        [("issuer", "root", "ed25519"), ("new_root", "next-root", "ed25519")])
    root1_prior = w.prior(objects+[root1], [m for m in maxima if m["stream"] != ["root"]]+[maximum(["root"], 1, [root1])],
        root_ids=[root1.statement_id])
    add("root_successor_keeps_finite_closure_without_retaining_root", observation(root1_prior, root=root1), [root1])
    invalid_root = json.loads(root1.payload)
    invalid_root["retained_statement_ids"] = sorted(invalid_root["retained_statement_ids"]+[w.genesis.statement_id])
    bad_root = w.statement("root_state", invalid_root,
        [("issuer", "root", "ed25519"), ("new_root", "next-root", "ed25519")])
    add("root_state_is_not_a_typed_finite_retention_entry", error("invalid"), [bad_root])
    invalid_person = json.loads(p2.payload)
    invalid_person["retained_statement_ids"] = sorted(invalid_person["retained_statement_ids"]+[w.genesis.statement_id])
    bad_person = w.statement("person_lease", invalid_person, [("issuer", "root", "ed25519")])
    add("person_retention_cannot_include_a_root_state", error("invalid"), [bad_person])
    # A signature can verify cryptographically while being impossible for the
    # referenced root.  No good same-DS alias or prior admission excuses it.
    wrong_alias = w.statement("person_lease", p.payload, [("issuer", "bob", "ed25519")])
    add("wrong_referenced_root_key_alias_beside_admitted_correct_alias", error("invalid"), [wrong_alias])
    add("cold_correct_alias_cannot_forgive_wrong_key_alias", error("invalid"), objects+[wrong_alias], local_prior="-")
    wrong_prior = w.prior(objects+[wrong_alias], maxima)
    add("admitted_marker_does_not_forgive_present_wrong_key_alias", error("invalid"), "-", local_prior=wrong_prior, operation="read")
    missing_root = "ds_"+"a"*64
    unknown = w.statement("person_lease", w.lease_payload("person_lease", person="bob", root_state_id=missing_root),
                          [("issuer", "bob", "ed25519")])
    add("unknown_reference_not_guessed_as_inert_wrong_key", error("proof_required", [missing_root]), [unknown])
    return result


def expiry_cases(w: World) -> list[Case]:
    """Fresh expired evidence cannot manufacture remembered admission/maxima."""
    result = []
    edge = "2026-10-26T12:00:01Z"
    p = w.statement("person_lease", w.lease_payload("person_lease"), [("issuer", "root", "ed25519")])
    h = w.statement("host_lease", w.lease_payload("host_lease"),
                    [("issuer", "root", "ed25519"), ("host", "host-a", "ed25519")])
    pstream, hstream = ["person", w.keys.public("alice")], ["host", w.keys.public("host-a")]
    basic_objects = [w.genesis, p, h]
    basic_maxima = [maximum(["root"], 0, [w.genesis]), maximum(pstream, 1, [p]), maximum(hstream, 1, [h])]
    basic_rows = [stream_row(pstream, 1, [p]), stream_row(hstream, 1, [h])]
    q = w.access("policy", person_lease=p)
    qstream = ["policy", w.keys.public("alice")]
    q_objects, q_maxima = basic_objects+[q], basic_maxima+[maximum(qstream, 1, [q])]
    q_rows = basic_rows+[stream_row(qstream, 1, [q])]
    root_row = {"head_ids": [w.genesis.statement_id], "maximum": 0, "selected_id": w.genesis.statement_id,
                "conflicted": False, "code": "-", "required_ids": []}
    def observed(next_prior: dict, rows: list[dict], now: str, inert: list[str] | None = None) -> dict:
        return {"ok": True, "context_id": w.context_id, "decision_time": now, "root": root_row,
                "streams": sorted(rows, key=lambda r: r["stream"]), "restrictions": [],
                "inert_statement_ids": sorted(inert or []), "next_prior": next_prior}
    def add(name: str, obj: PublicObject, stream: list[str], *, objects: list[PublicObject] = basic_objects,
            maxima: list[dict] = basic_maxima, rows: list[dict] = basic_rows,
            operation: str = "fresh", now: str = edge, admitted: bool = False, active: bool = False) -> None:
        prior = w.prior(objects, maxima)
        sequence = json.loads(obj.payload)["sequence"]
        if admitted or active:
            final_maxima = [m for m in maxima if m["stream"] != stream]+[maximum(stream, sequence, [obj])]
            body_prior = w.prior(objects+[obj], final_maxima)
            code = "-" if active else ("expired" if obj.kind in {"policy", "group"} else "authority_expired")
            final_rows = [r for r in rows if r["stream"] != stream]+[stream_row(stream, sequence, [obj], code=code)]
            if admitted:
                prior = body_prior
                candidates = "-"
            else:
                body_prior["clock_guard"] = now
                candidates = b64(w.catalog([obj]))
            expected = observed(body_prior, final_rows, now)
        else:
            next_prior = w.prior(objects+[obj], maxima, admitted_ids=[o.statement_id for o in objects], clock_guard=now)
            candidates = b64(w.catalog([obj]))
            expected = observed(next_prior, rows, now, [obj.statement_id])
        result.append(Case("expiry/"+name, {"format": 1, "kind": "projection", "descriptor_base64": b64(w.descriptor_bytes),
            "prior": prior, "candidate_catalog_base64": candidates, "now": now, "operation": operation}, expected))
    p2 = w.statement("person_lease", w.lease_payload("person_lease", sequence=77, predecessors=[p.statement_id], not_after=edge),
                     [("issuer", "root", "ed25519")])
    h2 = w.statement("host_lease", w.lease_payload("host_lease", sequence=77, predecessors=[h.statement_id], not_after=edge),
                     [("issuer", "root", "ed25519"), ("host", "host-a", "ed25519")])
    admin = w.statement("admin_lease", w.lease_payload("admin_lease", not_after=edge), [("issuer", "root", "ed25519")])
    binding = w.statement("binding_lease", w.lease_payload("binding_lease", not_after=edge,
        issuer={"kind": "person", "person_public_key": w.keys.public("alice")}, parents=[
            {"role": "subject_person", "id": p.statement_id}, {"role": "subject_host", "id": h.statement_id},
            {"role": "issuer_person", "id": p.statement_id}]),
        [("issuer", "alice", "sshsig"), ("host", "host-a", "ed25519")])
    q2 = w.access("policy", sequence=77, predecessors=[q.statement_id], person_lease=p, not_after=edge)
    group = w.access("group", not_after=edge)
    for name, obj, stream in [("person", p2, pstream), ("host", h2, hstream),
        ("admin", admin, ["admin", w.keys.public("alice")]), ("binding", binding, ["binding", w.keys.public("host-a")]),
        ("group", group, ["group", "operators"])]:
        add("unadmitted_"+name+"_at_exact_expiry_is_inert", obj, stream)
    add("unadmitted_policy_at_exact_expiry_cannot_poison_maximum", q2, qstream,
        objects=q_objects, maxima=q_maxima, rows=q_rows)
    for operation in ["repair"]:
        add("historical_repair_cannot_first_admit_expired_person", p2, pstream, operation=operation)
        add("historical_repair_cannot_first_admit_expired_policy", q2, qstream,
            objects=q_objects, maxima=q_maxima, rows=q_rows, operation=operation)
    add("prior_admitted_expired_person_preserves_head_maximum", p2, pstream, admitted=True, operation="read")
    add("prior_admitted_expired_policy_preserves_head_maximum", q2, qstream,
        objects=q_objects, maxima=q_maxima, rows=q_rows, admitted=True, operation="read")
    add("person_before_exact_expiry_can_be_admitted", p2, pstream, now=NOW, active=True)
    add("policy_before_exact_expiry_can_be_admitted", q2, qstream,
        objects=q_objects, maxima=q_maxima, rows=q_rows, now=NOW, active=True)
    future_p = w.statement("person_lease", w.lease_payload("person_lease", sequence=77,
        predecessors=[p.statement_id], issued_at=edge, not_before=edge), [("issuer", "root", "ed25519")])
    future_q = w.access("policy", sequence=77, predecessors=[q.statement_id], person_lease=p, issued_at=edge)
    add("future_person_does_not_advance_head_or_maximum", future_p, pstream, now=NOW)
    add("future_policy_does_not_advance_head_or_maximum", future_q, qstream,
        objects=q_objects, maxima=q_maxima, rows=q_rows, now=NOW)
    return result


def admin_withdrawal_cases(w: World) -> list[Case]:
    result = []
    edge = "2026-10-26T12:00:01Z"
    def archive(deadline: str = UNTIL):
        quinn = w.statement("person_lease", w.lease_payload("person_lease", person="quinn"), [("issuer", "root", "ed25519")])
        admin = w.statement("admin_lease", w.lease_payload("admin_lease", person="quinn"), [("issuer", "root", "ed25519")])
        parents = sorted([{"role": "issuer_person", "id": quinn.statement_id},
                          {"role": "issuer_admin", "id": admin.statement_id}], key=lambda p:p["role"])
        issuer = {"kind": "person", "person_public_key": w.keys.public("quinn")}
        alice = w.statement("person_lease", w.lease_payload("person_lease", not_after=deadline, issuer=issuer, parents=parents),
                            [("issuer", "quinn", "sshsig")])
        host = w.statement("host_lease", w.lease_payload("host_lease", not_after=deadline, issuer=issuer, parents=parents),
                           [("issuer", "quinn", "sshsig"), ("host", "host-a", "ed25519")])
        bob = w.statement("person_lease", w.lease_payload("person_lease", person="bob", issuer=issuer, parents=parents),
                          [("issuer", "quinn", "sshsig")])
        objects = [w.genesis, quinn, admin, alice, host, bob]
        keyed = [(["person", w.keys.public("quinn")], quinn), (["admin", w.keys.public("quinn")], admin),
                 (["person", w.keys.public("alice")], alice), (["host", w.keys.public("host-a")], host),
                 (["person", w.keys.public("bob")], bob)]
        maxima = [maximum(["root"], 0, [w.genesis])]+[maximum(stream, 1, [o]) for stream,o in keyed]
        return objects, keyed, maxima, quinn, admin, alice, host, bob
    objects, keyed, maxima, quinn, admin, alice, host, bob = archive()
    prior = w.prior(objects, maxima)
    def withdrawal(role: PublicObject, kept: list[str]) -> PublicObject:
        return w.statement("admin_withdraw", {"root_state_id": w.genesis.statement_id,
            "issuer": {"kind": "root", "person_public_key": "-"}, "parents": [], "issued_at": NOW,
            "target": {"statement_id": role.statement_id, "person_public_key": w.keys.public("quinn"),
                       "host_public_key": "-", "device_public_key": "-"},
            "kept_statement_ids": sorted(kept), "ratifies": "-"}, [("issuer", "root", "ed25519")])
    def view(next_prior: dict, entries: list[tuple[list[str], PublicObject]], codes: dict[str,str],
             restrictions: list[str], *, now: str = NOW, root: PublicObject | None = None) -> dict:
        r = w.genesis if root is None else root
        return {"ok": True, "context_id": w.context_id, "decision_time": now,
            "root": {"head_ids": [r.statement_id], "maximum": json.loads(r.payload)["epoch"],
                     "selected_id": r.statement_id, "conflicted": False, "code": "-", "required_ids": []},
            "streams": sorted([stream_row(stream, 1, [o], code=codes.get(o.statement_id,"-")) for stream,o in entries], key=lambda r:r["stream"]),
            "restrictions": sorted(restrictions), "inert_statement_ids": [], "next_prior": next_prior}
    def add(name: str, local_prior: dict, candidates: list[PublicObject] | str, expected: dict, *, now: str = NOW, operation: str = "fresh"):
        result.append(Case("admin_withdrawal/"+name, {"format":1,"kind":"projection","descriptor_base64":b64(w.descriptor_bytes),
            "prior":local_prior,"candidate_catalog_base64":candidates if isinstance(candidates,str) else b64(w.catalog(candidates)),
            "now":now,"operation":operation},expected))
    kept = withdrawal(admin, [alice.statement_id, host.statement_id])
    kept_prior = w.prior(objects+[kept], maxima, restrictions=[kept.statement_id])
    denied = {admin.statement_id:"forbidden", bob.statement_id:"forbidden"}
    add("exact_kept_person_host_survive_only_role_barrier", prior, [kept], view(kept_prior,keyed,denied,[kept.statement_id]))
    only_person = withdrawal(admin, [alice.statement_id])
    person_prior = w.prior(objects+[only_person], maxima, restrictions=[only_person.statement_id])
    add("kept_person_does_not_implicitly_keep_host_or_bob", prior, [only_person],
        view(person_prior,keyed,{**denied,host.statement_id:"forbidden"},[only_person.statement_id]))
    none = withdrawal(admin, [])
    none_prior = w.prior(objects+[none], maxima, restrictions=[none.statement_id])
    add("empty_kept_retires_all_dependent_admissions", prior, [none],
        view(none_prior,keyed,{**denied,alice.statement_id:"forbidden",host.statement_id:"forbidden"},[none.statement_id]))
    add("kept_requires_exact_eligible_person_or_host_kind", prior, [withdrawal(admin,[w.genesis.statement_id])], error("invalid"))
    missing = "ds_"+"a"*64
    add("missing_kept_body_is_not_an_asserted_admission", prior, [withdrawal(admin,[missing])], error("proof_required",[missing]))
    host_deny = w.restriction("host_revoke",host="host-a")
    host_prior = w.prior(objects+[kept,host_deny],maxima,restrictions=[kept.statement_id,host_deny.statement_id])
    add("kept_host_still_obeys_independent_host_revocation",kept_prior,[host_deny],
        view(host_prior,keyed,{**denied,host.statement_id:"forbidden"},[kept.statement_id,host_deny.statement_id]))
    issuer_deny = w.restriction("person_remove",person="quinn")
    issuer_prior = w.prior(objects+[kept,issuer_deny],maxima,restrictions=[kept.statement_id,issuer_deny.statement_id])
    add("kept_does_not_bypass_removed_issuer_person_ancestor",kept_prior,[issuer_deny],
        view(issuer_prior,keyed,{o.statement_id:"forbidden" for _,o in keyed},[kept.statement_id,issuer_deny.statement_id]))
    short_objects,short_keyed,short_maxima,_,short_admin,short_alice,short_host,_ = archive(edge)
    short_kept = withdrawal(short_admin,[short_alice.statement_id,short_host.statement_id])
    short_prior = w.prior(short_objects+[short_kept],short_maxima,restrictions=[short_kept.statement_id])
    add("kept_does_not_extend_original_hard_deadlines",short_prior,"-",
        view(short_prior,short_keyed,{short_admin.statement_id:"forbidden",bob.statement_id:"forbidden",
            short_alice.statement_id:"authority_expired",short_host.statement_id:"authority_expired"},[short_kept.statement_id],now=edge),
        now=edge,operation="read")
    r1 = w.statement("root_state",{"epoch":1,"predecessors":[w.genesis.statement_id],"resolves":[],
        "migration_proposal_id":"-","root_public_key":w.keys.public("next-root"),"issued_at":NOW,"retained_statement_ids":[]},
        [("issuer","root","ed25519"),("new_root","next-root","ed25519")])
    root_prior = w.prior(objects+[kept,r1],[m for m in maxima if m["stream"] != ["root"]]+[maximum(["root"],1,[r1])],
        root_ids=[r1.statement_id],restrictions=[kept.statement_id])
    add("role_kept_cannot_replace_missing_root_transition_retention",kept_prior,[r1],
        view(root_prior,keyed,{o.statement_id:"forbidden" for _,o in keyed},[kept.statement_id],root=r1))
    return result


def activation_cases(w: World) -> list[Case]:
    result = []
    a = w.original_link(scopes=7)
    _, complete_prior = activation_objects_prior(w, a)
    source_ids = {o.statement_id for o in a.source_objects}
    source_prior = w.prior(a.source_objects, [m for m in complete_prior["maxima"]
        if set(m["statement_ids"]) <= source_ids])
    objects = a.source_objects + a.new_objects
    manifest = json.loads(a.manifest)
    required_ds = sorted(manifest["ancestor_statement_ids"]+[a.device.statement_id])
    required_dp = manifest["proof_ids"]
    activation_dp = PublicObject("activation", w.context_id, b"", a.body, "").proof_id
    success = {"ok": True, "context_id": w.context_id, "request_id": a.request_id,
        "manifest_id": a.manifest_id, "activation_id": a.activation_id,
        "person_public_key": w.keys.public("alice"), "host_public_key": w.keys.public("host-b"),
        "device_public_key": w.keys.public("device-b"), "device_lease_id": a.device.statement_id,
        "scopes": 7, "effective_not_after": UNTIL, "required_statement_ids": required_ds,
        "required_proof_ids": required_dp, "review_pins_matched": False}
    bounds = {"required_statement_ids": (required_ds, sorted(o.statement_id for o in objects)),
              "required_proof_ids": (required_dp, sorted([o.proof_id for o in objects]+[activation_dp]))}
    def add(name: str, expected: dict, *, body: bytes = a.body, catalog: list[PublicObject] | None = None,
            pins: dict | str = "-", now: str = NOW, limits: dict | None = None) -> None:
        result.append(Case("activation/"+name, {"format": 1, "kind": "activation",
            "descriptor_base64": b64(w.descriptor_bytes), "prior": source_prior,
            "catalog_base64": b64(w.catalog(objects if catalog is None else catalog)),
            "activation_base64": b64(body), "now": now, "expected": pins}, expected,
            array_bounds=limits))
    add("complete_original_owner_new_host", success, limits=bounds)
    add("exact_private_review_pins", changed(success, review_pins_matched=True), pins=a.expected, limits=bounds)
    add("later_learning_after_local_signing_window", success, now="2026-10-26T12:05:01Z", limits=bounds)
    add("expired_finite_parents_not_a_permanent_receipt", error("authority_expired"), now=UNTIL)
    missing = json.loads(a.body)
    del missing["selection"]
    add("missing_requester_selection", error("invalid"), body=raw_json(missing))
    missing = json.loads(a.body)
    del missing["commit"]
    add("missing_separate_final_consent", error("invalid"), body=raw_json(missing))
    add("new_host_cannot_skip_administrator", error("invalid"),
        body=raw_json(changed(json.loads(a.body), administrator="-")))
    forged = json.loads(a.body)
    sig = bytearray(unb64(forged["commit"]["device_signature"]))
    sig[0] ^= 1
    forged["commit"]["device_signature"] = b64(sig)
    add("forged_target_device_commit", error("invalid"), body=raw_json(forged))
    # Re-signing a requester packet cannot erase the target-host binding consent.
    commit_payload = changed(json.loads(a.packets["commit"].payload), binding_host_signature="-")
    unsigned_binding = w.packet("commit", commit_payload, a.request_id, writer="host-b", signer="device-b", person="alice")
    add("new_binding_requires_actual_host_consent", error("invalid"),
        body=raw_json(changed(json.loads(a.body), commit=json.loads(unsigned_binding.body))))
    binding = a.new_objects[1]
    alias = w.alias(binding)
    substituted = [o for o in objects if o != binding]+[alias]
    add("alias_cannot_replace_manifest_pinned_complete_binding_body", error("proof_required", [binding.proof_id]), catalog=substituted)
    envelope = json.loads(w.genesis.body)
    sig = bytearray(unb64(envelope["signatures"][0]["signature"]))
    sig[0] ^= 1
    envelope["signatures"][0]["signature"] = b64(sig)
    bad_alias = PublicObject("root_state", w.context_id, w.genesis.payload, raw_json(envelope), w.genesis.statement_id)
    add("forged_unused_alias_not_forgiven_by_complete_consent", error("invalid"), catalog=objects+[bad_alias])
    return result


def activation_dag_cases(w: World) -> list[Case]:
    result = []
    old, renewed = w.renewal_after_expired_target()
    now = "2026-10-26T12:00:02Z"
    old_composite = PublicObject("activation", w.context_id, b"", old.body, "")
    current_composite = PublicObject("activation", w.context_id, b"", renewed.body, "")
    _, full_old_prior = activation_objects_prior(w, old)
    base_ids = {o.statement_id for o in old.source_objects}
    base_maxima = [m for m in full_old_prior["maxima"] if set(m["statement_ids"]) <= base_ids]
    base_prior = w.prior(old.source_objects, base_maxima)
    root_row = {"head_ids": [w.genesis.statement_id], "maximum": 0, "selected_id": w.genesis.statement_id,
                "conflicted": False, "code": "-", "required_ids": []}
    base_rows = []
    for m in base_maxima:
        if m["stream"] != ["root"]:
            base_rows.append(stream_row(m["stream"], m["sequence"], m["head_ids"]))
    expired_ids = sorted(o.statement_id for o in old.new_objects)
    old_objects = old.source_objects+old.new_objects+[old_composite]
    old_next = w.prior(old_objects, base_maxima, activations=[old.activation_id],
                       admitted_ids=sorted(base_ids), clock_guard=now)
    result.append(Case("activation_dag/expired_target_and_components_supply_consent_not_admission", {
        "format": 1, "kind": "projection", "descriptor_base64": b64(w.descriptor_bytes), "prior": base_prior,
        "candidate_catalog_base64": b64(w.catalog(old.new_objects+[old_composite])), "now": now, "operation": "repair"},
        {"ok": True, "context_id": w.context_id, "decision_time": now, "root": root_row,
         "streams": sorted(base_rows, key=lambda r: r["stream"]), "restrictions": [],
         "inert_statement_ids": expired_ids, "next_prior": old_next}))
    all_objects = renewed.source_objects+renewed.new_objects
    manifest = json.loads(renewed.manifest)
    required_ds = sorted(manifest["ancestor_statement_ids"]+[renewed.device.statement_id])
    required_dp = manifest["proof_ids"]
    minimum = {"ok": True, "context_id": w.context_id, "request_id": renewed.request_id,
        "manifest_id": renewed.manifest_id, "activation_id": renewed.activation_id,
        "person_public_key": w.keys.public("alice"), "host_public_key": w.keys.public("host-b"),
        "device_public_key": w.keys.public("device-b"), "device_lease_id": renewed.device.statement_id,
        "scopes": 7, "effective_not_after": UNTIL, "required_statement_ids": required_ds,
        "required_proof_ids": required_dp, "review_pins_matched": True}
    bounds = {"required_statement_ids": (required_ds, sorted(o.statement_id for o in all_objects if o.statement_id)),
              "required_proof_ids": (required_dp, sorted([o.proof_id for o in all_objects]+[current_composite.proof_id]))}
    request = {"format": 1, "kind": "activation", "descriptor_base64": b64(w.descriptor_bytes), "prior": base_prior,
        "catalog_base64": b64(w.catalog(all_objects)), "activation_base64": b64(renewed.body), "now": now,
        "expected": renewed.expected}
    result.append(Case("activation_dag/cold_renewal_uses_current_original_and_exact_ancestor_consent", request, minimum, array_bounds=bounds))
    without_consent = [o for o in all_objects if o != old_composite]
    result.append(Case("activation_dag/expired_predecessor_still_requires_exact_complete_consent", changed(request,
        catalog_base64=b64(w.catalog(without_consent))), error("proof_required", [old_composite.proof_id])))
    h2, b2 = renewed.source_objects[-2:]
    new_maxima = base_maxima+[
        maximum(["host", w.keys.public("host-b")], 2, [h2]),
        maximum(["binding", w.keys.public("host-b")], 2, [b2]),
        maximum(["device", w.keys.public("alice"), w.keys.public("device-b")], 2, [renewed.device])]
    admitted = sorted(base_ids | {h2.statement_id, b2.statement_id, renewed.device.statement_id})
    next_prior = w.prior(all_objects+[current_composite], new_maxima, admitted_ids=admitted,
        activations=[old.activation_id, renewed.activation_id], clock_guard=now)
    result.append(Case("activation_dag/expired_ancestor_cannot_poison_new_head_or_maximum", {
        "format": 1, "kind": "projection", "descriptor_base64": b64(w.descriptor_bytes), "prior": base_prior,
        "candidate_catalog_base64": b64(w.catalog(all_objects+[current_composite])), "now": now, "operation": "repair"},
        {"ok": True, "context_id": w.context_id, "decision_time": now, "root": root_row,
         "streams": sorted(base_rows+[
            stream_row(["host", w.keys.public("host-b")], 2, [h2]),
            stream_row(["binding", w.keys.public("host-b")], 2, [b2]),
            stream_row(["device", w.keys.public("alice"), w.keys.public("device-b")], 2, [renewed.device])], key=lambda r:r["stream"]),
         "restrictions": [], "inert_statement_ids": expired_ids, "next_prior": next_prior}))
    return result


def renewal_stage_cases(w: World) -> list[Case]:
    """PR99/100 distinguish independent current P/H from this ceremony's H.

    The positive request is the unchanged earlier DAG vector.  Only the
    negative's new H is operation-bound to this exact request and lacks the
    applicable administrator stage.  Complete owner/device/host consent cannot
    make that omitted stage optional.
    """
    pin = "2f692937fa5fd41f3bab3accca830628788b7e24"
    positive = next(case for case in activation_dag_cases(w)
                    if case.name.endswith("cold_renewal_uses_current_original_and_exact_ancestor_consent"))
    _, renewed = w.renewal_after_expired_target(host_from_this_ceremony=True)
    negative = changed(positive.request,
        catalog_base64=b64(w.catalog(renewed.source_objects + renewed.new_objects)),
        activation_base64=b64(renewed.body), expected=renewed.expected)
    return [
        Case("renewal_stage/independent_current_parents_allow_exact_admin_skip",
             positive.request, positive.expected, array_bounds=positive.array_bounds, oracle_pin=pin),
        Case("renewal_stage/same_ceremony_host_requires_administrator_stage",
             negative, error("invalid"), oracle_pin=pin),
    ]


def signature_format_cases(w: World) -> list[Case]:
    result = []
    a = w.original_link()
    p = a.source_objects[1]
    b = a.source_objects[3]
    policy = w.access("policy",person_lease=p)
    def statement(name: str, obj: PublicObject, expected: dict):
        result.append(Case("signature_format/"+name,{"format":1,"kind":"statement",
            "descriptor_base64":b64(w.descriptor_bytes),"statement_base64":b64(obj.body)},expected))
    statement("original_binding_sshsig_positive",b,statement_expected(b))
    statement("raw_original_binding_rejected",w.statement("binding_lease",b.payload,
        [("issuer","alice","ed25519"),("host","host-a","ed25519")]),error("invalid"))
    statement("raw_original_policy_rejected",w.statement("policy",policy.payload,[("issuer","alice","ed25519")]),error("invalid"))
    statement("raw_original_device_delegation_rejected",w.statement("device_lease",a.device.payload,
        [("issuer","alice","ed25519")]),error("invalid"))
    admin_payload = w.lease_payload("person_lease",person="bob",
        issuer={"kind":"person","person_public_key":w.keys.public("alice")},parents=sorted([
            {"role":"issuer_person","id":p.statement_id},{"role":"issuer_admin","id":"ds_"+"a"*64}],key=lambda x:x["role"]))
    statement("raw_original_admin_issued_person_rejected",w.statement("person_lease",admin_payload,
        [("issuer","alice","ed25519")]),error("invalid"))
    device_payload = changed(json.loads(policy.payload),issuer={"kind":"device","person_public_key":w.keys.public("alice")},
        parents=sorted([{"role":"issuer_person","id":p.statement_id},
                        {"role":"issuer_device","id":a.device.statement_id}],key=lambda x:x["role"]))
    statement("device_authority_cannot_use_sshsig",w.statement("policy",device_payload,
        [("issuer","device-b","sshsig")]),error("invalid"))
    statement("host_consent_cannot_use_sshsig",w.statement("binding_lease",b.payload,
        [("issuer","alice","sshsig"),("host","host-a","sshsig")]),error("invalid"))
    raw_packets = w.original_link(owner_packet_format="ed25519")
    _,prior = known_simple_prior(w,raw_packets.source_objects)
    result.append(Case("signature_format/raw_original_packet_authorities_rejected",{
        "format":1,"kind":"activation","descriptor_base64":b64(w.descriptor_bytes),"prior":prior,
        "catalog_base64":b64(w.catalog(unique_objects(raw_packets.source_objects+raw_packets.new_objects))),
        "activation_base64":b64(raw_packets.body),"now":NOW,"expected":raw_packets.expected},error("invalid")))
    ssh_root = w.original_link(root_packet_format="sshsig")
    _,prior = known_simple_prior(w,ssh_root.source_objects)
    expected,bounds = activation_observation(w,ssh_root)
    result.append(Case("signature_format/explicit_sshsig_network_root_packet_allowed",{
        "format":1,"kind":"activation","descriptor_base64":b64(w.descriptor_bytes),"prior":prior,
        "catalog_base64":b64(w.catalog(unique_objects(ssh_root.source_objects+ssh_root.new_objects))),
        "activation_base64":b64(ssh_root.body),"now":NOW,"expected":ssh_root.expected},expected,array_bounds=bounds))
    return result


def read_purity_cases(w: World) -> list[Case]:
    result = []
    p = w.statement("person_lease",w.lease_payload("person_lease"),[("issuer","root","ed25519")])
    h = w.statement("host_lease",w.lease_payload("host_lease"),[("issuer","root","ed25519"),("host","host-a","ed25519")])
    base,prior = known_simple_prior(w,[w.genesis,p,h])
    q = w.access("policy",person_lease=p)
    future_root = w.statement("root_state",{"epoch":1,"predecessors":[w.genesis.statement_id],"resolves":[],
        "migration_proposal_id":"-","root_public_key":w.keys.public("next-root"),"issued_at":"2026-10-26T12:00:01Z",
        "retained_statement_ids":[]},[("issuer","root","ed25519"),("new_root","next-root","ed25519")])
    future_deny = w.restriction("host_revoke",host="host-a",issued_at="2026-10-26T12:00:01Z")
    for name,obj in [("policy_now_has_current_issuer_but_remains_unadmitted",q),
                     ("future_root_later_becomes_timely_but_is_not_promoted",future_root),
                     ("future_restriction_later_becomes_timely_but_is_not_admitted",future_deny)]:
        local_prior = copy.deepcopy(prior)
        local_prior["catalog_base64"] = b64(w.catalog(base+[obj]))
        result.append(Case("read_purity/"+name,{"format":1,"kind":"projection","descriptor_base64":b64(w.descriptor_bytes),
            "prior":local_prior,"candidate_catalog_base64":"-","now":"2026-10-26T12:00:02Z","operation":"read"},
            {"ok":True,"context_id":w.context_id,"decision_time":"2026-10-26T12:00:02Z",
             "root":{"head_ids":[w.genesis.statement_id],"maximum":0,"selected_id":w.genesis.statement_id,
                     "conflicted":False,"code":"-","required_ids":[]},
             "streams":sorted([stream_row(["person",w.keys.public("alice")],1,[p]),
                                stream_row(["host",w.keys.public("host-a")],1,[h])],key=lambda r:r["stream"]),
             "restrictions":[],"inert_statement_ids":[obj.statement_id],"next_prior":local_prior}))
    return result


def revoked_retainer_cases(w: World) -> list[Case]:
    result = []
    admin = w.statement("admin_lease",w.lease_payload("admin_lease",person="quinn"),[("issuer","root","ed25519")])
    q = w.original_link(person="quinn",owner_host="host-q-owner",target_host="host-q",target_device="device-q",
        scopes=8,additional_proof_objects=[admin])
    q_proof = PublicObject("activation",w.context_id,b"",q.body,"")
    qp = next(o for o in q.source_objects if o.kind=="person_lease")
    p = w.statement("person_lease",w.lease_payload("person_lease"),[("issuer","root","ed25519")])
    h = w.statement("host_lease",w.lease_payload("host_lease"),[("issuer","root","ed25519"),("host","host-a","ed25519")])
    b = w.statement("binding_lease",w.lease_payload("binding_lease",issuer={"kind":"person","person_public_key":w.keys.public("alice")},
        parents=[{"role":"issuer_person","id":p.statement_id},{"role":"subject_person","id":p.statement_id},
                 {"role":"subject_host","id":h.statement_id}]),[("issuer","alice","sshsig"),("host","host-a","ed25519")])
    policy = w.access("policy",person_lease=p)
    objects,prior = known_simple_prior(w,q.source_objects+q.new_objects+[q_proof,admin,p,h,b,policy],activations=[q.activation_id])
    p2 = w.statement("person_lease",w.lease_payload("person_lease",sequence=2,predecessors=[p.statement_id],
        retained_statement_ids=sorted([p.statement_id,b.statement_id,policy.statement_id]),
        issuer={"kind":"device","person_public_key":w.keys.public("quinn")},parents=[
            {"role":"issuer_person","id":qp.statement_id},{"role":"issuer_admin","id":admin.statement_id},
            {"role":"issuer_device","id":q.device.statement_id}]),[("issuer","device-q","ed25519")])
    updated,retained_prior = known_simple_prior(w,objects+[p2],activations=[q.activation_id])
    deny = w.statement("device_revoke",{"root_state_id":w.genesis.statement_id,
        "issuer":{"kind":"person","person_public_key":w.keys.public("quinn")},
        "parents":[{"role":"issuer_person","id":qp.statement_id}],"issued_at":NOW,
        "target":{"statement_id":"-","person_public_key":w.keys.public("quinn"),"host_public_key":"-",
                  "device_public_key":w.keys.public("device-q")},"kept_statement_ids":[],"ratifies":"-"},[("issuer","quinn","sshsig")])
    _,revoked_prior = known_simple_prior(w,updated+[deny],activations=[q.activation_id],restrictions=[deny.statement_id])
    def view(local_prior: dict, revoked: bool) -> dict:
        denied = {q.device.statement_id,p2.statement_id,b.statement_id,policy.statement_id} if revoked else set()
        rows=[]
        for m in local_prior["maxima"]:
            if m["stream"]==["root"]:continue
            sid=m["head_ids"][0]
            rows.append(stream_row(m["stream"],m["sequence"],m["head_ids"],code="device_revoked" if sid in denied else "-"))
        return {"ok":True,"context_id":w.context_id,"decision_time":NOW,
            "root":{"head_ids":[w.genesis.statement_id],"maximum":0,"selected_id":w.genesis.statement_id,
                    "conflicted":False,"code":"-","required_ids":[]},"streams":sorted(rows,key=lambda r:r["stream"]),
            "restrictions":[deny.statement_id] if revoked else [],"inert_statement_ids":[],"next_prior":local_prior}
    result.append(Case("revoked_retainer/current_admin_successor_retains_old_root_person_contribution",{
        "format":1,"kind":"projection","descriptor_base64":b64(w.descriptor_bytes),"prior":prior,
        "candidate_catalog_base64":b64(w.catalog([p2])),"now":NOW,"operation":"fresh"},view(retained_prior,False)))
    result.append(Case("revoked_retainer/revoking_successor_issuer_invalidates_retained_children",{
        "format":1,"kind":"projection","descriptor_base64":b64(w.descriptor_bytes),"prior":retained_prior,
        "candidate_catalog_base64":b64(w.catalog([deny])),"now":NOW,"operation":"fresh"},view(revoked_prior,True)))
    policy2 = w.access("policy",sequence=2,predecessors=[policy.statement_id],person_lease=p2)
    result.append(Case("revoked_retainer/new_owner_policy_cannot_fallback_to_old_root_admission",{
        "format":1,"kind":"action","descriptor_base64":b64(w.descriptor_bytes),"prior":revoked_prior,
        "candidate_catalog_base64":b64(w.catalog([])),"now":NOW,
        "actor":{"person_public_key":w.keys.public("alice"),"host_public_key":"-","device_public_key":"-","issuer_id":"-"},
        "action_kind":"policy","unsigned_payload_base64":b64(policy2.payload)},error("device_revoked")))
    return result


def retained_root_cases(w: World) -> list[Case]:
    result=[]
    a=w.original_link()
    comp=PublicObject("activation",w.context_id,b"",a.body,"")
    finite=a.source_objects[1:]+a.new_objects
    root1=w.statement("root_state",{"epoch":1,"predecessors":[w.genesis.statement_id],"resolves":[],
        "migration_proposal_id":"-","root_public_key":w.keys.public("next-root"),"issued_at":"2026-10-26T12:00:01Z",
        "retained_statement_ids":sorted(o.statement_id for o in finite)},
        [("issuer","root","ed25519"),("new_root","next-root","ed25519")])
    objects=unique_objects(a.source_objects+a.new_objects+[comp,root1])
    augmented=copy.copy(a)
    augmented.source_objects=a.source_objects+[comp,root1]
    expected,bounds=activation_observation(w,augmented)
    request={"format":1,"kind":"activation","descriptor_base64":b64(w.descriptor_bytes),"prior":"-",
        "catalog_base64":b64(w.catalog(objects)),"activation_base64":b64(a.body),
        "now":"2026-10-26T12:00:02Z","expected":a.expected}
    result.append(Case("retained_root/cold_complete_activation_keeps_only_exact_endorsed_root_contribution",request,expected,array_bounds=bounds))
    _,known=activation_objects_prior(w,a)
    maxima=[m for m in known["maxima"] if m["stream"] != ["root"]]+[maximum(["root"],1,[root1])]
    next_prior=w.prior(objects,maxima,root_ids=[root1.statement_id],activations=[a.activation_id],clock_guard="2026-10-26T12:00:02Z")
    rows=[stream_row(m["stream"],m["sequence"],m["head_ids"]) for m in maxima if m["stream"] != ["root"]]
    result.append(Case("retained_root/cold_projection_admits_retained_finite_closure_under_r1",{
        "format":1,"kind":"projection","descriptor_base64":b64(w.descriptor_bytes),"prior":"-",
        "candidate_catalog_base64":b64(w.catalog(objects)),"now":"2026-10-26T12:00:02Z","operation":"repair"},
        {"ok":True,"context_id":w.context_id,"decision_time":"2026-10-26T12:00:02Z",
         "root":{"head_ids":[root1.statement_id],"maximum":1,"selected_id":root1.statement_id,
                 "conflicted":False,"code":"-","required_ids":[]},
         "streams":sorted(rows,key=lambda row:row["stream"]),"restrictions":[],"inert_statement_ids":[],"next_prior":next_prior}))
    def root_for(child, *, omit: list[str] | None = None, issued_at: str = "2026-10-26T12:00:01Z"):
        finite=child.source_objects[1:]+child.new_objects
        return w.statement("root_state",{"epoch":1,"predecessors":[w.genesis.statement_id],"resolves":[],
            "migration_proposal_id":"-","root_public_key":w.keys.public("next-root"),"issued_at":issued_at,
            "retained_statement_ids":sorted(o.statement_id for o in finite if o.statement_id not in set(omit or []))},
            [("issuer","root","ed25519"),("new_root","next-root","ed25519")])
    def denied(name: str, child, r1: PublicObject, code: str = "forbidden", *, now: str = "2026-10-26T12:00:02Z"):
        cp=PublicObject("activation",w.context_id,b"",child.body,"")
        catalog=unique_objects(child.source_objects+child.new_objects+[cp,r1])
        result.append(Case("retained_root/"+name,{"format":1,"kind":"activation",
            "descriptor_base64":b64(w.descriptor_bytes),"prior":"-","catalog_base64":b64(w.catalog(catalog)),
            "activation_base64":b64(child.body),"now":now,"expected":child.expected},error(code)))
    denied("omitted_device_retention_is_not_implicit_parent_retention",a,root_for(a,omit=[a.device.statement_id]))
    omitted_person=root_for(a,omit=[a.source_objects[1].statement_id])
    denied("complete_bytes_prove_missing_retired_person_contribution",a,omitted_person)
    future=w.original_link(target_host="host-future",target_device="device-future",created_at="2026-10-26T12:00:02Z")
    denied("child_issued_after_transition_cannot_be_retained",future,root_for(future),now="2026-10-26T12:00:03Z")
    short=w.original_link(not_after="2026-10-26T12:00:01Z")
    denied("retained_device_keeps_original_hard_expiry",short,root_for(short,issued_at=NOW),"authority_expired")
    # The exact same invalid finite retention cannot undo a valid root-key
    # transition or erase previously admitted unavailable heads/maxima.
    warm_objects,warm_prior=activation_objects_prior(w,a)
    warm_maxima=[m for m in warm_prior["maxima"] if m["stream"] != ["root"]]+[maximum(["root"],1,[omitted_person])]
    warm_next=w.prior(warm_objects+[omitted_person],warm_maxima,root_ids=[omitted_person.statement_id],
        activations=[a.activation_id],clock_guard="2026-10-26T12:00:02Z")
    warm_rows=[stream_row(m["stream"],m["sequence"],m["head_ids"],
        code="-" if m["stream"][0]=="host" else "forbidden") for m in warm_maxima if m["stream"] != ["root"]]
    result.append(Case("retained_root/ineligible_retention_keeps_valid_root_and_old_inactive_maxima",{
        "format":1,"kind":"projection","descriptor_base64":b64(w.descriptor_bytes),"prior":warm_prior,
        "candidate_catalog_base64":b64(w.catalog([omitted_person])),"now":"2026-10-26T12:00:02Z","operation":"fresh"},
        {"ok":True,"context_id":w.context_id,"decision_time":"2026-10-26T12:00:02Z",
         "root":{"head_ids":[omitted_person.statement_id],"maximum":1,"selected_id":omitted_person.statement_id,
                 "conflicted":False,"code":"-","required_ids":[]},
         "streams":sorted(warm_rows,key=lambda row:row["stream"]),"restrictions":[],"inert_statement_ids":[],"next_prior":warm_next}))
    return result


def root_origin_cases(w: World) -> list[Case]:
    """A signed root edge cannot replace an authenticated context origin."""
    now = "2026-10-26T12:00:02Z"
    missing_proposal = "ds_" + sha(b"independent missing migration origin")
    fake = w.statement("root_state", changed(w.genesis_payload,
        migration_proposal_id=missing_proposal, root_public_key=w.keys.public("origin-attacker")),
        [("issuer", "origin-attacker", "ed25519")])
    def transition(parent: PublicObject, old: str, new: str) -> PublicObject:
        return w.statement("root_state", {"epoch": 1, "predecessors": [parent.statement_id],
            "resolves": [], "migration_proposal_id": "-", "root_public_key": w.keys.public(new),
            "issued_at": NOW, "retained_statement_ids": []},
            [("issuer", old, "ed25519"), ("new_root", new, "ed25519")])
    actual_next = transition(w.genesis, "root", "next-root")
    fake_next = transition(fake, "origin-attacker", "origin-attacker-next")
    def person(root: PublicObject, signer: str) -> PublicObject:
        return w.statement("person_lease", w.lease_payload("person_lease", root_state_id=root.statement_id),
                           [("issuer", signer, "ed25519")])
    genuine_person = person(actual_next, "next-root")
    fake_person = person(fake_next, "origin-attacker-next")
    genuine = [w.genesis, actual_next, genuine_person]
    person_stream = ["person", w.keys.public("alice")]
    genuine_prior = w.prior(genuine, [maximum(["root"], 1, [actual_next]),
        maximum(person_stream, 1, [genuine_person])], root_ids=[actual_next.statement_id], clock_guard=now)
    def project(name: str, objects: list[PublicObject], observation: dict) -> Case:
        return Case("root_origin/" + name, {"format": 1, "kind": "projection",
            "descriptor_base64": b64(w.descriptor_bytes), "prior": "-",
            "candidate_catalog_base64": b64(w.catalog(objects)), "now": now, "operation": "repair"}, observation)
    denial = error("proof_required", [missing_proposal])
    result = [project("normal_transition_reaches_actual_descriptor_genesis", genuine,
        {"ok": True, "context_id": w.context_id, "decision_time": now,
         "root": {"head_ids": [actual_next.statement_id], "maximum": 1, "selected_id": actual_next.statement_id,
                  "conflicted": False, "code": "-", "required_ids": []},
         "streams": [stream_row(person_stream, 1, [genuine_person])], "restrictions": [],
         "inert_statement_ids": [], "next_prior": genuine_prior}),
        project("migration_label_without_complete_origin_is_not_root_authority", [fake], denial),
        project("successor_cannot_launder_unverified_migration_origin", [fake, fake_next, fake_person], denial)]
    result.append(Case("root_origin/attacker_successor_cannot_authorize_fresh_root_action", {
        "format": 1, "kind": "action", "descriptor_base64": b64(w.descriptor_bytes), "prior": "-",
        "candidate_catalog_base64": b64(w.catalog([fake, fake_next])), "now": now,
        "actor": {"person_public_key": "-", "host_public_key": "-", "device_public_key": "-",
                  "issuer_id": fake_next.statement_id}, "action_kind": "person_lease",
        "unsigned_payload_base64": b64(fake_person.payload)}, denial))
    for case in result:
        case.oracle_pin = "4ce8aabebf90acd2240c9226de726838336009b3"
    return result


def retention_time_cases(w: World) -> list[Case]:
    """Retention needs a live prior contribution at every actual replacement."""
    t1, t2, t3 = ["2026-10-26T12:00:0" + str(n) + "Z" for n in (1, 2, 3)]
    person = w.statement("person_lease", w.lease_payload("person_lease"), [("issuer", "root", "ed25519")])
    future_host = w.statement("host_lease", w.lease_payload("host_lease", not_before=t2),
        [("issuer", "root", "ed25519"), ("host", "host-a", "ed25519")])
    def rotate(epoch: int, previous: PublicObject, old: str, new: str,
               retained: list[PublicObject], issued: str) -> PublicObject:
        return w.statement("root_state", {"epoch": epoch, "predecessors": [previous.statement_id],
            "resolves": [], "migration_proposal_id": "-", "root_public_key": w.keys.public(new),
            "issued_at": issued, "retained_statement_ids": sorted(o.statement_id for o in retained)},
            [("issuer", old, "ed25519"), ("new_root", new, "ed25519")])
    early_root = rotate(1, w.genesis, "root", "next-root", [person, future_host], t1)
    future_prior = w.prior([w.genesis, person, future_host, early_root],
        [maximum(["root"], 1, [early_root]), maximum(["person", w.keys.public("alice")], 1, [person])],
        root_ids=[early_root.statement_id], clock_guard=t1,
        admitted_ids=[w.genesis.statement_id, person.statement_id, early_root.statement_id])
    binding = w.lease_payload("binding_lease", root_state_id=early_root.statement_id,
        issuer={"kind": "person", "person_public_key": w.keys.public("alice")},
        parents=sorted([{"role": "issuer_person", "id": person.statement_id},
                        {"role": "subject_person", "id": person.statement_id},
                        {"role": "subject_host", "id": future_host.statement_id}], key=lambda p:p["role"]),
        issued_at=t3, not_before=t3)
    action = {
        "format": 1, "kind": "action", "descriptor_base64": b64(w.descriptor_bytes), "prior": future_prior,
        "candidate_catalog_base64": b64(w.catalog([])), "now": t3,
        "actor": {"person_public_key": w.keys.public("alice"), "host_public_key": "-",
                  "device_public_key": "-", "issuer_id": "-"},
        "action_kind": "binding_lease", "unsigned_payload_base64": b64(raw_json(binding))}
    missing = changed(future_prior, catalog_base64=b64(w.catalog([w.genesis, person, early_root])))
    result = [Case("retention_time/not_yet_live_at_retaining_transition_cannot_activate_later", action, error("forbidden")),
              Case("retention_time/missing_retained_parent_still_requests_exact_bytes",
                   changed(action, prior=missing), error("proof_required", [future_host.statement_id]))]
    live_host = w.statement("host_lease", w.lease_payload("host_lease"),
        [("issuer", "root", "ed25519"), ("host", "host-a", "ed25519")])
    first = rotate(1, w.genesis, "root", "next-root", [live_host], t1)
    second = rotate(2, first, "next-root", "second-root", [live_host], t2)
    before = [w.genesis, live_host, first]
    prior = w.prior(before, [maximum(["root"], 1, [first]),
        maximum(["host", w.keys.public("host-a")], 1, [live_host])], root_ids=[first.statement_id], clock_guard=t1)
    after = w.prior(before + [second], [maximum(["root"], 2, [second]),
        maximum(["host", w.keys.public("host-a")], 1, [live_host])], root_ids=[second.statement_id], clock_guard=t3)
    result.append(Case("retention_time/second_rotation_can_explicitly_carry_still_live_old_root_host", {
        "format": 1, "kind": "projection", "descriptor_base64": b64(w.descriptor_bytes), "prior": prior,
        "candidate_catalog_base64": b64(w.catalog([second])), "now": t3, "operation": "fresh"},
        {"ok": True, "context_id": w.context_id, "decision_time": t3,
         "root": {"head_ids": [second.statement_id], "maximum": 2, "selected_id": second.statement_id,
                  "conflicted": False, "code": "-", "required_ids": []},
         "streams": [stream_row(["host", w.keys.public("host-a")], 1, [live_host])],
         "restrictions": [], "inert_statement_ids": [], "next_prior": after}))
    return result


def administrator_stage_cases(w: World) -> list[Case]:
    result = []
    admin = w.statement("admin_lease",w.lease_payload("admin_lease",person="quinn"),[("issuer","root","ed25519")])
    existing_h = w.statement("host_lease",w.lease_payload("host_lease",host="host-b"),
        [("issuer","root","ed25519"),("host","host-b","ed25519")])
    def build(scopes: int, *, deadline: str = UNTIL, revoked: bool = False):
        q = w.original_link(person="quinn",owner_host="host-q-owner",target_host="host-q",target_device="device-q",
            scopes=scopes,not_after=deadline,additional_proof_objects=[admin])
        q_composite = PublicObject("activation",w.context_id,b"",q.body,"")
        q_archive = unique_objects(q.source_objects+q.new_objects+[q_composite,admin])
        q_person = next(o for o in q.source_objects if o.kind=="person_lease")
        role = {"writer":"host-q","signer":"device-q","person":"quinn","issuer_id":q.device.statement_id,
                "signature_format":"ed25519","issuer_lease_ids":[q_person.statement_id,admin.statement_id,q.device.statement_id]}
        a = w.original_link(current_host=existing_h,administrator_role=role,additional_proof_objects=q_archive)
        objects,prior = known_simple_prior(w,a.source_objects,activations=[q.activation_id])
        if revoked:
            deny = w.statement("device_revoke",{"root_state_id":w.genesis.statement_id,
                "issuer":{"kind":"person","person_public_key":w.keys.public("quinn")},
                "parents":[{"role":"issuer_person","id":q_person.statement_id}],"issued_at":NOW,
                "target":{"statement_id":"-","person_public_key":w.keys.public("quinn"),
                          "host_public_key":"-","device_public_key":w.keys.public("device-q")},
                "kept_statement_ids":[],"ratifies":"-"},[("issuer","quinn","sshsig")])
            objects,prior = known_simple_prior(w,objects+[deny],activations=[q.activation_id],restrictions=[deny.statement_id])
        extra_ds = [o.statement_id for o in q.new_objects]+[q_person.statement_id,admin.statement_id]
        return a,objects,prior,extra_ds
    def add(name: str, a, objects, prior, expected: dict, *, now: str = NOW, bounds=None):
        result.append(Case("administrator_stage/"+name,{"format":1,"kind":"activation",
            "descriptor_base64":b64(w.descriptor_bytes),"prior":prior,
            "catalog_base64":b64(w.catalog(unique_objects(objects+a.new_objects))),"activation_base64":b64(a.body),
            "now":now,"expected":a.expected},expected,array_bounds=bounds))
    a,objects,prior,extra_ds = build(8)
    # PR95 fixes the minimum to D plus its signed manifest ancestors.  Quinn's
    # separate packet-issuer DS values remain permitted verified additions;
    # every exact Quinn proof remains manifest-pinned and mandatory below.
    expected,bounds = activation_observation(w,a)
    add("new_with_current_person_host_refs_still_has_valid_admin8_stage",a,objects,prior,expected,bounds=bounds)
    a,objects,prior,_ = build(7)
    add("live_owner_cannot_bypass_wrong_scope_admin_packet",a,objects,prior,error("forbidden"))
    a,objects,prior,_ = build(8,deadline="2026-10-26T12:00:01Z")
    add("live_owner_cannot_bypass_expired_admin_packet",a,objects,prior,error("authority_expired"),now="2026-10-26T12:00:02Z")
    a,objects,prior,_ = build(8,revoked=True)
    add("live_owner_cannot_bypass_revoked_admin_packet",a,objects,prior,error("device_revoked"))
    return result


def action_cases(w: World) -> list[Case]:
    result = []
    activation = w.original_link(scopes=7)
    objects, prior = activation_objects_prior(w, activation)
    person = activation.source_objects[1]
    target_host, binding, device = activation.new_objects
    original_actor = {"person_public_key": w.keys.public("alice"), "host_public_key": "-",
                      "device_public_key": "-", "issuer_id": "-"}
    root_actor = {"person_public_key": "-", "host_public_key": "-", "device_public_key": "-",
                  "issuer_id": w.genesis.statement_id}
    device_actor = {"person_public_key": w.keys.public("alice"), "host_public_key": w.keys.public("host-b"),
                    "device_public_key": w.keys.public("device-b"), "issuer_id": device.statement_id}
    def success(issuer: str, signer: str, direct: list[str], deadline: str = UNTIL) -> dict:
        return {"ok": True, "context_id": w.context_id, "decision_time": NOW, "issuer_id": issuer,
                "signer_public_key": w.keys.public(signer), "required_parent_ids": sorted(set(direct)),
                "effective_not_after": deadline}
    def add(name: str, kind: str, payload: dict | bytes, actor: dict, observation: dict,
            *, local_prior: dict | None = None, now: str = NOW) -> None:
        result.append(Case("action/"+name, {"format": 1, "kind": "action", "descriptor_base64": b64(w.descriptor_bytes),
            "prior": prior if local_prior is None else local_prior, "candidate_catalog_base64": b64(w.catalog([])),
            "now": now, "actor": actor, "action_kind": kind,
            "unsigned_payload_base64": b64(payload if isinstance(payload, bytes) else raw_json(payload))}, observation))
    person2 = w.lease_payload("person_lease", sequence=2, predecessors=[person.statement_id])
    add("root_renews_person", "person_lease", person2, root_actor,
        success(w.genesis.statement_id, "root", [w.genesis.statement_id]))
    admin = w.lease_payload("admin_lease")
    add("root_grants_admin_role", "admin_lease", admin, root_actor,
        success(w.genesis.statement_id, "root", [w.genesis.statement_id]))
    host2 = w.lease_payload("host_lease", host="host-b", sequence=2, predecessors=[target_host.statement_id])
    add("root_host_intent_needs_no_claimed_target_key_ownership", "host_lease", host2, root_actor,
        success(w.genesis.statement_id, "root", [w.genesis.statement_id]))
    group = w.access("group")
    add("root_group", "group", group.payload, root_actor,
        success(w.genesis.statement_id, "root", [w.genesis.statement_id]))
    policy = w.access("policy", person_lease=person)
    add("original_policy", "policy", policy.payload, original_actor,
        success("-", "alice", [w.genesis.statement_id, person.statement_id]))
    device_policy = json.loads(policy.payload)
    device_policy["issuer"] = {"kind": "device", "person_public_key": w.keys.public("alice")}
    device_policy["parents"] = sorted([{"role": "issuer_person", "id": person.statement_id},
                                       {"role": "issuer_device", "id": device.statement_id}], key=lambda p: p["role"])
    add("activated_device_policy_scope1", "policy", device_policy, device_actor,
        success(device.statement_id, "device-b", [w.genesis.statement_id, person.statement_id, device.statement_id]))
    bind2 = w.lease_payload("binding_lease", host="host-b", sequence=2, predecessors=[binding.statement_id],
        issuer={"kind": "person", "person_public_key": w.keys.public("alice")}, parents=[
            {"role": "subject_person", "id": person.statement_id}, {"role": "issuer_person", "id": person.statement_id},
            {"role": "subject_host", "id": target_host.statement_id}])
    add("original_binding_intent_has_external_target_cosignature", "binding_lease", bind2, original_actor,
        success("-", "alice", [w.genesis.statement_id, person.statement_id, target_host.statement_id]))
    # Root target denials require no finite root-identity deadline.
    root_deny = w.restriction("person_remove", person="bob")
    add("root_person_remove", "person_remove", root_deny.payload, root_actor,
        success(w.genesis.statement_id, "root", [w.genesis.statement_id], "-"))
    host_deny = w.restriction("host_revoke", host="host-b")
    add("root_host_revoke", "host_revoke", host_deny.payload, root_actor,
        success(w.genesis.statement_id, "root", [w.genesis.statement_id], "-"))
    unbind = {"root_state_id": w.genesis.statement_id,
              "issuer": {"kind": "person", "person_public_key": w.keys.public("alice")},
              "parents": [{"role": "issuer_person", "id": person.statement_id}], "issued_at": NOW,
              "target": {"statement_id": binding.statement_id, "person_public_key": w.keys.public("alice"),
                         "host_public_key": w.keys.public("host-b"), "device_public_key": "-"},
              "kept_statement_ids": [], "ratifies": "-"}
    add("original_can_unbind_target", "host_unbind", unbind, original_actor,
        success("-", "alice", [w.genesis.statement_id, person.statement_id]))
    self_unbind = changed(unbind, issuer={"kind": "device", "person_public_key": w.keys.public("alice")},
        parents=sorted([{"role": "issuer_person", "id": person.statement_id},
                        {"role": "issuer_device", "id": device.statement_id}], key=lambda p: p["role"]))
    add("device_cannot_disable_its_required_binding", "host_unbind", self_unbind, device_actor,
        error("authority_would_be_invalidated"))
    add("unknown_kind", "not-a-registered-action", person2, root_actor, error("invalid"))
    add("device_issuance_not_an_ordinary_action", "device_lease", device.payload, original_actor, error("invalid"))
    add("duplicate_unsigned_payload_field", "person_lease", raw_json(person2)[:-1]+b',"sequence":2}',
        root_actor, error("invalid"))
    add("clock_rollback", "person_lease", person2, root_actor, error("clock_rollback"), now="2026-10-26T11:54:59Z")
    missing = w.lease_payload("person_lease", sequence=2, predecessors=["ds_"+"a"*64])
    add("missing_stream_predecessor", "person_lease", missing, root_actor, error("proof_required", ["ds_"+"a"*64]))
    # Policy issuance checks the selected device's actual scope, never row/key presence.
    narrow = w.original_link(target_host="host-c", target_device="device-c", scopes=2)
    _, narrow_prior = activation_objects_prior(w, narrow)
    narrow_payload = changed(device_policy, parents=sorted([
        {"role": "issuer_person", "id": person.statement_id},
        {"role": "issuer_device", "id": narrow.device.statement_id}], key=lambda p: p["role"]))
    narrow_actor = {"person_public_key": w.keys.public("alice"), "host_public_key": w.keys.public("host-c"),
                    "device_public_key": w.keys.public("device-c"), "issuer_id": narrow.device.statement_id}
    add("scope2_device_cannot_issue_policy", "policy", narrow_payload, narrow_actor, error("forbidden"), local_prior=narrow_prior)
    # A literal MAX is valid; this operation never claims to test default increment.
    policy1 = w.statement("policy", device_policy, [("issuer", "device-b", "ed25519")])
    policy_stream = ["policy", w.keys.public("alice")]
    with_policy = copy.deepcopy(prior)
    with_policy["catalog_base64"] = b64(w.catalog(objects+[policy1]))
    with_policy["admitted_statement_ids"] = sorted(with_policy["admitted_statement_ids"]+[policy1.statement_id])
    with_policy["maxima"] = sorted(with_policy["maxima"]+[maximum(policy_stream, 1, [policy1])], key=lambda row: row["stream"])
    max_policy = json.loads(w.access("policy", sequence=2**64-1, predecessors=[policy1.statement_id], person_lease=person).payload)
    max_policy["issuer"] = device_policy["issuer"]
    max_policy["parents"] = device_policy["parents"]
    add("literal_max_policy_is_not_default_overflow", "policy", max_policy, device_actor,
        success(device.statement_id, "device-b", [w.genesis.statement_id, person.statement_id, device.statement_id]), local_prior=with_policy)
    # Pure intent accepts only a current root role for an ordinary rotation.
    rotate = {"epoch": 1, "predecessors": [w.genesis.statement_id], "resolves": [], "migration_proposal_id": "-",
              "root_public_key": w.keys.public("next-root"), "issued_at": NOW, "retained_statement_ids": []}
    add("root_transition_intent", "root_state", rotate, root_actor,
        success(w.genesis.statement_id, "root", [w.genesis.statement_id], "-"))
    add("root_actor_unused_person_literal", "person_lease", person2,
        changed(root_actor, person_public_key=w.keys.public("alice")), error("invalid"))
    add("original_actor_unused_host_literal", "policy", policy.payload,
        changed(original_actor, host_public_key=w.keys.public("host-b")), error("invalid"))
    add("original_actor_unused_issuer_literal", "policy", policy.payload,
        changed(original_actor, issuer_id=person.statement_id), error("invalid"))
    return result


def migration_cases(w: World) -> list[Case]:
    result = []
    m = w.unbound_migration()
    public = {"ok": True, "context_id": w.context_id, "proposal_id": m.proposal.statement_id,
        "root_state_id": m.root.statement_id, "prepared_catalog_sha256": sha(m.prepared_catalog),
        "roster_host_public_keys": [w.keys.public("host-a")], "local_approval_matched": False,
        "context_origin_valid": True, "usable_device_lease_ids": [], "inactive_device_lease_ids": []}
    def add(name: str, expected: dict, *, body: bytes = m.body, legacy_prior: dict | str = "-",
            purpose: str = "evidence", local_host: str = "-", now: str = NOW) -> None:
        result.append(Case("migration/"+name, {"format": 1, "kind": "migration",
            "descriptor_base64": b64(w.descriptor_bytes), "legacy_prior": legacy_prior, "prior": "-",
            "migration_base64": b64(body), "now": now, "purpose": purpose,
            "local_host_public_key": local_host}, expected))
    add("unbound_legacy_host_pre_feature_complete_origin", public)
    add("actual_local_acknowledgment_permits_adoption_proposal", changed(public, local_approval_matched=True),
        legacy_prior=m.legacy_prior, purpose="adoption", local_host=w.keys.public("host-a"))
    add("late_complete_origin_is_not_proposal_window_authority", public, now="2026-10-27T12:00:01Z")
    no_approval = changed(m.legacy_prior, acknowledged_proposal_id="-", acknowledged_prepared_sha256="-", acknowledgment_base64="-")
    add("public_complete_proof_cannot_manufacture_local_adoption_consent", error("forbidden"),
        legacy_prior=no_approval, purpose="adoption", local_host=w.keys.public("host-a"))
    add("another_host_acknowledgment_cannot_adopt_for_local_host", error("forbidden"),
        legacy_prior=m.legacy_prior, purpose="adoption", local_host=w.keys.public("host-b"))
    other = w.unbound_migration(nonce_name="other-genuinely-approved-proposal")
    conflict = changed(m.legacy_prior, acknowledged_proposal_id=other.proposal.statement_id,
        acknowledged_prepared_sha256=sha(other.prepared_catalog), acknowledgment_base64=b64(other.acknowledgment.body))
    add("different_durable_proposal_fence_is_not_overwritten", error("state_conflict"),
        legacy_prior=conflict, purpose="adoption", local_host=w.keys.public("host-a"))
    add("local_clock_rollback_blocks_adoption", error("clock_rollback"), legacy_prior=m.legacy_prior,
        purpose="adoption", local_host=w.keys.public("host-a"), now="2026-10-26T11:54:59Z")
    body = json.loads(m.body)
    body["acknowledgments"] = []
    add("missing_exact_host_acknowledgment", error("proof_required", [m.acknowledgment.statement_id]), body=raw_json(body))
    body = json.loads(m.body)
    sig = bytearray(unb64(body["acknowledgments"][0]["signatures"][0]["signature"]))
    sig[0] ^= 1
    body["acknowledgments"][0]["signatures"][0]["signature"] = b64(sig)
    add("forged_host_acknowledgment", error("invalid"), body=raw_json(body))
    body = json.loads(m.body)
    sig = bytearray(unb64(body["commit"]["signatures"][0]["signature"]))
    sig[0] ^= 1
    body["commit"]["signatures"][0]["signature"] = b64(sig)
    add("forged_final_current_legacy_root_commit", error("invalid"), body=raw_json(body))
    # Source-state endorsement covers the exact snapshot bytes, even when its
    # values appear plausible and all other source proofs remain unchanged.
    body = json.loads(m.body)
    state = json.loads(m.source_state)
    state["legacy_root_highwater"] = 1
    body["source_state_base64"] = b64(raw_json(state))
    add("source_state_hash_cannot_be_replaced", error("invalid"), body=raw_json(body))
    body = json.loads(m.body)
    body["prepared_catalog_base64"] = b64(w.catalog([m.proposal, m.root]))
    add("prepared_catalog_hash_cannot_omit_host_consent", error("invalid"), body=raw_json(body))
    return result


def migration_source_authority_cases(w: World) -> list[Case]:
    """Raw legacy proof presence is separate from actual inherited authority.

    Public migration section2 reissues active stable-key bans; legacy admin
    removal retains only explicitly listed exact statement-message digests.
    A signed inactive proof remains exact source evidence without a new ban.
    """
    result = []
    for kind in ("person_removal", "host_revocation"):
        for kept, copy_ban, suffix in [
            (False, False, "withdrawn_unkept_raw_proof_is_not_permanent_ban"),
            (True, True, "explicitly_kept_active_ban_is_copied"),
            (True, False, "explicitly_kept_active_ban_cannot_be_omitted"),
        ]:
            m = w.legacy_restriction_migration(kind, kept=kept, copy_ban=copy_ban)
            expected = ({"ok": True, "context_id": w.context_id, "proposal_id": m.proposal.statement_id,
                "root_state_id": m.root.statement_id, "prepared_catalog_sha256": sha(m.prepared_catalog),
                "roster_host_public_keys": [item["host_public_key"] for item in json.loads(m.proposal.payload)["roster"]],
                "local_approval_matched": False, "context_origin_valid": True,
                "usable_device_lease_ids": [], "inactive_device_lease_ids": []}
                if not kept or copy_ban else error("forbidden"))
            result.append(Case("migration_source_authority/"+kind+"/"+suffix,
                {"format": 1, "kind": "migration", "descriptor_base64": b64(w.descriptor_bytes),
                 "legacy_prior": "-", "prior": "-", "migration_base64": b64(m.body),
                 "now": NOW, "purpose": "evidence", "local_host_public_key": "-"}, expected,
                oracle_pin="0ea487eba4134b851c87816b7d54776f7b8bee31" if not kept or copy_ban else
                           "dada7fcedc4a215f79a78e08f2bedfa14e374931"))
    return result


def migration_sticky_restriction_cases(w: World) -> list[Case]:
    """A previously admitted stable ban stays sticky despite its lost role.

    The original raw source bytes and unkept withdrawal match the inactive
    control. Only the exact endorsed admitted-restrictions entry establishes
    the separately required inherited stable-ban history.
    """
    result = []
    for copy_ban, suffix in [(True, "previously_admitted_unkept_ban_is_copied"),
                              (False, "previously_admitted_unkept_ban_cannot_be_omitted")]:
        m = w.legacy_restriction_migration("person_removal", kept=False, admitted=True, copy_ban=copy_ban)
        expected = ({"ok": True, "context_id": w.context_id, "proposal_id": m.proposal.statement_id,
            "root_state_id": m.root.statement_id, "prepared_catalog_sha256": sha(m.prepared_catalog),
            "roster_host_public_keys": [w.keys.public("host-a")], "local_approval_matched": False,
            "context_origin_valid": True, "usable_device_lease_ids": [], "inactive_device_lease_ids": []}
            if copy_ban else error("forbidden"))
        result.append(Case("migration_sticky_restriction/"+suffix,
            {"format": 1, "kind": "migration", "descriptor_base64": b64(w.descriptor_bytes),
             "legacy_prior": "-", "prior": "-", "migration_base64": b64(m.body),
             "now": NOW, "purpose": "evidence", "local_host_public_key": "-"}, expected,
            oracle_pin="dada7fcedc4a215f79a78e08f2bedfa14e374931"))
    return result


def migration_source_budget_cases(w: World) -> list[Case]:
    """Independent decoded source-state cap at both public ingress modes."""
    result = []
    for size, suffix in [(256 * 1024, "exact_256KiB"), (256 * 1024 + 1, "over_256KiB")]:
        migration = w.unbound_migration(nonce_name="source-state-boundary", source_state_size=size)
        if len(migration.source_state) != size or len(migration.body) > 1024 * 1024:
            raise RuntimeError("source budget fixture hit an unrelated object boundary")
        obj = PublicObject("migration", w.context_id, b"", migration.body, "")
        catalog_expected = ({"ok": True, "context_id": w.context_id, "proof_ids": [obj.proof_id]}
                            if size == 256 * 1024 else error("quota_exceeded"))
        result.append(Case("migration_source_budget/catalog_" + suffix,
            {"format": 1, "kind": "catalog", "descriptor_base64": b64(w.descriptor_bytes),
             "catalog_base64": b64(w.catalog([obj]))}, catalog_expected))
        migration_expected = ({"ok": True, "context_id": w.context_id,
            "proposal_id": migration.proposal.statement_id, "root_state_id": migration.root.statement_id,
            "prepared_catalog_sha256": sha(migration.prepared_catalog),
            "roster_host_public_keys": [w.keys.public("host-a")], "local_approval_matched": False,
            "context_origin_valid": True, "usable_device_lease_ids": [], "inactive_device_lease_ids": []}
            if size == 256 * 1024 else error("quota_exceeded"))
        result.append(Case("migration_source_budget/complete_" + suffix,
            {"format": 1, "kind": "migration", "descriptor_base64": b64(w.descriptor_bytes),
             "legacy_prior": "-", "prior": "-", "migration_base64": b64(migration.body),
             "now": NOW, "purpose": "evidence", "local_host_public_key": "-"}, migration_expected))
    return result


def migration_origin_cases(w: World) -> list[Case]:
    """Ordinary state projection learns origin without local adoption consent."""
    migration = w.unbound_migration()
    proof = PublicObject("migration", w.context_id, b"", migration.body, "")
    root_max = maximum(["root"], 0, [migration.root])
    host_stream = ["host", w.keys.public("host-a")]
    host_max = maximum(host_stream, 1, [migration.host])
    root = {"head_ids": [migration.root.statement_id], "maximum": 0,
            "selected_id": migration.root.statement_id, "conflicted": False,
            "code": "-", "required_ids": []}
    def prior(live_host: bool) -> dict:
        value = w.prior([proof], [root_max, host_max] if live_host else [root_max],
            root_ids=[migration.root.statement_id],
            admitted_ids=[migration.root.statement_id, migration.host.statement_id]
                         if live_host else [migration.root.statement_id])
        value["migration_proposal_id"] = migration.proposal.statement_id
        return value
    def expected(next_prior: dict, streams: list[dict], *, now: str = NOW,
                 inert: list[str] | None = None) -> dict:
        return {"ok": True, "context_id": w.context_id, "decision_time": now, "root": root,
                "streams": streams, "restrictions": [], "inert_statement_ids": sorted(inert or []),
                "next_prior": next_prior}
    def add(name: str, objects: list[PublicObject] | str, observation: dict, *, now: str = NOW,
            local_prior: dict | str = "-", operation: str = "repair") -> Case:
        return Case("migration_origin/" + name, {"format": 1, "kind": "projection",
            "descriptor_base64": b64(w.descriptor_bytes), "prior": local_prior,
            "candidate_catalog_base64": objects if isinstance(objects, str) else b64(w.catalog(objects)),
            "now": now, "operation": operation}, observation)
    late = "2026-10-27T12:00:01Z"
    inactive_prior = prior(False)
    inactive_prior["clock_guard"] = late
    bad = json.loads(migration.body)
    signature = bytearray(unb64(bad["acknowledgments"][0]["signatures"][0]["signature"]))
    signature[0] ^= 1
    bad["acknowledgments"][0]["signatures"][0]["signature"] = b64(signature)
    forged = PublicObject("migration", w.context_id, b"", raw_json(bad), "")
    return [
        add("cold_complete_unbound_origin_and_live_host", [proof],
            expected(prior(True), [stream_row(host_stream, 1, [migration.host])])),
        add("late_complete_origin_without_expired_new_host_admission", [proof],
            expected(inactive_prior, [], now=late, inert=[migration.host.statement_id]), now=late),
        add("prior_admitted_expired_host_keeps_exact_head_and_max", "-",
            expected(prior(True), [stream_row(host_stream, 1, [migration.host], code="authority_expired")], now=late),
            now=late, local_prior=prior(True), operation="read"),
        add("forged_host_ack_is_not_a_cold_origin", [forged], error("invalid")),
    ]


def migration_current_cases(w: World) -> list[Case]:
    """Exact original M remains origin evidence, never a newer-state reset."""
    m = w.owned_migration()
    a = m.activation
    if a is None:
        raise ValueError("owned migration fixture omitted its complete activation")
    person, host, binding, device = a.source_objects[1], *a.new_objects
    proof = PublicObject("migration", w.context_id, b"", m.body, "")
    base_maxima = [maximum(["root"], 0, [m.root]),
        maximum(["person", w.keys.public("alice")], 1, [person]),
        maximum(["host", w.keys.public("host-a")], 1, [host]),
        maximum(["binding", w.keys.public("host-a")], 1, [binding]),
        maximum(["device", w.keys.public("alice"), w.keys.public("device-a")], 1, [device])]
    admitted = [m.root.statement_id, person.statement_id, host.statement_id, binding.statement_id, device.statement_id]
    def local_prior(extra: list[PublicObject], maxima: list[dict], restrictions: list[str] | None = None) -> dict:
        value = w.prior([proof] + extra, maxima, root_ids=[m.root.statement_id],
            admitted_ids=admitted + [o.statement_id for o in extra if o.kind != "device_revoke"],
            activations=[a.activation_id], restrictions=restrictions, clock_guard="2026-10-26T12:00:01Z")
        value["migration_proposal_id"] = m.proposal.statement_id
        return value
    public = {"ok": True, "context_id": w.context_id, "proposal_id": m.proposal.statement_id,
        "root_state_id": m.root.statement_id, "prepared_catalog_sha256": sha(m.prepared_catalog),
        "roster_host_public_keys": [w.keys.public("host-a")], "local_approval_matched": False,
        "context_origin_valid": True, "usable_device_lease_ids": [device.statement_id], "inactive_device_lease_ids": []}
    def case(name: str, prior: dict | str, usable: bool, *, now: str = NOW) -> Case:
        return Case("migration_current/" + name, {"format": 1, "kind": "migration",
            "descriptor_base64": b64(w.descriptor_bytes), "legacy_prior": "-", "prior": prior,
            "migration_base64": b64(m.body), "now": now, "purpose": "evidence", "local_host_public_key": "-"},
            public if usable else changed(public, usable_device_lease_ids=[], inactive_device_lease_ids=[device.statement_id]))
    deny = w.statement("device_revoke", {"root_state_id": m.root.statement_id,
        "issuer": {"kind": "person", "person_public_key": w.keys.public("alice")},
        "parents": [{"role": "issuer_person", "id": person.statement_id}], "issued_at": "2026-10-26T12:00:01Z",
        "target": {"statement_id": "-", "person_public_key": w.keys.public("alice"),
                   "host_public_key": "-", "device_public_key": w.keys.public("device-a")},
        "kept_statement_ids": [], "ratifies": "-"}, [("issuer", "alice", "sshsig")])
    newer_host = w.statement("host_lease", w.lease_payload("host_lease", root_state_id=m.root.statement_id,
        sequence=2, predecessors=[host.statement_id], issued_at="2026-10-26T12:00:01Z", not_before="2026-10-26T12:00:01Z"),
        [("issuer", "root", "ed25519"), ("host", "host-a", "ed25519")])
    newer_maxima = [row for row in base_maxima if row["stream"][0] != "host"] + [
        maximum(["host", w.keys.public("host-a")], 2, [newer_host])]
    return [case("complete_bound_same_key_origin_has_reviewed_live_device", "-", True),
        case("exact_original_origin_cannot_undo_known_device_revocation",
             local_prior([deny], base_maxima, [deny.statement_id]), False, now="2026-10-26T12:00:02Z"),
        case("exact_original_origin_cannot_replace_newer_host_head",
             local_prior([newer_host], newer_maxima), False, now="2026-10-26T12:00:02Z")]


def migration_conflict_cases(w: World) -> list[Case]:
    """Individually complete all-host histories have no arrival-order winner."""
    original = w.unbound_migration()
    distinct = w.unbound_migration(nonce_name="competing-complete-origin")
    alternative = w.unbound_migration(host_not_after="2026-10-27T11:00:00Z")
    if alternative.proposal.body != original.proposal.body or sha(alternative.prepared_catalog) == sha(original.prepared_catalog):
        raise ValueError("same-proposal conflict fixture changed proposal or failed to change prepared state")
    def prior(m) -> dict:
        proof = PublicObject("migration", w.context_id, b"", m.body, "")
        value = w.prior([proof], [maximum(["root"], 0, [m.root]),
            maximum(["host", w.keys.public("host-a")], 1, [m.host])], root_ids=[m.root.statement_id],
            admitted_ids=[m.root.statement_id, m.host.statement_id])
        value["migration_proposal_id"] = m.proposal.statement_id
        return value
    def observation(m) -> dict:
        return {"ok": True, "context_id": w.context_id, "proposal_id": m.proposal.statement_id,
            "root_state_id": m.root.statement_id, "prepared_catalog_sha256": sha(m.prepared_catalog),
            "roster_host_public_keys": [w.keys.public("host-a")], "local_approval_matched": False,
            "context_origin_valid": True, "usable_device_lease_ids": [], "inactive_device_lease_ids": []}
    def case(name: str, incoming, remembered=None) -> Case:
        return Case("migration_conflict/" + name, {"format": 1, "kind": "migration",
            "descriptor_base64": b64(w.descriptor_bytes), "legacy_prior": "-",
            "prior": "-" if remembered is None else prior(remembered), "migration_base64": b64(incoming.body),
            "now": NOW, "purpose": "evidence", "local_host_public_key": "-"},
            observation(incoming) if remembered is None else error("state_conflict"))
    return [case("different_proposal_is_individually_complete", distinct),
            case("same_proposal_alternative_prepared_state_is_individually_complete", alternative),
            case("different_complete_proposal_freezes_original_origin", distinct, original),
            case("original_complete_proposal_cannot_replace_other_known_origin", original, distinct),
            case("same_proposal_changed_prepared_hash_freezes_original", alternative, original),
            case("same_proposal_original_hash_cannot_replace_alternative", original, alternative)]


def migration_action_conflict_cases(w: World) -> list[Case]:
    """Ordinary action cannot bypass a complete competing context origin."""
    original = w.unbound_migration()
    distinct = w.unbound_migration(nonce_name="competing-complete-origin")
    alternative = w.unbound_migration(host_not_after="2026-10-27T11:00:00Z")
    def case(name: str, remembered, incoming=None) -> Case:
        proof = PublicObject("migration", w.context_id, b"", remembered.body, "")
        prior = w.prior([proof], [maximum(["root"], 0, [remembered.root]),
            maximum(["host", w.keys.public("host-a")], 1, [remembered.host])],
            root_ids=[remembered.root.statement_id],
            admitted_ids=[remembered.root.statement_id, remembered.host.statement_id])
        prior["migration_proposal_id"] = remembered.proposal.statement_id
        candidate = [] if incoming is None else [PublicObject("migration", w.context_id, b"", incoming.body, "")]
        expected = error("state_conflict") if incoming is not None else {
            "ok": True, "context_id": w.context_id, "decision_time": NOW,
            "issuer_id": remembered.root.statement_id, "signer_public_key": w.keys.public("root"),
            "required_parent_ids": [remembered.root.statement_id], "effective_not_after": UNTIL}
        return Case("migration_action_conflict/" + name, {"format": 1, "kind": "action",
            "descriptor_base64": b64(w.descriptor_bytes), "prior": prior,
            "candidate_catalog_base64": b64(w.catalog(candidate)), "now": NOW,
            "actor": {"person_public_key": "-", "host_public_key": "-", "device_public_key": "-",
                      "issuer_id": remembered.root.statement_id}, "action_kind": "person_lease",
            "unsigned_payload_base64": b64(raw_json(w.lease_payload("person_lease", root_state_id=remembered.root.statement_id)))}, expected)
    return [case("unopposed_known_origin_allows_exact_current_root_action", original),
            case("different_complete_proposal_blocks_original_root_action", original, distinct),
            case("original_complete_proposal_blocks_other_root_action", distinct, original),
            case("same_proposal_changed_prepared_hash_blocks_root_action", original, alternative),
            case("same_proposal_original_hash_blocks_alternative_root_action", alternative, original)]


def fixed_action_time_cases(w: World) -> list[Case]:
    """Revalidation never rewrites a fixed unsigned intent's issued_at."""
    pin = "57b0aed9553fa1d49bb237b1caee6a4c6ed451f9"
    baseline = next(c for c in action_cases(w) if c.name == "action/root_grants_admin_role")
    result = []
    for suffix, now, allowed in [
        ("one_second_after_issue", "2026-10-26T12:00:01Z", True),
        ("exact_300_seconds_after_issue", "2026-10-26T12:05:00Z", True),
        ("301_seconds_after_issue", "2026-10-26T12:05:01Z", False)]:
        request = changed(baseline.request, now=now)
        expected = changed(baseline.expected, decision_time=now) if allowed else error("expired")
        result.append(Case("fixed_action_time/"+suffix, request, expected, oracle_pin=pin))
    future = json.loads(unb64(baseline.request["unsigned_payload_base64"]))
    future["issued_at"] = future["not_before"] = "2026-10-26T12:00:02Z"
    result.append(Case("fixed_action_time/unsigned_future_issue_is_invalid", changed(baseline.request,
        now="2026-10-26T12:00:01Z", unsigned_payload_base64=b64(raw_json(future))), error("invalid"), oracle_pin=pin))
    delayed = json.loads(unb64(baseline.request["unsigned_payload_base64"]))
    delayed["not_before"] = "2026-10-26T12:00:02Z"
    result.append(Case("fixed_action_time/current_issued_payload_before_own_not_before_is_denied", changed(baseline.request,
        now="2026-10-26T12:00:01Z", unsigned_payload_base64=b64(raw_json(delayed))),
        error("not_yet_valid"), oracle_pin=pin))
    return result


def retained_device_scope_cases(w: World, scopes: int = 7) -> list[Case]:
    """A narrowed device head caps an already activated delegated child's power."""
    parent = w.original_link(scopes=15)
    child = w.original_link(owner_host="host-b", target_host="host-c", target_device="device-c",
                            scopes=15, owner_device=parent, created_at="2026-10-26T12:00:01Z")
    renewed = w.retaining_device_renewal(parent, child, scopes=scopes)
    result = []
    for name, activation, now in [
        ("complete_child_has_exact_scope15_owner_consent", child, "2026-10-26T12:00:01Z"),
        (f"complete_parent_narrows_to{scopes}_and_retains_exact_child", renewed, "2026-10-26T12:00:02Z")]:
        expected, bounds = activation_observation(w, activation)
        result.append(Case("retained_device_scope/"+name, {"format": 1, "kind": "activation", "prior": "-",
            "descriptor_base64": b64(w.descriptor_bytes),
            "catalog_base64": b64(w.catalog(unique_objects(activation.source_objects+activation.new_objects))),
            "activation_base64": b64(activation.body), "now": now, "expected": activation.expected},
            expected, array_bounds=bounds))
    p = parent.source_objects[1]
    admin = w.statement("admin_lease", w.lease_payload("admin_lease"), [("issuer", "root", "ed25519")])
    before_objects = unique_objects(child.source_objects+child.new_objects+[
        PublicObject("activation", w.context_id, b"", child.body, ""), admin])
    _, before = known_simple_prior(w, before_objects, activations=[parent.activation_id, child.activation_id])
    after_objects = unique_objects(before_objects+renewed.source_objects+renewed.new_objects+[
        PublicObject("activation", w.context_id, b"", renewed.body, "")])
    _, after = known_simple_prior(w, after_objects,
        activations=[parent.activation_id, child.activation_id, renewed.activation_id])
    now = "2026-10-26T12:00:03Z"
    actor = {"person_public_key": w.keys.public("alice"), "host_public_key": w.keys.public("host-c"),
             "device_public_key": w.keys.public("device-c"), "issuer_id": child.device.statement_id}
    def payload(kind: str) -> dict:
        value = json.loads(w.access(kind, person_lease=p).payload)
        value["issued_at"] = value["not_before"] = now
        if kind == "policy":
            body = json.loads(unb64(value["body_base64"]))
            body["issued_at"] = now
            value["body_base64"] = b64(raw_json(body))
        else:
            body = json.loads(unb64(value["body_base64"]))
            body["defined_at"] = now
            value["body_base64"] = b64(raw_json(body))
        value["issuer"] = {"kind": "device", "person_public_key": w.keys.public("alice")}
        value["parents"] = sorted([{"role": "issuer_person", "id": p.statement_id},
                                   {"role": "issuer_device", "id": child.device.statement_id}]+
                                  ([{"role": "issuer_admin", "id": admin.statement_id}] if kind == "group" else []),
                                  key=lambda row: row["role"])
        return value
    def add(name: str, kind: str, prior: dict, allowed: bool) -> None:
        body = payload(kind)
        expected = ({"ok": True, "context_id": w.context_id, "decision_time": now,
            "issuer_id": child.device.statement_id, "signer_public_key": w.keys.public("device-c"),
            "required_parent_ids": sorted({w.genesis.statement_id}|{r["id"] for r in body["parents"]}),
            "effective_not_after": UNTIL} if allowed else error("forbidden"))
        result.append(Case("retained_device_scope/"+name, {"format": 1, "kind": "action",
            "descriptor_base64": b64(w.descriptor_bytes), "prior": prior,
            "candidate_catalog_base64": b64(w.catalog([])), "now": now, "actor": actor,
            "action_kind": kind, "unsigned_payload_base64": b64(raw_json(body))}, expected))
    add("child_scope8_works_before_parent_narrowing", "group", before, True)
    add("retained_child_preserves_policy_bit1_after_parent_narrowing", "policy", after, True)
    add("retained_child_loses_admin_bit8_after_parent_narrowing", "group", after, False)
    return result


def retained_delegation_scope_cases(w: World) -> list[Case]:
    """Losing fresh delegation4 does not erase explicitly retained old consent."""
    pin = "fe79e59ff79d51cb0d6abec9d77c5f9b2496ce1c"
    base = retained_device_scope_cases(w, scopes=3)
    result = [c for c in base if c.name.endswith("complete_parent_narrows_to3_and_retains_exact_child") or
              c.name.endswith("retained_child_preserves_policy_bit1_after_parent_narrowing")]
    for case in result:
        case.name = case.name.replace("retained_device_scope/", "retained_delegation_scope/")
        case.oracle_pin = pin
    parent = w.original_link(scopes=15)
    child = w.original_link(owner_host="host-b", target_host="host-c", target_device="device-c",
                            scopes=15, owner_device=parent, created_at="2026-10-26T12:00:01Z")
    narrowed = w.retaining_device_renewal(parent, child, scopes=3)
    fresh = w.original_link(owner_host="host-b", target_host="host-d", target_device="device-d",
                            scopes=1, owner_device=narrowed, created_at="2026-10-26T12:00:03Z")
    objects = unique_objects(narrowed.source_objects+narrowed.new_objects+[
        PublicObject("activation", w.context_id, b"", narrowed.body, "")])
    _, prior = known_simple_prior(w, objects,
        activations=[parent.activation_id, child.activation_id, narrowed.activation_id])
    result.append(Case("retained_delegation_scope/parent3_cannot_authorize_a_fresh_child", {
        "format": 1, "kind": "activation", "descriptor_base64": b64(w.descriptor_bytes), "prior": prior,
        "catalog_base64": b64(w.catalog(unique_objects(fresh.source_objects+fresh.new_objects))),
        "activation_base64": b64(fresh.body), "now": "2026-10-26T12:00:03Z", "expected": fresh.expected},
        error("forbidden"), oracle_pin=pin))
    return result


def ceremony_scope_cases(w: World) -> list[Case]:
    """A separate root admin packet cannot add owner-delegated device scopes."""
    parent = w.original_link(scopes=7)
    result = []
    for scopes, name in [(7, "device7_can_delegate_complete_child7"),
                         (15, "root_admin_cannot_expand_owner_device7_to_child15")]:
        child = w.original_link(owner_host="host-b", target_host="host-c", target_device="device-c",
            scopes=scopes, owner_device=parent, created_at="2026-10-26T12:00:01Z")
        _, prior = known_simple_prior(w, child.source_objects, activations=[parent.activation_id])
        expected, bounds = activation_observation(w, child)
        result.append(Case("ceremony_scope/"+name, {"format": 1, "kind": "activation",
            "descriptor_base64": b64(w.descriptor_bytes), "prior": prior,
            "catalog_base64": b64(w.catalog(unique_objects(child.source_objects+child.new_objects))),
            "activation_base64": b64(child.body), "now": "2026-10-26T12:00:01Z", "expected": child.expected},
            expected if scopes == 7 else error("forbidden"), array_bounds=bounds if scopes == 7 else None))
    return result


def fixed_retention_time_cases(w: World) -> list[Case]:
    """Signing selections need eligibility at fixed transition time and NOW."""
    pin = "744bf491d9ccebfa109fd1b7f9a2a7c3331b7a8a"
    later = "2026-10-26T12:00:01Z"
    root_actor = {"person_public_key": "-", "host_public_key": "-", "device_public_key": "-",
                  "issuer_id": w.genesis.statement_id}
    person = w.statement("person_lease", w.lease_payload("person_lease"), [("issuer", "root", "ed25519")])
    result = []
    def intent(name: str, kind: str, payload: dict, prior: dict, allowed: bool) -> None:
        expected = ({"ok": True, "context_id": w.context_id, "decision_time": later,
            "issuer_id": w.genesis.statement_id, "signer_public_key": w.keys.public("root"),
            "required_parent_ids": ([w.genesis.statement_id] if kind != "root_state" else payload["predecessors"]),
            "effective_not_after": "-" if kind == "root_state" else UNTIL} if allowed else error("forbidden"))
        result.append(Case("fixed_retention_time/"+name, {"format": 1, "kind": "action",
            "descriptor_base64": b64(w.descriptor_bytes), "prior": prior,
            "candidate_catalog_base64": b64(w.catalog([])), "now": later, "actor": root_actor,
            "action_kind": kind, "unsigned_payload_base64": b64(raw_json(payload))}, expected, oracle_pin=pin))
    for live, name in [(True, "eligible_root_selection_is_signable"), (False, "root_selection_not_live_at_fixed_transition_refuses")]:
        host = w.statement("host_lease", w.lease_payload("host_lease", not_before=NOW if live else later),
            [("issuer", "root", "ed25519"), ("host", "host-a", "ed25519")])
        _, prior = known_simple_prior(w, [w.genesis, host])
        prior["clock_guard"] = later
        root_payload = {"epoch": 1, "predecessors": [w.genesis.statement_id], "resolves": [],
            "migration_proposal_id": "-", "root_public_key": w.keys.public("next-root"),
            "issued_at": NOW, "retained_statement_ids": [host.statement_id]}
        intent(name, "root_state", root_payload, prior, live)
        if not live:
            # At T0 this candidate H was not admitted; at T1 the otherwise
            # valid signed R1 cannot invent H's missing pre-transition power.
            root = w.statement("root_state", root_payload,
                [("issuer", "root", "ed25519"), ("new_root", "next-root", "ed25519")])
            before = w.prior([w.genesis, host], [maximum(["root"], 0, [w.genesis])],
                             admitted_ids=[w.genesis.statement_id])
            after = w.prior([w.genesis, host, root], [maximum(["root"], 1, [root])],
                root_ids=[root.statement_id], clock_guard=later,
                admitted_ids=[w.genesis.statement_id, root.statement_id])
            result.append(Case("fixed_retention_time/signed_root_still_advances_without_future_child_power", {
                "format": 1, "kind": "projection", "descriptor_base64": b64(w.descriptor_bytes), "prior": before,
                "candidate_catalog_base64": b64(w.catalog([root])), "now": later, "operation": "fresh"},
                {"ok": True, "context_id": w.context_id, "decision_time": later,
                 "root": {"head_ids": [root.statement_id], "maximum": 1, "selected_id": root.statement_id,
                          "conflicted": False, "code": "-", "required_ids": []},
                 "streams": [], "restrictions": [], "inert_statement_ids": [host.statement_id], "next_prior": after}, oracle_pin=pin))
    host = w.statement("host_lease", w.lease_payload("host_lease"),
        [("issuer", "root", "ed25519"), ("host", "host-a", "ed25519")])
    for live, name in [(True, "eligible_finite_successor_selection_is_signable"),
                       (False, "finite_successor_selection_not_live_at_fixed_transition_refuses")]:
        binding = w.statement("binding_lease", w.lease_payload("binding_lease", not_before=NOW if live else later,
            issuer={"kind": "person", "person_public_key": w.keys.public("alice")}, parents=[
                {"role": "subject_person", "id": person.statement_id},
                {"role": "issuer_person", "id": person.statement_id},
                {"role": "subject_host", "id": host.statement_id}]),
            [("issuer", "alice", "sshsig"), ("host", "host-a", "ed25519")])
        _, prior = known_simple_prior(w, [w.genesis, person, host, binding])
        prior["clock_guard"] = later
        successor = w.lease_payload("host_lease", sequence=2, predecessors=[host.statement_id],
                                    retained_statement_ids=[binding.statement_id])
        intent(name, "host_lease", successor, prior, live)
    return result


def reversible_barrier_cases(w: World) -> list[Case]:
    """A new generation must explicitly resolve every known reversible barrier."""
    activation = w.original_link(scopes=7)
    source, _ = activation_objects_prior(w, activation)
    person = activation.source_objects[1]
    host, binding, _ = activation.new_objects
    admin = w.statement("admin_lease", w.lease_payload("admin_lease"), [("issuer", "root", "ed25519")])
    withdraw = w.statement("admin_withdraw", {
        "root_state_id": w.genesis.statement_id,
        "issuer": {"kind": "root", "person_public_key": "-"}, "parents": [], "issued_at": NOW,
        "target": {"statement_id": admin.statement_id, "person_public_key": w.keys.public("alice"),
                   "host_public_key": "-", "device_public_key": "-"},
        "kept_statement_ids": [], "ratifies": "-"}, [("issuer", "root", "ed25519")])
    unbind = w.statement("host_unbind", {
        "root_state_id": w.genesis.statement_id,
        "issuer": {"kind": "person", "person_public_key": w.keys.public("alice")},
        "parents": [{"role": "issuer_person", "id": person.statement_id}], "issued_at": NOW,
        "target": {"statement_id": binding.statement_id, "person_public_key": w.keys.public("alice"),
                   "host_public_key": w.keys.public("host-b"), "device_public_key": "-"},
        "kept_statement_ids": [], "ratifies": "-"}, [("issuer", "alice", "sshsig")])
    now = "2026-10-26T12:00:01Z"
    result = []
    for kind, old, barrier, signer in [
        ("admin_lease", admin, withdraw, "root"), ("binding_lease", binding, unbind, "alice")]:
        _, prior = known_simple_prior(w, source+[admin, barrier], activations=[activation.activation_id],
                                     restrictions=[barrier.statement_id])
        original = signer == "alice"
        actor = {"person_public_key": w.keys.public("alice") if original else "-",
                 "host_public_key": "-", "device_public_key": "-",
                 "issuer_id": "-" if original else w.genesis.statement_id}
        payload = w.lease_payload(kind, host="host-b", sequence=2, predecessors=[old.statement_id],
                                 issued_at=now, not_before=now)
        if original:
            payload["issuer"] = {"kind": "person", "person_public_key": w.keys.public("alice")}
            payload["parents"] = sorted([
                {"role": "issuer_person", "id": person.statement_id},
                {"role": "subject_person", "id": person.statement_id},
                {"role": "subject_host", "id": host.statement_id}], key=lambda row: row["role"])
        for resolves, suffix in [([], "cannot_skip_known_barrier"), ([barrier.statement_id], "explicit_resolution_allows_new_generation")]:
            body = changed(payload, resolves=resolves)
            expected = ({"ok": True, "context_id": w.context_id, "decision_time": now,
                "issuer_id": actor["issuer_id"], "signer_public_key": w.keys.public(signer),
                "required_parent_ids": sorted({w.genesis.statement_id}|{r["id"] for r in body["parents"]}),
                "effective_not_after": UNTIL} if resolves else error("forbidden"))
            result.append(Case("reversible_barriers/"+kind+"_"+suffix, {
                "format": 1, "kind": "action", "descriptor_base64": b64(w.descriptor_bytes), "prior": prior,
                "candidate_catalog_base64": b64(w.catalog([])), "now": now, "actor": actor,
                "action_kind": kind, "unsigned_payload_base64": b64(raw_json(body))}, expected))
    return result


def packet_issuer_type_cases(w: World) -> list[Case]:
    """Expired target D never bypasses the administrator's exact typed IDs."""
    bob = w.statement("person_lease", w.lease_payload("person_lease", person="bob"),
                      [("issuer", "root", "ed25519")])
    policy = w.access("policy", person="bob", person_lease=bob)
    live_host = w.statement("host_lease", w.lease_payload("host_lease", host="host-b"),
        [("issuer", "root", "ed25519"), ("host", "host-b", "ed25519")])
    prior = w.prior([w.genesis], [maximum(["root"], 0, [w.genesis])])
    cases = []
    for unrelated, name in [(policy, "policy_is_not_a_packet_issuer_lease"),
                             (bob, "root_packet_cannot_name_an_unrelated_person_lease")]:
        ceremony = w.original_link(not_after="2026-10-26T12:00:01Z", current_host=live_host,
            additional_proof_objects=[bob, policy], administrator_role={
                "writer": "host-a", "signer": "root", "person": "-",
                "issuer_id": w.genesis.statement_id, "signature_format": "ed25519",
                "issuer_lease_ids": [unrelated.statement_id]})
        objects = unique_objects(ceremony.source_objects+ceremony.new_objects+[
            PublicObject("activation", w.context_id, b"", ceremony.body, "")])
        cases.append(Case("packet_issuer_types/expired_target_"+name, {
            "format": 1, "kind": "projection", "descriptor_base64": b64(w.descriptor_bytes),
            "prior": prior, "candidate_catalog_base64": b64(w.catalog(objects)),
            "now": "2026-10-26T12:00:02Z", "operation": "repair"}, error("invalid"),
            oracle_pin="188c5dce5e33f68f9020fb3fa221264d166e5886"))
    # Exact invalid responses contain no next_prior, admission, stream or
    # maximum result: neither unrelated Bob body can gain partial authority.
    return cases


def portable_original_issuer_cases(w: World) -> list[Case]:
    """A later root endorsement cannot invent original delegation power4."""
    cases = []
    for original_scopes, name in [(15, "original_delegator15_remains_valid_when_exactly_root_carried"),
                                  (3, "root_retention_cannot_supply_never_held_delegation4")]:
        parent = w.original_link(scopes=original_scopes)
        child = w.original_link(owner_host="host-b", target_host="host-c", target_device="device-c",
            owner_device=parent, scopes=1, created_at="2026-10-26T12:00:01Z")
        objects = unique_objects(child.source_objects+child.new_objects+[
            PublicObject("activation", w.context_id, b"", child.body, "")])
        finite = sorted({o.statement_id for o in objects if o.kind in {
            "person_lease", "host_lease", "binding_lease", "device_lease", "admin_lease", "policy", "group"}})
        root = w.statement("root_state", {"epoch": 1, "predecessors": [w.genesis.statement_id],
            "resolves": [], "migration_proposal_id": "-", "root_public_key": w.keys.public("next-root"),
            "issued_at": "2026-10-26T12:00:02Z", "retained_statement_ids": finite},
            [("issuer", "root", "ed25519"), ("new_root", "next-root", "ed25519")])
        observed = copy.copy(child)
        observed.source_objects = child.source_objects+[root]
        expected, bounds = activation_observation(w, observed)
        cases.append(Case("portable_original_issuer/"+name, {
            "format": 1, "kind": "activation", "descriptor_base64": b64(w.descriptor_bytes), "prior": "-",
            "catalog_base64": b64(w.catalog(unique_objects(objects+[root]))),
            "activation_base64": b64(child.body), "now": "2026-10-26T12:00:03Z", "expected": child.expected},
            expected if original_scopes == 15 else error("forbidden"),
            array_bounds=bounds if original_scopes == 15 else None,
            oracle_pin="b26aefddbf92d0efd30bef9f70fb4c117ecff09d"))
    return cases


def current_retained_issuer_cases(w: World) -> list[Case]:
    """Fresh issuance uses the issuer's current retained scope intersection."""
    # PR113 fixes the exact literal/current-proof and imported relation seams.
    pin = "7c5a483aa01d87a5d3715bc8fef902f4839ba214"
    parent = w.original_link(scopes=15)
    child = w.original_link(owner_host="host-b", target_host="host-c", target_device="device-c",
        scopes=15, owner_device=parent, created_at="2026-10-26T12:00:01Z")
    narrowed = w.retaining_device_renewal(parent, child, scopes=7)
    evidence = unique_objects(narrowed.source_objects+narrowed.new_objects+[
        PublicObject("activation", w.context_id, b"", narrowed.body, "")])
    _, prior = known_simple_prior(w, evidence,
        activations=[parent.activation_id, child.activation_id, narrowed.activation_id])
    cases = []
    for scopes in (7, 15):
        fresh = w.original_link(owner_host="host-c", owner_device=child, owner_device_key="device-c",
            target_host="host-d", target_device="device-d", scopes=scopes,
            created_at="2026-10-26T12:00:03Z", additional_proof_objects=evidence)
        manifest = json.loads(fresh.manifest)
        # D_B7 is a CURRENT reverse successor, never a signed forward edge of
        # D_C15. Its exact body and complete consent are separately DP-pinned.
        assert narrowed.device.statement_id not in manifest["ancestor_statement_ids"]
        assert narrowed.device.proof_id in manifest["proof_ids"]
        assert PublicObject("activation", w.context_id, b"", narrowed.body, "").proof_id in manifest["proof_ids"]
        expected, bounds = activation_observation(w, fresh)
        cases.append(Case("current_retained_issuer/nominal15_effective7_"+
            ("can_issue_child7" if scopes == 7 else "cannot_issue_child15"), {
                "format": 1, "kind": "activation", "descriptor_base64": b64(w.descriptor_bytes), "prior": prior,
                "catalog_base64": b64(w.catalog(unique_objects(fresh.source_objects+fresh.new_objects))),
                "activation_base64": b64(fresh.body), "now": "2026-10-26T12:00:03Z", "expected": fresh.expected},
            expected if scopes == 7 else error("forbidden"),
            array_bounds=bounds if scopes == 7 else None, oracle_pin=pin))
    # The last fresh ceremony requested child15 after B7 was already current.
    # A later root may list the bytes, but cannot retroactively add the scope
    # or skipped carrying edge that this child lacked at original issuance.
    overbroad = fresh
    carried = unique_objects(overbroad.source_objects+overbroad.new_objects+[
        PublicObject("activation", w.context_id, b"", overbroad.body, "")])
    finite = sorted({o.statement_id for o in carried if o.kind in {
        "person_lease", "host_lease", "binding_lease", "device_lease", "admin_lease", "policy", "group"}})
    later_root = w.statement("root_state", {"epoch": 1, "predecessors": [w.genesis.statement_id],
        "resolves": [], "migration_proposal_id": "-", "root_public_key": w.keys.public("next-root"),
        "issued_at": "2026-10-26T12:00:04Z", "retained_statement_ids": finite},
        [("issuer", "root", "ed25519"), ("new_root", "next-root", "ed25519")])
    cases.append(Case("current_retained_issuer/later_root_cannot_restore_child15_missing_intervening_eligibility", {
        "format": 1, "kind": "activation", "descriptor_base64": b64(w.descriptor_bytes), "prior": prior,
        "catalog_base64": b64(w.catalog(unique_objects(carried+[later_root]))),
        "activation_base64": b64(overbroad.body), "now": "2026-10-26T12:00:05Z", "expected": overbroad.expected},
        error("forbidden"), oracle_pin=pin))
    return cases


def imported_resolver_cases(w: World) -> list[Case]:
    """Imported typed resolvers cannot heal known forks by predecessors alone."""
    # PR113 fixes the exact literal/current-proof and imported relation seams.
    pin = "7c5a483aa01d87a5d3715bc8fef902f4839ba214"
    person = w.statement("person_lease", w.lease_payload("person_lease"), [("issuer", "root", "ed25519")])
    left = w.statement("person_lease", w.lease_payload("person_lease", sequence=2,
        predecessors=[person.statement_id]), [("issuer", "root", "ed25519")])
    right = w.statement("person_lease", w.lease_payload("person_lease", sequence=3,
        predecessors=[person.statement_id]), [("issuer", "root", "ed25519")])
    stream = ["person", w.keys.public("alice")]
    root_max = maximum(["root"], 0, [w.genesis])
    heads = sorted([left.statement_id, right.statement_id])
    history = [w.genesis, person, left, right]
    prior = w.prior(history, [root_max, maximum(stream, 3, [right], heads=heads)])
    root = {"head_ids": [w.genesis.statement_id], "maximum": 0, "selected_id": w.genesis.statement_id,
            "conflicted": False, "code": "-", "required_ids": []}
    cases = []
    for predecessors, resolves, name in [
        (heads, [], "multi_predecessor_missing_resolves_invalid_before_admission"),
        (heads, heads, "explicit_all_head_resolver_selects_new_generation"),
        ([left.statement_id], [], "one_branch_successor_keeps_other_head_conflicted")]:
        candidate = w.statement("person_lease", w.lease_payload("person_lease", sequence=4,
            predecessors=predecessors, resolves=resolves), [("issuer", "root", "ed25519")])
        if len(predecessors) > 1 and not resolves:
            expected = error("invalid")
        else:
            next_heads = [candidate] if resolves else [right, candidate]
            next_prior = w.prior(history+[candidate], [root_max, maximum(stream, 4, [candidate], heads=next_heads)])
            expected = {"ok": True, "context_id": w.context_id, "decision_time": NOW, "root": root,
                "streams": [stream_row(stream, 4, next_heads, code="-" if resolves else "state_conflict")],
                "restrictions": [], "inert_statement_ids": [], "next_prior": next_prior}
        cases.append(Case("imported_resolver/"+name, {"format": 1, "kind": "projection",
            "descriptor_base64": b64(w.descriptor_bytes), "prior": prior,
            "candidate_catalog_base64": b64(w.catalog([candidate])), "now": NOW, "operation": "fresh"},
            expected, oracle_pin=pin))
        if resolves:
            # A separately isolated absence is repairable, unlike malformed
            # complete typed relations. Preserve the actual remembered fork.
            missing = copy.deepcopy(prior)
            missing["catalog_base64"] = b64(w.catalog([o for o in history if o != left]))
            cases.append(Case("imported_resolver/valid_resolves_missing_exact_branch_body_requires_proof", {
                "format": 1, "kind": "projection", "descriptor_base64": b64(w.descriptor_bytes), "prior": missing,
                "candidate_catalog_base64": b64(w.catalog([candidate])), "now": NOW, "operation": "fresh"},
                error("proof_required", [left.statement_id]), oracle_pin=pin))
    return cases


def fork_retention_cases(w: World) -> list[Case]:
    """A root resolver cannot revive an old H omitted on either fork branch.

    All protocol ID arrays stay sorted. Independently chosen branch keys make
    the dropping branch sort before/after the keeping one; this varies the
    actual verified DAG, never its canonical wire ordering.
    """
    now = "2026-10-26T12:00:03Z"
    host = w.statement("host_lease", w.lease_payload("host_lease"),
        [("issuer", "root", "ed25519"), ("host", "host-a", "ed25519")])
    host_stream = ["host", w.keys.public("host-a")]

    def branch(key: str, keep: bool) -> PublicObject:
        return w.statement("root_state", {"epoch": 1, "predecessors": [w.genesis.statement_id],
            "resolves": [], "migration_proposal_id": "-", "root_public_key": w.keys.public(key),
            "issued_at": "2026-10-26T12:00:01Z",
            "retained_statement_ids": [host.statement_id] if keep else []},
            [("issuer", "root", "ed25519"), ("new_root", key, "ed25519")])

    result = []
    for mode in ("kept_branch_sorts_first", "dropping_branch_sorts_first", "all_branches_keep"):
        keep_key = "fork-retention-keep-"+mode
        kept = branch(keep_key, True)
        other = None
        for index in range(32):
            other_key = "fork-retention-other-"+mode+"-"+str(index)
            candidate = branch(other_key, mode == "all_branches_keep")
            ordered = kept.statement_id < candidate.statement_id
            if mode == "all_branches_keep" or ordered == (mode == "kept_branch_sorts_first"):
                other = candidate
                break
        if other is None:
            raise RuntimeError("independent root-branch key search exceeded32 candidates")
        branch_ids = sorted([kept.statement_id, other.statement_id])
        resolver = w.statement("root_state", {"epoch": 2, "predecessors": branch_ids,
            "resolves": branch_ids, "migration_proposal_id": "-",
            "root_public_key": w.keys.public("fork-retention-resolver-"+mode),
            "issued_at": "2026-10-26T12:00:02Z", "retained_statement_ids": [host.statement_id]},
            [("root_branch:"+kept.statement_id, keep_key, "ed25519"),
             ("root_branch:"+other.statement_id, other_key, "ed25519"),
             ("new_root", "fork-retention-resolver-"+mode, "ed25519")])
        before = [w.genesis, host, kept, other]
        prior = w.prior(before, [maximum(["root"], 1, [kept, other]), maximum(host_stream, 1, [host])],
                        root_ids=branch_ids, clock_guard="2026-10-26T12:00:01Z")
        after = w.prior(before+[resolver], [maximum(["root"], 2, [resolver]), maximum(host_stream, 1, [host])],
                        root_ids=[resolver.statement_id], clock_guard=now)
        result.append(Case("fork_retention/"+mode, {"format": 1, "kind": "projection",
            "descriptor_base64": b64(w.descriptor_bytes), "prior": prior,
            "candidate_catalog_base64": b64(w.catalog([resolver])), "now": now, "operation": "fresh"},
            {"ok": True, "context_id": w.context_id, "decision_time": now,
             "root": {"head_ids": [resolver.statement_id], "maximum": 2, "selected_id": resolver.statement_id,
                      "conflicted": False, "code": "-", "required_ids": []},
             "streams": [stream_row(host_stream, 1, [host], code="-" if mode == "all_branches_keep" else "forbidden")],
             "restrictions": [], "inert_statement_ids": [], "next_prior": after},
             oracle_pin="7c5a483aa01d87a5d3715bc8fef902f4839ba214"))
    return result


def retained_renewal_ancestor_cases(w: World) -> list[Case]:
    """Later root retention cannot turn a sibling into an old target ancestor."""
    parent = w.original_link(scopes=15)
    target = w.original_link(owner_host="host-b", owner_device=parent,
        target_host="host-c", target_device="device-c", scopes=4, created_at="2026-10-26T12:00:01Z")
    sibling = w.original_link(target_host="host-d", target_device="device-d", scopes=4,
                              created_at="2026-10-26T12:00:01Z")
    shared = sibling.source_objects+sibling.new_objects+[
        PublicObject("activation", w.context_id, b"", sibling.body, "")]
    cases = []
    for issuer, host, key, valid, name in [
        (parent, "host-b", "device-b", True, "strict_ancestor4_renewal_survives_exact_later_root_carrying"),
        (sibling, "host-d", "device-d", False, "later_root_cannot_turn_scope4_sibling_into_renewal_ancestor")]:
        renewal = w.delegated_device_renewal(target, issuer, issuer_host=host, issuer_device_key=key,
                                             additional_proof_objects=shared)
        objects = unique_objects(renewal.source_objects+renewal.new_objects+[
            PublicObject("activation", w.context_id, b"", renewal.body, "")])
        finite = sorted({o.statement_id for o in objects if o.kind in {
            "person_lease", "host_lease", "binding_lease", "device_lease", "admin_lease", "policy", "group"}})
        root = w.statement("root_state", {"epoch": 1, "predecessors": [w.genesis.statement_id], "resolves": [],
            "migration_proposal_id": "-", "root_public_key": w.keys.public("next-root"),
            "issued_at": "2026-10-26T12:00:04Z", "retained_statement_ids": finite},
            [("issuer", "root", "ed25519"), ("new_root", "next-root", "ed25519")])
        observed = copy.copy(renewal)
        observed.source_objects = renewal.source_objects+[root]
        expected, bounds = activation_observation(w, observed)
        cases.append(Case("retained_renewal_ancestor/"+name, {"format": 1, "kind": "activation",
            "descriptor_base64": b64(w.descriptor_bytes), "prior": "-",
            "catalog_base64": b64(w.catalog(unique_objects(objects+[root]))), "activation_base64": b64(renewal.body),
            "now": "2026-10-26T12:00:05Z", "expected": renewal.expected}, expected if valid else error("forbidden"),
            array_bounds=bounds if valid else None, oracle_pin="7c5a483aa01d87a5d3715bc8fef902f4839ba214"))
    return cases


def migration_root_transition_conflict_cases(w: World) -> list[Case]:
    result = []
    for case in migration_action_conflict_cases(w):
        if "different_complete_proposal" in case.name or "original_complete_proposal" in case.name:
            continue
        request = copy.deepcopy(case.request)
        current = request["actor"]["issuer_id"]
        epoch = next(row["sequence"] for row in request["prior"]["maxima"] if row["stream"] == ["root"])
        request["action_kind"] = "root_state"
        request["unsigned_payload_base64"] = b64(raw_json({"epoch": epoch + 1,
            "predecessors": [current], "resolves": [], "migration_proposal_id": "-",
            "root_public_key": w.keys.public("next-root"), "issued_at": NOW, "retained_statement_ids": []}))
        expected = changed(case.expected, effective_not_after="-") if case.expected.get("ok") else case.expected
        result.append(Case(case.name.replace("migration_action_conflict/", "migration_root_transition_conflict/"),
                           request, expected))
    return result


GROUPS = {"descriptor": descriptor_cases, "statement": statement_cases, "catalog": catalog_cases,
          "packet_issuer_types": packet_issuer_type_cases,
          "portable_original_issuer": portable_original_issuer_cases,
          "current_retained_issuer": current_retained_issuer_cases,
          "imported_resolver": imported_resolver_cases,
          "fork_retention": fork_retention_cases,
          "retained_renewal_ancestor": retained_renewal_ancestor_cases,
          "ceremony_scope": ceremony_scope_cases,
          "fixed_retention_time": fixed_retention_time_cases,
          "reversible_barriers": reversible_barrier_cases,
          "statement_more": statement_more_cases, "projection": projection_cases,
          "activation": activation_cases, "activation_dag": activation_dag_cases,
          "renewal_stage": renewal_stage_cases,
          "action": action_cases, "retention": retention_cases, "expiry": expiry_cases,
          "admin_withdrawal": admin_withdrawal_cases,
          "signature_format": signature_format_cases, "administrator_stage": administrator_stage_cases,
          "read_purity": read_purity_cases, "revoked_retainer": revoked_retainer_cases,
          "retained_root": retained_root_cases,
          "root_origin": root_origin_cases,
          "retention_time": retention_time_cases,
          "migration": migration_cases, "migration_source_authority": migration_source_authority_cases,
          "migration_sticky_restriction": migration_sticky_restriction_cases,
          "migration_source_budget": migration_source_budget_cases,
          "migration_origin": migration_origin_cases,
          "migration_current": migration_current_cases,
          "migration_conflict": migration_conflict_cases,
          "migration_action_conflict": migration_action_conflict_cases,
          "migration_root_transition_conflict": migration_root_transition_conflict_cases,
          "retained_device_scope": retained_device_scope_cases,
          "retained_delegation_scope": retained_delegation_scope_cases,
          "fixed_action_time": fixed_action_time_cases,
          "carrier": carrier_cases, "budget": budget_cases,
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
    parser.add_argument("--case", action="append", help="run only these exact names within the selected groups")
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
        if args.case:
            requested = set(args.case)
            missing = requested-{case.name for case in cases}
            if missing:
                parser.error("unknown selected case names: "+", ".join(sorted(missing)))
            cases = [case for case in cases if case.name in requested]
        if any(c.final_unterminated for c in cases) and len(cases) != 1:
            parser.error("carrier_final is a separate one-stream case; select it alone")
        names = [c.name for c in cases]
        if len(names) != len(set(names)):
            raise RuntimeError("duplicate independent case name")
        manifest = {"contract_pin": PIN, "implementation_source_read": False,
                    "suite_sha256": sha(Path(__file__).read_bytes()),
                    "fixture_sha256": sha(Path(__file__).with_name("decentralized_fixtures.py").read_bytes()),
                    "groups": groups, "selected_case_names": args.case or [],
                    "case_count": len(cases), "fixture_signatures": keys.signatures,
                    "cases": [{"name": c.name, "request_sha256": sha(request_bytes(c.request)),
                               "final_unterminated": c.final_unterminated,
                               **({"oracle_pin": c.oracle_pin} if c.oracle_pin else {}),
                               **({"response_array_bounds": {field: {"required": lower, "permitted": upper}
                                    for field, (lower, upper) in c.array_bounds.items()}} if c.array_bounds else {})}
                              for c in cases]}
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
