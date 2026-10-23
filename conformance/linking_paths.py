#!/usr/bin/env python3
"""Independent certificate-path conformance over injected verified state.

Derived from docs/linking-path-checks.md, the signing contract, and public
vectors. This is not catalog, activation, freshness, retention or transaction
verification. Neither host implementation is imported or inspected.
"""

import argparse
import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys

from linking_readers import (Author as ReaderOracle, BASE, FixtureSigner, Probe,
                             add_points, b64, digest, encode_point, message,
                             multiply_base, unb64, wire)


ROOT = Path(__file__).resolve().parents[1]
STATE_LIMIT = 1024 * 1024
NOW = "2026-10-24T12:00:00Z"
DAY = 86400


def at(seconds, origin=NOW):
    parsed = datetime.strptime(origin, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return (parsed + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def error(code, required=()):
    result = {"ok": False, "code": code}
    if code == "proof_required":
        result["required_ids"] = sorted(set(required))
    return result


@dataclass
class Certificate:
    body: dict

    @property
    def id(self):
        return "dc_" + digest(message("certificate", self.body))

    def entry(self):
        return {"id": self.id, "body_base64": b64(wire(self.body))}


@dataclass
class Case:
    name: str
    request: object
    expected: dict


class Author:
    def __init__(self, vectors):
        self.oracle = ReaderOracle(vectors)
        self.signers = self.oracle.signers
        self.primitive = vectors["machine-linking-v1.json"]
        self.person = self.primitive["keys"]["person_root"]["public_key"]
        self.other_person = self.primitive["keys"]["network_root"]["public_key"]
        self.network = self.primitive["network_id"]
        self.cases = []
        self.seen = set()
        self.keys = {}

    def key(self, label):
        if label not in self.keys:
            seed = hashlib.sha256(("public-linking-path-seed:" + label).encode()).digest()
            signer = FixtureSigner(seed)
            public = b64(signer.public)
            self.signers[public] = signer
            self.keys[label] = public
        return self.keys[label]

    def certificate(self, label, parent=None, **changes):
        parent_id = "root" if parent is None else parent.id
        issuer = self.person if parent is None else parent.body["device_public_key"]
        body = {"format": 1, "network_id": self.network, "person_public_key": self.person,
                "device_public_key": self.key(label + "/device"),
                "host_public_key": self.key(label + "/host"), "parent_id": parent_id,
                "scopes": 15, "issued_at": NOW, "not_after": at(90 * DAY),
                "request_id": "link_" + digest(("public-linking-path-request:" + label).encode())}
        body.update(changes)
        if parent is None:
            issuer = body["person_public_key"]
        body["signature"] = self.signers[issuer].sshsig(message("certificate", body))
        return Certificate(body)

    def chain(self, length, label="chain", changes=None):
        result = []
        for index in range(length):
            result.append(self.certificate(label + "/" + str(index),
                                           result[-1] if result else None,
                                           **((changes or {}).get(index, {}))))
        return result

    def state(self, certificates=(), administrator=True, person=None, network=None):
        person = person or self.person
        hosts = list(dict.fromkeys(cert.body["host_public_key"] for cert in certificates))
        return {"format": 1, "network_id": network or self.network,
                "persons": [{"public_key": person, "state": "admitted", "administrator": administrator}],
                "hosts": [{"public_key": host, "state": "admitted"} for host in hosts],
                "bindings": [{"host_public_key": host, "person_public_key": person} for host in hosts],
                "certificates": [cert.entry() for cert in certificates],
                "activated_certificates": [cert.id for cert in certificates], "revoked_devices": []}

    def request(self, state, certificate="root", scopes=1, now=NOW, person=None, raw=None):
        certificate_id = certificate.id if isinstance(certificate, Certificate) else certificate
        return {"kind": "path", "state_base64": b64(wire(state) if raw is None else raw),
                "person_public_key": person or self.person, "certificate_id": certificate_id,
                "required_scopes": scopes, "now": now}

    def success(self, certificates=(), person=None):
        person = person or self.person
        leaf = certificates[-1] if certificates else None
        return {"ok": True, "certificate_id": leaf.id if leaf else "root",
                "person_public_key": person,
                "signer_public_key": leaf.body["device_public_key"] if leaf else person,
                "scopes": leaf.body["scopes"] if leaf else 15,
                "not_after": leaf.body["not_after"] if leaf else "-",
                "certificate_ids": [cert.id for cert in certificates],
                "host_public_keys": [cert.body["host_public_key"] for cert in certificates]}

    def add_request(self, name, request, expected):
        encoded = request if isinstance(request, bytes) else wire(request)
        identity = encoded, wire(expected)
        if identity not in self.seen:
            self.seen.add(identity)
            self.cases.append(Case(name, request, expected))

    def add(self, name, state, certificates=(), code=None, required=(), **context):
        target = context.pop("certificate", certificates[-1] if certificates else "root")
        expected = error(code, required) if code else self.success(certificates, context.get("person"))
        self.add_request(name, self.request(state, target, **context), expected)

    def fixture_paths(self):
        certificates = [Certificate(copy.deepcopy(vector["certificate"]))
                        for vector in self.primitive["sshsig_vectors"] if "certificate" in vector]
        assert len(certificates) == 2
        for index, vector in enumerate(v for v in self.primitive["sshsig_vectors"] if "certificate" in v):
            assert certificates[index].id == vector["certificate_id"]
        self.add("fixture/root_person", self.state(), now=self.primitive["issued_at"])
        self.add("fixture/root_to_b", self.state(certificates[:1]), certificates[:1], now=self.primitive["issued_at"])
        self.add("fixture/root_to_b_to_c", self.state(certificates), certificates, now=self.primitive["issued_at"])

    def paths_and_scopes(self):
        one, eight, nine = self.chain(1), self.chain(8), self.chain(9)
        self.add("path/one", self.state(one), one)
        self.add("path/eight", self.state(eight), eight)
        self.add("path/nine", self.state(nine), nine, "invalid")
        shuffled = self.state(eight)
        for value in shuffled.values():
            if isinstance(value, list):
                value.reverse()
        self.add("path/input_order_independent", shuffled, eight)
        for scopes in range(1, 16):
            self.add("scope/root/" + str(scopes), self.state(), scopes=scopes)
            self.add("scope/device/" + str(scopes), self.state(one), one, scopes=scopes)
            code = "forbidden" if scopes & 8 else None
            self.add("scope/nonadmin_root/" + str(scopes), self.state(administrator=False), code=code, scopes=scopes)
            self.add("scope/nonadmin_device/" + str(scopes), self.state(one, administrator=False), one,
                     code=code, scopes=scopes)
        for mask in (1, 2, 4, 7, 8):
            path = self.chain(1, "leaf_scope_" + str(mask), {0: {"scopes": mask}})
            self.add("scope/exact_leaf_" + str(mask), self.state(path), path, scopes=mask)
            missing = next(bit for bit in (1, 2, 4, 8) if not mask & bit)
            self.add("scope/insufficient_leaf_" + str(mask), self.state(path), path, "forbidden", scopes=mask | missing)
        path = self.chain(2, "subset", {0: {"scopes": 7}, 1: {"scopes": 3}})
        self.add("scope/valid_subset", self.state(path), path, scopes=3)
        path = self.chain(2, "expansion", {0: {"scopes": 7}, 1: {"scopes": 15}})
        self.add("scope/child_expansion", self.state(path), path, "invalid")
        path = self.chain(2, "no_delegation", {0: {"scopes": 3}, 1: {"scopes": 1}})
        self.add("scope/issuer_without_delegation", self.state(path), path, "forbidden")
        for mask in (0, 16, -1):
            path = self.chain(1, "invalid_scope_" + str(mask), {0: {"scopes": mask}})
            self.add("scope/invalid_certificate_mask_" + str(mask), self.state(path), path, "invalid")

    def times(self):
        path = self.chain(1)
        state = self.state(path)
        for name, now, code in (("before_issuance", at(-1), "authority_expired"),
                                 ("at_issuance", NOW, None),
                                 ("last_valid_second", at(90 * DAY - 1), None),
                                 ("at_expiry", at(90 * DAY), "authority_expired"),
                                 ("after_expiry", at(90 * DAY + 1), "authority_expired")):
            self.add("time/" + name, state, path, code, now=now)
        for name, fields in (("empty", {"not_after": NOW}),
                             ("backwards", {"not_after": at(-1)}),
                             ("over_90_days", {"not_after": at(90 * DAY + 1)})):
            path = self.chain(1, "time/" + name, {0: fields})
            self.add("time/" + name, self.state(path), path, "invalid")
        path = self.chain(2, "earlier_child", {0: {"not_after": at(89 * DAY)},
                                               1: {"issued_at": at(-1), "not_after": at(89 * DAY)}})
        self.add("time/child_before_parent", self.state(path), path, "invalid")
        path = self.chain(2, "later_child_expiry", {0: {"not_after": at(89 * DAY)},
                                                   1: {"not_after": at(89 * DAY + 1)}})
        self.add("time/child_after_parent_expiry", self.state(path), path, "invalid")
        path = self.chain(2, "nested_intervals", {0: {"not_after": at(89 * DAY)},
                                                  1: {"issued_at": at(1), "not_after": at(88 * DAY)}})
        self.add("time/valid_nested_intervals", self.state(path), path, now=at(1))
        path = self.chain(2, "short_parent", {0: {"not_after": at(10)}, 1: {"not_after": at(10)}})
        self.add("time/ancestor_expired", self.state(path), path, "authority_expired", now=at(10))
        self.add("time/root_no_certificate_expiry", self.state(), now="2099-01-01T00:00:00Z")

    def keys_and_signatures(self):
        parent = self.certificate("collision_parent")
        for name, fields in (
                ("repeated_device", {"device_public_key": parent.body["device_public_key"]}),
                ("repeated_host", {"host_public_key": parent.body["host_public_key"]}),
                ("child_device_is_parent_host", {"device_public_key": parent.body["host_public_key"]}),
                ("child_host_is_parent_device", {"host_public_key": parent.body["device_public_key"]}),
                ("child_device_is_person", {"device_public_key": self.person})):
            child = self.certificate("collision_child/" + name, parent, **fields)
            path = [parent, child]
            self.add("keys/" + name, self.state(path), path, "invalid")
        for name, fields in (
                ("device_is_host", {"device_public_key": self.key("same_key"), "host_public_key": self.key("same_key")}),
                ("device_is_person", {"device_public_key": self.person})):
            path = [self.certificate("collision_direct/" + name, **fields)]
            self.add("keys/" + name, self.state(path), path, "invalid")
        # Test cross-collisions across a nonadjacent three-certificate path too.
        first = self.certificate("nonadjacent/first")
        second = self.certificate("nonadjacent/second", first)
        for field, value in (("device_public_key", first.body["host_public_key"]),
                              ("host_public_key", first.body["device_public_key"])):
            leaf = self.certificate("nonadjacent/" + field, second, **{field: value})
            path = [first, second, leaf]
            self.add("keys/nonadjacent_" + field, self.state(path), path, "invalid")
        for name, fields in (("wrong_network", {"network_id": "net_" + "a" * 64}),
                              ("wrong_person", {"person_public_key": self.other_person})):
            path = [self.certificate("context/" + name, **fields)]
            self.add("context/" + name, self.state(path), path, "invalid")
        path = self.chain(2, "bad_child_context", {1: {"network_id": "net_" + "b" * 64}})
        self.add("context/child_wrong_network", self.state(path), path, "invalid")
        path = self.chain(2, "bad_child_person", {1: {"person_public_key": self.other_person}})
        self.add("context/child_wrong_person", self.state(path), path, "invalid")
        path = self.chain(2)
        for name, issuer in (("wrong_parent_key", self.other_person), ("root_cannot_substitute_parent", self.person)):
            bad = copy.deepcopy(path)
            bad[-1].body["signature"] = self.signers[issuer].sshsig(message("certificate", bad[-1].body))
            self.add("signature/" + name, self.state(bad), bad, "invalid")
        bad = copy.deepcopy(path)
        signature = bytearray(unb64(bad[0].body["signature"]))
        signature[-1] ^= 1
        bad[0].body["signature"] = b64(signature)
        self.add("signature/ancestor_mutation", self.state(bad), bad, "invalid")
        bad = copy.deepcopy(path)
        bad[-1].body["scopes"] = 7
        self.add("signature/changed_message", self.state(bad), bad, "invalid")
        body = copy.deepcopy(path[0].body)
        body["signature"] = self.signers[self.other_person].sshsig(message("certificate", body))
        direct = [Certificate(body)]
        self.add("signature/independent_root_key", self.state(direct), direct, "invalid")

    def state_dependencies(self):
        path = self.chain(2)
        for name, change, code in (
                ("person_missing", lambda state: state["persons"].pop(0), "proof_required"),
                ("person_removed", lambda state: state["persons"][0].update(state="removed"), "forbidden"),
                ("host_missing", lambda state: state["hosts"].pop(0), "proof_required"),
                ("host_removed", lambda state: state["hosts"][0].update(state="removed"), "forbidden"),
                ("binding_missing", lambda state: state["bindings"].pop(0), "proof_required"),
                ("known_unbound", lambda state: state["bindings"][0].update(person_public_key="-"), "forbidden"),
                ("other_person_binding", lambda state: state["bindings"][0].update(person_public_key=self.other_person), "forbidden")):
            state = self.state(path)
            state["persons"].append({"public_key": self.other_person, "state": "admitted", "administrator": False})
            change(state)
            self.add("state/" + name, state, path, code)
        for index, title in ((0, "ancestor"), (1, "leaf")):
            state = self.state(path)
            state["certificates"].pop(index)
            self.add("proof/missing_" + title + "_certificate", state, path, "proof_required", [path[index].id])
            state = self.state(path)
            state["activated_certificates"].remove(path[index].id)
            self.add("proof/pending_" + title + "_activation", state, path, "proof_required",
                     [path[index].body["request_id"]])
        missing = "dc_" + "c" * 64
        self.add("proof/unknown_target", self.state(path), path, "proof_required", [missing], certificate=missing)
        alias = "dc_" + "d" * 64
        state = self.state(path[:1])
        state["certificates"][0]["id"] = alias
        state["activated_certificates"] = [alias]
        self.add("id/untrusted_asserted_index", state, path[:1], "invalid", certificate=alias)
        # True self-consistent hash cycles would require cryptographic fixed
        # points. These malformed asserted-ID graphs test rejection, without
        # claiming an independently signature-valid cyclic fixture.
        for size in (1, 2):
            state = self.state(path[:size])
            ids = ["dc_" + str(index + 1) * 64 for index in range(size)]
            for index, cert in enumerate(path[:size]):
                body = copy.deepcopy(cert.body)
                body["parent_id"] = ids[(index + 1) % size]
                body["signature"] = self.signers[self.person].sshsig(message("certificate", body))
                state["certificates"][index] = {"id": ids[index], "body_base64": b64(wire(body))}
            state["activated_certificates"] = ids
            self.add("graph/asserted_cycle_" + str(size), state, path[:size], "invalid", certificate=ids[0])

    def revocations_and_isolation(self):
        path = self.chain(2)
        for index, name in ((0, "ancestor"), (1, "leaf")):
            state = self.state(path)
            state["revoked_devices"] = [{"person_public_key": self.person,
                                         "device_public_key": path[index].body["device_public_key"]}]
            self.add("revocation/" + name, state, path, "device_revoked")
        state = self.state(path)
        state["revoked_devices"] = [{"person_public_key": self.other_person,
                                     "device_public_key": path[-1].body["device_public_key"]}]
        self.add("revocation/other_person_same_device", state, path)
        state = self.state(path)
        state["revoked_devices"] = [{"person_public_key": self.person,
                                     "device_public_key": self.key("unrelated_revoked_device")}]
        self.add("revocation/other_device", state, path)
        old = path[0]
        renewed = self.certificate("renewed_same_key", device_public_key=old.body["device_public_key"],
                                  host_public_key=old.body["host_public_key"])
        assert old.id != renewed.id
        state = self.state([old, renewed])
        state["revoked_devices"] = [{"person_public_key": self.person,
                                     "device_public_key": old.body["device_public_key"]}]
        self.add("revocation/replacement_certificate_same_key", state, [renewed], "device_revoked")
        self.add("revocation/original_id_remains_revoked", state, [old], "device_revoked")
        # Same device, same host, independent direct-root path: a revocation of
        # the first branch's ancestor must not revoke the leaf key on this branch.
        alternative = self.certificate("independent_same_leaf", device_public_key=path[-1].body["device_public_key"],
                                       host_public_key=path[-1].body["host_public_key"])
        state = self.state(path + [alternative])
        state["revoked_devices"] = [{"person_public_key": self.person,
                                     "device_public_key": path[0].body["device_public_key"]}]
        self.add("isolation/independent_same_device_path", state, [alternative])
        self.add("isolation/no_automatic_path_substitution", state, path, "device_revoked")
        state = self.state(path + [alternative])
        state["activated_certificates"].remove(path[-1].id)
        self.add("isolation/active_alternative_cannot_replace_pending_path", state, path,
                 "proof_required", [path[-1].body["request_id"]])
        state = self.state(path + [alternative])
        state["certificates"][0]["body_base64"] = b64(b"not JSON\xff")
        self.add("isolation/unrelated_damaged_path", state, [alternative])
        self.add("isolation/requested_damaged_path", state, path, "invalid")
        state = self.state(path + [alternative])
        self.add("isolation/exact_long_path_even_with_shorter_one", state, path)
        # Another person's certificate is unaffected by revocations scoped to
        # the original person, even when it intentionally reuses the same device.
        other = self.certificate("other_person_same_device", person_public_key=self.other_person,
                                 device_public_key=path[0].body["device_public_key"])
        state = self.state([other], person=self.other_person)
        state["revoked_devices"] = [{"person_public_key": self.person,
                                     "device_public_key": other.body["device_public_key"]}]
        self.add("revocation/person_scope", state, [other], person=self.other_person)
        other_network = "net_" + "e" * 64
        other = self.certificate("other_network", network_id=other_network,
                                 device_public_key=path[0].body["device_public_key"])
        self.add("revocation/separate_network_snapshot", self.state([other], network=other_network), [other])

    def strict_state(self):
        path = self.chain(1)
        base = self.state(path)
        for field in base:
            for name, state in (("missing", {key: value for key, value in base.items() if key != field}),
                                 ("null", dict(base, **{field: None}))):
                self.add("strict/state/" + name + "/" + field, state, path, "invalid")
        raw = wire(base)
        for name, encoded in (("duplicate", raw[:-1] + b',"format":1}'),
                               ("escaped_duplicate", raw[:-1] + b',"\\u0066ormat":1}'),
                               ("unknown", wire(dict(base, extra=True))),
                               ("invalid_utf8", raw[:-1] + b',"\xff":1}'),
                               ("trailing_json", raw + b"{}"),
                               ("deep", b"[" * 100 + b"0" + b"]" * 100),
                               ("wrong_root_type", b"[]"),
                               ("format_float", raw.replace(b'"format":1', b'"format":1.0')),
                               ("format_exponent", raw.replace(b'"format":1', b'"format":1e0'))):
            self.add("strict/state/" + name, base, path, "invalid", raw=encoded)
        schemas = {
            "persons": {"public_key": "key", "state": "status", "administrator": "boolean"},
            "hosts": {"public_key": "key", "state": "status"},
            "bindings": {"host_public_key": "key", "person_public_key": "key_or_absent"},
            "certificates": {"id": "id", "body_base64": "base64"},
            "revoked_devices": {"person_public_key": "key", "device_public_key": "key"},
        }
        base["revoked_devices"] = [{"person_public_key": self.other_person,
                                    "device_public_key": self.key("strict_revoked")}]
        for array in ("persons", "hosts", "bindings", "certificates", "activated_certificates", "revoked_devices"):
            for name, value in (("number", 1), ("boolean", True), ("string", "wrong"), ("object", {})):
                state = copy.deepcopy(base)
                state[array] = value
                self.add("strict/array_type/" + array + "/" + name, state, path, "invalid")
            state = copy.deepcopy(base)
            state[array].append(copy.deepcopy(state[array][0]))
            self.add("strict/duplicate_entry/" + array, state, path, "invalid")
        for array, schema in schemas.items():
            for name in ("unknown", "missing", "null"):
                state = copy.deepcopy(base)
                target = state[array][0]
                field = next(iter(schema))
                if name == "unknown":
                    target["extra"] = True
                elif name == "missing":
                    del target[field]
                else:
                    target[field] = None
                self.add("strict/entry/" + array + "/" + name, state, path, "invalid")
            for field, field_type in schema.items():
                values = (("string", "false"), ("number", 1), ("array", [])) if field_type == "boolean" else (
                    ("number", 1), ("boolean", True), ("array", []), ("object", {}))
                for name, value in values:
                    state = copy.deepcopy(base)
                    state[array][0][field] = value
                    self.add("strict/entry_type/" + array + "/" + field + "/" + name, state, path, "invalid")
        for array, field, values in (
                ("persons", "public_key", [self.person.rstrip("="), b64(b"x" * 31)]),
                ("persons", "state", ["unknown", "Admitted"]),
                ("hosts", "state", ["left", "Admitted"]),
                ("bindings", "person_public_key", ["root", self.person + "="]),
                ("certificates", "id", ["dc_" + "A" * 64, "dc_" + "0" * 63]),
                ("certificates", "body_base64", [base["certificates"][0]["body_base64"] + "=", "!invalid!"]),
                ("revoked_devices", "device_public_key", [b64(b"x" * 33), self.person + "\n"])):
            for index, value in enumerate(values):
                state = copy.deepcopy(base)
                state[array][0][field] = value
                self.add("strict/encoding/" + array + "/" + field + "/" + str(index), state, path, "invalid")
        state = copy.deepcopy(base)
        state["activated_certificates"] = ["ar_" + "0" * 64]
        self.add("strict/activation_id_kind", state, path, "invalid")
        # Candidate bytes are parsed only on the exact selected path; state
        # envelope types, duplicate entries and Base64 remain globally strict.
        state = self.state()
        state["certificates"] = [{"id": "dc_" + "a" * 64, "body_base64": b64(b"{invalid\xff") }]
        self.add("strict/unrelated_candidate_not_parsed_for_root", state)

    def limits(self):
        base = self.state()
        raw = wire(base)
        self.add("limits/exact_1MiB_state", base, raw=raw + b" " * (STATE_LIMIT - len(raw)))
        self.add("limits/oversize_state", base, code="invalid", raw=raw + b" " * (STATE_LIMIT + 1 - len(raw)))
        # Generate subgroup points using the independent curve helper, without
        # inventing invalid non-signing keys or computing 4097 private seeds.
        point = multiply_base(10000)
        keys = []
        for _ in range(4097):
            keys.append(b64(encode_point(point)))
            point = add_points(point, BASE)
        ids = ["dc_" + digest(("count-bound:" + str(i)).encode()) for i in range(4097)]
        arrays = {
            "persons": [{"public_key": self.person, "state": "admitted", "administrator": True}]
                       + [{"public_key": key, "state": "admitted", "administrator": False} for key in keys[:4096]],
            "hosts": [{"public_key": key, "state": "admitted"} for key in keys],
            "bindings": [{"host_public_key": key, "person_public_key": self.person} for key in keys],
            "certificates": [{"id": value, "body_base64": b64(b"{}") } for value in ids],
            "activated_certificates": ids,
            "revoked_devices": [{"person_public_key": self.person, "device_public_key": key} for key in keys],
        }
        for array, values in arrays.items():
            for count in (4096, 4097):
                state = copy.deepcopy(base)
                state[array] = values[:count]
                assert len(wire(state)) <= STATE_LIMIT
                self.add("limits/" + array + "/" + str(count), state,
                         code="invalid" if count == 4097 else None)

    def strict_probe(self):
        request = self.request(self.state())
        for field in request:
            self.add_request("probe/missing/" + field, {key: value for key, value in request.items() if key != field}, error("invalid"))
            self.add_request("probe/null/" + field, dict(request, **{field: None}), error("invalid"))
        for field, values in {
                "required_scopes": [0, 16, -1, True, 1.0, "1", [], {}, 1 << 64],
                "person_public_key": [self.person.rstrip("="), b64(b"x" * 31), True, []],
                "certificate_id": ["-", "dc_" + "A" * 64, 1, []],
                "now": ["2026-02-30T12:00:00Z", "2026-10-24T12:00:60Z", "2026-10-24T12:00:00+00:00",
                        "2026-10-24T12:00:00.0Z", 1, True],
                "state_base64": [request["state_base64"] + "=", "!invalid!", True, []]}.items():
            for index, value in enumerate(values):
                self.add_request("probe/field/" + field + "/" + str(index), dict(request, **{field: value}), error("invalid"))
        encoded = wire(request)
        for name, raw in (("non_json", b"{"), ("trailing_json", encoded + b"{}"),
                           ("duplicate", encoded[:-1] + b',"kind":"path"}'),
                           ("invalid_utf8", b'{"kind":"\xff"}'),
                           ("scope_exponent", encoded.replace(b'"required_scopes":1', b'"required_scopes":1e0')),
                           ("oversize_line", b" " * (2 * STATE_LIMIT + 1))):
            self.add_request("probe/" + name, raw, error("invalid"))
        self.add_request("probe/unknown_field", dict(request, extra=True), error("invalid"))
        self.add_request("probe/valid_after_rejections", request, self.success())

    def build(self):
        self.fixture_paths()
        self.paths_and_scopes()
        self.times()
        self.keys_and_signatures()
        self.state_dependencies()
        self.revocations_and_isolation()
        self.strict_state()
        self.limits()
        self.strict_probe()
        return self.cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go-probe")
    parser.add_argument("--rust-probe")
    parser.add_argument("--probe", action="append", default=[], metavar="LABEL=PATH")
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--timeout", type=float, default=15)
    args = parser.parse_args()
    probes = [(label, path) for label, path in (("go", args.go_probe), ("rust", args.rust_probe)) if path]
    for value in args.probe:
        if "=" not in value:
            parser.error("--probe requires LABEL=PATH")
        probes.append(tuple(value.split("=", 1)))
    if not probes and not args.self_check:
        parser.error("supply probe paths or --self-check")
    vectors = {path.name: json.loads(path.read_bytes()) for path in sorted((ROOT / "conformance" / "vectors").glob("*.json"))}
    author = Author(vectors)
    fixed_count = author.oracle.fixture_self_check()
    cases = author.build()
    successes = sum(case.expected["ok"] for case in cases)
    print(f"Independent oracle: {fixed_count} public signatures reproduced; {len(cases)} path checks "
          f"({successes} successes, {len(cases) - successes} rejections).", flush=True)
    if not probes:
        print("Self-check only; no path implementation or live protocol was tested.")
        return 0
    failures = 0
    for label, executable in probes:
        probe = Probe(label, executable, args.timeout)
        start = failures
        checked = 0
        try:
            for case in cases:
                actual = probe.exchange(case.request)
                checked += 1
                if actual != case.expected:
                    failures += 1
                    print(f"FAIL {label} {case.name}: expected {case.expected!r}; received {actual!r}", file=sys.stderr)
                    if failures - start >= 20:
                        raise AssertionError("stopping after 20 failures")
            # Keep this explicit: deduplication of ordinary cases must not remove
            # the final stream-framing check following the oversize line.
            expected = author.success()
            if probe.exchange(author.request(author.state())) != expected:
                failures += 1
                print(f"FAIL {label}: valid path request after rejected lines", file=sys.stderr)
            checked += 1
        except (AssertionError, OSError) as failure:
            failures += 1
            print(f"FAIL {label}: {failure}", file=sys.stderr)
        finally:
            diagnostic = probe.close()
            if failures > start and diagnostic:
                print(f"{label} stderr: {diagnostic}", file=sys.stderr)
        print(f"{label}: {checked} path checks completed.", flush=True)
    if failures:
        print(f"FAILED: {failures} path conformance failures.", file=sys.stderr)
        return 1
    print("PASS: certificate paths over injected verified facts only; no catalog, complete activation, "
          "freshness, retention or transaction verification claim.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
