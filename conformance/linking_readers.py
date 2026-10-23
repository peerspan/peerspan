#!/usr/bin/env python3
"""Independent UP-06c signed-object reader conformance; Python standard library.

This checks cryptographic object readers, not live authority or transactions.
See docs/linking-reader-checks.md for the deliberately small probe protocol.
The implementation under test is always a subprocess, never imported here.
"""

import argparse
import base64
import copy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import select
import struct
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
MAX_OBJECT = 1024 * 1024
MAX_PAYLOAD = 256 * 1024
INVALID = {"ok": False, "code": "invalid"}


def b64(value):
    return base64.b64encode(value).decode("ascii")


def unb64(value):
    return base64.b64decode(value, validate=True)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def lines(*values):
    return "\n".join(str(value) for value in values).encode("utf-8")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def ssh_string(value):
    return struct.pack(">I", len(value)) + value


# Independent RFC 8032 arithmetic, used only with the published fixture seeds.
# Extended Edwards coordinates avoid an inversion for every point addition.
Q = 2 ** 255 - 19
ORDER = 2 ** 252 + 27742317777372353535851937790883648493
ED_D = -121665 * pow(121666, Q - 2, Q) % Q


def recover_x(y):
    square = (y * y - 1) * pow(ED_D * y * y + 1, Q - 2, Q) % Q
    x = pow(square, (Q + 3) // 8, Q)
    if (x * x - square) % Q:
        x = x * pow(2, (Q - 1) // 4, Q) % Q
    return Q - x if x & 1 else x


BASE_Y = 4 * pow(5, Q - 2, Q) % Q
BASE_X = recover_x(BASE_Y)
BASE = (BASE_X, BASE_Y, 1, BASE_X * BASE_Y % Q)


def add_points(p, q):
    x, y, z, t = p
    u, v, w, s = q
    a = (y - x) * (v - u) % Q
    b = (y + x) * (v + u) % Q
    c = 2 * ED_D * t * s % Q
    d = 2 * z * w % Q
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % Q, g * h % Q, f * g % Q, e * h % Q


def multiply_base(scalar):
    result, point = (0, 1, 1, 0), BASE
    while scalar:
        if scalar & 1:
            result = add_points(result, point)
        point = add_points(point, point)
        scalar >>= 1
    return result


def encode_point(point):
    x, y, z, _ = point
    inverse = pow(z, Q - 2, Q)
    x, y = x * inverse % Q, y * inverse % Q
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


class FixtureSigner:
    def __init__(self, seed):
        hashed = hashlib.sha512(seed).digest()
        self.scalar = int.from_bytes(hashed[:32], "little")
        self.scalar = (self.scalar & ((1 << 254) - 8)) | (1 << 254)
        self.prefix = hashed[32:]
        self.public = encode_point(multiply_base(self.scalar))

    def raw(self, message):
        r = int.from_bytes(hashlib.sha512(self.prefix + message).digest(), "little") % ORDER
        encoded_r = encode_point(multiply_base(r))
        h = int.from_bytes(hashlib.sha512(encoded_r + self.public + message).digest(),
                           "little") % ORDER
        return encoded_r + ((r + h * self.scalar) % ORDER).to_bytes(32, "little")

    def sshsig(self, message, namespace=b"peerspan-person-v1", reserved=b"",
               algorithm=b"sha512", version=1, trailing=b"", key_trailing=b"",
               signature_trailing=b""):
        hashed = hashlib.sha256(message).digest() if algorithm == b"sha256" else hashlib.sha512(message).digest()
        preimage = (b"SSHSIG" + ssh_string(namespace) + ssh_string(reserved)
                    + ssh_string(algorithm) + ssh_string(hashed))
        key = ssh_string(b"ssh-ed25519") + ssh_string(self.public) + key_trailing
        signature = ssh_string(b"ssh-ed25519") + ssh_string(self.raw(preimage)) + signature_trailing
        blob = (b"SSHSIG" + struct.pack(">I", version) + ssh_string(key)
                + ssh_string(namespace) + ssh_string(reserved) + ssh_string(algorithm)
                + ssh_string(signature) + trailing)
        return b64(blob)


def message(kind, obj):
    if kind == "certificate":
        return lines("peerspan-device-certificate-v1", *(obj[key] for key in (
            "network_id", "person_public_key", "device_public_key", "host_public_key",
            "parent_id", "scopes", "issued_at", "not_after", "request_id")))
    if kind == "person_record":
        return lines("peerspan-person-authorization-v1", *(obj[key] for key in (
            "kind", "network_id", "epoch", "operation_id", "person_public_key",
            "certificate_id")), digest(unb64(obj["payload_base64"])))
    if kind == "root_record":
        return lines("peerspan-root-authorization-v1", *(obj[key] for key in (
            "kind", "network_id", "epoch", "operation_id")),
            digest(unb64(obj["payload_base64"])))
    if kind == "device_revocation":
        return lines("peerspan-device-revoke-v1", *(obj[key] for key in (
            "network_id", "person_public_key", "target_device_public_key",
            "target_certificate_id", "issuer_certificate_id", "revoked_at")))
    if kind == "checkpoint":
        return lines("peerspan-person-checkpoint-v1", *(obj[key] for key in (
            "network_id", "person_public_key", "issuer_certificate_id", "issued_at")),
            len(obj["records"]), *obj["records"])
    if kind == "packet":
        return lines("peerspan-link-packet-v1", *(obj[key] for key in (
            "request_id", "role", "writer_public_key", "person_public_key",
            "certificate_id")), digest(unb64(obj["payload_base64"])))
    if kind == "feature":
        return message("feature_proposal", obj["proposal"])
    if kind == "feature_proposal":
        return lines("peerspan-link-feature-v1", obj["network_id"], obj["epoch"],
                     "1", obj["issued_at"], len(obj["host_public_keys"]),
                     *obj["host_public_keys"])
    if kind == "feature_ack":
        return lines("peerspan-link-feature-ack-v1", obj["feature_id"], obj["host_public_key"])
    if kind == "admin_removal_v2":
        return lines("peerspan-admin-remove-v2", obj["network_id"],
                     obj["person_public_key"], str(obj["revoke_admitted"]).lower(),
                     obj["removed_at"], len(obj["kept"]), *obj["kept"])
    raise AssertionError(kind)


def expected_reply(kind, obj):
    msg = message(kind, obj)
    prefixes = {"certificate": "dc_", "device_revocation": "dr_",
                "feature_proposal": "lf_", "feature": "lf_"}
    semantic_id = prefixes[kind] + digest(msg) if kind in prefixes else "-"
    if kind == "person_record":
        semantic_id = "ar_" + digest(lines("peerspan-authorized-record-v1", digest(msg),
                                            obj["signature"], obj["host_signature"]))
    elif kind == "root_record":
        semantic_id = "rr_" + digest(lines("peerspan-root-authorized-record-v1", digest(msg),
                                            obj["signature"]))
    elif kind == "packet":
        semantic_id = "lp_" + digest(lines("peerspan-link-packet-id-v1", digest(msg),
                                            obj["host_signature"], obj["device_signature"],
                                            obj["authority_signature"]))
    return {"ok": True, "message_base64": b64(msg), "id": semantic_id,
            "payload_base64": obj.get("payload_base64", "-")}


@dataclass
class Case:
    name: str
    kind: str
    raw: bytes
    signer: str
    device: str = "-"
    expected: dict = None

    def request(self):
        return {"kind": self.kind, "object_base64": b64(self.raw),
                "signer_public_key": self.signer, "device_public_key": self.device}


class Author:
    def __init__(self, vectors):
        self.vectors = vectors
        self.signers = {}
        self.signature_keys = {}
        self.cases = []
        self.seen = set()
        self.representatives = {}
        self.crypto_only_sources = set()
        for data in vectors.values():
            for key in data["keys"].values():
                public = key["public_key"]
                if public not in self.signers:
                    signer = FixtureSigner(unb64(key["seed_base64"]))
                    assert b64(signer.public) == public, "fixture public key derivation mismatch"
                    self.signers[public] = signer
            for vector in data["sshsig_vectors"] + data["raw_signature_vectors"]:
                self.signature_keys[vector["signature"]] = vector["signer_public_key"]

    def fixture_self_check(self):
        count = 0
        for data in self.vectors.values():
            for category in ("sshsig_vectors", "raw_signature_vectors"):
                for vector in data[category]:
                    msg = unb64(vector["message_base64"])
                    signer = self.signers[vector["signer_public_key"]]
                    actual = signer.sshsig(msg) if category == "sshsig_vectors" else b64(signer.raw(msg))
                    assert actual == vector["signature"], "signing oracle disagrees with " + vector["name"]
                    if "message_sha256" in vector:
                        assert digest(msg) == vector["message_sha256"]
                    count += 1
        primitive = self.vectors["machine-linking-v1.json"]
        fields = {"certificate": "certificate", "record": "person_record",
                  "revocation": "device_revocation", "checkpoint": "checkpoint"}
        for vector in primitive["sshsig_vectors"]:
            for field, kind in fields.items():
                if field in vector:
                    expected = expected_reply(kind, vector[field])
                    assert expected["message_base64"] == vector["message_base64"]
                    for id_field in ("certificate_id", "record_id", "revocation_id"):
                        if id_field in vector:
                            assert expected["id"] == vector[id_field]
        for case in self.vectors["machine-linking-transactions-v1.json"]["cases"]:
            assert expected_reply("packet", case["activation"]["commit"])["id"] == case["manifest_id"]
            owner = json.loads(unb64(case["activation"]["owner"]["payload_base64"]))
            assert expected_reply("certificate", owner["certificate"])["id"] == case["certificate_id"]
        return count

    def add(self, name, kind, obj, signer, device="-", valid=True, raw=None):
        encoded = wire(obj) if raw is None else raw
        key = kind, encoded, signer, device, valid
        if key in self.seen:
            return
        self.seen.add(key)
        case = Case(name, kind, encoded, signer, device,
                    expected_reply(kind, obj) if valid else INVALID)
        self.cases.append(case)
        if valid:
            self.representatives.setdefault(kind, case)

    def key_for(self, obj):
        if "role" in obj:
            signature = obj["authority_signature"]
            if signature == "-":
                signature = obj["host_signature"]
        elif "proposal" in obj:
            signature = obj["proposal"]["signature"]
        else:
            signature = obj["signature"]
        assert signature in self.signature_keys, "fixture signature has no independent key vector"
        return self.signature_keys[signature]

    def collect(self, obj, path, raw=None):
        if isinstance(obj, list):
            for index, item in enumerate(obj):
                self.collect(item, path + "/" + str(index))
            return
        if not isinstance(obj, dict):
            return
        kind = None
        if obj.get("format") == 1:
            if "parent_id" in obj and "signature" in obj:
                kind = "certificate"
            elif "role" in obj and "authority_signature" in obj:
                kind = "packet"
            elif "payload_base64" in obj and "operation_id" in obj:
                kind = "person_record" if "person_public_key" in obj else "root_record"
            elif "target_device_public_key" in obj:
                kind = "device_revocation"
            elif "records" in obj and "issuer_certificate_id" in obj:
                kind = "checkpoint"
            elif "host_public_keys" in obj and "signature" in obj:
                kind = "feature_proposal"
            elif "feature_id" in obj and "host_public_key" in obj and "signature" in obj:
                kind = "feature_ack"
        elif set(obj) == {"proposal", "acknowledgments"}:
            kind = "feature"
        if kind:
            device = self.signature_keys[obj["device_signature"]] if (
                kind == "packet" and obj["device_signature"] != "-") else "-"
            # The owner's signed binding draft is intentionally not a complete record.
            valid = not (kind == "person_record" and obj["kind"] == "peerspan-host-bind-v1"
                         and obj["host_signature"] == "-")
            self.add("fixture/" + path, kind, obj, self.key_for(obj), device, valid, raw)
        for field, value in obj.items():
            if field in ("body_base64", "payload_base64") and isinstance(value, str):
                decoded = unb64(value)
                self.collect(json.loads(decoded), path + "/decoded_" + field, decoded)
            else:
                self.collect(value, path + "/" + field)

    def resign(self, kind, obj, signer, device="-", ssh_options=None, suffix=b""):
        msg = message(kind, obj) + suffix
        provider = self.signers[signer]
        ssh_options = ssh_options or {}
        if kind == "packet":
            if obj["role"] in ("request", "selection", "commit"):
                obj["host_signature"] = b64(provider.raw(msg))
                obj["device_signature"] = self.signers[device].sshsig(msg, **ssh_options)
            elif obj["certificate_id"] in ("network_root", "coordinator"):
                obj["authority_signature"] = b64(provider.raw(msg))
            else:
                obj["authority_signature"] = provider.sshsig(msg, **ssh_options)
        elif kind in ("root_record", "feature_proposal", "feature_ack", "admin_removal_v2"):
            obj["signature"] = b64(provider.raw(msg))
        else:
            obj["signature"] = provider.sshsig(msg, **ssh_options)
            if kind == "person_record" and obj["kind"] == "peerspan-host-bind-v1":
                try:
                    host = json.loads(unb64(obj["payload_base64"]))["host_public_key"]
                except (ValueError, UnicodeError, TypeError, KeyError):
                    # The payload can deliberately be invalid JSON. Its authority
                    # signature and this consent still cover those exact bytes.
                    host = self.vectors["machine-linking-v1.json"]["keys"]["host_c"]["public_key"]
                if host not in self.signers:
                    host = self.vectors["machine-linking-v1.json"]["keys"]["host_c"]["public_key"]
                consent = lines("peerspan-binding-consent-v1", digest(msg))
                obj["host_signature"] = b64(self.signers[host].raw(consent))
        return obj

    def generated(self, name, kind, obj, signer, device="-", valid=True, raw=None):
        self.resign(kind, obj, signer, device)
        self.add("generated/" + name, kind, obj, signer, device, valid, raw)

    def add_record_registry(self):
        template = json.loads(self.representatives["person_record"].raw)
        data = self.vectors["machine-linking-v1.json"]
        keys = data["keys"]
        person = keys["person_root"]["public_key"]
        host = keys["host_c"]["public_key"]
        invite = keys["device_c"]["public_key"]
        network, at = data["network_id"], data["issued_at"]
        payloads = {
            "host-bind-v1": {"network_id": network, "person_public_key": person,
                             "host_public_key": host, "bound_at": at},
            "host-unbind-v1": {"network_id": network, "person_public_key": person,
                               "host_public_key": host, "unbound_at": at},
            "host-admit-v1": {"network_id": network, "epoch": 1, "host_public_key": host,
                              "member": "alice", "admitted_at": at},
            "person-admit-v1": {"network_id": network, "epoch": 1,
                                "person_public_key": person, "member": "alice", "admitted_at": at},
            "person-remove-v1": {"network_id": network, "person_public_key": person, "removed_at": at},
            "revoke-host-v1": {"network_id": network, "host_public_key": host, "revoked_at": at},
            "revoke-invite-v1": {"network_id": network, "invite_public_key": invite, "revoked_at": at},
            "invite-v1": {"network_id": network, "invite_public_key": invite,
                          "member": "alice", "invite_expires_at": "2026-10-24T12:00:00Z"},
            "person-invite-v1": {"network_id": network, "invite_epoch": 1,
                                 "invite_public_key": invite, "member": "alice",
                                 "invite_expires_at": "2026-10-24T12:00:00Z"},
            "group-v1": {"network_id": network, "name": "team", "version": 1,
                         "defined_at": at, "members": ["person_" + digest(unb64(person))]},
        }
        for suffix, payload in payloads.items():
            obj = copy.deepcopy(template)
            obj.update(kind="peerspan-" + suffix, certificate_id="root",
                       person_public_key=person, host_signature="-", payload_base64=b64(wire(payload)))
            self.generated("registry/" + suffix, "person_record", obj, person)
            for bad_name, bad in (("unknown", dict(payload, extra=True)),
                                  ("null", dict(payload, **{next(iter(payload)): None}))):
                malformed = copy.deepcopy(obj)
                malformed["payload_base64"] = b64(wire(bad))
                self.generated("registry/" + suffix + "/" + bad_name,
                               "person_record", malformed, person, valid=False)
        group = copy.deepcopy(template)
        group.update(kind="peerspan-group-v1", certificate_id="root",
                     person_public_key=person, host_signature="-")
        member = payloads["group-v1"]["members"][0]
        for name, members, valid in (("empty", [], True), ("raw_key", [person], False),
                                      ("label", ["alice"], False),
                                      ("duplicate", [member, member], False),
                                      ("unsorted", ["person_" + "f" * 64, "person_" + "0" * 64], False)):
            group["payload_base64"] = b64(wire(dict(payloads["group-v1"], members=members)))
            self.generated("registry/group-v1/" + name, "person_record", copy.deepcopy(group),
                           person, valid=valid)
        # A network root may use either permitted signature format for its new domain.
        root = copy.deepcopy(json.loads(self.representatives["root_record"].raw))
        signer = self.representatives["root_record"].signer
        root["signature"] = self.signers[signer].sshsig(message("root_record", root))
        self.add("generated/root_record/sshsig", "root_record", root, signer)

    def add_policies(self):
        case = self.representatives["person_record"]
        data = self.vectors["machine-linking-v1.json"]
        person = data["keys"]["person_root"]["public_key"]
        host_id = "host_" + digest(unb64(data["keys"]["host_c"]["public_key"]))
        rule = {"agent": "reviewer", "principals": ["network"],
                "actions": ["message.append"], "max_message_bytes": 65536,
                "allow_disconnected": False}
        base = {"network_id": data["network_id"], "person_public_key": person,
                "version": 1, "issued_at": data["issued_at"],
                "valid_until": "2026-10-30T12:00:00Z", "rules": [rule]}
        capability = {"host": host_id, "capability": "docs", "principals": ["network"],
                      "max_input_bytes": 65536, "allow_disconnected": False,
                      "max_calls_per_hour": 100}
        v2 = dict(base, format=2, capability_rules=[capability],
                  trusted_hosts=[host_id], edits=[{"host": host_id, "seq": 1}])
        for version, payload in ((1, base), (2, v2)):
            obj = json.loads(case.raw)
            obj.update(kind="peerspan-policy-v" + str(version), certificate_id="root",
                       person_public_key=person, host_signature="-", payload_base64=b64(wire(payload)))
            self.generated("policy/v" + str(version), "person_record", obj, person)
            variants = [("unknown_payload", dict(payload, extra=True)),
                        ("null_rules", dict(payload, rules=None)),
                        ("zero_version", dict(payload, version=0)),
                        ("wrong_person", dict(payload, person_public_key=data["keys"]["device_b"]["public_key"])),
                        ("rule_unknown", dict(payload, rules=[dict(rule, extra=True)])),
                        ("rule_null", dict(payload, rules=[dict(rule, principals=None)])),
                        ("rule_bad_action", dict(payload, rules=[dict(rule, actions=["anything"])])),
                        ("rule_bool_limit", dict(payload, rules=[dict(rule, max_message_bytes=True)]))]
            if version == 2:
                variants += [("capability_unknown", dict(payload, capability_rules=[dict(capability, extra=True)])),
                             ("capability_null", dict(payload, capability_rules=[dict(capability, principals=None)])),
                             ("edit_unknown", dict(payload, edits=[{"host": host_id, "seq": 1, "extra": True}])),
                             ("edit_zero", dict(payload, edits=[{"host": host_id, "seq": 0}])),
                             ("trusted_bad_id", dict(payload, trusted_hosts=[person]))]
            for name, changed in variants:
                malformed = copy.deepcopy(obj)
                malformed["payload_base64"] = b64(wire(changed))
                self.generated("policy/v" + str(version) + "/" + name, "person_record",
                               malformed, person, valid=False)
            # The integer's spelling is inside the signed payload, so a still-valid
            # signature prevents a signature mismatch from masking lexical acceptance.
            malformed = copy.deepcopy(obj)
            malformed["payload_base64"] = b64(wire(payload).replace(b'"version":1', b'"version":1e0'))
            self.generated("policy/v" + str(version) + "/exponent_integer", "person_record",
                           malformed, person, valid=False)

    def add_admin_removal(self):
        data = self.vectors["machine-linking-v1.json"]
        signer = data["keys"]["network_root"]["public_key"]
        obj = {"format": 2, "network_id": data["network_id"],
               "person_public_key": data["keys"]["person_root"]["public_key"],
               "revoke_admitted": False, "removed_at": data["issued_at"],
               "kept": ["legacy:" + "0" * 64, "record:ar_" + "1" * 64,
                        "redemption:pf_" + "2" * 64]}
        self.generated("admin_removal/retained", "admin_removal_v2", obj, signer)
        for name, fields, valid in (
                ("irreversible", {"revoke_admitted": True, "kept": []}, True),
                ("true_with_kept", {"revoke_admitted": True}, False),
                ("unsorted", {"kept": list(reversed(obj["kept"]))}, False),
                ("duplicate", {"kept": [obj["kept"][0]] * 2}, False),
                ("bad_reference", {"kept": ["record:dc_" + "0" * 64]}, False)):
            changed = copy.deepcopy(obj)
            changed.update(fields)
            self.generated("admin_removal/" + name, "admin_removal_v2", changed, signer, valid=valid)
        obj["signature"] = self.signers[signer].sshsig(message("admin_removal_v2", obj))
        self.add("generated/admin_removal/sshsig", "admin_removal_v2", obj, signer)

    def add_generic_rejections(self):
        alternate = self.vectors["machine-linking-v1.json"]["keys"]["network_root"]["public_key"]
        for kind, case in list(self.representatives.items()):
            obj = json.loads(case.raw)
            key = next(iter(obj))
            for field in obj:
                self.add("strict/" + kind + "/missing_" + field, kind, obj,
                         case.signer, case.device, valid=False,
                         raw=wire({k: v for k, v in obj.items() if k != field}))
                self.add("strict/" + kind + "/null_" + field, kind, obj,
                         case.signer, case.device, valid=False,
                         raw=wire(dict(obj, **{field: None})))
            for name, raw in (
                    ("duplicate", case.raw[:-1] + b"," + wire(key) + b":" + wire(obj[key]) + b"}"),
                    ("escaped_duplicate", case.raw[:-1] + b',"\\u' + format(ord(key[0]), "04x").encode()
                     + key[1:].encode() + b'":' + wire(obj[key]) + b"}"),
                    ("unknown", wire(dict(obj, unrecognized=True))),
                    ("null", wire(dict(obj, **{key: None}))),
                    ("missing", wire({k: v for k, v in obj.items() if k != key})),
                    ("invalid_utf8", case.raw[:-1] + b',"\xff":1}'),
                    ("trailing_json", case.raw + b"{}"),
                    ("trailing_junk", case.raw + b"x"),
                    ("wrong_root_type", b"[]"),
                    ("oversize", case.raw + b" " * (MAX_OBJECT + 1 - len(case.raw))),
                    ("deep", b"[" * 100 + b"0" + b"]" * 100)):
                self.add("strict/" + kind + "/" + name, kind, obj, case.signer,
                         case.device, valid=False, raw=raw)
            wrong_signer = alternate if case.signer != alternate else next(
                key for key in self.signers if key != alternate)
            self.add("strict/" + kind + "/independent_signer", kind, obj, wrong_signer,
                     case.device, valid=False)
            for name, bad_key in (("unpadded_key", case.signer.rstrip("=")),
                                  ("invalid_key_length", b64(b"x" * 31)),
                                  ("invalid_signing_point", b64(b"\xff" * 32))):
                self.add("strict/" + kind + "/" + name, kind, obj, bad_key,
                         case.device, valid=False)
            if "format" in obj:
                raw = wire(obj)
                spelling = b'"format":' + str(obj["format"]).encode()
                for value in (b"1.0", b"1e0", b"true", b"01", b'"1"'):
                    self.add("strict/" + kind + "/integer_" + value.decode(), kind,
                             obj, case.signer, case.device, valid=False,
                             raw=raw.replace(spelling, b'"format":' + value, 1))
            for field in ("epoch", "scopes", "version"):
                if type(obj.get(field)) is not int:
                    continue
                raw = wire(obj)
                spelling = wire(field) + b":" + str(obj[field]).encode()
                for suffix in (b".0", b"e0"):
                    replacement = spelling + suffix
                    self.add("strict/" + kind + "/" + field + suffix.decode(), kind,
                             obj, case.signer, case.device, valid=False,
                             raw=raw.replace(spelling, replacement, 1))

    def add_encoding_checks(self):
        for kind in ("certificate", "person_record", "device_revocation", "checkpoint"):
            case = self.representatives[kind]
            obj = json.loads(case.raw)
            for name, options in (
                    ("namespace", {"namespace": b"another-namespace"}),
                    ("hash", {"algorithm": b"sha256"}),
                    ("reserved", {"reserved": b"reserved"}),
                    ("version", {"version": 2}),
                    ("trailing", {"trailing": b"x"}),
                    ("key_trailing", {"key_trailing": b"x"}),
                    ("signature_trailing", {"signature_trailing": b"x"})):
                changed = copy.deepcopy(obj)
                self.resign(kind, changed, case.signer, ssh_options=options)
                self.add("sshsig/" + kind + "/" + name, kind, changed, case.signer, valid=False)
            changed = copy.deepcopy(obj)
            self.resign(kind, changed, case.signer, suffix=b"\n")
            self.add("sshsig/" + kind + "/signed_trailing_lf", kind, changed, case.signer, valid=False)
            for name, transform in (
                    ("base64_whitespace", lambda value: value + "\n"),
                    ("base64_extra_padding", lambda value: value + "="),
                    ("corrupt_signature", lambda value: b64(unb64(value)[:-1] + bytes([unb64(value)[-1] ^ 1]))),
                    ("truncated_signature", lambda value: b64(unb64(value)[:-1]))):
                changed = copy.deepcopy(obj)
                changed["signature"] = transform(changed["signature"])
                self.add("sshsig/" + kind + "/" + name, kind, changed, case.signer, valid=False)
        # Raw and SSHSIG signature scalars must be canonical (S < the group order).
        for kind in ("certificate", "feature_ack"):
            case = self.representatives[kind]
            obj = json.loads(case.raw)
            encoded = bytearray(unb64(obj["signature"]))
            scalar = int.from_bytes(encoded[-32:], "little") + ORDER
            encoded[-32:] = scalar.to_bytes(32, "little")
            obj["signature"] = b64(encoded)
            self.add("signature/" + kind + "/noncanonical_scalar", kind, obj, case.signer, valid=False)
        case = self.representatives["certificate"]
        template = json.loads(case.raw)
        for field, values in {
                "scopes": [0, 16, -1, True, "15", 1.5],
                "format": [0, 2],
                "network_id": ["net_" + "A" * 64, "net_" + "a" * 63, "net_" + "g" * 64],
                "parent_id": ["-", "ar_" + "0" * 64],
                "request_id": ["link_" + "F" * 64, "link_" + "0" * 65],
                "issued_at": ["2026-02-30T12:00:00Z", "2026-10-23T12:00:60Z",
                              "2026-10-23T12:00:00+00:00", "2026-10-23T12:00:00.0Z"],
                "not_after": [template["issued_at"], "2026-10-22T12:00:00Z", "2027-01-21T12:00:01Z"],
                "device_public_key": [template["device_public_key"].rstrip("="), b64(b"x" * 31)],
                "host_public_key": [template["host_public_key"] + "=", template["host_public_key"] + "\r"]
        }.items():
            for index, value in enumerate(values):
                obj = copy.deepcopy(template)
                obj[field] = value
                self.generated("certificate/" + field + "/" + str(index), "certificate",
                               obj, case.signer, valid=False)
        # A different spelling of the same 32 bytes with nonzero unused pad bits.
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        obj = copy.deepcopy(template)
        value = obj["device_public_key"]
        obj["device_public_key"] = value[:-2] + alphabet[alphabet.index(value[-2]) ^ 1] + "="
        self.generated("certificate/key_pad_bits", "certificate", obj, case.signer, valid=False)

    def add_payload_checks(self):
        for kind in ("person_record", "root_record", "packet"):
            case = self.representatives[kind]
            template = json.loads(case.raw)
            original = unb64(template["payload_base64"])
            payload = json.loads(original)
            key = next(iter(payload))
            for name, payload_bytes in (
                    ("duplicate", original[:-1] + b"," + wire(key) + b":" + wire(payload[key]) + b"}"),
                    ("unknown", wire(dict(payload, unexpected=True))),
                    ("null", wire(dict(payload, **{key: None}))),
                    ("invalid_utf8", original[:-1] + b',"\xff":1}'),
                    ("trailing_json", original + b"{}"),
                    ("non_object", b"[]"),
                    ("oversize", original + b" " * (MAX_PAYLOAD + 1 - len(original))),
                    ("deep", b"[" * 100 + b"0" + b"]" * 100)):
                obj = copy.deepcopy(template)
                obj["payload_base64"] = b64(payload_bytes)
                self.generated("payload/" + kind + "/" + name, kind, obj,
                               case.signer, case.device, valid=False)
            # Semantically identical JSON with new bytes must be signed and hashed as supplied.
            changed_bytes = b" \n" + json.dumps(payload, indent=2, sort_keys=False,
                                                  ensure_ascii=True).encode() + b" \t"
            obj = copy.deepcopy(template)
            obj["payload_base64"] = b64(changed_bytes)
            self.generated("payload/" + kind + "/retained_whitespace", kind, obj,
                           case.signer, case.device)
            obj = copy.deepcopy(template)
            obj["payload_base64"] = b64(changed_bytes)
            self.add("payload/" + kind + "/reserialization_not_signature", kind, obj,
                     case.signer, case.device, valid=False)
            obj = copy.deepcopy(template)
            obj["payload_base64"] += "="
            self.add("payload/" + kind + "/noncanonical_base64", kind, obj,
                     case.signer, case.device, valid=False)
        # All six packet payload field sets, including a signed wrong field set.
        packets = [case for case in self.cases if case.kind == "packet" and case.expected != INVALID]
        roles = {}
        for case in packets:
            roles.setdefault(json.loads(case.raw)["role"], case)
        for role, case in roles.items():
            template = json.loads(case.raw)
            for name, change in (
                    ("extra_host_role", {"host_signature": b64(b"\0" * 64)}),
                    ("extra_authority_role", {"authority_signature": b64(b"\0" * 64)}),
                    ("missing_signature", {("device_signature" if case.device != "-"
                                             else "authority_signature"): "-"})):
                obj = copy.deepcopy(template)
                obj.update(change)
                if obj != template:
                    self.add("packet/" + role + "/" + name, "packet", obj,
                             case.signer, case.device, valid=False)
            payload = json.loads(unb64(template["payload_base64"]))
            payload["unexpected"] = True
            obj = copy.deepcopy(template)
            obj["payload_base64"] = b64(wire(payload))
            self.generated("packet/" + role + "/signed_unknown_payload", "packet", obj,
                           case.signer, case.device, valid=False)
            if case.device != "-":
                other = next(key for key in self.signers if key != case.device)
                self.add("packet/" + role + "/independent_device", "packet", template,
                         case.signer, other, valid=False)
            if template["certificate_id"] == "root":
                other = next(key for key in self.signers if key != case.signer)
                obj = copy.deepcopy(template)
                obj["writer_public_key"] = other
                self.generated("packet/" + role + "/root_person_mismatch", "packet", obj,
                               other, valid=False)
        binding = json.loads(self.representatives["person_record"].raw)
        signer = self.representatives["person_record"].signer
        for name, value in (("missing", "-"), ("wrong", b64(b"\0" * 64)),
                            ("noncanonical", binding["host_signature"] + "=")):
            obj = copy.deepcopy(binding)
            obj["host_signature"] = value
            self.add("binding/consent_" + name, "person_record", obj, signer, valid=False)
        # A valid SSHSIG from an unrelated key is not original-person authority.
        obj = copy.deepcopy(binding)
        obj["certificate_id"] = "root"
        other = next(key for key in self.signers if key != obj["person_public_key"])
        self.generated("person_record/root_person_mismatch", "person_record", obj,
                       other, valid=False)

    def add_set_checks(self):
        case = self.representatives["feature"]
        template = json.loads(case.raw)
        for name, modify in (
                ("missing_ack", lambda obj: obj["acknowledgments"].pop()),
                ("duplicate_ack", lambda obj: obj["acknowledgments"].append(copy.deepcopy(obj["acknowledgments"][0]))),
                ("unsorted_ack", lambda obj: obj["acknowledgments"].reverse()),
                ("bad_ack", lambda obj: obj["acknowledgments"][0].update(signature=b64(b"\0" * 64))),
                ("wrong_ack_feature", lambda obj: obj["acknowledgments"][0].update(feature_id="lf_" + "0" * 64)),
                ("unknown_nested", lambda obj: obj["proposal"].update(unexpected=True)),
                ("null_nested", lambda obj: obj["acknowledgments"][0].update(format=None))):
            obj = copy.deepcopy(template)
            modify(obj)
            if name == "wrong_ack_feature":
                ack = obj["acknowledgments"][0]
                self.resign("feature_ack", ack, ack["host_public_key"])
            self.add("feature/" + name, "feature", obj, case.signer, valid=False)
        case = self.representatives["feature_proposal"]
        template = json.loads(case.raw)
        for name, hosts in (("empty", []), ("unsorted", list(reversed(template["host_public_keys"]))),
                            ("duplicate", template["host_public_keys"] * 2)):
            obj = copy.deepcopy(template)
            obj["host_public_keys"] = hosts
            self.generated("feature_proposal/" + name, "feature_proposal", obj, case.signer, valid=False)
        obj = copy.deepcopy(template)
        obj["signature"] = self.signers[case.signer].sshsig(message("feature_proposal", obj))
        self.add("feature_proposal/sshsig", "feature_proposal", obj, case.signer)
        case = self.representatives["checkpoint"]
        template = json.loads(case.raw)
        for name, records, valid in (
                ("empty", [], True),
                ("completed_redemption", ["pf_" + "1" * 64], True),
                ("unsorted", list(reversed(template["records"])), False),
                ("duplicate", template["records"] * 2, False),
                ("certificate", ["dc_" + "0" * 64], False),
                ("uppercase", ["ar_" + "A" * 64], False)):
            obj = copy.deepcopy(template)
            obj["records"] = records
            self.generated("checkpoint/" + name, "checkpoint", obj, case.signer, valid=valid)

    def add_context_and_nested_checks(self):
        for kind, pointer in (("certificate", "parent_id"),
                              ("device_revocation", "issuer_certificate_id"),
                              ("checkpoint", "issuer_certificate_id")):
            case = self.representatives[kind]
            obj = json.loads(case.raw)
            obj[pointer] = "root"
            other = next(key for key in self.signers if key != obj["person_public_key"])
            self.generated("context/" + kind + "/root_person_mismatch", kind,
                           obj, other, valid=False)
        # A small-order expected signer and matching embedded key must be rejected,
        # even when a weak group-equation-only verifier accepts the forged signature.
        case = self.representatives["certificate"]
        obj = json.loads(case.raw)
        identity = b"\x01" + b"\x00" * 31
        obj.update(parent_id="root", person_public_key=b64(identity))
        key = ssh_string(b"ssh-ed25519") + ssh_string(identity)
        signature = ssh_string(b"ssh-ed25519") + ssh_string(identity + b"\x00" * 32)
        obj["signature"] = b64(b"SSHSIG" + struct.pack(">I", 1) + ssh_string(key)
                               + ssh_string(b"peerspan-person-v1") + ssh_string(b"")
                               + ssh_string(b"sha512") + ssh_string(signature))
        self.add("context/small_order_signer", "certificate", obj, b64(identity), valid=False)
        packets = {}
        for case in self.cases:
            if case.kind == "packet" and case.expected != INVALID:
                packets.setdefault(json.loads(case.raw)["role"], case)
        for role, nested_fields in (("owner", ("network", "certificate", "binding_record")),
                                    ("administrator", ("admission_record",))):
            case = packets[role]
            template = json.loads(case.raw)
            original = json.loads(unb64(template["payload_base64"]))
            for field in nested_fields:
                assert isinstance(original[field], dict)
                for name, value in (("unknown", dict(original[field], unexpected=True)),
                                    ("null", dict(original[field], **{next(iter(original[field])): None}))):
                    payload = copy.deepcopy(original)
                    payload[field] = value
                    obj = copy.deepcopy(template)
                    obj["payload_base64"] = b64(wire(payload))
                    self.generated("packet/" + role + "/nested_" + field + "/" + name,
                                   "packet", obj, case.signer, case.device, valid=False)
        # Envelope/payload agreement is structural; it does not require live state.
        for kind in ("person_record", "root_record"):
            case = self.representatives[kind]
            template = json.loads(case.raw)
            original = json.loads(unb64(template["payload_base64"]))
            for field in ("network_id", "epoch"):
                if field not in original:
                    continue
                payload = copy.deepcopy(original)
                payload[field] = "net_" + "0" * 64 if field == "network_id" else template["epoch"] + 1
                obj = copy.deepcopy(template)
                obj["payload_base64"] = b64(wire(payload))
                self.generated("payload/" + kind + "/mismatched_" + field, kind, obj,
                               case.signer, valid=False)
        case = self.representatives["root_record"]
        for name, changes in (("ordinary_operation", {"operation_id": "-"}),
                               ("other_kind", {"kind": "peerspan-person-admit-v1"})):
            obj = json.loads(case.raw)
            obj.update(changes)
            self.generated("root_record/" + name, "root_record", obj, case.signer, valid=False)
        case = self.representatives["person_record"]
        obj = json.loads(case.raw)
        obj.update(kind="peerspan-admin-delegate-v1", host_signature="-")
        self.generated("person_record/root_only_kind", "person_record", obj, case.signer, valid=False)

    def add_boundaries(self):
        case = self.representatives["certificate"]
        obj = json.loads(case.raw)
        self.add("limits/exact_1MiB_object", "certificate", obj, case.signer,
                 raw=case.raw + b" " * (MAX_OBJECT - len(case.raw)))
        for kind in ("person_record", "root_record", "packet"):
            case = self.representatives[kind]
            obj = json.loads(case.raw)
            payload = unb64(obj["payload_base64"])
            obj["payload_base64"] = b64(payload + b" " * (MAX_PAYLOAD - len(payload)))
            self.generated("limits/" + kind + "/exact_256KiB_payload", kind,
                           obj, case.signer, case.device)
        for case in list(self.cases):
            if case.kind != "packet" or case.expected == INVALID:
                continue
            packet = json.loads(case.raw)
            if packet["role"] != "commit":
                continue
            payload_bytes = unb64(packet["payload_base64"])
            if json.loads(payload_bytes)["mode"] != "renew":
                continue
            # JSON string escapes are decoded for scalar checks, while payload
            # hashing and retention still use the exact original UTF-8 bytes.
            escaped = payload_bytes.replace(b'"-"', b'"\\u002d"')
            assert escaped != payload_bytes
            packet["payload_base64"] = b64(escaped)
            self.generated("json_unicode_absent/retained_packet_payload", "packet", packet,
                           case.signer, case.device)
            packet = json.loads(case.raw)
            self.add("json_unicode_absent/packet_wrapper", "packet", packet,
                     case.signer, case.device,
                     raw=case.raw.replace(b'"-"', b'"\\u002d"'))
            break
        else:
            raise AssertionError("fixture set must include a renewal commit")

    def add_packet_type_checks(self):
        # These field types are listed in transaction contract sections 1 and 3.
        # Alter the retained payload, then sign its new hash with both required
        # wrapper keys. A signature mismatch therefore cannot mask a type error.
        schemas = {
            "request": {
                "mode": "string", "host_public_key": "string", "device_public_key": "string",
                "request_nonce": "string", "coordinator_address": "string",
                "coordinator_public_key": "string", "created_at": "string", "expires_at": "string",
                "expected_network_id": "string", "expected_person_public_key": "string",
                "renewed_certificate_id": "string"},
            "owner": {
                "request_packet_id": "string", "network": "object", "epoch": "integer",
                "feature_id": "string", "person_public_key": "string", "certificate": "object",
                "binding_record": "object_or_absent", "membership_proof_id": "string",
                "binding_proof_id": "string"},
            "selection": {
                "owner_offer_id": "string", "network_id": "string", "epoch": "integer",
                "feature_id": "string", "person_public_key": "string"},
            "administrator": {
                "owner_offer_id": "string", "selection_id": "string", "admission_record": "object"},
            "commit": {
                "mode": "string", "request_packet_id": "string", "owner_offer_id": "string",
                "selection_id": "string", "administrator_offer_id": "string", "network_id": "string",
                "epoch": "integer", "feature_id": "string", "person_public_key": "string",
                "certificate_id": "string", "binding_record": "object_or_absent",
                "admission_record_id": "string", "expires_at": "string"},
            "result": {"manifest_id": "string", "activation": "object", "catalog": "object"},
        }
        network_schema = {field: "string" for field in (
            "network_id", "name", "genesis_root_public_key", "coordinator_address", "coordinator_public_key")}
        certificate_schema = {field: "string" for field in (
            "network_id", "person_public_key", "device_public_key", "host_public_key",
            "parent_id", "issued_at", "not_after", "request_id", "signature")}
        certificate_schema.update(format="integer", scopes="integer")
        person_record_schema = {field: "string" for field in (
            "kind", "network_id", "operation_id", "person_public_key", "certificate_id",
            "payload_base64", "signature", "host_signature")}
        person_record_schema.update(format="integer", epoch="integer")
        activation_schema = {field: "object" for field in ("request", "owner", "selection", "commit")}
        activation_schema["administrator"] = "object_or_absent"
        catalog_schema = {"format": "integer", "network_id": "string", "objects": "array"}
        proof_schema = {field: "string" for field in ("id", "kind", "body_base64")}
        wrong_values = {
            "string": (("number", 7), ("boolean", True), ("array", []), ("object", {}), ("null", None)),
            "integer": (("float", 1.0), ("boolean", True), ("string", "1"),
                        ("array", []), ("object", {}), ("null", None)),
            "object": (("number", 7), ("boolean", True), ("string", "wrong"), ("array", []), ("null", None)),
            "object_or_absent": (("number", 7), ("boolean", True), ("string", "wrong"),
                                 ("array", []), ("null", None)),
            "array": (("number", 7), ("boolean", True), ("string", "wrong"), ("object", {}), ("null", None)),
        }
        packets = {}
        for case in self.cases:
            if case.kind == "packet" and case.expected != INVALID:
                packets.setdefault(json.loads(case.raw)["role"], case)
        assert set(packets) == set(schemas), "fixture set must cover all six packet roles"

        def apply_schema(role, case, prefix, schema):
            template = json.loads(case.raw)
            original = json.loads(unb64(template["payload_base64"]))
            target = original
            for component in prefix:
                target = target[component]
            assert isinstance(target, dict)
            assert set(target) == set(schema), "contract field set disagrees with fixture at " + role + "/" + repr(prefix)
            for field, field_type in schema.items():
                for value_name, value in wrong_values[field_type]:
                    changed = copy.deepcopy(original)
                    parent = changed
                    for component in prefix:
                        parent = parent[component]
                    parent[field] = copy.deepcopy(value)
                    packet = copy.deepcopy(template)
                    packet["payload_base64"] = b64(wire(changed))
                    path = "/".join(str(component) for component in (*prefix, field))
                    self.generated("packet_types/" + role + "/" + path + "/" + value_name,
                                   "packet", packet, case.signer, case.device, valid=False)

        for role, schema in schemas.items():
            apply_schema(role, packets[role], (), schema)
        apply_schema("owner", packets["owner"], ("network",), network_schema)
        apply_schema("owner", packets["owner"], ("certificate",), certificate_schema)
        apply_schema("owner", packets["owner"], ("binding_record",), person_record_schema)
        apply_schema("result", packets["result"], ("activation",), activation_schema)
        apply_schema("result", packets["result"], ("catalog",), catalog_schema)
        apply_schema("result", packets["result"], ("catalog", "objects", 0), proof_schema)

    def add_uint64_version_checks(self):
        # The shared reader representation is uint64. Live version progression
        # and storage remain outside this signature-and-wire reader slice.
        for domain in ("peerspan-policy-v1", "peerspan-policy-v2", "peerspan-group-v1"):
            for case in self.cases:
                if case.kind != "person_record" or case.expected == INVALID:
                    continue
                template = json.loads(case.raw)
                if template["kind"] == domain:
                    break
            else:
                raise AssertionError("missing valid version fixture for " + domain)
            payload = json.loads(unb64(template["payload_base64"]))
            for name, version in (("2pow63", 1 << 63), ("uint64_max", (1 << 64) - 1)):
                changed = dict(payload, version=version)
                record = copy.deepcopy(template)
                record["payload_base64"] = b64(wire(changed))
                self.generated("uint64_version/" + domain + "/" + name, "person_record",
                               record, case.signer, valid=True)
            # Preserve each rejected token literally inside the signed payload.
            # In particular 1e0 must not be converted to Python's 1.0 spelling.
            original = wire(payload)
            version_field = b'"version":' + str(payload["version"]).encode("ascii")
            assert original.count(version_field) == 1
            for name, literal in (("zero", b"0"), ("negative", b"-1"),
                                  ("fraction", b"1.5"), ("exponent", b"1e0"),
                                  ("uint64_overflow", str(1 << 64).encode("ascii"))):
                record = copy.deepcopy(template)
                record["payload_base64"] = b64(original.replace(version_field, b'"version":' + literal))
                self.generated("uint64_version/" + domain + "/" + name, "person_record",
                               record, case.signer, valid=False)

    def build(self):
        for filename, data in self.vectors.items():
            for source in data.get("cases", []):
                if source.get("expected", {}).get("code") not in (None, "committed"):
                    self.crypto_only_sources.add(source["name"])
            self.collect(data, filename)
        self.add_record_registry()
        self.add_policies()
        self.add_admin_removal()
        self.add_generic_rejections()
        self.add_encoding_checks()
        self.add_payload_checks()
        self.add_set_checks()
        self.add_context_and_nested_checks()
        self.add_boundaries()
        self.add_packet_type_checks()
        self.add_uint64_version_checks()
        return self.cases


class Probe:
    def __init__(self, label, executable, timeout):
        self.label = label
        self.timeout = timeout
        self.stderr = tempfile.TemporaryFile()
        self.process = subprocess.Popen([str(Path(executable).resolve())], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=self.stderr, bufsize=0)
        self.pending = b""

    def exchange(self, request):
        data = request if isinstance(request, bytes) else wire(request)
        try:
            remaining = memoryview(data + b"\n")
            while remaining:
                count = self.process.stdin.write(remaining)
                if not count:
                    raise BrokenPipeError("probe stopped accepting input")
                remaining = remaining[count:]
            self.process.stdin.flush()
        except BrokenPipeError as error:
            raise AssertionError("probe exited while reading input") from error
        while b"\n" not in self.pending:
            ready, _, _ = select.select([self.process.stdout], [], [], self.timeout)
            if not ready:
                raise AssertionError("probe response timeout")
            chunk = self.process.stdout.read(65536)
            if not chunk:
                raise AssertionError("probe exited without a response")
            self.pending += chunk
            if len(self.pending) > 2 * MAX_OBJECT:
                raise AssertionError("probe response exceeds 2 MiB")
        line, self.pending = self.pending.split(b"\n", 1)
        try:
            return json.loads(line)
        except (ValueError, UnicodeError) as error:
            raise AssertionError("probe emitted non-JSON stdout") from error

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.stderr.seek(0)
        diagnostic = self.stderr.read(4096).decode("utf-8", "replace")
        self.stderr.close()
        return diagnostic


def outer_rejections(case):
    request = case.request()
    yield "outer/non_json", b"{"
    yield "outer/trailing_json", wire(request) + b"{}"
    yield "outer/duplicate", wire(request)[:-1] + b',"kind":' + wire(request["kind"]) + b"}"
    yield "outer/unknown", dict(request, extra=True)
    yield "outer/unsupported", dict(request, kind="activate")
    yield "outer/null", dict(request, object_base64=None)
    yield "outer/missing", {key: value for key, value in request.items() if key != "signer_public_key"}
    yield "outer/noncanonical_base64", dict(request, object_base64=request["object_base64"] + "=")
    yield "outer/invalid_utf8", b'{"kind":"\xff"}'
    yield "outer/oversize_line", b" " * (2 * MAX_OBJECT + 1)


def mismatch(expected, actual):
    if expected == INVALID:
        if not isinstance(actual, dict):
            return "expected invalid; received " + repr(actual)
        return "expected invalid; received " + repr({key: actual.get(key) for key in ("ok", "id", "code")})
    if not isinstance(actual, dict) or actual.get("ok") is not True:
        return "expected signature-verified object " + expected["id"] + "; received " + repr(actual)
    changed = sorted(key for key in set(expected) | set(actual) if expected.get(key) != actual.get(key))
    return "response differs in " + ", ".join(changed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go-probe", help="Go conformance reader probe executable")
    parser.add_argument("--rust-probe", help="Rust conformance reader probe executable")
    parser.add_argument("--probe", action="append", default=[], metavar="LABEL=PATH",
                        help="additional/single probe; no shell is used")
    parser.add_argument("--self-check", action="store_true", help="check public fixtures and independent signing oracle only")
    parser.add_argument("--timeout", type=float, default=15, help="response timeout in seconds")
    args = parser.parse_args()
    probes = [(label, path) for label, path in (("go", args.go_probe), ("rust", args.rust_probe)) if path]
    for value in args.probe:
        if "=" not in value:
            parser.error("--probe requires LABEL=PATH")
        probes.append(tuple(value.split("=", 1)))
    if not probes and not args.self_check:
        parser.error("supply --go-probe/--rust-probe, --probe LABEL=PATH, or --self-check")
    filenames = ("machine-linking-v1.json", "machine-linking-transactions-v1.json",
                 "machine-linking-invite-redemptions-v1.json")
    vectors = {name: json.loads((ROOT / "conformance" / "vectors" / name).read_bytes()) for name in filenames}
    author = Author(vectors)
    vector_count = author.fixture_self_check()
    cases = author.build()
    valid_count = sum(case.expected != INVALID for case in cases)
    print(f"Fixture oracle: {vector_count} fixed signatures reproduced; "
          f"{len(cases)} object checks ({valid_count} cryptographic successes, "
          f"{len(cases) - valid_count} rejections).", flush=True)
    if not probes:
        print("Self-check only: no implementation or live authority was tested.")
        return 0
    failures = 0
    for label, executable in probes:
        probe = Probe(label, executable, args.timeout)
        checked = 0
        starting_failures = failures
        try:
            for case in cases:
                actual = probe.exchange(case.request())
                if actual != case.expected:
                    failures += 1
                    print(f"FAIL {label} {case.name}: {mismatch(case.expected, actual)}", file=sys.stderr)
                    if failures - starting_failures >= 20:
                        raise AssertionError("stopping after 20 failures")
                checked += 1
            for name, request in outer_rejections(author.representatives["certificate"]):
                actual = probe.exchange(request)
                if actual != INVALID:
                    failures += 1
                    print(f"FAIL {label} {name}: expected invalid, received {actual!r}", file=sys.stderr)
                checked += 1
            # Rejection and oversize draining must preserve stream framing.
            case = author.representatives["certificate"]
            if probe.exchange(case.request()) != case.expected:
                failures += 1
                print(f"FAIL {label} valid request after rejected lines", file=sys.stderr)
            checked += 1
        except (AssertionError, OSError) as error:
            failures += 1
            print(f"FAIL {label}: {error}", file=sys.stderr)
        finally:
            diagnostic = probe.close()
            if failures > starting_failures and diagnostic:
                print(f"{label} stderr: {diagnostic}", file=sys.stderr)
        print(f"{label}: {checked} reader checks completed.", flush=True)
    if failures:
        print(f"FAILED: {failures} reader conformance failures.", file=sys.stderr)
        return 1
    print("PASS: signed-object readers only; no live chain, role, activation or transaction acceptance claim.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
