#!/usr/bin/env python3
"""Independent signed-catalog and activation eligibility conformance.

Only contracts, public vectors and independently authored Python signing helpers
define these cases. No host implementation is imported. Eligibility is not a
commit, persistence, freshness, retention, recovery or end-to-end link result.
"""

import argparse
import copy
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
from pathlib import Path
import sys

from linking_readers import (Author as ReaderOracle, Probe, b64, digest,
                             expected_reply, lines, message, unb64, wire)
from linking_paths import error


ROOT = Path(__file__).resolve().parents[1]
LIMIT = 512 * 1024


def payload(packet):
    return json.loads(unb64(packet["payload_base64"]))


def semantic_id(kind, obj):
    return expected_reply(kind, obj)["id"]


def proof(kind, obj=None, raw=None):
    raw = wire(obj) if raw is None else raw
    return {"id": "pf_" + digest(lines("peerspan-link-proof-v1", kind, digest(raw))),
            "kind": kind, "body_base64": b64(raw)}


def sort_catalog(catalog):
    catalog["objects"].sort(key=lambda item: item["id"])


def shift(timestamp, seconds):
    return (datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
            + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Case:
    name: str
    request: object
    expected: dict


class Transcript:
    """Re-sign a fixture DAG so adversarial field edits keep valid signatures."""
    def __init__(self, author, fixture):
        self.author = author
        self.activation = copy.deepcopy(fixture["activation"])
        self.values = {role: payload(packet) for role, packet in self.activation.items() if packet != "-"}

    def sign_record(self, record, signer, draft=False):
        kind = "person_record" if "person_public_key" in record else "root_record"
        self.author.oracle.resign(kind, record, signer)
        if draft:
            record["host_signature"] = "-"

    def sign_certificate(self):
        cert = self.values["owner"]["certificate"]
        signer = self.activation["owner"]["writer_public_key"]
        cert["signature"] = self.author.signers[signer].sshsig(message("certificate", cert))

    def finish(self, overrides=None, final_binding=None):
        overrides = overrides or {}
        activation, values = self.activation, self.values
        device = values["request"]["device_public_key"]
        ids = {}
        for role in ("request", "owner", "selection", "administrator", "commit"):
            if activation[role] == "-":
                continue
            current = values[role]
            if role == "owner":
                current["request_packet_id"] = ids["request"]
            elif role == "selection":
                current["owner_offer_id"] = ids["owner"]
            elif role == "administrator":
                current.update(owner_offer_id=ids["owner"], selection_id=ids["selection"])
            elif role == "commit":
                current.update(request_packet_id=ids["request"], owner_offer_id=ids["owner"],
                               selection_id=ids["selection"],
                               administrator_offer_id=ids.get("administrator", "-"),
                               certificate_id=semantic_id("certificate", values["owner"]["certificate"]),
                               expires_at=values["request"]["expires_at"])
                if activation["administrator"] != "-":
                    record = values["administrator"]["admission_record"]
                    kind = "person_record" if "person_public_key" in record else "root_record"
                    current["admission_record_id"] = semantic_id(kind, record)
                if values["owner"]["binding_record"] != "-":
                    binding = copy.deepcopy(values["owner"]["binding_record"])
                    consent = lines("peerspan-binding-consent-v1", digest(message("person_record", binding)))
                    host = json.loads(unb64(binding["payload_base64"]))["host_public_key"]
                    binding["host_signature"] = b64(self.author.signers[host].raw(consent))
                    current["binding_record"] = binding
                if final_binding is not None:
                    current["binding_record"] = final_binding
            current.update(overrides.get(role, {}))
            packet = activation[role]
            packet["payload_base64"] = b64(wire(current))
            self.author.oracle.resign("packet", packet, packet["writer_public_key"],
                                      device if role in ("request", "selection", "commit") else "-")
            ids[role] = semantic_id("packet", packet)
        return copy.deepcopy(activation)


class Author:
    def __init__(self, vectors):
        self.oracle = ReaderOracle(vectors)
        self.signers = self.oracle.signers
        self.data = vectors["machine-linking-transactions-v1.json"]
        self.fixtures = {case["name"]: case for case in self.data["cases"]}
        self.base = self.fixtures["root_person_links_b"]
        self.person = self.data["keys"]["person_root"]["public_key"]
        self.root = self.data["keys"]["network_root"]["public_key"]
        self.other = self.data["keys"]["coordinator"]["public_key"]
        self.cases, self.seen = [], set()

    def request(self, fixture=None, activation=None, catalog=None, **context):
        fixture = fixture or self.base
        activation = activation or fixture["activation"]
        target = payload(activation["request"])
        owner = payload(activation["owner"])
        result = {"kind": "activation", "network_base64": b64(wire(self.data["network"])),
                  "catalog_base64": b64(wire(catalog if catalog is not None else fixture["catalog"])),
                  "activation_base64": b64(wire(activation)), "epoch": 0, "known_feature_id": "-",
                  "caller_host_public_key": target["host_public_key"],
                  "expected_person_public_key": owner["person_public_key"],
                  "now": fixture["evaluation_time"], "verification": "first"}
        result.update(context)
        return result

    def success(self, activation):
        request, owner, commit = (payload(activation[role]) for role in ("request", "owner", "commit"))
        return {"ok": True, "request_id": activation["request"]["request_id"],
                "manifest_id": semantic_id("packet", activation["commit"]),
                "certificate_id": semantic_id("certificate", owner["certificate"]),
                "network_id": owner["network"]["network_id"], "feature_id": owner["feature_id"],
                "person_public_key": owner["person_public_key"], "host_public_key": request["host_public_key"],
                "device_public_key": request["device_public_key"], "mode": commit["mode"]}

    def add_request(self, name, request, expected, keep=False):
        identity = request if isinstance(request, bytes) else wire(request)
        identity = identity, wire(expected)
        if keep or identity not in self.seen:
            self.seen.add(identity)
            self.cases.append(Case(name, request, expected))

    def add(self, name, fixture=None, activation=None, catalog=None, code=None, required=(), keep=False, **context):
        fixture = fixture or self.base
        activation = activation or fixture["activation"]
        self.add_request(name, self.request(fixture, activation, catalog, **context),
                         error(code, required) if code else self.success(activation), keep)

    def replace(self, catalog, index, obj=None, raw=None):
        catalog["objects"][index] = proof(catalog["objects"][index]["kind"], obj, raw)
        sort_catalog(catalog)

    def fixed_cases(self):
        assert len(self.data["cases"]) == 15
        for fixture in self.data["cases"]:
            code = fixture["expected"]["code"]
            if code == "committed":
                code = None
            required = []
            if code == "proof_required":
                parent_id = payload(fixture["activation"]["owner"])["certificate"]["parent_id"]
                parent = next(json.loads(unb64(item["body_base64"])) for item in fixture["catalog"]["objects"]
                              if item["kind"] == "certificate"
                              and semantic_id("certificate", json.loads(unb64(item["body_base64"]))) == parent_id)
                required = [parent["request_id"]]
            self.add("fixture/" + fixture["name"], fixture, code=code, required=required, keep=True)
            assert self.success(fixture["activation"])["manifest_id"] == fixture["manifest_id"]
            assert self.success(fixture["activation"])["certificate_id"] == fixture["certificate_id"]
        # Validate our independent DAG reconstruction against exact published IDs.
        for name in ("root_person_links_b", "delegated_b_links_c", "same_key_root_renewal",
                     "nonadmin_owner_with_independent_admin", "network_root_admits"):
            fixture = self.fixtures[name]
            rebuilt = Transcript(self, fixture).finish()
            assert self.success(rebuilt) == self.success(fixture["activation"]), "oracle DAG mismatch: " + name

    def contexts_and_time(self):
        for name, context, code in (
                ("caller", {"caller_host_public_key": self.other}, "invalid"),
                ("expected_person", {"expected_person_public_key": self.other}, "invalid"),
                ("known_feature", {"known_feature_id": self.data["feature_id"]}, None),
                ("wrong_known_feature", {"known_feature_id": "lf_" + "0" * 64}, "state_conflict"),
                ("no_expected_person", {"expected_person_public_key": "-"}, None),
                ("unsupported_epoch", {"epoch": 1}, "upgrade_required")):
            self.add("context/" + name, code=code, **context)
        for field, value in (("network_id", "net_" + "0" * 64),
                              ("name", "different"), ("genesis_root_public_key", self.other),
                              ("coordinator_address", "elsewhere.example:443"),
                              ("coordinator_public_key", self.root)):
            network = dict(self.data["network"], **{field: value})
            self.add("context/network_pin/" + field, code="invalid", network_base64=b64(wire(network)))
        request = payload(self.base["activation"]["request"])
        self.add("time/before_creation", code="expired", now=shift(request["created_at"], -1))
        self.add("time/last_second", now=shift(request["expires_at"], -1))
        self.add("time/deadline_historical", now=request["expires_at"], verification="historical")
        self.add("time/expired_target_historical", now="2027-01-22T12:00:00Z", verification="historical")
        delegated = self.fixtures["delegated_b_links_c"]
        historical = delegated["activation"]
        affected = [semantic_id("person_record", payload(historical["commit"])["binding_record"]),
                    semantic_id("person_record", payload(historical["administrator"])["admission_record"])]
        self.add_request("time/expired_issuer_needs_exact_history_endorsement",
                         self.request(delegated, now="2027-01-22T12:00:00Z", verification="historical"),
                         [error("proof_required", [record_id]) for record_id in affected])
        self.add("context/historical_caller_pin", code="invalid", verification="historical", caller_host_public_key=self.other)

    def signed_transcripts(self):
        for fixture_name in ("root_person_links_b", "same_key_root_renewal"):
            fixture = self.fixtures[fixture_name]
            for scopes in (2, 4):
                transcript = Transcript(self, fixture)
                transcript.values["owner"]["certificate"]["scopes"] = scopes
                transcript.sign_certificate()
                self.add("signed/positive_leaf_scope/" + fixture_name + "/" + str(scopes),
                         fixture, transcript.finish())
        # Conditional future administrator scope on the proposed device does
        # not require the owner to hold a current administrator role. The
        # independent current administrator still supplies this host admission.
        fixture = self.fixtures["nonadmin_owner_with_independent_admin"]
        transcript = Transcript(self, fixture)
        transcript.values["owner"]["certificate"]["scopes"] = 8
        transcript.sign_certificate()
        self.add("signed/conditional_leaf_admin_scope_for_nonadmin_owner", fixture, transcript.finish())
        for seconds in (-1, 1):
            transcript = Transcript(self, self.base)
            value = transcript.values["request"]
            value["expires_at"] = shift(value["expires_at"], seconds)
            self.add("signed/request_interval/" + str(300 + seconds), activation=transcript.finish(), code="invalid")
        for field, value in (("coordinator_address", "elsewhere.example:443"),
                              ("coordinator_public_key", self.root), ("expected_network_id", "net_" + "0" * 64),
                              ("expected_person_public_key", self.other),
                              ("request_nonce", b64(b"\x99" * 32)), ("renewed_certificate_id", "dc_" + "0" * 64)):
            transcript = Transcript(self, self.base)
            transcript.values["request"][field] = value
            self.add("signed/request/" + field, activation=transcript.finish(), code="invalid")
        transcript = Transcript(self, self.base)
        transcript.values["request"].update(expected_network_id="-", expected_person_public_key="-")
        self.add("signed/request_optional_expectations", activation=transcript.finish())
        for role, field, value in (
                ("owner", "request_packet_id", "lp_" + "0" * 64),
                ("owner", "epoch", 1), ("owner", "feature_id", "lf_" + "0" * 64),
                ("owner", "person_public_key", self.other),
                ("owner", "membership_proof_id", "pf_" + "0" * 64),
                ("owner", "binding_proof_id", "pf_" + "0" * 64),
                ("selection", "owner_offer_id", "lp_" + "0" * 64),
                ("selection", "network_id", "net_" + "0" * 64),
                ("selection", "epoch", 1), ("selection", "feature_id", "lf_" + "0" * 64),
                ("selection", "person_public_key", self.other),
                ("administrator", "owner_offer_id", "lp_" + "0" * 64),
                ("administrator", "selection_id", "lp_" + "0" * 64),
                ("commit", "request_packet_id", "lp_" + "0" * 64),
                ("commit", "owner_offer_id", "lp_" + "0" * 64),
                ("commit", "selection_id", "lp_" + "0" * 64),
                ("commit", "administrator_offer_id", "lp_" + "0" * 64),
                ("commit", "certificate_id", "dc_" + "0" * 64),
                ("commit", "admission_record_id", "ar_" + "0" * 64),
                ("commit", "expires_at", shift(payload(self.base["activation"]["request"])["expires_at"], 1)),
                ("commit", "mode", "renew"), ("commit", "person_public_key", self.other),
                ("commit", "network_id", "net_" + "0" * 64), ("commit", "epoch", 1)):
            transcript = Transcript(self, self.base)
            self.add("signed/" + role + "/" + field,
                     activation=transcript.finish({role: {field: value}}), code="invalid")
        for field, value in (("host_public_key", self.other), ("device_public_key", self.root),
                              ("person_public_key", self.other), ("request_id", "link_" + "0" * 64)):
            transcript = Transcript(self, self.base)
            transcript.values["owner"]["certificate"][field] = value
            transcript.sign_certificate()
            self.add("signed/certificate_association/" + field, activation=transcript.finish(), code="invalid")
        for fixture_name in ("root_person_links_b", "network_root_admits"):
            fixture = self.fixtures[fixture_name]
            for field, value in (("member", "mallory"), ("host_public_key", self.other), ("epoch", 1)):
                transcript = Transcript(self, fixture)
                record = transcript.values["administrator"]["admission_record"]
                unsigned = json.loads(unb64(record["payload_base64"]))
                unsigned[field] = value
                record["payload_base64"] = b64(wire(unsigned))
                transcript.sign_record(record, transcript.activation["administrator"]["writer_public_key"])
                self.add("signed/admission/" + fixture_name + "/" + field,
                         fixture, transcript.finish(), code="invalid")
        transcript = Transcript(self, self.base)
        draft = transcript.values["owner"]["binding_record"]
        final = copy.deepcopy(draft)
        unsigned = json.loads(unb64(final["payload_base64"]))
        unsigned["bound_at"] = shift(unsigned["bound_at"], 1)
        final["payload_base64"] = b64(wire(unsigned))
        transcript.sign_record(final, transcript.activation["owner"]["writer_public_key"])
        self.add("signed/final_binding_differs_from_draft", activation=transcript.finish(final_binding=final), code="invalid")
        transcript = Transcript(self, self.base)
        final = copy.deepcopy(payload(self.base["activation"]["commit"])["binding_record"])
        final["host_signature"] = "-"
        self.add("signed/final_binding_missing_host_consent", activation=transcript.finish(final_binding=final), code="invalid")
        for role in ("request", "owner", "selection", "administrator", "commit"):
            activation = copy.deepcopy(self.base["activation"])
            field = "authority_signature" if role in ("owner", "administrator") else "device_signature"
            signature = bytearray(unb64(activation[role][field]))
            signature[-1] ^= 1
            activation[role][field] = b64(signature)
            self.add("signature/" + role, activation=activation, code="invalid")

    def renewal_and_ancestors(self):
        fixture = self.fixtures["same_key_root_renewal"]
        catalog = copy.deepcopy(fixture["catalog"])
        owner = payload(fixture["activation"]["owner"])
        refs = {owner["membership_proof_id"], owner["binding_proof_id"]}
        assert refs <= {item["id"] for item in catalog["objects"]}
        catalog["objects"] = [item for item in catalog["objects"] if item["id"] not in refs]
        self.add("renewal/nested_only_exact_proofs", fixture, catalog=catalog)
        for field in ("membership_proof_id", "binding_proof_id"):
            transcript = Transcript(self, fixture)
            missing = "pf_" + "0" * 64
            transcript.values["owner"][field] = missing
            self.add("renewal/missing_" + field, fixture, transcript.finish(), code="proof_required", required=[missing])
        transcript = Transcript(self, fixture)
        missing = "dc_" + "0" * 64
        transcript.values["request"]["renewed_certificate_id"] = missing
        self.add("renewal/missing_old_certificate", fixture, transcript.finish(), code="proof_required", required=[missing])
        for field in ("host_public_key", "device_public_key"):
            transcript = Transcript(self, fixture)
            transcript.values["owner"]["certificate"][field] = self.other
            transcript.sign_certificate()
            self.add("renewal/replacement_" + field, fixture, transcript.finish(), code="invalid")
        transcript = Transcript(self, fixture)
        transcript.values["owner"]["binding_record"] = copy.deepcopy(payload(self.base["activation"]["owner"])["binding_record"])
        self.add("renewal/unexpected_binding", fixture, transcript.finish(), code="invalid")
        delegated = self.fixtures["delegated_b_links_c"]
        ancestor = next(json.loads(unb64(item["body_base64"])) for item in delegated["catalog"]["objects"] if item["kind"] == "activation")
        request_id = ancestor["request"]["request_id"]
        catalog = copy.deepcopy(delegated["catalog"])
        catalog["objects"] = [item for item in catalog["objects"] if item["kind"] != "activation"]
        # Supplying valid operation-bound records outside their activation must
        # not manufacture the missing ancestor's membership/binding authority.
        commit = payload(ancestor["commit"])
        admin = payload(ancestor["administrator"])
        existing = {item["id"] for item in catalog["objects"]}
        for record in (commit["binding_record"], admin["admission_record"]):
            candidate = proof("person_record", record)
            if candidate["id"] not in existing:
                catalog["objects"].append(candidate)
                existing.add(candidate["id"])
        sort_catalog(catalog)
        self.add("ancestor/records_without_activation", delegated, catalog=catalog,
                 code="proof_required", required=[request_id])

    def catalog_identity(self):
        base = self.base["catalog"]
        catalog = copy.deepcopy(base)
        catalog["objects"].reverse()
        self.add("catalog/unsorted", catalog=catalog, code="invalid")
        catalog = copy.deepcopy(base)
        catalog["objects"].append(copy.deepcopy(catalog["objects"][0]))
        sort_catalog(catalog)
        self.add("catalog/duplicate_pf_id", catalog=catalog, code="invalid")
        catalog = copy.deepcopy(base)
        catalog["objects"][0]["id"] = "pf_" + "0" * 64
        sort_catalog(catalog)
        self.add("catalog/wrong_exact_bytes_id", catalog=catalog, code="invalid")
        catalog = copy.deepcopy(base)
        for index, item in enumerate(list(catalog["objects"])):
            obj = json.loads(unb64(item["body_base64"]))
            catalog["objects"][index] = proof(item["kind"], raw=json.dumps(obj, indent=2).encode())
        sort_catalog(catalog)
        self.add("catalog/equivalent_reformatted_bodies", catalog=catalog)
        catalog = copy.deepcopy(base)
        first = catalog["objects"][0]
        catalog["objects"].append(proof(first["kind"], raw=b" \n" + unb64(first["body_base64"]) + b"\t"))
        sort_catalog(catalog)
        self.add("catalog/equivalent_semantic_alias", catalog=catalog)
        catalog = copy.deepcopy(base)
        feature = next(json.loads(unb64(item["body_base64"])) for item in base["objects"] if item["kind"] == "feature")
        feature["proposal"]["signature"] = self.signers[self.root].sshsig(message("feature_proposal", feature["proposal"]))
        catalog["objects"].append(proof("feature", feature))
        sort_catalog(catalog)
        self.add("catalog/conflicting_same_feature_id_signature", catalog=catalog, code="state_conflict")
        catalog = copy.deepcopy(base)
        catalog["objects"].append(proof("activation", self.base["activation"]))
        sort_catalog(catalog)
        self.add("catalog/exact_activation_alias", catalog=catalog)
        transcript = Transcript(self, self.base)
        cert = transcript.values["owner"]["certificate"]
        cert["not_after"] = shift(cert["not_after"], -1)
        transcript.sign_certificate()
        alternate = transcript.finish()
        self.add("catalog/conflicting_manifest_same_operation", activation=alternate, catalog=catalog, code="operation_conflict")
        # This is a distinct, fully signed operation for the same host. Its
        # issuer is the original person, so the retained first activation is
        # unrelated to the issuer path and still must establish the conflict.
        transcript = Transcript(self, self.base)
        request = transcript.values["request"]
        request["request_nonce"] = b64(b"\xaa" * 32)
        request_id = "link_" + digest(lines("peerspan-link-request-id-v1", request["coordinator_public_key"],
                                           request["host_public_key"], request["device_public_key"],
                                           request["request_nonce"]))
        assert request_id != self.base["request_id"]
        for packet in transcript.activation.values():
            if packet != "-":
                packet["request_id"] = request_id
        transcript.values["owner"]["certificate"]["request_id"] = request_id
        transcript.sign_certificate()
        draft = transcript.values["owner"]["binding_record"]
        draft["operation_id"] = request_id
        transcript.sign_record(draft, transcript.activation["owner"]["writer_public_key"], draft=True)
        admission = transcript.values["administrator"]["admission_record"]
        admission["operation_id"] = request_id
        transcript.sign_record(admission, transcript.activation["administrator"]["writer_public_key"])
        self.add("catalog/new_host_conflict_from_independent_activation", activation=transcript.finish(),
                 catalog=catalog, code="state_conflict")
        known = ("rotation", "admin_removal", "person_membership", "host_membership", "host_unbinding",
                 "host_leave", "host_revocation", "invite_revocation", "person_removal", "group", "policy",
                 "join_ack", "checkpoint", "invite_redemption")
        for kind in (*known, "unknown_kind"):
            catalog = copy.deepcopy(base)
            catalog["objects"].append(proof(kind, {}))
            sort_catalog(catalog)
            newly_supported = {"admin_removal", "person_membership", "host_membership", "host_unbinding",
                               "host_leave", "host_revocation", "invite_revocation", "person_removal",
                               "join_ack", "checkpoint", "invite_redemption"}
            self.add("catalog/unsupported/" + kind, catalog=catalog,
                     code="invalid" if kind == "unknown_kind" or kind in newly_supported else "upgrade_required")
        for kind in ("person_record", "root_record"):
            fixture = self.base if kind == "person_record" else self.fixtures["network_root_admits"]
            record = copy.deepcopy(payload(fixture["activation"]["administrator"])["admission_record"])
            record["operation_id"] = "-"
            self.oracle.resign(kind, record, fixture["activation"]["administrator"]["writer_public_key"])
            catalog = copy.deepcopy(base)
            catalog["objects"].append(proof(kind, record))
            if kind == "person_record":
                host = payload(record)["host_public_key"]
                ack = {"format": 1, "feature_id": self.data["feature_id"], "host_public_key": host}
                self.oracle.resign("feature_ack", ack, host)
                catalog["objects"].append(proof("join_ack", ack))
            sort_catalog(catalog)
            self.add("catalog/ordinary_host_admission_conflicts_with_new" if kind == "person_record"
                     else "catalog/ordinary_operation_unsupported/root_record", catalog=catalog,
                     code="state_conflict" if kind == "person_record" else "upgrade_required")

    def bootstrap(self):
        base = self.base["catalog"]
        fields = {"admin_delegation": ("network_id", "epoch", "person_public_key", "delegated_at"),
                  "person_admission": ("network_id", "epoch", "person_public_key", "member", "admitted_at"),
                  "host_admission": ("network_id", "epoch", "host_public_key", "member", "admitted_at"),
                  "host_binding": ("network_id", "person_public_key", "host_public_key", "bound_at")}
        domains = {"admin_delegation": "peerspan-admin-delegate-v1", "person_admission": "peerspan-person-admit-v1",
                   "host_admission": "peerspan-host-admit-v1", "host_binding": "peerspan-host-bind-v1"}
        for kind in (*fields, "feature"):
            catalog = copy.deepcopy(base)
            index = next(i for i, item in enumerate(catalog["objects"]) if item["kind"] == kind
                         and (kind in ("feature", "host_admission") or
                              json.loads(unb64(item["body_base64"])).get("person_public_key") == self.person))
            obj = json.loads(unb64(catalog["objects"][index]["body_base64"]))
            if kind == "feature":
                obj["proposal"]["signature"] = b64(self.signers[self.other].raw(message("feature_proposal", obj["proposal"])))
            else:
                msg = lines(domains[kind], *(obj[field] for field in fields[kind]))
                obj["signature"] = self.signers[self.other].sshsig(msg) if kind == "host_binding" else b64(self.signers[self.other].raw(msg))
            self.replace(catalog, index, obj)
            self.add("bootstrap/forged_" + kind, catalog=catalog, code="invalid")
        for kind, field in (("host_binding", "host_signature"), ("feature", "acknowledgment")):
            catalog = copy.deepcopy(base)
            index = next(i for i, item in enumerate(catalog["objects"]) if item["kind"] == kind)
            obj = json.loads(unb64(catalog["objects"][index]["body_base64"]))
            if field == "host_signature":
                msg = lines(domains[kind], *(obj[key] for key in fields[kind]))
                obj[field] = b64(self.signers[self.other].raw(msg))
            else:
                ack = obj["acknowledgments"][0]
                ack["signature"] = b64(self.signers[self.other].raw(message("feature_ack", ack)))
            self.replace(catalog, index, obj)
            self.add("bootstrap/forged_" + field, catalog=catalog, code="invalid")
        for kind, code in (("person_admission", "proof_required"), ("admin_delegation", "forbidden"), ("feature", "proof_required")):
            catalog = copy.deepcopy(base)
            catalog["objects"] = [item for item in catalog["objects"] if not (item["kind"] == kind and
                (kind == "feature" or json.loads(unb64(item["body_base64"])).get("person_public_key") == self.person))]
            self.add("bootstrap/missing_" + kind, catalog=catalog, code=code)

    def revocations(self):
        fixture = self.fixtures["fresh_root_certificate_cannot_revive_revoked_key"]
        revocation = next(json.loads(unb64(item["body_base64"])) for item in fixture["catalog"]["objects"]
                          if item["kind"] == "device_revocation")
        certificate = payload(self.base["activation"]["owner"])["certificate"]
        catalog = copy.deepcopy(self.base["catalog"])
        catalog["objects"] += [proof("certificate", certificate), proof("device_revocation", revocation)]
        sort_catalog(catalog)
        self.add("revocation/pending_target_and_descriptive_timestamp", catalog=catalog, code="device_revoked")
        self.add("revocation/historical_target_preserves_durable_evidence", catalog=catalog,
                 verification="historical", now="2026-10-23T13:00:00Z")
        for field, value in (("target_device_public_key", self.other), ("person_public_key", self.other)):
            changed = copy.deepcopy(revocation)
            changed[field] = value
            signer = changed["person_public_key"]
            self.oracle.resign("device_revocation", changed, signer)
            malformed = copy.deepcopy(self.base["catalog"])
            malformed["objects"] += [proof("certificate", certificate), proof("device_revocation", changed)]
            sort_catalog(malformed)
            self.add("revocation/target_association/" + field, catalog=malformed, code="invalid")
        changed = copy.deepcopy(revocation)
        missing = "dc_" + "0" * 64
        changed["target_certificate_id"] = missing
        self.oracle.resign("device_revocation", changed, changed["person_public_key"])
        malformed = copy.deepcopy(self.base["catalog"])
        malformed["objects"].append(proof("device_revocation", changed))
        sort_catalog(malformed)
        self.add("revocation/missing_exact_target", catalog=malformed, code="proof_required", required=[missing])

    def strict_authority_references(self):
        for role in ("owner", "administrator"):
            for name, certificate_id in (("short", "dc_bad"), ("uppercase", "dc_" + "A" * 64)):
                transcript = Transcript(self, self.base)
                transcript.activation[role]["certificate_id"] = certificate_id
                self.add("signed/actor_certificate_id/" + role + "/" + name,
                         activation=transcript.finish(), code="invalid")
        fixture = self.fixtures["same_key_root_renewal"]
        for field in ("membership_proof_id", "binding_proof_id"):
            transcript = Transcript(self, fixture)
            transcript.values["owner"][field] = "-"
            self.add("renewal/absent_" + field, fixture, transcript.finish(), code="invalid")
        # Keep the same keys and original request, but change the certificate's
        # unsigned message and therefore its dc_ ID. The retained completed
        # activation names the original ID, so it cannot activate this candidate.
        transcript = Transcript(self, fixture)
        old_id = transcript.values["request"]["renewed_certificate_id"]
        catalog = copy.deepcopy(fixture["catalog"])
        old = next(json.loads(unb64(item["body_base64"])) for item in catalog["objects"]
                   if item["kind"] == "certificate"
                   and semantic_id("certificate", json.loads(unb64(item["body_base64"]))) == old_id)
        assert old["parent_id"] == "root" and old["scopes"] == 15
        altered = copy.deepcopy(old)
        altered["scopes"] = 7
        altered["signature"] = self.signers[altered["person_public_key"]].sshsig(message("certificate", altered))
        altered_id = semantic_id("certificate", altered)
        assert altered_id != old_id
        assert all(altered[field] == old[field] for field in ("request_id", "device_public_key", "host_public_key"))
        catalog["objects"].append(proof("certificate", altered))
        sort_catalog(catalog)
        transcript.values["request"]["renewed_certificate_id"] = altered_id
        self.add("renewal/old_certificate_requires_exact_activated_id", fixture, transcript.finish(),
                 catalog=catalog, code="invalid")

    def strict_transport(self):
        request = self.request()
        for field in request:
            self.add_request("probe/missing/" + field, {key: value for key, value in request.items() if key != field}, error("invalid"))
            self.add_request("probe/null/" + field, dict(request, **{field: None}), error("invalid"))
        for field in ("network_base64", "catalog_base64", "activation_base64"):
            raw = unb64(request[field])
            obj = json.loads(raw)
            key = next(iter(obj))
            for name, encoded in (("duplicate", raw[:-1] + b"," + wire(key) + b":" + wire(obj[key]) + b"}"),
                                   ("unknown", wire(dict(obj, unexpected=True))),
                                   ("null", wire(dict(obj, **{key: None}))),
                                   ("invalid_utf8", raw[:-1] + b',"\xff":1}'),
                                   ("trailing_json", raw + b"{}"), ("deep", b"[" * 100 + b"0" + b"]" * 100),
                                   ("non_object", b"[]")):
                self.add_request("strict/" + field + "/" + name, dict(request, **{field: b64(encoded)}), error("invalid"))
            self.add_request("strict/" + field + "/base64_padding", dict(request, **{field: request[field] + "="}), error("invalid"))
        for field, values in {
                "epoch": [True, -1, 0.0, "0", [], {}],
                "known_feature_id": ["lf_" + "A" * 64, [], True],
                "caller_host_public_key": [self.person.rstrip("="), [], True],
                "expected_person_public_key": [self.person + "=", [], True],
                "verification": ["live", True, []], "now": ["2026-02-30T12:00:00Z", "2026-10-23T12:00:00+00:00", True],
                "network_base64": [True, [], "!invalid!"]}.items():
            for index, value in enumerate(values):
                self.add_request("strict/probe_field/" + field + "/" + str(index), dict(request, **{field: value}), error("invalid"))
        for name, raw in (("non_json", b"{"), ("trailing_json", wire(request) + b"{}"),
                           ("duplicate", wire(request)[:-1] + b',"kind":"activation"}'),
                           ("invalid_utf8", b'{"kind":"\xff"}'), ("oversize_line", b" " * (2 * 1024 * 1024 + 1))):
            self.add_request("strict/probe/" + name, raw, error("invalid"))
        self.add_request("strict/probe/unknown", dict(request, extra=True), error("invalid"))
        total = sum(len(unb64(request[field])) for field in ("network_base64", "catalog_base64", "activation_base64"))
        for amount in (LIMIT, LIMIT + 1):
            changed = dict(request)
            changed["network_base64"] = b64(unb64(request["network_base64"]) + b" " * (amount - total))
            self.add_request("limits/decoded_sum/" + str(amount), changed,
                             self.success(self.base["activation"]) if amount == LIMIT else error("invalid"))
        catalog = copy.deepcopy(self.base["catalog"])
        for index, item in enumerate(catalog["objects"]):
            for field in ("id", "kind", "body_base64"):
                malformed = copy.deepcopy(catalog)
                malformed["objects"][index][field] = None
                self.add("strict/catalog_entry/" + str(index) + "/" + field, catalog=malformed, code="invalid")
        for name, raw in (("duplicate", b'{"x":1,"x":1}'), ("null", b'{"x":null}'),
                           ("invalid_utf8", b'{"x":"\xff"}'), ("trailing_json", b"{}{}")):
            catalog = copy.deepcopy(self.base["catalog"])
            catalog["objects"].append(proof("certificate", raw=raw))
            sort_catalog(catalog)
            self.add("strict/candidate_body/" + name, catalog=catalog, code="invalid")

    def build(self):
        self.fixed_cases()
        self.contexts_and_time()
        self.signed_transcripts()
        self.renewal_and_ancestors()
        self.catalog_identity()
        self.bootstrap()
        self.revocations()
        self.strict_authority_references()
        self.strict_transport()
        return self.cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go-probe")
    parser.add_argument("--rust-probe")
    parser.add_argument("--probe", action="append", default=[], metavar="LABEL=PATH")
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--timeout", type=float, default=30)
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
    fixed = author.oracle.fixture_self_check()
    cases = author.build()
    positives = sum(isinstance(case.expected, dict) and case.expected["ok"] for case in cases)
    print(f"Independent oracle: {fixed} published signatures reproduced; {len(cases)} activation checks "
          f"({positives} eligible, {len(cases) - positives} rejected), including all 15 fixed transaction cases.", flush=True)
    if not probes:
        print("Self-check only; no implementation or transaction was tested.")
        return 0
    failures = 0
    for label, executable in probes:
        probe = Probe(label, executable, args.timeout)
        start, checked = failures, 0
        try:
            for case in cases:
                actual = probe.exchange(case.request)
                checked += 1
                if not (actual in case.expected if isinstance(case.expected, list) else actual == case.expected):
                    failures += 1
                    print(f"FAIL {label} {case.name}: expected {case.expected!r}; received {actual!r}", file=sys.stderr)
                    if failures - start >= 25:
                        raise AssertionError("stopping after 25 failures")
            if probe.exchange(author.request()) != author.success(author.base["activation"]):
                failures += 1
                print(f"FAIL {label}: valid activation after rejected input", file=sys.stderr)
            checked += 1
        except (AssertionError, OSError) as failure:
            failures += 1
            print(f"FAIL {label}: {failure}", file=sys.stderr)
        finally:
            diagnostics = probe.close()
            if failures > start and diagnostics:
                print(f"{label} stderr: {diagnostics}", file=sys.stderr)
        print(f"{label}: {checked} activation checks completed.", flush=True)
    if failures:
        print(f"FAILED: {failures} activation conformance failures.", file=sys.stderr)
        return 1
    print("PASS: signed catalog and activation eligibility only; no commit, persistence, freshness, "
          "retention, recovery or end-to-end linking claim.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
