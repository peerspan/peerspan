#!/usr/bin/env python3
"""Independent, state-free genesis linking-feature eligibility conformance.

Contracts, public fixtures and independently authored Python signers are the
oracle. Success means eligible under the supplied snapshot, not persisted,
fresh, enabled in a daemon, or proof that any remote binary upgraded.
"""

import argparse
import copy
import json
from pathlib import Path
import sys

from linking_activations import LIMIT, payload, proof, semantic_id, shift, sort_catalog
from linking_history import Author as HistoryAuthor, legacy_message
from linking_paths import error
from linking_readers import Probe, b64, digest, lines, message, unb64, wire


ROOT = Path(__file__).resolve().parents[1]


class Author(HistoryAuthor):
    def __init__(self, vectors):
        super().__init__(vectors)
        self.feature = next(json.loads(unb64(entry["body_base64"]))
                            for entry in self.base["catalog"]["objects"] if entry["kind"] == "feature")
        self.feature_id = semantic_id("feature", self.feature)
        self.issued = self.feature["proposal"]["issued_at"]
        self.host_a = self.data["keys"]["host_a"]["public_key"]
        self.host_q = self.data["keys"]["host_q"]["public_key"]
        self.catalog = self.without(self.base["catalog"], lambda kind, obj: kind == "feature")

    @staticmethod
    def without(catalog, predicate):
        result = copy.deepcopy(catalog)
        result["objects"] = [entry for entry in result["objects"]
                             if not predicate(entry["kind"], json.loads(unb64(entry["body_base64"])))]
        return result

    def complete(self, hosts=None, issued=None, epoch=0, ssh=False, network=None):
        proposal = copy.deepcopy(self.feature["proposal"])
        proposal.update(host_public_keys=sorted(hosts if hosts is not None else [self.host_a, self.host_q]),
                        issued_at=issued or self.issued, epoch=epoch)
        if network is not None:
            proposal["network_id"] = network
        msg = message("feature_proposal", proposal)
        proposal["signature"] = (self.signers[self.root].sshsig(msg) if ssh
                                 else b64(self.signers[self.root].raw(msg)))
        feature_id = semantic_id("feature_proposal", proposal)
        acknowledgments = []
        for host in proposal["host_public_keys"]:
            ack = {"format": 1, "feature_id": feature_id, "host_public_key": host}
            self.oracle.resign("feature_ack", ack, host)
            acknowledgments.append(ack)
        return {"proposal": proposal, "acknowledgments": acknowledgments}

    def request(self, feature=None, catalog=None, **context):
        result = {"kind": "feature_activation", "network_base64": b64(wire(self.data["network"])),
                  "catalog_base64": b64(wire(self.catalog if catalog is None else catalog)),
                  "feature_base64": b64(wire(self.feature if feature is None else feature)),
                  "epoch": 0, "known_feature_id": "-", "now": self.issued}
        result.update(context)
        return result

    def success(self, feature, known="-"):
        return {"ok": True, "network_id": self.network, "feature_id": semantic_id("feature", feature),
                "epoch": 0, "disposition": "activate" if known == "-" else "already_enabled"}

    def add(self, name, feature=None, catalog=None, code=None, required=(), **context):
        feature = self.feature if feature is None else feature
        self.add_request(name, self.request(feature, catalog, **context),
                         error(code, required) if code else self.success(feature, context.get("known_feature_id", "-")))

    def host_admission(self, host, member="new-host", signer=None, ssh=False):
        return self.signed_legacy("host_admission", {"epoch": 0, "host_public_key": host,
                                  "member": member, "admitted_at": self.issued}, signer, ssh)

    def join_ack(self, host, feature_id=None):
        obj = {"format": 1, "feature_id": feature_id or self.feature_id, "host_public_key": host}
        self.oracle.resign("feature_ack", obj, host)
        return obj

    def temporal_rosters(self):
        self.add("feature/raw_root_exact_multiple_hosts")
        self.add("feature/sshsig_root", self.complete(ssh=True))
        self.add("time/last_valid_second", now=shift(self.issued, 86400 - 1))
        for label, seconds in (("before_issuance", -1), ("exclusive_deadline", 86400), ("after_deadline", 86401)):
            self.add("time/" + label, now=shift(self.issued, seconds), code="expired")
        one_catalog = self.without(self.catalog, lambda kind, obj: kind == "host_admission"
                                   and obj["host_public_key"] == self.host_q)
        self.add("roster/one_host", self.complete([self.host_a]), one_catalog)
        self.add("roster/missing_current_host", self.complete([self.host_a]), code="state_conflict")
        self.add("roster/absent_membership_is_extra_host", catalog=one_catalog, code="state_conflict")
        host = self.key("feature-extra-host")
        three = self.complete([self.host_a, self.host_q, host])
        self.add("roster/extra_unadmitted_host", three, code="state_conflict")
        expanded = self.with_proofs(self.catalog, [("host_admission", self.host_admission(host))])
        self.add("roster/three_hosts_including_unbound", three, expanded)
        self.add("roster/missing_new_unbound_host", catalog=expanded, code="state_conflict")
        joined = self.with_proofs(expanded, [("join_ack", self.join_ack(host))])
        self.add("roster/nonroster_join_ack_cannot_replace_frozen_roster", catalog=joined, code="state_conflict")
        host_only = self.without(self.catalog, lambda kind, obj: kind != "host_admission")
        self.add("roster/transport_membership_needs_no_person_binding", catalog=host_only)
        catalog_feature = self.with_proofs(self.catalog, [("feature", self.feature)])
        self.add("first/matching_catalog_feature_is_still_eligible", catalog=catalog_feature)
        self.add("first/catalog_presence_is_not_durable", catalog=catalog_feature,
                 now=shift(self.issued, 86400), code="expired")
        removed = self.signed_legacy("host_revocation", {"host_public_key": self.host_a,
                                                        "revoked_at": self.issued})
        self.add("first/catalog_feature_does_not_repair_stale_roster", catalog=self.with_proofs(catalog_feature,
                 [("host_revocation", removed)]), code="state_conflict")

    def acknowledgments(self):
        for label, mutate in (
                ("omitted", lambda f: f["acknowledgments"].pop()),
                ("duplicate", lambda f: f["acknowledgments"].append(copy.deepcopy(f["acknowledgments"][0]))),
                ("unsorted", lambda f: f["acknowledgments"].reverse()),
                ("empty", lambda f: f.update(acknowledgments=[]))):
            feature = copy.deepcopy(self.feature)
            mutate(feature)
            self.add("ack/" + label, feature, code="invalid")
        for label, field, value in (("wrong_feature", "feature_id", "lf_" + "0" * 64),
                                     ("wrong_host", "host_public_key", self.key("ack-imposter"))):
            feature = copy.deepcopy(self.feature)
            ack = feature["acknowledgments"][0]
            ack[field] = value
            self.oracle.resign("feature_ack", ack, ack["host_public_key"])
            feature["acknowledgments"].sort(key=lambda item: item["host_public_key"])
            self.add("ack/" + label + "_valid_signature", feature, code="invalid")
        for role in ("proposal", "acknowledgment"):
            feature = copy.deepcopy(self.feature)
            obj = feature["proposal"] if role == "proposal" else feature["acknowledgments"][0]
            obj["signature"] = b64(b"\0" * 64)
            self.add("signature/forged_" + role, feature, code="invalid")
        feature = self.complete()
        feature["proposal"]["signature"] = self.signers[self.person].sshsig(message("feature_proposal", feature["proposal"]))
        self.add("signature/wrong_external_root", feature, code="invalid")
        feature = self.complete(ssh=True)
        feature["proposal"]["signature"] = self.signers[self.root].sshsig(
            message("feature_proposal", feature["proposal"]), namespace=b"wrong-feature-context")
        self.add("signature/wrong_sshsig_namespace", feature, code="invalid")
        for label, hosts in (("duplicate", [self.host_a, self.host_a]), ("empty", [])):
            self.add("proposal/" + label + "_signed_roster", self.complete(hosts), code="invalid")
        feature = self.complete()
        feature["proposal"]["host_public_keys"].reverse()
        feature["proposal"]["signature"] = b64(self.signers[self.root].raw(message("feature_proposal", feature["proposal"])))
        self.add("proposal/unsorted_signed_roster", feature, code="invalid")

    def restrictions(self):
        person_removed = self.signed_legacy("person_removal", {"person_public_key": self.person,
                                                               "removed_at": self.issued})
        unbound = self.signed_legacy("host_unbinding", {"person_public_key": self.person,
                                     "host_public_key": self.host_a, "unbound_at": self.issued}, self.person, ssh=True)
        for kind, obj in (("person_removal", person_removed), ("host_unbinding", unbound)):
            self.add("restriction/" + kind + "_keeps_transport_membership",
                     catalog=self.with_proofs(self.catalog, [(kind, obj)]))
        for kind, field in (("host_revocation", "revoked_at"), ("host_leave", "left_at")):
            signer = self.host_a if kind == "host_leave" else self.root
            obj = self.signed_legacy(kind, {"host_public_key": self.host_a, field: self.issued}, signer)
            catalog = self.with_proofs(self.catalog, [(kind, obj)])
            self.add("restriction/" + kind + "_makes_roster_stale", catalog=catalog, code="state_conflict")
            self.add("restriction/" + kind + "_exact_reduced_roster", self.complete([self.host_q]), catalog)
            self.add("replay/" + kind + "_does_not_disable", catalog=catalog, known_feature_id=self.feature_id,
                     now=shift(self.issued, 2 * 86400))
        leaves = [("host_leave", self.signed_legacy("host_leave", {"host_public_key": host,
                   "left_at": self.issued}, host)) for host in (self.host_a, self.host_q)]
        self.add("replay/every_original_host_departed", catalog=self.with_proofs(self.catalog, leaves),
                 known_feature_id=self.feature_id, now=shift(self.issued, 2 * 86400))

    def administrator_membership(self):
        base = self.without(self.catalog, lambda kind, obj: kind == "host_admission"
                            and obj["host_public_key"] == self.host_a)
        admission = self.host_admission(self.host_a, "alice", self.person, ssh=True)
        catalog = self.with_proofs(base, [("host_admission", admission)])
        self.add("admin/current_delegation_admits_host", catalog=catalog)
        statement_hash = digest(legacy_message("host_admission", admission))
        for version, kept in ((1, statement_hash), (2, "legacy:" + statement_hash)):
            retained = self.removal(self.person, [kept], version=version)
            self.add(f"admin/v{version}_exact_kept_admission", catalog=self.with_proofs(catalog, [("admin_removal", retained)]))
            removed = self.with_proofs(catalog, [("admin_removal", self.removal(self.person, version=version))])
            self.add(f"admin/v{version}_omitted_admission_stales_roster", catalog=removed, code="state_conflict")
            self.add(f"admin/v{version}_omitted_admission_reduced_roster", self.complete([self.host_q]), removed)
        unknown = self.host_admission(self.host_a, "alice", self.other, ssh=True)
        self.add("admin/signature_without_delegation", catalog=self.with_proofs(base, [("host_admission", unknown)]),
                 code="forbidden")
        conflict = self.with_proofs(self.catalog, [("admin_removal", self.removal(self.person)),
                    ("admin_removal", self.removal(self.person, ["legacy:" + statement_hash]))])
        self.add("admin/conflicting_removals", catalog=conflict, code="state_conflict")

    def invite_membership(self):
        invite = self.key("feature-invite")
        joined, expires = shift(self.issued, -30), shift(self.issued, -1)
        def membership(signer=None, ssh=False, joined_at=joined):
            obj = {"network_id": self.network, "member": "alice", "invite_public_key": invite,
                   "invite_expires_at": expires, "joined_at": joined_at, "host_public_key": self.host_a}
            invitation = lines("peerspan-invite-v1", self.network, invite, "alice", expires)
            author = self.signers[signer or self.root]
            obj["invite_signature"] = author.sshsig(invitation) if ssh else b64(author.raw(invitation))
            obj["host_signature"] = b64(self.signers[invite].raw(lines("peerspan-member-v1", self.network,
                                        invite, self.host_a, joined_at)))
            return obj
        base = self.without(self.catalog, lambda kind, obj: kind == "host_admission"
                            and obj["host_public_key"] == self.host_a)
        member = membership()
        catalog = self.with_proofs(base, [("host_membership", member)])
        self.add("invite/root_consumed_before_expiry", catalog=catalog)
        delegated = membership(self.person, ssh=True)
        delegated_catalog = self.with_proofs(base, [("host_membership", delegated)])
        self.add("invite/current_administrator", catalog=delegated_catalog)
        kept = "legacy:" + digest(lines("peerspan-invite-v1", self.network, invite, "alice", expires))
        self.add("invite/withdrawn_admin_exact_kept_invitation", catalog=self.with_proofs(delegated_catalog,
                 [("admin_removal", self.removal(self.person, [kept]))]))
        revoked = self.signed_legacy("invite_revocation", {"invite_public_key": invite, "revoked_at": self.issued})
        removed = self.with_proofs(catalog, [("invite_revocation", revoked)])
        self.add("invite/revoked_membership_stales_roster", catalog=removed, code="state_conflict")
        self.add("invite/revoked_membership_reduced_roster", self.complete([self.host_q]), removed)
        self.add("invite/independent_direct_admission_survives", catalog=self.with_proofs(self.catalog,
                 [("host_membership", member), ("invite_revocation", revoked)]))
        self.add("invite/late_consumption_signed", catalog=self.with_proofs(base,
                 [("host_membership", membership(joined_at=shift(expires, 1)))]), code="invalid")
        for field in ("invite_signature", "host_signature"):
            bad = dict(member, **{field: b64(b"\0" * 64)})
            self.add("invite/forged_" + field, catalog=self.with_proofs(base, [("host_membership", bad)]), code="invalid")

    def replay_and_circularity(self):
        self.add("replay/same_feature_after_deadline", known_feature_id=self.feature_id,
                 now=shift(self.issued, 10 * 86400))
        different = self.complete(issued=shift(self.issued, 1))
        self.add("replay/different_submitted_feature", different, known_feature_id=self.feature_id, code="state_conflict")
        self.add("replay/conflicting_catalog_feature", catalog=self.with_proofs(self.catalog, [("feature", different)]),
                 known_feature_id=self.feature_id, code="state_conflict")
        host = self.key("feature-later-host")
        later = self.with_proofs(self.catalog, [("host_admission", self.host_admission(host))])
        self.add("replay/later_host_missing_join_proof", catalog=later, known_feature_id=self.feature_id,
                 code="proof_required")
        self.add("replay/later_host_exact_join_ack", catalog=self.with_proofs(later, [("join_ack", self.join_ack(host))]),
                 known_feature_id=self.feature_id, now=shift(self.issued, 10 * 86400))
        self.add("replay/later_host_wrong_feature_join_ack", catalog=self.with_proofs(later,
                 [("join_ack", self.join_ack(host, "lf_" + "0" * 64))]), known_feature_id=self.feature_id, code="invalid")
        self.add("replay/inert_link_candidates", catalog=self.c_source["catalog"],
                 known_feature_id=self.feature_id, now=shift(self.issued, 2 * 86400))
        source = self.base["activation"]
        admitted_host = payload(source["request"])["host_public_key"]
        admitted_member = payload(payload(source["administrator"])["admission_record"])["member"]
        independent = self.host_admission(admitted_host, admitted_member)
        self.linked_join_catalog = self.with_proofs(self.c_source["catalog"], [("host_admission", independent)])
        self.add("replay/independent_complete_link_is_required_join_proof", catalog=self.linked_join_catalog,
                 known_feature_id=self.feature_id, now=shift(self.issued, 2 * 86400))
        missing_activation = self.without(self.linked_join_catalog, lambda kind, obj: kind == "activation")
        self.add("replay/missing_complete_link_join_proof", catalog=missing_activation,
                 known_feature_id=self.feature_id, now=shift(self.issued, 2 * 86400), code="proof_required")
        for target in ("proposal", "acknowledgment"):
            malformed = copy.deepcopy(self.feature)
            obj = malformed["proposal"] if target == "proposal" else malformed["acknowledgments"][0]
            obj["signature"] = b64(b"\0" * 64)
            self.add("replay/always_rechecks_" + target, malformed, known_feature_id=self.feature_id,
                     now=shift(self.issued, 2 * 86400), code="invalid")
        objects = [("certificate", self.cert_b), ("activation", self.base["activation"]),
                   ("person_record", payload(self.base["activation"]["commit"])["binding_record"]),
                   ("root_record", payload(self.fixtures["network_root_admits"]["activation"]["administrator"])["admission_record"]),
                   ("checkpoint", self.checkpoint([], issued_at=self.issued))]
        revocation = {"format": 1, "network_id": self.network, "person_public_key": self.person,
                      "issuer_certificate_id": "root", "target_device_public_key": self.cert_b["device_public_key"],
                      "target_certificate_id": semantic_id("certificate", self.cert_b), "revoked_at": self.issued}
        self.oracle.resign("device_revocation", revocation, self.person)
        objects.append(("device_revocation", revocation))
        for kind, obj in objects:
            self.add("first/circular_" + kind, catalog=self.with_proofs(self.catalog, [(kind, obj)]), code="forbidden")
        for kind in ("rotation", "policy", "group", "invite_redemption"):
            self.add("unsupported/" + kind, catalog=self.with_proofs(self.catalog, [(kind, {})]),
                     code="invalid" if kind in ("invite_redemption", "policy", "group") else "upgrade_required")
        self.add("unsupported/unknown_kind", catalog=self.with_proofs(self.catalog, [("unknown-kind", {})]), code="invalid")

    def strict_inputs(self):
        good = self.request()
        for field in good:
            if field == "kind":
                continue
            missing = copy.deepcopy(good)
            del missing[field]
            self.add_request("outer/missing_" + field, missing, error("invalid"))
            for label, value in (("null", None), ("wrong_type", [])):
                bad = dict(good, **{field: value})
                self.add_request("outer/" + label + "_" + field, bad, error("invalid"))
        self.add_request("outer/unknown_field", dict(good, unexpected=1), error("invalid"))
        for field in ("network_base64", "catalog_base64", "feature_base64"):
            for label, encoded in (("bad_alphabet", "!"), ("whitespace", good[field] + "\n"),
                                   ("unnecessary_padding", good[field] + "=")):
                self.add_request("base64/" + label + "/" + field, dict(good, **{field: encoded}), error("invalid"))
            raw = unb64(good[field])
            malformed = {"duplicate": raw[:-1] + b',"' + next(iter(json.loads(raw))).encode() + b'":null}',
                         "unknown": raw[:-1] + b',"unknown":0}', "invalid_utf8": b'"\xff"',
                         "trailing": raw + b" {}", "not_object": b"[]", "null": b"null",
                         "depth65": b'{"unknown":' + b"[" * 65 + b"0" + b"]" * 65 + b"}"}
            for label, value in malformed.items():
                self.add_request("json/" + label + "/" + field, dict(good, **{field: b64(value)}), error("invalid"))
        for container, original in (("feature", self.feature), ("proposal", self.feature["proposal"]),
                                     ("ack", self.feature["acknowledgments"][0])):
            for label, mutation in (("unknown", lambda o: o.update(unknown=0)),
                                     ("null", lambda o: o.update({next(iter(o)): None}))):
                feature = copy.deepcopy(self.feature)
                obj = feature if container == "feature" else feature["proposal"] if container == "proposal" else feature["acknowledgments"][0]
                mutation(obj)
                self.add("shape/" + container + "/" + label, feature, code="invalid")
            for field in original:
                feature = copy.deepcopy(self.feature)
                obj = feature if container == "feature" else feature["proposal"] if container == "proposal" else feature["acknowledgments"][0]
                obj[field] = {} if isinstance(obj[field], list) else []
                self.add("shape/" + container + "/type_" + field, feature, code="invalid")
        for field, value in (("epoch", 1),):
            self.add("context/nonzero_pinned_epoch", **{field: value}, code="upgrade_required")
        self.add("context/nonzero_signed_proposal_epoch", self.complete(epoch=1), code="upgrade_required")
        self.add("context/signed_proposal_network_mismatch", self.complete(network="net_" + "0" * 64), code="invalid")
        descriptor = dict(self.data["network"], name="different-caller-pin")
        self.add_request("context/standalone_proposal_has_no_signed_name", dict(good, network_base64=b64(wire(descriptor))),
                         self.success(self.feature))
        self.add("context/linked_history_authenticates_descriptor", catalog=self.linked_join_catalog,
                 network_base64=b64(wire(descriptor)), known_feature_id=self.feature_id,
                 now=shift(self.issued, 2 * 86400), code="invalid")
        bootstrap = self.host_admission(self.host_a, "alice")
        bootstrap["epoch"] = 1
        bootstrap["signature"] = b64(self.signers[self.root].raw(legacy_message("host_admission", bootstrap)))
        bootstrap_catalog = self.without(self.catalog, lambda kind, obj: kind == "host_admission"
                                        and obj["host_public_key"] == self.host_a)
        self.add("context/nonzero_signed_bootstrap_epoch", catalog=self.with_proofs(bootstrap_catalog,
                 [("host_admission", bootstrap)]), code="upgrade_required")
        self.add("context/malformed_feature_id", known_feature_id="lf_bad", code="invalid")
        for label, mutate in (("wrong_network_id", lambda n: n.update(network_id="net_" + "0" * 64)),
                               ("wrong_genesis_root", lambda n: n.update(genesis_root_public_key=self.person)),
                               ("bad_coordinator_key", lambda n: n.update(coordinator_public_key="not-base64"))):
            descriptor = copy.deepcopy(self.data["network"])
            mutate(descriptor)
            self.add_request("context/" + label, dict(good, network_base64=b64(wire(descriptor))), error("invalid"))
        for kind in ("host_admission", "person_admission", "admin_delegation", "host_binding"):
            entry = next(entry for entry in self.catalog["objects"] if entry["kind"] == kind)
            body = json.loads(unb64(entry["body_base64"]))
            signature = next(field for field in body if field.endswith("signature"))
            body[signature] = b64(b"\0" * 64)
            catalog = self.without(self.catalog, lambda k, obj: k == kind and wire(obj) == unb64(entry["body_base64"]))
            self.add("bootstrap/forged_" + kind, catalog=self.with_proofs(catalog, [(kind, body)]), code="invalid")
        self.catalog_strictness(good)

    def catalog_strictness(self, good):
        for label, mutate in (("unsorted", lambda c: c["objects"].reverse()),
                               ("duplicate", lambda c: c["objects"].append(copy.deepcopy(c["objects"][0]))),
                               ("wrong_hash", lambda c: c["objects"][0].update(id="pf_" + "0" * 64)),
                               ("unknown_entry", lambda c: c["objects"][0].update(unexpected=0))):
            catalog = copy.deepcopy(self.catalog)
            mutate(catalog)
            if label != "unsorted":
                sort_catalog(catalog)
            self.add("catalog/" + label, catalog=catalog, code="invalid")
        alias = copy.deepcopy(self.catalog)
        entry = alias["objects"][0]
        obj = json.loads(unb64(entry["body_base64"]))
        alias["objects"].append(proof(entry["kind"], raw=json.dumps(obj, indent=2).encode()))
        sort_catalog(alias)
        self.add("catalog/semantic_alias_exact_byte_id", catalog=alias)
        total = sum(len(unb64(good[field])) for field in ("network_base64", "catalog_base64", "feature_base64"))
        padded = dict(good, network_base64=b64(unb64(good["network_base64"]) + b" " * (LIMIT - total)))
        self.add_request("limit/exact_512k_decoded_sum", padded, self.success(self.feature))
        padded = dict(padded)
        padded["network_base64"] = b64(unb64(padded["network_base64"]) + b" ")
        self.add_request("limit/over_512k_decoded_sum", padded, error("invalid"))
        self.add_request("outer/trailing_json", wire(good) + b" {}", error("invalid"))
        self.add_request("outer/duplicate_kind", wire(good)[:-1] + b',"kind":"feature_activation"}', error("invalid"))
        self.add_request("outer/invalid_utf8", b'{"kind":"feature_activation","bad":"\xff"}', error("invalid"))
        self.add_request("framing/over_2mib", b" " * (2 * 1024 * 1024 + 1), error("invalid"))
        self.add_request("framing/recovery", good, self.success(self.feature), keep=True)

    def build(self):
        self.temporal_rosters()
        self.acknowledgments()
        self.restrictions()
        self.administrator_membership()
        self.invite_membership()
        self.replay_and_circularity()
        self.strict_inputs()
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
    eligible = sum(case.expected["ok"] for case in cases)
    print(f"Independent oracle: {fixed} published signatures reproduced; {len(cases)} feature checks "
          f"({eligible} eligible, {len(cases) - eligible} rejected).", flush=True)
    if not probes:
        print("Self-check only; no feature implementation or live protocol was tested.")
        return 0
    failures = 0
    for label, executable in probes:
        probe = Probe(label, executable, args.timeout)
        start, checked = failures, 0
        try:
            for case in cases:
                actual = probe.exchange(case.request)
                checked += 1
                if actual != case.expected:
                    failures += 1
                    print(f"FAIL {label} {case.name}: expected {case.expected!r}; received {actual!r}", file=sys.stderr)
                    if failures - start >= 25:
                        raise AssertionError("stopping after 25 failures")
        except (AssertionError, OSError) as failure:
            failures += 1
            print(f"FAIL {label}: {failure}", file=sys.stderr)
        finally:
            diagnostics = probe.close()
            if failures > start and diagnostics:
                print(f"{label} stderr: {diagnostics}", file=sys.stderr)
        print(f"{label}: {checked} feature checks completed.", flush=True)
    if failures:
        print(f"FAILED: {failures} feature conformance failures.", file=sys.stderr)
        return 1
    print("PASS: feature eligibility only; no persistence, freshness, enabled daemon, "
          "writer readiness or remote-binary upgrade claim.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
