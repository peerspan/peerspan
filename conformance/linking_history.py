#!/usr/bin/env python3
"""Independent genesis membership, restriction and retained-history checks.

Uses contracts, public vectors and separately authored signing helpers only.
Probe success is transcript eligibility, never persistence, freshness, a live
historical signer, or a completed link. No host implementation is imported.
"""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys

from linking_activations import (Author as ActivationAuthor, Transcript, payload,
                                 proof, semantic_id, shift, sort_catalog)
from linking_paths import error
from linking_readers import FixtureSigner, Probe, b64, digest, lines, message, unb64, wire


ROOT = Path(__file__).resolve().parents[1]
LATE = "2027-01-22T12:00:00Z"
EARLY = "2026-10-23T13:00:00Z"


def legacy_message(kind, obj):
    registry = {
        "person_admission": ("peerspan-person-admit-v1", ("network_id", "epoch", "person_public_key", "member", "admitted_at")),
        "host_admission": ("peerspan-host-admit-v1", ("network_id", "epoch", "host_public_key", "member", "admitted_at")),
        "person_removal": ("peerspan-person-remove-v1", ("network_id", "person_public_key", "removed_at")),
        "host_revocation": ("peerspan-revoke-host-v1", ("network_id", "host_public_key", "revoked_at")),
        "invite_revocation": ("peerspan-revoke-invite-v1", ("network_id", "invite_public_key", "revoked_at")),
        "host_leave": ("peerspan-leave-v1", ("network_id", "host_public_key", "left_at")),
        "host_unbinding": ("peerspan-host-unbind-v1", ("network_id", "person_public_key", "host_public_key", "unbound_at")),
    }
    domain, fields = registry[kind]
    return lines(domain, *(obj[field] for field in fields))


class Author(ActivationAuthor):
    def __init__(self, vectors):
        super().__init__(vectors)
        self.network = self.data["network"]["network_id"]
        self.quinn = self.data["keys"]["admin_q"]["public_key"]
        self.c_source = self.fixtures["delegated_b_links_c"]
        self.b_source = self.base
        self.cert_b = payload(self.b_source["activation"]["owner"])["certificate"]
        self.cert_c = payload(self.c_source["activation"]["owner"])["certificate"]
        self.record_b = payload(self.b_source["activation"]["administrator"])["admission_record"]
        self.records_c = {
            "binding": payload(self.c_source["activation"]["commit"])["binding_record"],
            "admission": payload(self.c_source["activation"]["administrator"])["admission_record"],
        }
        self.ids_c = {name: semantic_id("person_record", record) for name, record in self.records_c.items()}
        self.keys = {}
        catalog = self.with_proofs(self.c_source["catalog"], [
            ("activation", self.c_source["activation"]), ("certificate", self.cert_c),
            *(('person_record', record) for record in self.records_c.values())])
        self.renew_c = self.renewal(self.c_source["activation"], catalog, "root-renew-c", LATE)
        self.valid_objects = {}

    def key(self, label):
        if label not in self.keys:
            signer = FixtureSigner(hashlib.sha256(("public-link-history:" + label).encode()).digest())
            public = b64(signer.public)
            self.signers[public] = signer
            self.keys[label] = public
        return self.keys[label]

    def with_proofs(self, catalog, objects):
        result = copy.deepcopy(catalog)
        existing = {entry["id"] for entry in result["objects"]}
        for kind, obj in objects:
            entry = proof(kind, obj)
            if entry["id"] not in existing:
                result["objects"].append(entry)
                existing.add(entry["id"])
        sort_catalog(result)
        return result

    def signed_legacy(self, kind, fields, signer=None, ssh=False):
        obj = dict(network_id=self.network, **fields)
        signer = signer or self.root
        msg = legacy_message(kind, obj)
        obj["signature"] = self.signers[signer].sshsig(msg) if ssh else b64(self.signers[signer].raw(msg))
        self.valid_objects.setdefault(kind, copy.deepcopy(obj))
        return obj

    def checkpoint(self, records, issuer="root", signer=None, person=None, network=None, issued_at=LATE):
        person = person or self.person
        obj = {"format": 1, "network_id": network or self.network, "person_public_key": person,
               "issuer_certificate_id": issuer, "issued_at": issued_at, "records": sorted(records)}
        self.oracle.resign("checkpoint", obj, signer or person)
        self.valid_objects.setdefault("checkpoint", copy.deepcopy(obj))
        return obj

    def removal(self, person, kept=(), version=2, revoke=False, removed_at=EARLY):
        obj = {"network_id": self.network, "person_public_key": person, "revoke_admitted": revoke,
               "removed_at": removed_at, "kept": sorted(kept)}
        if version == 2:
            obj["format"] = 2
            self.oracle.resign("admin_removal_v2", obj, self.root)
        else:
            msg = lines("peerspan-admin-remove-v1", self.network, person, str(revoke).lower(), removed_at,
                        *([] if revoke else obj["kept"]))
            obj["signature"] = b64(self.signers[self.root].raw(msg))
        self.valid_objects.setdefault("admin_removal", copy.deepcopy(obj))
        return obj

    def renewal(self, source, catalog, label, created):
        fixture = copy.deepcopy(self.fixtures["same_key_renewal_after_old_expiry"])
        transcript = Transcript(self, fixture)
        source_request = payload(source["request"])
        old = payload(source["owner"])["certificate"]
        request = transcript.values["request"]
        request.update(host_public_key=source_request["host_public_key"], device_public_key=source_request["device_public_key"],
                       request_nonce=b64(hashlib.sha256(label.encode()).digest()), created_at=created,
                       expires_at=shift(created, 300), renewed_certificate_id=semantic_id("certificate", old))
        request_id = "link_" + digest(lines("peerspan-link-request-id-v1", request["coordinator_public_key"],
                                           request["host_public_key"], request["device_public_key"], request["request_nonce"]))
        for role, packet in transcript.activation.items():
            if packet != "-":
                packet["request_id"] = request_id
                if role in ("request", "selection", "commit"):
                    packet["writer_public_key"] = request["host_public_key"]
        owner = transcript.values["owner"]
        old_admission = payload(source["administrator"])["admission_record"]
        admission_kind = "person_record" if "person_public_key" in old_admission else "root_record"
        owner.update(binding_record="-", membership_proof_id=proof(admission_kind, old_admission)["id"],
                     binding_proof_id=proof("person_record", payload(source["commit"])["binding_record"])["id"])
        owner["certificate"].update(host_public_key=request["host_public_key"], device_public_key=request["device_public_key"],
                                     request_id=request_id, issued_at=created, not_after=shift(created, 90 * 86400))
        transcript.sign_certificate()
        activation = transcript.finish()
        return {"activation": activation, "catalog": copy.deepcopy(catalog), "evaluation_time": created, "name": label}

    def new_root_link(self, label, created=EARLY):
        transcript = Transcript(self, self.base)
        request = transcript.values["request"]
        host, device = self.key(label + "/host"), self.key(label + "/device")
        request.update(host_public_key=host, device_public_key=device,
                       request_nonce=b64(hashlib.sha256(label.encode()).digest()), created_at=created, expires_at=shift(created, 300))
        request_id = "link_" + digest(lines("peerspan-link-request-id-v1", request["coordinator_public_key"], host, device,
                                           request["request_nonce"]))
        for role, packet in transcript.activation.items():
            packet["request_id"] = request_id
            if role in ("request", "selection", "commit"):
                packet["writer_public_key"] = host
        owner = transcript.values["owner"]
        owner["certificate"].update(host_public_key=host, device_public_key=device, request_id=request_id,
                                     issued_at=created, not_after=shift(created, 90 * 86400))
        transcript.sign_certificate()
        draft = owner["binding_record"]
        draft["operation_id"] = request_id
        value = json.loads(unb64(draft["payload_base64"]))
        value.update(host_public_key=host, bound_at=created)
        draft["payload_base64"] = b64(wire(value))
        transcript.sign_record(draft, self.person, draft=True)
        admission = transcript.values["administrator"]["admission_record"]
        admission["operation_id"] = request_id
        value = json.loads(unb64(admission["payload_base64"]))
        value.update(host_public_key=host, admitted_at=created)
        admission["payload_base64"] = b64(wire(value))
        transcript.sign_record(admission, self.person)
        return {"activation": transcript.finish(), "catalog": copy.deepcopy(self.base["catalog"]),
                "evaluation_time": created, "name": label}

    def checkpoints(self):
        ids = self.ids_c
        for retained, missing in (([ids["binding"]], ids["admission"]), ([ids["admission"]], ids["binding"])):
            catalog = self.with_proofs(self.renew_c["catalog"], [("checkpoint", self.checkpoint(retained))])
            self.add("checkpoint/exact_missing_" + missing[:12], self.renew_c, catalog=catalog,
                     code="proof_required", required=[missing])
        complete = self.checkpoint(ids.values())
        catalog = self.with_proofs(self.renew_c["catalog"], [("checkpoint", complete)])
        self.add("checkpoint/root_restores_only_durable_c_records", self.renew_c, catalog=catalog)
        split = [("checkpoint", self.checkpoint([record_id])) for record_id in ids.values()]
        self.add("checkpoint/additive_anchors", self.renew_c, catalog=self.with_proofs(self.renew_c["catalog"], split))
        binding_cp = self.checkpoint([ids["binding"]])
        for name, cp in (
                ("wrong_person", self.checkpoint([ids["admission"]], person=self.quinn)),
                ("wrong_network", self.checkpoint([ids["admission"]], network="net_" + "0" * 64))):
            catalog = self.with_proofs(self.renew_c["catalog"], [("checkpoint", binding_cp), ("checkpoint", cp)])
            self.add("checkpoint/" + name, self.renew_c, catalog=catalog, code="proof_required", required=[ids["admission"]])
        for name, issuer, signer in (("self", semantic_id("certificate", self.cert_b), self.cert_b["device_public_key"]),
                                      ("descendant", semantic_id("certificate", self.cert_c), self.cert_c["device_public_key"])):
            cp = self.checkpoint(ids.values(), issuer, signer)
            catalog = self.with_proofs(self.renew_c["catalog"], [("checkpoint", cp)])
            self.add("checkpoint/forbidden_" + name, self.renew_c, catalog=catalog, code="forbidden")
        sibling = self.new_root_link("checkpoint_sibling", LATE)
        cert = payload(sibling["activation"]["owner"])["certificate"]
        cp = self.checkpoint(ids.values(), semantic_id("certificate", cert), cert["device_public_key"])
        catalog = self.with_proofs(self.renew_c["catalog"], [("activation", sibling["activation"]), ("checkpoint", cp)])
        self.add("checkpoint/forbidden_sibling", self.renew_c, catalog=catalog, code="forbidden")
        bad = copy.deepcopy(complete)
        signature = bytearray(unb64(bad["signature"]))
        signature[-1] ^= 1
        bad["signature"] = b64(signature)
        self.add("checkpoint/bad_matching_signature", self.renew_c,
                 catalog=self.with_proofs(self.renew_c["catalog"], [("checkpoint", bad)]), code="invalid")
        self.add("checkpoint/good_root_anchor_wins_over_bad_candidate", self.renew_c,
                 catalog=self.with_proofs(self.renew_c["catalog"], [("checkpoint", bad), ("checkpoint", complete)]))
        missing = "ar_" + "0" * 64
        cp = self.checkpoint([*ids.values(), missing])
        self.add("checkpoint/missing_listed_record", self.renew_c,
                 catalog=self.with_proofs(self.renew_c["catalog"], [("checkpoint", cp)]),
                 code="proof_required", required=[missing])
        non_redemption = next(entry["id"] for entry in self.renew_c["catalog"]["objects"]
                              if entry["kind"] == "person_admission")
        cp = self.checkpoint([*ids.values(), non_redemption])
        self.add("checkpoint/non_redemption_pf_retention_unsupported", self.renew_c,
                 catalog=self.with_proofs(self.renew_c["catalog"], [("checkpoint", cp)]), code="upgrade_required")
        pending = self.fixtures["signed_pending_parent_cannot_authorize"]
        self.add("checkpoint/cannot_activate_pending_issuer", pending,
                 catalog=self.with_proofs(pending["catalog"], [("checkpoint", complete)]),
                 code="proof_required", required=[self.base["request_id"]])
        fresh = Transcript(self, self.c_source)
        fresh.values["request"].update(created_at=LATE, expires_at=shift(LATE, 300))
        self.add("checkpoint/cannot_authorize_fresh_b_approval", self.c_source, fresh.finish(),
                 catalog=self.with_proofs(self.c_source["catalog"], [("checkpoint", complete)]),
                 verification="first", now=LATE, code="authority_expired")

    def delegated_checkpoint(self):
        # Root -> D -> B -> C, with B ending one day before D. C's durable
        # device-signed records can then be retained by unaffected ancestor D.
        ancestor = self.new_root_link("checkpoint_ancestor_d", "2026-10-23T11:59:00Z")
        cert_d = payload(ancestor["activation"]["owner"])["certificate"]
        id_d = semantic_id("certificate", cert_d)
        signer_d = cert_d["device_public_key"]
        middle = Transcript(self, self.b_source)
        middle.activation["owner"].update(writer_public_key=signer_d, certificate_id=id_d)
        middle.values["owner"]["certificate"].update(parent_id=id_d, not_after="2027-01-20T12:00:00Z")
        middle.sign_certificate()
        draft = middle.values["owner"]["binding_record"]
        draft["certificate_id"] = id_d
        middle.sign_record(draft, signer_d, draft=True)
        activation_b = middle.finish()
        cert_b = payload(activation_b["owner"])["certificate"]
        id_b = semantic_id("certificate", cert_b)
        child = Transcript(self, self.c_source)
        child.activation["owner"]["certificate_id"] = id_b
        child.activation["administrator"]["certificate_id"] = id_b
        child.values["owner"]["certificate"].update(parent_id=id_b, not_after=cert_b["not_after"])
        child.sign_certificate()
        child.values["owner"]["binding_record"]["certificate_id"] = id_b
        child.sign_record(child.values["owner"]["binding_record"], cert_b["device_public_key"], draft=True)
        child.values["administrator"]["admission_record"]["certificate_id"] = id_b
        child.sign_record(child.values["administrator"]["admission_record"], cert_b["device_public_key"])
        activation_c = child.finish()
        records = {"binding": payload(activation_c["commit"])["binding_record"],
                   "admission": payload(activation_c["administrator"])["admission_record"]}
        ids = {name: semantic_id("person_record", record) for name, record in records.items()}
        catalog = self.with_proofs(self.base["catalog"], [
            ("activation", ancestor["activation"]), ("activation", activation_b), ("activation", activation_c),
            ("certificate", cert_d), ("certificate", cert_b),
            ("certificate", payload(activation_c["owner"])["certificate"])])
        fixture = self.renewal(activation_c, catalog, "renew-c-with-unaffected-d", "2027-01-20T12:00:01Z")
        cp = self.checkpoint(ids.values(), id_d, signer_d, issued_at=fixture["evaluation_time"])
        self.add("checkpoint/current_unaffected_strict_ancestor", fixture,
                 catalog=self.with_proofs(catalog, [("checkpoint", cp)]))
        kept = ["record:" + semantic_id("person_record", payload(activation["administrator"])["admission_record"])
                for activation in (ancestor["activation"], activation_b, activation_c)]
        removed = self.removal(self.person, kept)
        root_admission = self.checkpoint([ids["admission"]], issued_at=fixture["evaluation_time"])
        binding_only = self.checkpoint([ids["binding"]], id_d, signer_d, issued_at=fixture["evaluation_time"])
        for name, checkpoints, code in (
                ("delegated_admin_role_still_required", [cp], "forbidden"),
                ("binding_scope_does_not_require_admin_role", [binding_only, root_admission], None),
                ("every_listed_record_scope_is_checked", [cp, root_admission], "forbidden")):
            self.add("checkpoint/" + name, fixture,
                     catalog=self.with_proofs(catalog, [("admin_removal", removed),
                         *(("checkpoint", value) for value in checkpoints)]), code=code)

    def roles(self):
        record_b_id = semantic_id("person_record", self.record_b)
        fixture = self.fixtures["same_key_root_renewal"]
        for version, kept, code in ((1, [], "forbidden"),
                                     (1, [digest(message("person_record", self.record_b))], "forbidden"),
                                     (2, [], "forbidden"), (2, ["record:" + record_b_id], None),
                                     (2, ["record:ar_" + "0" * 64], "forbidden")):
            removal = self.removal(self.person, kept, version)
            self.add("role/renewal_retention/v" + str(version) + "/" + str(len(kept)) + "/" + str(code), fixture,
                     catalog=self.with_proofs(fixture["catalog"], [("admin_removal", removal)]), code=code)
        cp = self.checkpoint(self.ids_c.values())
        kept = ["record:" + record_b_id, "record:" + self.ids_c["admission"]]
        for name, entries, checkpoints, code, required in (
                ("both_dimensions", kept, [cp], None, []),
                ("checkpoint_cannot_override_root", [kept[0]], [cp], "forbidden", []),
                ("root_list_cannot_replace_checkpoint", kept, [self.checkpoint([self.ids_c["binding"]])],
                 "proof_required", [self.ids_c["admission"]]),
                ("binding_still_needs_checkpoint", kept, [self.checkpoint([self.ids_c["admission"]])],
                 "proof_required", [self.ids_c["binding"]])):
            objects = [("admin_removal", self.removal(self.person, entries)),
                       *(("checkpoint", value) for value in checkpoints)]
            self.add("role/" + name, self.renew_c, catalog=self.with_proofs(self.renew_c["catalog"], objects),
                     code=code, required=required)
        for version in (1, 2):
            removed = self.removal(self.person, version=version)
            self.add("role/no_new_admin_after_v" + str(version),
                     catalog=self.with_proofs(self.base["catalog"], [("admin_removal", removed)]), code="forbidden")
        unrelated = self.removal(self.quinn)
        alias = proof("admin_removal", raw=b" " + wire(unrelated) + b"\n")
        catalog = self.with_proofs(self.base["catalog"], [("admin_removal", unrelated)])
        catalog["objects"].append(alias)
        sort_catalog(catalog)
        self.add("role/equivalent_removal_alias", catalog=catalog)
        conflict = self.removal(self.quinn, removed_at=shift(EARLY, 1))
        self.add("role/conflicting_false_removals", catalog=self.with_proofs(self.base["catalog"],
                 [("admin_removal", unrelated), ("admin_removal", conflict)]), code="state_conflict")
        escalation = self.removal(self.quinn, revoke=True)
        self.add("role/irreversible_escalation", catalog=self.with_proofs(self.base["catalog"],
                 [("admin_removal", unrelated), ("admin_removal", escalation)]))
        # Place the irreversible escalation before both false removals in the
        # required pf_ order. It still cannot hide their nonidentical history.
        catalog = self.with_proofs(self.base["catalog"],
                                   [("admin_removal", unrelated), ("admin_removal", conflict)])
        first_false = min(proof("admin_removal", value)["id"] for value in (unrelated, conflict))
        for spaces in range(4096):
            early_true = proof("admin_removal", raw=b" " * spaces + wire(escalation))
            if early_true["id"] < first_false:
                break
        else:
            raise AssertionError("could not place valid escalation alias before false removals")
        catalog["objects"].append(early_true)
        sort_catalog(catalog)
        self.add("role/conflicting_false_removals_survive_true_escalation", catalog=catalog, code="state_conflict")
        self.add("role/true_revocation_preserves_no_envelope", fixture,
                 catalog=self.with_proofs(fixture["catalog"], [("admin_removal", self.removal(self.person, revoke=True))]),
                 code="forbidden")
        # A removed Quinn's legacy person admission of Alice can be retained by
        # its exact statement digest, independently of Alice's current role.
        catalog = copy.deepcopy(self.base["catalog"])
        index = next(i for i, entry in enumerate(catalog["objects"]) if entry["kind"] == "person_admission"
                     and json.loads(unb64(entry["body_base64"]))["person_public_key"] == self.person)
        admission = json.loads(unb64(catalog["objects"][index]["body_base64"]))
        admission["signature"] = self.signers[self.quinn].sshsig(legacy_message("person_admission", admission))
        catalog["objects"][index] = proof("person_admission", admission)
        sort_catalog(catalog)
        statement_digest = digest(legacy_message("person_admission", admission))
        for version, retained in ((1, [statement_digest]), (2, ["legacy:" + statement_digest]), (1, []), (2, [])):
            removed = self.removal(self.quinn, retained, version)
            self.add("role/legacy_keep/v" + str(version) + "/" + str(bool(retained)),
                     catalog=self.with_proofs(catalog, [("admin_removal", removed)]), code=None if retained else "forbidden")
        # A valid independent Alice activation supplies current host facts, but
        # cannot authorize the exact Quinn-signed legacy proof chosen by renewal.
        fixture = self.fixtures["same_key_root_renewal"]
        target = payload(fixture["activation"]["request"])["host_public_key"]
        selected = {"network_id": self.network, "epoch": 0, "host_public_key": target,
                    "member": "alice", "admitted_at": EARLY}
        selected["signature"] = self.signers[self.quinn].sshsig(legacy_message("host_admission", selected))
        transcript = Transcript(self, fixture)
        transcript.values["owner"]["membership_proof_id"] = proof("host_admission", selected)["id"]
        selected_catalog = self.with_proofs(fixture["catalog"], [("host_admission", selected),
                                             ("admin_removal", self.removal(self.quinn))])
        self.add("role/renewal_reauthorizes_exact_selected_legacy_admission", fixture, transcript.finish(),
                 catalog=selected_catalog, code="forbidden")

    def memberships(self):
        invite = self.key("legacy_invite")
        joined, expires = "2026-10-23T11:58:00Z", "2026-10-23T11:59:00Z"
        def member(kind, subject, label="alice", key=invite):
            obj = {"network_id": self.network, "member": label, "invite_public_key": key,
                   "invite_expires_at": expires, "joined_at": joined}
            if kind == "person_membership":
                obj.update(invite_epoch=0, person_public_key=subject)
                invitation = lines("peerspan-person-invite-v1", self.network, 0, key, label, expires)
                consumption = lines("peerspan-person-member-v1", self.network, key, subject, joined)
                obj["invite_signature"] = b64(self.signers[self.root].raw(invitation))
                obj["person_signature"] = b64(self.signers[key].raw(consumption))
            else:
                obj["host_public_key"] = subject
                invitation = lines("peerspan-invite-v1", self.network, key, label, expires)
                consumption = lines("peerspan-member-v1", self.network, key, subject, joined)
                obj["invite_signature"] = b64(self.signers[self.root].raw(invitation))
                obj["host_signature"] = b64(self.signers[key].raw(consumption))
            self.valid_objects.setdefault(kind, copy.deepcopy(obj))
            return obj
        person_member = member("person_membership", self.person)
        host_a = self.data["keys"]["host_a"]["public_key"]
        host_member = member("host_membership", host_a)
        base = copy.deepcopy(self.base["catalog"])
        base["objects"] = [entry for entry in base["objects"] if not (entry["kind"] == "person_admission"
                           and json.loads(unb64(entry["body_base64"]))["person_public_key"] == self.person)]
        self.add("membership/person_redeemed_before_expiry", catalog=self.with_proofs(base, [("person_membership", person_member)]))
        both = copy.deepcopy(base)
        both["objects"] = [entry for entry in both["objects"] if not (entry["kind"] == "host_admission"
                           and json.loads(unb64(entry["body_base64"]))["host_public_key"] == host_a)]
        self.add("membership/separate_invite_halves", catalog=self.with_proofs(both,
                 [("person_membership", person_member), ("host_membership", host_member)]))
        revoked = self.signed_legacy("invite_revocation", {"invite_public_key": invite, "revoked_at": EARLY})
        self.add("membership/revoked_only_admission", catalog=self.with_proofs(base,
                 [("person_membership", person_member), ("invite_revocation", revoked)]), code="forbidden")
        self.add("membership/independent_root_admission_survives_invite_revocation",
                 catalog=self.with_proofs(self.base["catalog"], [("person_membership", person_member), ("invite_revocation", revoked)]))
        for kind, original, subject in (("person_membership", person_member, self.quinn),
                                        ("host_membership", host_member, self.data["keys"]["host_q"]["public_key"])):
            second = member(kind, subject, "quinn")
            self.add("membership/conflicting_consumption/" + kind,
                     catalog=self.with_proofs(self.base["catalog"], [(kind, original), (kind, second)]), code="state_conflict")
        for kind, original in (("person_membership", person_member), ("host_membership", host_member)):
            for field in ("invite_signature", "person_signature" if kind == "person_membership" else "host_signature"):
                bad = copy.deepcopy(original)
                bad[field] = b64(b"\0" * 64)
                self.add("membership/bad_signature/" + kind + "/" + field,
                         catalog=self.with_proofs(self.base["catalog"], [(kind, bad)]), code="invalid")
            bad = copy.deepcopy(original)
            bad["joined_at"] = shift(expires, 1)
            member_domain = "peerspan-person-member-v1" if kind == "person_membership" else "peerspan-member-v1"
            subject = bad["person_public_key" if kind == "person_membership" else "host_public_key"]
            field = "person_signature" if kind == "person_membership" else "host_signature"
            bad[field] = b64(self.signers[invite].raw(lines(member_domain, self.network, invite, subject, bad["joined_at"])))
            self.add("membership/join_after_expiry/" + kind,
                     catalog=self.with_proofs(self.base["catalog"], [(kind, bad)]), code="invalid")
        extra_host = self.key("unrostered_host")
        extra = member("host_membership", extra_host)
        catalog = self.with_proofs(self.base["catalog"], [("host_membership", extra)])
        self.add("membership/unrostered_host_needs_ack", catalog=catalog, code="proof_required")
        ack = {"format": 1, "feature_id": self.data["feature_id"], "host_public_key": extra_host}
        self.oracle.resign("feature_ack", ack, extra_host)
        self.valid_objects.setdefault("join_ack", copy.deepcopy(ack))
        self.add("membership/exact_join_ack", catalog=self.with_proofs(catalog, [("join_ack", ack)]))
        wrong = dict(ack, feature_id="lf_" + "0" * 64)
        self.oracle.resign("feature_ack", wrong, extra_host)
        self.add("membership/wrong_feature_ack", catalog=self.with_proofs(catalog, [("join_ack", wrong)]), code="invalid")
        wrong = dict(ack, host_public_key=host_a)
        self.oracle.resign("feature_ack", wrong, host_a)
        self.add("membership/other_host_ack_does_not_cover_target", catalog=self.with_proofs(catalog, [("join_ack", wrong)]),
                 code="proof_required")
        removed = self.signed_legacy("host_revocation", {"host_public_key": extra_host, "revoked_at": EARLY})
        self.add("membership/removed_unrostered_host_needs_no_ack", catalog=self.with_proofs(catalog, [("host_revocation", removed)]))
        fixture = self.fixtures["same_key_root_renewal"]
        target = payload(fixture["activation"]["request"])["host_public_key"]
        membership = member("host_membership", target)
        transcript = Transcript(self, fixture)
        transcript.values["owner"]["membership_proof_id"] = proof("host_membership", membership)["id"]
        catalog = self.with_proofs(fixture["catalog"], [("host_membership", membership)])
        self.add("membership/renewal_names_exact_host_membership", fixture, transcript.finish(), catalog=catalog)

    def restrictions(self):
        target = payload(self.base["activation"]["request"])["host_public_key"]
        restrictions = [
            ("person_removal", self.signed_legacy("person_removal", {"person_public_key": self.person, "removed_at": EARLY})),
            ("host_revocation", self.signed_legacy("host_revocation", {"host_public_key": target, "revoked_at": EARLY})),
            ("host_leave", self.signed_legacy("host_leave", {"host_public_key": target, "left_at": EARLY}, target)),
            ("host_unbinding", self.signed_legacy("host_unbinding", {"person_public_key": self.person,
                "host_public_key": target, "unbound_at": EARLY}, self.person, ssh=True)),
        ]
        for kind, obj in restrictions:
            self.add("restriction/first_" + kind, catalog=self.with_proofs(self.base["catalog"], [(kind, obj)]), code="forbidden")
            self.add("restriction/historical_evidence_" + kind,
                     catalog=self.with_proofs(self.base["catalog"], [(kind, obj)]), verification="historical",
                     code="forbidden" if kind == "person_removal" else None)
            fixture = self.fixtures["same_key_root_renewal"]
            self.add("restriction/no_resurrection_by_history_" + kind, fixture,
                     catalog=self.with_proofs(fixture["catalog"], [(kind, obj)]), code="forbidden")
        unrelated = self.signed_legacy("host_unbinding", {"person_public_key": self.quinn,
            "host_public_key": target, "unbound_at": EARLY}, self.quinn, ssh=True)
        self.add("restriction/unbinding_scoped_to_original_person",
                 catalog=self.with_proofs(self.base["catalog"], [("host_unbinding", unrelated)]))
        fixture = self.fixtures["network_root_admits"]
        person_removed = restrictions[0][1]
        self.add("restriction/historical_removed_owner_with_unaffected_root_admission", fixture,
                 catalog=self.with_proofs(fixture["catalog"], [("person_removal", person_removed)]),
                 verification="historical")

    def delegated_revocations(self):
        target_id = semantic_id("certificate", self.cert_c)
        issuer_id = semantic_id("certificate", self.cert_b)
        revocation = {"format": 1, "network_id": self.network, "person_public_key": self.person,
                      "target_device_public_key": self.cert_c["device_public_key"], "target_certificate_id": target_id,
                      "issuer_certificate_id": issuer_id, "revoked_at": EARLY}
        self.oracle.resign("device_revocation", revocation, self.cert_b["device_public_key"])
        self.valid_objects.setdefault("device_revocation", copy.deepcopy(revocation))
        revocation_id = semantic_id("device_revocation", revocation)
        for fixture_name, retained, code in (("same_key_root_renewal", False, None),
                                             ("same_key_renewal_after_old_expiry", False, "proof_required"),
                                             ("same_key_renewal_after_old_expiry", True, None)):
            fixture = self.fixtures[fixture_name]
            additions = [("certificate", self.cert_c), ("device_revocation", revocation)]
            if retained:
                additions.append(("checkpoint", self.checkpoint([revocation_id])))
            self.add("delegated_dr/" + fixture_name + "/" + str(retained), fixture,
                     catalog=self.with_proofs(fixture["catalog"], additions), code=code,
                     required=[revocation_id] if code else [])
        fixture = self.fixtures["same_key_root_renewal"]
        catalog = self.with_proofs(fixture["catalog"], [("certificate", self.cert_c), ("device_revocation", revocation)])
        catalog["objects"] = [entry for entry in catalog["objects"] if entry["kind"] != "activation"]
        self.add("delegated_dr/missing_issuer_activation", fixture, catalog=catalog,
                 code="proof_required", required=[self.b_source["request_id"]])
        self_revocation = copy.deepcopy(revocation)
        self_revocation.update(target_device_public_key=self.cert_b["device_public_key"], target_certificate_id=issuer_id)
        self.oracle.resign("device_revocation", self_revocation, self.cert_b["device_public_key"])
        self.add("delegated_dr/self_is_not_strict_ancestor", fixture,
                 catalog=self.with_proofs(fixture["catalog"], [("device_revocation", self_revocation)]), code="forbidden")
        fresh = self.new_root_link("unaffected_restriction_observer")
        root_revocation = copy.deepcopy(next(json.loads(unb64(entry["body_base64"]))
            for entry in self.fixtures["fresh_root_certificate_cannot_revive_revoked_key"]["catalog"]["objects"]
            if entry["kind"] == "device_revocation"))
        evidence = [("activation", self.b_source["activation"]), ("certificate", self.cert_c),
                    ("device_revocation", revocation), ("device_revocation", root_revocation)]
        for retained in (False, True):
            objects = evidence + ([("checkpoint", self.checkpoint([revocation_id]))] if retained else [])
            self.add("delegated_dr/root_revoked_issuer/" + str(retained), fresh,
                     catalog=self.with_proofs(fresh["catalog"], objects), code=None if retained else "proof_required",
                     required=[] if retained else [revocation_id])
        unbound = self.signed_legacy("host_unbinding", {"person_public_key": self.person,
            "host_public_key": self.cert_b["host_public_key"], "unbound_at": EARLY}, self.person, ssh=True)
        self.add("delegated_dr/unbound_issuer", fresh, catalog=self.with_proofs(fresh["catalog"],
                 evidence[:-1] + [("host_unbinding", unbound)]), code="proof_required", required=[revocation_id])
        sibling_target = payload(fresh["activation"]["owner"])["certificate"]
        sibling = copy.deepcopy(revocation)
        sibling.update(target_certificate_id=semantic_id("certificate", sibling_target),
                       target_device_public_key=sibling_target["device_public_key"])
        self.oracle.resign("device_revocation", sibling, self.cert_b["device_public_key"])
        self.add("delegated_dr/sibling_target_is_not_descendant", fresh, catalog=self.with_proofs(fresh["catalog"],
                 [("activation", self.b_source["activation"]), ("certificate", sibling_target),
                  ("device_revocation", sibling)]), code="forbidden")
        self.add("delegated_dr/checkpoint_cannot_replace_structural_issuer_certificate", fresh,
                 catalog=self.with_proofs(fresh["catalog"], [("certificate", self.cert_c),
                     ("device_revocation", revocation), ("checkpoint", self.checkpoint([revocation_id]))]),
                 code="proof_required", required=[issuer_id])

    def strict_new_facts(self):
        for kind, valid in self.valid_objects.items():
            for name, obj in (("unknown", dict(valid, unexpected=True)),
                               ("null", dict(valid, **{next(iter(valid)): None}))):
                self.add("strict/history/" + kind + "/" + name,
                         catalog=self.with_proofs(self.base["catalog"], [(kind, obj)]), code="invalid")
        unrelated = self.checkpoint(["ar_" + "e" * 64], person=self.quinn)
        self.add("candidate/unrelated_checkpoint_is_inert",
                 catalog=self.with_proofs(self.base["catalog"], [("checkpoint", unrelated)]))
        request = self.request()
        self.add_request("framing/oversize_line", b" " * (2 * 1024 * 1024 + 1), error("invalid"))
        self.add_request("framing/valid_after_rejection", request, self.success(self.base["activation"]), keep=True)

    def verification_modes(self):
        # A legacy admission for this unrostered target needs the same complete
        # activation as its feature join proof. That historical work must not
        # bypass the caller's separate first-finalization preconditions.
        def catalog_for(fixture, activation, additional=()):
            request = payload(activation["request"])
            admission = payload(activation["administrator"])["admission_record"]
            unsigned = json.loads(unb64(admission["payload_base64"]))
            legacy = {"network_id": self.network, "epoch": 0,
                      "host_public_key": request["host_public_key"], "member": unsigned["member"],
                      "admitted_at": request["created_at"]}
            legacy["signature"] = b64(self.signers[self.root].raw(legacy_message("host_admission", legacy)))
            return self.with_proofs(fixture["catalog"],
                                    [("host_admission", legacy), ("activation", activation), *additional])

        fixture = self.base
        activation = fixture["activation"]
        catalog = catalog_for(fixture, activation)
        self.add("mode/live_historical_join_proof_control", fixture, catalog=catalog, verification="historical")
        self.add("mode/live_first_still_conflicts", fixture, catalog=catalog, code="state_conflict")
        deadline = payload(activation["request"])["expires_at"]
        self.add("mode/deadline_historical_join_proof_control", fixture, catalog=catalog,
                 verification="historical", now=deadline)
        self.add_request("mode/deadline_first_is_not_historical", self.request(fixture, catalog=catalog, now=deadline),
                         [error("expired"), error("state_conflict")])

        # Keep this request current while B's path and the proposed C certificate
        # are expired. Exact root endorsements preserve the two durable C
        # records for historical evidence, without restoring present authority.
        fixture = self.c_source
        transcript = Transcript(self, fixture)
        transcript.values["request"].update(created_at=LATE, expires_at=shift(LATE, 300))
        activation = transcript.finish()
        retained = self.checkpoint(self.ids_c.values(), issued_at=LATE)
        catalog = catalog_for(fixture, activation, [("checkpoint", retained)])
        self.add("mode/expired_actor_historical_retained_control", fixture, activation, catalog=catalog,
                 verification="historical", now=LATE)
        self.add_request("mode/expired_actor_first_is_not_historical",
                         self.request(fixture, activation, catalog=catalog, now=LATE),
                         [error("authority_expired"), error("state_conflict")])

    def build(self):
        self.checkpoints()
        self.delegated_checkpoint()
        self.roles()
        self.memberships()
        self.restrictions()
        self.delegated_revocations()
        self.strict_new_facts()
        self.verification_modes()
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
    eligible = sum(isinstance(case.expected, dict) and case.expected["ok"] for case in cases)
    print(f"Independent oracle: {fixed} published signatures reproduced; {len(cases)} history checks "
          f"({eligible} eligible, {len(cases) - eligible} rejected).", flush=True)
    if not probes:
        print("Self-check only; no history implementation or live protocol was tested.")
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
        except (AssertionError, OSError) as failure:
            failures += 1
            print(f"FAIL {label}: {failure}", file=sys.stderr)
        finally:
            diagnostics = probe.close()
            if failures > start and diagnostics:
                print(f"{label} stderr: {diagnostics}", file=sys.stderr)
        print(f"{label}: {checked} history checks completed.", flush=True)
    if failures:
        print(f"FAILED: {failures} history conformance failures.", file=sys.stderr)
        return 1
    print("PASS: genesis history and transcript eligibility only; no persistence, freshness, "
          "live historical authority, retention for unsupported formats or completed-link claim.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
