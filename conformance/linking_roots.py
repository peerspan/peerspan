#!/usr/bin/env python3
"""Independent root-chain/epoch conformance from public signing contracts.

No implementation source is imported. Verification is stateless evidence,
without durable fork/rollback protection, freshness or transaction execution.
"""

import argparse
import copy
import json
from pathlib import Path
import sys

from linking_actions import Author as ActionAuthor, NOW
from linking_activations import Author as ActivationAuthor, Transcript, payload, proof, semantic_id, shift, sort_catalog
from linking_records import Author as RecordAuthor
from linking_policy_state import Author as PolicyAuthor
from linking_redemptions import Author as RedemptionAuthor
from linking_paths import error
from linking_readers import Probe, b64, lines, message, unb64, wire


ROOT = Path(__file__).resolve().parents[1]


class Author(RecordAuthor):
    invite = RedemptionAuthor.invite

    def __init__(self, vectors):
        super().__init__(vectors)
        self.roots = {0: self.root, 1: self.key("root-chain/1"), 2: self.key("root-chain/2")}
        self.r1 = self.rotation(1)
        self.r2 = self.rotation(2)

    def rotation(self, epoch, ssh=False, **changes):
        value = {"network_id": self.network, "epoch": epoch, "previous_root_public_key": self.roots.get(epoch - 1, self.root),
                 "root_public_key": self.roots.get(epoch, self.roots[1]), "rotated_at": NOW}
        value.update(changes)
        msg = lines("peerspan-root-rotate-v1", *(value[field] for field in ("network_id", "epoch", "previous_root_public_key", "root_public_key", "rotated_at")))
        signer = self.signers[value["previous_root_public_key"]]
        value["signature"] = signer.sshsig(msg) if ssh else b64(signer.raw(msg))
        return value

    def attestation(self, host, member="alice", epoch=1, signer=None):
        value = {"network_id": self.network, "epoch": epoch, "host_public_key": host, "member": member, "attested_at": NOW}
        value["signature"] = b64(self.signers[signer or self.roots[epoch]].raw(lines("peerspan-attest-v1", self.network, epoch, host, member, NOW)))
        return value

    def admission(self, kind, key, member, epoch=1):
        field = "person_public_key" if kind == "person_admission" else "host_public_key"
        return self.signed_legacy(kind, {"epoch": epoch, field: key, "member": member, "admitted_at": NOW}, self.roots[epoch])

    def role(self, person, epoch=1):
        value = {"network_id": self.network, "epoch": epoch, "person_public_key": person, "delegated_at": NOW}
        value["signature"] = b64(self.signers[self.roots[epoch]].raw(lines("peerspan-admin-delegate-v1", self.network, epoch, person, NOW)))
        return value

    def catalog(self, objects=(), current=False, epoch=1, source=None):
        additions = [("rotation", self.r1)] + ([("rotation", self.r2)] if epoch == 2 else []) + list(objects)
        if current:
            for person, label in ((self.person, "alice"), (self.quinn, "quinn")):
                additions += [("person_admission", self.admission("person_admission", person, label, epoch)),
                              ("admin_delegation", self.role(person, epoch))]
            for name, label in (("host_a", "alice"), ("host_q", "quinn")):
                additions.append(("attestation", self.attestation(self.data["keys"][name]["public_key"], label, epoch)))
        return self.with_proofs(self.base["catalog"] if source is None else source, additions)

    def stale_facts(self):
        facts = self.base_facts.clone()
        for person in list(facts.persons):
            facts.person(person, admitted=False, administrator=False)
        for host in list(facts.hosts):
            facts.host(host, admitted=False)
        return facts

    def epoch_activation(self, fixture, epoch):
        transcript = Transcript(self, fixture)
        for role, value in transcript.values.items():
            if "epoch" in value:
                value["epoch"] = epoch
            for field in ("binding_record", "admission_record"):
                record = value.get(field, "-")
                if record == "-":
                    continue
                record["epoch"] = epoch
                unsigned = payload(record)
                if "epoch" in unsigned:
                    unsigned["epoch"] = epoch
                record["payload_base64"] = b64(wire(unsigned))
                signer = transcript.activation[role]["writer_public_key"]
                if "person_public_key" not in record:
                    signer = self.roots[epoch]
                    transcript.activation[role]["writer_public_key"] = signer
                transcript.sign_record(record, signer, draft=role == "owner" and field == "binding_record")
        return transcript.finish()

    def chain_cases(self):
        self.add("chain/one_raw_rotation", self.catalog(), self.stale_facts(), epoch=1)
        self.add("chain/two_rotations", self.catalog(epoch=2), self.stale_facts(), epoch=2)
        self.add("chain/sshsig_previous_root", self.with_proofs(self.base["catalog"], [("rotation", self.rotation(1, ssh=True))]),
                 self.stale_facts(), epoch=1)
        alias = self.catalog()
        alias["objects"].append(proof("rotation", raw=json.dumps(self.r1, indent=2).encode()))
        sort_catalog(alias)
        self.add("chain/exact_byte_alias", alias, self.stale_facts(), epoch=1)
        self.add("chain/reused_historical_root_key_is_allowed", self.with_proofs(self.base["catalog"],
                 [("rotation", self.r1), ("rotation", self.rotation(2, root_public_key=self.root))]), self.stale_facts(), epoch=2)
        self.add("chain/selected_future", self.catalog(), code="proof_required", epoch=2)
        self.add("chain/selected_past", self.catalog(), code="state_conflict", epoch=0)
        self.add("chain/missing_intermediate", self.with_proofs(self.base["catalog"], [("rotation", self.r2)]), code="proof_required", epoch=2)
        fork = self.rotation(1, root_public_key=self.key("forked-root"))
        self.add("chain/fork", self.catalog([("rotation", fork)]), code="state_conflict", epoch=1)
        for label, value in (("epoch_zero", self.rotation(0)),
                              ("wrong_predecessor", self.rotation(1, previous_root_public_key=self.quinn)),
                              ("noncanonical_key", self.rotation(1, root_public_key=self.roots[1].rstrip("=")))):
            self.add("chain/" + label, self.with_proofs(self.base["catalog"], [("rotation", value)]), code="invalid", epoch=1)
        bad = dict(self.r1, signature=b64(self.signers[self.quinn].raw(lines("wrong"))))
        self.add("chain/bad_signature", self.with_proofs(self.base["catalog"], [("rotation", bad)]), code="invalid", epoch=1)
        for label, value in (("unknown", dict(self.r1, extra=True)), ("null", dict(self.r1, rotated_at=None))):
            self.add("chain/" + label, self.with_proofs(self.base["catalog"], [("rotation", value)]), code="invalid", epoch=1)
        raw = wire(self.r1)[:-1] + b',"epoch":1}'
        duplicate = self.base["catalog"]
        duplicate = copy.deepcopy(duplicate)
        duplicate["objects"].append(proof("rotation", raw=raw))
        sort_catalog(duplicate)
        self.add("chain/duplicate_json", duplicate, code="invalid", epoch=1)

    def current_and_sticky(self):
        self.add("current/admissions_roles_attestations", self.catalog(current=True), self.base_facts, epoch=1)
        self.add("current/second_epoch", self.catalog(current=True, epoch=2), self.base_facts, epoch=2)
        alice = self.admission("person_admission", self.person, "alice-renamed")
        facts = self.stale_facts().person(self.person, "alice-renamed")
        self.add("current/person_admission_does_not_restore_old_role", self.catalog([("person_admission", alice)]), facts, epoch=1)
        facts = facts.clone()
        facts.persons[self.person]["administrator"] = True
        self.add("current/current_delegation_restores_role", self.catalog([("person_admission", alice), ("admin_delegation", self.role(self.person))]), facts, epoch=1)
        host = self.data["keys"]["host_a"]["public_key"]
        facts = self.stale_facts().host(host, "alice")
        self.add("current/attestation_is_only_host_membership", self.catalog([("attestation", self.attestation(host))]), facts, epoch=1)
        self.add("current/old_attestation_is_inert", self.catalog([("attestation", self.attestation(host, epoch=0))]), self.stale_facts(), epoch=1)
        self.add("current/attestation_wrong_epoch_root", self.catalog([("attestation", self.attestation(host, signer=self.root))]), code="invalid", epoch=1)
        conflict = self.attestation(host, "different")
        self.add("current/conflicting_attested_label", self.catalog([("attestation", conflict)], current=True), code="state_conflict", epoch=1)
        future = self.admission("person_admission", self.person, "alice", epoch=2)
        self.add("current/missing_future_admission_root", self.catalog([("person_admission", future)]), code="proof_required", epoch=1)
        removed = self.signed_legacy("person_removal", {"person_public_key": self.quinn, "removed_at": NOW})
        facts = self.base_facts.clone().person(self.quinn, "quinn", admitted=False, administrator=False)
        facts.bind(self.data["keys"]["host_q"]["public_key"], "-")
        self.add("sticky/old_root_person_removal", self.catalog([("person_removal", removed)], current=True), facts, epoch=1)
        revoked = self.signed_legacy("host_revocation", {"host_public_key": host, "revoked_at": NOW})
        facts = self.base_facts.clone().host(host, "alice", admitted=False).bind(host, "-")
        self.add("sticky/old_root_host_revocation", self.catalog([("host_revocation", revoked)], current=True), facts, epoch=1)
        withdrawal = self.removal(self.person)
        facts = self.base_facts.clone()
        facts.persons[self.person]["administrator"] = False
        self.add("sticky/old_root_role_withdrawal_survives_new_delegation", self.catalog([("admin_removal", withdrawal)], current=True), facts, epoch=1)

    def historical_and_current_operations(self):
        historical_catalog = self.catalog(current=True)
        ordinary = self.record("host-bind-v1")
        self.add("history/ordinary_old_epoch_original_person_binding", self.with_proofs(historical_catalog, [("person_record", ordinary)]),
                 self.base_facts.clone().bind(self.target_host, self.person), epoch=1)
        current = self.record("host-unbind-v1", epoch=1)
        context = self.context(historical_catalog)
        self.add_request("action/current_epoch", ActionAuthor.request(self, current, context, epoch=1), ActionAuthor.success(self, current, context))
        self.add_request("action/stale_epoch", ActionAuthor.request(self, self.record("host-unbind-v1"), context, epoch=1), error("invalid"))
        activation = self.epoch_activation(self.base, 1)
        self.add_request("activation/current_first", ActivationAuthor.request(self, self.base, activation, historical_catalog, epoch=1), ActivationAuthor.success(self, activation))
        self.add_request("activation/stale_first", ActivationAuthor.request(self, self.base, catalog=historical_catalog, epoch=1), error("invalid"))
        self.add_request("activation/historical_original_epoch", ActivationAuthor.request(self, self.base, catalog=historical_catalog,
                         epoch=1, verification="historical"), ActivationAuthor.success(self, self.base["activation"]))
        for field in ("binding_record",):
            transcript = Transcript(self, {**self.base, "activation": activation})
            record = transcript.values["owner"][field]
            record["epoch"] = 0
            transcript.sign_record(record, self.person, draft=True)
            self.add_request("activation/mixed_" + field, ActivationAuthor.request(self, self.base, transcript.finish(), historical_catalog, epoch=1), error("invalid"))
        # Resolve B for an ordinary scope-2 grant: old administrator admissions
        # remain durable, while present root roles come only from epoch one.
        grant = self.record("host-bind-v1", self.b)
        catalog = self.catalog([("activation", self.base["activation"]), ("person_record", grant)], current=True)
        self.add("history/complete_old_person_transcript_supplies_device_path", catalog,
                 self.base_facts.clone().path(self.b).grant(grant), epoch=1)
        source = self.without(self.base["catalog"], lambda kind, obj: kind == "person_admission"
                              and obj["person_public_key"] == self.person)
        changed = self.catalog([("person_admission", self.admission("person_admission", self.person, "alice-renamed")),
                               ("attestation", self.attestation(self.data["keys"]["host_a"]["public_key"])),
                               ("attestation", self.attestation(self.data["keys"]["host_q"]["public_key"], "quinn")),
                               ("person_admission", self.admission("person_admission", self.quinn, "quinn")),
                               ("admin_delegation", self.role(self.person)), ("admin_delegation", self.role(self.quinn))], source=source)
        # No verified admission at or before epoch zero exists for Alice here.
        self.add_request("history/future_person_admission_cannot_backdate_transcript", ActivationAuthor.request(self, self.base,
                         catalog=changed, epoch=1, verification="historical"), error("invalid"))
        old_label_present = self.catalog([("person_admission", self.admission("person_admission", self.person, "alice-renamed"))])
        # Add current Quinn/host facts without replacing the old Alice proof.
        old_label_present = self.with_proofs(old_label_present, [("person_admission", self.admission("person_admission", self.quinn, "quinn")),
                    ("attestation", self.attestation(self.data["keys"]["host_a"]["public_key"])),
                    ("attestation", self.attestation(self.data["keys"]["host_q"]["public_key"], "quinn")),
                    ("admin_delegation", self.role(self.person)), ("admin_delegation", self.role(self.quinn))])
        self.add_request("history/old_label_survives_new_current_label", ActivationAuthor.request(self, self.base,
                         catalog=old_label_present, epoch=1, verification="historical"), ActivationAuthor.success(self, self.base["activation"]))
        root_fixture = self.fixtures["network_root_admits"]
        root_cert = payload(root_fixture["activation"]["owner"])["certificate"]
        root_catalog = self.catalog([("activation", root_fixture["activation"])], current=True)
        self.add_request("history/old_network_root_transcript_remains_evidence", ActivationAuthor.request(self, root_fixture,
                         catalog=root_catalog, epoch=1, verification="historical"), ActivationAuthor.success(self, root_fixture["activation"]))
        root_context = self.context(root_catalog, [root_cert])
        action = self.record("host-unbind-v1", root_context, epoch=1)
        self.add_request("history/old_root_admission_does_not_create_current_host", ActionAuthor.request(self, action, root_context, epoch=1), error("forbidden"))
        root_context["catalog"] = self.with_proofs(root_catalog, [("attestation", self.attestation(root_cert["host_public_key"]))])
        self.add_request("history/current_attestation_restores_exact_host", ActionAuthor.request(self, action, root_context, epoch=1), ActionAuthor.success(self, action, root_context))
        renamed_host = self.with_proofs(root_catalog, [("attestation", self.attestation(root_cert["host_public_key"], "renamed-host"))])
        self.add_request("history/inert_old_root_admission_coexists_with_current_renamed_host", ActivationAuthor.request(self, root_fixture,
                         catalog=renamed_host, epoch=1, verification="historical"), ActivationAuthor.success(self, root_fixture["activation"]))
        conflicting_host = self.with_proofs(historical_catalog, [("attestation", self.attestation(self.cert_b["host_public_key"], "renamed-host"))])
        self.add_request("history/two_currently_usable_host_labels_still_conflict", ActivationAuthor.request(self, self.base,
                         catalog=conflicting_host, epoch=1, verification="historical"), error("state_conflict"))
        renewal = self.fixtures["same_key_root_renewal"]
        old_membership = self.admission("host_admission", self.cert_b["host_public_key"], "alice", epoch=0)
        renewal_catalog = self.catalog([("host_admission", old_membership)], current=True, source=renewal["catalog"])
        renewed = self.epoch_activation(renewal, 1)
        transcript = Transcript(self, {**renewal, "activation": renewed})
        transcript.values["owner"]["membership_proof_id"] = proof("host_admission", old_membership)["id"]
        renewed = transcript.finish()
        self.add_request("renewal/independent_fact_cannot_replace_stale_selected_root_proof", ActivationAuthor.request(self, renewal,
                         renewed, renewal_catalog, epoch=1), error("forbidden"))
        renewal_catalog = self.with_proofs(renewal_catalog, [("attestation", self.attestation(self.cert_b["host_public_key"]))])
        self.add_request("renewal/exact_stale_root_proof_with_matching_current_attestation", ActivationAuthor.request(self, renewal,
                         renewed, renewal_catalog, epoch=1), ActivationAuthor.success(self, renewed))
        without_current_roles = self.catalog([(kind, value) for kind, value in (
                 ("person_admission", self.admission("person_admission", self.person, "alice")),
                 ("person_admission", self.admission("person_admission", self.quinn, "quinn")),
                 ("attestation", self.attestation(self.data["keys"]["host_a"]["public_key"])),
                 ("attestation", self.attestation(self.data["keys"]["host_q"]["public_key"], "quinn")))])
        context = self.context(without_current_roles)
        action = self.record("host-admit-v1", epoch=1, unsigned=dict(self.payloads["host-admit-v1"], epoch=1))
        self.add_request("action/old_delegation_cannot_authorize_current_administration", ActionAuthor.request(self, action, context, epoch=1), error("forbidden"))
        retained_catalog = self.with_proofs(without_current_roles, [("activation", self.base["activation"]), ("person_record", grant)])
        retained_facts = self.base_facts.clone().path(self.b).grant(grant)
        for value in retained_facts.persons.values():
            value["administrator"] = False
        self.add("history/old_delegation_preserves_durable_admission_without_current_role", retained_catalog, retained_facts, epoch=1)

    def legacy_invites(self):
        invite, host, person = self.key("old-root-invite"), self.target_host, self.new_person
        expires, joined = shift(NOW, 86400), NOW
        host_membership = {"network_id": self.network, "host_public_key": host, "member": "invited",
                           "invite_public_key": invite, "invite_expires_at": expires, "joined_at": joined}
        host_membership["invite_signature"] = b64(self.signers[self.root].raw(lines("peerspan-invite-v1", self.network, invite, "invited", expires)))
        host_membership["host_signature"] = b64(self.signers[invite].raw(lines("peerspan-member-v1", self.network, invite, host, joined)))
        person_membership = {"network_id": self.network, "invite_epoch": 0, "person_public_key": person, "member": "invited",
                             "invite_public_key": invite, "invite_expires_at": expires, "joined_at": joined}
        person_membership["invite_signature"] = b64(self.signers[self.root].raw(lines("peerspan-person-invite-v1", self.network, 0, invite, "invited", expires)))
        person_membership["person_signature"] = b64(self.signers[invite].raw(lines("peerspan-person-member-v1", self.network, invite, person, joined)))
        catalog = self.catalog([("host_membership", host_membership), ("person_membership", person_membership)])
        facts = self.stale_facts().host(host, admitted=False).person(person, admitted=False)
        self.add("legacy/old_root_invite_halves_are_inert", catalog, facts, epoch=1)
        ack = {"format": 1, "feature_id": self.data["feature_id"], "host_public_key": host}
        self.oracle.resign("feature_ack", ack, host)
        catalog = self.with_proofs(catalog, [("attestation", self.attestation(host, "invited")), ("join_ack", ack)])
        self.add("legacy/current_host_attestation_does_not_admit_person_half", catalog,
                 facts.clone().host(host, "invited"), epoch=1)

    def features_and_framing(self):
        feature = next(json.loads(unb64(entry["body_base64"])) for entry in self.base["catalog"]["objects"] if entry["kind"] == "feature")
        request = {"kind": "feature_activation", "network_base64": b64(wire(self.data["network"])),
                   "catalog_base64": b64(wire(self.catalog(current=True))), "feature_base64": b64(wire(feature)),
                   "epoch": 1, "known_feature_id": self.data["feature_id"], "now": NOW}
        expected = {"ok": True, "network_id": self.network, "feature_id": self.data["feature_id"], "epoch": 1, "disposition": "already_enabled"}
        self.add_request("feature/historical_id_survives_rotation", request, expected)
        self.add_request("feature/stale_first_proposal", dict(request, known_feature_id="-"), error("invalid"))
        proposal = dict(feature["proposal"], epoch=1, issued_at=NOW)
        proposal["signature"] = b64(self.signers[self.roots[1]].raw(message("feature_proposal", proposal)))
        current_id = semantic_id("feature_proposal", proposal)
        acknowledgments = []
        for host in proposal["host_public_keys"]:
            ack = {"format": 1, "feature_id": current_id, "host_public_key": host}
            self.oracle.resign("feature_ack", ack, host)
            acknowledgments.append(ack)
        current_feature = {"proposal": proposal, "acknowledgments": acknowledgments}
        no_feature = self.without(self.catalog(current=True), lambda kind, obj: kind == "feature")
        current_request = dict(request, catalog_base64=b64(wire(no_feature)), feature_base64=b64(wire(current_feature)), known_feature_id="-")
        self.add_request("feature/current_root_first_activation", current_request,
                         {"ok": True, "network_id": self.network, "feature_id": current_id, "epoch": 1, "disposition": "activate"})
        wrong = copy.deepcopy(current_feature)
        wrong["proposal"]["signature"] = b64(self.signers[self.root].raw(message("feature_proposal", wrong["proposal"])))
        self.add_request("feature/old_root_cannot_sign_new_proposal_epoch", dict(current_request, feature_base64=b64(wire(wrong))), error("invalid"))
        descriptor = dict(self.data["network"], genesis_root_public_key=self.roots[1])
        self.add("descriptor/rotation_does_not_change_genesis_pin", self.catalog(current=True), epoch=1,
                 network_base64=b64(wire(descriptor)), code="invalid")
        for label, raw in (("trailing", wire(request) + b"{}"), ("duplicate", wire(request)[:-1] + b',"kind":"feature_activation"}'),
                           ("invalid_utf8", b'{"kind":"\xff"}'), ("over_2mib", b" " * (2 * 1024 * 1024 + 1))):
            self.add_request("framing/" + label, raw, error("invalid"))
        self.add_request("framing/recovery", request, expected, keep=True)

    def policy_group_integration(self):
        # Reuse only the independent signing/row oracle, with this verified root chain.
        def candidate(suffix, **changes):
            return PolicyAuthor.candidate(self, suffix, legacy=True, **changes)

        def add(name, catalog, candidates, policies=(), groups=(), code=None, prior_groups=()):
            context = self.context(catalog)
            request = PolicyAuthor.request(self, candidates, context, epoch=1, prior_groups=prior_groups)
            expected = error(code) if code else {"ok": True, "network_id": self.network,
                       "feature_id": self.data["feature_id"], "policies": list(policies), "groups": list(groups)}
            self.add_request("access/" + name, request, expected)

        old = candidate("group-v1", signer=self.root, version=2)
        lower = candidate("group-v1", signer=self.roots[1], version=1)
        newer = candidate("group-v1", signer=self.roots[1], version=3)
        old_row = PolicyAuthor.row(old, False, "forbidden")
        add("historical_root_group_retains_inactive_maximum", self.catalog(), [old], groups=[old_row])
        add("lower_current_root_group_does_not_replace", self.catalog(), [old, lower], groups=[old_row])
        add("newer_current_root_group_recovers", self.catalog(), [old, newer],
            groups=[PolicyAuthor.row(newer)], prior_groups=[PolicyAuthor.prior(old_row)])
        policy = candidate("policy-v2")
        add("historical_person_admission_observes_policy", self.catalog(), [policy],
            policies=[PolicyAuthor.row(policy, False, "forbidden")])
        missing = self.without(self.catalog(), lambda kind, obj: kind == "person_admission" and obj["person_public_key"] == self.person)
        removed = self.signed_legacy("person_removal", {"person_public_key": self.person, "removed_at": NOW}, self.roots[1])
        missing = self.with_proofs(missing, [("person_removal", removed), ("admin_delegation", self.role(self.person))])
        add("bare_removed_delegated_person_is_not_admission_evidence", missing, [policy], code="proof_required")

    def completed_redemption_labels(self):
        source = self.without(self.base["catalog"], lambda kind, obj: kind == "person_admission" and obj["person_public_key"] == self.person)
        independent = [("person_admission", self.admission("person_admission", self.quinn, "quinn")),
                       ("admin_delegation", self.role(self.quinn)),
                       ("attestation", self.attestation(self.data["keys"]["host_a"]["public_key"])),
                       ("attestation", self.attestation(self.data["keys"]["host_q"]["public_key"], "quinn"))]
        stem = self.catalog(independent, source=source)
        quinn = self.root_person(self.quinn)
        completed = RedemptionAuthor.redemption(self, "person", "admit", quinn, person=self.person, label="alice",
                                               invite=self.key("root-history/redemption-label"))
        catalog = self.with_proofs(stem, [("invite_redemption", completed)])
        self.add_request("history/redemption_original_envelope_epoch_supplies_only_admission", ActivationAuthor.request(self, self.base,
                         catalog=catalog, epoch=1, verification="historical"), ActivationAuthor.success(self, self.base["activation"]))
        legacy = RedemptionAuthor.redemption(self, "person", "admit", quinn, person=self.person, label="alice", style="legacy_root",
                                            invite=self.key("root-history/legacy-redemption-label"))
        legacy_catalog = self.with_proofs(stem, [("invite_redemption", legacy)])
        root_only = self.fixtures["network_root_admits"]
        self.add_request("history/redemption_old_root_label_is_private_evidence", ActivationAuthor.request(self, root_only,
                         catalog=legacy_catalog, epoch=1, verification="historical"), ActivationAuthor.success(self, root_only["activation"]))
        facts = self.base_facts.clone().person(self.person, admitted=False, administrator=False)
        self.add("history/redemption_old_root_label_does_not_admit_current_person", legacy_catalog, facts, epoch=1)
        later = copy.deepcopy(completed)
        invitation = later["person_invite"]
        invitation["epoch"] = 1
        unsigned = payload(invitation)
        unsigned["invite_epoch"] = 1
        invitation["payload_base64"] = b64(wire(unsigned))
        self.oracle.resign("person_record", invitation, self.quinn)
        self.add_request("history/redemption_later_invitation_cannot_backdate_label", ActivationAuthor.request(self, root_only,
                         catalog=self.with_proofs(stem, [("invite_redemption", later)]), epoch=1, verification="historical"), error("invalid"))
        skip = RedemptionAuthor.redemption(self, "member", "skip", quinn, person=self.person, label="alice",
                                           invite=self.key("root-history/skip-no-label"))
        skip_catalog = self.with_proofs(stem, [("invite_redemption", skip), ("join_ack", self.ack(skip["host_public_key"]))])
        self.add_request("history/redemption_skip_does_not_supply_admission", ActivationAuthor.request(self, root_only,
                         catalog=skip_catalog, epoch=1, verification="historical"), error("proof_required"))
        excluded = self.with_proofs(catalog, [("admin_removal", self.removal(self.quinn))])
        self.add_request("history/redemption_excluded_admin_grant_supplies_no_label", ActivationAuthor.request(self, root_only,
                         catalog=excluded, epoch=1, verification="historical"), error("invalid"))

    def exact_renewal_attestation_boundaries(self):
        renewal = self.fixtures["same_key_root_renewal"]
        renewed = self.epoch_activation(renewal, 1)
        host = self.cert_b["host_public_key"]
        admitted = self.signed_legacy("host_admission", {"epoch": 0, "host_public_key": host,
                     "member": "alice", "admitted_at": NOW}, self.quinn, ssh=True)
        invite = self.key("renewal/exact-excluded-admin-invite")
        expires, joined = shift(NOW, 86400), NOW
        membership = {"network_id": self.network, "host_public_key": host, "member": "alice",
                      "invite_public_key": invite, "invite_expires_at": expires, "joined_at": joined}
        membership["invite_signature"] = self.signers[self.quinn].sshsig(lines("peerspan-invite-v1", self.network, invite, "alice", expires))
        membership["host_signature"] = b64(self.signers[invite].raw(lines("peerspan-member-v1", self.network, invite, host, joined)))
        root_membership = copy.deepcopy(membership)
        root_membership["invite_signature"] = b64(self.signers[self.root].raw(lines("peerspan-invite-v1", self.network, invite, "alice", expires)))
        attestation = self.attestation(host)
        for label, kind, grant, excluded in (("excluded_admin_admission", "host_admission", admitted, True),
                                            ("excluded_admin_invitation", "host_membership", membership, True),
                                            ("exact_stale_root_invitation", "host_membership", root_membership, False)):
            additions = [(kind, grant), ("attestation", attestation)]
            if excluded:
                additions.append(("admin_removal", self.removal(self.quinn)))
            catalog = self.catalog(additions, current=True, source=renewal["catalog"])
            transcript = Transcript(self, {**renewal, "activation": renewed})
            transcript.values["owner"]["membership_proof_id"] = proof(kind, grant)["id"]
            activation = transcript.finish()
            self.add_request("renewal/" + label + "_with_matching_current_attestation", ActivationAuthor.request(self, renewal,
                             activation, catalog, epoch=1), error("forbidden") if excluded else ActivationAuthor.success(self, activation))

    def build(self):
        self.chain_cases()
        self.current_and_sticky()
        self.historical_and_current_operations()
        self.legacy_invites()
        self.features_and_framing()
        self.policy_group_integration()
        self.completed_redemption_labels()
        self.exact_renewal_attestation_boundaries()
        return self.cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go-probe")
    parser.add_argument("--rust-probe")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()
    probes = [(label, path) for label, path in (("go", args.go_probe), ("rust", args.rust_probe)) if path]
    if not probes and not args.self_check:
        parser.error("supply a probe or --self-check")
    vectors = {path.name: json.loads(path.read_bytes()) for path in sorted((ROOT / "conformance" / "vectors").glob("*.json"))}
    author = Author(vectors)
    fixed = author.oracle.fixture_self_check()
    cases = author.build()
    print(f"Independent oracle: {fixed} signatures reproduced; {len(cases)} root-chain checks.", flush=True)
    failures = 0
    for label, executable in probes:
        probe = Probe(label, executable, 60)
        try:
            for case in cases:
                actual = probe.exchange(case.request)
                if actual != case.expected:
                    failures += 1
                    print(f"FAIL {label} {case.name}: expected {str(case.expected)[:3000]}; received {str(actual)[:3000]}", file=sys.stderr)
        finally:
            probe.close()
        print(f"{label}: {len(cases)} root-chain checks completed.", flush=True)
    return int(failures > 0)


if __name__ == "__main__":
    sys.exit(main())
