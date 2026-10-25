#!/usr/bin/env python3
"""Independent completed invitation-history catalog conformance.

Contracts, public fixtures and independent Python signers define every expected
fact. This suite does not test TLS callers, private tokens, first redemption,
single-use writes, committed retries, freshness, persistence or writer readiness.
"""

import argparse
import copy
import json
from pathlib import Path
import sys

from linking_actions import Author as ActionAuthor, NOW
from linking_activations import Author as ActivationAuthor, Transcript, payload, proof, semantic_id, shift, sort_catalog
from linking_records import Author as RecordAuthor
from linking_paths import error
from linking_readers import Probe, b64, digest, lines, message, unb64, wire


ROOT = Path(__file__).resolve().parents[1]
DAY = 86400
FORMS = (("host", "none"), ("person", "admit"), ("member", "admit"), ("member", "skip"))


def invite_value(invite):
    return payload(invite) if "payload_base64" in invite else invite


def redemption_id(redemption, raw=None):
    return proof("invite_redemption", redemption, raw)["id"]


class Author(RecordAuthor):
    def invite(self, kind, context, invite, label, expires, style):
        unsigned = {"network_id": self.network, "invite_public_key": invite,
                    "member": label, "invite_expires_at": expires}
        if kind == "person-invite-v1":
            unsigned["invite_epoch"] = 0
        if style == "envelope":
            return self.record(kind, context, unsigned)
        msg = (lines("peerspan-person-invite-v1", self.network, unsigned["invite_epoch"], invite, label, expires)
               if kind == "person-invite-v1" else lines("peerspan-invite-v1", self.network, invite, label, expires))
        signer = self.root if style in ("legacy_root", "legacy_root_ssh") else self.signer(context)
        unsigned["signature"] = (b64(self.signers[signer].raw(msg)) if style == "legacy_root"
                                 else self.signers[signer].sshsig(msg))
        return unsigned

    def redemption(self, mode="member", action="admit", context=None, style="envelope", invite=None,
                   host=None, person=None, label=None, expires=None, joined=NOW):
        context = context or self.root_context
        invite = invite or self.key("redemption/invite")
        label = label or ("alice" if action == "skip" else "dana")
        expires = expires or shift(NOW, DAY)
        host = host or self.target_host
        person = person or (self.person if action == "skip" else self.new_person)
        result = {"format": 1, "mode": mode, "person_action": action,
                  "host_public_key": "-", "person_public_key": "-", "joined_at": joined,
                  "host_invite": "-", "person_invite": "-", "host_member_signature": "-", "person_member_signature": "-"}
        if mode != "person":
            result["host_public_key"] = host
            result["host_invite"] = self.invite("invite-v1", context, invite, label, expires, style)
            result["host_member_signature"] = b64(self.signers[invite].raw(lines("peerspan-member-v1", self.network, invite, host, joined)))
        if mode != "host":
            result["person_public_key"] = person
        if action == "admit":
            result["person_invite"] = self.invite("person-invite-v1", context, invite, label, expires, style)
            result["person_member_signature"] = b64(self.signers[invite].raw(lines("peerspan-person-member-v1", self.network, invite, person, joined)))
        return result

    def catalog(self, redemptions, context=None, extra=(), acknowledgments=True):
        context = context or self.root_context
        objects = [("invite_redemption", value) for value in redemptions] + list(extra)
        for value in redemptions:
            host = value.get("host_public_key")
            if acknowledgments and isinstance(host, str) and host in self.signers:
                objects.append(("join_ack", self.ack(host)))
        return self.with_proofs(context["catalog"], objects)

    def expected(self, redemption, context=None, host=True, person=True, facts=None):
        context = context or self.root_context
        facts = facts or self.base_facts.clone()
        if host or person:
            facts.path(context)
        if redemption["host_invite"] != "-":
            value = invite_value(redemption["host_invite"])
            facts.host(redemption["host_public_key"], value["member"] if host else "-", admitted=host)
        if redemption["person_action"] == "admit":
            value = invite_value(redemption["person_invite"])
            subject = redemption["person_public_key"]
            administrator = facts.persons.get(subject, {}).get("administrator", False)
            facts.person(subject, value["member"] if person else "-", admitted=person, administrator=administrator)
        return facts

    def pair(self, redemption, half=None, raw=None):
        ids = [redemption_id(redemption, raw)]
        for field in (half,) if half else ("host_invite", "person_invite"):
            if redemption[field] != "-" and "payload_base64" in redemption[field]:
                ids.append(semantic_id("person_record", redemption[field]))
        return sorted(ids)

    def forms_and_signers(self):
        for mode, action in FORMS:
            for label, context in (("root", self.root_context), ("b", self.b), ("c", self.c)):
                red = self.redemption(mode, action, context)
                self.add(f"form/{mode}/{action}/{label}", self.catalog([red], context), self.expected(red, context))
            for style in ("legacy_root", "legacy_root_ssh", "legacy_person"):
                red = self.redemption(mode, action, style=style)
                self.add(f"legacy/{mode}/{action}/{style}", self.catalog([red]), self.expected(red))
        for mask in (1, 2, 8):
            context = self.narrowed(mask, "redemption-scope-" + str(mask))
            red = self.redemption("host", "none", context)
            self.add("scope/" + str(mask), self.catalog([red], context), self.expected(red, context),
                     code=None if mask & 8 else "forbidden")
        fixture = self.fixtures["nonadmin_owner_with_independent_admin"]
        cert = payload(fixture["activation"]["owner"])["certificate"]
        for label, context in (("root", self.context(fixture["catalog"])), ("device", self.active_context(fixture, [cert]))):
            red = self.redemption("host", "none", context)
            self.add("role/nonadmin_" + label, self.catalog([red], context), code="forbidden")
        red = self.redemption("host", "none", self.b, style="legacy_person")
        self.add("legacy/device_cannot_masquerade_as_person", self.catalog([red], self.b), code="forbidden")
        red = self.redemption("member", "admit", person=self.person, label="alice")
        self.add("historical/existing_subject_is_idempotent_not_first_admit", self.catalog([red]), self.expected(red))

    def skip_and_dependencies(self):
        red = self.redemption("member", "skip", person=self.new_person, label="dana")
        self.add("skip/missing_independent_person", self.catalog([red]), code="proof_required")
        ordinary = self.record("person-admit-v1", unsigned=dict(self.payloads["person-admit-v1"], member="dana"))
        facts = self.expected(red, facts=self.base_facts.clone().grant(ordinary))
        self.add("skip/ordinary_admission_dependency", self.catalog([red], extra=[("person_record", ordinary)]), facts)
        wrong = self.redemption("member", "skip", person=self.person, label="dana")
        self.add("skip/exact_admitted_label_required", self.catalog([wrong]), code="invalid")
        removed = self.signed_legacy("person_removal", {"person_public_key": self.new_person, "removed_at": NOW})
        self.add("skip/known_removed_person", self.catalog([red], extra=[("person_removal", removed)]), code="forbidden")
        admitting = self.redemption("person", "admit")
        later = self.redemption("member", "skip", invite=self.key("skip/later-invite"), person=self.new_person, label="dana")
        facts = self.expected(later, facts=self.expected(admitting))
        catalog = self.catalog([admitting, later])
        preceding = redemption_id(later)
        catalog["objects"] = [entry for entry in catalog["objects"] if entry["id"] != redemption_id(admitting)]
        for spaces in range(4096):
            alias = proof("invite_redemption", raw=b" " * spaces + wire(admitting))
            if alias["id"] > preceding:
                break
        else:
            raise AssertionError("could not order independent person proof after skip")
        catalog["objects"].append(alias)
        sort_catalog(catalog)
        self.add("skip/later_catalog_redemption_supplies_independent_person", catalog, facts)
        a, b = self.key("issuer/a"), self.key("issuer/b")
        ca, cb = self.root_person(a), self.root_person(b)
        ra = self.redemption("person", "admit", ca, person=b, invite=self.key("issuer/a-invite"))
        rb = self.redemption("person", "admit", cb, person=a, invite=self.key("issuer/b-invite"))
        roles = [("admin_delegation", self.delegation(key)) for key in (a, b)]
        self.add("dependency/issuer_admission_cycle", self.catalog([ra, rb], extra=roles), code="invalid")
        self_admit = self.redemption("person", "admit", ca, person=a)
        self.add("dependency/issuer_cannot_admit_itself", self.catalog([self_admit], extra=[roles[0]]), code="invalid")
        admission = self.subject_record(self.person, a, "dana")
        facts = self.base_facts.clone().person(a, "dana", administrator=True).person(b, "dana", administrator=True)
        self.add("dependency/independent_admission_breaks_cycle", self.catalog([ra, rb], extra=[*roles, ("person_record", admission)]), facts)
        no_role = self.redemption("person", "admit", ca, person=b)
        self.add("dependency/admission_does_not_supply_admin_role", self.catalog([no_role], extra=[("person_record", admission)]), code="forbidden")

    def half_use_and_aliases(self):
        host = self.redemption("host", "none")
        person = self.redemption("person", "admit")
        self.add("use/host_and_person_halves_are_separate", self.catalog([host, person]), self.expected(person, facts=self.expected(host)))
        for label, red, changed in (("host", host, dict(host, host_public_key=self.key("other-host"))),
                                     ("person", person, dict(person, person_public_key=self.key("other-person")))):
            field = "host_member_signature" if label == "host" else "person_member_signature"
            domain = "peerspan-member-v1" if label == "host" else "peerspan-person-member-v1"
            subject = changed["host_public_key" if label == "host" else "person_public_key"]
            invite = invite_value(red["host_invite" if label == "host" else "person_invite"])["invite_public_key"]
            changed[field] = b64(self.signers[invite].raw(lines(domain, self.network, invite, subject, changed["joined_at"])))
            self.add("use/conflicting_" + label + "_subjects", self.catalog([red, changed]), code="state_conflict")
        aliases = self.catalog([host])
        aliases["objects"].append(proof("invite_redemption", raw=json.dumps(host, indent=2).encode()))
        sort_catalog(aliases)
        self.add("use/equivalent_exact_byte_aliases", aliases, self.expected(host))
        second = self.redemption("host", "none", joined=shift(NOW, 1))
        self.add("use/same_subject_evidence_is_idempotent", self.catalog([host, second]), self.expected(host))
        invite = invite_value(host["host_invite"])
        other = self.key("legacy-conflicting-host")
        legacy = {"network_id": self.network, "host_public_key": other, "member": invite["member"],
                  "invite_public_key": invite["invite_public_key"], "invite_expires_at": invite["invite_expires_at"], "joined_at": NOW}
        legacy["invite_signature"] = b64(self.signers[self.root].raw(lines("peerspan-invite-v1", self.network,
                    invite["invite_public_key"], invite["member"], invite["invite_expires_at"])))
        legacy["host_signature"] = b64(self.signers[invite["invite_public_key"]].raw(lines("peerspan-member-v1", self.network,
                    invite["invite_public_key"], other, NOW)))
        self.add("use/conflict_with_legacy_membership", self.catalog([host], extra=[("host_membership", legacy), ("join_ack", self.ack(other))]), code="state_conflict")

    def retention(self):
        for mode, action in FORMS:
            for label, context in (("root", self.root_context), ("device", self.b)):
                red = self.redemption(mode, action, context)
                red_id = redemption_id(red)
                expiry = invite_value(red["person_invite"] if mode == "person" else red["host_invite"])["invite_expires_at"]
                catalog = self.catalog([red], context)
                facts = self.expected(red, context)
                self.add(f"retention/{mode}/{action}/{label}/expired_without_pair", catalog, code="proof_required", required=[red_id], now=expiry)
                cp = self.checkpoint(self.pair(red))
                self.add(f"retention/{mode}/{action}/{label}/exact_pair", self.with_proofs(catalog, [("checkpoint", cp)]), facts, now=expiry)
                legacy = self.redemption(mode, action, style="legacy_person")
                self.add(f"retention/{mode}/{action}/legacy_expiry_is_historical", self.catalog([legacy]), self.expected(legacy), now=expiry)
        red = self.redemption("member", "admit", self.b)
        red_id = redemption_id(red)
        expiry = invite_value(red["host_invite"])["invite_expires_at"]
        host_id, person_id = (semantic_id("person_record", red[field]) for field in ("host_invite", "person_invite"))
        catalog = self.catalog([red], self.b)
        for label, ids in (("only_redemption", [red_id]), ("only_invites", [host_id, person_id]),
                            ("missing_person_half", [host_id, red_id])):
            self.add("retention/" + label, self.with_proofs(catalog, [("checkpoint", self.checkpoint(ids))]), code="proof_required", required=[red_id], now=expiry)
        separate = [("checkpoint", self.checkpoint([host_id, red_id])), ("checkpoint", self.checkpoint([person_id, red_id]))]
        self.add("retention/separate_complete_pairs_per_half", self.with_proofs(catalog, separate), self.expected(red, self.b), now=expiry)
        host = self.redemption("host", "none", self.b)
        host_id, red_id = semantic_id("person_record", host["host_invite"]), redemption_id(host)
        catalog = self.catalog([host], self.b)
        one_each = [("checkpoint", self.checkpoint([host_id])), ("checkpoint", self.checkpoint([red_id]))]
        self.add("retention/two_one_id_checkpoints_are_not_a_pair", self.with_proofs(catalog, one_each), code="proof_required", required=[red_id], now=expiry)
        for label, cp in (("wrong_person", self.checkpoint([host_id, red_id], person=self.quinn, signer=self.quinn)),
                           ("self", self.checkpoint([host_id, red_id], semantic_id("certificate", self.cert_b), self.cert_b["device_public_key"])),
                           ("descendant", self.checkpoint([host_id, red_id], semantic_id("certificate", self.cert_c), self.cert_c["device_public_key"]))):
            context = self.c if label == "descendant" else self.b
            self.add("retention/checkpoint_" + label, self.catalog([host], context, [("checkpoint", cp)]),
                     code="proof_required" if label == "wrong_person" else "forbidden", required=[red_id], now=expiry)
        for label, missing in (("ar", "ar_" + "0" * 64), ("pf", "pf_" + "0" * 64)):
            cp = self.checkpoint([host_id, red_id, missing])
            self.add("retention/missing_referenced_" + label, self.with_proofs(catalog, [("checkpoint", cp)]), code="proof_required", required=[missing], now=expiry)
        non_redemption = next(entry["id"] for entry in catalog["objects"] if entry["kind"] == "person_admission")
        self.add("retention/non_redemption_pf_still_unsupported", self.with_proofs(catalog,
                 [("checkpoint", self.checkpoint([host_id, red_id, non_redemption]))]), code="upgrade_required", now=expiry)
        bad = self.checkpoint([host_id, red_id])
        signature = bytearray(unb64(bad["signature"]))
        signature[-1] ^= 1
        bad["signature"] = b64(signature)
        self.add("retention/bad_matching_checkpoint", self.with_proofs(catalog, [("checkpoint", bad)]), code="invalid", now=expiry)
        aliased = self.with_proofs(catalog, [("checkpoint", self.checkpoint([host_id, red_id]))])
        alias_raw = json.dumps(host, indent=2).encode()
        alias = proof("invite_redemption", raw=alias_raw)
        aliased["objects"].append(alias)
        sort_catalog(aliased)
        self.add("retention/byte_alias_needs_its_own_exact_pf", aliased, code="proof_required", required=[alias["id"]], now=expiry)
        child = self.redemption("host", "none", self.c)
        cp = self.checkpoint(self.pair(child), semantic_id("certificate", self.cert_b), self.cert_b["device_public_key"])
        self.add("retention/live_strict_ancestor", self.catalog([child], self.c, [("checkpoint", cp)]), self.expected(child, self.c), now=expiry)
        sibling = self.new_root_link("redemption-sibling", created="2026-10-23T12:00:00Z")
        sibling_cert = payload(sibling["activation"]["owner"])["certificate"]
        cp = self.checkpoint([host_id, red_id], semantic_id("certificate", sibling_cert), sibling_cert["device_public_key"])
        self.add("retention/sibling_checkpoint_forbidden", self.with_proofs(catalog, [("activation", sibling["activation"]), ("checkpoint", cp)]), code="forbidden", now=expiry)

    def issuer_and_final_authority(self):
        red = self.redemption("host", "none", self.b)
        red_id = redemption_id(red)
        cp = self.checkpoint(self.pair(red))
        pending = self.context(self.with_proofs(self.base["catalog"], [("certificate", self.cert_b)]), [self.cert_b])
        self.add("issuer/pending_certificate", self.catalog([red], pending), code="proof_required", required=[self.cert_b["request_id"]])
        self.add("issuer/checkpoint_cannot_activate_pending", self.catalog([red], pending, [("checkpoint", cp)]),
                 code="proof_required", required=[self.cert_b["request_id"]])
        self.add("issuer/missing_certificate", self.catalog([red]), code="proof_required", required=[semantic_id("certificate", self.cert_b)])
        for label, kind, restriction in (("revoked", "device_revocation", self.revocation(self.cert_b)),
                                          ("unbound", "person_record", self.record("host-unbind-v1", unsigned=dict(self.payloads["host-unbind-v1"], host_public_key=self.cert_b["host_public_key"])))):
            catalog = self.catalog([red], self.b, [(kind, restriction)])
            self.add("issuer/" + label + "_requires_pair", catalog, code="proof_required", required=[red_id])
            facts = self.expected(red, self.b)
            if label == "revoked":
                facts.revoked.add((self.person, self.cert_b["device_public_key"]))
            else:
                facts.bind(self.cert_b["host_public_key"], "-")
            self.add("issuer/" + label + "_exact_pair", self.with_proofs(catalog, [("checkpoint", cp)]), facts)
        cap = self.cert_b["not_after"]
        for label, expires, code in (("exact_path_expiry", cap, None), ("beyond_path_expiry", shift(cap, 1), "forbidden")):
            candidate = self.redemption("host", "none", self.b, expires=expires)
            self.add("issuer/" + label, self.catalog([candidate], self.b), self.expected(candidate, self.b), code=code)
        far = self.redemption("host", "none", expires=shift(NOW, 400 * DAY))
        self.add("historical/fresh_issue_30_day_bound_is_not_reapplied", self.catalog([far]), self.expected(far))

    def withdrawals(self):
        for label, context in (("root", self.root_context), ("device", self.b)):
            red = self.redemption("member", "admit", context)
            red_id = redemption_id(red)
            host_id, person_id = (semantic_id("person_record", red[field]) for field in ("host_invite", "person_invite"))
            variants = (("none", [], False, False), ("pf_only", ["redemption:" + red_id], False, False),
                        ("ar_only", ["record:" + host_id, "record:" + person_id], False, False),
                        ("host_only", ["record:" + host_id, "redemption:" + red_id], True, False),
                        ("person_only", ["record:" + person_id, "redemption:" + red_id], False, True),
                        ("both", ["record:" + host_id, "record:" + person_id, "redemption:" + red_id], True, True))
            for name, kept, host_ok, person_ok in variants:
                if context["path"] and (host_ok or person_ok):
                    kept = [*kept, "record:" + semantic_id("person_record", self.record_b)]
                removal = self.removal(self.person, kept)
                facts = self.expected(red, context if host_ok or person_ok else self.root_context, host_ok, person_ok)
                facts.persons[self.person]["administrator"] = False
                self.add("withdrawal/" + label + "/" + name, self.catalog([red], context, [("admin_removal", removal)]), facts)
            removal = self.removal(self.person, version=1)
            facts = self.expected(red, host=False, person=False)
            facts.persons[self.person]["administrator"] = False
            self.add("withdrawal/" + label + "/v1_retains_no_enveloped_halves", self.catalog([red], context, [("admin_removal", removal)]), facts)
            for field in ("host_member_signature", "person_member_signature"):
                bad = dict(red, **{field: b64(b"\0" * 64)})
                self.add("withdrawal/" + label + "/inert_bad_" + field, self.catalog([bad], context,
                         [("admin_removal", self.removal(self.person))]), code="invalid")
            malformed = copy.deepcopy(red)
            malformed["host_invite"]["signature"] = self.signers[self.quinn].sshsig(message("person_record", malformed["host_invite"]))
            self.add("withdrawal/" + label + "/inert_bad_inline_signature", self.catalog([malformed], context,
                     [("admin_removal", self.removal(self.person))]), code="invalid")
        red = self.redemption("host", "none", self.b)
        red_id = redemption_id(red)
        kept = ["record:" + semantic_id("person_record", red["host_invite"]), "redemption:" + red_id,
                "record:" + semantic_id("person_record", self.record_b)]
        expiry = invite_value(red["host_invite"])["invite_expires_at"]
        catalog = self.catalog([red], self.b, [("admin_removal", self.removal(self.person, kept))])
        self.add("withdrawal/root_kept_does_not_extend_invite_expiry", catalog, code="proof_required", required=[red_id], now=expiry)
        facts = self.expected(red, self.b)
        facts.persons[self.person]["administrator"] = False
        self.add("withdrawal/both_retention_dimensions", self.with_proofs(catalog,
                 [("checkpoint", self.checkpoint(self.pair(red)))]), facts, now=expiry)
        legacy = self.redemption("member", "admit", style="legacy_person")
        digests = []
        for field in ("host_invite", "person_invite"):
            value = legacy[field]
            msg = (lines("peerspan-person-invite-v1", self.network, 0, value["invite_public_key"], value["member"], value["invite_expires_at"])
                   if field == "person_invite" else lines("peerspan-invite-v1", self.network, value["invite_public_key"], value["member"], value["invite_expires_at"]))
            digests.append(digest(msg))
        for version, retained in ((1, digests), (2, ["legacy:" + value for value in digests])):
            facts = self.expected(legacy)
            facts.persons[self.person]["administrator"] = False
            self.add("withdrawal/legacy_exact_message_retention_v" + str(version), self.catalog([legacy], extra=
                     [("admin_removal", self.removal(self.person, retained, version))]), facts)

    def sticky_facts(self):
        red = self.redemption()
        base = self.expected(red)
        person_remove = self.record("person-remove-v1", unsigned=dict(self.payloads["person-remove-v1"], person_public_key=self.new_person))
        host_remove = self.record("revoke-host-v1")
        invite_revoke = self.record("revoke-invite-v1", unsigned=dict(self.payloads["revoke-invite-v1"],
                             invite_public_key=invite_value(red["host_invite"])["invite_public_key"]))
        person_facts = base.clone().person(self.new_person, "dana", admitted=False)
        host_facts = base.clone().host(self.target_host, "dana", admitted=False)
        self.add("restriction/person_removal_preserves_verified_label", self.catalog([red], extra=[("person_record", person_remove)]), person_facts)
        self.add("restriction/host_removal_preserves_verified_label_without_join_ack", self.catalog([red], extra=
                 [("person_record", host_remove)], acknowledgments=False), host_facts)
        false = self.base_facts.clone().person(self.new_person, admitted=False).host(self.target_host, admitted=False)
        self.add("restriction/invite_revocation_has_no_usable_label", self.catalog([red], extra=[("person_record", invite_revoke)]), false)
        independent = [self.record("person-admit-v1", unsigned=dict(self.payloads["person-admit-v1"], member="independent")),
                       self.record("host-admit-v1", unsigned=dict(self.payloads["host-admit-v1"], member="independent"))]
        facts = self.base_facts.clone().person(self.new_person, "independent").host(self.target_host, "independent")
        self.add("restriction/independent_admissions_survive_invite_revocation", self.catalog([red], extra=
                 [("person_record", invite_revoke), *(("person_record", record) for record in independent)]), facts)
        owner = self.root_person(self.new_person)
        binding = self.record("host-bind-v1", owner, dict(self.payloads["host-bind-v1"], person_public_key=self.new_person))
        unbinding = self.record("host-unbind-v1", owner, dict(self.payloads["host-unbind-v1"], person_public_key=self.new_person))
        self.add("restriction/redeemed_person_can_permanently_unbind", self.catalog([red], extra=
                 [("person_record", binding), ("person_record", unbinding)]), base.clone().bind(self.target_host, "-"))
        unrelated = self.record("host-unbind-v1")
        self.add("restriction/other_person_unbinding_cannot_clear_binding", self.catalog([red], extra=
                 [("person_record", binding), ("person_record", unrelated)]), base.clone().bind(self.target_host, self.new_person))
        device = self.redemption("host", "none", self.b)
        unbind_b = self.record("host-unbind-v1", unsigned=dict(self.payloads["host-unbind-v1"], host_public_key=self.cert_b["host_public_key"]))
        catalog = self.catalog([device], self.b)
        for spaces in range(4096):
            later = proof("person_record", raw=b" " * spaces + wire(unbind_b))
            if later["id"] > redemption_id(device):
                break
        else:
            raise AssertionError("could not order restriction after redemption")
        catalog["objects"].append(later)
        sort_catalog(catalog)
        self.add("restriction/later_dependency_rechecks_final_issuer", catalog, code="proof_required", required=[redemption_id(device)])

    def consumers_and_strictness(self):
        person = self.redemption("person", "admit")
        context = self.root_person(self.new_person, self.catalog([person]))
        action = self.record("host-bind-v1", context, dict(self.payloads["host-bind-v1"], person_public_key=self.new_person))
        self.add_request("consumer/action_uses_redeemed_person", ActionAuthor.request(self, action, context), ActionAuthor.success(self, action, context))
        fixture = self.fixtures["same_key_root_renewal"]
        target = payload(fixture["activation"]["request"])["host_public_key"]
        host = self.redemption("host", "none", host=target, label="alice")
        catalog = self.catalog([host], self.context(fixture["catalog"]))
        transcript = Transcript(self, fixture)
        transcript.values["owner"]["membership_proof_id"] = redemption_id(host)
        activation = transcript.finish()
        self.add_request("renewal/exact_redemption_host_half", ActivationAuthor.request(self, fixture, activation, catalog), ActivationAuthor.success(self, activation))
        missing = copy.deepcopy(catalog)
        missing["objects"] = [entry for entry in missing["objects"] if entry["id"] != redemption_id(host)]
        self.add_request("renewal/exact_redemption_pf_cannot_be_substituted", ActivationAuthor.request(self, fixture, activation, missing),
                         error("proof_required", [redemption_id(host)]))
        revoked = self.record("revoke-invite-v1", unsigned=dict(self.payloads["revoke-invite-v1"], invite_public_key=invite_value(host["host_invite"])["invite_public_key"]))
        self.add_request("renewal/independent_membership_does_not_authorize_revoked_selected_half",
                         ActivationAuthor.request(self, fixture, activation, self.with_proofs(catalog, [("person_record", revoked)])), error("forbidden"))
        excluded = self.redemption("host", "none", self.root_person(self.quinn), host=target, label="alice")
        selected = Transcript(self, fixture)
        selected.values["owner"]["membership_proof_id"] = redemption_id(excluded)
        self.add_request("renewal/independent_membership_cannot_authorize_inert_selected_half", ActivationAuthor.request(self, fixture,
                         selected.finish(), self.catalog([excluded], self.context(fixture["catalog"]),
                         [("admin_removal", self.removal(self.quinn))])), error("forbidden"))
        feature = next(json.loads(unb64(entry["body_base64"])) for entry in self.base["catalog"]["objects"] if entry["kind"] == "feature")
        first = {"kind": "feature_activation", "network_base64": b64(wire(self.data["network"])),
                 "catalog_base64": b64(wire(self.catalog([person]))), "feature_base64": b64(wire(feature)),
                 "epoch": 0, "known_feature_id": "-", "now": NOW}
        self.add_request("consumer/first_feature_refuses_well_formed_redemption", first, error("forbidden"))
        for mode, action in FORMS:
            red = self.redemption(mode, action)
            for field in red:
                malformed = dict(red)
                del malformed[field]
                self.add(f"strict/{mode}/{action}/missing_{field}", self.catalog([malformed]), code="invalid")
            for label, edits in (("unknown", {"extra": True}), ("seed", {"invite_seed": b64(b"\0" * 32)}),
                                  ("mode", {"mode": "other"}), ("action", {"person_action": "other"}),
                                  ("null_joined", {"joined_at": None})):
                self.add(f"strict/{mode}/{action}/{label}", self.catalog([dict(red, **edits)]), code="invalid")
        host = self.redemption("host", "none")
        for mode, action in (("host", "admit"), ("host", "skip"), ("person", "none"), ("person", "skip"), ("member", "none")):
            self.add("strict/invalid_pair/" + mode + "/" + action, self.catalog([dict(host, mode=mode, person_action=action)]), code="invalid")
        both = self.redemption()
        for field in ("host_member_signature", "person_member_signature"):
            self.add("signature/" + field, self.catalog([dict(both, **{field: b64(b"\0" * 64)})]), code="invalid")
        for field in ("host_invite", "person_invite"):
            malformed = copy.deepcopy(both)
            malformed[field]["signature"] = self.signers[self.quinn].sshsig(message("person_record", malformed[field]))
            self.add("signature/inline_" + field, self.catalog([malformed]), code="invalid")
        for label, context in (("different_person", self.root_person(self.quinn)), ("different_certificate", self.b)):
            mixed = copy.deepcopy(both)
            value = invite_value(both["person_invite"])
            mixed["person_invite"] = self.invite("person-invite-v1", context, value["invite_public_key"], value["member"], value["invite_expires_at"], "envelope")
            self.add("agreement/" + label, self.catalog([mixed], self.b), code="invalid")
        for field, value in (("invite_public_key", self.key("mismatched-invite")), ("member", "different"),
                              ("invite_expires_at", shift(NOW, 2 * DAY))):
            mixed = copy.deepcopy(both)
            unsigned = dict(invite_value(mixed["person_invite"]), **{field: value})
            mixed["person_invite"] = self.record("person-invite-v1", unsigned=unsigned)
            mixed["person_member_signature"] = b64(self.signers[unsigned["invite_public_key"]].raw(lines("peerspan-person-member-v1",
                    self.network, unsigned["invite_public_key"], mixed["person_public_key"], mixed["joined_at"])))
            self.add("agreement/" + field, self.catalog([mixed]), code="invalid")
        mixed = copy.deepcopy(both)
        value = invite_value(both["person_invite"])
        mixed["person_invite"] = self.invite("person-invite-v1", self.root_context, value["invite_public_key"], value["member"], value["invite_expires_at"], "legacy_person")
        self.add("agreement/legacy_person_and_envelope_same_exact_issuer", self.catalog([mixed]), self.expected(mixed))
        mixed["person_invite"] = self.invite("person-invite-v1", self.root_context, value["invite_public_key"], value["member"], value["invite_expires_at"], "legacy_root")
        self.add("agreement/network_root_is_distinct_from_original_person", self.catalog([mixed]), code="invalid")
        for label, changed in (("host_has_person", dict(host, person_public_key=self.new_person)),
                                ("person_has_host", dict(person, host_public_key=self.target_host)),
                                ("skip_has_unused_person_half", dict(self.redemption("member", "skip"), person_invite=both["person_invite"])),
                                ("admit_has_absent_person", dict(both, person_public_key="-"))):
            self.add("strict/inconsistent_absent/" + label, self.catalog([changed]), code="invalid")
        legacy = self.redemption("person", "admit", style="legacy_root")
        value = legacy["person_invite"]
        value["invite_epoch"] = 1
        value["signature"] = b64(self.signers[self.root].raw(lines("peerspan-person-invite-v1", self.network, 1,
                                      value["invite_public_key"], value["member"], value["invite_expires_at"])))
        self.add("context/legacy_nonzero_epoch", self.catalog([legacy]), code="proof_required")
        for field, value in (("network_id", "net_" + "0" * 64), ("epoch", 1), ("operation_id", self.cert_b["request_id"])):
            malformed = self.redemption("person", "admit")
            malformed["person_invite"][field] = value
            self.oracle.resign("person_record", malformed["person_invite"], self.person)
            self.add("context/envelope_" + field, self.catalog([malformed]), code="invalid")
        late = self.redemption("host", "none", joined=shift(NOW, 2 * DAY))
        self.add("strict/joined_after_expiry", self.catalog([late]), code="invalid")
        self.add("feature/host_missing_join_ack", self.catalog([host], acknowledgments=False), code="proof_required")
        good = self.request(self.catalog([person]))
        for label, raw in (("duplicate", wire(good)[:-1] + b',"kind":"catalog_facts"}'),
                           ("invalid_utf8", b'{"kind":"\xff"}'), ("trailing", wire(good) + b"{}"),
                           ("over_2mib", b" " * (2 * 1024 * 1024 + 1))):
            self.add_request("framing/" + label, raw, error("invalid"))
        self.add_request("framing/recovery", good, self.expected(person).reply(), keep=True)

    def build(self):
        self.forms_and_signers()
        self.skip_and_dependencies()
        self.half_use_and_aliases()
        self.retention()
        self.issuer_and_final_authority()
        self.withdrawals()
        self.sticky_facts()
        self.consumers_and_strictness()
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
    accepted = sum(case.expected["ok"] for case in cases)
    print(f"Independent oracle: {fixed} published signatures reproduced; {len(cases)} redemption checks "
          f"({accepted} accepted, {len(cases) - accepted} rejected).", flush=True)
    if not probes:
        print("Self-check only; no redemption implementation or live protocol was tested.")
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
        print(f"{label}: {checked} redemption checks completed.", flush=True)
    if failures:
        print(f"FAILED: {failures} redemption conformance failures.", file=sys.stderr)
        return 1
    print("PASS: completed public invitation history only; no TLS-caller, private token, first-use, "
          "committed retry, mutation, persistence or freshness claim.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
