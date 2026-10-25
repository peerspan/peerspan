#!/usr/bin/env python3
"""Independent historical ordinary-grant materialization conformance.

Only accepted contracts, public fixtures and independent Python signing helpers
define expected facts. No host implementation is imported. A successful bounded
projection is not persisted state, freshness, a mutation or writer readiness.
"""

import argparse
import copy
import json
from pathlib import Path
import sys

from linking_actions import Author as ActionAuthor, NOW
from linking_activations import Author as ActivationAuthor, LIMIT, Transcript, payload, proof, semantic_id, shift, sort_catalog
from linking_paths import error
from linking_readers import Probe, b64, digest, lines, message, unb64, wire


ROOT = Path(__file__).resolve().parents[1]
LATE = "2027-01-22T12:00:00Z"
KINDS = ("host-bind-v1", "host-admit-v1", "person-admit-v1")


class Facts:
    """Explicit expected facts, added only by a case's independently proved work."""
    def __init__(self, author):
        self.author = author
        self.persons, self.hosts, self.bindings = {}, {}, {}
        self.activated, self.revoked = set(), set()
        self.person(author.person, "alice", administrator=True)
        self.person(author.quinn, "quinn", administrator=True)
        for name, person, label in (("host_a", author.person, "alice"), ("host_q", author.quinn, "quinn")):
            host = author.data["keys"][name]["public_key"]
            self.host(host, label)
            self.bind(host, person)

    def clone(self):
        result = Facts(self.author)
        for field in ("persons", "hosts", "bindings", "activated", "revoked"):
            setattr(result, field, copy.deepcopy(getattr(self, field)))
        return result

    def person(self, key, member="-", admitted=True, administrator=False):
        self.persons[key] = {"person_public_key": key, "member": member, "admitted": admitted,
                             "administrator": administrator}
        return self

    def host(self, key, member="-", admitted=True):
        self.hosts[key] = {"host_public_key": key, "member": member, "admitted": admitted}
        return self

    def bind(self, host, person):
        self.bindings[host] = {"host_public_key": host, "person_public_key": person}
        return self

    def path(self, context):
        for cert in context["path"]:
            self.activated.add(semantic_id("certificate", cert))
            self.host(cert["host_public_key"], "alice")
            self.bind(cert["host_public_key"], cert["person_public_key"])
        return self

    def grant(self, record, admitted=True):
        value = payload(record)
        kind = record["kind"]
        if kind == "peerspan-host-bind-v1":
            self.bind(value["host_public_key"], value["person_public_key"])
        elif kind == "peerspan-host-admit-v1":
            self.host(value["host_public_key"], value["member"] if admitted else "-", admitted)
        else:
            self.person(value["person_public_key"], value["member"] if admitted else "-", admitted)
        return self

    def reply(self):
        return {"ok": True, "network_id": self.author.network, "feature_id": self.author.data["feature_id"],
                "persons": [self.persons[key] for key in sorted(self.persons)],
                "hosts": [self.hosts[key] for key in sorted(self.hosts)],
                "bindings": [self.bindings[key] for key in sorted(self.bindings)],
                "activated_certificate_ids": sorted(self.activated),
                "revoked_devices": [{"person_public_key": person, "device_public_key": device}
                                    for person, device in sorted(self.revoked)]}


class Author(ActionAuthor):
    def __init__(self, vectors):
        super().__init__(vectors)
        self.new_person = self.key("ordinary-subject")
        self.payloads["person-admit-v1"]["person_public_key"] = self.new_person
        self.base_facts = Facts(self)

    def request(self, catalog=None, **pins):
        result = {"kind": "catalog_facts", "network_base64": b64(wire(self.data["network"])),
                  "catalog_base64": b64(wire(self.base["catalog"] if catalog is None else catalog)),
                  "epoch": 0, "known_feature_id": "-", "now": NOW}
        result.update(pins)
        return result

    def add(self, name, catalog=None, facts=None, code=None, required=(), **pins):
        self.add_request(name, self.request(catalog, **pins), error(code, required) if code
                         else (facts or self.base_facts).reply())

    def catalog_with(self, records, context=None, extra=()):
        context = context or self.root_context
        additions = [("person_record", record) for record in records] + list(extra)
        for record in records:
            if record["kind"] == "peerspan-host-admit-v1":
                host = payload(record)["host_public_key"]
                additions.append(("join_ack", self.ack(host)))
        return self.with_proofs(context["catalog"], additions)

    def ack(self, host):
        value = {"format": 1, "feature_id": self.data["feature_id"], "host_public_key": host}
        self.oracle.resign("feature_ack", value, host)
        return value

    def delegation(self, person):
        value = {"network_id": self.network, "epoch": 0, "person_public_key": person, "delegated_at": NOW}
        value["signature"] = b64(self.signers[self.root].raw(lines("peerspan-admin-delegate-v1", self.network, 0, person, NOW)))
        return value

    def root_person(self, person, catalog=None):
        return self.context(catalog or self.base["catalog"], person=person)

    def subject_record(self, signer, subject, label):
        unsigned = dict(self.payloads["person-admit-v1"], person_public_key=subject, member=label)
        return self.record("person-admit-v1", self.root_person(signer), unsigned)

    def projection_and_grants(self):
        self.add("projection/legacy_baseline")
        self.add("projection/persisted_feature_pin", known_feature_id=self.data["feature_id"])
        self.add("projection/unused_complete_candidates_remain_lazy", self.c["catalog"])
        roles_only = self.with_proofs(self.base["catalog"], [("admin_delegation", self.delegation(self.new_person))])
        self.add("projection/delegation_alone_has_no_subject_entry", roles_only)
        for label, context in (("root", self.root_context), ("b", self.b), ("c", self.c)):
            records = []
            for kind in KINDS:
                record = self.record(kind, context)
                records.append(record)
                facts = self.base_facts.clone().path(context).grant(record)
                self.add("grant/" + label + "/" + kind, self.catalog_with([record], context), facts)
            combined = self.base_facts.clone().path(context)
            for record in records:
                combined.grant(record)
            self.add("grant/" + label + "/combined", self.catalog_with(records, context), combined)
        admitted = self.record("person-admit-v1")
        person_context = self.root_person(self.new_person)
        binding = self.record("host-bind-v1", person_context, dict(self.payloads["host-bind-v1"], person_public_key=self.new_person))
        facts = self.base_facts.clone().grant(admitted).grant(binding)
        self.add("grant/newly_admitted_original_person_can_bind", self.catalog_with([admitted, binding]), facts)
        host = self.record("host-admit-v1")
        missing_ack = self.with_proofs(self.base["catalog"], [("person_record", host)])
        self.add("feature/ordinary_admission_is_not_reader_support", missing_ack, code="proof_required")
        wrong_ack = dict(self.ack(self.target_host), feature_id="lf_" + "0" * 64)
        self.oracle.resign("feature_ack", wrong_ack, self.target_host)
        self.add("feature/wrong_join_feature", self.with_proofs(missing_ack, [("join_ack", wrong_ack)]), code="invalid")
        person_only = self.base_facts.clone().grant(admitted)
        self.add("grant/subject_is_not_admin_or_host_binding", self.catalog_with([admitted]), person_only)

    def dependencies(self):
        people = [self.key("ordinary-chain/" + str(index)) for index in range(4)]
        records = [self.subject_record(self.person, people[0], "person-0")]
        records += [self.subject_record(people[index - 1], people[index], "person-" + str(index)) for index in range(1, 4)]
        roles = [("admin_delegation", self.delegation(person)) for person in people[:-1]]
        facts = self.base_facts.clone()
        for index, person in enumerate(people):
            facts.person(person, "person-" + str(index), administrator=index < 3)
        self.add("dependency/independently_rooted_chain", self.catalog_with(records, extra=roles), facts)
        a, b = people[:2]
        cycle = [self.subject_record(a, b, "person-1"), self.subject_record(b, a, "person-0")]
        cycle_roles = [("admin_delegation", self.delegation(person)) for person in (a, b)]
        self.add("dependency/two_person_cycle", self.catalog_with(cycle, extra=cycle_roles), code="invalid")
        self.add("dependency/self_admission_cycle", self.catalog_with([self.subject_record(a, a, "person-0")],
                 extra=[cycle_roles[0]]), code="invalid")
        independent = self.subject_record(self.person, a, "person-0")
        broken = self.base_facts.clone().person(a, "person-0", administrator=True).person(b, "person-1", administrator=True)
        self.add("dependency/independent_proof_breaks_cycle", self.catalog_with([*cycle, independent], extra=cycle_roles), broken)
        unknown = self.subject_record(a, self.new_person, "unknown-subject")
        self.add("dependency/missing_signer_admission", self.catalog_with([unknown], extra=[cycle_roles[0]]), code="proof_required")
        admitted_a = self.subject_record(self.person, a, "person-0")
        self.add("dependency/admission_does_not_create_admin_role", self.catalog_with([admitted_a, unknown]), code="forbidden")
        many = [self.subject_record(self.person, self.key("independent/" + str(index)), "person-" + str(index)) for index in range(32)]
        many_facts = self.base_facts.clone()
        for record in many:
            many_facts.grant(record)
        self.add("dependency/32_independent_records_are_not_a_recursion_limit", self.catalog_with(many), many_facts)

    def history(self):
        for kind in KINDS:
            record = self.record(kind, self.b)
            record_id = semantic_id("person_record", record)
            catalog = self.catalog_with([record], self.b)
            facts = self.base_facts.clone().path(self.b).grant(record)
            self.add("history/expired_without_checkpoint/" + kind, catalog, code="proof_required", required=[record_id], now=LATE)
            cp = self.checkpoint([record_id])
            retained = self.with_proofs(catalog, [("checkpoint", cp)])
            self.add("history/expired_exact_root_checkpoint/" + kind, retained, facts, now=LATE)
            self.add("history/wrong_person_checkpoint/" + kind, self.with_proofs(catalog,
                     [("checkpoint", self.checkpoint([record_id], person=self.quinn, signer=self.quinn))]),
                     code="proof_required", required=[record_id], now=LATE)
            self.add("history/self_checkpoint_forbidden/" + kind, self.with_proofs(catalog,
                     [("checkpoint", self.checkpoint([record_id], semantic_id("certificate", self.cert_b),
                                                     self.cert_b["device_public_key"]))]), code="forbidden", now=LATE)
            bad = copy.deepcopy(cp)
            signature = bytearray(unb64(bad["signature"]))
            signature[-1] ^= 1
            bad["signature"] = b64(signature)
            self.add("history/bad_matching_checkpoint/" + kind, self.with_proofs(catalog, [("checkpoint", bad)]),
                     code="invalid", now=LATE)
            pending = self.context(self.with_proofs(self.base["catalog"], [("certificate", self.cert_b)]), [self.cert_b])
            self.add("history/checkpoint_cannot_activate_pending_issuer/" + kind,
                     self.catalog_with([record], pending, [("checkpoint", cp)]), code="proof_required",
                     required=[self.cert_b["request_id"]], now=LATE)
            self.add("history/missing_issuer_certificate/" + kind, self.catalog_with([record]), code="proof_required",
                     required=[semantic_id("certificate", self.cert_b)])
            for restriction_kind, restriction in (
                    ("revoked", self.revocation(self.cert_b)),
                    ("unbound", self.signed_legacy("host_unbinding", {"person_public_key": self.person,
                        "host_public_key": self.cert_b["host_public_key"], "unbound_at": NOW}, self.person, ssh=True))):
                wire_kind = "device_revocation" if restriction_kind == "revoked" else "host_unbinding"
                restricted = self.with_proofs(catalog, [(wire_kind, restriction)])
                self.add("history/" + restriction_kind + "_without_checkpoint/" + kind, restricted,
                         code="proof_required", required=[record_id])
                restored_facts = facts.clone()
                if restriction_kind == "revoked":
                    restored_facts.revoked.add((self.person, self.cert_b["device_public_key"]))
                else:
                    restored_facts.bind(self.cert_b["host_public_key"], "-")
                self.add("history/" + restriction_kind + "_exact_root_checkpoint/" + kind,
                         self.with_proofs(restricted, [("checkpoint", cp)]), restored_facts)
        records = [self.record(kind, self.b) for kind in KINDS]
        ids = [semantic_id("person_record", record) for record in records]
        partial = self.catalog_with(records, self.b, [("checkpoint", self.checkpoint(ids[:-1]))])
        self.add("history/partial_checkpoint_names_exact_missing_record", partial, code="proof_required", required=[ids[-1]], now=LATE)
        missing = "ar_" + "0" * 64
        self.add("history/every_checkpoint_member_is_verified", self.catalog_with([records[0]], self.b,
                 [("checkpoint", self.checkpoint([ids[0], missing]))]), code="proof_required", required=[missing], now=LATE)
        # C expires first, while its strict ancestor B can still retain C's
        # ordinary grant. The complete C activation remains required.
        fixture = copy.deepcopy(self.c_source)
        transcript = Transcript(self, fixture)
        transcript.values["owner"]["certificate"]["not_after"] = shift(NOW, 60)
        transcript.sign_certificate()
        fixture["activation"] = transcript.finish()
        cert = payload(fixture["activation"]["owner"])["certificate"]
        context = self.active_context(fixture, [self.cert_b, cert])
        record = self.record("host-bind-v1", context)
        record_id = semantic_id("person_record", record)
        cp = self.checkpoint([record_id], semantic_id("certificate", self.cert_b), self.cert_b["device_public_key"])
        self.add("history/unaffected_strict_ancestor_retains_ordinary_record", self.catalog_with([record], context,
                 [("checkpoint", cp)]), self.base_facts.clone().path(context).grant(record), now=shift(NOW, 60))
        for mask, kind, code in ((1, "host-bind-v1", "forbidden"), (2, "host-bind-v1", None),
                                 (2, "host-admit-v1", "forbidden"), (8, "person-admit-v1", None)):
            context = self.narrowed(mask, "ordinary-scope-" + str(mask))
            record = self.record(kind, context)
            self.add(f"scope/{mask}/" + kind, self.catalog_with([record], context),
                     self.base_facts.clone().path(context).grant(record), code=code)

    def withdrawals(self):
        for kind in ("host-admit-v1", "person-admit-v1"):
            for label, context in (("root", self.root_context), ("device", self.b)):
                record = self.record(kind, context)
                record_id = semantic_id("person_record", record)
                catalog = self.catalog_with([record], context)
                for version, kept, retained in ((1, [], False), (1, [digest(message("person_record", record))], False),
                                                 (2, [], False), (2, ["record:ar_" + "0" * 64], False),
                                                 (2, ["record:" + record_id], True)):
                    if retained and context["path"]:
                        kept = [*kept, "record:" + semantic_id("person_record", self.record_b)]
                    removal = self.removal(self.person, kept, version=version)
                    facts = self.base_facts.clone()
                    facts.persons[self.person]["administrator"] = False
                    if retained:
                        facts.path(context).grant(record)
                    else:
                        facts.grant(record, admitted=False)
                    self.add(f"withdrawal/{label}/{kind}/v{version}/{len(kept)}/{retained}",
                             self.with_proofs(catalog, [("admin_removal", removal)]), facts)
                removed = self.removal(self.person)
                malformed = dict(record, signature=self.signers[self.quinn].sshsig(message("person_record", record)))
                self.add(f"withdrawal/{label}/{kind}/bad_excluded_signature", self.catalog_with([malformed], context,
                         [("admin_removal", removed)]), code="invalid")
                if context["path"]:
                    pending = self.context(self.with_proofs(self.base["catalog"], [("certificate", self.cert_b)]), [self.cert_b])
                    false_facts = self.base_facts.clone().grant(record, admitted=False)
                    false_facts.persons[self.person]["administrator"] = False
                    self.add("withdrawal/excluded_grant_needs_no_issuer_activation/" + kind,
                             self.catalog_with([record], pending, [("admin_removal", removed)]), false_facts)
        record = self.record("host-bind-v1")
        facts = self.base_facts.clone().grant(record)
        facts.persons[self.person]["administrator"] = False
        self.add("withdrawal/original_person_binding_does_not_require_admin", self.catalog_with([record], extra=
                 [("admin_removal", self.removal(self.person))]), facts)
        record = self.record("host-admit-v1", self.b)
        record_id = semantic_id("person_record", record)
        kept = self.removal(self.person, ["record:" + record_id, "record:" + semantic_id("person_record", self.record_b)])
        catalog = self.catalog_with([record], self.b, [("admin_removal", kept)])
        self.add("withdrawal/root_kept_list_cannot_replace_person_checkpoint", catalog,
                 code="proof_required", required=[record_id], now=LATE)
        facts = self.base_facts.clone().path(self.b).grant(record)
        facts.persons[self.person]["administrator"] = False
        self.add("withdrawal/both_retention_dimensions", self.with_proofs(catalog,
                 [("checkpoint", self.checkpoint([record_id]))]), facts, now=LATE)
        independent = self.signed_legacy("host_admission", {"epoch": 0, "host_public_key": self.target_host,
                   "member": "independent-root-label", "admitted_at": NOW})
        excluded = self.with_proofs(self.catalog_with([record], self.b),
                    [("admin_removal", self.removal(self.person)), ("host_admission", independent)])
        facts = self.base_facts.clone().host(self.target_host, "independent-root-label")
        facts.persons[self.person]["administrator"] = False
        self.add("withdrawal/independent_admission_wins_over_excluded_label", excluded, facts)

    def conflicts_and_restrictions(self):
        host = self.record("host-admit-v1")
        person = self.record("person-admit-v1")
        binding = self.record("host-bind-v1")
        for kind, original, field in (("host", host, "member"), ("person", person, "member")):
            conflicting = self.record(original["kind"][len("peerspan-"):], unsigned=dict(payload(original), **{field: "different"}))
            self.add("conflict/usable_" + kind + "_labels", self.catalog_with([original, conflicting]), code="state_conflict")
        p_admit = self.record("person-admit-v1")
        other_binding = self.record("host-bind-v1", self.root_person(self.new_person),
                                    dict(payload(binding), person_public_key=self.new_person))
        self.add("conflict/two_usable_person_bindings", self.catalog_with([binding, other_binding, p_admit]), code="state_conflict")
        catalog = self.catalog_with([host, person, binding])
        facts = self.base_facts.clone().grant(host).grant(person).grant(binding)
        alias = proof("person_record", raw=json.dumps(host, indent=2).encode())
        aliased = copy.deepcopy(catalog)
        aliased["objects"].append(alias)
        sort_catalog(aliased)
        self.add("identity/semantic_alias_keeps_exact_transport_id", aliased, facts)
        duplicate = self.record("host-admit-v1", unsigned=dict(payload(host), admitted_at=shift(NOW, 1)))
        self.add("identity/equal_label_is_idempotent", self.catalog_with([host, duplicate]), self.base_facts.clone().grant(host))
        for kind, obj, modified in (
                ("host_revocation", self.signed_legacy("host_revocation", {"host_public_key": self.target_host, "revoked_at": NOW}),
                 self.base_facts.clone().grant(host).host(self.target_host, "new-member", admitted=False)),
                ("host_leave", self.signed_legacy("host_leave", {"host_public_key": self.target_host, "left_at": NOW}, self.target_host),
                 self.base_facts.clone().grant(host).host(self.target_host, "new-member", admitted=False)),
                ("person_removal", self.signed_legacy("person_removal", {"person_public_key": self.new_person, "removed_at": NOW}),
                 self.base_facts.clone().grant(person).person(self.new_person, "new-member", admitted=False))):
            record = person if kind == "person_removal" else host
            self.add("restriction/sticky_" + kind, self.catalog_with([record], extra=[(kind, obj)]), modified)
        unbinding = self.signed_legacy("host_unbinding", {"person_public_key": self.person,
                   "host_public_key": self.target_host, "unbound_at": NOW}, self.person, ssh=True)
        self.add("restriction/sticky_unbinding", self.catalog_with([binding], extra=[("host_unbinding", unbinding)]),
                 self.base_facts.clone().bind(self.target_host, "-"))
        record = self.record("host-bind-v1", self.b)
        revoked = self.revocation(self.cert_b)
        catalog = self.catalog_with([record], self.b)
        first = proof("person_record", record)["id"]
        for spaces in range(4096):
            later_revocation = proof("device_revocation", raw=b" " * spaces + wire(revoked))
            if later_revocation["id"] > first:
                break
        else:
            raise AssertionError("could not order public revocation alias after ordinary record")
        catalog["objects"].append(later_revocation)
        sort_catalog(catalog)
        self.add("restriction/later_known_revocation_revalidates_ordinary_grant", catalog,
                 code="proof_required", required=[semantic_id("person_record", record)])

    def consumers_and_renewal(self):
        # A new person's independently authorized admission is consumed by the
        # current action gate; the admission itself supplies no administrator role.
        admission = self.record("person-admit-v1")
        context = self.root_person(self.new_person, self.catalog_with([admission]))
        binding = self.record("host-bind-v1", context, dict(self.payloads["host-bind-v1"], person_public_key=self.new_person))
        self.add_request("consumer/action_uses_ordinary_person_admission", ActionAuthor.request(self, binding, context),
                         ActionAuthor.success(self, binding, context))
        admin = self.record("host-admit-v1", context)
        self.add_request("consumer/ordinary_admission_is_not_admin", ActionAuthor.request(self, admin, context), error("forbidden"))
        self.add_request("consumer/action_still_requires_durable_feature", ActionAuthor.request(self, binding, context,
                         known_feature_id="-"), error("upgrade_required"))
        host = self.record("host-admit-v1")
        feature = next(json.loads(unb64(entry["body_base64"])) for entry in self.base["catalog"]["objects"] if entry["kind"] == "feature")
        proposal = dict(feature["proposal"], host_public_keys=sorted([*feature["proposal"]["host_public_keys"], self.target_host]))
        proposal["signature"] = b64(self.signers[self.root].raw(message("feature_proposal", proposal)))
        feature_id = semantic_id("feature_proposal", proposal)
        acks = []
        for key in proposal["host_public_keys"]:
            ack = {"format": 1, "feature_id": feature_id, "host_public_key": key}
            self.oracle.resign("feature_ack", ack, key)
            acks.append(ack)
        complete = {"proposal": proposal, "acknowledgments": acks}
        first_catalog = self.without(self.base["catalog"], lambda kind, obj: kind == "feature")
        first_catalog = self.with_proofs(first_catalog, [("person_record", host)])
        request = {"kind": "feature_activation", "network_base64": b64(wire(self.data["network"])),
                   "catalog_base64": b64(wire(first_catalog)), "feature_base64": b64(wire(complete)),
                   "epoch": 0, "known_feature_id": "-", "now": NOW}
        self.add_request("consumer/first_feature_still_refuses_ordinary_linking_envelope", request, error("forbidden"))
        fixture = self.fixtures["same_key_root_renewal"]
        target = payload(fixture["activation"]["request"])["host_public_key"]
        ordinary_binding = self.record("host-bind-v1", unsigned=dict(self.payloads["host-bind-v1"], host_public_key=target))
        ordinary_admission = self.record("host-admit-v1", unsigned=dict(self.payloads["host-admit-v1"], host_public_key=target, member="alice"))
        catalog = self.catalog_with([ordinary_binding, ordinary_admission], self.context(fixture["catalog"]))
        transcript = Transcript(self, fixture)
        transcript.values["owner"].update(binding_proof_id=proof("person_record", ordinary_binding)["id"],
                                          membership_proof_id=proof("person_record", ordinary_admission)["id"])
        activation = transcript.finish()
        expected = ActivationAuthor.success(self, activation)
        self.add_request("renewal/exact_ordinary_binding_and_admission", ActivationAuthor.request(self, fixture, activation, catalog), expected)
        missing_id = proof("person_record", ordinary_binding)["id"]
        missing = copy.deepcopy(catalog)
        missing["objects"] = [entry for entry in missing["objects"] if entry["id"] != missing_id]
        self.add_request("renewal/another_binding_cannot_replace_exact_reference", ActivationAuthor.request(self, fixture, activation, missing),
                         error("proof_required", [missing_id]))
        unkept = self.record("host-admit-v1", self.root_person(self.quinn), payload(ordinary_admission))
        selected = Transcript(self, fixture)
        selected.values["owner"].update(binding_proof_id=proof("person_record", ordinary_binding)["id"],
                                        membership_proof_id=proof("person_record", unkept)["id"])
        excluded = self.catalog_with([ordinary_binding, unkept], self.context(fixture["catalog"]),
                                    [("admin_removal", self.removal(self.quinn))])
        self.add_request("renewal/independent_current_fact_cannot_authorize_excluded_selected_proof",
                         ActivationAuthor.request(self, fixture, selected.finish(), excluded), error("forbidden"))
        # Historical resolution of this same B activation as a join proof may
        # not satisfy the separate first-finalization preconditions.
        new_fixture = self.base
        ordinary_b = self.record("host-admit-v1", unsigned=dict(self.payloads["host-admit-v1"], host_public_key=target, member="alice"))
        first = self.with_proofs(self.base["catalog"], [("person_record", ordinary_b), ("activation", self.base["activation"])])
        self.add_request("consumer/historical_join_resolution_does_not_skip_first_conflict",
                         ActivationAuthor.request(self, new_fixture, catalog=first), error("state_conflict"))

    def strict_inputs(self):
        record = self.record("host-bind-v1")
        catalog = self.catalog_with([record])
        for kind in KINDS:
            original = self.record(kind)
            for label, edits in (("wrong_network", {"network_id": "net_" + "0" * 64}), ("wrong_epoch", {"epoch": 1})):
                changed = dict(original, **edits)
                self.oracle.resign("person_record", changed, self.person)
                self.add("strict/" + kind + "/" + label, self.catalog_with([changed]),
                         code="proof_required" if label == "wrong_epoch" and kind == "host-bind-v1" else "invalid")
            unknown = self.record(kind, unsigned=dict(payload(original), unknown=True))
            self.add("strict/" + kind + "/unknown_payload", self.catalog_with([unknown]), code="invalid")
            forged = dict(original, signature=self.signers[self.quinn].sshsig(message("person_record", original)))
            self.add("strict/" + kind + "/forged_signature", self.catalog_with([forged]), code="invalid")
        self.add("strict/binding_requires_exact_host_consent", self.catalog_with([dict(record, host_signature=b64(b"\0" * 64))]), code="invalid")
        for kind in self.payloads:
            if kind not in (*KINDS, "host-unbind-v1", "person-remove-v1", "revoke-host-v1", "revoke-invite-v1",
                            "policy-v1", "policy-v2", "group-v1"):
                self.add("unsupported/ordinary_" + kind, self.catalog_with([self.record(kind)]), code="upgrade_required")
        self.add("gate/conflicting_known_feature", known_feature_id="lf_" + "0" * 64, code="state_conflict")
        good = self.request(catalog)
        expected = self.base_facts.clone().grant(record).reply()
        for field in good:
            if field == "kind":
                continue
            missing = dict(good)
            del missing[field]
            self.add_request("outer/missing_" + field, missing, error("invalid"))
            for label, value in (("null", None), ("wrong_type", [])):
                self.add_request("outer/" + label + "_" + field, dict(good, **{field: value}), error("invalid"))
        self.add_request("outer/unknown_field", dict(good, extra=1), error("invalid"))
        self.add_request("outer/nonzero_epoch", dict(good, epoch=1), error("proof_required"))
        for field in ("network_base64", "catalog_base64"):
            raw = unb64(good[field])
            for label, value in (("bad_alphabet", "!"), ("extra_padding", good[field] + "="), ("whitespace", good[field] + "\n")):
                self.add_request("encoding/" + field + "/" + label, dict(good, **{field: value}), error("invalid"))
            for label, value in (("duplicate", raw[:-1] + b',"' + next(iter(json.loads(raw))).encode() + b'":null}'),
                                 ("unknown", raw[:-1] + b',"extra":0}'), ("null", b"null"), ("not_object", b"[]"),
                                 ("invalid_utf8", b'{"bad":"\xff"}'), ("trailing", raw + b"{}"),
                                 ("deep", b"[" * 65 + b"0" + b"]" * 65)):
                self.add_request("json/" + field + "/" + label, dict(good, **{field: b64(value)}), error("invalid"))
        for label, mutation in (("unsorted", lambda c: c["objects"].reverse()),
                                ("duplicate", lambda c: c["objects"].append(copy.deepcopy(c["objects"][0]))),
                                ("wrong_hash", lambda c: c["objects"][0].update(id="pf_" + "0" * 64))):
            malformed = copy.deepcopy(catalog)
            mutation(malformed)
            if label != "unsorted":
                sort_catalog(malformed)
            self.add("catalog/" + label, malformed, code="invalid")
        total = sum(len(unb64(good[field])) for field in ("network_base64", "catalog_base64"))
        padded = dict(good, network_base64=b64(unb64(good["network_base64"]) + b" " * (LIMIT - total)))
        self.add_request("limit/exact_512k", padded, expected)
        self.add_request("limit/over_512k", dict(padded, network_base64=b64(unb64(padded["network_base64"]) + b" ")), error("invalid"))
        for label, raw in (("duplicate_kind", wire(good)[:-1] + b',"kind":"catalog_facts"}'),
                           ("trailing", wire(good) + b"{}"), ("invalid_utf8", b'{"kind":"\xff"}'),
                           ("over_2mib", b" " * (2 * 1024 * 1024 + 1))):
            self.add_request("framing/" + label, raw, error("invalid"))
        self.add_request("framing/recovery", good, expected, keep=True)

    def build(self):
        self.projection_and_grants()
        self.dependencies()
        self.history()
        self.withdrawals()
        self.conflicts_and_restrictions()
        self.consumers_and_renewal()
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
    print(f"Independent oracle: {fixed} published signatures reproduced; {len(cases)} record checks "
          f"({eligible} accepted, {len(cases) - eligible} rejected).", flush=True)
    if not probes:
        print("Self-check only; no catalog implementation or live protocol was tested.")
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
        print(f"{label}: {checked} record checks completed.", flush=True)
    if failures:
        print(f"FAILED: {failures} record conformance failures.", file=sys.stderr)
        return 1
    print("PASS: bounded historical catalog facts and their consumers only; no mutation, persistence, "
          "freshness, complete-v1 catalog support or writer-readiness claim.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
