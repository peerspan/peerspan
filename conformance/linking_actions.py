#!/usr/bin/env python3
"""Independent current signing-authority checks for ordinary management actions.

Uses the accepted contracts, public fixtures and separately authored standard
library signers only. Authorization does not apply a fact, persist state, prove
freshness, grant policy access, or satisfy a writer's transaction preconditions.
"""

import argparse
import copy
import json
from pathlib import Path
import sys

from linking_activations import LIMIT, Transcript, payload, proof, semantic_id, shift, sort_catalog
from linking_history import Author as HistoryAuthor, legacy_message
from linking_paths import error
from linking_readers import Probe, b64, digest, lines, message, unb64, wire


ROOT = Path(__file__).resolve().parents[1]
NOW = "2026-10-23T12:02:00Z"
DAY = 86400
SCOPES = {"policy-v1": 1, "policy-v2": 1, "host-bind-v1": 2, "host-unbind-v1": 2,
          **{kind: 8 for kind in ("host-admit-v1", "person-admit-v1", "person-remove-v1",
                                 "revoke-host-v1", "revoke-invite-v1", "invite-v1",
                                 "person-invite-v1", "group-v1")}}


class Author(HistoryAuthor):
    def __init__(self, vectors):
        super().__init__(vectors)
        self.root_context = self.context(self.base["catalog"])
        self.b = self.active_context(self.base, [self.cert_b])
        self.c = self.active_context(self.c_source, [self.cert_b, self.cert_c])
        self.target_host = self.key("action-target-host")
        self.target_invite = self.key("action-target-invite")
        rule = {"agent": "reviewer", "principals": ["network"], "actions": ["message.append"],
                "max_message_bytes": 65536, "allow_disconnected": False}
        policy = {"network_id": self.network, "person_public_key": self.person, "version": 1,
                  "issued_at": NOW, "valid_until": shift(NOW, DAY), "rules": [rule]}
        host_id = "host_" + digest(unb64(self.target_host))
        self.payloads = {
            "policy-v1": policy,
            "policy-v2": dict(policy, format=2, capability_rules=[{"host": host_id, "capability": "docs",
                "principals": ["network"], "max_input_bytes": 65536, "allow_disconnected": False,
                "max_calls_per_hour": 100}], trusted_hosts=[host_id], edits=[{"host": host_id, "seq": 1}]),
            "host-bind-v1": {"network_id": self.network, "person_public_key": self.person,
                             "host_public_key": self.target_host, "bound_at": NOW},
            "host-unbind-v1": {"network_id": self.network, "person_public_key": self.person,
                               "host_public_key": self.target_host, "unbound_at": NOW},
            "host-admit-v1": {"network_id": self.network, "epoch": 0, "host_public_key": self.target_host,
                              "member": "new-member", "admitted_at": NOW},
            "person-admit-v1": {"network_id": self.network, "epoch": 0, "person_public_key": self.quinn,
                                "member": "new-member", "admitted_at": NOW},
            "person-remove-v1": {"network_id": self.network, "person_public_key": self.quinn, "removed_at": NOW},
            "revoke-host-v1": {"network_id": self.network, "host_public_key": self.target_host, "revoked_at": NOW},
            "revoke-invite-v1": {"network_id": self.network, "invite_public_key": self.target_invite, "revoked_at": NOW},
            "invite-v1": {"network_id": self.network, "invite_public_key": self.target_invite,
                          "member": "new-member", "invite_expires_at": shift(NOW, DAY)},
            "person-invite-v1": {"network_id": self.network, "invite_epoch": 0,
                                 "invite_public_key": self.target_invite, "member": "new-member",
                                 "invite_expires_at": shift(NOW, DAY)},
            "group-v1": {"network_id": self.network, "name": "team", "version": 1, "defined_at": NOW,
                         "members": ["person_" + digest(unb64(self.quinn))]},
        }

    def context(self, catalog, path=(), now=NOW, person=None):
        return {"catalog": copy.deepcopy(catalog), "path": copy.deepcopy(list(path)),
                "now": now, "person": person or self.person}

    def active_context(self, fixture, path):
        catalog = self.with_proofs(fixture["catalog"], [("activation", fixture["activation"]),
                                  ("certificate", path[-1])])
        return self.context(catalog, path)

    @staticmethod
    def certificate_id(context):
        return semantic_id("certificate", context["path"][-1]) if context["path"] else "root"

    def signer(self, context):
        return context["path"][-1]["device_public_key"] if context["path"] else context["person"]

    @staticmethod
    def without(catalog, predicate):
        result = copy.deepcopy(catalog)
        result["objects"] = [entry for entry in result["objects"]
                             if not predicate(entry["kind"], json.loads(unb64(entry["body_base64"])))]
        return result

    def record(self, suffix, context=None, unsigned=None, **changes):
        context = context or self.root_context
        obj = {"format": 1, "kind": "peerspan-" + suffix, "network_id": self.network, "epoch": 0,
               "operation_id": "-", "person_public_key": context["person"],
               "certificate_id": self.certificate_id(context),
               "payload_base64": b64(wire(self.payloads[suffix] if unsigned is None else unsigned)),
               "host_signature": "-"}
        obj.update(changes)
        self.oracle.resign("person_record", obj, self.signer(context))
        return obj

    def revocation(self, target, context=None, **changes):
        context = context or self.root_context
        obj = {"format": 1, "network_id": self.network, "person_public_key": context["person"],
               "target_device_public_key": target["device_public_key"],
               "target_certificate_id": semantic_id("certificate", target),
               "issuer_certificate_id": self.certificate_id(context), "revoked_at": NOW}
        obj.update(changes)
        self.oracle.resign("device_revocation", obj, self.signer(context))
        return obj

    def request(self, action, context=None, action_kind=None, **pins):
        context = context or self.root_context
        result = {"kind": "action_authorization", "action_kind": action_kind or
                  ("person_record" if "operation_id" in action else "device_revocation"),
                  "network_base64": b64(wire(self.data["network"])),
                  "catalog_base64": b64(wire(context["catalog"])), "action_base64": b64(wire(action)),
                  "epoch": 0, "known_feature_id": self.data["feature_id"],
                  "person_public_key": context["person"], "certificate_id": self.certificate_id(context),
                  "now": context["now"]}
        result.update(pins)
        return result

    def success(self, action, context, kind=None):
        kind = kind or ("person_record" if "operation_id" in action else "device_revocation")
        required = SCOPES[action["kind"][len("peerspan-"):]] if kind == "person_record" else 4
        return {"ok": True, "action_kind": kind, "record_id": semantic_id(kind, action),
                "network_id": self.network, "feature_id": self.data["feature_id"],
                "person_public_key": context["person"], "certificate_id": self.certificate_id(context),
                "required_scope": required,
                "not_after": context["path"][-1]["not_after"] if context["path"] else "-"}

    def add(self, name, action, context=None, code=None, required=(), affected=False, **pins):
        context = context or self.root_context
        expected = ({"ok": False, "code": "authority_would_be_invalidated", "certificate_ids":
                     [semantic_id("certificate", cert) for cert in context["path"]]} if affected
                    else error(code, required) if code else self.success(action, context, pins.get("action_kind")))
        self.add_request(name, self.request(action, context, **pins), expected)

    def narrowed(self, mask, label=None, expires=None):
        fixture = self.new_root_link(label or "action-scope-" + str(mask), created="2026-10-23T12:00:00Z")
        transcript = Transcript(self, fixture)
        cert = transcript.values["owner"]["certificate"]
        cert["scopes"] = mask
        if expires is not None:
            cert["not_after"] = expires
        transcript.sign_certificate()
        fixture["activation"] = transcript.finish()
        return self.active_context(fixture, [cert])

    def registry_and_scopes(self):
        assert len(SCOPES) == 12 and set(SCOPES) == set(self.payloads)
        for kind in SCOPES:
            for label, context in (("root", self.root_context), ("b", self.b), ("c", self.c)):
                self.add("registry/" + label + "/" + kind, self.record(kind, context), context)
        nonadmin_fixture = self.fixtures["nonadmin_owner_with_independent_admin"]
        nonadmin_cert = payload(nonadmin_fixture["activation"]["owner"])["certificate"]
        for label, context in (("root", self.context(nonadmin_fixture["catalog"])),
                               ("device", self.active_context(nonadmin_fixture, [nonadmin_cert]))):
            for kind, scope in SCOPES.items():
                self.add("nonadmin/" + label + "/" + kind, self.record(kind, context), context,
                         code="forbidden" if scope == 8 else None)
        for mask in (1, 2, 4, 8):
            context = self.narrowed(mask)
            for kind in ("policy-v1", "host-bind-v1", "host-admit-v1"):
                self.add(f"scope/leaf_{mask}/" + kind, self.record(kind, context), context,
                         code=None if mask & SCOPES[kind] else "forbidden")
            target = copy.deepcopy(self.cert_c)
            target.update(parent_id=self.certificate_id(context), issued_at=NOW,
                          device_public_key=self.key(f"scope-target-{mask}/device"),
                          host_public_key=self.key(f"scope-target-{mask}/host"), scopes=mask)
            self.oracle.resign("certificate", target, self.signer(context))
            target_context = copy.deepcopy(context)
            target_context["catalog"] = self.with_proofs(context["catalog"], [("certificate", target)])
            self.add(f"scope/leaf_{mask}/device_revocation", self.revocation(target, context), target_context,
                     code=None if mask & 4 else "forbidden")

    def policies_and_invites(self):
        cap = self.cert_b["not_after"]
        for kind in ("policy-v1", "policy-v2"):
            for label, expiry, code in (("equal_path_cap", cap, None),
                                         ("beyond_path_cap", shift(cap, 1), "forbidden")):
                unsigned = dict(self.payloads[kind], issued_at=shift(cap, -DAY), valid_until=expiry)
                self.add("policy/" + kind + "/" + label, self.record(kind, self.b, unsigned), self.b, code=code)
                if code:
                    self.add("policy/" + kind + "/root_has_no_device_cap", self.record(kind, unsigned=unsigned))
            for label, seconds in (("shorter_than_day", DAY - 1), ("longer_than_90_days", 90 * DAY + 1)):
                unsigned = dict(self.payloads[kind], valid_until=shift(NOW, seconds))
                self.add("policy/" + kind + "/" + label, self.record(kind, unsigned=unsigned), code="invalid")
            historical = dict(self.payloads[kind], issued_at="2020-01-01T00:00:00Z", valid_until="2020-01-02T00:00:00Z")
            self.add("policy/" + kind + "/current_access_window_is_not_authority", self.record(kind, self.b, historical), self.b)
            malformed = dict(self.payloads[kind], rules=[dict(self.payloads[kind]["rules"][0], unknown=True)])
            self.add("policy/" + kind + "/strict_nested_rule", self.record(kind, unsigned=malformed), code="invalid")
        near_expiry = copy.deepcopy(self.b)
        near_expiry["now"] = shift(cap, -100)
        root_near = self.context(self.base["catalog"], now=near_expiry["now"])
        for kind in ("invite-v1", "person-invite-v1"):
            for label, seconds, code in (("past", -1, "expired"), ("exclusive_now", 0, "expired"),
                                         ("first_future_second", 1, None), ("inclusive_30_days", 30 * DAY, None),
                                         ("over_30_days", 30 * DAY + 1, "invalid")):
                unsigned = dict(self.payloads[kind], invite_expires_at=shift(NOW, seconds))
                for signer, context in (("root", self.root_context), ("device", self.b)):
                    self.add(f"invite/{kind}/{signer}/{label}", self.record(kind, context, unsigned), context, code=code)
            for label, expiry, code in (("equal_path_cap", cap, None), ("beyond_path_cap", shift(cap, 1), "forbidden")):
                unsigned = dict(self.payloads[kind], invite_expires_at=expiry)
                self.add("invite/" + kind + "/" + label, self.record(kind, near_expiry, unsigned), near_expiry, code=code)
                if code:
                    self.add("invite/" + kind + "/root_has_no_device_cap", self.record(kind, root_near, unsigned), root_near)

    def current_authority(self):
        action = self.record("host-unbind-v1", self.b)
        missing_cert = self.context(self.base["catalog"], [self.cert_b])
        self.add("authority/missing_exact_certificate", action, missing_cert, code="proof_required",
                 required=[self.certificate_id(self.b)])
        pending = self.context(self.with_proofs(self.base["catalog"], [("certificate", self.cert_b)]), [self.cert_b])
        self.add("authority/pending_certificate", action, pending, code="proof_required", required=[self.cert_b["request_id"]])
        binding = self.record("host-bind-v1", pending, dict(self.payloads["host-bind-v1"], host_public_key=self.cert_b["host_public_key"]))
        self.add("authority/candidate_cannot_bind_or_activate_its_signer", binding, pending,
                 code="proof_required", required=[self.cert_b["request_id"]])
        for label, now, code in (("at_issuance", self.cert_b["issued_at"], None),
                                 ("last_live_second", shift(self.cert_b["not_after"], -1), None),
                                 ("exclusive_expiry", self.cert_b["not_after"], "authority_expired")):
            context = copy.deepcopy(self.b)
            context["now"] = now
            self.add("authority/" + label, action, context, code=code)
        expired = copy.deepcopy(self.b)
        expired["now"] = self.cert_b["not_after"]
        expired["catalog"] = self.with_proofs(expired["catalog"], [("checkpoint", self.checkpoint([], issued_at=expired["now"]))])
        self.add("authority/checkpoint_does_not_revive_current_path", action, expired, code="authority_expired")
        renewal = self.fixtures["same_key_renewal_after_old_expiry"]
        alternative = self.context(self.with_proofs(renewal["catalog"], [("activation", renewal["activation"])]),
                                   [self.cert_b], now=renewal["evaluation_time"])
        self.add("authority/same_key_live_certificate_does_not_replace_exact_old_selection", action, alternative,
                 code="authority_expired")
        renewed_cert = payload(renewal["activation"]["owner"])["certificate"]
        selected_new = self.context(alternative["catalog"], [renewed_cert], now=renewal["evaluation_time"])
        self.add("authority/explicit_live_replacement_selection", self.record("host-unbind-v1", selected_new), selected_new)
        for kind, fields, signer, ssh, code in (
                ("host_revocation", {"host_public_key": self.cert_b["host_public_key"], "revoked_at": NOW}, None, False, "forbidden"),
                ("host_unbinding", {"person_public_key": self.person, "host_public_key": self.cert_b["host_public_key"],
                                    "unbound_at": NOW}, self.person, True, "forbidden"),
                ("person_removal", {"person_public_key": self.person, "removed_at": NOW}, None, False, "forbidden")):
            context = copy.deepcopy(self.b)
            restriction = self.signed_legacy(kind, fields, signer, ssh)
            context["catalog"] = self.with_proofs(context["catalog"], [(kind, restriction)])
            self.add("authority/known_" + kind, action, context, code=code)
        revoked = copy.deepcopy(self.b)
        revoked["catalog"] = self.with_proofs(revoked["catalog"], [("device_revocation", self.revocation(self.cert_b))])
        self.add("authority/known_sticky_device_revocation", action, revoked, code="device_revoked")
        # Exact endorsements preserve C's durable admission and binding while
        # providing no present authority to the expired/revoked/unbound B path.
        retained = self.checkpoint(self.ids_c.values(), issued_at=self.cert_b["not_after"])
        c_action = self.record("host-unbind-v1", self.c)
        for label, now, restrictions, code in (
                ("expired_parent", self.cert_b["not_after"], [], "authority_expired"),
                ("revoked_parent", NOW, [("device_revocation", self.revocation(self.cert_b))], "device_revoked"),
                ("unbound_parent", NOW, [("host_unbinding", self.signed_legacy("host_unbinding",
                    {"person_public_key": self.person, "host_public_key": self.cert_b["host_public_key"],
                     "unbound_at": NOW}, self.person, ssh=True))], "forbidden")):
            context = copy.deepcopy(self.c)
            context["now"] = now
            context["catalog"] = self.with_proofs(context["catalog"], [("checkpoint", retained), *restrictions])
            self.add("authority/retained_history_does_not_revive_" + label, c_action, context, code=code)
        withdrawn = copy.deepcopy(self.b)
        kept = self.removal(self.person, ["record:" + semantic_id("person_record", self.record_b)])
        withdrawn["catalog"] = self.with_proofs(withdrawn["catalog"], [("admin_removal", kept)])
        for kind, code in (("host-unbind-v1", None), ("host-admit-v1", "forbidden")):
            self.add("authority/root_kept_history_is_not_current_admin/" + kind,
                     self.record(kind, withdrawn), withdrawn, code=code)
        absent = self.without(self.base["catalog"], lambda kind, obj: kind == "person_admission"
                              and obj["person_public_key"] == self.person)
        self.add("authority/root_needs_current_person_admission", self.record("host-unbind-v1"),
                 self.context(absent), code="proof_required")

    def revocations_and_self_guard(self):
        for label, context, target in (("root_pending_c", self.root_context, self.cert_c),
                                        ("live_b_pending_c", self.b, self.cert_c),
                                        ("root_active_b", self.root_context, self.cert_b)):
            resolved = copy.deepcopy(context)
            proofs = [("certificate", target)]
            if target["parent_id"] == semantic_id("certificate", self.cert_b):
                # The target remains pending; its parent public proof is needed
                # to authenticate the target's certificate signature only.
                proofs.append(("certificate", self.cert_b))
            resolved["catalog"] = self.with_proofs(context["catalog"], proofs)
            self.add("revocation/" + label, self.revocation(target, context), resolved)
        expired_target = copy.deepcopy(self.cert_b)
        expired_target.update(issued_at=shift(NOW, -DAY - 1), not_after=shift(NOW, -1))
        self.oracle.resign("certificate", expired_target, self.person)
        context = self.context(self.with_proofs(self.base["catalog"], [("certificate", expired_target)]))
        self.add("revocation/root_pending_expired_target", self.revocation(expired_target), context)
        self.add("revocation/missing_exact_target", self.revocation(self.cert_c), code="proof_required",
                 required=[semantic_id("certificate", self.cert_c)])
        for label, fields, signer in (("wrong_person", {"person_public_key": self.quinn}, self.quinn),
                                      ("wrong_network", {"network_id": "net_" + "0" * 64}, self.person),
                                      ("bad_signature", {}, self.quinn)):
            target = dict(self.cert_b, **fields)
            self.oracle.resign("certificate", target, signer)
            context = self.context(self.with_proofs(self.base["catalog"], [("certificate", target)]))
            self.add("revocation/target_" + label, self.revocation(target), context, code="invalid")
        mismatched = self.revocation(self.cert_b, target_device_public_key=self.cert_c["device_public_key"])
        self.add("revocation/target_key_mismatch", mismatched, self.root_context,
                 code="proof_required", required=[semantic_id("certificate", self.cert_b)])
        context = self.context(self.with_proofs(self.base["catalog"], [("certificate", self.cert_b)]))
        self.add("revocation/target_key_mismatch_with_proof", mismatched, context, code="invalid")
        sibling = dict(self.cert_c, device_public_key=self.key("sibling/device"), host_public_key=self.key("sibling/host"))
        self.oracle.resign("certificate", sibling, self.cert_b["device_public_key"])
        unrelated = dict(sibling, parent_id="root")
        self.oracle.resign("certificate", unrelated, self.person)
        for label, target in (("sibling", sibling), ("unrelated", unrelated)):
            context = copy.deepcopy(self.c)
            context["catalog"] = self.with_proofs(context["catalog"], [("certificate", target)])
            self.add("revocation/" + label, self.revocation(target, self.c), context, code="forbidden")
        for label, context in (("b", self.b), ("c", self.c)):
            for index, cert in enumerate(context["path"]):
                for kind, unsigned in (
                        ("host-unbind-v1", dict(self.payloads["host-unbind-v1"], host_public_key=cert["host_public_key"])),
                        ("revoke-host-v1", dict(self.payloads["revoke-host-v1"], host_public_key=cert["host_public_key"]))):
                    action = self.record(kind, context, unsigned)
                    self.add(f"self/{label}/path_{index}/" + kind, action, context, affected=True)
                    self.add(f"self/root_alternative/{label}/path_{index}/" + kind, self.record(kind, unsigned=unsigned))
                self.add(f"self/{label}/path_{index}/device_revocation", self.revocation(cert, context), context, affected=True)
                alias = dict(cert, request_id="link_" + digest((label + "/alias/" + str(index)).encode()))
                issuer = self.person if index == 0 else context["path"][index - 1]["device_public_key"]
                self.oracle.resign("certificate", alias, issuer)
                aliased = copy.deepcopy(context)
                aliased["catalog"] = self.with_proofs(context["catalog"], [("certificate", alias)])
                self.add(f"self/{label}/path_{index}/same_key_alias", self.revocation(alias, context), aliased, affected=True)
            unsigned = dict(self.payloads["person-remove-v1"], person_public_key=self.person)
            self.add("self/" + label + "/person_remove", self.record("person-remove-v1", context, unsigned), context, affected=True)
        self.add("self/root_alternative/person_remove", self.record("person-remove-v1",
                 unsigned=dict(self.payloads["person-remove-v1"], person_public_key=self.person)))

    def signed_boundaries(self):
        for context_name, context in (("root", self.root_context), ("b", self.b)):
            for kind in SCOPES:
                unsigned = dict(self.payloads[kind], unknown=True)
                self.add("registry/strict_unknown/" + context_name + "/" + kind,
                         self.record(kind, context, unsigned), context, code="invalid")
        for kind in ("policy-v1", "policy-v2", "host-bind-v1", "host-unbind-v1"):
            unsigned = dict(self.payloads[kind], person_public_key=self.quinn)
            self.add("identity/owner_subject_must_match/" + kind, self.record(kind, self.b, unsigned), self.b, code="invalid")
        for field, value in (("operation_id", self.cert_b["request_id"]), ("network_id", "net_" + "0" * 64),
                              ("epoch", 1), ("person_public_key", self.quinn), ("certificate_id", "root")):
            action = self.record("host-unbind-v1", self.b, **{field: value})
            self.add("context/signed_envelope_" + field, action, self.b, code="invalid")
        for kind, field, value in (("host-admit-v1", "epoch", 1), ("person-invite-v1", "invite_epoch", 1),
                                   ("host-unbind-v1", "network_id", "net_" + "0" * 64)):
            self.add("context/signed_payload_" + field, self.record(kind, self.b,
                     dict(self.payloads[kind], **{field: value})), self.b, code="invalid")
        for kind in ("host-bind-v1", "host-unbind-v1"):
            action = self.record(kind, self.b)
            for label, mutate in (("bad_signature", lambda a: a.update(signature=self.signers[self.person].sshsig(message("person_record", a)))),
                                   ("raw_signature", lambda a: a.update(signature=b64(self.signers[self.signer(self.b)].raw(message("person_record", a))))),
                                   ("legacy_domain", lambda a: a.update(signature=self.signers[self.signer(self.b)].sshsig(
                                       legacy_message("host_unbinding", self.payloads["host-unbind-v1"]))))):
                bad = copy.deepcopy(action)
                mutate(bad)
                self.add("signature/" + kind + "/" + label, bad, self.b, code="invalid")
        binding = self.record("host-bind-v1", self.b)
        for label, value in (("absent", "-"), ("forged", b64(b"\0" * 64))):
            self.add("consent/" + label, dict(binding, host_signature=value), self.b, code="invalid")
        unbinding = self.record("host-unbind-v1", self.b)
        self.add("consent/other_actions_forbid_host_signature", dict(unbinding, host_signature=binding["host_signature"]), self.b, code="invalid")
        wrong_context = copy.deepcopy(self.b)
        self.add("pins/wrong_exact_certificate", unbinding, wrong_context,
                 certificate_id=semantic_id("certificate", self.cert_c), code="invalid")
        self.add("pins/wrong_original_person", unbinding, self.b, person_public_key=self.quinn, code="invalid")
        self.add("gate/catalog_feature_is_not_durable_pin", unbinding, self.b, known_feature_id="-", code="upgrade_required")
        self.add("gate/known_feature_conflict", unbinding, self.b, known_feature_id="lf_" + "0" * 64, code="state_conflict")
        missing_feature = copy.deepcopy(self.b)
        missing_feature["catalog"] = self.without(self.b["catalog"], lambda kind, obj: kind == "feature")
        self.add("gate/missing_complete_feature", unbinding, missing_feature, code="proof_required")
        ordinary = copy.deepcopy(self.b)
        ordinary["catalog"] = self.with_proofs(self.b["catalog"], [("person_record", self.record("host-unbind-v1"))])
        self.add("catalog/ordinary_unbinding_supported", unbinding, ordinary)
        root_record = payload(self.fixtures["network_root_admits"]["activation"]["administrator"])["admission_record"]
        self.add("route/root_companion_record_not_person_action", root_record, action_kind="person_record", code="invalid")

    def strict_transport(self):
        action = self.record("host-unbind-v1")
        good = self.request(action)
        for field in good:
            if field == "kind":
                continue
            missing = dict(good)
            del missing[field]
            self.add_request("outer/missing_" + field, missing, error("invalid"))
            for label, value in (("null", None), ("wrong_type", [])):
                self.add_request("outer/" + label + "_" + field, dict(good, **{field: value}), error("invalid"))
        self.add_request("outer/unknown", dict(good, extra=1), error("invalid"))
        self.add_request("outer/unsupported_action_kind", dict(good, action_kind="root_record"), error("invalid"))
        self.add_request("outer/nonzero_pinned_epoch", dict(good, epoch=1), error("upgrade_required"))
        for field in ("network_base64", "catalog_base64", "action_base64"):
            raw = unb64(good[field])
            for label, changed in (("bad_base64", "!"), ("extra_padding", good[field] + "="),
                                    ("base64_whitespace", good[field] + "\n")):
                self.add_request("encoding/" + field + "/" + label, dict(good, **{field: changed}), error("invalid"))
            for label, changed in (("duplicate", raw[:-1] + b',"' + next(iter(json.loads(raw))).encode() + b'":null}'),
                                    ("unknown", raw[:-1] + b',"extra":0}'), ("null", b"null"),
                                    ("invalid_utf8", b'{"bad":"\xff"}'), ("trailing", raw + b"{}"),
                                    ("not_object", b"[]"), ("deep", b"[" * 65 + b"0" + b"]" * 65)):
                self.add_request("json/" + field + "/" + label, dict(good, **{field: b64(changed)}), error("invalid"))
        for field in action:
            malformed = dict(action, **{field: None})
            self.add("shape/action_null_" + field, malformed, code="invalid")
        for kind in ("policy-v1", "policy-v2", "group-v1"):
            for spelling in (b"0", b"-1", b"1.0", b"1e0", b"18446744073709551616"):
                record = self.record(kind)
                raw = unb64(record["payload_base64"]).replace(b'"version":1', b'"version":' + spelling)
                record["payload_base64"] = b64(raw)
                self.oracle.resign("person_record", record, self.person)
                self.add("integer/" + kind + "/" + spelling.decode(), record, code="invalid")
        for label, mutate in (("unsorted", lambda c: c["objects"].reverse()),
                               ("duplicate", lambda c: c["objects"].append(copy.deepcopy(c["objects"][0]))),
                               ("wrong_hash", lambda c: c["objects"][0].update(id="pf_" + "0" * 64))):
            context = copy.deepcopy(self.root_context)
            mutate(context["catalog"])
            if label != "unsorted":
                sort_catalog(context["catalog"])
            self.add("catalog/" + label, action, context, code="invalid")
        total = sum(len(unb64(good[field])) for field in ("network_base64", "catalog_base64", "action_base64"))
        padded = dict(good, network_base64=b64(unb64(good["network_base64"]) + b" " * (LIMIT - total)))
        self.add_request("limit/exact_512k", padded, self.success(action, self.root_context))
        self.add_request("limit/over_512k", dict(padded, network_base64=b64(unb64(padded["network_base64"]) + b" ")), error("invalid"))
        for label, raw in (("trailing", wire(good) + b"{}"), ("duplicate", wire(good)[:-1] + b',"kind":"action_authorization"}'),
                            ("invalid_utf8", b'{"kind":"\xff"}'), ("over_2mib", b" " * (2 * 1024 * 1024 + 1))):
            self.add_request("framing/" + label, raw, error("invalid"))
        self.add_request("framing/recovery", good, self.success(action, self.root_context), keep=True)

    def build(self):
        self.registry_and_scopes()
        self.policies_and_invites()
        self.current_authority()
        self.revocations_and_self_guard()
        self.signed_boundaries()
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
    eligible = sum(case.expected["ok"] for case in cases)
    print(f"Independent oracle: {fixed} published signatures reproduced; {len(cases)} action checks "
          f"({eligible} authorized, {len(cases) - eligible} rejected).", flush=True)
    if not probes:
        print("Self-check only; no action implementation or live protocol was tested.")
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
        print(f"{label}: {checked} action checks completed.", flush=True)
    if failures:
        print(f"FAILED: {failures} action conformance failures.", file=sys.stderr)
        return 1
    print("PASS: current signing authority only; no mutation, persistence, freshness, policy access, "
          "invite redemption or transaction-precondition claim.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
