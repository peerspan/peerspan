#!/usr/bin/env python3
"""Independent retained ordinary-restriction catalog conformance.

Expected projections and signatures come from contracts, public vectors and
independent Python helpers. Successful verification is not a write, persistence,
freshness, rollback protection, or support for all ordinary catalog history.
"""

import argparse
import copy
import json
from pathlib import Path
import sys

from linking_actions import Author as ActionAuthor, NOW
from linking_activations import Author as ActivationAuthor, Transcript, payload, proof, semantic_id, shift, sort_catalog
from linking_history import legacy_message
from linking_records import Author as RecordAuthor, LATE
from linking_paths import error
from linking_readers import Probe, b64, digest, lines, message, unb64, wire


ROOT = Path(__file__).resolve().parents[1]
KINDS = ("host-unbind-v1", "person-remove-v1", "revoke-host-v1", "revoke-invite-v1")


def restricted(facts, record):
    """Apply only a case's already independently authorized restriction."""
    value, kind = payload(record), record["kind"]
    if kind == "peerspan-person-remove-v1":
        person = value["person_public_key"]
        member = facts.persons.get(person, {}).get("member", "-")
        facts.person(person, member, admitted=False, administrator=False)
        for binding in facts.bindings.values():
            if binding["person_public_key"] == person:
                binding["person_public_key"] = "-"
    elif kind == "peerspan-revoke-host-v1":
        host = value["host_public_key"]
        member = facts.hosts.get(host, {}).get("member", "-")
        facts.host(host, member, admitted=False)
        if host in facts.bindings:
            facts.bind(host, "-")
    elif kind == "peerspan-host-unbind-v1":
        host, person = value["host_public_key"], value["person_public_key"]
        if facts.bindings.get(host, {}).get("person_public_key") == person:
            facts.bind(host, "-")
    return facts


class Author(RecordAuthor):
    def all_signers(self):
        for label, context in (("root", self.root_context), ("b", self.b), ("c", self.c)):
            for kind in KINDS:
                record = self.record(kind, context)
                facts = restricted(self.base_facts.clone().path(context), record)
                self.add("registry/" + label + "/" + kind, self.catalog_with([record], context), facts)
        missing = self.key("removed-with-no-admission")
        record = self.record("person-remove-v1", unsigned=dict(self.payloads["person-remove-v1"], person_public_key=missing))
        self.add("projection/removed_unknown_person_is_knownfalse", self.catalog_with([record]),
                 restricted(self.base_facts.clone(), record))
        host_a, host_q = (self.data["keys"][name]["public_key"] for name in ("host_a", "host_q"))
        for label, kind, host in (("matching_unbinding", "host-unbind-v1", host_a),
                                  ("other_person_binding_unchanged", "host-unbind-v1", host_q),
                                  ("host_revocation_clears_binding", "revoke-host-v1", host_a)):
            record = self.record(kind, unsigned=dict(self.payloads[kind], host_public_key=host))
            self.add("projection/" + label, self.catalog_with([record]), restricted(self.base_facts.clone(), record))
        fixture = self.fixtures["nonadmin_owner_with_independent_admin"]
        cert = payload(fixture["activation"]["owner"])["certificate"]
        for label, context in (("root", self.context(fixture["catalog"])),
                               ("device", self.active_context(fixture, [cert]))):
            for kind in KINDS:
                record = self.record(kind, context)
                facts = self.base_facts.clone().path(context)
                facts.persons[self.person]["administrator"] = False
                self.add("role/nonadmin_" + label + "/" + kind, self.catalog_with([record], context),
                         restricted(facts, record), code=None if kind == "host-unbind-v1" else "forbidden")
        for mask in (1, 2, 8):
            context = self.narrowed(mask, "restriction-scope-" + str(mask))
            for kind in KINDS:
                record = self.record(kind, context)
                required = 2 if kind == "host-unbind-v1" else 8
                self.add(f"scope/{mask}/" + kind, self.catalog_with([record], context),
                         restricted(self.base_facts.clone().path(context), record), code=None if mask & required else "forbidden")

    def sticky_effects(self):
        person = self.record("person-admit-v1")
        host = self.record("host-admit-v1")
        binding = self.record("host-bind-v1")
        remove_person = self.record("person-remove-v1", unsigned=dict(self.payloads["person-remove-v1"], person_public_key=self.new_person))
        remove_host = self.record("revoke-host-v1")
        unbind = self.record("host-unbind-v1")
        for label, grants, restriction in (("person_removal", [person], remove_person),
                                            ("host_revocation", [host, binding], remove_host),
                                            ("unbinding", [host, binding], unbind)):
            facts = self.base_facts.clone()
            for grant in grants:
                facts.grant(grant)
            restricted(facts, restriction)
            catalog = self.catalog_with([*grants, restriction])
            self.add("sticky/ordinary_" + label, catalog, facts)
            timestamp = "unbound_at" if label == "unbinding" else "removed_at" if label == "person_removal" else "revoked_at"
            for seconds in (-86400, 86400):
                changed = self.record(restriction["kind"][len("peerspan-"):], unsigned=dict(payload(restriction), **{timestamp: shift(NOW, seconds)}))
                self.add(f"sticky/{label}/descriptive_time_{seconds}", self.catalog_with([*grants, changed]), facts)
            aliases = copy.deepcopy(catalog)
            aliases["objects"].append(proof("person_record", raw=json.dumps(restriction, indent=2).encode()))
            sort_catalog(aliases)
            self.add("sticky/" + label + "/byte_alias", aliases, facts)
        # A removed host no longer needs a feature acknowledgment. A live host
        # with only an unrelated invite revocation still needs its own proof.
        no_ack = self.with_proofs(self.base["catalog"], [("person_record", host), ("person_record", remove_host)])
        self.add("feature/revoked_host_no_longer_needs_join_ack", no_ack,
                 restricted(self.base_facts.clone().grant(host), remove_host))
        self.add("feature/unrelated_restriction_does_not_cover_live_host", self.with_proofs(self.base["catalog"],
                 [("person_record", host), ("person_record", self.record("revoke-invite-v1"))]), code="proof_required")

    def invite_halves(self):
        invite = self.key("restriction-invite")
        expires, joined = shift(NOW, -1), shift(NOW, -60)
        person = {"network_id": self.network, "invite_epoch": 0, "person_public_key": self.new_person,
                  "member": "invited", "invite_public_key": invite, "invite_expires_at": expires, "joined_at": joined}
        person["invite_signature"] = b64(self.signers[self.root].raw(lines("peerspan-person-invite-v1", self.network,
                                                   0, invite, "invited", expires)))
        person["person_signature"] = b64(self.signers[invite].raw(lines("peerspan-person-member-v1", self.network,
                                                     invite, self.new_person, joined)))
        host = {"network_id": self.network, "host_public_key": self.target_host, "member": "invited",
                "invite_public_key": invite, "invite_expires_at": expires, "joined_at": joined}
        host["invite_signature"] = b64(self.signers[self.root].raw(lines("peerspan-invite-v1", self.network, invite, "invited", expires)))
        host["host_signature"] = b64(self.signers[invite].raw(lines("peerspan-member-v1", self.network, invite, self.target_host, joined)))
        halves = [("person_membership", person), ("host_membership", host), ("join_ack", self.ack(self.target_host))]
        facts = self.base_facts.clone().person(self.new_person, "invited").host(self.target_host, "invited")
        self.add("invite/both_legacy_halves_control", self.with_proofs(self.base["catalog"], halves), facts)
        restriction = self.record("revoke-invite-v1", unsigned=dict(self.payloads["revoke-invite-v1"], invite_public_key=invite))
        catalog = self.catalog_with([restriction], extra=halves)
        false_facts = self.base_facts.clone().person(self.new_person, admitted=False).host(self.target_host, admitted=False)
        self.add("invite/revocation_disables_both_halves", catalog, false_facts)
        independent = [self.record("person-admit-v1", unsigned=dict(self.payloads["person-admit-v1"], member="independent")),
                       self.record("host-admit-v1", unsigned=dict(self.payloads["host-admit-v1"], member="independent"))]
        independent_facts = self.base_facts.clone().person(self.new_person, "independent").host(self.target_host, "independent")
        self.add("invite/independent_ordinary_admissions_survive", self.catalog_with([restriction, *independent], extra=halves), independent_facts)
        other = self.record("revoke-invite-v1")
        self.add("invite/unrelated_key_has_no_effect", self.catalog_with([other], extra=halves), facts)

    def retained_history(self):
        records = []
        for kind in KINDS:
            record = self.record(kind, self.b)
            records.append(record)
            record_id = semantic_id("person_record", record)
            catalog = self.catalog_with([record], self.b)
            facts = restricted(self.base_facts.clone().path(self.b), record)
            self.add("history/expired_requires_exact_record/" + kind, catalog, code="proof_required", required=[record_id], now=LATE)
            cp = self.checkpoint([record_id])
            self.add("history/root_checkpoint/" + kind, self.with_proofs(catalog, [("checkpoint", cp)]), facts, now=LATE)
            self.add("history/wrong_person_checkpoint/" + kind, self.with_proofs(catalog, [("checkpoint",
                     self.checkpoint([record_id], person=self.quinn, signer=self.quinn))]), code="proof_required", required=[record_id], now=LATE)
            pending = self.context(self.with_proofs(self.base["catalog"], [("certificate", self.cert_b)]), [self.cert_b])
            self.add("history/checkpoint_never_activates_issuer/" + kind, self.catalog_with([record], pending, [("checkpoint", cp)]),
                     code="proof_required", required=[self.cert_b["request_id"]], now=LATE)
            self.add("history/missing_exact_issuer_certificate/" + kind, self.catalog_with([record]), code="proof_required",
                     required=[semantic_id("certificate", self.cert_b)])
        ids = [semantic_id("person_record", record) for record in records]
        self.add("history/partial_checkpoint", self.catalog_with(records, self.b, [("checkpoint", self.checkpoint(ids[:-1]))]),
                 code="proof_required", required=[ids[-1]], now=LATE)
        record = records[-1]
        record_id = ids[-1]
        for label, context, cert in (("self", self.b, self.cert_b), ("descendant", self.c, self.cert_c)):
            cp = self.checkpoint([record_id], semantic_id("certificate", cert), cert["device_public_key"])
            self.add("history/forbidden_" + label + "_checkpoint", self.catalog_with([record], context, [("checkpoint", cp)]),
                     code="forbidden", now=LATE)
        bad = self.checkpoint([record_id])
        signature = bytearray(unb64(bad["signature"]))
        signature[-1] ^= 1
        bad["signature"] = b64(signature)
        self.add("history/bad_matching_checkpoint", self.catalog_with([record], self.b, [("checkpoint", bad)]), code="invalid", now=LATE)
        fixture = copy.deepcopy(self.c_source)
        transcript = Transcript(self, fixture)
        transcript.values["owner"]["certificate"]["not_after"] = shift(NOW, 60)
        transcript.sign_certificate()
        fixture["activation"] = transcript.finish()
        cert = payload(fixture["activation"]["owner"])["certificate"]
        context = self.active_context(fixture, [self.cert_b, cert])
        records = [self.record(kind, context) for kind in ("host-unbind-v1", "revoke-invite-v1")]
        ids = [semantic_id("person_record", record) for record in records]
        cp = self.checkpoint(ids, semantic_id("certificate", self.cert_b), self.cert_b["device_public_key"])
        facts = self.base_facts.clone().path(context)
        self.add("history/unaffected_strict_ancestor_for_scopes_2_and_8", self.catalog_with(records, context, [("checkpoint", cp)]),
                 facts, now=shift(NOW, 60))
        sibling = self.new_root_link("restriction-checkpoint-sibling", created="2026-10-23T12:00:00Z")
        sibling_cert = payload(sibling["activation"]["owner"])["certificate"]
        sibling_cp = self.checkpoint(ids, semantic_id("certificate", sibling_cert), sibling_cert["device_public_key"])
        self.add("history/sibling_checkpoint_forbidden", self.catalog_with(records, context,
                 [("activation", sibling["activation"]), ("checkpoint", sibling_cp)]), code="forbidden", now=shift(NOW, 60))

    def withdrawals_and_self_history(self):
        for kind in KINDS[1:]:
            for label, context in (("root", self.root_context), ("device", self.b)):
                record = self.record(kind, context)
                record_id = semantic_id("person_record", record)
                for version, kept, effective in ((1, [], False), (1, [digest(message("person_record", record))], False),
                                                 (2, [], False), (2, ["record:" + record_id], True)):
                    if effective and context["path"]:
                        kept = [*kept, "record:" + semantic_id("person_record", self.record_b)]
                    removal = self.removal(self.person, kept, version=version)
                    facts = self.base_facts.clone()
                    facts.persons[self.person]["administrator"] = False
                    if effective:
                        restricted(facts.path(context), record)
                    self.add(f"withdrawal/{label}/{kind}/v{version}/{len(kept)}/{effective}",
                             self.catalog_with([record], context, [("admin_removal", removal)]), facts)
                removed = self.removal(self.person)
                malformed = dict(record, signature=self.signers[self.quinn].sshsig(message("person_record", record)))
                self.add("withdrawal/bad_inert_signature/" + label + "/" + kind,
                         self.catalog_with([malformed], context, [("admin_removal", removed)]), code="invalid")
                if context["path"]:
                    pending = self.context(self.with_proofs(self.base["catalog"], [("certificate", self.cert_b)]), [self.cert_b])
                    facts = self.base_facts.clone()
                    facts.persons[self.person]["administrator"] = False
                    self.add("withdrawal/inert_record_needs_no_activation/" + kind,
                             self.catalog_with([record], pending, [("admin_removal", removed)]), facts)
        record = self.record("revoke-host-v1", self.b)
        record_id = semantic_id("person_record", record)
        removal = self.removal(self.person, ["record:" + record_id, "record:" + semantic_id("person_record", self.record_b)])
        catalog = self.catalog_with([record], self.b, [("admin_removal", removal)])
        self.add("retention/kept_role_cannot_replace_person_checkpoint", catalog, code="proof_required", required=[record_id], now=LATE)
        facts = restricted(self.base_facts.clone().path(self.b), record)
        facts.persons[self.person]["administrator"] = False
        self.add("retention/both_dimensions_required", self.with_proofs(catalog, [("checkpoint", self.checkpoint([record_id]))]), facts, now=LATE)
        for label, context in (("b", self.b), ("c", self.c)):
            for index, cert in enumerate(context["path"]):
                for kind in ("host-unbind-v1", "revoke-host-v1"):
                    record = self.record(kind, context, dict(self.payloads[kind], host_public_key=cert["host_public_key"]))
                    cp = self.checkpoint([semantic_id("person_record", record)])
                    for checkpointed in (False, True):
                        extra = [("checkpoint", cp)] if checkpointed else []
                        self.add(f"self/{label}/path_{index}/{kind}/{checkpointed}", self.catalog_with([record], context, extra), code="forbidden")
            record = self.record("person-remove-v1", context, dict(self.payloads["person-remove-v1"], person_public_key=self.person))
            cp = self.checkpoint([semantic_id("person_record", record)])
            self.add("self/" + label + "/person_removal_even_checkpointed", self.catalog_with([record], context, [("checkpoint", cp)]), code="forbidden")
        record = self.record("person-remove-v1", unsigned=dict(self.payloads["person-remove-v1"], person_public_key=self.person))
        self.add("self/original_person_removal_requires_root_kept_authorization", self.catalog_with([record]), code="forbidden")
        removal = self.removal(self.person, ["record:" + semantic_id("person_record", record)])
        facts = restricted(self.base_facts.clone(), record)
        self.add("self/original_person_removal_with_exact_root_authorization", self.catalog_with([record], extra=[("admin_removal", removal)]), facts)

    def final_authority_and_consumers(self):
        record = self.record("revoke-invite-v1", self.b)
        record_id = semantic_id("person_record", record)
        cp = self.checkpoint([record_id])
        unbind = self.record("host-unbind-v1", unsigned=dict(self.payloads["host-unbind-v1"], host_public_key=self.cert_b["host_public_key"]))
        for label, kind, restriction in (("ordinary_unbinding", "person_record", unbind),
                                          ("device_revocation", "device_revocation", self.revocation(self.cert_b))):
            catalog = self.catalog_with([record], self.b, [(kind, restriction)])
            self.add("final/" + label + "_requires_record_retention", catalog, code="proof_required", required=[record_id])
            facts = self.base_facts.clone().path(self.b)
            if kind == "person_record":
                restricted(facts, restriction)
            else:
                facts.revoked.add((self.person, self.cert_b["device_public_key"]))
            self.add("final/" + label + "_root_checkpoint", self.with_proofs(catalog, [("checkpoint", cp)]), facts)
        catalog = self.catalog_with([record], self.b)
        first = proof("person_record", record)["id"]
        for spaces in range(4096):
            later = proof("person_record", raw=b" " * spaces + wire(unbind))
            if later["id"] > first:
                break
        else:
            raise AssertionError("could not order restriction alias after dependent record")
        catalog["objects"].append(later)
        sort_catalog(catalog)
        self.add("final/later_alias_cannot_preserve_cached_authority", catalog, code="proof_required", required=[record_id])
        for kind in ("host-unbind-v1", "revoke-host-v1"):
            restriction = self.record(kind, unsigned=dict(self.payloads[kind], host_public_key=self.cert_b["host_public_key"]))
            context = copy.deepcopy(self.b)
            context["catalog"] = self.catalog_with([restriction], self.b)
            action = self.record("host-unbind-v1", self.b)
            self.add_request("consumer/current_action_refuses_" + kind, ActionAuthor.request(self, action, context), error("forbidden"))
        # Historical C records can be retained after B is unbound, without
        # converting the same transcript's first finalization into history.
        catalog = self.catalog_with([unbind], self.context(self.c_source["catalog"]),
                                    [("checkpoint", self.checkpoint(self.ids_c.values()))])
        historical = ActivationAuthor.request(self, self.c_source, catalog=catalog, verification="historical")
        self.add_request("consumer/historical_activation_control", historical, ActivationAuthor.success(self, self.c_source["activation"]))
        self.add_request("consumer/first_activation_still_checks_restricted_owner", ActivationAuthor.request(self, self.c_source, catalog=catalog), error("forbidden"))
        feature = next(json.loads(unb64(entry["body_base64"])) for entry in self.base["catalog"]["objects"] if entry["kind"] == "feature")
        feature_request = {"kind": "feature_activation", "network_base64": b64(wire(self.data["network"])),
                           "catalog_base64": b64(wire(self.catalog_with([self.record("revoke-invite-v1")]))),
                           "feature_base64": b64(wire(feature)), "epoch": 0, "known_feature_id": "-", "now": NOW}
        self.add_request("consumer/first_feature_refuses_person_envelopes", feature_request, error("forbidden"))
        person = self.key("restriction-missing-signer")
        context = self.root_person(person)
        unsigned = self.record("revoke-invite-v1", context)
        catalog = self.catalog_with([unsigned], extra=[("admin_delegation", self.delegation(person))])
        self.add("dependency/restriction_cannot_admit_its_signer", catalog, code="proof_required")
        own_admission = self.subject_record(person, person, "self-created")
        self.add("dependency/self_admission_plus_restriction_is_cycle", self.with_proofs(catalog,
                 [("person_record", own_admission)]), code="invalid")

    def strictness(self):
        domains = {"host-unbind-v1": "host_unbinding", "person-remove-v1": "person_removal",
                   "revoke-host-v1": "host_revocation", "revoke-invite-v1": "invite_revocation"}
        for kind in KINDS:
            record = self.record(kind)
            for label, edits in (("network", {"network_id": "net_" + "0" * 64}), ("epoch", {"epoch": 1})):
                changed = dict(record, **edits)
                self.oracle.resign("person_record", changed, self.person)
                self.add("strict/" + kind + "/" + label, self.catalog_with([changed]), code="invalid")
            for label, unsigned in (("unknown", dict(payload(record), extra=True)),
                                     ("null", dict(payload(record), network_id=None))):
                changed = self.record(kind, unsigned=unsigned)
                self.add("strict/" + kind + "/payload_" + label, self.catalog_with([changed]), code="invalid")
            bad = dict(record, signature=self.signers[self.quinn].sshsig(message("person_record", record)))
            self.add("strict/" + kind + "/wrong_signer", self.catalog_with([bad]), code="invalid")
            legacy = dict(record, signature=self.signers[self.person].sshsig(legacy_message(domains[kind], payload(record))))
            self.add("strict/" + kind + "/legacy_domain_is_not_envelope", self.catalog_with([legacy]), code="invalid")
            self.add("strict/" + kind + "/host_consent_forbidden", self.catalog_with([dict(record, host_signature=b64(b"\0" * 64))]), code="invalid")
        wrong_owner = self.record("host-unbind-v1", unsigned=dict(self.payloads["host-unbind-v1"], person_public_key=self.quinn))
        self.add("strict/unbinding_owner_mismatch", self.catalog_with([wrong_owner]), code="invalid")
        unsupported = ("invite-v1", "person-invite-v1")
        for kind in unsupported:
            self.add("unsupported/" + kind, self.catalog_with([self.record(kind)]), code="upgrade_required")
        good = self.request(self.catalog_with([self.record("host-unbind-v1")]))
        for label, raw in (("trailing", wire(good) + b"{}"), ("duplicate", wire(good)[:-1] + b',"kind":"catalog_facts"}'),
                           ("invalid_utf8", b'{"kind":"\xff"}'), ("over_2mib", b" " * (2 * 1024 * 1024 + 1))):
            self.add_request("framing/" + label, raw, error("invalid"))
        self.add_request("framing/recovery", good, self.base_facts.reply(), keep=True)

    def build(self):
        self.all_signers()
        self.sticky_effects()
        self.invite_halves()
        self.retained_history()
        self.withdrawals_and_self_history()
        self.final_authority_and_consumers()
        self.strictness()
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
    print(f"Independent oracle: {fixed} published signatures reproduced; {len(cases)} restriction checks "
          f"({accepted} accepted, {len(cases) - accepted} rejected).", flush=True)
    if not probes:
        print("Self-check only; no restriction implementation or live protocol was tested.")
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
        print(f"{label}: {checked} restriction checks completed.", flush=True)
    if failures:
        print(f"FAILED: {failures} restriction conformance failures.", file=sys.stderr)
        return 1
    print("PASS: retained ordinary restrictions and bounded catalog facts only; no mutation, persistence, "
          "freshness, rollback protection or complete ordinary-history claim.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
