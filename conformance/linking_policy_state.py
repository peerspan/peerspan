#!/usr/bin/env python3
"""Independent verified policy/group selection and high-water conformance.

Uses accepted contracts, public vectors and independent Python signers only.
Selection is not persisted, fresh, an access decision, or writer readiness.
"""

import argparse
import copy
import json
from pathlib import Path
import sys

from linking_actions import Author as ActionAuthor, NOW
from linking_activations import LIMIT, payload, proof, semantic_id, shift, sort_catalog
from linking_paths import error
from linking_readers import Probe, b64, digest, lines, message, unb64, wire


ROOT = Path(__file__).resolve().parents[1]


def legacy_policy_message(value):
    version = 2 if value.get("format") == 2 else 1
    parts = ["peerspan-policy-v" + str(version), value["network_id"], value["person_public_key"],
             value["version"], value["issued_at"], value["valid_until"]]
    for rule in value["rules"]:
        bounds = str(rule["max_message_bytes"]) + " " + str(rule["allow_disconnected"]).lower()
        if rule.get("max_artifact_bytes", 0):
            bounds += " " + str(rule["max_artifact_bytes"])
        parts += ["rule", rule["agent"], " ".join(rule["principals"]), " ".join(rule["actions"]), bounds]
    if version == 2:
        for rule in value["capability_rules"]:
            parts += ["capability_rule", rule["host"], rule["capability"], " ".join(rule["principals"]),
                      str(rule["max_input_bytes"]) + " " + str(rule["allow_disconnected"]).lower() + " " + str(rule["max_calls_per_hour"]), "end"]
        parts += [" ".join(["trusted", *sorted(value["trusted_hosts"])]),
                  " ".join(["edits", *sorted(item["host"] + ":" + str(item["seq"]) for item in value["edits"])])]
    return lines(*parts)


def legacy_group_message(value):
    return lines("peerspan-group-v1", value["network_id"], value["name"], value["version"], value["defined_at"], *value["members"])


class Author(ActionAuthor):
    def candidate(self, suffix="policy-v2", context=None, legacy=False, signer=None, **edits):
        context = context or self.root_context
        value = copy.deepcopy(self.payloads[suffix])
        value.update(edits)
        if not legacy:
            return "person_record", self.record(suffix, context, value)
        kind = "group" if suffix == "group-v1" else "policy"
        signer = signer or (self.root if kind == "group" else value["person_public_key"])
        msg = legacy_group_message(value) if kind == "group" else legacy_policy_message(value)
        value["signature"] = b64(self.signers[signer].raw(msg)) if signer == self.root and kind == "group" else self.signers[signer].sshsig(msg)
        return kind, value

    @staticmethod
    def row(candidate, active=True, code="active", raw=None):
        kind, obj = candidate
        value = payload(obj) if kind == "person_record" else obj
        group = (obj["kind"] == "peerspan-group-v1") if kind == "person_record" else kind == "group"
        msg = message("person_record", obj) if kind == "person_record" else legacy_group_message(value) if group else legacy_policy_message(value)
        result = {"name" if group else "person_public_key": value["name" if group else "person_public_key"],
                  "version": value["version"], "message_hash": digest(msg), "proof_id": proof(kind, obj, raw)["id"],
                  "record_id": semantic_id("person_record", obj) if kind == "person_record" else "-",
                  "body_base64": b64(wire(obj) if raw is None else raw), "active": active,
                  "code": code, "required_ids": []}
        return result

    @staticmethod
    def prior(row):
        return {key: row[key] for key in ("name" if "name" in row else "person_public_key", "version", "message_hash")}

    @staticmethod
    def missing(prior):
        return dict(prior, proof_id="-", record_id="-", body_base64="-", active=False, code="proof_required", required_ids=[])

    def request(self, candidates=(), context=None, prior_policies=(), prior_groups=(), **pins):
        context = context or self.root_context
        catalog = self.with_proofs(context["catalog"], candidates)
        result = {"kind": "access_state", "network_base64": b64(wire(self.data["network"])), "catalog_base64": b64(wire(catalog)),
                  "epoch": 0, "known_feature_id": self.data["feature_id"], "now": context["now"],
                  "prior_policies": list(prior_policies), "prior_groups": list(prior_groups)}
        result.update(pins)
        return result

    def add(self, name, candidates=(), policies=(), groups=(), context=None, code=None, required=(), **pins):
        expected = error(code, required) if code else {"ok": True, "network_id": self.network, "feature_id": self.data["feature_id"],
                   "policies": sorted(policies, key=lambda row: row["person_public_key"]), "groups": sorted(groups, key=lambda row: row["name"])}
        self.add_request(name, self.request(candidates, context, **pins), expected)

    def shapes_and_versions(self):
        self.add("selection/empty")
        for suffix in ("policy-v1", "policy-v2", "group-v1"):
            for label, context in (("root", self.root_context), ("b", self.b), ("c", self.c)):
                value = self.candidate(suffix, context)
                rows = {"groups" if suffix == "group-v1" else "policies": [self.row(value)]}
                self.add("ordinary/" + label + "/" + suffix, [value], context=context, **rows)
            for signer in ((self.root, self.person) if suffix == "group-v1" else (self.person,)):
                value = self.candidate(suffix, legacy=True, signer=signer)
                rows = {"groups" if suffix == "group-v1" else "policies": [self.row(value)]}
                self.add("legacy/" + suffix + "/" + signer[:8], [value], **rows)
            for legacy in (False, True):
                for version in (2 ** 63, 2 ** 64 - 1):
                    value = self.candidate(suffix, legacy=legacy, version=version)
                    rows = {"groups" if suffix == "group-v1" else "policies": [self.row(value)]}
                    self.add(f"version/{suffix}/{legacy}/{version}", [value], **rows)
                for version in (0, -1, 2 ** 64):
                    self.add(f"version/invalid/{suffix}/{legacy}/{version}", [self.candidate(suffix, legacy=legacy, version=version)], code="invalid")
        for suffix in ("policy-v2", "group-v1"):
            value = self.candidate(suffix)
            alias_raw = json.dumps(value[1], indent=2).encode()
            alias = proof(value[0], raw=alias_raw)
            normal = proof(*value)
            request = self.request([value])
            catalog = json.loads(unb64(request["catalog_base64"]))
            catalog["objects"].append(alias)
            sort_catalog(catalog)
            request["catalog_base64"] = b64(wire(catalog))
            row = self.row(value, raw=alias_raw) if alias["id"] < normal["id"] else self.row(value)
            expected = {"ok": True, "network_id": self.network, "feature_id": self.data["feature_id"],
                        "policies": [] if suffix == "group-v1" else [row], "groups": [row] if suffix == "group-v1" else []}
            self.add_request("selection/exact_alias/" + suffix, request, expected)

    def selection_and_priors(self):
        one = self.candidate("policy-v1", version=1)
        two = self.candidate("policy-v2", version=2)
        self.add("policy/highest_whole_body", [two, one], policies=[self.row(two)])
        variants = [self.candidate("policy-v2", legacy=True, version=3), self.candidate("policy-v2", self.b, version=3)]
        winner = min(variants, key=lambda candidate: self.row(candidate)["message_hash"])
        self.add("policy/tie_actual_legacy_or_envelope_message_hash", variants, policies=[self.row(winner)], context=self.b)
        for label, prior, candidates, selected in (
                ("lower_candidate_no_fallback", self.prior(self.row(two)), [one], self.missing(self.prior(self.row(two)))),
                ("equal_exact_body", self.prior(self.row(two)), [two], self.row(two)),
                ("higher_candidate", self.prior(self.row(one)), [two], self.row(two)),
                ("equal_worse_hash", dict(self.prior(self.row(two)), message_hash="0" * 64), [two],
                 self.missing(dict(self.prior(self.row(two)), message_hash="0" * 64))),
                ("equal_better_hash", dict(self.prior(self.row(two)), message_hash="f" * 64), [two], self.row(two))):
            self.add("prior/policy/" + label, candidates, policies=[selected], prior_policies=[prior])
        group = self.candidate("group-v1", version=4)
        other = self.candidate("group-v1", version=4, members=[])
        higher = self.candidate("group-v1", version=5)
        self.add("group/same_version_conflict", [group, other], code="state_conflict")
        self.add("group/conflict_below_later_maximum", [group, other, higher], code="state_conflict")
        prior = self.prior(self.row(group))
        self.add("prior/group/missing_winner", [], groups=[self.missing(prior)], prior_groups=[prior])
        self.add("prior/group/lower_body_cannot_replace", [self.candidate("group-v1", version=3)], groups=[self.missing(prior)], prior_groups=[prior])
        self.add("prior/group/equal_conflict_despite_newer", [other, higher], prior_groups=[prior], code="state_conflict")
        self.add("prior/group/newer_recovers", [higher], groups=[self.row(higher)], prior_groups=[prior])
        for suffix, key in (("policy-v2", "prior_policies"), ("group-v1", "prior_groups")):
            current = self.prior(self.row(self.candidate(suffix, version=2 ** 64 - 1)))
            rows = {"groups" if key == "prior_groups" else "policies": [self.missing(current)]}
            self.add("prior/u64_missing/" + suffix, **{key: [current]}, **rows)

    def authority_and_windows(self):
        policy = self.candidate("policy-v2", legacy=True)
        for label, seconds, active in (("before_skew", -301, False), ("inclusive_skew", -300, True),
                                       ("last_second", 86400 - 1, True), ("exclusive_end", 86400, False)):
            self.add("policy/window/" + label, [policy], policies=[self.row(policy, active, "active" if active else "expired")], now=shift(NOW, seconds))
        expired = self.candidate("policy-v1", legacy=True, version=2, issued_at=shift(NOW, -2 * 86400), valid_until=shift(NOW, -86400))
        old = self.candidate("policy-v2", version=1)
        self.add("policy/inactive_maximum_never_falls_back", [old, expired], policies=[self.row(expired, False, "expired")])
        recovered = self.candidate("policy-v2", version=3)
        self.add("policy/newer_recovers_expired_prior", [old, recovered], policies=[self.row(recovered)], prior_policies=[self.prior(self.row(expired))])
        for suffix in ("policy-v2", "group-v1"):
            value = self.candidate(suffix, self.b)
            self.add("dependency/missing_certificate/" + suffix, [value], code="proof_required", required=[semantic_id("certificate", self.cert_b)])
            pending = self.context(self.with_proofs(self.base["catalog"], [("certificate", self.cert_b)]), [self.cert_b])
            self.add("dependency/missing_activation/" + suffix, [value], context=pending, code="proof_required", required=[self.cert_b["request_id"]])
            cp = self.checkpoint([semantic_id("person_record", value[1])])
            for label, extra, code in (
                    ("revoked", [("device_revocation", self.revocation(self.cert_b))], "device_revoked"),
                    ("unbound", [("host_unbinding", self.signed_legacy("host_unbinding", {"person_public_key": self.person,
                        "host_public_key": self.cert_b["host_public_key"], "unbound_at": NOW}, self.person, ssh=True))], "forbidden")):
                context = copy.deepcopy(self.b)
                context["catalog"] = self.with_proofs(context["catalog"], extra)
                rows = {"groups" if suffix == "group-v1" else "policies": [self.row(value, False, code)]}
                self.add("authority/" + label + "/" + suffix, [value], context=context, **rows)
                context["catalog"] = self.with_proofs(context["catalog"], [("checkpoint", cp)])
                self.add("authority/checkpoint_does_not_revive/" + label + "/" + suffix, [value], context=context, **rows)
        group = self.candidate("group-v1", self.b)
        self.add("authority/expired_device_group", [group], groups=[self.row(group, False, "authority_expired")], context=self.b, now=self.cert_b["not_after"])
        removal = self.removal(self.person, ["record:" + semantic_id("person_record", self.record_b)])
        context = copy.deepcopy(self.b)
        context["catalog"] = self.with_proofs(context["catalog"], [("admin_removal", removal)])
        policy = self.candidate("policy-v1", self.b)
        self.add("authority/role_withdrawal_does_not_disable_owner_policy", [policy, group], context=context,
                 policies=[self.row(policy)], groups=[self.row(group, False, "forbidden")])
        high = self.candidate("group-v1", self.b, version=2)
        low = self.candidate("group-v1", legacy=True, version=1)
        self.add("authority/withdrawn_group_maximum_has_no_root_fallback", [low, high], context=context,
                 groups=[self.row(high, False, "forbidden")])
        removed = self.record("person-remove-v1", self.context(self.base["catalog"], person=self.quinn),
                              dict(self.payloads["person-remove-v1"], person_public_key=self.person))
        removed_context = self.context(self.with_proofs(self.base["catalog"], [("person_record", removed)]))
        for legacy in (False, True):
            candidate = self.candidate("policy-v1", legacy=legacy)
            self.add("authority/known_removed_owner/" + str(legacy), [candidate], context=removed_context,
                     policies=[self.row(candidate, False, "forbidden")])
        self.add("authority/network_root_group_has_no_person_admission_dependency", [low], context=removed_context,
                 groups=[self.row(low)])
        cap = self.cert_b["not_after"]
        for suffix in ("policy-v1", "policy-v2"):
            exact = self.candidate(suffix, self.b, issued_at=shift(cap, -86400), valid_until=cap)
            self.add("policy/exact_path_cap/" + suffix, [exact], context=self.b, policies=[self.row(exact, False, "expired")])
            overflow = self.candidate(suffix, self.b, issued_at=shift(cap, -86400), valid_until=shift(cap, 1))
            self.add("policy/path_cap_overflow_never_advances/" + suffix, [overflow], context=self.b, code="forbidden")
        for mask, suffix in ((2, "policy-v2"), (1, "group-v1")):
            context = self.narrowed(mask, "access-scope-" + str(mask))
            self.add("scope/structural_wrong_scope/" + suffix, [self.candidate(suffix, context)], context=context, code="forbidden")
        missing = self.key("missing-policy-owner")
        self.add("dependency/missing_legacy_owner", [self.candidate("policy-v1", legacy=True, person_public_key=missing)], code="proof_required")
        bare_removal = self.record("person-remove-v1", unsigned=dict(self.payloads["person-remove-v1"], person_public_key=missing))
        bare_context = self.context(self.with_proofs(self.base["catalog"], [("person_record", bare_removal)]))
        self.add("dependency/bare_removal_cannot_admit_policy_owner", [self.candidate("policy-v1", legacy=True,
                 person_public_key=missing)], context=bare_context, code="proof_required")
        self.add("group/unrecognized_legacy_admin_never_advances", [self.candidate("group-v1", legacy=True, signer=self.other)], code="forbidden")

    def strictness(self):
        for suffix in ("policy-v1", "policy-v2", "group-v1"):
            for legacy in (False, True):
                candidate = self.candidate(suffix, legacy=legacy)
                kind, obj = candidate
                bad = copy.deepcopy(obj)
                bad["signature"] = self.signers[self.quinn].sshsig(message("person_record", bad) if kind == "person_record" else
                                    legacy_group_message(bad) if kind == "group" else legacy_policy_message(bad))
                self.add("signature/" + suffix + "/" + str(legacy), [(kind, bad)], code="invalid" if suffix != "group-v1" or not legacy else None,
                         groups=[self.row((kind, bad))] if suffix == "group-v1" and legacy else [])
                unknown = copy.deepcopy(obj)
                unknown["extra"] = True
                self.add("shape/unknown/" + suffix + "/" + str(legacy), [(kind, unknown)], code="invalid")
        policy = self.candidate("policy-v2")
        good = self.request([policy])
        self.add("gate/absent_persisted_feature", [policy], known_feature_id="-", code="upgrade_required")
        self.add("gate/conflicting_feature", [policy], known_feature_id="lf_" + "0" * 64, code="state_conflict")
        for field in good:
            if field == "kind":
                continue
            missing = dict(good)
            del missing[field]
            self.add_request("outer/missing_" + field, missing, error("invalid"))
            self.add_request("outer/null_" + field, dict(good, **{field: None}), error("invalid"))
        for field, key in (("prior_policies", "person_public_key"), ("prior_groups", "name")):
            row = {key: self.person if key == "person_public_key" else "team", "version": 1, "message_hash": "a" * 64}
            for label, value in (("zero", dict(row, version=0)), ("overflow", dict(row, version=2 ** 64)),
                                  ("wrong_type", dict(row, version=True)), ("hash", dict(row, message_hash="A" * 64)),
                                  ("unknown", dict(row, extra=True)), ("null", dict(row, message_hash=None))):
                self.add_request("prior/invalid/" + field + "/" + label, dict(good, **{field: [value]}), error("invalid"))
            self.add_request("prior/duplicate/" + field, dict(good, **{field: [row, row]}), error("invalid"))
            second = dict(row, **{key: self.quinn if key == "person_public_key" else "other"})
            descending = sorted([row, second], key=lambda value: value[key], reverse=True)
            self.add_request("prior/unsorted/" + field, dict(good, **{field: descending}), error("invalid"))
        too_many = [{"name": "g" + str(index).zfill(5), "version": 1, "message_hash": "0" * 64} for index in range(16385)]
        request = dict(good, prior_groups=too_many)
        assert len(wire(request)) < 2 * 1024 * 1024
        self.add_request("limit/prior_rows_16385", request, error("invalid"))
        total = sum(len(unb64(good[field])) for field in ("network_base64", "catalog_base64"))
        padded = dict(good, network_base64=b64(unb64(good["network_base64"]) + b" " * (LIMIT - total)))
        expected = {"ok": True, "network_id": self.network, "feature_id": self.data["feature_id"], "policies": [self.row(policy)], "groups": []}
        self.add_request("limit/exact_512k", padded, expected)
        self.add_request("limit/over_512k", dict(padded, network_base64=b64(unb64(padded["network_base64"]) + b" ")), error("invalid"))
        for label, raw in (("duplicate", wire(good)[:-1] + b',"kind":"access_state"}'), ("trailing", wire(good) + b"{}"),
                           ("invalid_utf8", b'{"kind":"\xff"}'), ("over_2mib", b" " * (2 * 1024 * 1024 + 1))):
            self.add_request("framing/" + label, raw, error("invalid"))
        self.add_request("framing/recovery", good, expected, keep=True)

    def build(self):
        self.shapes_and_versions()
        self.selection_and_priors()
        self.authority_and_windows()
        self.strictness()
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
    print(f"Independent oracle: {fixed} signatures reproduced; {len(cases)} policy/group checks.", flush=True)
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
        print(f"{label}: {len(cases)} policy/group checks completed.", flush=True)
    return int(failures > 0)


if __name__ == "__main__":
    sys.exit(main())
