#!/usr/bin/env python3
"""Independent fixed stored-catalog budget and no-truncation conformance.

Only contracts, public vectors and independently authored signing helpers are
used. Stored verification is not persistence, freshness or a runtime mutation.
"""

import argparse
import copy
from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from linking_actions import Author as ActionAuthor, NOW
from linking_activations import Author as ActivationAuthor, LIMIT, payload, proof, sort_catalog
from linking_paths import error
from linking_readers import Probe, b64, unb64, wire
from linking_records import Author as RecordAuthor


ROOT = Path(__file__).resolve().parents[1]
MIB = 1024 * 1024


class ModeProbe(Probe):
    def __init__(self, label, executable, stored):
        self.label, self.timeout, self.pending = label, 120, b""
        self.stderr = tempfile.TemporaryFile()
        argv = [str(Path(executable).resolve())] + (["--stored-snapshot"] if stored else [])
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr, bufsize=0)


@dataclass
class Case:
    mode: bool
    name: str
    request: object
    expected: dict


class Author(RecordAuthor):
    def add_case(self, name, request, expected, stored=True):
        self.cases.append(Case(stored, name, request, expected))

    def request_for(self, kind, catalog):
        context = self.context(catalog)
        if kind == "catalog_facts":
            return RecordAuthor.request(self, catalog), self.base_facts.reply()
        if kind == "activation":
            return ActivationAuthor.request(self, catalog=catalog), ActivationAuthor.success(self, self.base["activation"])
        if kind == "action_authorization":
            action = self.record("host-unbind-v1")
            return ActionAuthor.request(self, action, context), ActionAuthor.success(self, action, context)
        if kind == "feature_activation":
            feature = next(json.loads(unb64(entry["body_base64"])) for entry in catalog["objects"] if entry["kind"] == "feature")
            request = {"kind": kind, "network_base64": b64(wire(self.data["network"])), "catalog_base64": b64(wire(catalog)),
                       "feature_base64": b64(wire(feature)), "epoch": 0, "known_feature_id": self.data["feature_id"], "now": NOW}
            return request, {"ok": True, "network_id": self.network, "feature_id": self.data["feature_id"], "epoch": 0, "disposition": "already_enabled"}
        return ({"kind": "access_state", "network_base64": b64(wire(self.data["network"])), "catalog_base64": b64(wire(catalog)),
                 "epoch": 0, "known_feature_id": self.data["feature_id"], "now": NOW, "prior_policies": [], "prior_groups": []},
                {"ok": True, "network_id": self.network, "feature_id": self.data["feature_id"], "policies": [], "groups": []})

    @staticmethod
    def padded(raw, length, prefix=b""):
        assert len(raw) + len(prefix) <= length
        return prefix + raw + b" " * (length - len(raw) - len(prefix))

    def with_alias(self, catalog, length, prefix=b"", source=None):
        catalog = copy.deepcopy(catalog)
        catalog["objects"].append(proof("certificate", raw=self.padded(wire(source or self.cert_b), length, prefix)))
        sort_catalog(catalog)
        return catalog

    def build(self):
        base = self.base["catalog"]
        large = self.with_alias(base, 600 * 1024)
        for kind in ("catalog_facts", "activation", "feature_activation", "action_authorization", "access_state"):
            request, expected = self.request_for(kind, large)
            self.add_case("entrypoint/" + kind + "/stored", request, expected)
            self.add_case("entrypoint/" + kind + "/normal_512k", request, error("invalid"), stored=False)
        # Top-level entry bodies count exact supplied bytes, including aliases.
        decoded = copy.deepcopy(base)
        remaining = 8 * MIB - sum(len(unb64(entry["body_base64"])) for entry in base["objects"])
        for index in range(8):
            length = min(MIB, remaining)
            decoded = self.with_alias(decoded, length, b"\t" * index)
            remaining -= length
        assert remaining == 0 and sum(len(unb64(entry["body_base64"])) for entry in decoded["objects"]) == 8 * MIB
        request, expected = self.request_for("catalog_facts", decoded)
        self.add_case("body_budget/exact_8mib", request, expected)
        overflow = copy.deepcopy(decoded)
        index = next(index for index, entry in enumerate(overflow["objects"]) if entry["kind"] == "certificate"
                     and len(unb64(entry["body_base64"])) < MIB)
        entry = overflow["objects"][index]
        overflow["objects"][index] = proof("certificate", raw=unb64(entry["body_base64"]) + b" ")
        sort_catalog(overflow)
        self.add_case("body_budget/over_8mib", self.request_for("catalog_facts", overflow)[0], error("invalid"))
        # Catalog syntax bytes are a separate inclusive budget.
        exact_json = self.padded(wire(decoded), 16 * MIB)
        exact_request = dict(request, catalog_base64=b64(exact_json))
        self.add_case("catalog_json/exact_16mib", exact_request, expected)
        self.add_case("catalog_json/over_16mib", dict(request, catalog_base64=b64(exact_json + b" ")), error("invalid"))
        entries = copy.deepcopy(base)
        body = wire(self.cert_b)
        for index in range(4096 - len(base["objects"])):
            prefix = bytes(9 if index & (1 << bit) else 32 for bit in range(12))
            entries["objects"].append(proof("certificate", raw=prefix + body))
        sort_catalog(entries)
        assert len(entries["objects"]) == 4096
        self.add_case("entries/exact_4096", self.request_for("catalog_facts", entries)[0], expected)
        entries["objects"].append(proof("certificate", raw=b"\t" * 13 + body))
        sort_catalog(entries)
        self.add_case("entries/over_4096", self.request_for("catalog_facts", entries)[0], error("invalid"))
        for length in (MIB, MIB + 1):
            object_catalog = self.with_alias(base, length)
            self.add_case("object/" + str(length), self.request_for("catalog_facts", object_catalog)[0],
                          expected if length == MIB else error("invalid"))
        for length in (256 * 1024, 256 * 1024 + 1):
            record = self.record("host-bind-v1")
            record["payload_base64"] = b64(self.padded(unb64(record["payload_base64"]), length))
            self.oracle.resign("person_record", record, self.person)
            catalog = self.with_proofs(large, [("person_record", record)])
            self.add_case("payload/" + str(length), self.request_for("catalog_facts", catalog)[0],
                          self.base_facts.clone().grant(record).reply() if length == 256 * 1024 else error("invalid"))
        # No authority shortcut or silent prefix is permitted for large state.
        pending = self.context(large, [self.cert_b])
        action = self.record("host-unbind-v1", pending)
        self.add_case("authority/large_pending_still_requires_activation", ActionAuthor.request(self, action, pending),
                      error("proof_required", [self.cert_b["request_id"]]))
        revoked = copy.deepcopy(self.b)
        revoked["catalog"] = self.with_alias(self.with_proofs(self.b["catalog"], [("device_revocation", self.revocation(self.cert_b))]), 600 * 1024)
        self.add_case("authority/large_revoked_path_still_rejected", ActionAuthor.request(self, self.record("host-unbind-v1", revoked), revoked), error("device_revoked"))
        malformed = copy.deepcopy(large)
        last = max(entry["id"] for entry in malformed["objects"])
        for spaces in range(4096):
            entry = proof("certificate", raw=b" " * spaces + b"{}")
            if entry["id"] > last:
                break
        else:
            raise AssertionError("could not place malformed candidate after valid catalog")
        malformed["objects"].append(entry)
        sort_catalog(malformed)
        self.add_case("authority/malformed_late_entry_fails_whole_catalog", self.request_for("catalog_facts", malformed)[0], error("invalid"))
        malformed = copy.deepcopy(large)
        malformed["objects"][-1]["body_base64"] += "="
        self.add_case("strict/noncanonical_body_base64", self.request_for("catalog_facts", malformed)[0], error("invalid"))
        deep = self.record("host-bind-v1")
        value = wire(payload(deep))[:-1] + b',"unknown":' + b"[" * 65 + b"0" + b"]" * 65 + b"}"
        deep["payload_base64"] = b64(value)
        self.oracle.resign("person_record", deep, self.person)
        self.add_case("strict/depth65_payload", self.request_for("catalog_facts", self.with_proofs(large, [("person_record", deep)]))[0], error("invalid"))
        # Separate descriptor/action bound excludes the stored catalog itself.
        small, small_expected = self.request_for("catalog_facts", large)
        descriptor = unb64(small["network_base64"])
        self.add_case("context/exact_512k_descriptor", dict(small, network_base64=b64(self.padded(descriptor, LIMIT))), small_expected)
        self.add_case("context/over_512k_descriptor", dict(small, network_base64=b64(self.padded(descriptor, LIMIT + 1))), error("invalid"))
        # Complete framing caps include the LF appended by Probe.exchange.
        raw = wire(exact_request)
        assert len(raw) < 24 * MIB
        self.add_case("framing/exact_24mib", raw + b" " * (24 * MIB - 1 - len(raw)), expected)
        self.add_case("framing/over_24mib", raw + b" " * (24 * MIB - len(raw)), error("invalid"))
        self.add_case("framing/stored_recovery", small, small_expected)
        normal, normal_expected = self.request_for("catalog_facts", base)
        raw = wire(normal)
        self.add_case("framing/exact_normal_2mib", raw + b" " * (2 * MIB - 1 - len(raw)), normal_expected, stored=False)
        self.add_case("framing/over_normal_2mib", raw + b" " * (2 * MIB - len(raw)), error("invalid"), stored=False)
        self.add_case("framing/normal_recovery", normal, normal_expected, stored=False)
        for kind in ("path", "certificate"):
            self.add_case("mode/other_kind_" + kind, {"kind": kind}, error("invalid"))
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
    print(f"Independent oracle: {fixed} signatures reproduced; {len(cases)} stored-budget checks.", flush=True)
    failures = 0
    for label, executable in probes:
        modes = {mode: ModeProbe(label, executable, mode) for mode in (False, True)}
        try:
            for case in cases:
                actual = modes[case.mode].exchange(case.request)
                if actual != case.expected:
                    failures += 1
                    print(f"FAIL {label} {case.name}: expected {str(case.expected)[:3000]}; received {str(actual)[:3000]}", file=sys.stderr)
        finally:
            for mode in modes.values():
                mode.close()
        print(f"{label}: {len(cases)} stored-budget checks completed.", flush=True)
    return int(failures > 0)


if __name__ == "__main__":
    sys.exit(main())
