#!/usr/bin/env python3
"""Independent M07 copy-writer controls on a separately frozen public source.

No former test function, implementation source or daemon key is used. Carol's
original SSH key stays in her signer fixture and is never given to the daemon.
"""
from __future__ import annotations

import argparse
from datetime import timedelta
import json
from pathlib import Path
import time
import traceback

from decentralized_complete_link import statement_id, table_rows
from decentralized_fixtures import FixtureKeys, b64, lines, raw_json, sha, unb64
from decentralized_migration_device_bans_fixture import external_original_signature
from decentralized_migration_identity import INTENT, VIEW, moment, stamp
from decentralized_native_introduction import Introduction, ssh_public
from decentralized_owner_preview import authority_rows
from decentralized_runtime import CreationSuite, SLOT_FIELDS
from decentralized_storage import CheckFailure, all_database_snapshots, require
from decentralized_vectors import strict_output

PIN = "802d16b8b129e510590ac2cca45bb7ab8abed251"
SPEC = Path(__file__).with_name("decentralized_migration_device_bans_cases.json")
PLAN = json.loads(SPEC.read_bytes()); CASES = [v["name"] for v in PLAN["cases"]]
REVIEW = set(PLAN["response"]["review_fields"])


class Copies:
    def __init__(self, args, keys):
        self.args, self.keys = args, keys; self.trace = []; self.submitted = {}; self.templates = {}
        public = args.fixture_dir/"M07-public-fixture.json"
        require(sha(public.read_bytes()) == args.fixture_sha256, "public source manifest differs from the preexecution freeze")
        self.f = strict_output(public.read_bytes())
        self.person, self.network, self.proposal = (self.f[k] for k in ("copy_person_public_key", "network_id", "proposal_id"))
        signer = strict_output((args.fixture_dir/"M07-local-signer.private.json").read_bytes())
        self.original = Path(signer["original_key_path"]); self.signer_home = Path(signer["signer_home"])
        require(ssh_public(self.original) == self.person and self.person != self.f["writer_person_public_key"] and
                self.original.parent == self.signer_home, "original signer is not independent hostless Carol on her own fixture")
        self.b = CreationSuite(args.host, args.work_dir, keys)
        self.b.host.state = args.fixture_dir/"owner"/"state"
        require(not (self.b.host.state/"admin.sock").exists(), "actual M07 writer is not stopped")
        self.clock = args.fixture_dir/"authority-clock"; self.now = moment(self.clock.read_text())
        require(stamp(self.now) == self.f["decision_time"], "first M07 execution would reset the exact prepared clock")
        self.b.host.environment.update(PEERSPAN_DEC_TEST_MODE="1", PEERSPAN_DEC_TEST_CLOCK_FILE=str(self.clock))
        self.route = "/v2/networks/"+self.network+"/migration"

    def call(self, suffix, body=None, *, method="POST", status=200):
        return self.b.api(method, self.route+suffix, body, status=status)[0]

    def migration(self):
        rows = table_rows(self.b.host, "dec_migrations", "record", " WHERE proposal_id=?", (self.proposal,))
        require(len(rows) == 1, "source proposal disappeared/duplicated")
        return strict_output(rows[0][0].encode())

    def copy_intents(self):
        return [(identifier, strict_output(encoded.encode()), secret) for identifier, encoded, secret in
            table_rows(self.b.host, "dec_intents", "intent_id,record,secret", " WHERE kind='migration'")
            if (lambda r:r["operation_id"] == self.proposal and r["person_public_key"] == self.person and
                any(t["object_type"] == "device_revoke" for t in r["templates"]))(strict_output(encoded.encode()))]

    def wrapper(self, value, *, pending=False, person=None):
        require(set(value) == {"migration", "review", "signing_requests"} and set(value["migration"]) == VIEW and
            set(value["review"]) == REVIEW, "M07 wrapper/review differs from exact public variant")
        review = value["review"]; selected = person or self.person
        require(review["stage"] == "inherited_device_bans" and review["network_id"] == self.network and
            review["proposal_id"] == self.proposal and review["new_context_id"] == self.f["context_id"] and
            review["person_public_key"] == selected and review["root_state_id"] == self.f["root_state_id"] and
            review["access_maxima"] == self.f["access_maxima"] and isinstance(review["authority_warning"], str) and
            bool(review["authority_warning"]), "copy review changed source, person/root/context, ALL maxima or warning")
        evidence = self.f["evidence"]
        require(review["source_catalog_sha256"] == sha(unb64(evidence["source_catalog_base64"])) and
            review["source_state_sha256"] == sha(unb64(evidence["source_state_base64"])), "copy review rewrote original endorsed hashes")
        if selected == self.person:
            require(review["person_lease_id"] == self.f["person_lease_id"] and
                [v["device_public_key"] for v in review["copies"]] == sorted(self.f["source_targets"]), "review omitted/added a stable target or changed shared Carol P")
            for row in review["copies"]:
                require(set(row) == {"device_public_key", "source_proof_ids", "statement_id"} and
                    row["source_proof_ids"] == self.f["source_targets"][row["device_public_key"]] and
                    (row["statement_id"] == "-" if pending else row["statement_id"].startswith("ds_")),
                    "review changed ALL exact applicable source proofs or copy ID state")
        return review

    def inert(self):
        snapshots = all_database_snapshots(self.b.host.state)
        device_rows = {name:db["tables"].get("link_device_keys") for name, db in snapshots["databases"].items()}
        prior_intents_retained = all(set(old).issubset(set(snapshots["databases"][name]["tables"]["dec_intents"]["rows"]))
            for name, old in self.prior_intent_hashes.items())
        require(authority_rows(self.b) == self.authority and
            device_rows == self.device_rows and prior_intents_retained and
            table_rows(self.b.host, "dec_intents", "intent_id,record", " WHERE kind='migration_identity'") == self.identity_rows and
            table_rows(self.b.host, "events", "*") == self.events, "copy work changed active authority/provider/identity seed/device/event")
        migration = self.migration()
        require(not migration["fenced"] and migration["local_acknowledgment_base64"] == migration["commit_base64"] == migration["migration_base64"] == "-",
            "copy work supplied ACK/fence/commit/adoption")

    def intent_and_templates(self):
        found = self.copy_intents(); require(len(found) == 1, "approved copy intent is missing/ambiguous")
        identifier, record, secret = found[0]
        require(set(record) == INTENT and record["approved"] and record["approved_at"] == self.approved_at and secret is None and
            record["operation_id"] == self.proposal and record["root_state_id"] == self.f["root_state_id"] and
            record["person_public_key"] == self.person and record["host_public_key"] == self.f["writer_host_public_key"] and
            record["device_public_key"] == "-" and record["scopes"] == 0 and record["not_after"] == record["result_base64"] == "-" and
            record["expires_at"] == self.f["proposal_window"][1] and record["terminal"] == "-" and record["provider"] ==
            {"kind":"original", "signer_public_key":self.person, "signature_format":"sshsig", "lease_id":"-"},
            "copy intent mixed selector/subject/approval/window or stored a seed")
        require([t["slot_id"] for t in record["templates"]] == list(range(1, len(record["templates"])+1)), "copy slot IDs are not consecutive")
        targets = []
        for template in record["templates"]:
            require(set(template) == {"slot_id", "object_type", "template_base64"} and template["object_type"] == "device_revoke", "unrelated copy-intent template")
            statement = strict_output(unb64(template["template_base64"])); payload = strict_output(unb64(statement["payload_base64"]))
            target = payload["target"]["device_public_key"]; targets.append(target)
            require(statement["kind"] == "device_revoke" and statement["context_id"] == self.f["context_id"] and
                payload == {"root_state_id":self.f["root_state_id"], "issuer":{"kind":"person", "person_public_key":self.person},
                    "parents":[{"role":"issuer_person", "id":self.f["person_lease_id"]}], "issued_at":record["created_at"],
                    "target":{"statement_id":"-", "person_public_key":self.person, "host_public_key":"-", "device_public_key":target},
                    "kept_statement_ids":[], "ratifies":"-"} and target in self.f["source_targets"], "copy template changed schema/issuer/target/P or fixed time")
            previous = self.templates.setdefault(template["slot_id"], template["template_base64"])
            require(previous == template["template_base64"], "copy template changed across signing/restart")
        require(sorted(targets) == sorted(self.f["source_targets"]) and len(targets) == len(set(targets)), "copy set omitted/duplicated/added a target")
        return identifier, record

    def run(self):
        self.b.host.start(); self.b.identity = self.b.host.api("GET", "/v1/host")
        require(self.b.identity["public_key"] == self.f["writer_host_public_key"], "M07 reopening replaced actual Alice writer")
        self.authority = authority_rows(self.b)
        snapshots = all_database_snapshots(self.b.host.state)
        self.device_rows = {name:db["tables"].get("link_device_keys") for name, db in snapshots["databases"].items()}
        self.prior_intent_hashes = {name:db["tables"]["dec_intents"]["rows"] for name, db in snapshots["databases"].items()
            if "dec_intents" in db["tables"]}
        self.identity_rows = table_rows(self.b.host, "dec_intents", "intent_id,record", " WHERE kind='migration_identity'")
        before = self.args.work_dir/"before-database-row-hashes.json"
        before.write_bytes(raw_json(snapshots)); before.chmod(0o600)
        self.events = table_rows(self.b.host, "events", "*")
        body = {"proposal_id":self.proposal, "person_public_key":self.person, "approve":False}
        def preview():
            before = all_database_snapshots(self.b.host.state)
            self.wrapper(self.call("/device-bans", body), pending=True)
            again = self.call("/device-bans", body); self.wrapper(again, pending=True)
            require(again["signing_requests"] == [] and self.copy_intents() == [] and all_database_snapshots(self.b.host.state) == before,
                "explicitly pure copy preview created intent/signature/key/clock or changed state")
            self.inert()
        self.b.case(CASES[0], preview)
        def refuse():
            before = all_database_snapshots(self.b.host.state)
            empty = self.call("/device-bans", dict(body, person_public_key=self.f["writer_person_public_key"]))
            self.wrapper(empty, pending=True, person=self.f["writer_person_public_key"])
            require(empty["review"]["copies"] == empty["signing_requests"] == [], "empty admitted owner acquired a copy")
            denied = self.call("/device-bans", dict(body, person_public_key=self.keys.public("M07-foreign-unadmitted")), status=403)
            self.b.error(denied, "forbidden")
            for field in ("targets", "body_base64", "signature", "unknown"):
                denied = self.call("/device-bans", dict(body, **{field:[] if field == "targets" else "-"}), status=400)
                self.b.error(denied, "invalid")
            require(all_database_snapshots(self.b.host.state) == before and not self.copy_intents(), "foreign/new-target refusals changed pure state")
            self.inert()
        self.b.case(CASES[1], refuse)
        def approve_sign():
            self.approved_at = stamp(self.now)
            value = self.call("/device-bans", dict(body, approve=True)); self.wrapper(value)
            identifier, record = self.intent_and_templates()
            require(not record["completed"] and record["signatures"] == [], "copy signed before external original possession")
            self.b.host.stop(); self.now += timedelta(seconds=301)
            require(self.now < moment(self.f["proposal_window"][1]), "source proposal cannot fit the frozen301-second signing check")
            self.clock.write_text(stamp(self.now)); self.clock.chmod(0o600); self.b.host.start()
            value = self.call("/resume", {}); self.wrapper(value)
            wrong_done = False
            for _ in range(8):
                identifier, record = self.intent_and_templates()
                if record["completed"]: break
                slots = value["signing_requests"]; require(0 < len(slots) <= 16, "missing/unbounded external original copy slots")
                batch = []
                for slot in slots:
                    require(set(slot) == SLOT_FIELDS and slot["intent_id"] == identifier and slot["object_type"] == "device_revoke" and
                        slot["role"] == "issuer" and slot["public_key"] == self.person and slot["format"] == "sshsig" and
                        slot["template_base64"] == self.templates[slot["slot_id"]], "ready slot chose another kind/key/template")
                    expected = lines("peerspan-decentralized-signature-v1", statement_id(strict_output(unb64(slot["template_base64"]))), "issuer", self.person)
                    require(slot["object_id"] == statement_id(strict_output(unb64(slot["template_base64"]))) and unb64(slot["message_base64"]) == expected,
                        "ready copy message/DS differs")
                    if not wrong_done:
                        denied = self.call("/signed", {"intent_id":identifier, "signatures":[{"slot_id":slot["slot_id"], "role":"host", "signature":"-"}]}, status=400)
                        self.b.error(denied, "invalid")
                        wrong = b64(self.keys.sshsig("M07-wrong-original", expected))
                        denied = self.call("/signed", {"intent_id":identifier, "signatures":[{"slot_id":slot["slot_id"], "role":"issuer", "signature":wrong}]}, status=400)
                        self.b.error(denied, "invalid"); wrong_done = True
                        require(self.intent_and_templates()[1]["signatures"] == [], "wrong role/key populated a signature")
                    signature = external_original_signature(self.original, expected, self.signer_home, "copy-slot-%d" % slot["slot_id"])
                    Introduction.verify_original(self, signature, expected)
                    submitted = {"slot_id":slot["slot_id"], "role":"issuer", "signature":signature}
                    batch.append(submitted); self.submitted[slot["slot_id"]] = submitted
                value = self.call("/signed", {"intent_id":identifier, "signatures":batch}); self.wrapper(value)
            else: raise CheckFailure("copy signing exceeded8 dependency batches")
            require(self.intent_and_templates()[1]["completed"], "all exact copy signatures did not complete")
            self.inert()
            self.trace.append({"writer_person":self.f["writer_person_public_key"], "external_copy_person":self.person,
                "approved_at_unchanged":self.approved_at, "signature_decision_time":stamp(self.now), "original_key_remained_in_own_signer_fixture":True})
        self.b.case(CASES[2], approve_sign)
        def history():
            identifier, record = self.intent_and_templates(); exact = record
            first = self.call("/evidence", method="GET")
            self.wrapper(self.call("/device-bans", dict(body, approve=True)))
            self.wrapper(self.call("/signed", {"intent_id":identifier, "signatures":[self.submitted[k] for k in sorted(self.submitted)]}))
            self.b.host.stop(); self.b.host.start()
            require(self.intent_and_templates()[1] == exact and self.call("/evidence", method="GET") == first, "completed copy retry/restart rewrote exact template/signature/source")
            catalog = strict_output(unb64(first["prepared_catalog_base64"])); found = {}
            for entry in catalog["objects"]:
                if entry["kind"] != "device_revoke": continue
                statement = strict_output(unb64(entry["body_base64"])); payload = strict_output(unb64(statement["payload_base64"]))
                if payload["issuer"]["person_public_key"] != self.person: continue
                ds = statement_id(statement); signature = statement["signatures"]
                require(len(signature) == 1 and signature[0]["role"] == "issuer" and signature[0]["public_key"] == self.person and
                    signature[0]["format"] == "sshsig" and signature[0]["signature"] != "-", "public copy is partial or another authority")
                Introduction.verify_original(self, signature[0]["signature"], lines("peerspan-decentralized-signature-v1", ds, "issuer", self.person))
                found[payload["target"]["device_public_key"]] = {"statement_id":ds, "proof_id":entry["id"], "body_sha256":sha(unb64(entry["body_base64"]))}
            require(set(found) == set(self.f["source_targets"]), "public prepared catalog omitted/added completed copies")
            for field in ("proposal_base64", "source_catalog_base64", "source_state_base64"):
                require(first[field] == self.f["evidence"][field], "copy publication changed original endorsed component")
            self.inert(); self.trace.append({"complete_prepared_copies":found, "all_source_maxima":self.f["access_maxima"],
                "no_provider_ACK_fence_adoption_or_whole_owned_M_claim":True})
        self.b.case(CASES[3], history)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("host", "fixture-dir", "work-dir", "results"): parser.add_argument("--"+name, type=Path, required=True)
    parser.add_argument("--source", required=True); parser.add_argument("--fixture-sha256", required=True); args = parser.parse_args()
    for name in ("host", "fixture_dir", "work_dir", "results"): setattr(args, name, getattr(args, name).resolve())
    args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    keys = FixtureKeys(); suite = None; failure = detail = None; began = time.monotonic()
    try:
        suite = Copies(args, keys); suite.run()
    except BaseException as error:
        failure = type(error).__name__; detail = str(error) if isinstance(error, CheckFailure) else "fixture/transport failure"
        diagnostic = args.work_dir/"failure.traceback.private"
        diagnostic.write_text(traceback.format_exc()); diagnostic.chmod(0o600)
    finally:
        if suite is not None: suite.b.host.stop()
        keys.close()
    value = {"contract_pin":PIN, "source":args.source, "implementation_source_read":False,
        "artifact":{"path":str(args.host), "sha256":sha(args.host.read_bytes())}, "fixture_sha256":args.fixture_sha256,
        "suite_sha256":sha(Path(__file__).read_bytes()), "spec_sha256":sha(SPEC.read_bytes()),
        "rows":[] if suite is None else suite.b.rows, "trace":[] if suite is None else suite.trace,
        "failure":failure, "detail":detail, "seconds":round(time.monotonic()-began, 3),
        "scope":"new inherited-device-ban API writer only; no pure-high-u64/runtime MAX, whole owned M, installed or final-head claim",
        "passed":failure is None and suite is not None and len(suite.b.rows) == 4 and all(v["passed"] for v in suite.b.rows)}
    args.results.parent.mkdir(parents=True, exist_ok=True); args.results.write_text(json.dumps(value, indent=2)+"\n")
    return 0 if value["passed"] else 1


if __name__ == "__main__": raise SystemExit(main())
