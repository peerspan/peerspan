#!/usr/bin/env python3
"""Same-H4 unbound-only ACK/fence/root-commit/adoption, public contracts only.

Actual U root/host keys stay in place. No H4 test function is called, no source
or proposal is recreated, and no person/device or seven-stage flow is invented.
This is not an owned/three-host migration or an atomic crash-boundary claim.
"""
from __future__ import annotations

import argparse
import copy
from datetime import timedelta
import json
from pathlib import Path
import time

from decentralized_complete_link import statement_id, table_rows
from decentralized_fixtures import FixtureKeys, b64, lines, raw_json, sha, unb64
from decentralized_migration_host_lease import HostLease
from decentralized_migration_identity import moment, stamp
from decentralized_owner_preview import authority_rows
from decentralized_runtime import SLOT_FIELDS
from decentralized_storage import CheckFailure, UnixHTTP, all_database_snapshots, require
from decentralized_vectors import strict_output


PIN = "5871eb080c15e102a1369583fea6a8e6a89ebea8"
SPEC = Path(__file__).with_name("decentralized_unbound_migration_cases.json")
FREEZE = json.loads(SPEC.read_bytes())
CASES = [c["name"] for c in FREEZE["cases"]]
FIELDS = {"proposal_base64", "source_catalog_base64", "source_state_base64", "prepared_catalog_base64", "acknowledgments_base64", "commit_base64"}


class Unbound(HostLease):
    def __init__(self, args, keys):
        super().__init__(args, keys)
        rows = table_rows(self.target.host, "dec_migrations", "proposal_id,record")
        require(len(rows) == 1, "same H4 state lacks one exact original migration")
        self.original = strict_output(rows[0][1].encode())
        self.proposal = rows[0][0]; fixture = FREEZE["fixture"]
        acknowledged = bool(args.after_acknowledged_from)
        require(self.proposal == fixture["proposal_id"] and self.original["approved"] and self.original["fenced"] == acknowledged and
                (self.original["local_acknowledgment_base64"] != "-") == acknowledged and
                self.original["commit_base64"] == self.original["migration_base64"] == "-",
                "same H4 fixture changed proposal/participation or already crossed ACK")
        proposal = strict_output(unb64(self.original["proposal_base64"])); payload = strict_output(unb64(proposal["payload_base64"]))
        root = strict_output(unb64(self.original["initial_root_state_base64"]))
        self.context, self.root_id = proposal["context_id"], statement_id(root)
        self.root_key = payload["legacy_root_public_key"]
        self.proposal_window = (payload["issued_at"], payload["expires_at"])
        require(self.context == fixture["context_id"] and self.root_id == fixture["root_state_id"] and
                payload["roster"] == self.roster and moment(payload["issued_at"]) <= self.now < moment(payload["expires_at"]),
                "same H4 context/root/host-only roster/window differs")
        self.host_id = fixture["host_lease_id"]
        self.counter = 0

    def raw_call(self, suffix, data, status):
        self.counter += 1
        client = UnixHTTP(self.target.host.state/"admin.sock", timeout=35)
        try:
            client.request("POST", self.route+suffix, body=data, headers={"Content-Type":"application/json"})
            response = client.getresponse(); body = response.read(32*1024*1024+1)
            out = self.args.work_dir/("wire-%03d.json" % self.counter)
            out.write_bytes(body); out.chmod(0o600)
            out.with_suffix(".meta.json").write_bytes(raw_json({"path":self.route+suffix, "status":response.status,
                "request_sha256":sha(data), "response_sha256":sha(body)}))
            require(response.status == status and len(body) <= 32*1024*1024, "migration raw carrier returned unexpected status/limit")
            return strict_output(body)
        finally: client.close()

    def migration(self):
        rows = table_rows(self.target.host, "dec_migrations", "record", " WHERE proposal_id=?", (self.proposal,))
        require(len(rows) == 1, "exact original migration disappeared/duplicated")
        return strict_output(rows[0][0].encode())

    def named_preparation_rows(self):
        """Exact documented private metadata only; never export a seed."""
        intents = {}
        for identifier, network, context, kind, encoded, secret in table_rows(self.target.host, "dec_intents",
                "intent_id,network_id,context_id,kind,record,secret"):
            intents[identifier] = {"network_id":network, "context_id":context, "kind":kind,
                "record":strict_output(encoded.encode()), "secret_is_null":secret is None,
                "secret_sha256":None if secret is None else sha(secret)}
        return {"dec_intents":intents,
            "dec_migrations":{network+"/"+proposal:strict_output(encoded.encode()) for network, proposal, encoded in
                table_rows(self.target.host, "dec_migrations", "network_id,proposal_id,record")},
            "dec_clock":{network:strict_output(encoded.encode()) for network, encoded in
                table_rows(self.target.host, "dec_clock", "network_id,record")}}

    def ack_preview_changes(self, before, named_before, after, named_after, label, *, root_commit=False):
        """M08/M09 permit one exact unapproved intent/reference and guard."""
        path = self.args.work_dir/(label+"-named-rows.private.json")
        changed = {table:[key for key in sorted(set(named_before[table]) | set(named_after[table]))
            if named_before[table].get(key) != named_after[table].get(key)] for table in named_before}
        path.write_bytes(raw_json({"before":named_before, "after":named_after, "changed_rows":changed})); path.chmod(0o600)
        # Preserve all table definitions/versions and every unrelated exact row.
        require(set(before["databases"]) == set(after["databases"]), "ACK preview changed the database set")
        for database, old in before["databases"].items():
            current = after["databases"][database]
            require(old["user_version"] == current["user_version"] and set(old["tables"]) == set(current["tables"]),
                "ACK preview changed schema/version")
            for table, rows in old["tables"].items():
                require(rows["ddl_sha256"] == current["tables"][table]["ddl_sha256"], "ACK preview changed table DDL")
                if table not in named_before:
                    require(rows == current["tables"][table], "ACK preview changed unrelated table "+table)
        migration_key = self.network+"/"+self.proposal
        old_m = named_before["dec_migrations"][migration_key]; new_m = named_after["dec_migrations"][migration_key]
        reference = "root_intent_ids" if root_commit else "local_ack_intent_id"
        if root_commit:
            old_refs, new_refs = old_m[reference], new_m[reference]
            require(new_refs[:len(old_refs)] == old_refs and len(new_refs)-len(old_refs) in (0, 1),
                    "root commit preview replaced/reordered another root intent")
            matches = [key for key in new_refs if key in named_after["dec_intents"] and
                any(t["object_type"] == "migration_commit" for t in named_after["dec_intents"][key]["record"]["templates"])]
            require(len(matches) <= 1, "root commit preview duplicated its typed intent")
            identifier = matches[0] if matches else "-"
            require(not new_refs[len(old_refs):] or new_refs[len(old_refs):] == [identifier], "root preview appended another intent kind")
        else:
            identifier = new_m[reference]
        require(changed["dec_migrations"] in ([], [migration_key]) and
                {k:v for k,v in old_m.items() if k != reference} ==
                {k:v for k,v in new_m.items() if k != reference} and
                (root_commit or old_m[reference] in ("-", identifier)), "preview changed other migration state or replaced its intent")
        require(changed["dec_intents"] in ([], [identifier]) and set(named_before["dec_intents"]) <= set(named_after["dec_intents"]),
                "ACK preview changed an unrelated intent")
        if identifier != "-":
            row = named_after["dec_intents"][identifier]; record = row["record"]
            require(row["network_id"] == self.network and row["context_id"] == self.context and row["kind"] == "migration" and
                    row["secret_is_null"] and record["operation_id"] == self.proposal and not record["approved"] and
                    record["approved_at"] == "-" and record["signatures"] == [] and not record["completed"] and
                    record["terminal"] == record["result_base64"] == "-" and record["root_state_id"] == self.root_id and
                    record["host_public_key"] == ("-" if root_commit else self.spec["host_public_key"]) and record["person_public_key"] ==
                    record["device_public_key"] == "-" and record["scopes"] == (8 if root_commit else 0) and
                    (not root_commit or record["not_after"] == "-") and record["provider"] ==
                    {"kind":"root" if root_commit else "host", "signer_public_key":self.root_key if root_commit else self.spec["host_public_key"],
                     "signature_format":"ed25519", "lease_id":"-"},
                    "typed migration preview acquired approval/signature/completion/secret or another subject/selector")
            templates = record["templates"]
            kind = "migration_commit" if root_commit else "migration_ack"
            role, key = ("issuer", self.root_key) if root_commit else ("host", self.spec["host_public_key"])
            require(len(templates) == 1 and templates[0]["slot_id"] == 1 and templates[0]["object_type"] == kind,
                    "ACK preview retained an unrelated template")
            template = strict_output(unb64(templates[0]["template_base64"]))
            payload = strict_output(unb64(template["payload_base64"]))
            expected = {"proposal_id":self.proposal, "root_state_id":self.root_id, "prepared_catalog_sha256":self.prepared_hash,
                    "host_public_key":self.spec["host_public_key"], "host_lease_id":self.host_id,
                    **{k:"-" for k in ("person_public_key", "device_public_key", "binding_lease_id", "device_lease_id", "activation_id")},
                    "acknowledged_at":payload.get("acknowledged_at")}
            if root_commit:
                expected = {"proposal_id":self.proposal, "root_state_id":self.root_id, "prepared_catalog_sha256":self.prepared_hash,
                    "acknowledgment_ids":[self.ack_id], "committed_at":payload.get("committed_at")}
                require(moment(self.proposal_window[0]) <= moment(payload["committed_at"]) < moment(self.proposal_window[1]),
                        "root preview time is outside the original proposal window")
            require(template["kind"] == kind and template["context_id"] == self.context and
                    template["signatures"] == [{"role":role, "public_key":key, "format":"ed25519", "signature":"-"}] and
                    payload == expected, "preview template changed the fixed full-catalog/actual signer pins")
            if identifier in named_before["dec_intents"]:
                require(named_before["dec_intents"][identifier] == row, "exact ACK preview retry replaced its fixed template/review")
            if root_commit: self.commit_template = templates[0]["template_base64"]
            else: self.ack_template = templates[0]["template_base64"]
        else:
            require(changed["dec_intents"] == changed["dec_migrations"] == [], "read-only ACK preview changed intent/reference")
        require(changed["dec_clock"] in ([], [self.network]), "ACK preview changed an unrelated clock")
        if changed["dec_clock"]:
            anchor = named_after["dec_clock"][self.network]
            require(set(anchor) == {"format", "largest_local_time"} and anchor["format"] == 1 and
                    moment(anchor["largest_local_time"]) == self.now and
                    (self.network not in named_before["dec_clock"] or moment(named_before["dec_clock"][self.network]["largest_local_time"]) <= self.now),
                    "ACK preview rewound or advanced clock beyond the guarded decision")
        self.trace.append({"M09_named_changed_rows" if root_commit else "M08_named_changed_rows":changed, "capture":str(path),
            "only_exact_unapproved_typed_preparation_permitted":True, "prior_approvals_unchanged":True})

    def evidence(self):
        value = self.call("GET", "/evidence")
        require(set(value) == FIELDS and isinstance(value["acknowledgments_base64"], list), "evidence is not exact six-field Base64 carrier")
        caps = {"proposal_base64":1024*1024, "source_catalog_base64":512*1024, "source_state_base64":256*1024,
                "prepared_catalog_base64":1024*1024, "commit_base64":1024*1024}
        for field, cap in caps.items():
            encoded = value[field]
            require(type(encoded) is str, "byte field is not string")
            if encoded != "-":
                raw = unb64(encoded); require(len(raw) <= cap and b64(raw) == encoded, "evidence byte field cap/canonical Base64 differs")
        require(len(value["acknowledgments_base64"]) <= 4096 and all(isinstance(v, str) and v != "-" and
            len(unb64(v)) <= 1024*1024 and b64(unb64(v)) == v for v in value["acknowledgments_base64"]), "ACK byte-array bounds/encoding differ")
        for field in ("proposal_base64", "source_catalog_base64", "source_state_base64"):
            require(value[field] == self.original[field], "public evidence rewrote original endorsed proposal/source bytes")
        return value

    def signed_statement(self, encoded, kind, role, key):
        value = strict_output(unb64(encoded)); identifier = statement_id(value)
        require(value["kind"] == kind and value["context_id"] == self.context and
            value["signatures"] == [{"role":role, "public_key":key, "format":"ed25519", "signature":value["signatures"][0]["signature"]}],
            "typed migration signature kind/context/actual role/key differs")
        self.target.verify_raw(key, lines("peerspan-decentralized-signature-v1", identifier, role, key), value["signatures"][0]["signature"])
        return identifier, strict_output(unb64(value["payload_base64"]))

    def inert(self):
        require(authority_rows(self.target) == self.authority_before and
            not table_rows(self.target.host, "dec_signers", "network_id") and not table_rows(self.target.host, "dec_operations", "request_id"),
            "unbound pending migration installed ordinary context/provider/outcome")
        require(table_rows(self.target.host, "dec_intents", "intent_id,record,secret", " WHERE kind='migration_identity'") == self.identity,
            "ACK preparation copied/replaced original host-only identity")

    def advance(self, predicate, kind, role, key):
        for _ in range(8):
            if predicate(): return
            value = self.call("POST", "/resume", {})
            for slot in value["signing_requests"]:
                require(set(slot) == SLOT_FIELDS and slot["object_type"] == kind and slot["role"] == role and
                    slot["public_key"] == key and slot["format"] == "ed25519", "resume exposed unrelated migration signing authority")
                template = strict_output(unb64(slot["template_base64"])); identifier = statement_id(template)
                require(slot["object_id"] == identifier and unb64(slot["message_base64"]) ==
                    lines("peerspan-decentralized-signature-v1", identifier, role, key), "ready slot changed exact typed signing message")
        raise CheckFailure("approved owned migration role did not complete within8 dependency batches")

    def run(self):
        self.target.host.start(); self.target.identity = self.target.host.api("GET", "/v1/host")
        require(self.target.identity["public_key"] == self.spec["host_public_key"], "opening replaced actual U host key")
        self.authority_before = authority_rows(self.target)
        self.before = all_database_snapshots(self.target.host.state)
        self.trace.append({"H4_test_functions_skipped":True, "same_original_source_proposal_complete_H_and_host_keys":True,
            "original_proposal_id":self.proposal, "clock":stamp(self.now), "no_host_or_root_private_key_read":True})

        def carrier():
            before = all_database_snapshots(self.target.host.state); value = self.evidence()
            require(all_database_snapshots(self.target.host.state) == before, "evidence GET changed durable state")
            require(value["prepared_catalog_base64"] != "-", "H4 completed proof set is unavailable through public export")
            catalog = strict_output(unb64(value["prepared_catalog_base64"]))
            hosts = [o for o in catalog["objects"] if o["kind"] == "host_lease" and
                     statement_id(strict_output(unb64(o["body_base64"]))) == self.host_id]
            require(len(hosts) == 1 and sha(unb64(hosts[0]["body_base64"])) == FREEZE["fixture"]["completed_host_lease_sha256"],
                "prepared export lost/rewrote exact completed H4 host lease")
            self.parse_h(unb64(hosts[0]["body_base64"]), complete=True)
            self.prepared = value["prepared_catalog_base64"]; self.prepared_hash = sha(unb64(self.prepared))
            require(value["acknowledgments_base64"] == [] and value["commit_base64"] == "-", "public carrier invented ACK/commit")
            for payload in [dict(value, proposal_base64=value["proposal_base64"]+"\n"), dict(value, unknown=True),
                            {"proposal":strict_output(unb64(value["proposal_base64"])), "catalog":catalog}]:
                denied = self.raw_call("/evidence", raw_json(payload), 400)
                require(denied.get("code") == "invalid", "malformed/old-inline carrier did not report invalid")
            duplicate = raw_json(value)[:-1]+b',"commit_base64":"-"}'
            require(self.raw_call("/evidence", duplicate, 400).get("code") == "invalid", "duplicate evidence field accepted")
            partial = copy.deepcopy(catalog)
            entry = next(o for o in partial["objects"] if o["id"] == hosts[0]["id"])
            body = strict_output(unb64(entry["body_base64"]))
            for signature in body["signatures"]:
                if signature["role"] == "host": signature["signature"] = "-"
            raw = raw_json(body); entry["body_base64"] = b64(raw)
            entry["id"] = "dp_"+sha(lines("peerspan-decentralized-proof-v1", "host_lease", sha(raw)))
            partial["objects"].sort(key=lambda o:(o["kind"], o["id"]))
            bad = dict(value, prepared_catalog_base64=b64(raw_json(partial)))
            require(self.raw_call("/evidence", raw_json(bad), 400).get("code") == "invalid", "partial public H supplied ACK preparation")
            # Outer spelling only; exact components and authority stay fixed.
            outer = json.dumps({k:value[k] for k in reversed(value)}, indent=2).replace("/", "\\/").encode()
            self.raw_call("/evidence", outer, 200)
            require(self.evidence() == value and not self.migration()["fenced"], "carrier roundtrip changed exact bytes or supplied fence")
            self.inert()
        if self.args.after_acknowledged_from:
            value = self.evidence(); self.prepared = value["prepared_catalog_base64"]; self.prepared_hash = sha(unb64(self.prepared))
            require(self.prepared_hash == FREEZE["fixture"]["prepared_catalog_sha256"] and
                    value["acknowledgments_base64"] == [self.original["local_acknowledgment_base64"]] and value["commit_base64"] == "-",
                    "acknowledged continuation changed exact prepared/ACK/commit pins")
            self.ack = self.original["local_acknowledgment_base64"]
            self.ack_id, payload = self.signed_statement(self.ack, "migration_ack", "host", self.spec["host_public_key"])
            require(payload == {"proposal_id":self.proposal, "root_state_id":self.root_id, "prepared_catalog_sha256":self.prepared_hash,
                "host_public_key":self.spec["host_public_key"], "host_lease_id":self.host_id,
                **{k:"-" for k in ("person_public_key", "device_public_key", "binding_lease_id", "device_lease_id", "activation_id")},
                "acknowledged_at":payload["acknowledged_at"]}, "retained exact actual host ACK changed unbound pins")
            self.trace.append({"carrier_H4_ACK_preview_approval_signature_restart_functions_all_skipped":True,
                "retained_exact_ACK_sha256":sha(unb64(self.ack)), "retained_ACK_id":self.ack_id,
                "same_existing_fence":True, "no_ACK_reapproval_or_signature_replay":True})
        elif self.args.after_ack_preview_from:
            previous = strict_output((self.args.after_ack_preview_from/"target"/"public-responses"/"003.json").read_bytes())
            value = self.evidence(); self.prepared = value["prepared_catalog_base64"]; self.prepared_hash = sha(unb64(self.prepared))
            require(self.prepared_hash == previous["review"]["prepared_catalog_sha256"] and
                    value["acknowledgments_base64"] == [] and value["commit_base64"] == "-", "same failed ACK preview changed fixed prepared bytes")
            self.trace.append({"passed_carrier_case_skipped":True, "original_oracle_overconstraint_receipt":
                "/tmp/peerspan-dec-migration-unbound-first/results.json", "prepared_catalog_sha256":self.prepared_hash})
        else:
            self.target.case(CASES[0], carrier)

        self.ack_body = {"proposal_id":self.proposal, "prepared_catalog_sha256":self.prepared_hash, "approve":False}
        def preview():
            before = all_database_snapshots(self.target.host.state); named_before = self.named_preparation_rows()
            value = self.call("POST", "/acknowledgment", self.ack_body)
            require(value["review"]["stage"] == "acknowledgment" and value["review"]["prepared_catalog_sha256"] == self.prepared_hash and
                value["review"]["roster"] == self.roster and not value["migration"]["fenced"] and value["signing_requests"] == [],
                "ACK preview changed complete review or supplied consent/signature/fence")
            self.ack_preview_changes(before, named_before, all_database_snapshots(self.target.host.state),
                self.named_preparation_rows(), "ACK-preview-first")
            before = all_database_snapshots(self.target.host.state); named_before = self.named_preparation_rows()
            repeated = self.call("POST", "/acknowledgment", self.ack_body)
            require(repeated["signing_requests"] == [] and not repeated["migration"]["fenced"], "exact unapproved ACK retry supplied signature/fence")
            self.ack_preview_changes(before, named_before, all_database_snapshots(self.target.host.state),
                self.named_preparation_rows(), "ACK-preview-retry")
            self.inert()
        if not self.args.after_acknowledged_from: self.target.case(CASES[1], preview)

        def ack():
            self.call("POST", "/acknowledgment", dict(self.ack_body, approve=True))
            self.advance(lambda:self.migration()["local_acknowledgment_base64"] != "-", "migration_ack", "host", self.spec["host_public_key"])
            record = self.migration(); self.ack = record["local_acknowledgment_base64"]
            self.ack_id, payload = self.signed_statement(self.ack, "migration_ack", "host", self.spec["host_public_key"])
            expected = {"proposal_id":self.proposal, "root_state_id":self.root_id, "prepared_catalog_sha256":self.prepared_hash,
                "host_public_key":self.spec["host_public_key"], "host_lease_id":self.host_id,
                **{k:"-" for k in ("person_public_key", "device_public_key", "binding_lease_id", "device_lease_id", "activation_id")},
                "acknowledged_at":payload["acknowledged_at"]}
            require(payload == expected and record["fenced"] and record["commit_base64"] == "-", "unbound ACK has wrong exact H/owner fields or lacks durable separate fence")
            self.target.host.stop(); self.target.host.start()
            old_clock = stamp(self.now)
            self.now += timedelta(seconds=301)
            require(self.now < moment(self.proposal_window[1]), "same proposal has no remaining301-second signing interval")
            self.clock.write_text(stamp(self.now)); self.clock.chmod(0o600)
            self.call("POST", "/acknowledgment", dict(self.ack_body, approve=True))
            require(self.migration()["local_acknowledgment_base64"] == self.ack and self.migration()["fenced"], "restart/exact ACK retry changed signature/time/fence")
            self.inert()
            self.trace.append({"post_ACK_clock_before":old_clock, "post_ACK_clock_after":stamp(self.now),
                "same_ACK_signature_time_hash_and_fence_preserved":True, "original_proposal_deadline_not_extended":True})
        if not self.args.after_acknowledged_from: self.target.case(CASES[2], ack)
        if self.args.stop_after_ack:
            self.trace.append({"root_commit_preview_held_until_its_reviewed_literal_pin":True})
            return

        def commit_adopt():
            body = {"proposal_id":self.proposal, "prepared_catalog_sha256":self.prepared_hash,
                "acknowledgment_ids":[self.ack_id], "signature_format":"ed25519", "approve":False}
            before = all_database_snapshots(self.target.host.state); named_before = self.named_preparation_rows()
            preview = self.call("POST", "/commit", body)
            require(preview["signing_requests"] == [] and preview["migration"]["fenced"] and preview["migration"]["root_commit_id"] == "-",
                "root commit preview signed, unfenced or supplied public commit")
            self.ack_preview_changes(before, named_before, all_database_snapshots(self.target.host.state),
                self.named_preparation_rows(), "root-commit-preview-first", root_commit=True)
            before = all_database_snapshots(self.target.host.state); named_before = self.named_preparation_rows()
            repeated = self.call("POST", "/commit", body)
            require(repeated["signing_requests"] == [] and repeated["migration"]["fenced"] and repeated["migration"]["root_commit_id"] == "-",
                "exact unapproved commit retry supplied signature/commit or changed fence")
            self.ack_preview_changes(before, named_before, all_database_snapshots(self.target.host.state),
                self.named_preparation_rows(), "root-commit-preview-retry", root_commit=True)
            self.call("POST", "/commit", dict(body, approve=True))
            self.advance(lambda:self.migration()["commit_base64"] != "-", "migration_commit", "issuer", self.root_key)
            self.commit = self.migration()["commit_base64"]
            self.commit_id, payload = self.signed_statement(self.commit, "migration_commit", "issuer", self.root_key)
            if hasattr(self, "commit_template"):
                require(statement_id(strict_output(unb64(self.commit_template))) == self.commit_id,
                        "root approval/signature replaced the exact previewed commit template")
            require(set(payload) == {"proposal_id", "root_state_id", "prepared_catalog_sha256", "acknowledgment_ids", "committed_at"} and
                payload["proposal_id"] == self.proposal and payload["root_state_id"] == self.root_id and
                payload["prepared_catalog_sha256"] == self.prepared_hash and payload["acknowledgment_ids"] == [self.ack_id],
                "root commit changed the exact proposal/hash/all-host ACK set")
            # ACK explicitly preapproved exact eventual adoption; it may already
            # have occurred during approved-work resume. Do not invent a third
            # mandatory consent or depend on an intermediate no-adoption state.
            if self.migration()["state"] != "adopted":
                self.call("POST", "/adopt", {"proposal_id":self.proposal, "commit_id":self.commit_id, "approve":True})
            require(self.migration()["state"] == "adopted", "complete unbound migration did not adopt")
            network = self.target.api("GET", "/v2/networks/"+self.network)[0]
            require(network["mode"] == "decentralized" and network["context_id"] == self.context and
                network["person_public_key"] == "-" and network["host_public_key"] == self.spec["host_public_key"], "adoption manufactured an owner or changed original U tuple")
            require(not table_rows(self.target.host, "dec_signers", "network_id") and
                not table_rows(self.target.host, "dec_operations", "request_id") and
                not table_rows(self.target.host, "link_device_keys", "public_key"), "unbound adoption invented provider/device/participant outcome")
            contexts = table_rows(self.target.host, "dec_contexts", "record")
            require(len(contexts) == 1 and strict_output(contexts[0][0].encode())["origin"] == "migration", "adoption lacks exact migration origin pin")
            events = self.target.host.api("GET", "/v1/activity?limit=1000")
            require(sum(v["kind"] == "network.migrated" for v in events) == 1 and
                not any(v["kind"] == "network.link_applied" for v in events), "migration lost/duplicated event or fabricated per-host link apply")
            after = all_database_snapshots(self.target.host.state)
            writable = {"networks", "network_members", "events", "dec_contexts", "dec_objects", "dec_admissions", "dec_restrictions",
                "dec_activations", "dec_heads", "dec_highwater", "dec_signers", "dec_clock", "dec_intents", "dec_pending",
                "dec_frames", "dec_operations", "dec_outbox", "dec_migrations", "dec_contacts", "dec_helpers"}
            for database, original in self.before["databases"].items():
                require(database in after["databases"], "adoption lost original database")
                current = after["databases"][database]
                for name, table in original["tables"].items():
                    if name not in writable:
                        require(current["tables"].get(name) == table, "adoption changed unrelated legacy/product table "+name)
            self.complete = self.evidence()
        self.target.case(CASES[3], commit_adopt)

        def history():
            before = all_database_snapshots(self.target.host.state)
            require(self.evidence() == self.complete and all_database_snapshots(self.target.host.state) == before, "adopted export is not pure exact history")
            self.raw_call("/evidence", raw_json(self.complete), 200)
            self.call("POST", "/adopt", {"proposal_id":self.proposal, "commit_id":self.commit_id, "approve":True})
            self.target.host.stop(); self.target.host.start()
            require(self.evidence() == self.complete, "restart changed original exported transition")
            events = self.target.host.api("GET", "/v1/activity?limit=1000")
            require(sum(v["kind"] == "network.migrated" for v in events) == 1 and
                not table_rows(self.target.host, "dec_signers", "network_id"), "historical retry changed provider or duplicated adoption")
            before = all_database_snapshots(self.target.host.state)
            denied = self.call("POST", "/adopt", {"proposal_id":self.proposal, "commit_id":self.root_id, "approve":True}, status=409)
            require(denied.get("code") == "operation_conflict" and all_database_snapshots(self.target.host.state) == before,
                "changed adopted commit identity did not conflict without mutation")
            self.trace.append({"proposal_id":self.proposal, "acknowledgment_id":self.ack_id, "commit_id":self.commit_id,
                "prepared_catalog_sha256":self.prepared_hash, "unbound_only":True,
                "no_owned_seven_stage_or_crash_atomicity_claim":True})
        self.target.case(CASES[4], history)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("host", "fixture-dir", "work-dir", "results"): parser.add_argument("--"+name, type=Path, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--after-ack-preview-from", type=Path, help="Skip passed carrier1; continue failed M08 preview and3 unevaluated cases on the same original U/prepared state")
    parser.add_argument("--stop-after-ack", action="store_true", help="Execute only failed M08 preview and previously unevaluated ACK/fence; root-commit preview/history remain held")
    parser.add_argument("--after-acknowledged-from", type=Path, help="Only previously unevaluated root commit/adoption/history on the exact acknowledged/fenced original U; no ACK approval/signature replay")
    args = parser.parse_args()
    for name in ("host", "fixture_dir", "work_dir", "results"): setattr(args, name, getattr(args, name).resolve())
    if args.after_ack_preview_from and args.after_acknowledged_from: parser.error("continuation boundaries are distinct")
    retained = args.after_ack_preview_from or args.after_acknowledged_from
    args.after_partial_dir = None if retained is None else retained.resolve()
    if args.after_ack_preview_from: args.after_ack_preview_from = args.after_partial_dir
    if args.after_acknowledged_from: args.after_acknowledged_from = args.after_partial_dir
    if args.stop_after_ack and not args.after_ack_preview_from: parser.error("bounded ACK continuation requires the retained failed-preview fixture")
    args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False); (args.work_dir/"target").mkdir(mode=0o700)
    keys = FixtureKeys(); suite = None; failure = detail = None; began = time.monotonic()
    try:
        suite = Unbound(args, keys); suite.run()
    except BaseException as error:
        failure = type(error).__name__; detail = str(error) if isinstance(error, CheckFailure) else "fixture/transport failure"
    finally:
        if suite is not None:
            try: suite.target.host.stop()
            except BaseException as error: failure = failure or type(error).__name__
        keys.close()
    result = {"contract_pin":PIN, "implementation_source_read":False, "source":args.source,
        "artifact":{"path":str(args.host), "sha256":sha(args.host.read_bytes())}, "spec_sha256":sha(SPEC.read_bytes()),
        "suite_sha256":sha(Path(__file__).read_bytes()), "rows":[] if suite is None else suite.target.rows,
        "trace":[] if suite is None else suite.trace, "failure":failure, "detail":detail, "seconds":round(time.monotonic()-began, 3),
        "scope":"same-H4-U unbound migration only; no H4 test function, person/device/owned stage or crash-atomicity replay",
        "after_ack_preview_from":None if args.after_ack_preview_from is None else str(args.after_ack_preview_from),
        "stop_after_ack":args.stop_after_ack,
        "after_acknowledged_from":None if args.after_acknowledged_from is None else str(args.after_acknowledged_from),
        "passed":failure is None and suite is not None and len(suite.target.rows) == (2 if args.stop_after_ack or args.after_acknowledged_from else 4 if args.after_ack_preview_from else 5) and all(v["passed"] for v in suite.target.rows)}
    args.results.parent.mkdir(parents=True, exist_ok=True); args.results.write_text(json.dumps(result, indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__": raise SystemExit(main())
