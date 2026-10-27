#!/usr/bin/env python3
"""Independent ONE-roster/three-actual-host owned whole migration acceptance.

Prepare/freeze only until the parent offers exact reviewed runtime artifacts.
Authority is constructed through public writers, never copied stores or SQL.
Named normative reads below are postcondition/hash oracles, never setup writes.
The historical inline evidence helper is deliberately not used.
"""
from __future__ import annotations

import argparse
import ast
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import socket
import subprocess
import threading
import time
import traceback
from types import SimpleNamespace

from decentralized_complete_link import packet_message, statement_id, table_rows
from decentralized_fixtures import FixtureKeys, b64, lines, raw_json, sha, unb64
from decentralized_migration_device_bans_fixture import external_original_signature
from decentralized_migration_identity import ROSTER, REVIEW, VIEW, moment, stamp
from decentralized_owned_migration_fixture import OwnedLegacy
from decentralized_requester import VIEW as LINK_VIEW
from decentralized_runtime import CreationSuite, SLOT_FIELDS
from decentralized_storage import CheckFailure, UnixHTTP, all_database_snapshots, require
from decentralized_vectors import strict_output


SPEC = Path(__file__).with_name("decentralized_owned_migration_cases.json")
CASES = [row["name"] for row in strict_output(SPEC.read_bytes())["cases"]]
FIELDS = {"proposal_base64", "source_catalog_base64", "source_state_base64",
    "prepared_catalog_base64", "acknowledgments_base64", "commit_base64"}
LABELS = ("owner", "selected", "unbound")


class OwnedMigration:
    def __init__(self, args, keys):
        self.args, self.keys = args, keys
        self.instances, self.rows, self.trace, self.fixed_slots = {}, [], [], {}
        self.requests, self.stage_views, self.acks = {}, {}, {}
        self.legacy = None; self.observer = None; self.observer_thread = None
        self.observer_stop, self.coordinator_attempts = threading.Event(), []
        self.original_source = None; self.captured_partial = None

    def case(self, index, function):
        began = time.monotonic()
        try: function()
        except BaseException as error:
            self.rows.append({"name":CASES[index], "passed":False, "error_type":type(error).__name__,
                "detail":str(error) if isinstance(error, CheckFailure) else "fixture/transport failure; protected captures retained",
                "seconds":round(time.monotonic()-began, 3)})
            print("FAIL "+CASES[index], flush=True); raise
        self.rows.append({"name":CASES[index], "passed":True, "seconds":round(time.monotonic()-began, 3)})
        print("PASS "+CASES[index], flush=True)

    def api(self, label, method, path, body=None, *, statuses=(200,)):
        value = self.instances[label]
        client = UnixHTTP(value.host.state/"admin.sock", timeout=40)
        try:
            encoded = None if body is None else raw_json(body)
            client.request(method, path, body=encoded, headers={} if body is None else {"Content-Type":"application/json"})
            response = client.getresponse(); raw = response.read(32*1024*1024+1)
            value.response_count += 1; saved = value.responses/("%03d.json" % value.response_count)
            saved.write_bytes(raw); saved.chmod(0o600)
            saved.with_suffix(".meta.json").write_bytes(raw_json({"method":method, "path":path,
                "status":response.status, "body_sha256":sha(raw), "request_sha256":None if encoded is None else sha(encoded)}))
            require(len(raw) <= 32*1024*1024 and response.status in statuses,
                "owned migration API unexpected status"+str(response.status)+"; response_sha256="+sha(raw))
            return strict_output(raw), response.status
        finally: client.close()

    def call(self, label, suffix="", body=None, *, method="POST", statuses=(200,)):
        return self.api(label, method, self.route+suffix, body, statuses=statuses)[0]

    def migration(self, label):
        value = self.call(label, method="GET")
        require(set(value) == VIEW and value["network_id"] == self.network, "MIGRATION_VIEW exact fields/network differ")
        return value

    def wrapper(self, value, stage=None):
        require(set(value) == {"migration", "review", "signing_requests"} and set(value["migration"]) == VIEW and
            set(value["review"]) == REVIEW and (stage is None or value["review"]["stage"] == stage),
            "migration review wrapper/stage differs")
        return value

    def export(self, label, *, pending=False):
        value, status = self.api(label, "GET", self.route+"/evidence", statuses=(200, 404) if pending else (200,))
        if status == 404:
            require(value.get("code") == "not_found", "unsigned proposal export has another error")
            return None
        require(set(value) == FIELDS and type(value["acknowledgments_base64"]) is list,
            "public migration evidence is not STRICT six-field Base64 carrier")
        caps = {"proposal_base64":1024*1024, "source_catalog_base64":512*1024, "source_state_base64":256*1024,
            "prepared_catalog_base64":1024*1024, "commit_base64":1024*1024}
        for name, cap in caps.items():
            require(type(value[name]) is str, "component is not a string")
            if value[name] != "-":
                raw = unb64(value[name]); require(len(raw) <= cap and b64(raw) == value[name], "component bytes exceed cap or Base64 is noncanonical")
        hosts = []
        require(len(value["acknowledgments_base64"]) <= 4096, "ACK list exceeds public bound")
        for encoded in value["acknowledgments_base64"]:
            raw = unb64(encoded); require(len(raw) <= 1024*1024 and b64(raw) == encoded, "ACK bytes/encoding invalid")
            statement = strict_output(raw); require(statement["kind"] == "migration_ack", "ACK array contains wrong kind")
            hosts.append(strict_output(unb64(statement["payload_base64"]))["host_public_key"])
        require(hosts == sorted(set(hosts)), "ACK array is not sorted uniquely by decoded host key")
        if self.original_source:
            require(all(value[name] == self.original_source[name] for name in self.original_source),
                "public handoff rewrote original endorsed proposal/source bytes")
        return value

    def import_evidence(self, label, evidence):
        # Re-serialize ONLY the outer carrier; each encoded component is exact.
        return self.wrapper(self.call(label, "/evidence", strict_output(raw_json(evidence))))

    def pending(self, label, request):
        rows = table_rows(self.instances[label].host, "dec_pending", "record,secret", " WHERE request_id=?", (request,))
        require(len(rows) == 1, "exact staged pending request missing/duplicated")
        return strict_output(rows[0][0].encode()), rows[0][1]

    def key_hashes(self, label):
        # Hash only; never copy/export actual seed bytes into results or inputs.
        return {key:sha(seed) for key,seed in table_rows(self.instances[label].host, "link_device_keys", "public_key,seed")}

    def private_files(self, host):
        """Hash actual state/HOME files in place; never copy a key or store."""
        snapshots = all_database_snapshots(host.state)
        databases = {str(host.state/name)+suffix for name in snapshots["databases"]
            for suffix in ("", "-wal", "-shm", "-journal")}
        result = {}
        for label, root in (("state",host.state), ("home",Path(host.environment["HOME"]))):
            for path in sorted(root.rglob("*")):
                require(not path.is_symlink(), "unexpected private-state symlink")
                if path.is_file() and str(path) not in databases:
                    result[label+"/"+str(path.relative_to(root))] = sha(path.read_bytes())
        return result

    def custody(self):
        for label,value in self.instances.items():
            current = self.private_files(value.host)
            require(all(current.get(name) == digest for name,digest in self.source_private_files[label].items()),
                "migration changed an original private state/HOME file")
            roots = table_rows(value.host, "networks", "root_seed", " WHERE id=?", (self.network,))
            require(len(roots) == 1 and (None if roots[0][0] is None else sha(roots[0][0])) == self.source_root_hashes[label],
                "same-root migration replaced or exported an owned root seed")
            current_rows = all_database_snapshots(value.host.state)
            for name,database in self.before_upgrade[label]["databases"].items():
                require(name in current_rows["databases"], "upgrade removed an original actual database")
                for table,rows in database["tables"].items():
                    require(table in current_rows["databases"][name]["tables"] and rows["ddl_sha256"] ==
                        current_rows["databases"][name]["tables"][table]["ddl_sha256"], "upgrade changed an original table definition")
                    if table in {"network_statements", "link_objects", "link_features", "link_highwater", "link_operations", "link_signers"}:
                        require(rows == current_rows["databases"][name]["tables"][table],
                            "migration rewrote original legacy evidence/highwater/outcome/selection rows")
        require(sha(self.original_key.read_bytes()) == self.original_key_hash, "migration changed A's sole original key")

    def identity_record(self, label):
        rows = table_rows(self.instances[label].host, "dec_intents", "intent_id,record,secret", " WHERE kind='migration_identity'")
        require(len(rows) == 1, "missing/duplicate approved own identity contribution")
        identifier, encoded, secret = rows[0]
        return identifier, strict_output(encoded.encode()), None if secret is None else sha(secret)

    def inert(self):
        for label, value in self.instances.items():
            require(not table_rows(value.host, "dec_contexts", "network_id", " WHERE network_id=?", (self.network,)) and
                not table_rows(value.host, "dec_signers", "network_id", " WHERE network_id=?", (self.network,)) and
                not table_rows(value.host, "dec_operations", "request_id", " WHERE network_id=?", (self.network,)),
                "staged whole migration installed ordinary DEC context/provider/outcome")
            records = table_rows(value.host, "networks", "record", " WHERE id=?", (self.network,))
            require(len(records) == 1 and strict_output(records[0][0].encode()).get("format") != 2,
                "staged preparation changed legacy network into active format2")
            require(self.key_hashes(label) == self.old_device_hashes[label], "staging installed/replaced an actual device seed")
            events = value.host.api("GET", "/v1/activity?limit=1000")
            require(sum(row["kind"] == "network.link_applied" for row in events) == self.old_link_events[label] and
                not any(row["kind"] == "network.migrated" for row in events), "staging emitted application/migration event")
        self.custody()

    def prepare_fixture(self):
        legacy_root = self.args.work_dir/"legacy"; legacy_root.mkdir(mode=0o700)
        self.legacy = OwnedLegacy(SimpleNamespace(work_dir=legacy_root, baseline=self.args.baseline,
            coordinator=self.args.coordinator, probe=self.args.probe), self.keys)
        self.baseline = self.legacy.build()
        self.legacy.stop(); self.legacy = None
        self.network = self.baseline["network_id"]; self.person = self.baseline["person_public_key"]
        self.original_key = legacy_root/"owner"/"original-ed25519"
        self.original_key_hash = sha(self.original_key.read_bytes())
        self.specs = {row["label"]:row for row in self.baseline["specs"]}
        require(len({row["network_id"] for row in self.specs.values()}) == 1 and len(self.specs) == 3,
            "whole migration requires ONE actual network and all THREE source hosts")
        self.before_upgrade = {label:all_database_snapshots(legacy_root/label/"state") for label in LABELS}
        source_hosts = self.legacy_hosts = {label:SimpleNamespace(state=legacy_root/label/"state",
            environment={"HOME":str(legacy_root/label/"home")}) for label in LABELS}
        self.source_private_files = {label:self.private_files(host) for label,host in source_hosts.items()}
        self.source_root_hashes = {}
        for label,host in source_hosts.items():
            roots = table_rows(host, "networks", "root_seed", " WHERE id=?", (self.network,))
            require(len(roots) == 1, "legacy source lost its exact network root home")
            self.source_root_hashes[label] = None if roots[0][0] is None else sha(roots[0][0])
        require(self.source_root_hashes["owner"] is not None and self.source_root_hashes["selected"] is None and
            self.source_root_hashes["unbound"] is None, "legacy setup does not keep raw root only on A")
        self.source_device_hashes = {label:{key:sha(seed) for key,seed in table_rows(
            SimpleNamespace(state=legacy_root/label/"state"), "link_device_keys", "public_key,seed")} for label in LABELS}
        # The old coordinator is dead. This socket observes attempts only; it
        # returns no authority/protocol response and has none of its keys.
        address = self.baseline["coordinator_address"]
        self.observer = socket.socket(); self.observer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.observer.bind(("127.0.0.1", int(address.rsplit(":", 1)[1]))); self.observer.listen(16); self.observer.settimeout(.1)
        def observe():
            while not self.observer_stop.is_set():
                try: connection, _ = self.observer.accept()
                except socket.timeout: continue
                except OSError: break
                self.coordinator_attempts.append(time.monotonic()); connection.close()
        self.observer_thread = threading.Thread(target=observe, name="stopped-legacy-coordinator-refusal-observer")
        self.observer_thread.start()
        self.now = max(moment(self.baseline["decision_time"]), datetime.now(timezone.utc).replace(microsecond=0))+timedelta(seconds=2)
        self.clocks, self.peers = {}, {}
        for label in LABELS:
            root = self.args.work_dir/("current-"+label); root.mkdir(mode=0o700)
            value = CreationSuite(getattr(self.args, label+"_host"), root, self.keys)
            value.host.state = legacy_root/label/"state"
            require(not (value.host.state/"admin.sock").exists(), "old actual source host not stopped")
            value.host.environment["PATH"] = "/usr/bin:/bin"
            old_home = legacy_root/label/"home"
            value.host.environment.update(HOME=str(old_home), XDG_CONFIG_HOME=str(old_home/"config"),
                XDG_STATE_HOME=str(old_home/"state"), XDG_DATA_HOME=str(old_home/"data"),
                GH_CONFIG_DIR=str(old_home/"gh"), CODEX_HOME=str(old_home/"codex"))
            clock = root/"authority-clock"; clock.write_text(stamp(self.now)); clock.chmod(0o600)
            value.host.environment.update(PEERSPAN_DEC_TEST_MODE="1", PEERSPAN_DEC_TEST_CLOCK_FILE=str(clock))
            with socket.socket() as reserved:
                reserved.bind(("127.0.0.1", 0)); tcp = "127.0.0.1:"+str(reserved.getsockname()[1])
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserved:
                reserved.bind(("127.0.0.1", 0)); peer = "127.0.0.1:"+str(reserved.getsockname()[1])
            value.host.run_arguments = ["--bootstrap-listen", tcp, "--peer-listen", peer, "--advertise", peer]
            self.instances[label], self.clocks[label], self.peers[label] = value, clock, peer
            value.host.start(); value.identity = value.host.api("GET", "/v1/host")
            require(value.identity["public_key"] == self.specs[label]["host_public_key"], "in-place upgrade replaced an actual host identity")
        self.route = "/v2/networks/"+self.network+"/migration"
        self.old_device_hashes = self.source_device_hashes
        require(all(self.key_hashes(label) == self.old_device_hashes[label] for label in LABELS), "upgrade changed an existing actual device seed")
        require(not self.old_device_hashes["owner"] and not self.old_device_hashes["unbound"] and
            self.specs["selected"]["device_public_key"] in self.old_device_hashes["selected"], "source private key custody differs from original-only/selected15/unbound")
        self.old_link_events = {label:sum(row["kind"] == "network.link_applied" for row in value.host.api("GET", "/v1/activity?limit=1000"))
            for label,value in self.instances.items()}
        require(sha(self.original_key.read_bytes()) == self.original_key_hash and not self.coordinator_attempts,
            "opening new mode changed original key or depended on old coordinator")
        self.custody()
        path = self.args.work_dir/"source-custody-hashes.private.json"
        path.write_bytes(raw_json({"private_files":self.source_private_files, "root_seed_sha256":self.source_root_hashes,
            "device_seed_sha256":self.source_device_hashes, "databases":self.before_upgrade})); path.chmod(0o600)

    def identities(self):
        self.roster, self.identity_before = [], {}
        for label in LABELS:
            expected = {key:self.specs[label][key] for key in ROSTER}
            before = all_database_snapshots(self.instances[label].host.state)
            preview = self.call(label, "/identity", {"scopes":expected["scopes"], "approve":False})
            require(set(preview) == {"migration", "identity", "review", "signing_requests"} and not preview["signing_requests"] and
                all_database_snapshots(self.instances[label].host.state) == before, "identity preview signed/generated/changed rows")
            approved = self.call(label, "/identity", {"scopes":expected["scopes"], "approve":True})
            identity = approved["identity"]
            require(set(identity) == ROSTER and identity["host_public_key"] == expected["host_public_key"] and
                identity["person_public_key"] == expected["person_public_key"] and identity["scopes"] == expected["scopes"] and
                (identity["device_public_key"] != "-" if label == "owner" else identity["device_public_key"] == expected["device_public_key"]),
                "approved identity replaced exact old owner/selected15/unbound tuple")
            repeated = self.call(label, "/identity", {"scopes":expected["scopes"], "approve":True})
            require(repeated == approved, "identity retry regenerated tuple/review/key")
            self.specs[label].update(identity); self.roster.append(identity); self.identity_before[label] = self.identity_record(label)
        self.roster.sort(key=lambda row:row["host_public_key"]); self.inert()

    def proposal(self):
        ready = self.wrapper(self.call("owner", "/prepare", {"roster":self.roster, "signature_format":"ed25519", "approve":True}))
        evidence = None
        for _ in range(20):
            for slot in ready["signing_requests"]:
                require(set(slot) == SLOT_FIELDS and slot["format"] == "ed25519", "root preparation slot schema/format differs")
                if slot["object_type"] == "host_lease" and slot["role"] == "host":
                    require(slot["public_key"] == self.specs["unbound"]["host_public_key"], "root exposes unrelated target host signer")
                    self.captured_partial = slot["template_base64"]
                else: require(slot["role"] == "issuer" and slot["public_key"] == ready["review"]["legacy_root_public_key"],
                    "root migration work requests an unrelated original/device signer")
            evidence = self.export("owner", pending=True)
            if evidence and evidence["prepared_catalog_base64"] != "-":
                objects = strict_output(unb64(evidence["prepared_catalog_base64"]))["objects"]
                if {row["kind"] for row in objects} >= {"root_state", "person_lease"} and self.captured_partial: break
            ready = self.wrapper(self.call("owner", "/resume", {}))
        else: raise CheckFailure("root public preparation did not expose complete proposal/P and root-signed C handoff")
        self.original_source = {name:evidence[name] for name in ("proposal_base64", "source_catalog_base64", "source_state_base64")}
        offered_source = strict_output(unb64(evidence["source_catalog_base64"]))
        source_tuples = {(row["kind"],row["id"],unb64(row["body_base64"])) for row in offered_source["objects"]}
        require({(row["kind"],row["id"],unb64(row["body_base64"])) for row in self.baseline["legacy_catalog"]["objects"]} <= source_tuples,
            "root source omitted or reserialized an exact already known legacy proof tuple")
        proposal = strict_output(unb64(evidence["proposal_base64"])); self.proposal_id = statement_id(proposal)
        self.context = proposal["context_id"]; payload = strict_output(unb64(proposal["payload_base64"]))
        self.root_key = payload["legacy_root_public_key"]; self.expires_at = payload["expires_at"]
        self.verify_statement(evidence["proposal_base64"], "migration_proposal")
        descriptor = strict_output(unb64(payload["legacy_descriptor_base64"]))
        require(descriptor == {"network_id":self.network,"name":"Independent owned three-host migration",
            "genesis_root_public_key":self.root_key,"coordinator_address":self.baseline["coordinator_address"],
            "coordinator_public_key":self.baseline["coordinator_public_key"]}, "proposal changed historical descriptor/coordinator pins")
        require([(row["role"],row["public_key"],row["format"]) for row in proposal["signatures"]] ==
            [("issuer",self.root_key,"ed25519")] and moment(payload["expires_at"])-moment(payload["issued_at"]) == timedelta(days=1),
            "root proposal signature or fixed24h window differs")
        self.proposal_payload = payload
        require(payload["roster"] == self.roster and payload["source_catalog_sha256"] == sha(unb64(evidence["source_catalog_base64"])) and
            payload["source_state_sha256"] == sha(unb64(evidence["source_state_base64"])), "proposal roster/source hash changed")
        state = strict_output(unb64(evidence["source_state_base64"]))
        require(state["known_admitted_hosts"] == sorted(row["host_public_key"] for row in self.roster) and
            state["access_maxima"] == self.baseline["access_maxima"] and
            any(row["kind"] == "policy" and row["subject"] == self.person and row["version"] == 1 for row in state["access_maxima"]) and
            any(row["kind"] == "group" and row["subject"] == "migration-floor" and row["version"] == 1 for row in state["access_maxima"]),
            "endorsed snapshot omitted a source host or actual writer floor")
        roots = [row for row in strict_output(unb64(evidence["prepared_catalog_base64"]))["objects"] if row["kind"] == "root_state"]
        require(len(roots) == 1, "prepared root is ambiguous")
        root,root_payload,self.root_id = self.verify_statement(roots[0]["body_base64"], "root_state")
        require(root_payload == {"epoch":payload["legacy_epoch"], "predecessors":[], "resolves":[],
            "root_public_key":self.root_key, "issued_at":payload["issued_at"], "retained_statement_ids":[],
            "migration_proposal_id":self.proposal_id} and [(row["role"],row["public_key"],row["format"])
                for row in root["signatures"]] == [("issuer",self.root_key,"ed25519")],
            "prepared root is not the exact inert migrated initial root")
        self.source_state = state
        for label in LABELS:
            if label != "owner": self.import_evidence(label, evidence)
            before = self.migration(label)
            require(not before["approved"] and not before["fenced"], "proposal preparation/import supplied host participation")
            self.wrapper(self.call(label, "/review", {"proposal_id":self.proposal_id, "approve":False}), "participation")
            reviewed = self.wrapper(self.call(label, "/review", {"proposal_id":self.proposal_id, "approve":True}), "participation")
            require(reviewed["migration"]["approved"] and not reviewed["migration"]["fenced"], "separate participation did not stay unfenced")
        self.inert()

    def verify_statement(self, encoded, kind):
        statement = strict_output(unb64(encoded)); identifier = statement_id(statement)
        require(statement["kind"] == kind and statement["context_id"] == self.context and
            all(row["signature"] != "-" for row in statement["signatures"]), "public statement kind/context/signature incomplete")
        for signature in statement["signatures"]:
            message = lines("peerspan-decentralized-signature-v1", identifier, signature["role"], signature["public_key"])
            if signature["format"] == "ed25519": self.instances["owner"].verify_raw(signature["public_key"], message, signature["signature"])
            else:
                require(signature["format"] == "sshsig" and signature["public_key"] == self.person, "unexpected external original signer")
                self.verify_original(signature["signature"], message)
        return statement, strict_output(unb64(statement["payload_base64"])), identifier

    def verify_original(self, signature, message):
        # Existing independently authored OpenSSH public verifier; no private
        # key is given to it or any daemon.
        from decentralized_native_introduction import Introduction
        Introduction.verify_original(SimpleNamespace(person=self.person, b=self.instances["owner"]), signature, message)

    def signed_slots(self, ready, request, stage):
        require(set(ready) == {"request", "review", "signing_requests"} and ready["review"]["stage"] == stage,
            "ceremony stage wrapper mismatch")
        slots = ready["signing_requests"]; signatures = []
        allowed = {"owner":{"owner_offer_packet"}, "administrator":{"person_lease", "host_lease", "administrator_packet"},
            "owner_finalization":{"binding_lease", "device_lease", "owner_finalization_packet"}}[stage]
        for slot in slots:
            require(set(slot) == SLOT_FIELDS and slot["object_type"] in allowed, "stage requests unrelated typed object")
            template = strict_output(unb64(slot["template_base64"]))
            if slot["object_type"].endswith("_packet"):
                message = packet_message(template); identifier = "dpk_"+sha(message)
                require(slot["role"] == "authority" and template["request_id"] == request and template["context_id"] == self.context,
                    "packet slot changed role/request/context")
                require(template["writer_host_public_key"] == self.specs["owner"]["host_public_key"] and
                    template["signer_public_key"] == slot["public_key"] and template["authority_signature_format"] == slot["format"],
                    "packet slot changed actual writer/authority selector")
            else:
                identifier = statement_id(template)
                message = lines("peerspan-decentralized-signature-v1", identifier, slot["role"], slot["public_key"])
                require(template["context_id"] == self.context and template["kind"] == slot["object_type"], "lease slot kind/context differs")
            require(slot["object_id"] == identifier and unb64(slot["message_base64"]) == message, "typed ready message/ID differs")
            key = (slot["intent_id"], slot["slot_id"], slot["role"])
            fixed = (slot["template_base64"], slot["message_base64"])
            require(self.fixed_slots.get(key, fixed) == fixed, "fixed template/message changed between dependency batches")
            self.fixed_slots[key] = fixed
            if slot["format"] == "sshsig":
                require(slot["public_key"] == self.person and stage != "administrator", "external slot is not A original-owner consent")
                signature = external_original_signature(self.original_key, message, self.args.work_dir/"legacy/owner",
                    "new-typed-"+str(len(self.fixed_slots)))
                self.verify_original(signature, message)
                signatures.append({"slot_id":slot["slot_id"], "role":slot["role"], "signature":signature})
            else: require(slot["format"] == "ed25519" and slot["public_key"] in {self.root_key, self.specs["owner"]["host_public_key"]},
                "owned raw role cannot be exported or replaced by fixture signer")
        if signatures:
            require(len({slot["intent_id"] for slot in slots if slot["format"] == "sshsig"}) == 1, "external batch mixes intents")
            return self.api("owner", "POST", "/v2/link/requests/"+request+"/signed",
                {"intent_id":next(slot["intent_id"] for slot in slots if slot["format"] == "sshsig"), "signatures":signatures})[0]
        self.api("owner", "POST", "/v2/link/requests/"+request+"/resume", {})
        return self.api("owner", "GET", "/v2/link/requests/"+request+"/approval")[0]

    def finish_stage(self, ready, request, stage, field):
        deadline = time.monotonic()+120
        for _ in range(32):
            record, _ = self.pending("owner", request)
            if record[field] != "-": return record
            require(time.monotonic() < deadline, "approved stage did not progress within bounded120s fixture budget")
            ready = self.signed_slots(ready, request, stage); time.sleep(.1)
        raise CheckFailure("approved stage exceeded32 fixed dependency batches")

    def observe(self, label, request, completed):
        deadline = time.monotonic()+120
        for _ in range(32):
            view = self.api(label, "POST", "/v2/link/requests/"+request+"/resume", {})[0]
            require(LINK_VIEW <= set(view) and view["migration_proposal_id"] == self.proposal_id, "staged LINK_VIEW changed shape/proposal")
            if completed in view["completed"] and (completed != "commit_persisted" or view["state"] == "migration_prepared"): return view
            require(time.monotonic() < deadline, "exact stage observation exceeded bounded120s fixture budget")
            time.sleep(.2)
        raise CheckFailure("actual requester did not observe exact published "+completed)

    def staged_hosts(self):
        for label in ("owner", "selected"):
            request = self.call(label, "/link", {"proposal_id":self.proposal_id}, statuses=(201,))
            require(set(request) == LINK_VIEW|{"display_code"} and request["mode"] == "new" and
                request["migration_proposal_id"] == self.proposal_id and all(request[key] == self.specs[label][key]
                    for key in ("person_public_key", "host_public_key", "device_public_key")), "staged new request changed exact approved tuple")
            self.requests[label] = request; identifier = request["request_id"]
            deadline = stamp(self.now+timedelta(days=2))
            owner = {"code":request["display_code"], "network_id":self.network, "person_public_key":self.person,
                "provider_id":self.person, "signature_format":"sshsig", "scopes":self.specs[label]["scopes"], "not_after":deadline,
                "expected_host_public_key":request["host_public_key"], "expected_device_public_key":request["device_public_key"], "approve":False}
            preview = self.api("owner", "POST", "/v2/link/approvals", owner)[0]
            require(preview["signing_requests"] == [] and self.pending("owner", identifier)[0]["owner_packet_base64"] == "-",
                "owner preview signed the pending offer before separate approval")
            ready = self.api("owner", "POST", "/v2/link/approvals", dict(owner, approve=True))[0]
            record = self.finish_stage(ready, identifier, "owner", "owner_packet_base64")
            self.observe(label, identifier, "owner_offered")
            selection = {"owner_offer_id":record["owner_offer_id"], "network_id":self.network, "context_id":self.context,
                "person_public_key":self.person, "host_public_key":request["host_public_key"], "device_public_key":request["device_public_key"], "approve":False}
            self.api(label, "POST", "/v2/link/requests/"+identifier+"/selection", selection)
            require(not self.pending(label, identifier)[0]["selection_approved"], "selection preview supplied consent")
            self.api(label, "POST", "/v2/link/requests/"+identifier+"/selection", dict(selection, approve=True))
            selected = self.observe(label, identifier, "owner_selected")
            admin = {"code":request["display_code"], "network_id":self.network, "person_public_key":self.person,
                "provider_id":"network_root", "signature_format":"ed25519", "owner_offer_id":selected["owner_offer_id"],
                "selection_id":selected["selection_id"], "expected_host_public_key":request["host_public_key"],
                "expected_device_public_key":request["device_public_key"], "approve":True}
            ready = self.api("owner", "POST", "/v2/link/admissions", admin)[0]
            record = self.finish_stage(ready, identifier, "administrator", "administrator_packet_base64")
            self.observe(label, identifier, "administrator_offered")
            final = {"owner_offer_id":record["owner_offer_id"], "selection_id":record["selection_id"],
                "administrator_offer_id":record["administrator_offer_id"], "network_id":self.network, "context_id":self.context,
                "person_public_key":self.person, "host_public_key":request["host_public_key"], "device_public_key":request["device_public_key"], "approve":False}
            self.api("owner", "POST", "/v2/link/requests/"+identifier+"/finalization", final)
            ready = self.api("owner", "POST", "/v2/link/requests/"+identifier+"/finalization", dict(final, approve=True))[0]
            self.finish_stage(ready, identifier, "owner_finalization", "owner_finalization_packet_base64")
            finalized = self.observe(label, identifier, "owner_finalized")
            commit = dict(final, owner_finalization_id=finalized["owner_finalization_id"], approve=False)
            self.api(label, "POST", "/v2/link/requests/"+identifier+"/commit", commit)
            require(not self.pending(label, identifier)[0]["commit_approved"], "final preview supplied requester consent")
            self.api(label, "POST", "/v2/link/requests/"+identifier+"/commit", dict(commit, approve=True))
            terminal = self.observe(label, identifier, "commit_persisted")
            require(terminal["state"] == "migration_prepared" and terminal["selection_approved"] and terminal["commit_approved"] and
                terminal["outcome_id"] == "-" and "locally_applied" not in terminal["completed"], "owned transcript ordinary-applied before whole M")
            self.stage_views[label] = terminal; self.inert()

    def prepared_union(self):
        require(self.captured_partial is not None, "no public root-signed unbound handoff")
        template = strict_output(unb64(self.captured_partial)); payload = strict_output(unb64(template["payload_base64"]))
        require(template["kind"] == "host_lease" and template["context_id"] == self.context and
            payload["operation_id"] == self.proposal_id and payload["root_state_id"] == self.root_id and
            payload["sequence"] == 1 and payload["predecessors"] == payload["resolves"] == payload["retained_statement_ids"] == [] and
            payload["parents"] == [] and payload["issuer"] == {"kind":"root", "person_public_key":"-"} and
            payload["subject"] == {"person_public_key":"-", "host_public_key":self.specs["unbound"]["host_public_key"],
                "device_public_key":"-", "member":self.specs["unbound"]["member"], "scopes":0} and
            moment(self.proposal_payload["issued_at"]) <= moment(payload["issued_at"]) <= moment(self.expires_at) and
            moment(payload["issued_at"]) <= moment(payload["not_before"]) <= self.now < moment(payload["not_after"]) and
            moment(payload["not_after"])-moment(payload["issued_at"]) <= timedelta(days=7) and
            {row["role"]:row["signature"] for row in template["signatures"]}["host"] == "-" and
            {row["role"]:row["signature"] for row in template["signatures"]}["issuer"] != "-", "C handoff lacks fixed root-first signature")
        require([(row["role"],row["public_key"],row["format"]) for row in template["signatures"]] ==
            [("host",self.specs["unbound"]["host_public_key"],"ed25519"),("issuer",self.root_key,"ed25519")],
            "unbound H template has an extra or substituted signature role")
        self.unbound_host_id = statement_id(template)
        issuer = next(row for row in template["signatures"] if row["role"] == "issuer")
        self.instances["owner"].verify_raw(self.root_key, lines("peerspan-decentralized-signature-v1", self.unbound_host_id,
            "issuer",self.root_key), issuer["signature"])
        body = {"proposal_id":self.proposal_id, "host_lease_base64":self.captured_partial, "approve":False}
        before = all_database_snapshots(self.instances["unbound"].host.state)
        self.call("unbound", "/host-lease", body)
        require(all_database_snapshots(self.instances["unbound"].host.state) == before, "C host-membership preview mutated state")
        self.call("unbound", "/host-lease", dict(body, approve=True))
        for _ in range(12):
            value = self.export("unbound")
            bodies = [] if value["prepared_catalog_base64"] == "-" else strict_output(unb64(value["prepared_catalog_base64"]))["objects"]
            matches = [row for row in bodies if row["kind"] == "host_lease" and
                statement_id(strict_output(unb64(row["body_base64"]))) == statement_id(template)]
            if matches: self.verify_statement(matches[0]["body_base64"], "host_lease"); break
            self.call("unbound", "/resume", {})
        else: raise CheckFailure("C actual host consent did not enter public prepared evidence")
        objects = {}
        for label in LABELS:
            evidence = self.export(label)
            require(evidence["prepared_catalog_base64"] != "-", "participant exports no exact public prepared bytes")
            catalog = strict_output(unb64(evidence["prepared_catalog_base64"]))
            require(set(catalog) == {"format", "context_id", "objects"} and catalog["format"] == 1 and catalog["context_id"] == self.context,
                "prepared catalog wrapper/context differs")
            for row in catalog["objects"]:
                require(set(row) == {"id","kind","body_base64"} and row["id"] == "dp_"+sha(lines(
                    "peerspan-decentralized-proof-v1", row["kind"], sha(unb64(row["body_base64"])))),
                    "prepared proof tuple does not preserve its exact original bytes")
                require(row["kind"] not in {"migration", "migration_ack", "migration_commit"}, "prepared catalog is self-containing")
                require(row["id"] not in objects or objects[row["id"]] == row, "same public proof ID has changed body/kind")
                objects[row["id"]] = row
        self.prepared_catalog = {"format":1, "context_id":self.context, "objects":[objects[key] for key in sorted(objects)]}
        self.prepared_raw = raw_json(self.prepared_catalog); self.prepared_hash = sha(self.prepared_raw)
        self.fixed_evidence = {**self.original_source, "prepared_catalog_base64":b64(self.prepared_raw), "acknowledgments_base64":[], "commit_base64":"-"}
        require(len(self.prepared_raw) <= 1024*1024, "whole prepared catalog exceeds1MiB")
        decoded = [(row, strict_output(unb64(row["body_base64"]))) for row in self.prepared_catalog["objects"]]
        persons = [(row,statement) for row,statement in decoded if row["kind"] == "person_lease"]
        require(len(persons) == 1 and strict_output(unb64(persons[0][1]["payload_base64"]))["subject"]["person_public_key"] == self.person,
            "owned hosts did not share one exact pending Alice P")
        person,pp,self.person_lease_id = self.verify_statement(persons[0][0]["body_base64"], "person_lease")
        require(pp["operation_id"] == "-" and pp["root_state_id"] == self.root_id and pp["sequence"] == 1 and
            pp["predecessors"] == pp["resolves"] == [] and [(row["role"],row["public_key"],row["format"])
                for row in person["signatures"]] == [("issuer",self.root_key,"ed25519")], "shared pending P is not ordinary root-issued sequence1")
        require(not any(row["kind"] == "admin_lease" and strict_output(unb64(statement["payload_base64"]))["subject"]["person_public_key"] == self.person
            for row,statement in decoded), "nominal15 cutover fabricated Alice administrator A")
        for label, view in self.stage_views.items():
            require(any(row["kind"] == "activation" and self.activation(row)["activation_id"] == view["activation_id"] for row in self.prepared_catalog["objects"]),
                "complete public prepared union omitted an actual owned activation")
        for label in LABELS: self.import_evidence(label, self.fixed_evidence)
        self.inert()

    def activation(self, entry):
        raw = unb64(entry["body_base64"]); activation = strict_output(raw)
        require(entry["id"] == "dp_"+sha(lines("peerspan-decentralized-proof-v1", "activation", sha(raw))) and
            set(activation) == {"format", "context_id", "request", "owner", "selection", "administrator", "owner_finalization", "commit"} and
            activation["format"] == 1 and activation["context_id"] == self.context, "complete public activation shape/proof ID differs")
        request_id = activation["request"]["request_id"]
        label = next((name for name, value in self.requests.items() if value["request_id"] == request_id), None)
        require(label is not None, "prepared activation is not an exact owned roster request")
        device, host = self.specs[label]["device_public_key"], self.specs[label]["host_public_key"]
        packet_ids = {}
        for role in ("request", "owner", "selection", "administrator", "owner_finalization", "commit"):
            packet = activation[role]; message = packet_message(packet); packet_ids[role] = "dpk_"+sha(message)
            require(packet["role"] == role and packet["request_id"] == request_id and
                packet["person_public_key"] == ("-" if role in {"request","administrator"} else self.person) and
                packet["context_id"] == ("-" if role == "request" else self.context),
                "activation packet changed exact typed role/request/person/context")
            self.instances["owner"].verify_raw(packet["writer_host_public_key"], message, packet["host_signature"])
            if role in {"request", "selection", "commit"}:
                require(packet["writer_host_public_key"] == host and packet["signer_public_key"] == device and
                    packet["issuer_id"] == packet["authority_signature_format"] == packet["authority_signature"] == "-", "requester possession role changed")
                self.instances["owner"].verify_raw(device, message, packet["device_signature"])
            elif role == "administrator":
                require(packet["signer_public_key"] == self.root_key and packet["authority_signature_format"] == "ed25519",
                    "staging administrator is not exact root")
                require(packet["issuer_id"] == self.root_id and packet["device_signature"] == "-" and
                    packet["writer_host_public_key"] == self.specs["owner"]["host_public_key"], "root administrator changed typed issuer/writer")
                self.instances["owner"].verify_raw(self.root_key, message, packet["authority_signature"])
            else:
                require(packet["signer_public_key"] == self.person and packet["authority_signature_format"] == "sshsig",
                    "owner/F was not signed by the original on A")
                require(packet["issuer_id"] == packet["device_signature"] == "-" and
                    packet["writer_host_public_key"] == self.specs["owner"]["host_public_key"], "original owner/F changed issuer/writer")
                self.verify_original(packet["authority_signature"], message)
        commit = strict_output(unb64(activation["commit"]["payload_base64"]))
        manifest_raw = unb64(commit["manifest_base64"]); manifest = strict_output(manifest_raw)
        manifest_id = "dm_"+sha(lines("peerspan-decentralized-manifest-v1", sha(manifest_raw)))
        require(manifest["context_id"] == self.context and manifest["request_id"] == request_id and manifest["root_state_id"] == self.root_id and
            all(manifest[field] == packet_ids[role] for field,role in (("request_packet_id","request"), ("owner_offer_id","owner"),
                ("selection_id","selection"), ("administrator_offer_id","administrator"), ("owner_finalization_id","owner_finalization"))),
            "complete manifest changed exact fixed stage/root references")
        identifier = "da_"+sha(lines("peerspan-decentralized-activation-v1", self.context, request_id, manifest_id, packet_ids["commit"]))
        require(identifier == self.stage_views[label]["activation_id"] and manifest_id == self.stage_views[label]["manifest_id"],
            "public activation semantic IDs differ from actual staged result")
        owner = strict_output(unb64(activation["owner"]["payload_base64"]))
        require(owner["root_state_id"] == self.root_id and owner["person_lease_id"] == self.person_lease_id and
            owner["scopes"] == self.specs[label]["scopes"], "staged offer lost exact shared P/root/nominal device profile")
        proofs = {row["id"]:row for row in self.prepared_catalog["objects"]}
        require(manifest["binding_proof_id"] in proofs and manifest["device_proof_id"] in proofs,
            "prepared union lacks the exact final B/D proof bodies")
        binding,bp,binding_id = self.verify_statement(proofs[manifest["binding_proof_id"]]["body_base64"], "binding_lease")
        device_statement,dp,device_id = self.verify_statement(proofs[manifest["device_proof_id"]]["body_base64"], "device_lease")
        require(binding_id == manifest["binding_lease_id"] and device_id == manifest["device_lease_id"] and
            bp["operation_id"] == dp["operation_id"] == request_id and bp["root_state_id"] == dp["root_state_id"] == self.root_id and
            bp["issuer"] == dp["issuer"] == {"kind":"person","person_public_key":self.person} and
            bp["subject"] == {"person_public_key":self.person,"host_public_key":host,"device_public_key":"-","member":"-","scopes":2} and
            dp["subject"] == {"person_public_key":self.person,"host_public_key":host,"device_public_key":device,
                "member":"-","scopes":self.specs[label]["scopes"]}, "prepared B/D widened or replaced exact original/host/device/scopes")
        common = [{"role":"issuer_person","id":self.person_lease_id},{"role":"subject_host","id":manifest["host_lease_id"]},
            {"role":"subject_person","id":self.person_lease_id}]
        require(bp["parents"] == sorted(common,key=lambda row:row["role"]) and dp["parents"] == sorted(
            common+[{"role":"subject_binding","id":binding_id}],key=lambda row:row["role"]), "original B/D has unrelated or missing finite parents")
        require([(v["role"],v["public_key"],v["format"]) for v in binding["signatures"]] ==
            [("host",host,"ed25519"),("issuer",self.person,"sshsig")] and
            [(v["role"],v["public_key"],v["format"]) for v in device_statement["signatures"]] == [("issuer",self.person,"sshsig")],
            "prepared B/D signatures substituted another owner or target host")
        require(next(v["signature"] for v in binding["signatures"] if v["role"] == "host") == commit["binding_host_signature"],
            "final B proof differs from exact separate requester binding signature")
        return {**manifest, "activation_id":identifier, "activation_sha256":sha(raw), "label":label}

    def named_metadata(self, label):
        host = self.instances[label].host
        return {"dec_intents":{identifier:{"network_id":network,"context_id":context,"kind":kind,
                    "record":strict_output(encoded.encode()), "secret_is_null":secret is None}
                for identifier,network,context,kind,encoded,secret in table_rows(host, "dec_intents", "intent_id,network_id,context_id,kind,record,secret")},
            "dec_migrations":{proposal:strict_output(encoded.encode()) for proposal,encoded in table_rows(host, "dec_migrations", "proposal_id,record")},
            "dec_clock":{network:strict_output(encoded.encode()) for network,encoded in table_rows(host, "dec_clock", "network_id,record")}}

    def preview(self, label, suffix, body, kind):
        """Only the literal132/133 named unsigned intent/ref/guard allowance."""
        before = all_database_snapshots(self.instances[label].host.state); old = self.named_metadata(label)
        ready = self.wrapper(self.call(label, suffix, dict(body, approve=False)))
        after = all_database_snapshots(self.instances[label].host.state); new = self.named_metadata(label)
        changed = {table:[key for key in sorted(set(old[table])|set(new[table])) if old[table].get(key) != new[table].get(key)] for table in old}
        capture = self.instances[label].root/(kind+"-preview-named-rows.private.json")
        capture.write_bytes(raw_json({"before":old, "after":new, "changed_rows":changed})); capture.chmod(0o600)
        require(before["databases"].keys() == after["databases"].keys(), "preview changed DB set")
        for name, database in before["databases"].items():
            current = after["databases"][name]
            require(database["user_version"] == current["user_version"] and database["tables"].keys() == current["tables"].keys(), "preview changed schema/version")
            for table, rows in database["tables"].items():
                require(rows["ddl_sha256"] == current["tables"][table]["ddl_sha256"], "preview changed DDL")
                if table not in old: require(rows == current["tables"][table], "preview changed unrelated table "+table)
        require(changed["dec_migrations"] in ([], [self.proposal_id]) and changed["dec_clock"] in ([], [self.network]) and
            len(changed["dec_intents"]) <= 1, "preview changed unrelated named rows")
        old_m, new_m = old["dec_migrations"][self.proposal_id], new["dec_migrations"][self.proposal_id]
        field = "root_intent_ids" if kind == "migration_commit" else "local_ack_intent_id"
        require({key:value for key,value in old_m.items() if key != field} == {key:value for key,value in new_m.items() if key != field},
            "preview changed other migration approvals/fence/evidence")
        if changed["dec_intents"]:
            identifier = changed["dec_intents"][0]; row = new["dec_intents"][identifier]; record = row["record"]
            require(identifier not in old["dec_intents"], "preview rewrote an already fixed private intent")
            require(row["network_id"] == self.network and row["context_id"] == self.context and row["kind"] == "migration" and
                row["secret_is_null"] and not record["approved"] and record["approved_at"] == "-" and
                record["signatures"] == [] and not record["completed"] and record["operation_id"] == self.proposal_id and
                record["terminal"] == record["result_base64"] == "-" and
                record["expires_at"] == self.expires_at and record["root_state_id"] == self.root_id and
                strict_output(unb64(record["review_base64"])) == ready["review"] and
                len(record["templates"]) == 1 and record["templates"][0]["object_type"] == kind,
                "preview created approval/signature/seed or unrelated template")
            template = strict_output(unb64(record["templates"][0]["template_base64"]))
            payload = strict_output(unb64(template["payload_base64"]))
            require(template["kind"] == kind and template["context_id"] == self.context and
                payload["proposal_id"] == self.proposal_id and payload["root_state_id"] == self.root_id and
                payload["prepared_catalog_sha256"] == self.prepared_hash and
                all(row["signature"] == "-" for row in template["signatures"]), "preview template changed signed migration pins")
            if kind == "migration_commit":
                require(new_m[field][:len(old_m[field])] == old_m[field] and new_m[field][len(old_m[field]):] == [identifier] and
                    record["person_public_key"] == record["host_public_key"] == record["device_public_key"] == "-" and
                    record["scopes"] == 8 and record["not_after"] == "-" and record["provider"] == {"kind":"root", "signer_public_key":self.root_key,
                        "signature_format":"ed25519", "lease_id":"-"}, "root preview changed subject/selector/reference")
                require(payload["acknowledgment_ids"] == body["acknowledgment_ids"] and
                    moment(self.proposal_payload["issued_at"]) <= moment(payload["committed_at"]) <= self.now < moment(self.expires_at) and
                    [(v["role"],v["public_key"],v["format"]) for v in template["signatures"]] == [("issuer",self.root_key,"ed25519")],
                    "root preview changed ALL3 ACKs, signing time or role")
            else:
                require(old_m[field] in ("-",identifier) and new_m[field] == identifier, "ACK preview replaced own intent reference")
                expected = {"kind":"host", "signer_public_key":self.specs[label]["host_public_key"], "signature_format":"ed25519", "lease_id":"-"}
                if label != "unbound": expected = {"kind":"device", "signer_public_key":self.specs[label]["device_public_key"],
                    "signature_format":"ed25519", "lease_id":self.activation_facts[label]["device_lease_id"]}
                require(record["provider"] == expected, "ACK preview selected another owned host/device key")
                require(all(record[k] == self.specs[label][k] for k in ("person_public_key","host_public_key","device_public_key")) and
                    (label != "unbound" or record["scopes"] == 0),
                    "ACK preview changed its own private tuple")
                self.ack_pins(label, payload)
        else: require(changed["dec_migrations"] == [], "read-only preview changed private reference without its intent")
        if changed["dec_clock"]:
            current = new["dec_clock"][self.network]
            require(set(current) == {"format","largest_local_time"} and current["format"] == 1 and
                moment(current["largest_local_time"]) <= self.now and (self.network not in old["dec_clock"] or
                    moment(current["largest_local_time"]) >= moment(old["dec_clock"][self.network]["largest_local_time"])),
                "preview guard update rewound or exceeded the exact decision clock")
        require(ready["signing_requests"] == [], "unapproved migration preview exposed ready signing slot")
        self.trace.append({"preview_named_changed_rows":changed, "host_role":label, "kind":kind})
        return ready

    def ack_pins(self, label, payload):
        require(payload["proposal_id"] == self.proposal_id and payload["root_state_id"] == self.root_id and
            payload["prepared_catalog_sha256"] == self.prepared_hash and payload["host_public_key"] == self.specs[label]["host_public_key"] and
            payload["person_public_key"] == self.specs[label]["person_public_key"] and payload["device_public_key"] == self.specs[label]["device_public_key"],
            "ACK changed exact proposal/catalog/own tuple")
        require(moment(self.proposal_payload["issued_at"]) <= moment(payload["acknowledged_at"]) <= self.now < moment(self.expires_at),
            "ACK time escaped its original proposal window/current decision")
        if label == "unbound":
            require(payload["host_lease_id"] == self.unbound_host_id and all(payload[key] == "-" for key in
                ("binding_lease_id", "device_lease_id", "activation_id")), "unbound ACK invented owned activation or another H")
        else:
            require(all(payload[key] == self.activation_facts[label][key] for key in
                ("host_lease_id", "binding_lease_id", "device_lease_id", "activation_id")), "owned ACK references another prepared activation/grant")

    def verify_ack(self, label, encoded):
        statement, payload, identifier = self.verify_statement(encoded, "migration_ack")
        roles = [(row["role"], row["public_key"],row["format"]) for row in statement["signatures"]]
        expected_roles = [("host", self.specs[label]["host_public_key"],"ed25519")]
        if label != "unbound": expected_roles.append(("device", self.specs[label]["device_public_key"],"ed25519"))
        require(roles == sorted(expected_roles), "ACK signature roles/keys differ from actual owned host/device")
        self.ack_pins(label, payload)
        return identifier

    def ack_all(self):
        self.activation_facts = {self.activation(row)["label"]:self.activation(row)
            for row in self.prepared_catalog["objects"] if row["kind"] == "activation"}
        # Every per-host signing/consent already completed. Moving the opted-in
        # migration decision time does not extend/recreate the old request.
        self.now += timedelta(seconds=301)
        require(self.now < moment(self.expires_at), "fixture exhausted original24h proposal window")
        for path in self.clocks.values(): path.write_text(stamp(self.now))
        for label in LABELS:
            self.inert()
            wrong = {"proposal_id":self.proposal_id, "prepared_catalog_sha256":"0"*64, "approve":True}
            before = self.migration(label)
            denied = self.call(label, "/acknowledgment", wrong, statuses=(409,))
            require(denied["code"] == "operation_conflict" and self.migration(label) == before,
                "wrong exact prepared hash did not refuse immutably")
            body = {"proposal_id":self.proposal_id, "prepared_catalog_sha256":self.prepared_hash, "approve":True}
            self.preview(label, "/acknowledgment", body, "migration_ack")
            self.wrapper(self.call(label, "/acknowledgment", body), "acknowledgment")
            for _ in range(12):
                evidence = self.export(label)
                matches = [encoded for encoded in evidence["acknowledgments_base64"] if
                    strict_output(unb64(strict_output(unb64(encoded))["payload_base64"]))["host_public_key"] == self.specs[label]["host_public_key"]]
                if matches:
                    require(len(matches) == 1, "duplicate own ACK")
                    self.acks[label] = matches[0]; self.verify_ack(label, matches[0]); break
                self.call(label, "/resume", {})
            else: raise CheckFailure("explicit own ACK did not durably sign/fence")
            require(self.migration(label)["fenced"], "signed ACK was not durably fenced")
            # Retain and exchange exact ACKs; no source/prepared component changes.
            partial = {**self.fixed_evidence, "acknowledgments_base64":[self.acks[key] for key in sorted(self.acks, key=lambda key:self.specs[key]["host_public_key"])]}
            for target in LABELS: self.import_evidence(target, partial)
            if label == "selected":
                denied = self.call("owner", "/commit", {"proposal_id":self.proposal_id, "prepared_catalog_sha256":self.prepared_hash,
                    "acknowledgment_ids":sorted(self.verify_ack(name, ack) for name,ack in self.acks.items()),
                    "signature_format":"ed25519", "approve":True}, statuses=(409,))
                require(denied["code"] == "proof_required" and self.migration("owner")["root_commit_id"] == "-" and
                    self.specs["unbound"]["host_public_key"] in self.migration("owner")["missing_host_keys"],
                    "root committed incomplete roster or hid C")
        self.fixed_evidence["acknowledgments_base64"] = [self.acks[key] for key in sorted(self.acks, key=lambda key:self.specs[key]["host_public_key"])]
        # The earlier301s jump aged staged preparation, not an ACK fence.
        # Age the already durable ALL3 fences separately, without refreshing
        # an acknowledgment, identity, source/proposal or fixed signature.
        fence_before = {label:table_rows(value.host,"dec_migrations","record"," WHERE proposal_id=?",(self.proposal_id,))
            for label,value in self.instances.items()}
        evidence_before = {label:self.export(label) for label in LABELS}
        identities_before = {label:self.identity_record(label) for label in LABELS}
        key_hashes_before = {label:self.key_hashes(label) for label in LABELS}
        acknowledged_at = {label:strict_output(unb64(strict_output(unb64(ack))["payload_base64"]))["acknowledged_at"]
            for label,ack in self.acks.items()}
        before_aging = stamp(self.now); self.now += timedelta(seconds=301)
        require(self.now < moment(self.expires_at) and all((self.now-moment(when)).total_seconds() > 300
            for when in acknowledged_at.values()), "fixture failed to age every actual ACK fence within original proposal window")
        for path in self.clocks.values(): path.write_text(stamp(self.now))
        for label,value in self.instances.items():
            before = self.migration(label); value.host.stop(); value.host.start()
            require(self.migration(label) == before and before["fenced"], "restart cleared exact ACK fence")
            require(table_rows(value.host,"dec_migrations","record"," WHERE proposal_id=?",(self.proposal_id,)) == fence_before[label] and
                self.export(label) == evidence_before[label] and self.identity_record(label) == identities_before[label] and
                self.key_hashes(label) == key_hashes_before[label], "aging/restart changed exact ACK/fence/evidence/identity/keys")
        self.trace.append({"all_three_exact_ACK_fences_survive_restart_and_301s_after_ACK":True,
            "separate_post_ACK_clock_before":before_aging,"separate_post_ACK_clock_after":stamp(self.now),
            "original_acknowledged_at":acknowledged_at,"original_proposal_expires_at":self.expires_at,
            "product_fresh_admission_enforcement":"HELD: no otherwise-positive product admission fixture has been established; legacy sync426/history is not such a control"})
        self.inert()

    def commit_and_adopt(self):
        ids = sorted(self.verify_ack(label, self.acks[label]) for label in LABELS)
        body = {"proposal_id":self.proposal_id, "prepared_catalog_sha256":self.prepared_hash,
            "acknowledgment_ids":ids, "signature_format":"ed25519", "approve":True}
        self.preview("owner", "/commit", body, "migration_commit")
        self.wrapper(self.call("owner", "/commit", body), "root_commit")
        for _ in range(12):
            evidence = self.export("owner")
            if evidence["commit_base64"] != "-": break
            self.call("owner", "/resume", {})
        else: raise CheckFailure("actual current root did not publish final complete commit")
        commit, payload, self.commit_id = self.verify_statement(evidence["commit_base64"], "migration_commit")
        require(commit["signatures"][0]["public_key"] == self.root_key and payload["proposal_id"] == self.proposal_id and
            [(row["role"],row["public_key"],row["format"]) for row in commit["signatures"]] == [("issuer",self.root_key,"ed25519")] and
            payload["prepared_catalog_sha256"] == self.prepared_hash and payload["acknowledgment_ids"] == ids,
            "final root commit did not bind ALL3 exact ACKs")
        self.complete_evidence = evidence; self.views, self.full_migration = {}, {}
        for label in LABELS:
            if label != "owner": self.import_evidence(label, evidence)
            self.call(label, "/adopt", {"proposal_id":self.proposal_id, "commit_id":self.commit_id, "approve":True})
            for _ in range(12):
                if self.migration(label)["state"] == "adopted": break
                self.call(label, "/resume", {})
            else: raise CheckFailure("approved complete all-host migration did not locally adopt")
            self.adoption_postconditions(label)
        require(not self.coordinator_attempts and sha(self.original_key.read_bytes()) == self.original_key_hash,
            "whole migration depended on old coordinator or changed sole original key")
        self.custody()
        for source,target in (("owner","selected"),("selected","owner"),("unbound","owner")):
            result = subprocess.run([str(self.args.probe), "--state", str(self.instances[source].host.state), "--address", self.peers[target],
                "--alpn", "peerspan-peer/1", "--method", "GET", "--path", "/peer/v2/networks/"+self.network+"/catalog"],
                capture_output=True, env=self.instances[source].host.environment, timeout=40)
            require(result.returncode == 0 and strict_output(result.stdout)["status"] == 200, "adopted actual H lacks normal member catalog traffic")
        self.trace.append({"all_three_hosts_adopted_same_exact_components_and_transcript_identities":True,
            "first_per_host_full_M_sha256":{label:sha(unb64(body)) for label,body in self.full_migration.items()},
            "no_cross_host_outer_M_serialization_equality_claim":True, "original_only_on_A":True,
            "B_actual_same_device_nominal15_no_new_admin_A":True, "C_remains_unbound":True,
            "coordinator_attempts_after_stop":len(self.coordinator_attempts), "raw_probe_has_no_client_server_pin_claim":True})

    def adoption_postconditions(self, label):
        value = self.instances[label]
        network = self.api(label, "GET", "/v2/networks/"+self.network)[0]; self.views[label] = network
        require(network["context_id"] == self.context and network["root_state_id"] == self.root_id and
            all(network[key] == self.specs[label][key] for key in ("person_public_key", "host_public_key", "member")),
            "adoption replaced own identity/context/root")
        require(len(table_rows(value.host, "dec_contexts", "network_id", " WHERE network_id=?", (self.network,))) == 1 and
            not table_rows(value.host, "dec_operations", "request_id", " WHERE network_id=?", (self.network,)),
            "whole adoption lacks context or fabricated ordinary participant outcome")
        rows = table_rows(value.host, "dec_migrations", "record", " WHERE proposal_id=?", (self.proposal_id,))
        require(len(rows) == 1, "whole migration history missing")
        record = strict_output(rows[0][0].encode())
        require(record["migration_base64"] == self.full_migration.setdefault(label,record["migration_base64"]),
            "this host rewrote its first retained exact complete M bytes")
        require(record["state"] == "adopted" and record["migration_base64"] != "-" and record["fenced"] and
            record["prepared_catalog_base64"] == b64(self.prepared_raw), "adoption rewrote fixed prepared evidence/fence")
        complete = strict_output(unb64(record["migration_base64"]))
        require(set(complete) == {"format","proposal","source_catalog_base64","source_state_base64","prepared_catalog_base64","acknowledgments","commit"} and
            complete["format"] == 1 and complete["proposal"] == strict_output(unb64(self.complete_evidence["proposal_base64"])) and
            complete["commit"] == strict_output(unb64(self.complete_evidence["commit_base64"])) and
            complete["acknowledgments"] == [strict_output(unb64(v)) for v in self.complete_evidence["acknowledgments_base64"]] and
            all(complete[name] == self.complete_evidence[name] for name in
                ("source_catalog_base64","source_state_base64","prepared_catalog_base64")), "retained complete M changed original component bytes or full ACK/root evidence")
        contexts = table_rows(value.host,"dec_contexts","record"," WHERE network_id=? AND context_id=?",(self.network,self.context))
        require(len(contexts) == 1, "adoption lacks its exact context origin record")
        origin = strict_output(contexts[0][0].encode())
        require(origin["origin"] == "migration" and origin["migration_proposal_id"] == self.proposal_id and origin["origin_proof_id"] ==
            "dp_"+sha(lines("peerspan-decentralized-proof-v1","migration",sha(unb64(record["migration_base64"])))),
            "local context origin does not pin this host's exact retained complete M proof")
        if label == "unbound":
            require(network["provider"] is None and network["person_public_key"] == "-" and not self.key_hashes(label),
                "unbound C acquired person/device/provider")
        else:
            provider = network["provider"]
            require(provider is not None and provider["kind"] == "device" and provider["device_public_key"] == self.specs[label]["device_public_key"] and
                provider["lease_id"] == self.activation_facts[label]["device_lease_id"] and network["provider_state"]["state"] == "available",
                "owned adoption did not select actual exact owned device")
            if label == "selected": require(self.key_hashes(label) == self.old_device_hashes[label], "B selected15 seed changed")
            else: require(self.key_hashes(label).get(provider["device_public_key"]) == self.identity_before[label][2],
                "A installed a seed other than its unique approved pending identity")
        versions = self.api(label, "GET", "/v2/networks/"+self.network+"/access-versions")[0]
        for floor in self.source_state["access_maxima"]:
            candidates = versions["policies" if floor["kind"] == "policy" else "groups"]
            subject = "person_public_key" if floor["kind"] == "policy" else "name"
            require(any(row[subject] == floor["subject"] and row["version"] >= floor["version"] for row in candidates),
                "adoption lowered an exact source access floor")
        events = value.host.api("GET", "/v1/activity?limit=1000")
        require(sum(row["kind"] == "network.migrated" for row in events) == 1 and
            sum(row["kind"] == "network.link_applied" for row in events) == self.old_link_events[label],
            "whole adoption duplicated event or ordinary-applied a staged link")

    def history(self):
        for label,value in self.instances.items():
            exported = self.export(label)
            require(exported == self.complete_evidence, "adoption export differs from original complete public carrier")
            value.host.stop(); value.host.start()
            before = all_database_snapshots(value.host.state)
            require(self.export(label) == exported and self.export(label) == exported and
                all_database_snapshots(value.host.state) == before, "history GET changed original bytes or durable rows")
            response = self.call(label, "/adopt", {"proposal_id":self.proposal_id, "commit_id":self.commit_id, "approve":True})
            require(response["migration"]["state"] == "adopted" and all_database_snapshots(value.host.state) == before,
                "exact adopted retry forgot historical result or changed durable rows")
            self.adoption_postconditions(label)
            require(self.export(label) == exported, "exact retry rewrote original evidence")
        require(sha(self.original_key.read_bytes()) == self.original_key_hash and not self.coordinator_attempts,
            "historical retry changed original or contacted old coordinator")
        self.custody()

    def run(self):
        self.prepare_fixture()  # NEW necessary constructor, not an old case.
        for index,function in enumerate((self.identities, self.proposal, self.staged_hosts, self.prepared_union,
                self.ack_all, self.commit_and_adopt, self.history)):
            self.case(index, function)

    def close(self):
        errors = []
        for value in reversed(list(self.instances.values())):
            try: value.host.stop()
            except BaseException as error: errors.append(error)
        if self.legacy is not None:
            try: self.legacy.stop()
            except BaseException as error: errors.append(error)
        self.observer_stop.set()
        if self.observer: self.observer.close()
        if self.observer_thread: self.observer_thread.join(timeout=2)
        if errors: raise errors[0]


def binding():
    directory = Path(__file__).parent
    names, pending = {SPEC.name}, [Path(__file__).name]
    while pending:
        name = pending.pop()
        if name in names: continue
        names.add(name)
        tree = ast.parse((directory/name).read_bytes(), filename=name)
        for node in ast.walk(tree):
            if isinstance(node,ast.Constant) and isinstance(node.value,str) and node.value.endswith(".json") and "/" not in node.value:
                dependency = directory/node.value
                if dependency.is_file(): names.add(node.value)
            modules = [node.module] if isinstance(node,ast.ImportFrom) else [item.name for item in node.names] if isinstance(node,ast.Import) else []
            for module in modules:
                if module and module.startswith("decentralized_"):
                    candidate = module.split(".")[0]+".py"
                    require((directory/candidate).is_file(), "missing independently authored support "+candidate)
                    pending.append(candidate)
    return {"format":1, "implementation_source_read":False, "case_names":CASES,
        "files":{name:sha((directory/name).read_bytes()) for name in sorted(names)},
        "fixture":"NEW ONE legacy network/THREE actual stores; A sole original/raw root, B actual selected15 then Alice admin withdrawn, C SAME-network host-only. Old coordinator stops before in-place cutover.",
        "carrier":"ONLY six exact canonical Base64 fields; original component bytes unchanged; no historical inline EVIDENCE constant used.",
        "reader_bounds":{"owner_local_seconds":40,"stage_elapsed_seconds":120,"stage_dependency_batches":32,
            "note":"Fixture reader bounds only; no change to protocol/signature/request/proposal/transport deadlines."},
        "runtime_cases_executed_during_binding":0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit-binding", type=Path)
    for name in ("baseline", "coordinator", "probe", "owner-host", "selected-host", "unbound-host", "work-dir", "results", "frozen-binding"):
        parser.add_argument("--"+name, type=Path)
    parser.add_argument("--source", help="Exact common current-runtime source commit; separately offered artifacts required")
    args = parser.parse_args(); frozen = binding()
    if args.emit_binding:
        require(not args.emit_binding.exists(), "owned-M binding already exists")
        args.emit_binding.write_bytes(raw_json(frozen)); args.emit_binding.chmod(0o600)
    if args.work_dir is None:
        require(args.emit_binding is not None, "use --emit-binding or separately offered runtime args")
        print("FROZEN seven owned-M controls; no fixture/key/host/probe executed"); return 0
    require(all(getattr(args,name) for name in ("baseline","coordinator","probe","owner_host","selected_host","unbound_host","results","frozen_binding")) and
        re.fullmatch("[0-9a-f]{40}", args.source or ""), "owned-M runtime requires exact separately offered source/artifacts and frozen binding")
    require(strict_output(args.frozen_binding.read_bytes()) == frozen, "owned-M executable/spec/support changed after freeze")
    for name in ("baseline","coordinator","probe","owner_host","selected_host","unbound_host","work_dir","results","frozen_binding"):
        setattr(args,name,getattr(args,name).resolve())
    args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    keys = FixtureKeys(); suite = OwnedMigration(args, keys); failure = detail = None; began = time.monotonic()
    try: suite.run()
    except BaseException as error:
        failure = type(error).__name__; detail = str(error) if isinstance(error,CheckFailure) else "fixture/transport failure; protected captures retained"
        path = args.work_dir/"failure.traceback.private"; path.write_text(traceback.format_exc()); path.chmod(0o600)
    finally:
        try: suite.close()
        except BaseException as error: failure = failure or type(error).__name__
        keys.close()
    result = {"implementation_source_read":False, "source":args.source, "binding_sha256":sha(args.frozen_binding.read_bytes()),
        "artifacts":{name:{"path":str(getattr(args,name)),"sha256":sha(getattr(args,name).read_bytes())} for name in
            ("baseline","coordinator","probe","owner_host","selected_host","unbound_host")},
        "rows":suite.rows, "trace":suite.trace, "failure":failure, "detail":detail, "seconds":round(time.monotonic()-began,3),
        "scope":"NEW one-source three-actual-host functional whole owned migration only; no crash-boundary/installed/live/NAT/MAX-generation/final-head claim",
        "held_subchecks":["Otherwise-positive fresh product admission under ACK fence; not established by denied legacy mutation or history sync."],
        "passed":failure is None and len(suite.rows) == len(CASES) and all(row["passed"] for row in suite.rows)}
    args.results.parent.mkdir(parents=True,exist_ok=True); args.results.write_text(json.dumps(result,indent=2)+"\n")
    print(str(sum(row["passed"] for row in suite.rows))+"/7 NEW owned whole-migration controls passed")
    return 0 if result["passed"] else 1


if __name__ == "__main__": raise SystemExit(main())
