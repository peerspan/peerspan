#!/usr/bin/env python3
"""Independent merged136 current-group aggregate and native read controls.

Only public creation/action/catalog routes construct authority. A legitimate
root transition moves signing to a separately owned synthetic fixture key;
no daemon key is read or copied. Each proof-loss control stops its own actual
disposable fixture and deletes only exact independently identified PUBLIC
dec_objects rows. No whole store is copied and no admission is manufactured.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
import time
from urllib.parse import quote

from decentralized_complete_link import statement_id
from decentralized_fixtures import FixtureKeys, World, b64, lines, raw_json, sha, unb64
from decentralized_runtime import CreationSuite, SLOT_FIELDS
from decentralized_storage import CheckFailure, all_database_snapshots, require
from decentralized_vectors import strict_output


PIN = "32921db847245f7751c473e3cf837065dc615c5b"
SPEC = Path(__file__).with_name("decentralized_current_groups_cases.json")
CASES = [row["name"] for row in strict_output(SPEC.read_bytes())["cases"]]
PEER = "peerspan-peer/1"


def stamp(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


class Groups:
    def __init__(self, args, keys):
        self.args, self.keys = args, keys
        self.world = World(keys)
        self.hosts, self.rows, self.trace = [], [], []
        self.now = datetime.now(timezone.utc).replace(microsecond=0)

    def case(self, index, function):
        if self.args.case and CASES[index] not in self.args.case:
            return
        began = time.monotonic()
        try:
            function()
        except BaseException as error:
            self.rows.append({"name":CASES[index], "passed":False, "error_type":type(error).__name__,
                "detail":str(error) if isinstance(error, CheckFailure) else "fixture/transport failure; see protected captures",
                "seconds":round(time.monotonic()-began, 3)})
            print("FAIL "+CASES[index], flush=True)
            raise
        self.rows.append({"name":CASES[index], "passed":True, "seconds":round(time.monotonic()-began, 3)})
        print("PASS "+CASES[index], flush=True)

    def fixture(self, label):
        """Necessary fresh public setup, never an older positive case function."""
        root = self.args.work_dir/label; root.mkdir(mode=0o700)
        s = CreationSuite(self.args.host, root, self.keys); self.hosts.append(s)
        if label == "empty" and self.args.after_root_fixture:
            return self.retained_empty(s)
        s.name = "Independent current groups "+label
        s.clock = root/"clock"; s.clock.write_text(stamp(self.now)); s.clock.chmod(0o600)
        s.host.environment.update(PEERSPAN_DEC_TEST_MODE="1", PEERSPAN_DEC_TEST_CLOCK_FILE=str(s.clock))
        s.host.environment["PATH"] = "/usr/bin:/bin"
        s.host.environment.pop("SSH_AUTH_SOCK", None)
        # Only the actual state owner supplies its TLS key through --state.
        # The wire client provides no server-pin or host-client behavior claim.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserved:
            reserved.bind(("127.0.0.1", 0)); s.address = "127.0.0.1:"+str(reserved.getsockname()[1])
        s.host.run_arguments = ["--peer-listen", s.address]
        s.host.start(); s.identity = s.host.api("GET", "/v1/host")
        s.preview = s.api("POST", "/v2/networks", {"name":s.name, "member":s.member,
            "person_public_key":self.keys.public("alice"), "approve":False})[0]
        s.creation_shape(s.preview, False)
        creation = "/v2/network-creations/"+s.preview["creation_id"]
        ready = s.api("POST", creation+"/approve", {"context_id":s.context_id,
            "root_state_id":s.preview["review"]["root_state_id"], "person_public_key":self.keys.public("alice"),
            "host_public_key":s.identity["public_key"], "approve":True})[0]
        for _ in range(8):
            if ready["committed"]: break
            slots = ready["signing_requests"]
            require(0 < len(slots) <= 16, "fixture: no bounded original-person creation batch")
            ready = s.api("POST", creation+"/signed", {"intent_id":slots[0]["intent_id"],
                "signatures":[s.slot_signature(slot) for slot in slots]})[0]
        require(ready["committed"], "fixture: public creation did not complete")
        s.network = ready["network"]; s.route = "/v2/networks/"+s.network["id"]
        s.original = s.verify_catalog()
        s.root_signer = "current-groups-external-root-"+label
        expected_root = self.keys.public(s.root_signer)
        retained = sorted(identifier for kind, (identifier, _) in s.original.items() if kind != "root_state")
        rotation = s.api("POST", s.route+"/root-transitions", {"new_root_public_key":expected_root,
            "new_root_signature_format":"ed25519", "signature_format":"ed25519",
            "retained_statement_ids":retained, "approve":True})[0]
        for _ in range(4):
            if rotation["committed"]: break
            slots = rotation["signing_requests"]; signatures = []
            require(0 < len(slots) <= 16, "fixture: external root transition has no ready bounded consent slot")
            for slot in slots:
                require(set(slot) == SLOT_FIELDS and slot["object_type"] == "root_state" and slot["role"] == "new_root" and
                    slot["public_key"] == expected_root and slot["format"] == "ed25519", "fixture: transition requested another private signer")
                template = strict_output(unb64(slot["template_base64"]))
                payload = strict_output(unb64(template["payload_base64"]))
                identifier = statement_id(template)
                message = lines("peerspan-decentralized-signature-v1", identifier, "new_root", expected_root)
                require(template["context_id"] == s.context_id and payload["root_public_key"] == expected_root and
                    payload["epoch"] == 1 and payload["predecessors"] == [s.original["root_state"][0]] and
                    payload["retained_statement_ids"] == retained and slot["object_id"] == identifier and
                    unb64(slot["message_base64"]) == message, "fixture: external root consent terms changed")
                signatures.append({"slot_id":slot["slot_id"], "role":"new_root", "signature":b64(self.keys.sign(s.root_signer, message))})
            rotation = s.api("POST", s.route+"/actions/"+rotation["action_id"]+"/signed",
                {"intent_id":slots[0]["intent_id"], "signatures":signatures})[0]
        require(rotation["committed"], "fixture: legitimate externally owned root transition did not apply")
        root_statement = strict_output(unb64(rotation["statement_base64"]))
        s.root_id = statement_id(root_statement)
        root_payload = strict_output(unb64(root_statement["payload_base64"]))
        expected_roles = [("issuer", s.descriptor["genesis_root_public_key"]), ("new_root", expected_root)]
        require(root_statement["kind"] == "root_state" and root_statement["context_id"] == s.context_id and
            root_payload["root_public_key"] == expected_root and root_payload["epoch"] == 1 and
            root_payload["predecessors"] == [s.original["root_state"][0]] and root_payload["resolves"] == [] and
            root_payload["migration_proposal_id"] == "-" and root_payload["retained_statement_ids"] == retained and
            [(row["role"], row["public_key"]) for row in root_statement["signatures"]] == expected_roles,
            "fixture: exact current root or original finite carrying differs")
        for signature in root_statement["signatures"]:
            require(signature["format"] == "ed25519", "fixture: raw root consent signature format changed")
            s.verify_raw(signature["public_key"], lines("peerspan-decentralized-signature-v1", s.root_id,
                signature["role"], signature["public_key"]), signature["signature"])
        s.network = s.api("GET", s.route)[0]
        require(s.network["root_state_id"] == s.root_id and s.network["root_public_key"] == expected_root and
            s.network["authority"]["state"] == "usable" and s.network["provider_state"]["state"] == "unavailable",
            "fixture: current public authority must be usable while the original signer remains unavailable")
        if label != "empty":
            # The transport pin grants no network authority. The caller's
            # independently retained actual H is still required on every import.
            before = all_database_snapshots(s.host.state)
            grants = s.host.api("GET", "/v1/grants")
            s.api("POST", "/v1/peers", {"id":s.identity["id"], "public_key":s.identity["public_key"], "address":s.address})
            after = all_database_snapshots(s.host.state)
            for name, database in before["databases"].items():
                for table, value in database["tables"].items():
                    if (table.startswith("dec_") and table not in {"dec_contacts", "dec_outbox"}) or table in {"networks", "network_members"}:
                        require(after["databases"][name]["tables"][table] == value,
                            "fixture: public transport pin changed DEC authority, intent, identity, guard or provider rows")
            require(s.host.api("GET", "/v1/grants") == grants, "fixture: transport pin created an operation grant")
            pin_record = {"actual_host_id":s.identity["id"], "actual_public_key":s.identity["public_key"],
                "loopback_listener":s.address, "before":before, "after":after,
                "independent_current_H_still_required":True, "no_grant_or_authority_provider_change":True}
            pin_path = s.root/"transport-pin.public.json"; pin_path.write_bytes(raw_json(pin_record)); pin_path.chmod(0o600)
            # Admit a hostless second person before group references; no group
            # or membership is supplied by the manual transport pin itself.
            bob = self.statement(s, "person_lease", {"root_state_id":s.root_id, "operation_id":"-", "sequence":1,
                "predecessors":[], "resolves":[], "retained_statement_ids":[],
                "subject":{"person_public_key":self.keys.public("bob"), "host_public_key":"-", "device_public_key":"-", "member":"Group Bob", "scopes":0},
                "issuer":{"kind":"root", "person_public_key":"-"}, "parents":[], "issued_at":stamp(self.now),
                "not_before":stamp(self.now), "not_after":stamp(self.now+timedelta(days=1))})
            self.import_objects(s, [bob])
            s.members = sorted("person_"+sha(unb64(self.keys.public(name))) for name in ("alice", "bob"))
            persons = s.api("GET", s.route+"/persons")[0]
            require(any(row["person_public_key"] == self.keys.public("bob") and row["person_lease_id"] == bob.statement_id
                for row in persons["persons"]), "fixture: hostless second person is not independently admitted before group references")
        else:
            s.members = ["person_"+sha(unb64(self.keys.public("alice")))]
        s.policy = next(entry for entry in s.api("GET", s.route+"/catalog")[0]["catalog"]["objects"] if entry["kind"] == "policy")
        s.original_policy_id = statement_id(strict_output(unb64(s.policy["body_base64"])))
        self.trace.append({"uncounted_actual_fixture":label, "host_public_key":s.identity["public_key"],
            "network_id":s.network["id"], "context_id":s.context_id, "root_state_id":s.root_id,
            "external_fixture_root_public_key":expected_root, "no_daemon_key_read_copy_or_store_copy":True,
            "exact_independently_admitted_stable_member_ids":s.members, "wire_probe_has_no_server_pin_claim":True})
        return s

    def retained_empty(self, s):
        """Resume only the actual completed-root fixture; no setup replay."""
        original = self.args.after_root_fixture
        frozen = strict_output(SPEC.read_bytes())["fixture_continuation"]
        boundary_path = original/"stopped-boundary.public.json"
        require(str(original) == frozen["actual_fixture_dir"] and sha(boundary_path.read_bytes()) == frozen["stopped_boundary_sha256"],
            "continuation: exact original stopped public-boundary binding changed")
        boundary = strict_output(boundary_path.read_bytes())
        require(boundary["group_assertions_evaluated"] == 0 and boundary["candidate_object_present"] ==
            boundary["candidate_admitted"] == 0, "continuation: original TLS failure did not stop before group input/admission")
        s.host.state = original/"state"; s.clock = original/"clock"
        require(not (s.host.state/"admin.sock").exists() and s.clock.read_text() == boundary["clock"] and
            all_database_snapshots(s.host.state) == boundary["before_continuation"],
            "continuation: original stopped store/clock changed since its exact public boundary")
        new_home = str(s.root/"home"); old_home = str(original/"home")
        for key, value in list(s.host.environment.items()):
            if value == new_home or value.startswith(new_home+"/"):
                s.host.environment[key] = old_home+value[len(new_home):]
        s.host.environment.update(PEERSPAN_DEC_TEST_MODE="1", PEERSPAN_DEC_TEST_CLOCK_FILE=str(s.clock))
        s.host.environment["PATH"] = "/usr/bin:/bin"; s.host.environment.pop("SSH_AUTH_SOCK", None)
        s.address = boundary["original_peer_listener"]
        s.host.run_arguments = ["--peer-listen", s.address]
        s.preview = strict_output((original/"public-responses/001.json").read_bytes())
        s.name = s.preview["review"]["name"]
        s.host.start(); s.identity = s.host.api("GET", "/v1/host"); s.creation_shape(s.preview, False)
        s.network = boundary["network"]; s.route = "/v2/networks/"+s.network["id"]
        actual = s.api("GET", s.route)[0]
        require(actual["root_state_id"] == s.network["root_state_id"] and actual["root_public_key"] == s.network["root_public_key"] and
            actual["host_public_key"] == s.identity["public_key"] == s.network["host_public_key"] and
            actual["person_public_key"] == s.network["person_public_key"] == self.keys.public("alice") and
            actual["provider"] == s.network["provider"] and actual["authority"] == s.network["authority"] and
            actual["provider_state"] == s.network["provider_state"], "continuation: existing actual root/identity/provider/current authority changed")
        catalog = strict_output((original/"public-responses/004.json").read_bytes())["catalog"]
        s.policy = next(entry for entry in catalog["objects"] if entry["kind"] == "policy")
        s.original_policy_id = statement_id(strict_output(unb64(s.policy["body_base64"])))
        require(all_database_snapshots(s.host.state) == boundary["before_continuation"],
            "continuation: reopening/read checks changed original rows before the first group assertion")
        self.trace.append({"same_actual_completed_root_fixture":str(original), "original_clock_unchanged":boundary["clock"],
            "no_creation_root_transition_Bob_import_or_transport_pin_replayed":True, "group_assertions_previously_evaluated":0})
        return s

    def retained_ancestor_loss(self):
        """The failed read only: no authority writer or proof loss is replayed."""
        original = self.args.retained_missing_ancestor
        frozen = strict_output(SPEC.read_bytes())["failed_ancestor_continuation"]
        require(str(original) == frozen["actual_fixture_dir"], "continuation: wrong failed ancestor fixture")
        for name, digest in frozen["public_file_sha256"].items():
            require(sha((original/name).read_bytes()) == digest, "continuation: exact failed fixture/public-proof/control binding changed")
        root = self.args.work_dir/"missing-ancestor"; root.mkdir(mode=0o700)
        s = CreationSuite(self.args.host, root, self.keys); self.hosts.append(s)
        s.host.state = original/"state"; s.clock = original/"clock"
        require(not (s.host.state/"admin.sock").exists(), "continuation: actual failed ancestor fixture is not stopped")
        new_home, old_home = str(root/"home"), str(original/"home")
        for key, value in list(s.host.environment.items()):
            if value == new_home or value.startswith(new_home+"/"):
                s.host.environment[key] = old_home+value[len(new_home):]
        s.host.environment.update(PEERSPAN_DEC_TEST_MODE="1", PEERSPAN_DEC_TEST_CLOCK_FILE=str(s.clock))
        s.host.environment["PATH"] = "/usr/bin:/bin"; s.host.environment.pop("SSH_AUTH_SOCK", None)
        loss = strict_output((original/"proof-loss.public.json").read_bytes())
        expected = {"databases":loss["after"], "private_file_manifest_sha256":loss["private_file_manifest_sha256"]}
        require(self.protected(s) == expected and loss["target_statement_id"] == frozen["missing_statement_id"],
            "continuation: retained faulty rows/private files or exact missing statement changed")
        s.network = strict_output((original/"public-responses/007.json").read_bytes())
        s.context_id = s.network["context_id"]; s.route = "/v2/networks/"+s.network["id"]
        catalog = strict_output((original/"public-responses/010.json").read_bytes())["catalog"]
        s.policy = next(entry for entry in catalog["objects"] if entry["kind"] == "policy")
        s.original_policy_id = statement_id(strict_output(unb64(s.policy["body_base64"])))
        s.host.start(); actual_host = s.host.api("GET", "/v1/host")
        require(actual_host["public_key"] == s.network["host_public_key"] and self.protected(s) == expected,
            "continuation: reopening changed actual host or retained faulty rows/private files")
        self.trace.append({"six_passed_group_functions_skipped":True, "same_actual_failed_fixture":str(original),
            "no_creation_rotation_pin_import_proof_deletion_or_consent_replayed":True,
            "original_clock_sha256_unchanged":frozen["public_file_sha256"]["clock"],
            "missing_statement_id":frozen["missing_statement_id"]})
        return s

    def retained_fork(self):
        """Read the original Rust fork; no setup or signed input is replayed."""
        original = self.args.retained_fork
        frozen = strict_output(SPEC.read_bytes())["rust_fork_continuation"]
        require(str(original) == frozen["actual_fixture_dir"], "continuation: wrong original Rust fork fixture")
        boundary_path = original/"stopped-fork-boundary.public.json"
        require(sha(boundary_path.read_bytes()) == frozen["stopped_boundary_sha256"],
            "continuation: original stopped fork boundary changed")
        boundary = strict_output(boundary_path.read_bytes())
        for name, digest in boundary["original_public_file_sha256"].items():
            require(sha((original/name).read_bytes()) == digest, "continuation: original public input/clock binding changed")
        root = self.args.work_dir/"fork"; root.mkdir(mode=0o700)
        s = CreationSuite(self.args.host, root, self.keys); self.hosts.append(s)
        s.host.state = original/"state"; s.clock = original/"clock"
        require(not (s.host.state/"admin.sock").exists(), "continuation: original fork fixture is not stopped")
        new_home, old_home = str(root/"home"), str(original/"home")
        for key, value in list(s.host.environment.items()):
            if value == new_home or value.startswith(new_home+"/"):
                s.host.environment[key] = old_home+value[len(new_home):]
        s.host.environment.update(PEERSPAN_DEC_TEST_MODE="1", PEERSPAN_DEC_TEST_CLOCK_FILE=str(s.clock))
        s.host.environment["PATH"] = "/usr/bin:/bin"; s.host.environment.pop("SSH_AUTH_SOCK", None)
        s.address = boundary["original_peer_listener"]; s.host.run_arguments = ["--peer-listen", s.address]
        s.network = boundary["network"]; s.context_id = s.network["context_id"]
        s.route = "/v2/networks/"+s.network["id"]
        require(s.network["person_public_key"] == self.keys.public("alice") and
            self.protected(s) == boundary["stopped_protected"],
            "continuation: original identity/rows/private files/guard changed before reopening")
        catalog = strict_output((original/"public-responses/010.json").read_bytes())["catalog"]
        s.policy = next(entry for entry in catalog["objects"] if entry["kind"] == "policy")
        s.original_policy_id = statement_id(strict_output(unb64(s.policy["body_base64"])))
        s.host.start(); identity = s.host.api("GET", "/v1/host")
        require(identity["public_key"] == s.network["host_public_key"] and
            self.protected(s) == boundary["stopped_protected"],
            "continuation: reopening changed the actual host or stopped protected state")
        self.trace.append({"four_passed_Rust_functions_skipped":True, "same_actual_failed_fork":str(original),
            "no_creation_rotation_pin_import_signature_consent_or_time_replayed":True,
            "original_clock_sha256":boundary["original_public_file_sha256"]["clock"],
            "exact_conflict_ids":boundary["expected_conflict_ids"]})
        return s, boundary["expected_conflict_ids"]

    def statement(self, s, kind, payload, *, admin=False):
        return self.world.statement(kind, payload,
            [("issuer", "alice" if admin else s.root_signer, "sshsig" if admin else "ed25519")], context_id=s.context_id)

    def group(self, s, name, *, sequence=1, predecessors=(), seconds=3600, admin=False, members=None):
        body = {"network_id":s.network["id"], "name":name, "version":sequence,
            "defined_at":stamp(self.now), "members":s.members if members is None else members}
        parents = ([{"role":"issuer_admin", "id":s.original["admin_lease"][0]},
            {"role":"issuer_person", "id":s.original["person_lease"][0]}] if admin else [])
        return self.statement(s, "group", {"root_state_id":s.root_id, "operation_id":"-", "sequence":sequence,
            "predecessors":sorted(predecessors), "resolves":[],
            "issuer":{"kind":"person" if admin else "root", "person_public_key":self.keys.public("alice") if admin else "-"},
            "parents":parents, "issued_at":stamp(self.now), "not_before":stamp(self.now),
            "not_after":stamp(self.now+timedelta(seconds=seconds)), "body_base64":b64(raw_json(body))}, admin=admin)

    def import_objects(self, s, objects):
        catalog = {"format":1, "context_id":s.context_id, "objects":sorted((obj.entry() for obj in objects), key=lambda row:row["id"])}
        request = raw_json({"catalog":catalog})
        argv = [str(self.args.probe), "--address", s.address, "--state", str(s.host.state), "--alpn", PEER,
            "--method", "POST", "--path", "/peer/v2/networks/"+s.network["id"]+"/catalog", "--body-stdin"]
        number = len(list(s.root.glob("wire-*.request.json")))+1; prefix = s.root/("wire-%03d" % number)
        saved_request = prefix.with_suffix(".request.json")
        saved_request.write_bytes(request); saved_request.chmod(0o600)
        result = subprocess.run(argv, input=request, capture_output=True, env=s.host.environment, timeout=40)
        for suffix, data in (("stdout", result.stdout), ("stderr", result.stderr)):
            path = prefix.with_suffix("."+suffix); path.write_bytes(data); path.chmod(0o600)
        prefix.with_suffix(".meta.json").write_bytes(raw_json({"exit":result.returncode, "request_sha256":sha(request),
            "actual_own_host_state_used":True, "no_server_pin_claim":True}))
        require(result.returncode == 0, "fixture: authenticated current-member public catalog transport failed")
        value = strict_output(result.stdout)
        require(set(value) == {"status", "body"} and value["status"] == 200 and set(value["body"]) == {"catalog"},
            "fixture: current-member catalog union refused otherwise complete public signed evidence")
        returned = value["body"]["catalog"]
        require(returned["context_id"] == s.context_id and all(obj.entry() in returned["objects"] for obj in objects),
            "fixture: accepted union did not retain exact independent public proof bytes")

    def private_stream(self, s, name):
        connection = sqlite3.connect(self.normative_database(s).as_uri()+"?mode=ro", uri=True)
        try:
            connection.execute("BEGIN")
            values = {}
            for table, columns in (("dec_heads", "record"), ("dec_highwater", "version,record")):
                rows = connection.execute("SELECT "+columns+" FROM "+table+" WHERE network_id=? AND context_id=? AND stream_kind='group' AND subject=? AND subject2='-'",
                    (s.network["id"], s.context_id, name)).fetchall()
                require(len(rows) == 1, "fixture: public admitted group lacks its exact normative retained stream row")
                values[table] = [[b64(value) if isinstance(value, bytes) else value for value in row] for row in rows]
            return values
        finally:
            connection.close()

    def normative_database(self, s):
        # Normal hosts also own an isolated bootstrap resource database. Select
        # the actual generated file by its normative DEC table, never by a
        # guessed filename or a one-database assumption.
        candidates = []
        for name in all_database_snapshots(s.host.state)["databases"]:
            path = s.host.state/name
            with sqlite3.connect(path.as_uri()+"?mode=ro", uri=True) as connection:
                if connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='dec_objects'").fetchone():
                    candidates.append(path)
        require(len(candidates) == 1, "fixture: expected one actual database owning normative dec_objects")
        return candidates[0]

    def policy_unchanged(self, s):
        value = s.api("GET", s.route+"/policy/"+quote(self.keys.public("alice"), safe=""))[0]
        require(value == {"statement_id":s.original_policy_id, "statement_base64":s.policy["body_base64"]},
            "unrelated complete personal policy became unavailable or changed because of a group-only problem")

    def protected(self, s):
        databases = all_database_snapshots(s.host.state)
        database_paths = {s.host.state/name for name in databases["databases"]}
        excluded = {str(path)+suffix for path in database_paths for suffix in ("", "-wal", "-shm", "-journal")}
        files = []
        # Hash only; no private bytes enter a response, trace or fixture copy.
        # Include HOME to catch an unwanted generated default original key.
        for label, root in (("state", s.host.state), ("home", Path(s.host.environment["HOME"]))):
            for path in sorted(root.rglob("*")):
                require(not path.is_symlink(), "fixture: unexpected private-state symlink")
                if path.is_file() and str(path) not in excluded:
                    files.append([label, str(path.relative_to(root)), sha(path.read_bytes())])
        return {"databases":databases, "private_file_manifest_sha256":sha(raw_json(files))}

    def read(self, s, objects):
        before = self.protected(s)
        value = s.api("GET", s.route+"/groups")[0]
        expected = [{"name":strict_output(unb64(strict_output(obj.payload)["body_base64"]))["name"],
            "statement_id":obj.statement_id, "statement_base64":b64(obj.body)} for obj in objects]
        expected.sort(key=lambda row:row["name"])
        require(value == {"context_id":s.context_id, "groups":expected}, "current groups did not equal exact independently usable original-byte/name-sorted rows")
        self.policy_unchanged(s)
        require(self.protected(s) == before, "group/current-policy GET changed a DB row, private file/key, guard, provider, head, maximum, outbox or event")

    def denied_read(self, s, code, identifiers):
        before = self.protected(s)
        value = s.api("GET", s.route+"/groups", status=409)[0]; s.error(value, code)
        details = value["details"]
        expected_required = sorted(identifiers) if code == "proof_required" else []
        expected_conflicts = sorted(identifiers) if code == "state_conflict" else []
        require(details["network_id"] == s.network["id"] and details["context_id"] == s.context_id and
            details["required_ids"] == expected_required and details["conflict_ids"] == expected_conflicts,
            "aggregate group refusal omitted/invented an exact ID or used the wrong missing/conflict diagnostic field")
        self.policy_unchanged(s)
        require(self.protected(s) == before, "failed aggregate group read repaired/mutated state, private files or an unrelated domain")

    def native(self, s, objects):
        before = self.protected(s)
        result = subprocess.run([str(self.args.host), "--state", str(s.host.state), "network", "groups", s.network["id"]],
            capture_output=True, env=s.host.environment, timeout=30)
        for suffix, data in (("stdout", result.stdout), ("stderr", result.stderr)):
            path = s.root/("native-groups."+suffix); path.write_bytes(data); path.chmod(0o600)
        require(result.returncode == 0 and result.stdout.strip(), "native network groups did not read verified groups without a signer")
        text = result.stdout.decode("utf-8")
        for obj in objects:
            payload = strict_output(obj.payload); body = strict_output(unb64(payload["body_base64"]))
            require(body["name"] in text and str(body["version"]) in text, "native groups omitted a current group name or version")
            for member in body["members"]:
                label = "Fixture owner" if member == "person_"+sha(unb64(self.keys.public("alice"))) else "Group Bob"
                require(member in text or label in text, "native groups omitted an actual independently admitted member")
        require(self.protected(s) == before, "native group display changed any durable state or generated a private key")

    def remove_public_proof(self, s, target):
        """Parent-approved exact public loss on THIS stopped actual fixture."""
        s.host.stop()
        before_protected = self.protected(s); before = before_protected["databases"]
        connection = sqlite3.connect(self.normative_database(s))
        try:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute("SELECT proof_id,kind,body FROM dec_objects WHERE network_id=? AND context_id=?",
                (s.network["id"], s.context_id)).fetchall()
            removed = []
            for identifier, kind, original in rows:
                require(kind not in {"activation", "migration"}, "fixture: containing public composite prevents the independently enumerated ordinary proof-loss precondition")
                envelope = strict_output(original)
                if statement_id(envelope) == target.statement_id:
                    require(kind == target.kind and unb64(envelope["payload_base64"]) == target.payload,
                        "fixture: public alias has different exact signed payload")
                    removed.append((identifier, kind, original))
            require(removed and any(original == target.body for _, _, original in removed), "fixture: intended exact current/ancestor public proof was not present before loss")
            for identifier, kind, original in removed:
                cursor = connection.execute("DELETE FROM dec_objects WHERE network_id=? AND context_id=? AND proof_id=? AND kind=? AND body=?",
                    (s.network["id"], s.context_id, identifier, kind, original))
                require(cursor.rowcount == 1, "fixture: exact public row-only loss did not affect exactly its one identified row")
            connection.commit()
        except BaseException:
            connection.rollback(); raise
        finally:
            connection.close()
        after_protected = self.protected(s); after = after_protected["databases"]
        require(before_protected["private_file_manifest_sha256"] == after_protected["private_file_manifest_sha256"],
            "fixture: exact public proof loss changed a private file/key")
        require(before["databases"].keys() == after["databases"].keys(), "fixture: proof loss changed another database")
        for name in before["databases"]:
            old, new = before["databases"][name], after["databases"][name]
            require(old["user_version"] == new["user_version"] and old["tables"].keys() == new["tables"].keys(), "fixture: proof loss changed schema/version")
            for table in old["tables"]:
                require(old["tables"][table]["ddl_sha256"] == new["tables"][table]["ddl_sha256"], "fixture: proof loss changed a table definition")
                if table != "dec_objects":
                    require(old["tables"][table] == new["tables"][table], "fixture: proof loss changed private/admission/head/max/guard state")
                else:
                    expected = list(old["tables"][table]["rows"])
                    for identifier, kind, original in removed:
                        digest = sha(raw_json([["str", s.network["id"]], ["str", s.context_id], ["str", identifier], ["str", kind], ["blob", b64(original)]]))
                        require(digest in expected, "fixture: independently identified exact public row hash was not in the before snapshot")
                        expected.remove(digest)
                    require(new["tables"][table]["rows"] == sorted(expected), "fixture: named proof loss changed another public object row")
        public = {"target_statement_id":target.statement_id, "removed_public_rows":[{"proof_id":i, "kind":k, "body_base64":b64(raw)} for i,k,raw in removed],
            "before":before, "after":after, "private_file_manifest_sha256":after_protected["private_file_manifest_sha256"],
            "no_store_or_private_key_copy":True, "only_public_dec_objects_rows_removed":True}
        path = s.root/"proof-loss.public.json"; path.write_bytes(raw_json(public)); path.chmod(0o600)
        s.host.start()
        require(self.protected(s) == after_protected,
            "opening proof-loss fixture changed a private file/key, retained private/head/max/guard or remaining public row")
        self.trace.append({"proof_loss_fixture":str(s.root), "target_statement_id":target.statement_id,
            "removed_public_proof_ids":sorted(row[0] for row in removed), "named_public_loss_sha256":sha(path.read_bytes()),
            "all_other_rows_and_private_hashes_unchanged":True})

    def run(self):
        def empty():
            s = self.fixture("empty"); self.read(s, []); s.host.stop()
        self.case(0, empty)
        def current():
            s = self.fixture("current")
            zulu, alpha = self.group(s, "zulu"), self.group(s, "alpha")
            self.import_objects(s, [zulu]); self.import_objects(s, [alpha])
            self.read(s, [alpha, zulu]); self.native(s, [alpha, zulu]); s.host.stop()
        self.case(1, current)
        def expired():
            s = self.fixture("expiry")
            old, keep = self.group(s, "expiry", seconds=3600), self.group(s, "independent")
            self.import_objects(s, [old, keep])
            new = self.group(s, "expiry", sequence=2, predecessors=[old.statement_id], seconds=60)
            self.import_objects(s, [new]); heads = self.private_stream(s, "expiry")
            s.clock.write_text(stamp(self.now+timedelta(seconds=61)))
            self.read(s, [keep])
            require(self.private_stream(s, "expiry") == heads, "expiry exposed a lower group or erased admitted higher maximum/head")
            s.host.stop()
        self.case(2, expired)
        def withdrawn():
            s = self.fixture("withdrawn")
            admin, keep = self.group(s, "withdrawn", admin=True), self.group(s, "independent")
            self.import_objects(s, [admin, keep]); heads = self.private_stream(s, "withdrawn")
            withdrawal = self.statement(s, "admin_withdraw", {"root_state_id":s.root_id,
                "issuer":{"kind":"root", "person_public_key":"-"}, "parents":[], "issued_at":stamp(self.now),
                "target":{"statement_id":s.original["admin_lease"][0], "person_public_key":self.keys.public("alice"), "host_public_key":"-", "device_public_key":"-"},
                "kept_statement_ids":[], "ratifies":"-"})
            self.import_objects(s, [withdrawal]); self.read(s, [keep])
            require(self.private_stream(s, "withdrawn") == heads, "withdrawal erased the group's admitted high-water/history")
            s.host.stop()
        self.case(3, withdrawn)
        def fork():
            if self.args.retained_fork:
                s, identifiers = self.retained_fork()
                self.denied_read(s, "state_conflict", identifiers); s.host.stop(); return
            s = self.fixture("fork")
            base, keep = self.group(s, "fork"), self.group(s, "independent")
            self.import_objects(s, [base, keep])
            left = self.group(s, "fork", sequence=2, predecessors=[base.statement_id], members=[s.members[0]])
            right = self.group(s, "fork", sequence=2, predecessors=[base.statement_id], members=[s.members[1]])
            self.import_objects(s, [left, right]); self.denied_read(s, "state_conflict", [left.statement_id, right.statement_id]); s.host.stop()
        self.case(4, fork)
        def lost_head():
            s = self.fixture("missing-head")
            old, keep = self.group(s, "missing"), self.group(s, "independent")
            self.import_objects(s, [old, keep])
            head = self.group(s, "missing", sequence=2, predecessors=[old.statement_id]); self.import_objects(s, [head])
            heads = self.private_stream(s, "missing"); self.remove_public_proof(s, head)
            self.denied_read(s, "proof_required", [head.statement_id])
            require(self.private_stream(s, "missing") == heads, "missing group body changed admission/high-water/head metadata")
            s.host.stop()
        self.case(5, lost_head)
        def lost_ancestor():
            if self.args.retained_missing_ancestor:
                s = self.retained_ancestor_loss(); heads = self.private_stream(s, "missing")
                missing = strict_output(SPEC.read_bytes())["failed_ancestor_continuation"]["missing_statement_id"]
                self.denied_read(s, "proof_required", [missing])
                require(self.private_stream(s, "missing") == heads, "read-only continuation changed the original admitted group head/maximum")
                s.host.stop(); return
            s = self.fixture("missing-ancestor")
            old, keep = self.group(s, "missing"), self.group(s, "independent")
            self.import_objects(s, [old, keep])
            head = self.group(s, "missing", sequence=2, predecessors=[old.statement_id]); self.import_objects(s, [head])
            heads = self.private_stream(s, "missing"); self.remove_public_proof(s, old)
            self.denied_read(s, "proof_required", [old.statement_id])
            require(self.private_stream(s, "missing") == heads, "missing required ancestor changed group maximum/head metadata")
            s.host.stop()
        self.case(6, lost_ancestor)


def binding():
    directory = Path(__file__).parent
    names = [Path(__file__).name, SPEC.name, "decentralized_runtime.py", "decentralized_storage.py", "decentralized_fixtures.py", "decentralized_complete_link.py"]
    return {"contract_pin":PIN, "implementation_source_read":False, "case_names":CASES,
        "files":{name:sha((directory/name).read_bytes()) for name in names},
        "native_public_help_binding":"network groups [ID]; global --state; supplied by parent for binding only before runtime offer",
        "fixture_recipe":"Same already-created actual empty fixture on the explicitly frozen setup-only continuation; other scenarios use fresh actual public create/root-transition/current-member imports. Before imports, public own-host transport pin only; no old positive function, store copy or daemon private-key extraction. Two exact public-row-loss fixtures retain all private/admission/head/max/guard hashes.",
        "fixture_continuation":strict_output(SPEC.read_bytes()).get("fixture_continuation"),
        "failed_ancestor_continuation":strict_output(SPEC.read_bytes()).get("failed_ancestor_continuation"),
        "rust_fork_continuation":strict_output(SPEC.read_bytes()).get("rust_fork_continuation"),
        "runtime_cases_executed_during_binding":0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit-binding", type=Path)
    for name in ("host", "probe", "work-dir", "results", "frozen-binding"): parser.add_argument("--"+name, type=Path)
    parser.add_argument("--source")
    parser.add_argument("--case", action="append", help="Only separately reviewed failed/unevaluated controls; no passed case function runs")
    parser.add_argument("--after-root-fixture", type=Path, help="Same stopped empty-group fixture after setup-only TLS failure; no create/root/key/clock/import replay")
    parser.add_argument("--retained-missing-ancestor", type=Path, help="ONLY last failed control on its exact actual faulted store; no setup/deletion or six passed controls replayed")
    parser.add_argument("--retained-fork", type=Path, help="Same failed Rust fork read, followed only by the two unevaluated fresh public-proof-loss fixtures")
    args = parser.parse_args(); value = binding()
    require(not args.case or set(args.case) <= set(CASES), "unknown current-group case selector")
    require(not args.retained_missing_ancestor or (args.case == [CASES[6]] and args.after_root_fixture is None),
        "failed ancestor continuation requires exactly its one case and no other fixture selector")
    require(not args.retained_fork or (args.case == CASES[4:] and args.after_root_fixture is None and args.retained_missing_ancestor is None),
        "Rust fork continuation requires exactly failed case4 plus unevaluated5/6 and no other fixture selector")
    if args.emit_binding:
        require(not args.emit_binding.exists(), "binding output already exists")
        args.emit_binding.write_bytes(raw_json(value)); args.emit_binding.chmod(0o600)
    if not args.work_dir:
        require(args.emit_binding is not None, "use --emit-binding or explicitly offered full runtime arguments")
        print("FROZEN seven current-group controls; no host/probe executed")
        return 0
    require(args.host and args.probe and args.results and args.frozen_binding and re.fullmatch("[0-9a-f]{40}", args.source or ""),
        "runtime needs separately offered exact source/host/probe and frozen binding")
    require(strict_output(args.frozen_binding.read_bytes()) == value, "current-group executable/fixture recipe changed after freeze")
    for name in ("host", "probe", "work_dir", "results"): setattr(args, name, getattr(args, name).resolve())
    if args.after_root_fixture: args.after_root_fixture = args.after_root_fixture.resolve()
    if args.retained_missing_ancestor: args.retained_missing_ancestor = args.retained_missing_ancestor.resolve()
    if args.retained_fork: args.retained_fork = args.retained_fork.resolve()
    args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    keys = FixtureKeys(); suite = None; failure = detail = None; began = time.monotonic()
    try:
        suite = Groups(args, keys); suite.run()
    except BaseException as error:
        failure = type(error).__name__; detail = str(error) if isinstance(error, CheckFailure) else "fixture/transport failure; protected captures retained"
    finally:
        if suite is not None:
            for s in reversed(suite.hosts):
                try: s.host.stop()
                except BaseException as error: failure = failure or type(error).__name__
        keys.close()
    result = {"contract_pin":PIN, "implementation_source_read":False, "source":args.source,
        "host":{"path":str(args.host), "sha256":sha(args.host.read_bytes())}, "probe":{"path":str(args.probe), "sha256":sha(args.probe.read_bytes())},
        "binding_sha256":sha(args.frozen_binding.read_bytes()), "rows":[] if suite is None else suite.rows,
        "trace":[] if suite is None else suite.trace, "failure":failure, "detail":detail, "seconds":round(time.monotonic()-began, 3),
        "scope":"NEW verified aggregate/native group reads only; no installed/final-head/product-call/size-pressure or internal native HTTP tracing claim",
        "selected_cases":CASES if not args.case else [name for name in CASES if name in args.case],
        "passed":failure is None and suite is not None and len(suite.rows) == (len(set(args.case)) if args.case else len(CASES)) and all(row["passed"] for row in suite.rows)}
    args.results.parent.mkdir(parents=True, exist_ok=True); args.results.write_text(json.dumps(result, indent=2)+"\n")
    print(str(sum(row["passed"] for row in result["rows"]))+"/7 NEW current-group controls passed")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
