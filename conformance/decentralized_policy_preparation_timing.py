#!/usr/bin/env python3
"""Independent PR138 ordinary-action first-preparation versus signing time.

This binds ONLY the last two cases in decentralized_policy_reapplication_cases.
The sibling-fork, native withdrawal and historical-alias cases have separate
fixture requirements and are not implied by this executable. No implementation
or implementer test is imported. --emit-binding reads source files only.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import ast
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import time
from urllib.parse import quote

from decentralized_fixtures import b64, lines, raw_json, sha, unb64
from decentralized_runtime import CreationSuite, SLOT_FIELDS
from decentralized_storage import CheckFailure, UnixHTTP, all_database_snapshots, require
from decentralized_vectors import strict_output


PIN = "d96e17ac80cdf72f7e00c87f89a017970a366463"
SPEC = Path(__file__).with_name("decentralized_policy_reapplication_cases.json")
PLAN = Path(__file__).with_name("decentralized_policy_reapplication_plan.json")
BINDING = Path(__file__).with_name("decentralized_policy_preparation_timing_binding.json")
CASES = [row["name"] for row in json.loads(SPEC.read_bytes())["cases"]][-2:]
ACTION_FIELDS = set("action_id review signing_requests statement_base64 proof_id catalog committed delivery".split())


def stamp(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def statement_id(statement):
    require(set(statement) == {"format", "kind", "context_id", "payload_base64", "signatures"} and
        statement["format"] == 1, "ordinary statement envelope shape differs")
    return "ds_"+sha(lines("peerspan-decentralized-statement-v1", statement["kind"],
        statement["context_id"], sha(unb64(statement["payload_base64"]))))


def ssh_public(path):
    blob = unb64(path.with_suffix(".pub").read_text().split()[1])
    require(blob[:4] == (11).to_bytes(4, "big") and blob[4:15] == b"ssh-ed25519" and
        blob[15:19] == (32).to_bytes(4, "big") and len(blob) == 51,
        "fixture original SSH public-key framing differs")
    return b64(blob[19:])


class Original:
    """An actual fixture original, generated and used only in A's signer HOME."""
    def __init__(self, directory):
        self.directory = directory
        directory.mkdir(mode=0o700)
        self.path = directory/"original-ed25519"
        made = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.path)],
            capture_output=True, timeout=10)
        require(made.returncode == 0, "fixture original key generation failed")
        self.person = ssh_public(self.path)
        self.count = 0

    def public(self, name):
        require(name == "alice", "fixture attempted to select another original")
        return self.person

    def sshsig(self, name, message):
        require(name == "alice", "fixture attempted to sign as another original")
        self.count += 1
        path = self.directory/("public-message-%03d" % self.count)
        path.write_bytes(message); path.chmod(0o600)
        made = subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(self.path), "-n",
            "peerspan-person-v1", "-q", str(path)], capture_output=True, timeout=10)
        require(made.returncode == 0, "same-machine external original signing failed")
        signature = path.with_name(path.name+".sig")
        signature.chmod(0o600)
        encoded = "".join(line for line in signature.read_text().splitlines() if not line.startswith("-----"))
        return unb64(encoded)


def sqlite_rows(host, table, columns):
    """Normative actual table discovery with a coherent read transaction."""
    result = []
    for path in sorted(host.state.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        with path.open("rb") as stream:
            if stream.read(16) != b"SQLite format 3\x00":
                continue
        with closing(sqlite3.connect(path.as_uri()+"?mode=ro", uri=True)) as db, db, closing(db.cursor()) as cursor:
            cursor.execute("BEGIN")
            if cursor.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                result.extend(cursor.execute('SELECT '+columns+' FROM "'+table+'"').fetchall())
    return result


def without_clock(snapshot):
    value = copy.deepcopy(snapshot)
    for database in value["databases"].values():
        database["tables"].pop("dec_clock", None)
    return value


class TimingFixture:
    def __init__(self, args, root):
        self.args, self.root = args, root
        root.mkdir(mode=0o700)
        self.original = Original(root/"signer-home")
        self.s = CreationSuite(args.host, root/"owner", self.original)
        self.s.host.environment["PATH"] = "/usr/bin:/bin"
        self.s.host.environment.pop("SSH_AUTH_SOCK", None)
        self.base = datetime.now(timezone.utc).replace(microsecond=0)
        self.clock = root/"clock"
        self.clock.write_text(stamp(self.base)); self.clock.chmod(0o600)
        self.s.host.environment.update(PEERSPAN_DEC_TEST_MODE="1", PEERSPAN_DEC_TEST_CLOCK_FILE=str(self.clock))
        require(not any(v in self.s.host.run_arguments for v in ("--person-key-file", "--person-agent")),
            "fixture accidentally supplied original signing to the daemon")
        self.trace, self.native_count = [], 0

    def start(self):
        self.s.host.start(); self.s.identity = self.s.host.api("GET", "/v1/host")
        # Necessary new public setup; no existing positive case is called.
        self.s.name = "Independent PR138 private preparation"
        self.s.preview = self.s.api("POST", "/v2/networks", {"name":self.s.name, "member":self.s.member,
            "person_public_key":self.original.person, "approve":False})[0]
        self.s.creation_shape(self.s.preview, False)
        creation = "/v2/network-creations/"+self.s.preview["creation_id"]
        ready = self.s.api("POST", creation+"/approve", {"context_id":self.s.context_id,
            "root_state_id":self.s.preview["review"]["root_state_id"], "person_public_key":self.original.person,
            "host_public_key":self.s.identity["public_key"], "approve":True})[0]
        for _ in range(8):
            if ready["committed"]:
                break
            slots = ready["signing_requests"]
            require(0 < len(slots) <= 16, "public fixture creation lacks bounded external-original slots")
            ready = self.s.api("POST", creation+"/signed", {"intent_id":slots[0]["intent_id"],
                "signatures":[self.s.slot_signature(slot) for slot in slots]})[0]
        require(ready["committed"], "public fixture creation exceeded eight dependency batches")
        self.network = ready["network"]
        self.route = "/v2/networks/"+self.network["id"]
        self.original_objects = self.s.verify_catalog()
        self.identity = dict(self.s.identity)
        self.key_hash = sha(self.original.path.read_bytes())
        self.original_policy_id, self.original_policy = self.original_objects["policy"]
        self.original_body = strict_output(unb64(self.original_policy["body_base64"]))
        require(self.original_policy["sequence"] == self.original_body["version"] == 1 and
            self.original_policy["issuer"] == {"kind":"person", "person_public_key":self.original.person},
            "fixture does not have the original person's exact initial current policy")

    def at(self, seconds):
        return stamp(self.base+timedelta(seconds=seconds))

    def set_time(self, seconds):
        value = self.at(seconds)
        require(value >= self.clock.read_text(), "fixture attempted authority-clock rewind")
        self.clock.write_text(value)
        self.trace.append({"explicit_decision_time":value, "transport_time_remains_real":True})

    def snapshot(self):
        return all_database_snapshots(self.s.host.state)

    def intent(self, payload):
        encoded = b64(raw_json(payload))
        matches = []
        for identifier, kind, raw, secret in sqlite_rows(self.s.host, "dec_intents", "intent_id,kind,record,secret"):
            if kind != "action":
                continue
            record = strict_output(raw.encode())
            for entry in record["templates"]:
                template = strict_output(unb64(entry["template_base64"]))
                if entry["object_type"] == "policy" and template["payload_base64"] == encoded:
                    require(secret is None, "ordinary action unexpectedly contains a private seed/secret")
                    matches.append((identifier, record))
                    break
        require(len(matches) == 1, "exact actual ordinary action intent is absent or duplicated")
        return matches[0]

    def record_hashes(self):
        return {identifier:sha(raw.encode()) for identifier, kind, raw, secret in
            sqlite_rows(self.s.host, "dec_intents", "intent_id,kind,record,secret") if kind == "action"}

    def save_boundary(self, label):
        value = {"all_rows":self.snapshot(), "clock_rows":[list(row) for row in
            sqlite_rows(self.s.host, "dec_clock", "network_id,record")],
            "actual_host":self.s.host.api("GET", "/v1/host"), "original_key_sha256":sha(self.original.path.read_bytes())}
        path = self.root/(label+".hashes.json")
        path.write_bytes(raw_json(value)); path.chmod(0o600)
        return value

    def payload(self, *, until_seconds=7200):
        payload, body = copy.deepcopy(self.original_policy), copy.deepcopy(self.original_body)
        body.update(version=2, issued_at=self.at(0), valid_until=self.at(until_seconds))
        require("signature" not in body, "unsigned DEC policy body contains a legacy signature")
        payload.update(sequence=2, predecessors=[self.original_policy_id], resolves=[], issued_at=self.at(0),
            not_before=self.at(0), not_after=self.at(until_seconds), body_base64=b64(raw_json(body)))
        require(payload["parents"] == self.original_policy["parents"] and
            payload["root_state_id"] == self.network["root_state_id"], "fixture changed independent issuer provenance")
        return payload

    def prepare(self, payload, *, approve, status=200):
        value = self.s.api("POST", self.route+"/actions", {"kind":"policy", "provider_id":self.original.person,
            "signature_format":"sshsig", "payload_base64":b64(raw_json(payload)), "approve":approve}, status=status)[0]
        if status == 200:
            require(set(value) == ACTION_FIELDS and not value["committed"] and
                value["statement_base64"] == value["proof_id"] == value["catalog"] == "-",
                "unsigned preparation returned signed/public/applied policy")
            require(re.fullmatch(r"act_[0-9a-f]{64}", value["action_id"]) is not None,
                "ordinary action ID is not canonical")
        return value

    def signature(self, slot, payload):
        require(set(slot) == SLOT_FIELDS and slot["object_type"] == "policy" and slot["role"] == "issuer" and
            slot["public_key"] == self.original.person and slot["format"] == "sshsig",
            "ordinary policy requested an unrelated signer/role/format")
        template = strict_output(unb64(slot["template_base64"]))
        expected = {"format":1, "kind":"policy", "context_id":self.network["context_id"],
            "payload_base64":b64(raw_json(payload)), "signatures":[{"role":"issuer", "public_key":self.original.person,
                "format":"sshsig", "signature":"-"}]}
        require(template == expected, "ready ordinary template changed the exact fixed policy payload/issuer")
        identifier = statement_id(template)
        message = lines("peerspan-decentralized-signature-v1", identifier, "issuer", self.original.person)
        require(slot["object_id"] == identifier and unb64(slot["message_base64"]) == message,
            "ready original slot message/ID differs from independent typed derivation")
        return {"slot_id":slot["slot_id"], "role":"issuer", "signature":b64(self.original.sshsig("alice", message))}

    def submit(self, ready, payload, *, status=200, retained_request=None):
        slots = ready["signing_requests"]
        require(len(slots) == 1, "approved ordinary policy lacks its one exact external original slot")
        request = {"intent_id":slots[0]["intent_id"], "signatures":[self.signature(slots[0], payload)]} if retained_request is None else retained_request
        require(request["intent_id"] == slots[0]["intent_id"] and len(request["signatures"]) == 1 and
            request["signatures"][0]["slot_id"] == slots[0]["slot_id"] and request["signatures"][0]["role"] == slots[0]["role"],
            "retained signed submission changed the exact ready intent/slot")
        return self.s.api("POST", self.route+"/actions/"+ready["action_id"]+"/signed", request, status=status)[0]

    def stale_read(self, ready):
        """Expired is an allowed read diagnostic; retained state proves identity."""
        route = self.route+"/actions/"+ready["action_id"]
        connection = UnixHTTP(self.s.host.state/"admin.sock", timeout=10)
        try:
            connection.request("GET", route)
            response = connection.getresponse(); raw = response.read(32*1024*1024+1)
            require(len(raw) <= 32*1024*1024, "stale action read exceeded owner response bound")
            path = self.root/"stale-action-read.json"; path.write_bytes(raw); path.chmod(0o600)
            path.with_suffix(".meta.json").write_bytes(raw_json({"method":"GET", "path":route,
                "status":response.status, "body_sha256":sha(raw)}))
            value = strict_output(raw)
            if response.status == 200:
                require(set(value) == ACTION_FIELDS and value["action_id"] == ready["action_id"] and not value["committed"],
                    "stale action read changed identity or claimed application")
            else:
                require(response.status == 410, "stale action read returned an unrelated failure")
                self.s.error(value, "expired")
            return response.status
        finally:
            connection.close()

    def fixed_times(self, payload, created, approved):
        identifier, record = self.intent(payload)
        require(record["created_at"] == self.at(created) and record["expires_at"] == self.at(300) and
            record["approved_at"] == (self.at(approved) if approved is not None else "-") and
            record["approved"] is (approved is not None), "actual preparation/approval/payload-bound expiry differs")
        require(record["provider"] == {"kind":"original", "signer_public_key":self.original.person,
            "signature_format":"sshsig", "lease_id":"-"}, "ordinary intent changed concrete original provider")
        return identifier, record

    def native_renew(self):
        self.native_count += 1
        argv = [str(self.args.host), "--state", str(self.s.host.state), "access", "renew", "--network",
            self.network["id"], "--person-key", str(self.original.path)]
        began = time.monotonic()
        result = subprocess.run(argv, capture_output=True, env=self.s.host.environment, timeout=40)
        path = self.root/("native-%02d" % self.native_count)
        for suffix, data in (("stdout", result.stdout), ("stderr", result.stderr)):
            target = path.with_suffix("."+suffix); target.write_bytes(data); target.chmod(0o600)
        path.with_suffix(".meta.json").write_bytes(raw_json({"exit":result.returncode,
            "seconds":round(time.monotonic()-began, 3), "stdout_sha256":sha(result.stdout), "stderr_sha256":sha(result.stderr),
            "external_original_only_on_A":True, "argv_without_private_bytes":argv}))
        require(result.returncode == 0 and result.stdout.strip(), "later actual native renewal failed; see protected CLI captures")
        value = self.s.api("GET", self.route+"/policy/"+quote(self.original.person, safe=""))[0]
        statement = strict_output(unb64(value["statement_base64"]))
        payload = strict_output(unb64(statement["payload_base64"]))
        require(statement["kind"] == "policy" and statement_id(statement) == value["statement_id"] and
            payload["issued_at"] == self.clock.read_text() and payload["sequence"] == 2,
            "later native renewal did not admit a fresh exact current policy generation/time")
        return payload

    def unchanged_keys(self):
        require(self.s.host.api("GET", "/v1/host") == self.identity and
            sha(self.original.path.read_bytes()) == self.key_hash, "retry/reopen replaced actual host or original key")

    def stop(self):
        self.s.host.stop()


class Timing:
    def __init__(self, args):
        self.args, self.rows, self.trace, self.fixtures = args, [], [], []

    def case(self, index, call):
        began = time.monotonic()
        try:
            call()
        except BaseException as error:
            self.rows.append({"name":CASES[index], "passed":False, "error_type":type(error).__name__,
                "detail":str(error) if isinstance(error, CheckFailure) else "fixture/transport failure; see protected captures",
                "seconds":round(time.monotonic()-began, 3)})
            raise
        self.rows.append({"name":CASES[index], "passed":True, "seconds":round(time.monotonic()-began, 3)})

    def fixture(self, label):
        value = TimingFixture(self.args, self.args.work_dir/label)
        self.fixtures.append(value); value.start()
        return value

    def delayed(self):
        f = self.fixture("delayed")
        payload = f.payload(); f.set_time(2)
        preview = f.prepare(payload, approve=False)
        require(preview["signing_requests"] == [], "unapproved action exposed a ready signature slot")
        f.fixed_times(payload, 2, None)
        f.set_time(3); ready = f.prepare(payload, approve=True)
        require(ready["action_id"] == preview["action_id"], "explicit approval replaced exact prepared action")
        identifier, before = f.fixed_times(payload, 2, 3)
        require(not before["completed"] and before["signatures"] == [] and before["terminal"] == "-",
            "external-original preparation signed or applied without its original")
        slots = ready["signing_requests"]
        require(len(slots) == 1, "approved delayed policy lacks its exact ready original slot")
        retained_request = {"intent_id":slots[0]["intent_id"], "signatures":[f.signature(slots[0], payload)]}
        signed_request_path = f.root/"honest-signed-request-withheld-at-age3.json"
        signed_request_path.write_bytes(raw_json(retained_request)); signed_request_path.chmod(0o600)
        signed_request_hash = sha(signed_request_path.read_bytes())
        original_signature_count = f.original.count
        before_fixed = {key:before[key] for key in ("created_at", "expires_at", "approved_at", "provider", "templates", "review_base64")}
        f.save_boundary("before-stale-reopen"); f.stop(); f.set_time(301); f.s.host.start()
        before_read = f.snapshot()
        stale_read_status = f.stale_read(ready)
        require(before_read == f.snapshot(), "stale action read changed durable state")
        identifier_after, stale = f.fixed_times(payload, 2, 3)
        require(identifier_after == identifier and all(stale[key] == value for key, value in before_fixed.items()),
            "stale action retry refreshed its fixed preparation fields/template/provider")
        before_failure = f.snapshot(); f.save_boundary("before-stale-signature")
        require(sha(signed_request_path.read_bytes()) == signed_request_hash, "withheld honest signed request changed")
        refused = f.submit(ready, payload, status=410, retained_request=strict_output(signed_request_path.read_bytes()))
        f.s.error(refused, "expired")
        require(f.original.count == original_signature_count, "stale submission invoked the original signer outside its window")
        after_failure = f.snapshot(); f.save_boundary("after-stale-signature")
        # The intent may acquire the documented expired terminal. It cannot
        # acquire signatures or alter exact approved public material.
        _, after = f.fixed_times(payload, 2, 3)
        require(not after["completed"] and after["signatures"] == [] and
            all(after[key] == value for key, value in before_fixed.items()), "stale refusal signed or refreshed exact intent")
        require(after["terminal"] in {"-", "expired"} and
            {key:value for key, value in after.items() if key != "terminal"} ==
            {key:value for key, value in before.items() if key != "terminal"},
            "stale refusal changed private intent beyond a named expired terminal")
        for name, old in without_clock(before_failure)["databases"].items():
            new = without_clock(after_failure)["databases"][name]
            for table, value in old["tables"].items():
                if table != "dec_intents":
                    require(new["tables"][table] == value, "stale signing refusal changed non-intent table "+table)
        renewed = f.native_renew()
        _, historical = f.fixed_times(payload, 2, 3)
        require(all(historical[key] == value for key, value in before_fixed.items()) and historical["signatures"] == [],
            "fresh renewal rewrote the old stale approved action")
        require(renewed["body_base64"] != payload["body_base64"], "fresh renewal reused the stale fixed time/body")
        f.unchanged_keys(); f.save_boundary("after-fresh-native-renewal")
        self.trace.append({"case":CASES[0], "fixed_issued":f.at(0), "actual_created":f.at(2),
            "approved":f.at(3), "fixed_expiry":f.at(300), "stale_decision":f.at(301),
            "honest_signature_generated_at":f.at(3), "withheld_public_signed_request_sha256":signed_request_hash,
            "stale_read_status":stale_read_status, "historical_intent_id":identifier,
            "actual_native_renewal_issued":renewed["issued_at"]})
        f.stop()

    def equality(self):
        f = self.fixture("equality")
        first, second = f.payload(), f.payload(until_seconds=7201)
        f.set_time(2); ready = f.prepare(first, approve=True)
        identifier, record = f.fixed_times(first, 2, 2)
        original_fixed = {key:record[key] for key in ("created_at", "expires_at", "approved_at", "provider", "templates")}
        f.set_time(300)
        before = f.snapshot(); intents = f.record_hashes(); f.save_boundary("before-new-expired-preparation")
        refused = f.prepare(second, approve=False, status=410)
        f.s.error(refused, "expired")
        after = f.snapshot(); f.save_boundary("after-new-expired-preparation")
        require(without_clock(before) == without_clock(after) and f.record_hashes() == intents,
            "new preparation at fixed expiry persisted private/public state")
        result = f.submit(ready, first)
        require(set(result) == ACTION_FIELDS and result["committed"] and result["action_id"] == ready["action_id"],
            "existing honest-signing age300 was refused or replaced")
        statement = strict_output(unb64(result["statement_base64"]))
        require(statement["payload_base64"] == b64(raw_json(first)) and statement_id(statement) == result["review"]["statement_id"],
            "inclusive boundary apply changed the original fixed payload")
        _, applied = f.fixed_times(first, 2, 2)
        require(applied["completed"] and applied["terminal"] == "applied" and
            all(applied[key] == value for key, value in original_fixed.items()), "age300 apply refreshed fixed preparation")
        f.unchanged_keys(); f.save_boundary("after-existing-age300-apply")
        self.trace.append({"case":CASES[1], "existing_intent_id":identifier,
            "fixed_issued":f.at(0), "actual_created":f.at(2), "fixed_expiry":f.at(300),
            "new_preparation_denied_before_persistence":True, "existing_honest_signing_age":300})
        f.stop()


def binding():
    """Exact transitive author source closure; never import/execute a fixture."""
    directory = Path(__file__).parent
    pending, found = [Path(__file__).resolve()], set()
    while pending:
        path = pending.pop()
        if path in found:
            continue
        found.add(path)
        for node in ast.walk(ast.parse(path.read_bytes(), filename=str(path))):
            names = [node.module] if isinstance(node, ast.ImportFrom) and node.level == 0 else (
                [item.name for item in node.names] if isinstance(node, ast.Import) else [])
            for name in names:
                target = directory/(name.split(".")[0]+".py")
                if target.is_file():
                    pending.append(target.resolve())
    found |= {SPEC.resolve(), PLAN.resolve()}
    return {"format":1, "contract_merge":PIN, "scope":CASES, "state":"frozen executable; runtime offer required",
        "files":{str(path.relative_to(directory.parent)):sha(path.read_bytes()) for path in sorted(found)},
        "artifact":None, "source":None, "no_cases_executed_by_emit_binding":True,
        "excluded_scopes":["sibling fork", "untrust", "dropped markers", "historical writer", "final head", "installed", "whole migration"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit-binding", type=Path)
    parser.add_argument("--host", type=Path)
    parser.add_argument("--source")
    parser.add_argument("--host-sha256")
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--results", type=Path)
    args = parser.parse_args()
    if args.emit_binding:
        args.emit_binding.write_bytes(raw_json(binding())+b"\n")
        return
    require(all((args.host, args.source, args.host_sha256, args.work_dir, args.results)), "runtime requires a complete explicit frozen artifact binding")
    require(re.fullmatch(r"[0-9a-f]{40}", args.source) is not None and
        sha(args.host.read_bytes()) == args.host_sha256, "runtime source/hash binding differs")
    frozen = strict_output(BINDING.read_bytes())
    require(frozen["contract_merge"] == PIN and frozen["scope"] == CASES and
        frozen["files"] == binding()["files"], "frozen executable/support/spec input hashes differ")
    require(not args.work_dir.exists() and not args.results.exists(), "runtime paths must be fresh; preserve original failures")
    args.work_dir.mkdir(mode=0o700); args.results.parent.mkdir(parents=True, exist_ok=True)
    value = Timing(args); error = None
    try:
        value.case(0, value.delayed); value.case(1, value.equality)
    except BaseException as caught:
        error = caught
    finally:
        for fixture in value.fixtures:
            try:
                fixture.stop()
            except BaseException as stopped:
                if error is None:
                    error = stopped
        result = {"contract_merge":PIN, "source":args.source, "host_sha256":args.host_sha256,
            "input_binding":binding(), "cases":value.rows, "trace":value.trace,
            "unevaluated":[name for name in CASES if name not in {row["name"] for row in value.rows}],
            "all_passed":len(value.rows) == len(CASES) and all(row["passed"] for row in value.rows) and error is None,
            "no_final_head_installed_or_whole_migration_claim":True}
        args.results.write_bytes(raw_json(result)+b"\n"); args.results.chmod(0o600)
    if error:
        raise error


if __name__ == "__main__":
    main()
