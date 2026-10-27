#!/usr/bin/env python3
"""Independent merged131 omitted owner-deadline and admin-root defaults.

Only process/codecs from our own suites are reused; no old test body is called.
A's actual root stays in place; a new cold original is generated only on C.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import socket
import subprocess
import time

from decentralized_complete_link import packet_message, table_rows
from decentralized_fixtures import FixtureKeys, raw_json, sha, unb64
from decentralized_native_introduction import Introduction, ssh_public
from decentralized_owner_preview import authority_rows
from decentralized_runtime import CreationSuite
from decentralized_storage import CheckFailure, require
from decentralized_vectors import strict_output

PIN = "e7cb49bdec5dbaa254abfb2417d6bc695d65d88d"
SPEC = Path(__file__).with_name("decentralized_native_defaults_cases.json")
CASES = [c["name"] for c in json.loads(SPEC.read_bytes())["cases"]]


class Defaults:
    def __init__(self, args, keys):
        self.args = args; self.trace = []; self.calls = 0
        self.a = CreationSuite(args.host, args.work_dir/"owner", keys)
        self.b = CreationSuite(args.host, args.work_dir/"cold", keys)
        self.a.host.state = args.fixture_dir/"owner"/"state"
        if args.retained_from: self.b.host.state = args.retained_from/"cold"/"state"
        require(not (self.a.host.state/"admin.sock").exists(), "actual creator state is not stopped")
        self.created = strict_output((args.fixture_dir/"cli-001.stdout").read_bytes())
        self.network = self.created["id"]
        self.key = (args.retained_from/"cold" if args.retained_from else self.b.root)/"independent-cold-original"
        if args.retained_from:
            require(self.key.is_file() and not (self.b.host.state/"admin.sock").exists(), "retained cold original/state is missing or not stopped")
            self.request = strict_output((args.retained_from/"native-001.stdout").read_bytes())
            self.code = self.request["display_code"]
        else:
            result = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)], capture_output=True, timeout=10)
            require(result.returncode == 0, "cold original key generation failed")
        self.person = ssh_public(self.key)
        for suite in (self.a, self.b):
            suite.host.environment["PATH"] = "/usr/bin:/bin"
            with socket.socket() as s: s.bind(("127.0.0.1", 0)); tcp = "127.0.0.1:"+str(s.getsockname()[1])
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s: s.bind(("127.0.0.1", 0)); udp = "127.0.0.1:"+str(s.getsockname()[1])
            if args.retained_from:
                record = self.pending(self.b)
                public = self.request["host_public_key"] if suite is self.b else self.created["host_public_key"]
                endpoints = [v for v in record["carrier_endpoints"] if v["kind"] == "participant" and v["public_key"] == public]
                require(len(endpoints) == 1, "retained exact participant endpoint disappeared")
                tcp = endpoints[0]["address"]
            suite.host.run_arguments = ["--bootstrap-listen", tcp, "--peer-listen", udp, "--advertise", udp]

    def cli(self, suite, *arguments, data=b""):
        self.calls += 1; prefix = self.args.work_dir/("native-%03d" % self.calls)
        result = subprocess.run([str(self.args.host), "--state", str(suite.host.state), *arguments],
            input=data, capture_output=True, env=suite.host.environment, timeout=30)
        for suffix, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
            path = prefix.with_suffix("."+suffix); path.write_bytes(raw); path.chmod(0o600)
        prefix.with_suffix(".meta.json").write_bytes(raw_json({"arguments":list(arguments), "exit":result.returncode,
            "stdout_sha256":sha(result.stdout), "stderr_sha256":sha(result.stderr)}))
        require(result.returncode != 0 and result.stdout.strip(), "native pending/default-no command omitted flat pending output")
        return strict_output(result.stdout), result.stderr

    def pending(self, suite):
        rows = table_rows(suite.host, "dec_pending", "record", " WHERE request_id=?", (self.request["request_id"],))
        require(len(rows) == 1, "exact defaults request disappeared/duplicated")
        return strict_output(rows[0][0].encode())

    def intents(self, suite, kind):
        return [(identifier, strict_output(encoded.encode()), secret) for identifier, encoded, secret in
            table_rows(suite.host, "dec_intents", "intent_id,record,secret", " WHERE kind=?", (kind,))
            if strict_output(encoded.encode())["operation_id"] == self.request["request_id"]]

    def run(self):
        for suite in (self.a, self.b):
            suite.host.start(); suite.identity = suite.host.api("GET", "/v1/host")
        require(self.a.identity["public_key"] == self.created["host_public_key"] and self.person != self.created["person_public_key"],
                "defaults fixture replaced actual A or is not an independent cold original")
        self.current = self.a.api("GET", "/v2/networks/"+self.network)[0]
        if not self.args.retained_from:
            invitation = self.a.api("POST", "/v2/networks/"+self.network+"/invitations",
                {"member":"Independent omitted defaults", "expected_person_public_key":self.person}, status=201)[0]["invitation"]
            private = self.b.root/"introduction.private"; private.write_text(invitation+"\n"); private.chmod(0o600)
            self.request, _ = self.cli(self.b, "network", "join", "--invite-file", str(private), "--person-key", str(self.key))
            self.code = self.request["display_code"]
        else:
            require(self.request["host_public_key"] == self.b.identity["public_key"] and
                    self.request["person_public_key"] == self.person and not self.pending(self.b)["selection_approved"] and
                    not self.pending(self.b)["commit_approved"] and
                    datetime.now(timezone.utc) < datetime.fromisoformat(self.request["expires_at"].replace("Z", "+00:00")),
                    "retained defaults attempt changed identities/consent or actually expired")
            self.trace.append({"same_actual_request_and_original_host_keys":True, "first_stderr_format_overconstraint_retained":True,
                "no_invitation_join_or_key_generation_replayed":True})
        payload = strict_output(unb64(strict_output(unb64(self.pending(self.b)["request_packet_base64"]))["payload_base64"]))
        created_at = datetime.fromisoformat(payload["created_at"].replace("Z", "+00:00"))
        deadline = (created_at+timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        require(self.b.api("GET", "/v2/networks")[0] == [] and payload["mode"] == "new", "requester is not cold/unadmitted")
        owner = ["link", "approve", "--network", self.network, "--person", self.person, "--person-key", str(self.key),
            "--expect-host-key", self.request["host_public_key"], "--expect-device-key", self.request["device_public_key"], "--code-stdin"]

        def owner_deadline():
            for attempt in range(2):
                view, review = self.cli(self.b, *owner, data=(self.code+"\n").encode())
                require(not view["selection_approved"] and not view["commit_approved"], "owner preview supplied requester consent")
                owners = self.intents(self.b, "owner")
                require(len(owners) == 1 and owners[0][1]["not_after"] == deadline and
                        strict_output(unb64(owners[0][1]["review_base64"]))["not_after"] == deadline,
                        "exact typed omitted owner deadline is not signed request plus7days")
                require(self.pending(self.b)["owner_packet_base64"] == "-" and all(not record["approved"] and
                    record["approved_at"] == "-" and record["signatures"] == [] for _, record, _ in self.intents(self.b, "owner")),
                    "default-no owner preview supplied approval/signature")
                if attempt == 0: time.sleep(1.1)
            self.cli(self.b, *owner, "--approve", data=(self.code+"\n").encode())
            record = self.pending(self.b); packet = strict_output(unb64(record["owner_packet_base64"]))
            body = strict_output(unb64(packet["payload_base64"]))
            require(body["not_after"] == deadline and body["scopes"] == 7 and body["root_state_id"] == body["person_lease_id"] == "-" and
                    body["issuer_lease_ids"] == [] and packet["signer_public_key"] == packet["person_public_key"] == self.person and
                    packet["authority_signature_format"] == "sshsig", "explicit approval replaced the previewed default terms/person")
            Introduction.verify_original(self, packet["authority_signature"], packet_message(packet))
            require(not record["selection_approved"] and not record["commit_approved"] and self.b.api("GET", "/v2/networks")[0] == [],
                    "owner approval supplied requester consent or adoption")
            self.trace.append({"signed_request_created_at":payload["created_at"], "default_not_after":deadline,
                "cold_possession_has_no_current_finite_parents":True, "preview_then_explicit_approval_same_terms":True})
        self.a.case(CASES[0], owner_deadline)

        def root_default():
            record = self.pending(self.b)
            selection = {"owner_offer_id":record["owner_offer_id"], "network_id":self.network, "context_id":self.current["context_id"],
                "person_public_key":self.person, "host_public_key":self.request["host_public_key"],
                "device_public_key":self.request["device_public_key"], "approve":True}
            self.b.api("POST", "/v2/link/requests/"+self.request["request_id"]+"/selection", selection)
            for _ in range(8):
                view = self.b.api("POST", "/v2/link/requests/"+self.request["request_id"]+"/resume", {})[0]
                if "owner_selected" in view["completed"]: break
            record = self.pending(self.b); before = authority_rows(self.a)
            self.cli(self.a, "link", "admit", "--network", self.network, "--person", self.person,
                "--expect-host-key", self.request["host_public_key"], "--expect-device-key", self.request["device_public_key"],
                "--owner-offer", record["owner_offer_id"], "--selection", record["selection_id"], "--code-stdin", data=(self.code+"\n").encode())
            intents = self.intents(self.a, "administrator")
            require(len(intents) == 1, "native default admission lacks one observable exact typed unapproved intent")
            _, intent, secret = intents[0]; review = strict_output(unb64(intent["review_base64"]))
            require(not intent["approved"] and intent["approved_at"] == "-" and not intent["completed"] and intent["signatures"] == [] and
                    secret is None and intent["provider"] == {"kind":"root", "signer_public_key":self.current["root_public_key"],
                    "signature_format":"ed25519", "lease_id":"-"} and review["provider"]["kind"] == "network_root" and
                    review["provider"]["scopes"] == 8 and review["person_public_key"] == self.person and
                    review["host_public_key"] == self.request["host_public_key"] and review["device_public_key"] == self.request["device_public_key"],
                    "omitted administrator signer is not the exact unapproved root review")
            require(self.pending(self.a)["administrator_packet_base64"] == "-" and authority_rows(self.a) == before and
                    not self.pending(self.b)["commit_approved"] and self.b.api("GET", "/v2/networks")[0] == [],
                    "default-no administrator preview supplied signature/authority/provider/adoption")
            self.trace.append({"native_signer_flag_omitted":True, "exact_typed_provider_kind":"root", "default_no_unsigned":True,
                "owned_root_private_key_not_read":True, "no_final_adoption_attempted":True})
        self.a.case(CASES[1], root_default)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("host", "fixture-dir", "work-dir", "results"): parser.add_argument("--"+name, type=Path, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--retained-from", type=Path, help="Same actual cold requester/original/window after the noninteractive stderr expectation overconstraint; no new request or key")
    args = parser.parse_args()
    if args.retained_from: args.retained_from = args.retained_from.resolve()
    for name in ("host", "fixture_dir", "work_dir", "results"): setattr(args, name, getattr(args, name).resolve())
    args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name in ("owner", "cold"): (args.work_dir/name).mkdir(mode=0o700)
    keys = FixtureKeys(); suite = None; failure = detail = None; began = time.monotonic()
    try:
        suite = Defaults(args, keys); suite.run()
    except BaseException as error:
        failure = type(error).__name__; detail = str(error) if isinstance(error, CheckFailure) else "fixture/transport failure"
    finally:
        if suite is not None:
            for value in (suite.b, suite.a): value.host.stop()
        keys.close()
    result = {"contract_pin":PIN, "source":args.source, "implementation_source_read":False,
        "artifact":{"path":str(args.host), "sha256":sha(args.host.read_bytes())}, "suite_sha256":sha(Path(__file__).read_bytes()),
        "spec_sha256":sha(SPEC.read_bytes()), "rows":[] if suite is None else suite.a.rows, "trace":[] if suite is None else suite.trace,
        "retained_from":None if args.retained_from is None else str(args.retained_from),
        "failure":failure, "detail":detail, "seconds":round(time.monotonic()-began, 3), "scope":"omitted native defaults only; no old A function/adoption/final-head gate",
        "passed":failure is None and suite is not None and len(suite.a.rows) == 2 and all(v["passed"] for v in suite.a.rows)}
    args.results.parent.mkdir(parents=True, exist_ok=True); args.results.write_text(json.dumps(result, indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__": raise SystemExit(main())
