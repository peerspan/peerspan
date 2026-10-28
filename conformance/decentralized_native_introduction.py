#!/usr/bin/env python3
"""Independent native contact introduction and TWO PEOPLE / TWO HOSTS gate.

Bind the frozen introduction cases to public native help only. A owns Alice's
original key and the current root; cold B independently owns Bob's original key.
No daemon private key is read/copied. Foreground hosts do not establish installed
up/service, adapter, relay, NAT or live-task readiness. --final-head marks the
separate required acceptance run at ONE offered coherent source, never a sum of
earlier passing functions. Stop on the first failure and retain every fixture.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import time
import traceback

from decentralized_complete_link import packet_message, table_rows
from decentralized_fixtures import FixtureKeys, b64, lines, raw_json, sha, ssh_string, unb64
from decentralized_native_link import NativeLink
from decentralized_owner_preview import authority_rows
from decentralized_requester import VIEW, private_token
from decentralized_storage import CheckFailure, all_database_snapshots, require
from decentralized_vectors import strict_output


PIN = "b36bc2ec8b947419a63388f7ab3a8cfa0aca32d8"
SPEC = Path(__file__).with_name("decentralized_native_introduction_cases.json")
CASES = [v["name"] for v in json.loads(SPEC.read_bytes())["cases"]]


def public_sqlite_failure(error):
    """Only non-data SQLite text and source locations; never frame locals/rows."""
    if not isinstance(error, sqlite3.DatabaseError):
        return None
    message = str(error)
    known = {"database disk image is malformed", "file is not a database", "disk I/O error",
        "database is locked", "database table is locked", "database schema is locked",
        "unable to open database file", "database or disk is full", "attempt to write a readonly database",
        "interrupted", "query aborted", "out of memory", "not authorized"}
    # Schema identifiers may be public diagnostics, but arbitrary SQL/row/value
    # text is never uploaded. Preserve its digest for an owned private audit.
    safe = message in known or re.fullmatch(r"(?:no such table|no such column|database table is locked|database schema is locked): [A-Za-z_][A-Za-z_0-9.]*", message)
    result = {"sqlite_errorname":getattr(error, "sqlite_errorname", None),
        "sqlite_errorcode":getattr(error, "sqlite_errorcode", None), "sqlite_library_version":sqlite3.sqlite_version,
        "message":message if safe else "nonstandard SQLite diagnostic retained only in protected traceback",
        "message_sha256":sha(message.encode()), "source_stack":[]}
    current = error.__traceback__
    while current is not None:
        frame = current.tb_frame
        filename = Path(frame.f_code.co_filename).name
        result["source_stack"].append({"file":filename, "line":current.tb_lineno, "function":frame.f_code.co_name})
        if filename == "decentralized_complete_link.py" and frame.f_code.co_name == "table_rows":
            # Deliberately select only these non-data facts. Never serialize
            # locals, SQL arguments, current row, records, secrets or keys.
            host, path, table = (frame.f_locals.get(key) for key in ("host", "path", "table"))
            if host is not None and path is not None and isinstance(table, str):
                process = getattr(host, "process", None)
                try:
                    relative = str(path.relative_to(host.state))
                except (ValueError, AttributeError):
                    relative = "outside-actual-state"
                result["reader_boundary"] = {"table":table, "database_relative_path":relative,
                    "tracked_daemon_live":process is not None and process.poll() is None}
        current = current.tb_next
    return result


def ssh_public(path):
    blob = unb64(path.with_suffix(".pub").read_text().split()[1])
    size = int.from_bytes(blob[:4], "big")
    require(blob[4:4+size] == b"ssh-ed25519", "fixture original key is not Ed25519")
    tail = blob[4+size:]
    require(int.from_bytes(tail[:4], "big") == 32 and len(tail) == 36, "fixture public key framing differs")
    return b64(tail[4:])


class Introduction(NativeLink):
    def __init__(self, args, keys):
        # Reuse transport/process/TTY plumbing only, not any earlier case body.
        super().__init__(args, keys)
        self.alice, self.alice_key = self.person, self.key
        original = args.actual_fixture_dir if (args.after_cold_selection_from or args.fresh_final_from) else args.fresh_after_intro_from
        self.bob_key = (original/"requester" if original else self.b.root)/"bob-original-ed25519"
        if original:
            require(self.bob_key.is_file(), "remaining-only continuation lost original Bob key")
        else:
            result = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.bob_key)],
                                    capture_output=True, timeout=10)
            require(result.returncode == 0, "independent Bob original key generation failed")
        self.person = ssh_public(self.bob_key)
        require(self.person != self.alice, "fixture is not two independent original people")
        self.member = "Independent Bob <new>&owner"
        self.deadline = (datetime.now(timezone.utc)+timedelta(hours=1)).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

    def pending(self):
        rows = table_rows(self.b.host, "dec_pending", "request_id,record,secret", " WHERE request_id=?", (self.request["request_id"],))
        require(len(rows) == 1, "exact native requester disappeared/duplicated")
        return rows[0][0], strict_output(rows[0][1].encode()), rows[0][2]

    def selected_postconditions(self):
        """Observe live progress publicly, then read private state while stopped.

        A guide may still be polling/writing. Do not treat a filesystem-wide
        SQLite discovery during that work as a coherent private snapshot.
        Stopping this CLI and daemon supplies no consent or signature; the
        restarted guide resumes the already selected exact packet.
        """
        current = self.b.api("GET", "/v2/link/requests/"+self.request["request_id"])[0]
        self.view(current)
        require(current["selection_approved"] and not current["commit_approved"] and
                "owner_selected" in current["completed"], "exact public selection has not completed")
        self.stop_guide(); self.b.host.stop()
        record = self.pending()[1]
        require(record["selection_approved"] and not record["commit_approved"] and
                record["host_public_key"] == self.request["host_public_key"] and
                record["device_public_key"] == self.request["device_public_key"] and
                record["selection_packet_base64"] != "-", "stopped selected state changed identity or consent")
        self.owner_packet()
        require(not table_rows(self.b.host, "dec_contexts", "network_id") and
                not table_rows(self.b.host, "dec_signers", "network_id") and
                not table_rows(self.b.host, "dec_operations", "request_id"),
                "stopped selected state supplied context, provider or outcome")
        self.trace.append({"selected_private_postconditions_from_stopped_state":True,
            "exact_owner_packet_sha256":sha(unb64(record["owner_packet_base64"])),
            "exact_selection_packet_sha256":sha(unb64(record["selection_packet_base64"])),
            "no_selection_approval_or_signature_replay":True})
        self.b.host.start()
        require(self.b.api("GET", "/v2/networks")[0] == [], "selection restart supplied an adopted network")
        self.start_guide()

    def raw_cli(self, instance, *arguments):
        """Refusal can have empty stdout; do not invent a JSON error promise."""
        self.calls += 1
        prefix = self.args.work_dir/("refusal-%03d" % self.calls)
        result = subprocess.run([str(self.args.host), "--state", str(instance.host.state), *arguments],
                                input=b"", capture_output=True, env=instance.host.environment, timeout=30)
        for suffix, data in (("stdout", result.stdout), ("stderr", result.stderr)):
            path = prefix.with_suffix("."+suffix); path.write_bytes(data); path.chmod(0o600)
        prefix.with_suffix(".meta.json").write_bytes(raw_json({"arguments":list(arguments), "exit":result.returncode,
            "stdout_sha256":sha(result.stdout), "stderr_sha256":sha(result.stderr)}))
        return result

    def protected(self):
        return {"authority":authority_rows(self.b),
            "pending":table_rows(self.b.host, "dec_pending", "request_id,record,secret"),
            "selection":table_rows(self.b.host, "dec_signers", "network_id,context_id,provider_kind,person_key,device_key,lease_id"),
            "bob_original_sha256":sha(self.bob_key.read_bytes())}

    def save_private(self, name, token):
        path = self.b.root/name
        path.write_text(token+"\n"); path.chmod(0o600)
        self.sensitive.append(token.encode())
        return path

    def decode_intro(self, token):
        require(token.startswith("psi2-") and len(token.encode()) <= 32768, "native invite omitted bounded psi2 introduction")
        suffix = token[5:]
        raw = base64.urlsafe_b64decode(suffix+"="*((-len(suffix)) % 4))
        require(private_token("psi2-", raw) == token, "native psi2 token is not canonical unpadded Base64URL")
        envelope = strict_output(raw)
        require(set(envelope) == {"format", "context_id", "inviter_host_public_key", "payload_base64", "signature"} and
                envelope["format"] == 1 and envelope["inviter_host_public_key"] == self.a.identity["public_key"],
                "native invitation envelope/actual inviter differs")
        payload_bytes = unb64(envelope["payload_base64"]); payload = strict_output(payload_bytes)
        require(set(payload) == {"descriptor", "expected_person_public_key", "member", "issued_at", "expires_at", "contacts", "helpers"},
                "native invitation payload fields differ")
        descriptor = payload["descriptor"]
        context = "ctx_"+sha(lines("peerspan-decentralized-context-v1", descriptor["protocol"],
            descriptor["network_id"], descriptor["name"], descriptor["genesis_root_public_key"]))
        require(descriptor["network_id"] == self.network["id"] and descriptor["name"] == self.network["name"] and
                context == envelope["context_id"] == self.network["context_id"] and payload["member"] == self.member,
                "native introduction changed network/context/member pins")
        parsed = lambda v: datetime.fromisoformat(v.replace("Z", "+00:00"))
        # Spec 8.1 and DEC-Q2: an invite lasts 60 s to 24 h (1 h by default from the CLI), not 300 s.
        require(60 <= (parsed(payload["expires_at"])-parsed(payload["issued_at"])).total_seconds() <= 86400 and
                parsed(payload["issued_at"]) <= datetime.now(timezone.utc)+timedelta(seconds=30) and
                datetime.now(timezone.utc) < parsed(payload["expires_at"]), "native introduction time interval differs")
        message = lines("peerspan-decentralized-contact-invitation-v1", context, envelope["inviter_host_public_key"], sha(payload_bytes))
        self.a.verify_raw(envelope["inviter_host_public_key"], message, envelope["signature"])
        require(len(payload["contacts"]) <= 4 and len(payload["helpers"]) <= 4, "native introduction exceeds contact/helper bounds")
        for contact in payload["contacts"]:
            require(set(contact) == set("format context_id host_public_key sequence issued_at expires_at payload_base64 signature".split()) and
                    contact["format"] == 1 and contact["context_id"] == context and
                    contact["host_public_key"] == envelope["inviter_host_public_key"], "intro contact changed context/inviter")
            cm = lines("peerspan-decentralized-contact-v1", context, contact["host_public_key"], contact["sequence"],
                contact["issued_at"], contact["expires_at"], sha(unb64(contact["payload_base64"])))
            self.a.verify_raw(contact["host_public_key"], cm, contact["signature"])
        return raw, envelope, payload, "di_"+sha(message)

    def verify_original(self, signature, message):
        """Verify the exact public SSHSIG container without reading a private key."""
        data = unb64(signature); require(data[:6] == b"SSHSIG" and data[6:10] == b"\x00\x00\x00\x01", "original signature header differs")
        pos = 10
        def field():
            nonlocal pos
            require(pos+4 <= len(data), "truncated public SSHSIG")
            length = int.from_bytes(data[pos:pos+4], "big"); pos += 4
            value = data[pos:pos+length]; pos += length
            require(len(value) == length, "truncated SSHSIG field")
            return value
        public, namespace, reserved, algorithm, sig = [field() for _ in range(5)]
        require(pos == len(data) and public == ssh_string(b"ssh-ed25519")+ssh_string(unb64(self.person)) and
                namespace == b"peerspan-person-v1" and reserved == b"" and algorithm == b"sha512" and
                sig[:19] == ssh_string(b"ssh-ed25519")+b"\x00\x00\x00@" and len(sig) == 83,
                "original SSHSIG key/namespace/hash/Ed25519 role differs")
        signed = b"SSHSIG"+ssh_string(namespace)+ssh_string(reserved)+ssh_string(algorithm)+ssh_string(hashlib.sha512(message).digest())
        self.b.verify_raw(self.person, signed, b64(sig[19:]))

    def owner_packet(self):
        record = self.pending()[1]
        require(record["owner_packet_base64"] != "-", "native cold owner offer has not been durably signed")
        packet = strict_output(unb64(record["owner_packet_base64"])); payload = strict_output(unb64(packet["payload_base64"]))
        require(packet["role"] == "owner" and packet["writer_host_public_key"] == self.b.identity["public_key"] and
                packet["signer_public_key"] == packet["person_public_key"] == self.person and packet["issuer_id"] == "-" and
                packet["authority_signature_format"] == "sshsig" and payload["root_state_id"] == payload["person_lease_id"] == "-" and
                payload["issuer_lease_ids"] == [] and payload["scopes"] == 7 and payload["member"] == self.member,
                "cold offer substituted inviter, claimed current authority or changed default target7")
        message = packet_message(packet)
        self.verify_original(packet["authority_signature"], message)
        self.b.verify_raw(packet["writer_host_public_key"], message, packet["host_signature"])
        return packet, payload

    def run(self):
        for instance in self.hosts.values():
            instance.host.start(); instance.identity = instance.host.api("GET", "/v1/host")
        if self.args.after_cold_selection_from:
            original = self.args.actual_fixture_dir; captured = self.args.after_cold_selection_from
            self.network = self.a.api("GET", "/v2/networks/"+strict_output((original/"cli-001.stdout").read_bytes())["id"])[0]
            self.request = strict_output(self.args.request_capture.read_bytes())
            self.code = self.request["display_code"]; self.sensitive.append(self.code.encode())
            record = self.pending()[1]
            require(record["selection_approved"] and record["selection_packet_base64"] != "-" and not record["commit_approved"] and
                self.request["person_public_key"] == self.person and self.request["host_public_key"] == self.b.identity["public_key"] and
                self.network["host_public_key"] == self.a.identity["public_key"], "same-selected-state continuation lost actual person/hosts or durable consent")
            self.trace.append({"passed_functions_skipped":4 if self.args.only_final else 3,"existing_selection_signature_not_repeated":True,
                "exact_retained_owner_packet_sha256":sha(unb64(record["owner_packet_base64"])),
                "exact_retained_selection_packet_sha256":sha(unb64(record["selection_packet_base64"]))})
        elif self.args.fresh_final_from:
            original = self.args.actual_fixture_dir; captured = self.args.fresh_final_from
            self.network = self.a.api("GET", "/v2/networks/"+strict_output((original/"cli-001.stdout").read_bytes())["id"])[0]
            previous = strict_output(self.args.request_capture.read_bytes()); self.request = previous
            old = self.pending()[1]
            require(old["selection_approved"] and not old["commit_approved"] and
                datetime.fromisoformat(previous["expires_at"].replace("Z", "+00:00")) < datetime.now(timezone.utc),
                "final-only fresh boundary requires the actual expired selected precommit request")
            fixed = {key:old[key] for key in ("request_packet_base64", "owner_packet_base64", "selection_packet_base64", "administrator_packet_base64",
                "host_public_key", "device_public_key", "owner_offer_id", "selection_id", "administrator_offer_id")}
            old_keys = table_rows(self.b.host, "link_device_keys", "public_key,created_at")
            cancelled = self.b.api("POST", "/v2/link/requests/"+previous["request_id"]+"/cancel", {})[0]
            require(cancelled["state"] == "cancelled" and self.pending()[2] is None and
                all(self.pending()[1][key] == value for key, value in fixed.items()) and
                table_rows(self.b.host, "link_device_keys", "public_key,created_at") == old_keys,
                "precommit cancellation changed old reviewed signed evidence or owned keys")
            invitation = self.a.api("POST", "/v2/networks/"+self.network["id"]+"/invitations",
                {"member":self.member, "expected_person_public_key":"-"}, status=201)[0]["invitation"]
            self.intro_raw, self.intro, self.intro_payload, _ = self.decode_intro(invitation)
            private = self.save_private("final-only-introduction.private", invitation)
            self.request, _, _ = self.cli(self.b, "network", "join", "--invite-file", str(private), "--person-key", str(self.bob_key), success=False)
            self.view(self.request, code=True); self.code = self.request["display_code"]; self.sensitive.append(self.code.encode())
            require(self.request["person_public_key"] == self.person and self.request["host_public_key"] == previous["host_public_key"] and
                self.request["request_id"] != previous["request_id"] and not self.request["selection_approved"] and not self.request["commit_approved"],
                "fresh final-only prerequisite revived old request or replaced original/host")
            owner_args = ["link", "approve", "--network", self.network["id"], "--person", self.person,
                "--expect-host-key", self.request["host_public_key"], "--expect-device-key", self.request["device_public_key"],
                "--person-key", str(self.bob_key), "--not-after", self.deadline, "--code-stdin", "--approve"]
            self.cli(self.b, *owner_args, input=(self.code+"\n").encode(), success=False)
            self.owner_packet()
            selection = {"owner_offer_id":self.pending()[1]["owner_offer_id"], "network_id":self.network["id"], "context_id":self.network["context_id"],
                "person_public_key":self.person, "host_public_key":self.request["host_public_key"], "device_public_key":self.request["device_public_key"], "approve":False}
            self.b.api("POST", "/v2/link/requests/"+self.request["request_id"]+"/selection", selection)
            self.b.api("POST", "/v2/link/requests/"+self.request["request_id"]+"/selection", dict(selection, approve=True))
            for _ in range(8):
                view = self.b.api("POST", "/v2/link/requests/"+self.request["request_id"]+"/resume", {})[0]
                if view["selection_approved"] and "owner_selected" in view["completed"]: break
            require(view["selection_approved"] and "owner_selected" in view["completed"] and not view["commit_approved"],
                "minimum explicit selection prerequisite did not complete without final consent")
            self.start_guide()
            self.trace.append({"four_passed_test_functions_skipped":True, "old_expired_selected_request_id":previous["request_id"],
                "old_exact_public_packet_hashes":{key:sha(unb64(value)) for key, value in fixed.items() if key.endswith("_base64") and value != "-"},
                "same_actual_A_network_people_host_keys":True,
                "uncounted_new_attempt_prerequisites":["explicit selected-precommit cancel", "fresh private intro/join", "local original possession offer", "explicit exact requester selection"],
                "no_old_window_or_key_reset":True})
        elif self.args.fresh_after_intro_from:
            # Existing A network and both originals/host stores stay in place.
            # Only an explicitly cancelled old unsigned attempt is replaced.
            old = self.args.fresh_after_intro_from
            previous_network = strict_output((old/"cli-001.stdout").read_bytes())
            self.network = self.a.api("GET", "/v2/networks/"+previous_network["id"])[0]
            previous = strict_output((old/"cli-005.stdout").read_bytes())
            self.request = previous
            require(previous["person_public_key"] == self.person and previous["host_public_key"] == self.b.identity["public_key"] and
                previous_network["host_public_key"] == self.a.identity["public_key"] and
                datetime.fromisoformat(previous["expires_at"].replace("Z", "+00:00")) < datetime.now(timezone.utc) and
                not self.pending()[1]["selection_approved"] and not self.pending()[1]["commit_approved"],
                "remaining-only fixture changed original Bob/host or crossed consent")
            old_record = self.pending()[1]
            # The signed packet contains the exact immutable request window;
            # created_at/expires_at are not fields of dec_pending.record.
            old_public = {key:old_record[key] for key in ("request_packet_base64", "host_public_key", "device_public_key")}
            old_keys = table_rows(self.b.host, "link_device_keys", "public_key,created_at")
            cancelled = self.b.api("POST", "/v2/link/requests/"+previous["request_id"]+"/cancel", {})[0]
            require(cancelled["state"] == "cancelled" and self.pending()[2] is None and
                all(self.pending()[1][key] == value for key, value in old_public.items()) and
                table_rows(self.b.host, "link_device_keys", "public_key,created_at") == old_keys,
                "explicit precommit cancellation changed old signed window/identity or removed owned key")
            intro = self.a.api("POST", "/v2/networks/"+self.network["id"]+"/invitations",
                {"member":self.member, "expected_person_public_key":"-"}, status=201)[0]
            self.invitation = intro["invitation"]
            self.intro_raw, self.intro, self.intro_payload, _ = self.decode_intro(self.invitation)
            self.private_intro = self.save_private("new-reviewed-introduction.private", self.invitation)
            self.trace.append({"passed_native_invite_and_negative_functions_skipped":True,
                "old_request_id":previous["request_id"], "old_signed_request_sha256":sha(unb64(old_public["request_packet_base64"])),
                "explicit_old_precommit_cancel_only":True, "same_existing_A_network_Bob_original_and_actual_host_keys":True,
                "uncounted_minimum_prerequisite":"one fresh private intro; new explicit pending attempt, never old TTL/key reset"})
        else:
            # Necessary source setup for DISTINCT introduction controls, uncounted.
            self.cli(self.a, "network", "create", "Independent two-person acceptance", "--as", "Alice administrator",
                     "--person-key-file", str(self.alice_key), success=True)
            self.network = self.a.api("GET", "/v2/networks")[0][0]
        require(self.network["person_public_key"] == self.alice, "uncounted inviter creation lacks its own Alice identity")
        self.trace.append({"uncounted_setup":"existing A creator retained" if self.args.retained_dir else "actual A local creator only; no earlier native six function called",
                           "two_different_original_public_keys":True, "coordinator_or_helper_started":False})

        def invite():
            before = authority_rows(self.a); guard = table_rows(self.a.host, "dec_clock", "network_id,record")
            value, _, _ = self.cli(self.a, "network", "invite", "--network", self.network["id"], "--member", self.member, success=True)
            self.invitation = value["invitation"]; self.sensitive.append(self.invitation.encode())
            self.intro_raw, self.intro, self.intro_payload, identifier = self.decode_intro(self.invitation)
            require(value["invitation_id"] == identifier and self.intro_payload["expected_person_public_key"] == "-",
                    "unselected-person native invitation changed its exact ID/person placeholder")
            after = authority_rows(self.a); after_guard = table_rows(self.a.host, "dec_clock", "network_id,record")
            observations = {"before_authority_rows_sha256":before,"after_authority_rows_sha256":after,
                "before_clock_rows":guard,"after_clock_rows":after_guard,
                "authority_rows_unchanged":after == before,"clock_rows_unchanged":after_guard == guard}
            capture = self.args.work_dir/"invite-authority-observations.public.json"
            capture.write_bytes(raw_json(observations)); capture.chmod(0o600)
            self.trace.append({"invite_authority_observations":str(capture),"sha256":sha(capture.read_bytes()),**observations})
            require(after == before and after_guard == guard,
                    "contact invitation changed authority/provider or advanced authority guard")
            self.private_intro = self.save_private("reviewed-introduction.private", self.invitation)
        if not (self.args.fresh_after_intro_from or self.args.after_cold_selection_from or self.args.fresh_final_from): self.a.case(CASES[0], invite)

        def bad_inputs():
            before = self.protected(); generic_before = all_database_snapshots(self.b.host.state)
            changed = dict(self.intro); raw = bytearray(unb64(changed["signature"])); raw[0] ^= 1; changed["signature"] = b64(raw)
            bad = self.save_private("bad-signature.private", private_token("psi2-", raw_json(changed)))
            result = self.raw_cli(self.b, "network", "join", "--invite-file", str(bad), "--person-key", str(self.bob_key))
            require(result.returncode != 0 and self.protected() == before, "bad intro signature created/replaced request, identity or authority")
            pinned = self.a.api("POST", "/v2/networks/"+self.network["id"]+"/invitations",
                {"member":self.member, "expected_person_public_key":self.alice}, status=201)[0]
            path = self.save_private("wrong-person.private", pinned["invitation"])
            result = self.raw_cli(self.b, "network", "join", "--invite-file", str(path), "--person-key", str(self.bob_key))
            require(result.returncode != 0 and self.protected() == before, "wrong person pin generated/substituted identity or enrollment")
            self.trace.append({"negative_input_database_before":generic_before, "negative_input_database_after":all_database_snapshots(self.b.host.state),
                               "protected_identity_pending_authority_unchanged":True})
        if not (self.args.fresh_after_intro_from or self.args.after_cold_selection_from or self.args.fresh_final_from): self.a.case(CASES[1], bad_inputs)

        def join():
            self.request, review, _ = self.cli(self.b, "network", "join", "--invite-file", str(self.private_intro),
                                             "--person-key", str(self.bob_key), success=False)
            def shown_key(public):
                digest = hashlib.sha256(unb64(public)).digest()
                return any(v in review for v in (public.encode(), digest.hex().encode(),
                    ("SHA256:"+b64(digest).rstrip("=")).encode()))
            require(self.network["name"].encode() in review and self.member.encode() in review and
                    self.network["context_id"].encode() in review and shown_key(self.a.identity["public_key"]) and
                    shown_key(self.intro_payload["descriptor"]["genesis_root_public_key"]) and shown_key(self.person),
                    "native private join did not present exact intro/selected-original review terms")
            self.view(self.request, code=True); self.code = self.request["display_code"]; self.sensitive.append(self.code.encode())
            require(self.request["network_id"] == self.network["id"] and self.request["context_id"] == self.network["context_id"] and
                    self.request["person_public_key"] == self.person and self.request["host_public_key"] == self.b.identity["public_key"] and
                    not self.request["selection_approved"] and not self.request["commit_approved"], "private join supplied consent or changed reviewed original/context")
            record = self.pending()[1]
            require(record["contact_invitation_base64"] == b64(self.intro_raw), "native join did not retain exact introduction for later selection")
            if record["owner_packet_base64"] != "-":
                # Join may already have guided the local original's possession
                # offer. Retrying it must never review different fixed terms.
                _, payload = self.owner_packet(); self.deadline = payload["not_after"]
            before = self.consent_snapshot(); self.b.host.stop(); self.b.host.start()
            status, _, _ = self.cli(self.b, "link", "status", self.request["request_id"], success=False)
            self.view(status); require(self.consent_snapshot() == before and self.pending()[1]["contact_invitation_base64"] == b64(self.intro_raw),
                                      "restart/status changed pending key, consent or original invitation")
            self.no_adoption()
        if not (self.args.after_cold_selection_from or self.args.fresh_final_from): self.a.case(CASES[2], join)

        def possession():
            if self.args.after_cold_selection_from:
                self.owner_packet()
                declined = strict_output(self.args.decline_capture.read_bytes())
                require(not declined["selection_approved"] and not declined["commit_approved"] and
                    declined["request_id"] == self.request["request_id"], "original blank-decline observation changed")
                self.selected_postconditions()
                return
            args = ["link", "approve", "--network", self.network["id"], "--person", self.person,
                "--expect-host-key", self.request["host_public_key"], "--expect-device-key", self.request["device_public_key"],
                "--person-key", str(self.bob_key), "--not-after", self.deadline, "--code-stdin"]
            # Do not pass --scopes: this is the independent new-original default7 check.
            value, _, _ = self.cli(self.b, *args, input=(self.code+"\n").encode(), success=False); self.view(value)
            value, _, _ = self.cli(self.b, *args, "--approve", input=(self.code+"\n").encode(), success=False); self.view(value)
            _, payload = self.owner_packet()
            preview = self.b.api("POST", "/v2/link/approvals", {"code":self.code, "network_id":self.network["id"],
                "person_public_key":self.person, "provider_id":self.person, "signature_format":"sshsig", "scopes":7,
                "not_after":payload["not_after"], "expected_host_public_key":self.request["host_public_key"],
                "expected_device_public_key":self.request["device_public_key"], "approve":False})[0]
            provider = preview["review"]["provider"]
            require(provider["kind"] == "original_person" and provider["scopes"] == 0 and provider["root_state_id"] ==
                    provider["lease_id"] == provider["device_public_key"] == "-", "possession preview claims normal current authority")
            value, prompt = self.resume()
            require(b"Select this exact owner offer?" in prompt and not value["selection_approved"] and not value["commit_approved"],
                    "cold-original selection did not default to no")
            fixed = self.consent_snapshot(); self.b.host.stop(); self.b.host.start()
            self.start_guide(); self.guide_prompt(b"Select this exact owner offer?"); self.guide_send(b"yes\n")
            until = time.monotonic()+10
            while time.monotonic() < until:
                current = self.b.host.api("GET", "/v2/link/requests/"+self.request["request_id"])
                if current["selection_approved"] and "owner_selected" in current["completed"]: break
                time.sleep(.02)
            require(current["selection_approved"] and not current["commit_approved"] and
                    current["device_public_key"] == fixed["device"], "explicit cold selection changed key or supplied final consent")
            self.selected_postconditions()
        if self.args.only_final:
            self.selected_postconditions()  # Necessary same-state setup, no case/body or consent replay.
        elif not self.args.fresh_final_from:
            self.a.case(CASES[3], possession)

        def final():
            pending = self.pending()[1]; time.sleep(2.05)
            admit = ["link", "admit", "--network", self.network["id"], "--person", self.person, "--signer", "network_root",
                "--expect-host-key", self.request["host_public_key"],
                "--expect-device-key", self.request["device_public_key"], "--owner-offer", pending["owner_offer_id"],
                "--selection", pending["selection_id"], "--code-stdin", "--approve"]
            self.cli(self.a, *admit, input=(self.code+"\n").encode(), success=False); time.sleep(2.05)
            began_resume = time.monotonic()
            try:
                observed = self.b.api("POST", "/v2/link/requests/"+self.request["request_id"]+"/resume", {}, timeout=40)[0]
            finally:
                self.trace.append({"post_admin_requester_resume_reader_seconds":40,
                    "response_elapsed_seconds":round(time.monotonic()-began_resume, 3),
                    "fixture_reader_only_no_protocol_deadline_change":True})
            self.view(observed, code="display_code" in observed)
            pending = self.pending()[1]
            require(pending["administrator_offer_id"].startswith("dpk_") and not pending["commit_approved"], "actual root administrator did not supply pending exact P/H")
            final_args = ["link", "finalize", self.request["request_id"], "--network", self.network["id"], "--context", self.network["context_id"],
                "--expect-person", self.person, "--expect-host-key", self.request["host_public_key"], "--expect-device-key", self.request["device_public_key"],
                "--owner-offer", pending["owner_offer_id"], "--selection", pending["selection_id"],
                "--administrator-offer", pending["administrator_offer_id"], "--person-key", str(self.bob_key), "--approve"]
            self.cli(self.b, *final_args, success=False)
            self.guide_prompt(b"Commit this exact machine link?"); self.no_adoption()
            self.guide_send(b"\n"); declined = self.finish_guide()
            require(declined["selection_approved"] and not declined["commit_approved"], "cold finalization bypassed final default-no")
            linked, _ = self.resume(b"yes\n", success=True)
            require(linked["state"] == "linked" and linked["commit_approved"] and self.pending()[2] is None,
                    "explicit cold final consent did not apply or retire pairing secret")
            provider = self.b.api("GET", "/v2/networks/"+self.network["id"]+"/provider")[0]
            require(provider["kind"] == "device" and provider["person_public_key"] == self.person and
                    provider["device_public_key"] == self.request["device_public_key"] and provider["scopes"] == 7,
                    "cold final apply lost requested7 or selected another person/device")
            for _ in range(4):
                remote, _, _ = self.cli(self.a, "link", "resume", self.request["request_id"])
                if remote["state"] == "linked": break
                time.sleep(2.05)
            require(remote["state"] == "linked", "actual inviter failed to apply Bob's exact completed operation")
            operations = {}
            for label, instance in self.hosts.items():
                rows = table_rows(instance.host, "dec_operations",
                    "network_id,context_id,request_id,activation_id,manifest_id,record,locally_applied",
                    " WHERE request_id=?", (self.request["request_id"],))
                require(len(rows) == 1 and rows[0][:5] == (self.network["id"], self.network["context_id"], self.request["request_id"],
                    linked["activation_id"], linked["manifest_id"]) and rows[0][6] == 1,
                    "actual participant did not atomically retain the same complete operation tuple")
                record = strict_output(rows[0][5].encode())
                require(set(record) == {"format", "activation_base64", "catalog_base64", "outcome_packet_base64", "applied_at"} and
                    record["format"] == 1, "participant's immutable outcome carrier differs")
                operations[label] = unb64(record["activation_base64"])
            require(operations["owner"] == operations["requester"], "participants retained different complete activation bytes")
            current_a = self.a.api("GET", "/v2/networks/"+self.network["id"])[0]
            require(current_a["person_public_key"] == self.alice, "target Bob substituted the inviter's selected Alice identity")
            normal = subprocess.run([str(self.args.probe), "--state", str(self.b.host.state), "--address", self.addresses["owner"],
                "--alpn", "peerspan-peer/1", "--method", "GET", "--path", "/peer/v2/networks/"+self.network["id"]+"/catalog"],
                capture_output=True, env=self.b.host.environment, timeout=40)
            require(normal.returncode == 0 and strict_output(normal.stdout)["status"] == 200, "two-person actual admission lacks direct normal catalog access")
            self.trace.append({"request_id":linked["request_id"], "activation_id":linked["activation_id"], "manifest_id":linked["manifest_id"],
                "inviter_person":self.alice, "invitee_person":self.person, "two_original_people":True, "two_actual_hosts":True,
                "no_coordinator_or_helper":True, "normal_direct_catalog_observed":True,
                "actual_both_operation_tuples_and_activation_bytes_equal":True,
                "activation_body_sha256":sha(operations["requester"]),
                "raw_probe_does_not_establish_client_server_pin":True})
        self.a.case(CASES[4], final)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("host", "probe", "work-dir", "results"): parser.add_argument("--"+name, type=Path, required=True)
    parser.add_argument("--source", required=True, help="Exact offered coherent source commit, recorded with binary hash")
    parser.add_argument("--final-head", action="store_true", help="The separately authorized full final-head two-people/two-host acceptance run")
    parser.add_argument("--fresh-after-intro-from", type=Path, help="Only still-failed valid join and2 unevaluated cases after original real expiry; existing A network and both original/host keys stay in place")
    parser.add_argument("--after-cold-selection-from", type=Path, help="Only remaining possession postconditions and final case after actual completed selection; no owner approval/selection replay")
    parser.add_argument("--fresh-final-from", type=Path, help="Only still-failed final control, with explicitly reviewed minimum new-attempt prerequisites after actual selected precommit expiry")
    parser.add_argument("--actual-fixture-dir", type=Path, help="Original actual A/B stores and original-key files for same-selected-state continuation")
    parser.add_argument("--request-capture", type=Path, help="Exact protected original join LINK_VIEW capture for a same-selected continuation")
    parser.add_argument("--decline-capture", type=Path, help="Exact protected original blank-selection LINK_VIEW capture; no replay")
    parser.add_argument("--only-final", action="store_true", help="Only the still-failed final control on an already selected exact retained request; no selection-case repeat")
    args = parser.parse_args()
    require(re.fullmatch("[0-9a-f]{40}", args.source) is not None, "offered source must be an exact commit")
    for name in ("host", "probe", "work_dir", "results"): setattr(args, name, getattr(args, name).resolve())
    # Base process plumbing's historical continuations are deliberately disabled.
    if sum(bool(v) for v in (args.fresh_after_intro_from, args.after_cold_selection_from, args.fresh_final_from)) > 1: parser.error("continuation boundaries are distinct")
    if args.final_head and (args.fresh_after_intro_from or args.after_cold_selection_from or args.fresh_final_from or args.only_final): parser.error("final coherent-head acceptance requires a fresh complete five-case run")
    if args.only_final and not args.after_cold_selection_from: parser.error("same-state final-only requires the exact already-selected attempt")
    if (args.after_cold_selection_from or args.fresh_final_from) and args.actual_fixture_dir is None: parser.error("continuation requires original actual fixture")
    for name in ("retained_dir", "history_cli", "fresh_remaining_from", "fresh_after_pending_from", "fresh_after_owner_from"): setattr(args, name, None)
    if args.fresh_after_intro_from:
        args.fresh_after_intro_from = args.fresh_after_intro_from.resolve()
        args.retained_dir = args.fresh_after_intro_from
    if args.after_cold_selection_from or args.fresh_final_from:
        captured = (args.after_cold_selection_from or args.fresh_final_from).resolve()
        if args.after_cold_selection_from: args.after_cold_selection_from = captured
        else: args.fresh_final_from = captured
        args.actual_fixture_dir = args.actual_fixture_dir.resolve(); args.retained_dir = args.actual_fixture_dir
        args.request_capture = (args.request_capture or captured/"cli-001.stdout").resolve()
        args.decline_capture = (args.decline_capture or captured/"cli-005.stdout").resolve()
        selected = strict_output(args.request_capture.read_bytes())
        owner = strict_output((args.actual_fixture_dir/"cli-001.stdout").read_bytes())
        args.retained_request_id = selected["request_id"]
        args.retained_participant_keys = {"owner":owner["host_public_key"], "requester":selected["host_public_key"]}
    for name in ("after_owner", "after_selection", "after_local_finalization", "after_applied"): setattr(args, name, False)
    args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    for label in ("owner", "requester"): (args.work_dir/label).mkdir(mode=0o700)
    keys = FixtureKeys(); suite = None; failure = detail = sqlite_failure = None; started = time.monotonic()
    try:
        suite = Introduction(args, keys); suite.run()
    except BaseException as error:
        failure = type(error).__name__; detail = str(error) if isinstance(error, CheckFailure) else "fixture/transport failure; see protected captures"
        sqlite_failure = public_sqlite_failure(error)
        diagnostic = args.work_dir/"failure.traceback.private"; diagnostic.write_text(traceback.format_exc()); diagnostic.chmod(0o600)
    finally:
        if suite is not None:
            suite.stop_guide()
            for host in reversed(list(suite.hosts.values())):
                try:
                    host.host.stop()
                    logs = host.host.log_path.read_bytes() if host.host.log_path.exists() else b""
                    require(not any(value in logs for value in suite.sensitive), "daemon log exposed private intro/pairing code")
                except BaseException as error: failure = failure or type(error).__name__
        keys.close()
    result = {"contract_pin":PIN, "implementation_source_read":False, "source":args.source, "final_head_acceptance":args.final_head,
        "artifact":{"path":str(args.host), "sha256":sha(args.host.read_bytes())},
        "probe":{"path":str(args.probe), "sha256":sha(args.probe.read_bytes())}, "spec_sha256":sha(SPEC.read_bytes()),
        "suite_sha256":sha(Path(__file__).read_bytes()), "planned_cases":CASES, "rows":[] if suite is None else suite.a.rows,
        "fresh_after_intro_from":None if args.fresh_after_intro_from is None else str(args.fresh_after_intro_from),
        "after_cold_selection_from":None if args.after_cold_selection_from is None else str(args.after_cold_selection_from),
        "fresh_final_from":None if args.fresh_final_from is None else str(args.fresh_final_from),
        "only_final":args.only_final,
        "trace":[] if suite is None else suite.trace, "failure":failure, "detail":detail, "sqlite_failure":sqlite_failure,
        "seconds":round(time.monotonic()-started, 3),
        "scope":"one coherent offered head; two original people/two actual foreground hosts/no coordinator; no installed up, adapter, relay, NAT or full migration claim",
        "passed":failure is None and suite is not None and len(suite.a.rows) == (1 if args.fresh_final_from or args.only_final else 2 if args.after_cold_selection_from else 3 if args.fresh_after_intro_from else len(CASES)) and all(v["passed"] for v in suite.a.rows)}
    args.results.parent.mkdir(parents=True, exist_ok=True); args.results.write_text(json.dumps(result, indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__": raise SystemExit(main())
