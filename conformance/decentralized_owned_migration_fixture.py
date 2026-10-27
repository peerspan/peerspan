#!/usr/bin/env python3
"""Uncounted public legacy setup for ONE three-host owned migration.

This constructs new actual stores, never copies them. A owns the raw legacy
root and sole original SSH key. B really completes old linking with device15;
C joins the SAME network host-only. No old positive case function is called.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import socket
import subprocess
import time
from types import SimpleNamespace

from decentralized_complete_link import table_rows
from decentralized_fixtures import b64, lines, raw_json, sha, unb64
from decentralized_migration_device_bans_fixture import external_original_signature
from decentralized_migration_identity import LegacyFixture, stamp
from decentralized_native_introduction import Introduction, ssh_public
from decentralized_runtime import CreationSuite
from decentralized_storage import require
from decentralized_vectors import strict_output


class OwnedLegacy(LegacyFixture):
    """Reuse public process/signature plumbing, not LegacyFixture.build."""

    def __init__(self, args, keys):
        self.args, self.keys, self.root = args, keys, args.work_dir
        self.clock = self.root/"legacy-clock"
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.clock.write_text(stamp(self.now)); self.clock.chmod(0o600)
        self.hosts, self.addresses = {}, {}
        for label in ("owner", "selected", "unbound"):
            root = self.root/label; root.mkdir(mode=0o700)
            value = CreationSuite(args.baseline, root, keys)
            value.host.environment.update(PEERSPAN_LINK_TEST_MODE="1", PEERSPAN_LINK_TEST_CLOCK_FILE=str(self.clock))
            value.host.environment["PATH"] = "/usr/bin:/bin"
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserved:
                reserved.bind(("127.0.0.1", 0)); address = "127.0.0.1:"+str(reserved.getsockname()[1])
            value.host.run_arguments = ["--peer-listen", address, "--advertise", address]
            self.hosts[label], self.addresses[label] = value, address
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0)); self.address = "127.0.0.1:"+str(reserved.getsockname()[1])
        self.coord_root = self.root/"coordinator"; self.coord_root.mkdir(mode=0o700)
        self.coord_log = (self.coord_root/"daemon.log").open("ab"); self.coordinator = None
        self.person_file = self.root/"owner"/"original-ed25519"
        generated = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.person_file)],
            capture_output=True, timeout=10)
        require(generated.returncode == 0, "owned legacy setup: original generation on A failed")

    def tick(self, seconds=None):
        # This constructor needs no artificial legacy expiry jump. Keep its
        # opted-in decision clock monotonic and near actual resource time.
        require(seconds is None, "owned legacy setup has no implicit clock-advance step")
        self.now = max(self.now,datetime.now(timezone.utc).replace(microsecond=0))
        self.clock.write_text(stamp(self.now))

    def public_catalog(self):
        result = subprocess.run([str(self.args.probe), "--state", str(self.hosts["selected"].host.state),
            "--address", self.addresses["owner"], "--alpn", "peerspan-peer/1", "--method", "GET", "--path",
            "/peer/v1/networks/"+self.network+"/link-catalog"], capture_output=True,
            env=self.hosts["selected"].host.environment, timeout=40)
        for suffix, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
            path = self.root/("legacy-catalog."+suffix); path.write_bytes(raw); path.chmod(0o600)
        require(result.returncode == 0, "owned legacy setup: actual member source catalog transport failed")
        wrapped = strict_output(result.stdout)
        require(set(wrapped) == {"status", "body"} and wrapped["status"] == 200,
            "owned legacy setup: source catalog response is not200")
        return wrapped["body"]["catalog"]

    def build(self):
        env = dict(self.hosts["owner"].host.environment)
        self.coordinator = subprocess.Popen([str(self.args.coordinator), "--state", str(self.coord_root/"state"),
            "run", "--listen", self.address], env=env, stdout=self.coord_log, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic()+20
        while time.monotonic() < deadline:
            require(self.coordinator.poll() is None, "owned legacy setup: coordinator exited")
            try:
                with socket.create_connection(("127.0.0.1", int(self.address.rsplit(":", 1)[1])), timeout=.1): break
            except OSError: time.sleep(.02)
        else: raise RuntimeError("owned legacy coordinator readiness exceeded20s")
        info = subprocess.run([str(self.args.coordinator), "--state", str(self.coord_root/"state"), "info"], capture_output=True, timeout=20)
        require(info.returncode == 0, "owned legacy setup: coordinator public info failed")
        self.coordinator_key = strict_output(info.stdout)["public_key"]
        for value in self.hosts.values():
            value.host.start(); value.identity = value.host.api("GET", "/v1/host")
        a = self.hosts["owner"]
        created = a.host.cli("network", "create", "Independent owned three-host migration", "--as", "Owned Alice",
            "--person-key", str(self.person_file), "--coordinator", self.address, "--coordinator-key", self.coordinator_key)
        self.network, self.person = created["id"], created["person"]["key"]["public_key"]
        require(self.person == ssh_public(self.person_file), "legacy creator chose another original identity")
        self.tick()
        a.host.cli("network", "enable-linking", "--network", self.network)
        request = self.api("selected", "POST", "/v1/link/requests", {"mode":"new", "network_id":self.network,
            "person_public_key":self.person, "coordinator_address":self.address,
            "coordinator_public_key":self.coordinator_key}, status=201)
        identifier = request["request_id"]
        approval = {"code":request["display_code"], "network_id":self.network,
            "expected_person_id":"person_"+sha(unb64(self.person)), "expected_host_key":"-", "expected_device_key":"-",
            "signer":"person_root", "approve":False}
        review = self.api("owner", "POST", "/v1/link/approvals", approval)["review"]
        require(review["scopes"] == 15, "owned legacy setup: ordinary original review did not propose exact15")
        approval.update(expected_host_key=review["host_public_key"], expected_device_key=review["device_public_key"], approve=True)
        self.sign(self.api("owner", "POST", "/v1/link/approvals", approval), identifier)
        self.consent(request)
        def administrator():
            self.api("owner", "POST", "/v1/link/requests/"+identifier+"/resume", {})
            self.sign(self.api("owner", "GET", "/v1/link/requests/"+identifier+"/approval"), identifier)
            rows = table_rows(a.host, "link_pending", "record", " WHERE request_id=?", (identifier,))
            return rows and strict_output(rows[0][0].encode())["administrator_packet_base64"] != "-"
        self.until(administrator, "actual old administrator packet")
        self.consent(request, commit=True)
        linked = self.until(lambda: (value if (value:=self.api("selected", "POST",
            "/v1/link/requests/"+identifier+"/resume", {}))["state"] == "linked" else None), "actual old selected15 application")
        signer = self.api("selected", "GET", "/v1/networks/"+self.network+"/link-signer")
        require(signer["person_public_key"] == self.person and signer["scopes"] == 15,
            "owned legacy setup: B does not have an actual selected15 device")
        invite = a.host.cli("network", "invite", "--network", self.network, "--member", "Unbound C",
            "--expires-at", stamp(self.now+timedelta(days=1)), "--host-only")
        joined = self.api("unbound", "POST", "/v1/networks/join", {"token":invite["token"]}, status=201)
        require(joined["id"] == self.network and joined.get("person") is None,
            "owned legacy setup: C did not join the SAME source network unbound")
        policy_message = lines("peerspan-policy-v1", self.network, self.person, 1, stamp(self.now), stamp(self.now+timedelta(days=2)))
        policy = {"network_id":self.network, "person_public_key":self.person, "version":1,
            "issued_at":stamp(self.now), "valid_until":stamp(self.now+timedelta(days=2)), "rules":[]}
        policy["signature"] = external_original_signature(self.person_file, policy_message, self.root/"owner", "source-policy")
        self.api("owner", "POST", "/v1/networks/"+self.network+"/policy", {"policy":policy}, status=201)
        a.host.cli("network", "group", "set", "--network", self.network, "--group", "migration-floor",
            "--person", "person_"+sha(unb64(self.person)))
        a.host.cli("network", "remove-admin", "--network", self.network, "--person", "person_"+sha(unb64(self.person)))
        for _ in range(3):
            for label in self.hosts: self.api(label, "POST", "/v1/networks/"+self.network+"/sync", {})
        expected_hosts = sorted(value.identity["public_key"] for value in self.hosts.values())
        for label in self.hosts:
            members = self.api(label, "GET", "/v1/networks/"+self.network+"/members")
            require(sorted(value["public_key"] for value in members) == expected_hosts,
                "owned legacy setup: one actual source host lacks the exact three-host roster")
        labels = {value["public_key"]:value["member"] for value in members}
        persons = self.api("owner", "GET", "/v1/networks/"+self.network+"/persons")
        require(len(persons) == 1 and persons[0]["public_key"] == self.person and not persons[0]["administrator"],
            "owned legacy setup: Alice admin withdrawal did not become current")
        catalog = self.public_catalog()
        maxima = {label:self.api(label, "GET", "/v1/networks/"+self.network+"/link-access-versions") for label in self.hosts}
        require(all(value == maxima["owner"] for value in maxima.values()), "legacy source hosts disagree on exact access maxima")
        access_maxima = [{"kind":kind,"subject":row[field],"version":row["version"],"message_hash":row["message_hash"]}
            for key,kind,field in (("policies","policy","person_public_key"),("groups","group","name")) for row in maxima["owner"][key]]
        access_maxima.sort(key=lambda row:(row["kind"],row["subject"]))
        certificates = [strict_output(unb64(row["body_base64"])) for row in catalog["objects"] if row["kind"] == "certificate"]
        matching = [value for value in certificates if value["device_public_key"] == signer["device_public_key"]]
        require(len(matching) == 1 and matching[0]["scopes"] == 15 and matching[0]["parent_id"] == "root" and
            matching[0]["network_id"] == self.network and matching[0]["person_public_key"] == self.person and
            matching[0]["host_public_key"] == self.hosts["selected"].identity["public_key"],
            "owned legacy setup: exact original nominal15 certificate is not retained")
        certificate = matching[0]
        certificate_message = lines("peerspan-device-certificate-v1", self.network, self.person,
            certificate["device_public_key"], certificate["host_public_key"], certificate["parent_id"], certificate["scopes"],
            certificate["issued_at"], certificate["not_after"], certificate["request_id"])
        Introduction.verify_original(SimpleNamespace(person=self.person,b=a), certificate["signature"], certificate_message)
        self.specs = [{"label":label, "network_id":self.network, "member":labels[value.identity["public_key"]],
            "person_public_key":"-" if label == "unbound" else self.person,
            "host_public_key":value.identity["public_key"],
            "device_public_key":signer["device_public_key"] if label == "selected" else "-",
            "scopes":15 if label == "selected" else 0 if label == "unbound" else 7} for label,value in self.hosts.items()]
        public = {"format":1, "specs":self.specs, "network_id":self.network, "person_public_key":self.person,
            "selected_signer_at_issuance":signer, "selected_certificate":matching[0], "legacy_catalog":catalog,
            "policy":policy, "policy_message_hash":sha(policy_message), "decision_time":stamp(self.now),
            "access_maxima":access_maxima,
            "actually_linked_request_view":linked, "coordinator_address":self.address,
            "coordinator_public_key":self.coordinator_key, "Alice_current_administrator":False,
            "baseline_sha256":sha(self.args.baseline.read_bytes()), "coordinator_sha256":sha(self.args.coordinator.read_bytes())}
        path = self.root/"owned-legacy-public.json"; path.write_bytes(raw_json(public)); path.chmod(0o600)
        return public
