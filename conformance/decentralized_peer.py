#!/usr/bin/env python3
"""Independent DEC current-peer replication and expired-member proof repair.

Only public contracts, our own codecs and an already admitted stopped fixture
are used. Actual daemon keys remain in place. The raw wire probe intentionally
makes NO server-pinning claim; the separate owner-local sync exercises the real
client. This slice excludes partial-container repair, known bans and data APIs.
"""
from __future__ import annotations

import argparse
import base64
import copy
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import time

from decentralized_complete_link import table_rows
from decentralized_fixtures import FixtureKeys, b64, lines, raw_json, sha, unb64
from decentralized_owner_preview import authority_rows
from decentralized_runtime import CreationSuite, NETWORK_FIELDS
from decentralized_storage import CheckFailure, all_database_snapshots, require
from decentralized_vectors import strict_output


PIN = "dada7fcedc4a215f79a78e08f2bedfa14e374931"
PEER, REPAIR = "peerspan-peer/1", "peerspan-state-repair/1"
CONTACT_FIELDS = set("format context_id host_public_key sequence issued_at expires_at payload_base64 signature".split())
CASES = [
    "current_catalog_exact_proof_bytes", "exact_catalog_union_and_retry_preserve_authority",
    "forged_alias_rejects_entire_catalog_without_mutation", "contacts_exact_signature_and_advertisement",
    "actual_tls_writer_contact_is_retained", "other_key_contact_cannot_replace_tls_writer",
    "forged_contact_and_unknown_field_rejected_without_head_change", "unknown_tls_key_discloses_no_catalog",
    "explicit_sync_attempts_independently_pinned_contact", "expired_member_loses_normal_catalog_route",
    "expired_remembered_member_can_fetch_exact_repair_catalog", "repair_router_exposes_no_admin_or_contact_route",
    "repair_reads_preserve_authority_clock_and_selection", "valid_contact_does_not_advance_authority_clock",
]


def stamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


class PeerReplication:
    def __init__(self, args, keys: FixtureKeys) -> None:
        self.args, self.keys, self.root = args, keys, args.work_dir
        self.rows, self.trace, self.wire_count = [], [], 0
        self.prior_passed = set()
        for receipt in args.prior_results:
            previous = json.loads(receipt.read_text())
            self.prior_passed |= {row["name"] for row in previous["rows"] if row["passed"]}
        self.hosts, self.addresses, self.clocks = {}, {}, {}
        for label, binary in (("owner", args.owner), ("requester", args.requester)):
            root = self.root/label; root.mkdir(mode=0o700)
            instance = CreationSuite(binary, root, keys)
            instance.host.state = args.retained_dir/label/"state"
            require(not (instance.host.state/"admin.sock").exists(), "retained actual fixture is not stopped")
            self.hosts[label] = instance
            clock = root/"authority-clock"
            clock.write_bytes((args.retained_dir/"requester"/"clock").read_bytes()); clock.chmod(0o600)
            self.clocks[label] = clock
            instance.host.environment.update(PEERSPAN_DEC_TEST_MODE="1", PEERSPAN_DEC_TEST_CLOCK_FILE=str(clock))
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserved:
                reserved.bind(("127.0.0.1", 0)); self.addresses[label] = "127.0.0.1:"+str(reserved.getsockname()[1])
        self.origin_now = (args.retained_dir/"requester"/"clock").read_text()
        anchors = [datetime.fromisoformat(self.origin_now.replace("Z", "+00:00"))]
        guarded_times = {}
        for label,instance in self.hosts.items():
            guarded_times[label] = []
            for encoded, in table_rows(instance.host,"dec_clock","record"):
                record = strict_output(encoded.encode())
                require(set(record) == {"format","largest_local_time"} and record["format"] == 1,
                        "retained normative clock record is malformed")
                anchors.append(datetime.fromisoformat(record["largest_local_time"].replace("Z", "+00:00")))
                guarded_times[label].append(record["largest_local_time"])
        # A prior actual sync may legitimately have advanced its guard. Start
        # both peers at that retained anchor rather than rewind either clock or
        # mint one peer's contact beyond the other's permitted hint skew.
        self.now = stamp(max(anchors))
        for clock in self.clocks.values(): clock.write_text(self.now)
        self.trace.append({"continuation_control_clocks":{"original_retained_file_time":self.origin_now,
            "retained_guard_times":guarded_times,"new_process_control_file_times":{k:self.now for k in self.clocks},
            "reason":"respect actually committed authority anchors after prior sync; align contact hint clocks without rewind",
            "original_retained_clock_file_not_written":True,"real_transport_timeouts_and_waits_unchanged":True}})
        if args.repair_only:
            require(args.from_controls_dir is not None, "repair continuation needs exact previous process control files")
            restored = {}
            for label,clock in self.clocks.items():
                previous = (args.from_controls_dir/label/"authority-clock").read_text()
                values = [datetime.fromisoformat(s.replace("Z", "+00:00")) for s in [previous,*guarded_times[label]]]
                restored[label] = stamp(max(values)); clock.write_text(restored[label])
            self.trace.append({"repair_only_control_clocks":{"previous_control_directory":str(args.from_controls_dir),
                "new_process_control_file_times":restored,"reason":"resume expired-state proof reads without new contact/signing setup or clock rewind"}})
        self.receipts = self.root/"wire"; self.receipts.mkdir(mode=0o700)

    def case(self, label, name, function):
        if label+"/"+name in self.prior_passed:
            return
        began = time.monotonic()
        try:
            function()
        except BaseException as error:
            self.rows.append({"name": label+"/"+name, "passed": False, "error_type": type(error).__name__,
                "detail": str(error) if isinstance(error, CheckFailure) else "fixture/transport failure",
                "seconds": round(time.monotonic()-began, 3)})
            print("FAIL "+label+"/"+name, flush=True); raise
        self.rows.append({"name": label+"/"+name, "passed": True, "seconds": round(time.monotonic()-began, 3)})
        print("PASS "+label+"/"+name, flush=True)

    def operation_hash(self, label):
        return sha(raw_json(table_rows(self.hosts[label].host, "dec_operations", "request_id,record,activation_id,manifest_id,locally_applied")))

    def authority(self, label):
        instance = self.hosts[label]
        return (authority_rows(instance), sha(raw_json(table_rows(instance.host, "dec_clock", "*"))))

    def contacts_hash(self, label):
        return sha(raw_json(table_rows(self.hosts[label].host, "dec_contacts", "*")))

    def wire(self, target, sender, method, path, body=None, *, alpn=PEER):
        argv = [str(self.args.probe), "--address", self.addresses[target], "--alpn", alpn,
                "--method", method, "--path", path]
        if sender is None:
            seed = hashlib.sha256(lines("peerspan-independent-dec-fixture-only-v1", "peer-unknown")).hexdigest()
            argv += ["--seed-hex", seed]
        else:
            argv += ["--state", str(self.hosts[sender].host.state)]
        data = None if body is None else raw_json(body)
        if data is not None: argv += ["--body-stdin"]
        result = subprocess.run(argv, input=data, capture_output=True, timeout=40,
                                env=self.hosts[target].host.environment)
        self.wire_count += 1; prefix = self.receipts/f"{self.wire_count:03}"
        for suffix, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
            saved = prefix.with_suffix("."+suffix); saved.write_bytes(raw); saved.chmod(0o600)
        meta = {"target":target,"sender":sender or "fixture-unknown", "actual_host_state_used":sender is not None,
            "method":method,"path":path,"alpn":alpn,"exit":result.returncode,
            "request_sha256": None if data is None else sha(data), "stdout_sha256":sha(result.stdout),
            "stderr_sha256":sha(result.stderr),"raw_probe_has_no_server_pin_check":True}
        prefix.with_suffix(".meta.json").write_bytes(raw_json(meta))
        if data is not None: prefix.with_suffix(".request.json").write_bytes(data)
        if result.returncode:
            return None, None, result
        value = strict_output(result.stdout)
        require(set(value) == {"status", "body"} and type(value["status"]) is int,
                "public raw-probe status/body wrapper differs")
        return value["status"], value["body"], result

    def success(self, target, sender, method, path, body=None, *, alpn=PEER):
        status, value, _ = self.wire(target, sender, method, path, body, alpn=alpn)
        require(status == 200, f"wire {alpn} {method} {path} returned {status}, expected200; see wire receipt")
        return value

    def catalog(self, value):
        require(type(value) is dict and set(value) == {"catalog"}, "peer catalog wrapper differs")
        catalog = value["catalog"]
        require(set(catalog) == {"format","context_id","objects"} and catalog["format"] == 1 and
                catalog["context_id"] == self.context, "peer catalog context/fields differ")
        ids = [item["id"] for item in catalog["objects"]]
        require(ids == sorted(set(ids)), "peer catalog IDs are not sortedunique")
        proofs = {}
        for item in catalog["objects"]:
            require(set(item) == {"id","kind","body_base64"}, "peer proof entry fields differ")
            raw = unb64(item["body_base64"])
            require(item["id"] == "dp_"+sha(lines("peerspan-decentralized-proof-v1", item["kind"], sha(raw))),
                    "peer rewrote exact proof bytes or proof ID")
            proofs[item["id"]] = item
        return catalog, proofs

    def contact(self, value):
        require(set(value) == CONTACT_FIELDS and type(value["format"]) is int and value["format"] == 1 and
                value["context_id"] == self.context and type(value["sequence"]) is int and 0 < value["sequence"] < 2**64,
                "signed contact fields/context/sequence differ")
        payload = strict_output(unb64(value["payload_base64"]))
        require(set(payload) == {"quic_addresses","bootstrap_addresses","relays"}, "contact payload fields differ")
        for field in ("quic_addresses", "bootstrap_addresses"):
            require(payload[field] == sorted(set(payload[field])) and len(payload[field]) <= 8, "contact endpoint order/count differs")
        require(len(payload["relays"]) <= 8 and sum(len(payload[k]) for k in payload) <= 16, "contact total endpoints exceeds bound")
        start, end = (datetime.fromisoformat(value[k].replace("Z", "+00:00")) for k in ("issued_at","expires_at"))
        require(0 < (end-start).total_seconds() <= 300 and len(raw_json(value)) <= 8192, "contact interval/size exceeds bound")
        message = lines("peerspan-decentralized-contact-v1", self.context, value["host_public_key"], value["sequence"],
                        value["issued_at"], value["expires_at"], sha(unb64(value["payload_base64"])))
        self.hosts["owner"].verify_raw(value["host_public_key"], message, value["signature"])
        return payload

    def prepare(self):
        pending_rows = table_rows(self.hosts["requester"].host, "dec_pending", "record")
        require(len(pending_rows) == 1, "retained actual requester operation is not unique")
        pending = strict_output(pending_rows[0][0].encode())
        require(pending["terminal"] == "applied", "retained requester is not actually applied")
        descriptor = strict_output(unb64(pending["descriptor_base64"]))
        activation = strict_output(unb64(strict_output(table_rows(self.hosts["requester"].host,
            "dec_operations", "record")[0][0].encode())["activation_base64"]))
        self.network, self.context = descriptor["network_id"], activation["context_id"]
        expected = {"owner":activation["owner"]["writer_host_public_key"],
                    "requester":activation["request"]["writer_host_public_key"]}
        before = {label:all_database_snapshots(instance.host.state) for label,instance in self.hosts.items()}
        operations = {label:self.operation_hash(label) for label in self.hosts}
        (self.root/"before-state-hashes.json").write_bytes(raw_json(before))
        self.trace.append({"preexisting_operation_hashes":operations, "expected_actual_host_public_keys":expected})
        for label, instance in self.hosts.items():
            endpoints = [e for e in pending["carrier_endpoints"] if e["kind"] == "participant" and e["public_key"] == expected[label]]
            require(len(endpoints) == 1, "retained actual participant listener is not unique")
            config = instance.root/"transport.json"
            config.write_bytes(raw_json({"format":1,"advertise_bootstrap":[endpoints[0]["address"]],
                "advertise_quic":[self.addresses[label]],"rendezvous":[],"relays":[],"publish_contacts":not self.args.repair_only})); config.chmod(0o600)
            instance.host.run_arguments = ["--bootstrap-listen", endpoints[0]["address"], "--peer-listen",self.addresses[label],
                "--advertise",self.addresses[label],"--transport-config",str(config)]
            instance.host.start(); instance.identity = instance.host.api("GET", "/v1/host")
            require(instance.identity["public_key"] == expected[label] and self.operation_hash(label) == operations[label],
                    "integrated reopen changed actual host identity or signed historical operation")
        time.sleep(2.05)  # Real transport/outbox scheduling; not authority time.
        self.route = "/peer/v2/networks/"+self.network
        self.repair_route = "/repair/v1/networks/"+self.network+"/catalog"
        self.baseline, self.own_contacts = {}, {}
        for label, instance in self.hosts.items():
            local, _ = instance.api("GET", "/v2/networks/"+self.network+"/catalog")
            self.baseline[label] = self.catalog(local)[1]
            if self.args.repair_only:
                continue
            # The documented explicit action mints the actual host's signed
            # contact. publish_contacts is optional encrypted helper delivery,
            # and GET contacts need not invent an unstored own-host hint.
            self.own_contacts[label] = self.mint_contact(label)
            require(self.own_contacts[label]["host_public_key"] == instance.identity["public_key"] and
                    self.addresses[label] in self.contact(self.own_contacts[label])["quic_addresses"],
                    "explicitly minted actual signed contact omitted peer advertisement")
        if self.args.repair_only:
            return
        for target,sender in (("owner","requester"),("requester","owner")):
            contact = self.own_contacts[sender]
            value = self.success(target,sender,"POST",self.route+"/contact",{"contact":contact})
            require(value == {"contact":contact}, "actual-writer contact fixture setup was not accepted exactly")
        self.trace.append({"contacts_fixture_precondition":"explicit invitation mint plus actual TLS-writer contact POST",
            "automatic_own_contact_in_GET_not_assumed":True})

    def current(self, target, sender):
        instance = self.hosts[target]
        def read():
            _, proofs = self.catalog(self.success(target,sender,"GET",self.route+"/catalog"))
            require(self.baseline[target].items() <= proofs.items(), "peer catalog omitted or rewrote retained proofs")
        self.case(target, CASES[0], read)
        def repeat():
            candidate = self.hosts[sender].api("GET", "/v2/networks/"+self.network+"/catalog")[0]
            known = self.catalog(candidate)[1]
            first = self.success(target,sender,"POST",self.route+"/catalog",candidate)
            _, union = self.catalog(first)
            require(self.baseline[target].items() <= union.items() and known.items() <= union.items(), "union lost exact local/candidate proofs")
            before = self.authority(target); operation = self.operation_hash(target)
            again = self.success(target,sender,"POST",self.route+"/catalog",candidate)
            require(self.catalog(again)[1] == union and self.authority(target) == before and self.operation_hash(target) == operation,
                    "exact catalog retry changed signed proofs, admission, maxima, clock or outcome")
        self.case(target, CASES[1], repeat)
        def forged():
            original = self.success(target,sender,"GET",self.route+"/catalog")["catalog"]
            entry = next(item for item in original["objects"] if item["kind"] == "root_state")
            altered = strict_output(unb64(entry["body_base64"])); signature = bytearray(unb64(altered["signatures"][0]["signature"]))
            signature[0] ^= 1; altered["signatures"][0]["signature"] = b64(bytes(signature)); raw = raw_json(altered)
            bad_entry = {"id":"dp_"+sha(lines("peerspan-decentralized-proof-v1",entry["kind"],sha(raw))),
                         "kind":entry["kind"],"body_base64":b64(raw)}
            bad = copy.deepcopy(original); bad["objects"] = sorted(bad["objects"]+[bad_entry], key=lambda e:e["id"])
            before = self.authority(target)
            status, error, _ = self.wire(target,sender,"POST",self.route+"/catalog",{"catalog":bad})
            require(status == 400 and error["code"] == "invalid" and self.authority(target) == before,
                    "forged alias was accepted or changed authoritative state")
        self.case(target, CASES[2], forged)
    def contact_boundaries(self, target, sender):
        if target+"/"+CASES[13] in self.prior_passed:
            # Restore the earlier passed control's in-memory clock precondition
            # while skipping its assertions, preserving the next failed input.
            old = datetime.fromisoformat(self.clocks[target].read_text().replace("Z", "+00:00"))
            desired = datetime.fromisoformat(self.origin_now.replace("Z", "+00:00"))+timedelta(seconds=60)
            self.clocks[target].write_text(stamp(max(old,desired)))
        def actual():
            contact = self.own_contacts[sender]
            value = self.success(target,sender,"POST",self.route+"/contact",{"contact":contact})
            require(value == {"contact":contact}, "valid TLS writer contact was rewritten")
            observed = self.success(target,sender,"GET",self.route+"/contacts")["contacts"]
            require(contact in observed, "valid actual writer contact was not retained")
        self.case(target,CASES[4],actual)
        def contact_clock():
            # Runtime mutations, including the target's own background work,
            # may persist the guard at the target's actual LOCAL decision time;
            # only a contact-derived time is attributable to the contact. So
            # mint a newer valid sender contact issued 20s AFTER the target's
            # local time (inside the 30s hint skew), stop the sender so no
            # replication lands in the window, let the target's guard settle,
            # and require the contact neither adopts its issued_at nor changes
            # any other authority, provider, admission, head, maximum or outcome.
            base = max(datetime.fromisoformat(c.read_text().replace("Z", "+00:00")) for c in self.clocks.values())
            local, ahead = base+timedelta(seconds=60), base+timedelta(seconds=80)
            self.clocks[target].write_text(stamp(local)); self.clocks[sender].write_text(stamp(ahead))
            contact = self.mint_contact(sender)
            require(contact["issued_at"] == stamp(ahead) and contact["sequence"] > self.own_contacts[sender]["sequence"],
                    "fresh sender contact was not issued at its later local decision time")
            self.pause(sender)
            settle = time.monotonic()+5
            while time.monotonic() < settle:
                rows = table_rows(self.hosts[target].host, "dec_clock", "record")
                if rows and all(strict_output(r[0].encode())["largest_local_time"] == stamp(local) for r in rows): break
                time.sleep(.1)
            before = self.authority(target); operation = self.operation_hash(target)
            guard_before = [strict_output(r[0].encode())["largest_local_time"] for r in table_rows(self.hosts[target].host, "dec_clock", "record")]
            value = self.success(target,sender,"POST",self.route+"/contact",{"contact":contact})
            after = self.authority(target)
            guard_after = [strict_output(r[0].encode())["largest_local_time"] for r in table_rows(self.hosts[target].host, "dec_clock", "record")]
            self.trace.append({"target":target,"contact_clock":{"local_decision_time":stamp(local),"contact_issued_at":stamp(ahead),
                "guard_before":guard_before,"guard_after":guard_after}})
            require(value == {"contact":contact} and after[0] == before[0] and self.operation_hash(target) == operation and
                    all(g in (b, stamp(local)) for g, b in zip(guard_after, guard_before)) and len(guard_after) == len(guard_before) and
                    stamp(ahead) not in guard_after,
                    "valid signed contact advanced authority clock, provider, admission, heads, maxima or outcome")
            self.own_contacts[sender] = contact
        self.case(target,CASES[13],contact_clock)
        def contacts():
            value = self.success(target,sender,"GET",self.route+"/contacts")
            require(set(value) == {"contacts"}, "peer contacts wrapper differs")
            pairs = [(c["host_public_key"],c["sequence"]) for c in value["contacts"]]
            require(pairs == sorted(pairs), "peer contacts are not host/sequence ordered")
            for item in value["contacts"]: self.contact(item)
            require(self.own_contacts[sender] in value["contacts"], "peer GET omitted exact accepted actual-writer contact")
        self.case(target, CASES[3], contacts)
        start = datetime.fromisoformat(self.now.replace("Z", "+00:00"))
        payload = raw_json({"quic_addresses":["127.0.0.1:40999"],"bootstrap_addresses":[],"relays":[]})
        contact = {"format":1,"context_id":self.context,"host_public_key":self.keys.public("peer-unknown"),
            "sequence":1,"issued_at":stamp(start),"expires_at":stamp(start+timedelta(seconds=300)),"payload_base64":b64(payload)}
        def sign(value):
            return b64(self.keys.sign("peer-unknown",lines("peerspan-decentralized-contact-v1", self.context,value["host_public_key"],
                value["sequence"],value["issued_at"],value["expires_at"],sha(unb64(value["payload_base64"])))))
        contact["signature"] = sign(contact)
        def mismatch():
            before = (self.authority(target),self.contacts_hash(target))
            status,error,_ = self.wire(target,sender,"POST",self.route+"/contact",{"contact":contact})
            after = (self.authority(target),self.contacts_hash(target))
            self.trace.append({"target":target,"contact_writer_mismatch":{
                "status":status,"code":error.get("code") if type(error) is dict else None,
                "authority_and_contact_hash_before":before,"authority_and_contact_hash_after":after}})
            require(status == 403 and error["code"] == "forbidden" and before == after,
                    "different signed key contact bypassed actual TLS writer or changed remembered head")
        self.case(target,CASES[5],mismatch)
        def malformed():
            wrong = dict(contact,host_public_key=self.hosts[sender].identity["public_key"])
            wrong["signature"] = sign(wrong)
            extra = dict(contact,unrecognized=True)
            for bad in (wrong,extra):
                before = (self.authority(target),self.contacts_hash(target))
                status,error,_ = self.wire(target,sender,"POST",self.route+"/contact",{"contact":bad})
                require(status == 400 and error["code"] == "invalid" and before == (self.authority(target),self.contacts_hash(target)),
                        "invalid contact signature/field changed head or escaped strict rejection")
        self.case(target,CASES[6],malformed)
        def unknown():
            self.success(target,sender,"GET",self.route+"/catalog")
            before = self.authority(target)
            status,error,result = self.wire(target,None,"GET",self.route+"/catalog")
            if status is None:
                require(result.returncode != 0 and not result.stdout, "unknown TLS host received response data")
                phase = "TLS_or_protocol_refusal_no_HTTP_response"
            else:
                require(status == 403 and type(error) is dict and error.get("code") == "forbidden" and "catalog" not in error,
                        "unknown actual TLS host received catalog or unexpected HTTP failure")
                phase = "HTTP403_forbidden"
            require(self.authority(target) == before, "unknown TLS request changed authority")
            self.success(target,sender,"GET",self.route+"/catalog")
            self.trace.append({"target":target,"unknown_host_refusal_phase":phase})
        self.case(target,CASES[7],unknown)
        self.resume(sender)

    def mint_contact(self, label):
        instance = self.hosts[label]
        value,_ = instance.api("POST", "/v2/networks/"+self.network+"/invitations",
            {"member":"Independent peer contact", "expected_person_public_key":"-"}, status=201)
        require(set(value) == {"network_id","context_id","invitation_id","invitation","expires_at"} and
                value["network_id"] == self.network and value["context_id"] == self.context and
                value["invitation"].startswith("psi2-"), "explicit contact-invitation mint wrapper differs")
        token = value["invitation"][5:]
        invitation = strict_output(base64.urlsafe_b64decode(token+"="*((-len(token))%4)))
        payload = strict_output(unb64(invitation["payload_base64"]))
        require(invitation["inviter_host_public_key"] == instance.identity["public_key"] and
                len(payload["contacts"]) == 1, "explicit invitation did not carry its actual host contact")
        return payload["contacts"][0]

    def pause(self, label):
        self.hosts[label].host.stop()
        self.trace.append({"isolation":"sender daemon stopped during target authority-purity controls", "sender":label})

    def resume(self, label):
        instance = self.hosts[label]
        identity = instance.identity
        instance.host.start(); instance.identity = instance.host.api("GET", "/v1/host")
        require(instance.identity == identity, "isolation restart replaced actual sender host identity")

    def sync(self,target,sender):
        def exchange():
            before_network,_ = self.hosts[target].api("GET","/v2/networks/"+self.network)
            value,_ = self.hosts[target].api("POST","/v2/networks/"+self.network+"/sync",{})
            require(set(value) == {"network","attempted","learned_proof_ids","unavailable"} and
                    set(value["network"]) == NETWORK_FIELDS and value["network"]["id"] == self.network,
                    "explicit sync wrapper/network differs")
            require(value["attempted"] == sorted(set(value["attempted"])) and
                    self.hosts[sender].identity["public_key"] in value["attempted"], "sync did not attempt exact independently signed peer contact")
            require(value["learned_proof_ids"] == sorted(set(value["learned_proof_ids"])) and
                    all(set(v) == {"host_public_key","code"} for v in value["unavailable"]), "sync arrays/errors differ")
            require([v["host_public_key"] for v in value["unavailable"]] == sorted({v["host_public_key"] for v in value["unavailable"]}),
                    "sync unavailable host keys are not sortedunique")
            final_proofs = self.catalog(self.hosts[target].api("GET","/v2/networks/"+self.network+"/catalog")[0])[1]
            require(set(value["learned_proof_ids"]) <= final_proofs.keys(), "sync invented learned proof IDs absent from retained exact catalog")
            require(all(value["network"][key] == before_network[key] for key in
                    ("id","context_id","host_public_key","person_public_key","provider")) and
                    value["network"]["authority"]["state"] == "usable" and
                    value["network"]["provider_state"] == before_network["provider_state"],
                    "reachable same-state sync changed identity/provider or lost independently valid offline authority")
            require(not any(v["host_public_key"] == self.hosts[sender].identity["public_key"] for v in value["unavailable"]),
                    "reachable pinned peer was unavailable during explicit sync")
            self.trace.append({"target":target,"actual_client_sync_to_prior_pinned_peer_observed":True,
                "wrong_server_key_negative_evaluated":False,
                "attempted":value["attempted"],"learned_proof_ids":value["learned_proof_ids"]})
        self.case(target,CASES[8],exchange)

    def expiry(self,target,sender):
        instance = self.hosts[target]
        catalog = instance.api("GET","/v2/networks/"+self.network+"/catalog")[0]["catalog"]
        expiries = []
        for entry in catalog["objects"]:
            if entry["kind"] != "host_lease": continue
            body = strict_output(unb64(entry["body_base64"])); payload = strict_output(unb64(body["payload_base64"]))
            if payload["subject"]["host_public_key"] == self.hosts[sender].identity["public_key"]:
                expiries.append(datetime.fromisoformat(payload["not_after"].replace("Z", "+00:00")))
        require(expiries, "expiry case lacks actual admitted sender H body")
        expired_at = stamp(max(expiries)+timedelta(seconds=1))
        self.pause(sender)
        self.clocks[target].write_text(expired_at)
        self.trace.append({"target":target,"authority_clock_only":expired_at,"actual_sender_host_lease_ceiling":stamp(max(expiries)),
            "transport_clock_unchanged":True})
        def normal_denied():
            status,value,result = self.wire(target,sender,"GET",self.route+"/catalog")
            if status is None:
                require(result.returncode != 0 and not result.stdout, "expired normal caller received data")
            else:
                require(status == 403 and type(value) is dict and "catalog" not in value,
                        "expired sender retained normal catalog permission")
        self.case(target,CASES[9],normal_denied)
        def fetch():
            before = self.authority(target)
            value = self.success(target,sender,"GET",self.repair_route,alpn=REPAIR)
            _,proofs = self.catalog(value)
            local = self.catalog(instance.api("GET","/v2/networks/"+self.network+"/catalog")[0])[1]
            require(proofs == local and self.authority(target) == before,
                    "expired repair omitted/reencoded proofs or mutated authoritative state")
        self.case(target,CASES[10],fetch)
        def isolated():
            # Runtime§8 requires nondisclosure and imports bootstrap resource
            # bounds. Discard forcing mailbox-router404 onto this separate ALPN:
            # that response requirement is absent from the public repair wire.
            for path in ("/v1/host",self.route+"/contacts"):
                status,value,result = self.wire(target,sender,"GET",path,alpn=REPAIR)
                if status is None:
                    require(result.returncode != 0 and not result.stdout,
                            "repair off-route rejection disclosed response data")
                    phase = "transport_closure_with_zero_response_data"
                else:
                    require(status == 404 and type(value) is dict and value.get("code") == "not_found" and
                        set(value) in ({"code","error","details"},{"code","error","required_ids"}) and type(value["error"]) is str,
                        "repair off-route HTTP response was not strict not_found or disclosed unrelated fields")
                    phase = "HTTP404_not_found"
                self.trace.append({"target":target,"repair_off_route":path,"nondisclosure_phase":phase,
                    "no_bootstrap_mailbox_router_404_requirement_assumed":True})
        self.case(target,CASES[11],isolated)
        def read_only():
            before = self.authority(target); operation = self.operation_hash(target)
            # Four repair GETs total, separated so the public1/s burst4 limiter
            # is not itself the subject of this authority/read-purity case.
            time.sleep(1.05)
            self.success(target,sender,"GET",self.repair_route,alpn=REPAIR)
            require(self.authority(target) == before and self.operation_hash(target) == operation,
                    "repair read advanced guard, changed provider/admission/head/max/outcome")
        self.case(target,CASES[12],read_only)
        self.resume(sender)

    def run(self):
        self.prepare()
        if not self.args.repair_only:
            for target,sender in (("owner","requester"),("requester","owner")): self.current(target,sender)
            for target,sender in (("owner","requester"),("requester","owner")): self.contact_boundaries(target,sender)
            for target,sender in (("owner","requester"),("requester","owner")): self.sync(target,sender)
        for target,sender in (("owner","requester"),("requester","owner")): self.expiry(target,sender)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("owner","requester","probe","retained-dir","work-dir","results"):
        parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--prior-results", type=Path, action="append", default=[],
        help="Retained earlier receipt: skip ONLY its passed cases on the same in-place fixture")
    parser.add_argument("--repair-only", action="store_true", help="Continue only expired-state controls without new contact signing")
    parser.add_argument("--from-controls-dir", type=Path, help="Exact prior receipt directory containing each process authority-clock")
    args = parser.parse_args()
    for name in ("owner","requester","probe","retained_dir","work_dir","results"):
        setattr(args,name,getattr(args,name).resolve())
    args.work_dir.mkdir(mode=0o700,parents=True,exist_ok=False)
    keys = FixtureKeys(); suite = PeerReplication(args,keys); failure = detail = None; began = time.monotonic()
    try: suite.run()
    except BaseException as error:
        failure,detail = type(error).__name__, str(error) if isinstance(error,CheckFailure) else "fixture/transport failure"
    finally:
        for instance in reversed(list(suite.hosts.values())):
            try: instance.host.stop()
            except BaseException as error:
                failure = failure or type(error).__name__
                suite.rows.append({"name":"cleanup","passed":False,"error_type":type(error).__name__})
        keys.close()
    support = ("decentralized_complete_link.py","decentralized_fixtures.py","decentralized_owner_preview.py",
               "decentralized_runtime.py","decentralized_storage.py","decentralized_vectors.py",
               "decentralized_requester.py","decentralized_helper.py","decentralized_direct_carrier.py")
    result = {"contract_pin":PIN,"suite_sha256":sha(Path(__file__).read_bytes()),"implementation_source_read":False,
        "support_sha256":{name:sha(Path(__file__).with_name(name).read_bytes()) for name in support},
        "artifacts":{name:{"path":str(getattr(args,name)),"sha256":sha(getattr(args,name).read_bytes())} for name in ("owner","requester","probe")},
        "retained_dir":str(args.retained_dir),"planned_cases":{label:CASES for label in suite.hosts},
        "prior_passed_cases_not_repeated":sorted(suite.prior_passed),
        "prior_results":[str(p) for p in args.prior_results],
        "rows":suite.rows,"trace":suite.trace,"failure":failure,"detail":detail,"seconds":round(time.monotonic()-began,3),
        "scope":"new normal catalog/contact/current-prior TLS gates, actual pinned owner sync and expired remembered-host QUIC proof repair only; no known-ban/partial-container/data/native/installed or raw-client server-pin claim",
        "passed":failure is None and len(suite.rows)==2*len(CASES)-len(suite.prior_passed) and all(r["passed"] for r in suite.rows)}
    args.results.parent.mkdir(parents=True,exist_ok=True); args.results.write_text(json.dumps(result,indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__": raise SystemExit(main())
