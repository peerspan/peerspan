#!/usr/bin/env python3
"""Public-construction primitives for the independent PR138 fork fixtures.

No case function or implementation is imported. The original remains in A's
signer HOME; B owns its normally generated host/device keys. No SQL mutation,
whole-store copy, seed export or daemon original signing is used. This module
has no runtime entry point and performs no work when imported.
"""
from __future__ import annotations

import copy
import socket
import subprocess
import textwrap
import time
from urllib.parse import quote

from decentralized_fixtures import b64, lines, raw_json, sha, unb64
from decentralized_policy_preparation_timing import ACTION_FIELDS, TimingFixture, sqlite_rows, statement_id
from decentralized_runtime import CreationSuite, SLOT_FIELDS
from decentralized_storage import all_database_snapshots, require
from decentralized_vectors import strict_output


PACKET_FIELDS = set("format context_id request_id role writer_host_public_key signer_public_key person_public_key "
    "issuer_id payload_base64 host_signature device_signature authority_signature_format authority_signature".split())
REFERENCE_FIELDS = {"statement_id", "proof_id", "statement_base64", "body_base64"}
EDIT_FIELDS = set("format mode context_id seq state start signed signed_version dropped reserved_at signed_at "
    "unsettled_at closed_at dropped_at".split())


def packet_id(packet):
    require(set(packet) == PACKET_FIELDS and packet["format"] == 1, "typed packet schema differs")
    message = lines("peerspan-decentralized-packet-v1", packet["context_id"], packet["request_id"], packet["role"],
        packet["writer_host_public_key"], packet["signer_public_key"], packet["person_public_key"], packet["issuer_id"],
        packet["authority_signature_format"], sha(unb64(packet["payload_base64"])))
    return "dpk_"+sha(message), message


class PolicyPair:
    """Two normally enrolled actual siblings, with controlled proof delivery."""
    def __init__(self, args, root):
        self.args, self.root = args, root
        root.mkdir(mode=0o700)
        self.creator = TimingFixture(args, root/"A")
        self.a = self.creator.s
        self.original = self.creator.original
        self.b = CreationSuite(args.host, root/"B", self.original)
        self.hosts = {"A":self.a, "B":self.b}
        self.dead_sockets, self.addresses, self.bootstrap = [], {}, {}
        self.trace, self.wire_count, self.cli_count = [], 0, 0
        self.receipts = root/"public-wire"; self.receipts.mkdir(mode=0o700)
        for label, suite in self.hosts.items():
            suite.host.environment["PATH"] = "/usr/bin:/bin"
            suite.host.environment.pop("SSH_AUTH_SOCK", None)
            suite.host.environment.update(PEERSPAN_DEC_TEST_MODE="1", PEERSPAN_DEC_TEST_CLOCK_FILE=str(self.creator.clock))
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
                reserved.bind(("127.0.0.1", 0)); tcp = "127.0.0.1:"+str(reserved.getsockname()[1])
            # Keep the dead advertised port actually occupied. Explicit probe
            # imports use a different unadvertised real peer listener below.
            dead = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dead.bind(("127.0.0.1", 0)); self.dead_sockets.append(dead)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserved:
                reserved.bind(("127.0.0.1", 0)); udp = "127.0.0.1:"+str(reserved.getsockname()[1])
            self.addresses[label], self.bootstrap[label] = udp, tcp
            suite.host.run_arguments = ["--bootstrap-listen", tcp, "--peer-listen", udp,
                "--advertise", "127.0.0.1:"+str(dead.getsockname()[1])]
            require(not any(v in suite.host.run_arguments for v in ("--person-key-file", "--person-agent")),
                "new daemon fixture accidentally acquired original signing")

    def pending(self, label):
        matches = [strict_output(raw.encode()) for identifier, raw in
            sqlite_rows(self.hosts[label].host, "dec_pending", "request_id,record") if identifier == self.request["request_id"]]
        require(len(matches) == 1, "actual sibling enrollment lost its exact pending record")
        return matches[0]

    def original_slot(self, slot, *, payload=None, request=None):
        require(set(slot) == SLOT_FIELDS and slot["public_key"] == self.original.person and
            slot["format"] == "sshsig" and slot["role"] in {"issuer", "authority"},
            "typed fixture work requested another private signer or format")
        template = strict_output(unb64(slot["template_base64"]))
        if slot["object_type"].endswith("_packet"):
            identifier, message = packet_id(template)
            require(slot["role"] == "authority" and template["signer_public_key"] == self.original.person and
                template["person_public_key"] == self.original.person and template["authority_signature_format"] == "sshsig" and
                template["authority_signature"] == "-" and template["context_id"] == self.network["context_id"] and
                template["request_id"] == request and template["writer_host_public_key"] == self.a.identity["public_key"] and
                template["role"] in {"owner", "owner_finalization"}, "fixture packet changed authority, writer, role or exact request")
        else:
            identifier = statement_id(template)
            message = lines("peerspan-decentralized-signature-v1", identifier, "issuer", self.original.person)
            issuer = [entry for entry in template["signatures"] if entry["role"] == "issuer"]
            require(slot["role"] == "issuer" and template["context_id"] == self.network["context_id"] and
                template["kind"] == slot["object_type"] and issuer == [{"role":"issuer",
                    "public_key":self.original.person, "format":"sshsig", "signature":"-"}],
                "fixture ordinary template changed issuer/key/context")
            value = strict_output(unb64(template["payload_base64"]))
            require(value["root_state_id"] == self.network["root_state_id"] and
                value["issuer"] == {"kind":"person", "person_public_key":self.original.person},
                "fixture requested another root or policy/owner issuer")
            if payload is not None:
                require(value == payload and template["kind"] == "policy" and template["signatures"] == issuer,
                    "fixture action payload/roles changed before external signing")
            else:
                require(template["kind"] in {"binding_lease", "device_lease"} and value["operation_id"] == request and
                    value["subject"]["person_public_key"] == self.original.person and
                    value["subject"]["host_public_key"] == self.request["host_public_key"] and
                    value["subject"]["scopes"] == (7 if template["kind"] == "device_lease" else 2) and
                    value["subject"]["device_public_key"] == (self.request["device_public_key"] if template["kind"] == "device_lease" else "-"),
                    "fixture owner lease changed target, scope, device or operation")
                other = [entry for entry in template["signatures"] if entry["role"] != "issuer"]
                require(other == [] or (template["kind"] == "binding_lease" and other == [{"role":"host",
                    "public_key":self.request["host_public_key"], "format":"ed25519", "signature":"-"}]),
                    "fixture owner template requested another non-issuer signature")
        require(slot["object_id"] == identifier and unb64(slot["message_base64"]) == message,
            "fixture typed slot message/ID differs from independent derivation")
        return {"slot_id":slot["slot_id"], "role":slot["role"], "signature":b64(self.original.sshsig("alice", message))}

    def finish_owner(self, ready, field):
        for _ in range(8):
            if self.pending("A")[field] != "-":
                return ready
            slots = ready["signing_requests"]
            require(0 < len(slots) <= 16 and len({slot["intent_id"] for slot in slots}) == 1,
                "approved fixture owner stage has no bounded ready batch")
            ready = self.a.api("POST", self.request_route+"/signed", {"intent_id":slots[0]["intent_id"],
                "signatures":[self.original_slot(slot, request=self.request["request_id"]) for slot in slots]})[0]
        raise RuntimeError("fixture owner stage exceeded eight dependency batches")

    def learn(self, label, field):
        for _ in range(5):
            time.sleep(2.05)  # Real transport-read cache, never DEC-clock expiry.
            value = self.hosts[label].api("POST", self.request_route+"/resume", {}, timeout=40)[0]
            if value[field] != "-":
                return value
        raise RuntimeError("fixture did not observe its exact public stage within five bounded actual polls")

    def start(self):
        """Only new necessary setup; no older positive case body is called."""
        self.creator.start()
        self.network, self.route = self.creator.network, self.creator.route
        self.a.context_id = self.network["context_id"]
        self.b.host.start(); self.b.identity = self.b.host.api("GET", "/v1/host")
        # A same-person sibling introduction carries the person's existing
        # admitted member label; the requester pins it against the owner offer.
        intro = self.a.api("POST", self.route+"/invitations", {"member":self.a.member,
            "expected_person_public_key":self.original.person}, status=201)[0]
        self.request = self.b.api("POST", "/v2/link/requests", {"mode":"new", "network_id":self.network["id"],
            "person_public_key":self.original.person, "migration_proposal_id":"-", "contact_invitation":intro["invitation"],
            "helpers":[]}, status=201)[0]
        self.request_route = "/v2/link/requests/"+self.request["request_id"]
        require(not self.request["selection_approved"] and not self.request["commit_approved"] and
            self.request["host_public_key"] == self.b.identity["public_key"], "fixture request fabricated consent or another host")
        terms = {"code":self.request["display_code"], "network_id":self.network["id"], "person_public_key":self.original.person,
            "provider_id":self.original.person, "signature_format":"sshsig", "scopes":7, "not_after":self.creator.at(14400),
            "expected_host_public_key":self.request["host_public_key"], "expected_device_public_key":self.request["device_public_key"],
            "approve":True}
        ready = self.a.api("POST", "/v2/link/approvals", terms)[0]
        self.finish_owner(ready, "owner_packet_base64")
        owner = self.learn("B", "owner_offer_id")
        selection = {key:owner[key] for key in ("owner_offer_id", "network_id", "context_id", "person_public_key", "host_public_key", "device_public_key")}
        chosen = self.b.api("POST", self.request_route+"/selection", dict(selection, approve=True))[0]["request"]
        require(chosen["selection_approved"] and not chosen["commit_approved"], "fixture selection supplied final consent")
        time.sleep(2.05)
        admin = {key:terms[key] for key in ("code", "network_id", "person_public_key", "expected_host_public_key", "expected_device_public_key")}
        admin.update(provider_id="network_root", signature_format="ed25519", owner_offer_id=chosen["owner_offer_id"],
            selection_id=chosen["selection_id"], approve=True)
        granted = self.a.api("POST", "/v2/link/admissions", admin)[0]
        require(granted["signing_requests"] == [], "owned root fixture asked for an unowned administrator signature")
        view = self.learn("B", "administrator_offer_id")
        final = {key:view[key] for key in ("network_id", "context_id", "person_public_key", "host_public_key", "device_public_key",
            "owner_offer_id", "selection_id", "administrator_offer_id")}
        ready = self.a.api("POST", self.request_route+"/finalization", dict(final, approve=True))[0]
        self.finish_owner(ready, "owner_finalization_packet_base64")
        view = self.learn("B", "owner_finalization_id")
        commit = {key:view[key] for key in ("network_id", "context_id", "person_public_key", "host_public_key", "device_public_key",
            "owner_offer_id", "selection_id", "administrator_offer_id", "owner_finalization_id")}
        linked = self.b.api("POST", self.request_route+"/commit", dict(commit, approve=True), timeout=40)[0]["request"]
        require(linked["selection_approved"] and linked["commit_approved"] and linked["state"] == "linked",
            "fixture sibling did not actually complete separate final consent and local adoption")
        self.learn("A", "activation_id")
        applied = [row for row in sqlite_rows(self.a.host, "dec_operations", "request_id,locally_applied")
            if row[0] == self.request["request_id"]]
        require(applied == [(self.request["request_id"], 1)], "fixture approver has not actually applied the complete sibling operation")
        self.views = {label:suite.api("GET", self.route)[0] for label, suite in self.hosts.items()}
        require(self.views["B"]["provider"]["kind"] == "device" and self.views["B"]["person_public_key"] == self.original.person and
            self.views["B"]["provider"]["device_public_key"] == self.request["device_public_key"] and
            self.views["B"]["provider"]["scopes"] == 7 and self.views["B"]["authority"]["state"] == "usable",
            "fixture sibling lacks actual current selected scope7 device authority")
        for label, suite in self.hosts.items():
            # Exact public transport pin only; no grant or authority is added.
            other = self.hosts["B" if label == "A" else "A"]
            suite.api("POST", "/v1/peers", {"id":other.identity["id"], "public_key":other.identity["public_key"],
                "address":"127.0.0.1:"+str(self.dead_sockets[0 if label == "B" else 1].getsockname()[1])})
        self.original_file_hash = sha(self.original.path.read_bytes())
        self.trace.append({"uncounted_actual_sibling_setup":True, "network_id":self.network["id"],
            "context_id":self.network["context_id"], "request_id":self.request["request_id"], "actual_hosts":[self.a.identity, self.b.identity],
            "separate_selection_and_commit":True, "B_actual_selected_device":linked["device_public_key"],
            "original_only_on_A":True, "new_daemons_have_no_original_signer":True})

    def cli(self, label, *arguments):
        self.cli_count += 1; suite = self.hosts[label]
        argv = [str(self.args.host), "--state", str(suite.host.state), *arguments]
        began = time.monotonic()
        result = subprocess.run(argv, capture_output=True, env=suite.host.environment, timeout=40)
        prefix = self.root/("native-%03d" % self.cli_count)
        for suffix, data in (("stdout", result.stdout), ("stderr", result.stderr)):
            path = prefix.with_suffix("."+suffix); path.write_bytes(data); path.chmod(0o600)
        prefix.with_suffix(".meta.json").write_bytes(raw_json({"label":label, "argv":argv, "exit":result.returncode,
            "seconds":round(time.monotonic()-began, 3), "stdout_sha256":sha(result.stdout), "stderr_sha256":sha(result.stderr)}))
        require(result.returncode == 0 and result.stdout.strip(), "native fixture operation failed; see protected captures")
        return strict_output(result.stdout)

    def current(self, label):
        value = self.hosts[label].api("GET", self.route+"/policy/"+quote(self.original.person, safe=""))[0]
        require(set(value) == {"statement_id", "statement_base64"}, "current policy wrapper differs")
        statement = strict_output(unb64(value["statement_base64"]))
        require(statement_id(statement) == value["statement_id"], "current policy exact envelope/ID differs")
        payload = strict_output(unb64(statement["payload_base64"]))
        body = strict_output(unb64(payload["body_base64"]))
        self.verify_policy(statement)
        return value["statement_id"], statement, payload, body

    def verify_policy(self, statement):
        payload = strict_output(unb64(statement["payload_base64"]))
        require(statement["kind"] == "policy" and statement["context_id"] == self.network["context_id"] and
            payload["issuer"]["person_public_key"] == self.original.person and len(statement["signatures"]) == 1,
            "actual policy changed kind/context/owner/signature count")
        signature = statement["signatures"][0]
        original = payload["issuer"]["kind"] == "person"
        require(payload["issuer"]["kind"] in {"person", "device"} and signature["role"] == "issuer" and
            signature["public_key"] == (self.original.person if original else self.request["device_public_key"]) and
            signature["format"] == ("sshsig" if original else "ed25519"), "actual policy has another issuer key/role/format")
        message = lines("peerspan-decentralized-signature-v1", statement_id(statement), "issuer", signature["public_key"])
        if not original:
            self.a.verify_raw(signature["public_key"], message, signature["signature"])
            return
        directory = self.original.directory
        allowed, signed = directory/"public-allowed-signers", directory/"public-policy-verify.sig"
        allowed.write_text("fixture "+" ".join(self.original.path.with_suffix(".pub").read_text().split()[:2])+"\n")
        signed.write_text("-----BEGIN SSH SIGNATURE-----\n"+"\n".join(textwrap.wrap(signature["signature"], 70))+"\n-----END SSH SIGNATURE-----\n")
        allowed.chmod(0o600); signed.chmod(0o600)
        result = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", "fixture", "-n",
            "peerspan-person-v1", "-s", str(signed)], input=message, capture_output=True, timeout=10)
        require(result.returncode == 0, "actual native/original policy signature does not independently verify")

    def versions(self, label):
        value = self.hosts[label].api("GET", self.route+"/access-versions")[0]
        rows = [row for row in value["policies"] if row["person_public_key"] == self.original.person]
        require(len(rows) == 1, "actual retained policy maximum is missing or duplicated")
        return rows[0]

    def wire(self, target, sender, method, path, body=None, *, status=200, timeout=40):
        self.wire_count += 1
        argv = [str(self.args.probe), "--address", self.addresses[target], "--alpn", "peerspan-peer/1",
            "--state", str(self.hosts[sender].host.state), "--method", method, "--path", path]
        data = None if body is None else raw_json(body)
        if data is not None:
            argv.append("--body-stdin")
        result = subprocess.run(argv, input=data, capture_output=True, env=self.hosts[sender].host.environment, timeout=timeout)
        prefix = self.receipts/("%03d" % self.wire_count)
        for suffix, raw in (("stdout", result.stdout), ("stderr", result.stderr), ("request", data or b"")):
            saved = prefix.with_suffix("."+suffix); saved.write_bytes(raw); saved.chmod(0o600)
        prefix.with_suffix(".meta.json").write_bytes(raw_json({"target":target, "sender":sender, "method":method,
            "path":path, "exit":result.returncode, "expected_status":status, "request_sha256":None if data is None else sha(data),
            "stdout_sha256":sha(result.stdout), "stderr_sha256":sha(result.stderr), "actual_client_state":True,
            "raw_probe_does_not_check_server_pin":True}))
        require(result.returncode == 0, "public member wire exchange failed before HTTP; see protected wire captures")
        value = strict_output(result.stdout)
        require(set(value) == {"status", "body"} and type(value["status"]) is int and value["status"] == status,
            "public wire HTTP status/body differs; see protected wire captures")
        return value["body"]

    def import_from(self, target, sender):
        catalog = self.hosts[sender].api("GET", self.route+"/catalog")[0]
        result = self.wire(target, sender, "POST", "/peer/v2/networks/"+self.network["id"]+"/catalog", catalog)
        require(type(result) is dict and set(result) == {"catalog"}, "catalog union returned another public shape")
        expected = {row["id"]:row for row in catalog["catalog"]["objects"]}
        actual = {row["id"]:row for row in result["catalog"]["objects"]}
        require(expected.items() <= actual.items(), "catalog union omitted or rewrote exact signed proof bytes")
        return result

    def edit_rows(self, label):
        result = {}
        for network, person, seq, raw in sqlite_rows(self.hosts[label].host, "policy_edits", "network_id,person_id,seq,record"):
            if network != self.network["id"]:
                continue
            value = strict_output(raw.encode())
            require(set(value) == EDIT_FIELDS and value["format"] == 2 and value["mode"] == "decentralized" and
                value["context_id"] == self.network["context_id"] and value["seq"] == seq,
                "actual tagged edit row schema/context/sequence differs")
            require(seq not in result, "duplicate owner-local edit sequence")
            result[seq] = {"record":value, "raw_sha256":sha(raw.encode()), "person_id":person}
        return result

    def reference(self, reference, label="A"):
        require(set(reference) == REFERENCE_FIELDS and reference["statement_id"].startswith("ds_") and
            reference["proof_id"].startswith("dp_"), "frozen policy reference schema differs")
        statement = strict_output(unb64(reference["statement_base64"]))
        payload = strict_output(unb64(statement["payload_base64"]))
        require(statement["kind"] == "policy" and statement["context_id"] == self.network["context_id"] and
            statement_id(statement) == reference["statement_id"] and payload["body_base64"] == reference["body_base64"],
            "frozen reference does not carry exact original envelope/body")
        self.verify_policy(statement)
        sources = [(kind, raw) for network, context, proof, kind, raw in sqlite_rows(self.hosts[label].host,
            "dec_objects", "network_id,context_id,proof_id,kind,body") if network == self.network["id"] and
            context == self.network["context_id"] and proof == reference["proof_id"]]
        require(len(sources) == 1 and sources[0][0] == "policy" and sources[0][1] == unb64(reference["statement_base64"]),
            "ordinary fixture reference substituted/missed its exact original standalone proof container")
        require(reference["proof_id"] == "dp_"+sha(lines("peerspan-decentralized-proof-v1", "policy", sha(sources[0][1]))),
            "frozen ordinary proof ID differs from exact retained source bytes")
        admitted = [strict_output(raw.encode()) for network, context, identifier, raw in sqlite_rows(self.hosts[label].host,
            "dec_admissions", "network_id,context_id,statement_id,record") if network == self.network["id"] and
            context == self.network["context_id"] and identifier == reference["statement_id"]]
        require(len(admitted) == 1 and admitted[0]["kind"] == "policy" and admitted[0]["proof_id"] == reference["proof_id"],
            "frozen exact policy reference lacks its actual admitted source provenance")
        return payload, strict_output(unb64(reference["body_base64"]))

    def reserve(self, label="A"):
        value = self.hosts[label].api("POST", self.route+"/policy-edits", {"provider_id":self.original.person})[0]
        require(set(value) == {"context_id", "person_public_key", "policy", "version", "seq", "created_at", "expires_at"} and
            value["context_id"] == self.network["context_id"] and value["person_public_key"] == self.original.person,
            "actual reservation shape/context/person differs")
        return value

    def narrow_optional_admin(self):
        """A real short admin8 ceiling must not shorten an unrelated owner1 path."""
        persons = self.a.api("GET", self.route+"/persons")[0]
        identifier, old = self.creator.original_objects["admin_lease"]
        payload = copy.deepcopy(old)
        self.short_admin_deadline = self.creator.at(90)
        payload.update(sequence=2, predecessors=[identifier], resolves=[], issued_at=self.creator.at(0),
            not_before=self.creator.at(0), not_after=self.short_admin_deadline, retained_statement_ids=[])
        value = self.a.api("POST", self.route+"/actions", {"kind":"admin_lease", "provider_id":"network_root",
            "signature_format":"ed25519", "payload_base64":b64(raw_json(payload)), "approve":True})[0]
        require(set(value) == ACTION_FIELDS and value["committed"] and value["signing_requests"] == [],
            "fixture root did not actually apply its separately reviewed short administrator lease")
        statement = strict_output(unb64(value["statement_base64"]))
        require(statement["kind"] == "admin_lease" and statement["payload_base64"] == b64(raw_json(payload)) and
            self.a.api("GET", self.route+"/persons")[0] == persons,
            "short admin fixture changed the independent original person authority")
        self.trace.append({"uncounted_short_admin8_deadline":self.short_admin_deadline,
            "independently_current_person_unchanged":True})

    def original_payload(self, label, body, *, predecessors, resolves=()):
        versions = self.versions(label)
        require(versions["version"] < 2**64-1, "fixture policy maximum is exhausted")
        persons = self.hosts[label].api("GET", self.route+"/persons")[0]["persons"]
        current = [row for row in persons if row["person_public_key"] == self.original.person]
        require(len(current) == 1, "fixture lacks an independently current original person lease")
        issued = self.creator.clock.read_text(); until = min(self.creator.at(7200), current[0]["not_after"])
        body = copy.deepcopy(body)
        body.update(version=versions["version"]+1, issued_at=issued, valid_until=until)
        return {"root_state_id":self.network["root_state_id"], "operation_id":"-", "sequence":body["version"],
            "predecessors":sorted(predecessors), "resolves":sorted(resolves),
            "issuer":{"kind":"person", "person_public_key":self.original.person},
            "parents":[{"role":"issuer_person", "id":current[0]["person_lease_id"]}],
            "issued_at":issued, "not_before":issued, "not_after":until, "body_base64":b64(raw_json(body))}

    def action(self, label, payload, *, approve=True, status=200, claim=None):
        body = {"provider_id":self.original.person, "signature_format":"sshsig", "payload_base64":b64(raw_json(payload)), "approve":approve}
        suffix = "/policy-claims" if claim else "/actions"
        body.update({"capability":claim} if claim else {"kind":"policy"})
        value = self.hosts[label].api("POST", self.route+suffix, body, status=status)[0]
        if status == 200:
            require(set(value) == ACTION_FIELDS and not value["committed"], "unsigned fixture action shape/applied marker differs")
        return value

    def apply_original(self, label, payload):
        ready = self.action(label, payload)
        slots = ready["signing_requests"]
        require(len(slots) == 1, "actual external policy action lacks one ready original slot")
        result = self.hosts[label].api("POST", self.route+"/actions/"+ready["action_id"]+"/signed", {
            "intent_id":slots[0]["intent_id"], "signatures":[self.original_slot(slots[0], payload=payload)]})[0]
        require(set(result) == ACTION_FIELDS and result["committed"] and result["action_id"] == ready["action_id"],
            "actual original policy action did not commit its fixed payload")
        statement = strict_output(unb64(result["statement_base64"]))
        require(statement["payload_base64"] == b64(raw_json(payload)), "external action applied another payload")
        return result

    def resolve_branch(self, label, branch):
        before = self.edit_rows(label)
        versions = self.versions(label); heads = versions["head_ids"]
        require(len(heads) == 2 and branch[0] in heads, "fixture does not have exactly its two real sibling heads")
        payload = self.original_payload(label, branch[3], predecessors=heads, resolves=heads)
        chosen = strict_output(unb64(payload["body_base64"]))
        require({k:v for k,v in chosen.items() if k not in {"version", "issued_at", "valid_until"}} ==
            {k:v for k,v in branch[3].items() if k not in {"version", "issued_at", "valid_until"}},
            "explicit resolver did not select exact entire admitted branch content/edits")
        result = self.apply_original(label, payload)
        after = self.edit_rows(label)
        require(set(before) == set(after), "all-head recovery consumed a new edit reservation or erased history")
        for seq, old in before.items():
            new = after[seq]["record"]; prior = old["record"]
            for field in ("start", "signed", "signed_version", "signed_at", "dropped", "reserved_at"):
                require(new[field] == prior[field], "resolver rewrote frozen edit field "+field)
            if prior["state"] == "reserved":
                require(new == prior, "resolver fabricated a signed state for a never-signed reservation")
            if prior["state"] == "closed":
                require(new == prior, "resolver resurrected a closed edit")
        require(self.versions(label)["head_ids"] == [statement_id(strict_output(unb64(result["statement_base64"])))],
            "all-head resolver did not establish its exact unique policy head")
        return result

    def pure_snapshot(self, label):
        network = self.hosts[label].api("GET", self.route)[0]
        return {"databases":all_database_snapshots(self.hosts[label].host.state),
            "clock_rows":sqlite_rows(self.hosts[label].host, "dec_clock", "network_id,record"),
            "original_key_sha256":sha(self.original.path.read_bytes()),
            "selected_provider":network["provider"], "actual_provider_state":network["provider_state"]}

    def catalog_proofs(self, label):
        value = self.hosts[label].api("GET", self.route+"/catalog")[0]["catalog"]
        require(value["context_id"] == self.network["context_id"] and value["format"] == 1,
            "fixture catalog changed context/format")
        result = {}
        for entry in value["objects"]:
            raw = unb64(entry["body_base64"])
            require(entry["id"] == "dp_"+sha(lines("peerspan-decentralized-proof-v1", entry["kind"], sha(raw))) and
                entry["id"] not in result, "fixture catalog proof IDs are forged/duplicated")
            result[entry["id"]] = (entry["kind"], sha(raw))
        return result

    def outboxes(self, label):
        return {identifier:{"target":target, "record":strict_output(raw.encode())} for identifier, network, target, raw in
            sqlite_rows(self.hosts[label].host, "dec_outbox", "delivery_id,network_id,target_key,record")
            if network == self.network["id"]}

    def other_authority(self, label):
        """Exclude only expected policy ingestion and transport bookkeeping."""
        host = self.hosts[label].host
        snapshots = all_database_snapshots(host.state)
        # policy_edits is compared separately by edit_transitions(): learning
        # a head that reflects a live signed sibling edit may settle it.
        tables = {"dec_contexts", "dec_restrictions", "dec_signers", "dec_operations", "link_device_keys", "dec_intents", "dec_clock"}
        result = {database:{name:value for name,value in snapshot["tables"].items() if name in tables}
            for database,snapshot in snapshots["databases"].items()}
        # Hash-only root custody; no actual key or store is exported/copied.
        result["owned_root_seed_hashes"] = [None if row[0] is None else sha(row[0]) for row in sqlite_rows(host, "networks", "root_seed")]
        result["original_key_sha256"] = sha(self.original.path.read_bytes())
        result["nonpolicy_heads"] = sha(raw_json([row for row in sqlite_rows(host, "dec_heads",
            "network_id,context_id,stream_kind,subject,subject2,record") if row[2] != "policy"]))
        result["nonpolicy_maxima"] = sha(raw_json([row for row in sqlite_rows(host, "dec_highwater",
            "network_id,context_id,stream_kind,subject,subject2,version,record") if row[2] != "policy"]))
        result["nonpolicy_admissions"] = sha(raw_json([row for row in sqlite_rows(host, "dec_admissions",
            "network_id,context_id,statement_id,record") if strict_output(row[3].encode()).get("kind") != "policy"]))
        return result

    def edit_transitions(self, label, before, head_body):
        """Frozen edit history is immutable; only reflected intent may settle.

        Policy-edit contract: live signed rows not reflected by a unique
        current policy are unsettled, while reflected intent may settle with
        its original frozen references and drops preserved. Nothing else may
        change during publication.
        """
        after = self.edit_rows(label)
        require(set(after) == set(before), "publication added or erased an owner-local edit row")
        reflected = {row["seq"] for row in head_body["edits"] if row["host"] == self.hosts[label].identity["id"]}
        settled = []
        for seq, old in before.items():
            prior, new = old["record"], after[seq]["record"]
            if new == prior:
                continue
            require(prior["state"] == "unsettled" and new["state"] == "settled" and seq in reflected and
                new["unsettled_at"] == "-" and new["closed_at"] == "-" and
                all(new[field] == prior[field] for field in ("format", "mode", "context_id", "seq", "start", "signed",
                    "signed_version", "signed_at", "reserved_at", "dropped", "dropped_at")),
                "publication changed frozen private edit history beyond settling reflected intent")
            settled.append(seq)
        return settled

    def quiesce_deliveries(self):
        """Acknowledge actual original publications after the explicit resolver.

        This supplies a causal fixture boundary for strict subsequent purity
        checks. No read/refusal assertion ignores or excuses outbox changes.
        """
        head = self.current("A")[0]
        expected = self.catalog_proofs("A")
        for identifier, value in self.catalog_proofs("B").items():
            require(identifier not in expected or expected[identifier] == value, "siblings disagree on original proof bytes")
            expected[identifier] = value
        before = {label:self.other_authority(label) for label in self.hosts}
        edits = {label:self.edit_rows(label) for label in self.hosts}
        original = {label:self.outboxes(label) for label in self.hosts}
        for label, suite in self.hosts.items():
            other = "B" if label == "A" else "A"
            suite.api("POST", "/v1/peers", {"id":self.hosts[other].identity["id"],
                "public_key":self.hosts[other].identity["public_key"], "address":self.addresses[other]})
        # Existing public maximum retry delay60s + scheduling2s + one bounded
        # connection/publication30s. Poll actual progress; never sleep blindly
        # and never rewrite next_attempt_at/ack/consent/private rows.
        until = time.monotonic()+95
        for label, suite in self.hosts.items():
            result = suite.api("POST", self.route+"/sync", {}, timeout=40)[0]
            other = self.hosts["B" if label == "A" else "A"].identity["public_key"]
            require(set(result) == {"network", "attempted", "learned_proof_ids", "unavailable"} and other in result["attempted"] and
                not any(row["host_public_key"] == other for row in result["unavailable"]),
                "fixture did not actually exchange current proofs at its restored independently pinned peer")
        while True:
            pending = {label:self.outboxes(label) for label in self.hosts}
            for label, rows in pending.items():
                for identifier, old in original[label].items():
                    if identifier in rows:
                        require(rows[identifier]["target"] == old["target"] and all(rows[identifier]["record"][field] == old["record"][field]
                            for field in ("format", "kind", "body_base64", "proof_ids", "created_at")),
                            "pending publication changed its original exact payload/proof obligations")
            if not any(pending.values()):
                break
            require(time.monotonic() < until, "fixture did not observe acknowledged outbox retirement within existing retry/publication budget")
            time.sleep(.1)
        settled = {}
        for label in self.hosts:
            require(self.catalog_proofs(label) == expected and self.current(label)[0] == head,
                "fixture publication did not preserve exact union or a device worker produced unexpected new policy authority")
            require(self.other_authority(label) == before[label],
                "publication changed non-policy authority, provider/key/intent or private signer/operation state")
            settled[label] = self.edit_transitions(label, edits[label], self.current(label)[3])
            remote = self.catalog_proofs("B" if label == "A" else "A")
            for delivery in original[label].values():
                require(all(proof in remote and remote[proof] == expected[proof] for proof in delivery["record"]["proof_ids"]),
                    "retired original delivery lacks its exact acknowledged proof bytes on the actual peer")
        self.trace.append({"quiescent_actual_publications":True, "head_id":head,
            "retired_original_delivery_ids":{label:sorted(rows) for label,rows in original.items()},
            "exact_original_proof_ids":sorted(expected), "both_current_heads_exact":True,
            "other_authority_and_owned_keys_unchanged":True, "frozen_edit_history_unchanged":True,
            "reflected_unsettled_edits_settled":settled,
            "unexpected_B_device_worker_authority_would_refuse_fixture":True})

    def close(self):
        first = None
        for suite in self.hosts.values():
            try:
                suite.host.stop()
            except BaseException as error:
                first = first or error
        for reserved in self.dead_sockets:
            reserved.close()
        if first:
            raise first
