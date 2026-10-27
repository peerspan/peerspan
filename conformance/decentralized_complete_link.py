#!/usr/bin/env python3
"""Independent explicit-consent DEC linking and participant outcome acceptance.

Only merged public contracts and our own fixtures are used. Real owner and
requester daemons keep their host/device keys; the fixture signs only its own
original Alice's exact typed authority slots. This functional slice does not
claim the separately reviewed approval/signature/frame crash boundaries.
"""

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import timedelta
import json
from pathlib import Path
import socket
import sqlite3
import time

from decentralized_direct_carrier import CarrierWire
from decentralized_fixtures import FixtureKeys, b64, lines, raw_json, sha, unb64
from decentralized_helper import ClientIdentity
from decentralized_owner_preview import REVIEW, OwnerPreview, authority_rows, create
from decentralized_requester import VIEW
from decentralized_runtime import NETWORK_FIELDS, SLOT_FIELDS
from decentralized_storage import require
from decentralized_vectors import strict_output


PIN = "7c5a483aa01d87a5d3715bc8fef902f4839ba214"
PACKET_FIELDS = set("format context_id request_id role writer_host_public_key signer_public_key "
    "person_public_key issuer_id payload_base64 host_signature device_signature authority_signature_format authority_signature".split())
STATEMENT_FIELDS = {"format", "kind", "context_id", "payload_base64", "signatures"}


def table_rows(host, table: str, columns: str, predicate: str = "", values=()) -> list[tuple]:
    """Read a named normative DEC table in actual discovered fixture databases."""
    # SQLite transaction contexts do not close connections. Finish each cursor
    # and transaction, then close before the next raw magic-byte probe:
    # https://docs.python.org/3.12/library/sqlite3.html#how-to-use-the-connection-context-manager
    # https://www.sqlite.org/howtocorrupt.html#_posix_advisory_locks_canceled_by_a_separate_thread_doing_close_
    rows = []
    for path in host.state.rglob("*"):
        if not path.is_file():
            continue
        with path.open("rb") as stream:
            if stream.read(16) != b"SQLite format 3\x00":
                continue
        with closing(sqlite3.connect("file:"+str(path)+"?mode=ro", uri=True)) as db, db, closing(db.cursor()) as cursor:
            if cursor.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                rows.extend(cursor.execute('SELECT '+columns+' FROM "'+table+'"'+predicate, values).fetchall())
    return rows


def packet_message(packet: dict) -> bytes:
    require(set(packet) == PACKET_FIELDS and packet["format"] == 1, "packet shape/format differs")
    return lines("peerspan-decentralized-packet-v1", packet["context_id"], packet["request_id"], packet["role"],
        packet["writer_host_public_key"], packet["signer_public_key"], packet["person_public_key"], packet["issuer_id"],
        packet["authority_signature_format"], sha(unb64(packet["payload_base64"])))


def statement_id(statement: dict) -> str:
    require(set(statement) == STATEMENT_FIELDS and statement["format"] == 1, "statement shape/format differs")
    return "ds_"+sha(lines("peerspan-decentralized-statement-v1", statement["kind"], statement["context_id"],
                           sha(unb64(statement["payload_base64"]))))


class CompleteLink(OwnerPreview):
    def __init__(self, owner_binary: Path, requester_binary: Path, root: Path, keys: FixtureKeys) -> None:
        super().__init__(owner_binary, root, keys)
        self.requester.host.binary = requester_binary
        self.signatures = {}
        self.fixed_slots = {}
        self.trace = []
        self.endpoints = {}
        for label, host in (("owner", self.owner.host), ("requester", self.requester.host)):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
                reserved.bind(("127.0.0.1", 0))
                address = "127.0.0.1:"+str(reserved.getsockname()[1])
            host.run_arguments = ["--bootstrap-listen", address]
            self.endpoints[label] = {"address": address}

    def pending(self, requester: bool = True) -> dict:
        if requester:
            return strict_output(self.requester.pending(self.request["request_id"])[0])
        value = self.owner_pending(authority_allowed=True)
        require(value is not None, "approver lost its exact pending operation")
        return value

    def wrapper(self, value: dict, stage: str) -> None:
        require(set(value) == {"request", "review", "signing_requests"} and set(value["request"]) == VIEW and
                set(value["review"]) == REVIEW and value["review"]["stage"] == stage,
                "approver wrapper/review/stage differs")
        review = value["review"]
        require(review["network_id"] == self.network["id"] and review["context_id"] == self.network["context_id"] and
                review["person_public_key"] == self.keys.public("alice") and
                review["host_public_key"] == self.request["host_public_key"] and
                review["device_public_key"] == self.request["device_public_key"] and
                review["scopes"] == self.terms["scopes"] and review["not_after"] == self.terms["not_after"],
                "approver review changed exact selected target/terms")

    def sign_slot(self, slot: dict, stage: str) -> dict:
        require(set(slot) == SLOT_FIELDS and slot["public_key"] == self.keys.public("alice") and
                slot["format"] == "sshsig" and type(slot["slot_id"]) is int and 0 < slot["slot_id"] < 2**64,
                "ceremony authority slot changed signer, format, index or fields")
        allowed = {"administrator": {"person_lease", "host_lease", "administrator_packet"},
                   "owner_finalization": {"binding_lease", "device_lease", "owner_finalization_packet"}}
        require(slot["object_type"] in allowed[stage], "stage exposed unrelated typed signing work")
        template = strict_output(unb64(slot["template_base64"]))
        if slot["object_type"].endswith("_packet"):
            message = packet_message(template)
            expected_role = "administrator" if stage == "administrator" else "owner_finalization"
            require(slot["role"] == "authority" and template["role"] == expected_role and
                    template["context_id"] == self.network["context_id"] and
                    template["request_id"] == self.request["request_id"] and
                    template["writer_host_public_key"] == self.owner.identity["public_key"] and
                    template["signer_public_key"] == template["person_public_key"] == self.keys.public("alice") and
                    template["issuer_id"] == template["authority_signature"] == template["device_signature"] == "-" and
                    template["authority_signature_format"] == "sshsig",
                    "packet slot changed authority role or exact writer/owner/request/context")
            object_id = "dpk_"+sha(message)
        else:
            object_id = statement_id(template)
            require(template["kind"] == slot["object_type"] and template["context_id"] == self.network["context_id"] and
                    slot["role"] == "issuer", "statement slot changed kind/context/issuer role")
            payload = strict_output(unb64(template["payload_base64"]))
            subject = payload["subject"]
            expected = {"person_public_key": self.keys.public("alice"), "host_public_key": "-",
                        "device_public_key": "-", "member": "-", "scopes": 0}
            if template["kind"] == "person_lease":
                expected["member"] = self.owner.member
            elif template["kind"] == "host_lease":
                expected.update(person_public_key="-", host_public_key=self.request["host_public_key"], member=self.owner.member)
            else:
                expected.update(host_public_key=self.request["host_public_key"], scopes=2)
                if template["kind"] == "device_lease":
                    expected.update(device_public_key=self.request["device_public_key"], scopes=self.terms["scopes"])
            require(subject == expected and payload["operation_id"] == self.request["request_id"] and
                    payload["root_state_id"] == self.network["root_state_id"] and
                    payload["issuer"] == {"kind": "person", "person_public_key": self.keys.public("alice")} and
                    payload["not_after"] <= self.terms["not_after"], "typed lease changed exact operation/issuer/subject/ceiling")
            issuer = [entry for entry in template["signatures"] if entry["role"] == "issuer"]
            require(issuer == [{"role": "issuer", "public_key": self.keys.public("alice"), "format": "sshsig", "signature": "-"}],
                    "lease template lacks exact unfilled original issuer slot")
            message = lines("peerspan-decentralized-signature-v1", object_id, "issuer", self.keys.public("alice"))
        require(slot["object_id"] == object_id and unb64(slot["message_base64"]) == message,
                "slot message/object ID differs from independent typed derivation")
        key = (slot["intent_id"], slot["slot_id"], slot["role"])
        fixed = (slot["template_base64"], slot["message_base64"])
        require(self.fixed_slots.get(key, fixed) == fixed, "ready typed template/message changed after being fixed")
        self.fixed_slots[key] = fixed
        signature = b64(self.keys.sshsig("alice", message))
        self.signatures[(object_id, slot["role"])] = signature
        return {"slot_id": slot["slot_id"], "role": slot["role"], "signature": signature}

    def finish(self, ready: dict, stage: str, packet_field: str) -> dict:
        for _ in range(8):
            if self.pending(False)[packet_field] != "-":
                return ready
            self.wrapper(ready, stage)
            slots = ready["signing_requests"]
            require(0 < len(slots) <= 16 and len({s["intent_id"] for s in slots}) == 1,
                    "approved stage lacks a bounded ready signature batch")
            ready, _ = self.owner.api("POST", self.request_route+"/signed", {
                "intent_id": slots[0]["intent_id"], "signatures": [self.sign_slot(s, stage) for s in slots]})
        raise RuntimeError("ceremony stage exceeded8 fixed dependency batches")

    def setup(self) -> None:
        a, b = self.owner, self.requester
        a.host.start(); a.identity = a.host.api("GET", "/v1/host")
        self.network, descriptor = create(a, "Independent complete consent")
        self.endpoints["owner"]["public_key"] = a.identity["public_key"]
        b.world.descriptor, b.world.context_id = descriptor, self.network["context_id"]
        b.host.start(); b.identity = b.host.api("GET", "/v1/host")
        self.endpoints["requester"]["public_key"] = b.identity["public_key"]
        intro, _ = a.api("POST", "/v2/networks/"+self.network["id"]+"/invitations", {
            "member": a.member, "expected_person_public_key": self.keys.public("alice")}, status=201)
        self.request, _ = b.api("POST", "/v2/link/requests", {"mode": "new", "network_id": self.network["id"],
            "person_public_key": self.keys.public("alice"), "migration_proposal_id": "-",
            "contact_invitation": intro["invitation"], "helpers": []}, status=201)
        b.decode_request(self.request)
        self.request_route = "/v2/link/requests/"+self.request["request_id"]
        self.terms = {"code": self.request["display_code"], "network_id": self.network["id"],
            "person_public_key": self.keys.public("alice"), "provider_id": self.keys.public("alice"),
            "signature_format": "sshsig", "scopes": 7,
            "not_after": (b.base+timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expected_host_public_key": self.request["host_public_key"],
            "expected_device_public_key": self.request["device_public_key"], "approve": False}
        # Existing owner/selection behavior is a required setup, not another
        # counted run of the previously accepted owner-slot/selection suite.
        case = a.case
        a.case = lambda name, f: f()
        try:
            self.owner_slots(self.terms, self.network, selection_only=True)
        finally:
            a.case = case
        self.signatures[(self.slot["object_id"], "authority")] = self.signature
        self.setup_trace = self.trace
        self.trace = []
        # Respect the shared successful-poll cache; do not create a new budget
        # by changing TLS keys or treating an immediate stale poll as authority.
        time.sleep(2.05)

    def operation(self, instance) -> tuple:
        rows = table_rows(instance.host, "dec_operations", "network_id,context_id,request_id,activation_id,manifest_id,record,locally_applied",
            " WHERE request_id=?", (self.request["request_id"],))
        require(len(rows) == 1, "participant lacks exactly one actual local outcome row")
        row = rows[0]
        require(row[:3] == (self.network["id"], self.network["context_id"], self.request["request_id"]) and row[6] == 1,
                "participant outcome tuple/applied marker differs")
        record = strict_output(row[5].encode())
        require(set(record) == {"format", "activation_base64", "catalog_base64", "outcome_packet_base64", "applied_at"} and
                record["format"] == 1, "participant record fields differ")
        return row

    def verify_packet(self, packet: dict) -> str:
        message = packet_message(packet)
        packet_id = "dpk_"+sha(message)
        self.owner.verify_raw(packet["writer_host_public_key"], message, packet["host_signature"])
        if packet["role"] in {"request", "selection", "commit"}:
            require(packet["signer_public_key"] == self.request["device_public_key"] and
                    packet["writer_host_public_key"] == self.request["host_public_key"] and
                    packet["authority_signature_format"] == packet["authority_signature"] == "-",
                    "requester packet changed possession roles")
            self.owner.verify_raw(packet["signer_public_key"], message, packet["device_signature"])
        elif packet["role"] == "outcome":
            require(all(packet[k] == "-" for k in ("signer_public_key", "person_public_key", "issuer_id",
                "device_signature", "authority_signature_format", "authority_signature")), "outcome invented authority")
        else:
            require(packet["writer_host_public_key"] == self.owner.identity["public_key"] and
                    packet["signer_public_key"] == packet["person_public_key"] == self.keys.public("alice") and
                    packet["authority_signature_format"] == "sshsig" and packet["issuer_id"] == packet["device_signature"] == "-" and
                    packet["authority_signature"] == self.signatures[(packet_id, "authority")],
                    "completed authority packet differs from exact fixture-owned typed signature")
        require(packet["request_id"] == self.request["request_id"] and
                packet["context_id"] == ("-" if packet["role"] == "request" else self.network["context_id"]),
                "packet changed immutable request/context")
        return packet_id

    def verify_complete(self, row: tuple, writer: str) -> dict:
        record = strict_output(row[5].encode())
        activation = strict_output(unb64(record["activation_base64"]))
        require(set(activation) == {"format", "context_id", "request", "owner", "selection", "administrator", "owner_finalization", "commit"} and
                activation["format"] == 1 and activation["context_id"] == self.network["context_id"], "complete activation fields differ")
        ids = {role: self.verify_packet(activation[role]) for role in
               ("request", "owner", "selection", "administrator", "owner_finalization", "commit")}
        commit = strict_output(unb64(activation["commit"]["payload_base64"]))
        require(set(commit) == {"manifest_base64", "binding_host_signature", "committed_at"}, "commit payload fields differ")
        manifest_bytes = unb64(commit["manifest_base64"]); manifest = strict_output(manifest_bytes)
        manifest_id = "dm_"+sha(lines("peerspan-decentralized-manifest-v1", sha(manifest_bytes)))
        require(set(manifest) == set("format context_id request_id request_packet_id owner_offer_id selection_id administrator_offer_id "
            "owner_finalization_id root_state_id person_lease_id host_lease_id binding_lease_id device_lease_id binding_proof_id "
            "device_proof_id ancestor_statement_ids proof_ids".split()) and manifest["format"] == 1 and
            manifest["context_id"] == self.network["context_id"] and manifest["request_id"] == self.request["request_id"] and
            manifest["root_state_id"] == self.network["root_state_id"], "manifest fields/context/root differ")
        for field, role in (("request_packet_id", "request"), ("owner_offer_id", "owner"), ("selection_id", "selection"),
                            ("administrator_offer_id", "administrator"), ("owner_finalization_id", "owner_finalization")):
            require(manifest[field] == ids[role], "manifest substituted an exact completed stage")
        activation_id = "da_"+sha(lines("peerspan-decentralized-activation-v1", self.network["context_id"],
            self.request["request_id"], manifest_id, ids["commit"]))
        require((row[3], row[4]) == (activation_id, manifest_id), "stored activation/manifest semantic IDs differ")
        catalog = strict_output(unb64(record["catalog_base64"]))
        require(set(catalog) == {"format", "context_id", "objects"} and catalog["format"] == 1 and
                catalog["context_id"] == self.network["context_id"], "complete catalog fields/context differ")
        proofs, statements = {}, {}
        for entry in catalog["objects"]:
            require(set(entry) == {"id", "kind", "body_base64"}, "complete catalog entry shape differs")
            original = unb64(entry["body_base64"])
            require(entry["id"] == "dp_"+sha(lines("peerspan-decentralized-proof-v1", entry["kind"], sha(original))),
                    "complete catalog exact proof ID differs")
            require(entry["id"] not in proofs, "complete catalog duplicated a proof ID")
            proofs[entry["id"]] = entry
            body = strict_output(original)
            if entry["kind"] == "activation":
                require(original == unb64(record["activation_base64"]), "minimal local completion unexpectedly includes another activation")
                continue
            ds = statement_id(body)
            require(body["kind"] == entry["kind"] and body["context_id"] == self.network["context_id"], "proof kind/context differs")
            statements[ds] = strict_output(unb64(body["payload_base64"]))
            for signature in body["signatures"]:
                message = lines("peerspan-decentralized-signature-v1", ds, signature["role"], signature["public_key"])
                if signature["format"] == "sshsig":
                    expected = self.signatures.get((ds, signature["role"]), self.owner.submitted.get((ds, signature["role"])))
                    require(signature["public_key"] == self.keys.public("alice") and signature["signature"] == expected,
                            "complete original-person signature differs from fixed external slot")
                else:
                    require(signature["format"] == "ed25519", "unknown complete raw signature format")
                    self.owner.verify_raw(signature["public_key"], message, signature["signature"])
        require(list(proofs) == sorted(proofs), "complete catalog proofs not sorted unique")
        require(manifest["proof_ids"] == sorted(set(manifest["proof_ids"])) and set(manifest["proof_ids"]) <= proofs.keys(),
                "manifest pins missing or duplicate original proof bodies")
        for field, kind in (("binding_proof_id", "binding_lease"), ("device_proof_id", "device_lease")):
            entry = proofs[manifest[field]]
            require(entry["kind"] == kind and statement_id(strict_output(unb64(entry["body_base64"]))) == manifest[kind+"_id"],
                    "manifest did not pin the exact external B/D body")
        binding = strict_output(unb64(proofs[manifest["binding_proof_id"]]["body_base64"]))
        require([s["signature"] for s in binding["signatures"] if s["role"] == "host"] == [commit["binding_host_signature"]],
                "complete binding does not contain the exact actual requester host consent")
        frontier = {manifest[k] for k in ("person_lease_id", "host_lease_id", "binding_lease_id", "device_lease_id")}
        closure = set()
        while frontier:
            current = frontier.pop()
            if current in closure:
                continue
            require(current in statements, "literal manifest ancestor body absent from exact supplied proofs")
            closure.add(current); payload = statements[current]
            refs = set(payload.get("predecessors", [])) | set(payload.get("resolves", [])) | set(payload.get("retained_statement_ids", []))
            refs |= {p["id"] for p in payload.get("parents", [])}
            refs |= set(payload.get("kept_statement_ids", []))
            for value in (payload.get("root_state_id", "-"), payload.get("ratifies", "-"), payload.get("target", {}).get("statement_id", "-")):
                if value != "-": refs.add(value)
            frontier |= refs-closure
        closure.remove(manifest["device_lease_id"])
        require(manifest["ancestor_statement_ids"] == sorted(closure), "manifest ancestor list differs from literal fixed point")
        outcome = strict_output(unb64(record["outcome_packet_base64"]))
        self.verify_packet(outcome)
        payload = strict_output(unb64(outcome["payload_base64"]))
        require(outcome["role"] == "outcome" and outcome["writer_host_public_key"] == writer and payload == {
            "context_id": self.network["context_id"], "request_id": self.request["request_id"], "manifest_id": manifest_id,
            "activation_id": activation_id, "activation_sha256": sha(unb64(record["activation_base64"])),
            "observed_root_state_id": self.network["root_state_id"], "applied_at": record["applied_at"]},
            "outcome is not the exact host-signed historical local application")
        return manifest

    def run(self) -> None:
        self.setup()
        a, b = self.owner, self.requester
        def administrator() -> None:
            state = self.pending()
            terms = {key: self.terms[key] for key in ("code", "network_id", "person_public_key", "provider_id", "signature_format",
                                                    "expected_host_public_key", "expected_device_public_key")}
            terms.update(owner_offer_id=state["owner_offer_id"], selection_id=state["selection_id"], approve=False)
            before = authority_rows(b)
            old_packet = self.pending(False)["administrator_packet_base64"]
            preview, _ = a.api("POST", "/v2/link/admissions", terms)
            self.wrapper(preview, "administrator")
            require(self.pending(False)["administrator_packet_base64"] == old_packet,
                    "administrator preview generated a new signed packet")
            ready, _ = a.api("POST", "/v2/link/admissions", dict(terms, approve=True))
            self.finish(ready, "administrator", "administrator_packet_base64")
            time.sleep(2.05)
            view, _ = b.api("POST", self.request_route+"/resume", {})
            require(set(view) == VIEW|{"display_code"} and view["administrator_offer_id"].startswith("dpk_") and
                    view["selection_approved"] and not view["commit_approved"] and view["activation_id"] == view["outcome_id"] == "-" and
                    b.api("GET", "/v2/networks")[0] == [] and authority_rows(b) == before,
                    "administrator evidence supplied final consent or admitted requester authority")
        a.case("complete_link/explicit_admin_grant_remains_pending_without_final_consent", administrator)

        def finalization() -> None:
            state = self.pending()
            terms = {key: state[key] for key in ("owner_offer_id", "selection_id", "administrator_offer_id")}
            terms.update(network_id=self.network["id"], context_id=self.network["context_id"], person_public_key=self.keys.public("alice"),
                         host_public_key=self.request["host_public_key"], device_public_key=self.request["device_public_key"], approve=False)
            before = authority_rows(b)
            old_packet = self.pending(False)["owner_finalization_packet_base64"]
            preview, _ = a.api("POST", self.request_route+"/finalization", terms)
            self.wrapper(preview, "owner_finalization")
            require(self.pending(False)["owner_finalization_packet_base64"] == old_packet,
                    "finalization preview generated a new signed packet")
            ready, _ = a.api("POST", self.request_route+"/finalization", dict(terms, approve=True))
            self.finish(ready, "owner_finalization", "owner_finalization_packet_base64")
            time.sleep(2.05)
            view, _ = b.api("POST", self.request_route+"/resume", {})
            require(view["owner_finalization_id"].startswith("dpk_") and view["selection_approved"] and not view["commit_approved"] and
                    view["activation_id"] == view["outcome_id"] == "-" and b.api("GET", "/v2/networks")[0] == [] and
                    authority_rows(b) == before, "owner finalization supplied requester consent/adoption")
            self.commit_terms = {key: view[key] for key in ("owner_offer_id", "selection_id", "administrator_offer_id", "owner_finalization_id",
                "network_id", "context_id", "person_public_key", "host_public_key", "device_public_key")}
        a.case("complete_link/explicit_owner_finalization_cannot_commit_for_requester", finalization)

        def preview_commit() -> None:
            before = self.pending(); authority = authority_rows(b)
            preview, _ = b.api("POST", self.request_route+"/commit", dict(self.commit_terms, approve=False))
            require(set(preview) == {"request", "review"} and set(preview["review"]) == REVIEW and
                    preview["review"]["stage"] == "commit" and not preview["request"]["commit_approved"] and
                    before["commit_packet_base64"] == self.pending()["commit_packet_base64"] == "-" and
                    authority_rows(b) == authority and b.api("GET", "/v2/networks")[0] == [],
                    "final default-no preview signed, committed or adopted")
            wrong = dict(self.commit_terms, host_public_key=self.keys.public("wrong-final-target"), approve=True)
            value, _ = b.api("POST", self.request_route+"/commit", wrong, status=400)
            b.error(value, "invalid")
            require(not self.pending()["commit_approved"] and self.pending()["commit_packet_base64"] == "-" and authority_rows(b) == authority,
                    "wrong final pin changed consent/signature/admission")
        a.case("complete_link/final_preview_and_wrong_target_never_grant_consent", preview_commit)

        def apply() -> None:
            # Final commit may include first publication under the runtime
            # contract's bounded 30s attempt; this is an owner-local reader bound.
            result, _ = b.api("POST", self.request_route+"/commit", dict(self.commit_terms, approve=True), timeout=40)
            require(set(result) == {"request", "review"}, "final commit response wrapper differs")
            view = result["request"]
            for _ in range(4):
                if view["state"] == "linked": break
                time.sleep(2.05)
                view, _ = b.api("POST", self.request_route+"/resume", {})
            require(set(view) == VIEW and view["state"] == "linked" and view["selection_approved"] and view["commit_approved"] and
                    view["completed"] == ["request_created", "owner_offered", "owner_selected", "administrator_offered", "owner_finalized", "commit_persisted", "locally_applied"],
                    "final consent did not produce exact durable local completed stages")
            self.requester_operation = self.operation(b)
            self.manifest = self.verify_complete(self.requester_operation, b.identity["public_key"])
            stored = self.pending(); secret, read_cap = b.pending(self.request["request_id"])[1:]
            require(secret is None and (read_cap is None or len(read_cap) == 32) and stored["terminal"] == "applied" and
                    stored["manifest_id"] == view["manifest_id"] == self.requester_operation[4] and
                    stored["activation_id"] == view["activation_id"] == self.requester_operation[3],
                    "application/outcome/secret retirement not represented atomically")
            network, _ = b.api("GET", "/v2/networks/"+self.network["id"])
            provider, _ = b.api("GET", "/v2/networks/"+self.network["id"]+"/provider")
            require(set(network) == NETWORK_FIELDS and network["host_public_key"] == self.request["host_public_key"] and
                    network["person_public_key"] == self.keys.public("alice") and network["context_id"] == self.network["context_id"] and
                    network["provider"] == provider and provider["kind"] == "device" and provider["device_public_key"] == self.request["device_public_key"] and
                    provider["lease_id"] == self.manifest["device_lease_id"] and provider["scopes"] == self.terms["scopes"] and
                    network["provider_state"]["state"] == "available" and network["authority"]["state"] == "usable",
                    "atomic requester adoption changed identity or selected an original/unavailable device")
            self.trace.append({"request_id": self.request["request_id"], "activation_id": view["activation_id"], "manifest_id": view["manifest_id"],
                "selected_device_lease_id": provider["lease_id"], "requester_local_apply_observed": True, "pairing_secret_retired": True,
                "independent_complete_signatures_manifest_and_outcome_verified": True})
        a.case("complete_link/explicit_final_consent_atomically_adopts_exact_owned_device", apply)

        def publish_participant() -> None:
            for _ in range(4):
                a.api("POST", self.request_route+"/resume", {})
                found = table_rows(a.host, "dec_operations", "request_id", " WHERE request_id=?", (self.request["request_id"],))
                if found: break
                time.sleep(2.05)
            self.owner_operation = self.operation(a)
            manifest = self.verify_complete(self.owner_operation, a.identity["public_key"])
            require(manifest == self.manifest and self.owner_operation[3:5] == self.requester_operation[3:5],
                    "actual owner participant received a different complete operation")
            members, _ = a.api("GET", "/v2/networks/"+self.network["id"]+"/members")
            target = [m for m in members["members"] if m["host_public_key"] == self.request["host_public_key"]]
            require(len(target) == 1 and target[0]["person_public_key"] == self.keys.public("alice") and
                    target[0]["binding_lease_id"] == self.manifest["binding_lease_id"] and
                    target[0]["device_lease_id"] == self.manifest["device_lease_id"], "real owner did not apply exact complete target membership")
            self.trace.append({"actual_owner_participant_local_apply_observed": True, "delivery_mechanism_not_inferred_from_requester_view": True})
        a.case("complete_link/actual_other_participant_applies_same_complete_operation", publish_participant)

        def historical_reopen() -> None:
            identities = {"owner": a.identity, "requester": b.identity}
            operations = {"owner": self.owner_operation, "requester": self.requester_operation}
            # Ordinary replication may still be bringing the other participant's
            # unrelated current proofs (e.g. its own policy/binding) into either
            # store. Converge explicitly first so the restart/retry comparison
            # observes only the restart and the historical retry.
            for _ in range(4):
                learned = []
                for instance in (b, a):
                    value, _ = instance.api("POST", "/v2/networks/"+self.network["id"]+"/sync", {}, timeout=40)
                    learned += value["learned_proof_ids"]
                if not learned:
                    break
            require(not learned, "participants did not converge on their ordinary current proofs before restart")
            before = {label: authority_rows(instance) for label, instance in (("owner", a), ("requester", b))}
            for label, instance in (("owner", a), ("requester", b)):
                instance.host.stop(); instance.host.start()
                require(instance.host.api("GET", "/v1/host") == identities[label], "restart replaced actual host identity")
                resumed, _ = instance.api("POST", self.request_route+"/resume", {})
                require(set(resumed) == VIEW and resumed["state"] == "linked" and resumed["activation_id"] == self.requester_operation[3] and
                        self.operation(instance) == operations[label] and authority_rows(instance) == before[label],
                        "completed restart/retry changed original outcome, public authority or identity")
            retry, _ = b.api("POST", self.request_route+"/commit", dict(self.commit_terms, approve=True))
            require(retry["request"]["activation_id"] == self.requester_operation[3] and self.operation(b) == self.requester_operation and
                    authority_rows(b) == before["requester"], "exact committed retry reapplied or changed its historical outcome")
        a.case("complete_link/either_restart_and_exact_retry_preserve_original_local_outcomes", historical_reopen)

        def isolated() -> None:
            observer = ClientIdentity(self.keys, "complete-link-nonparticipant")
            for label in ("owner", "requester"):
                wire = CarrierWire(self.endpoints[label])
                response = wire.request(observer, "GET", "/v1/host")
                error = strict_output(response.body)
                require(response.status == 404 and error["code"] == "not_found", "bootstrap exposed owner-local host router")
                response = wire.request(observer, "GET", "/bootstrap/v1/operations/"+self.request["request_id"])
                error = strict_output(response.body)
                require(response.status == 403 and error["code"] == "forbidden", "nonparticipant retrieved a private local operation outcome")
        a.case("complete_link/bootstrap_router_and_participant_outcome_auth_remain_isolated", isolated)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", type=Path, required=True)
    parser.add_argument("--requester", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args(); args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    keys = FixtureKeys(); suite = CompleteLink(args.owner.resolve(), args.requester.resolve(), args.work_dir.resolve(), keys)
    started, failure = time.monotonic(), None
    try:
        suite.run()
    except BaseException as error:
        failure = type(error).__name__
    finally:
        for label, instance in (("requester", suite.requester), ("owner", suite.owner)):
            try:
                instance.host.stop()
                logs = instance.host.log_path.read_bytes() if instance.host.log_path.exists() else b""
                require(not any(v and v in logs for v in suite.requester.sensitive), "host log exposed private pairing code/secret")
            except BaseException as error:
                suite.rows.append({"name": "cleanup/"+label, "passed": False, "error_type": type(error).__name__})
                failure = failure or type(error).__name__
        keys.close()
    result = {"contract_pin": PIN, "implementation_source_read": False,
        "suite_sha256": sha(Path(__file__).read_bytes()),
        "support_sha256": {name: sha(Path(__file__).with_name(name).read_bytes()) for name in (
            "decentralized_owner_preview.py", "decentralized_direct_carrier.py", "decentralized_fixtures.py", "decentralized_helper.py",
            "decentralized_storage.py", "decentralized_requester.py", "decentralized_runtime.py", "decentralized_vectors.py")},
        "owner": str(args.owner.resolve()), "owner_sha256": sha(args.owner.read_bytes()),
        "requester": str(args.requester.resolve()), "requester_sha256": sha(args.requester.read_bytes()),
        "rows": suite.rows, "trace": suite.trace, "failure": failure, "seconds": round(time.monotonic()-started, 3),
        "scope": "explicit API administrator/finalization/final requester consent, actual participant application, exact historical outcomes/reopen and isolated bootstrap; no phase-crash, CLI/up/data-path/relay/installed claim",
        "passed": failure is None and bool(suite.rows) and all(row["passed"] for row in suite.rows)}
    args.results.parent.mkdir(parents=True, exist_ok=True); args.results.write_text(json.dumps(result, indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
