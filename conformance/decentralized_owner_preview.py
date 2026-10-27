#!/usr/bin/env python3
"""Owner review and cached-code pin refusals, before packet signing readiness.

Only public contracts and our independent fixtures are used. Two real created
contexts make wrong-network rejection meaningful. Incoming transport may be
cached; no preview/mismatch may approve an intent, publish authority or grant
either requester consent. No packet slot, administrator or full-link claim.
"""

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import timedelta
import json
from pathlib import Path
import sqlite3
import time

from decentralized_fixtures import FixtureKeys, b64, lines, raw_json, sha, unb64
from decentralized_runtime import CreationSuite, SLOT_FIELDS
from decentralized_requester import Requester, VIEW
from decentralized_storage import require
from decentralized_vectors import strict_output


REVIEW = set("stage network_id context_id person_id person_public_key host_public_key device_public_key root_state_id provider "
    "owner_offer_id selection_id administrator_offer_id person_lease_id host_lease_id binding_lease_id device_lease_id scopes not_after authority_warning".split())


def create(owner: CreationSuite, name: str) -> tuple[dict, dict]:
    """Minimal public setup, without repeating the existing creation suite."""
    owner.name = name
    owner.preview, _ = owner.api("POST", "/v2/networks", {"name": name, "member": owner.member,
        "person_public_key": owner.keys.public("alice"), "approve": False})
    owner.creation_shape(owner.preview, False)
    route = "/v2/network-creations/"+owner.preview["creation_id"]
    ready, _ = owner.api("POST", route+"/approve", {"context_id": owner.context_id,
        "root_state_id": owner.preview["review"]["root_state_id"], "person_public_key": owner.keys.public("alice"),
        "host_public_key": owner.identity["public_key"], "approve": True})
    for _ in range(8):
        if ready["committed"]:
            return ready["network"], dict(owner.descriptor)
        slots = ready["signing_requests"]
        require(0 < len(slots) <= 16, "public creation setup lacks ready external original slots")
        ready, _ = owner.api("POST", route+"/signed", {"intent_id": slots[0]["intent_id"],
            "signatures": [owner.slot_signature(slot) for slot in slots]})
    raise RuntimeError("public creation setup exceeded fixed8 dependency batches")


def approved(owner: CreationSuite) -> list[str]:
    result = []
    for path in owner.host.state.rglob("*"):
        if not path.is_file():
            continue
        with path.open("rb") as stream:
            if stream.read(16) != b"SQLite format 3\x00":
                continue
        with closing(sqlite3.connect("file:"+str(path)+"?mode=ro", uri=True)) as db, db, closing(db.cursor()) as cursor:
            if not cursor.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='dec_intents'").fetchone():
                continue
            result += [row[0] for row in cursor.execute("SELECT intent_id,record FROM dec_intents") if strict_output(row[1].encode())["approved"]]
    return sorted(result)


def authority_rows(requester: Requester) -> str:
    """Hash only normative authoritative DEC rows, permitting proof caching."""
    tables = {"dec_contexts", "dec_admissions", "dec_restrictions", "dec_heads", "dec_highwater",
              "dec_signers", "dec_operations"}
    observed = {name: [] for name in tables}
    for path in requester.host.state.rglob("*"):
        if not path.is_file():
            continue
        with path.open("rb") as stream:
            if stream.read(16) != b"SQLite format 3\x00":
                continue
        with closing(sqlite3.connect("file:"+str(path)+"?mode=ro", uri=True)) as db, db, closing(db.cursor()) as cursor:
            present = {row[0] for row in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for name in sorted(tables & present):
                for row in cursor.execute('SELECT * FROM "'+name+'"'):
                    observed[name].append([{"blob": b64(cell)} if isinstance(cell, bytes) else cell for cell in row])
    return sha(raw_json({name: sorted(rows, key=raw_json) for name, rows in sorted(observed.items())}))


class OwnerPreview:
    def __init__(self, binary: Path, root: Path, keys: FixtureKeys) -> None:
        self.binary, self.root, self.keys = binary, root, keys
        a, b = root/"owner", root/"requester"
        a.mkdir(mode=0o700); b.mkdir(mode=0o700)
        self.owner = CreationSuite(binary, a, keys)
        self.requester = Requester(binary, b, keys)
        self.owner.host.environment.update(PEERSPAN_DEC_TEST_MODE="1",
            PEERSPAN_DEC_TEST_CLOCK_FILE=str(self.requester.clock))
        self.rows = self.owner.rows
        self.trace = []

    def unchanged(self) -> None:
        require(approved(self.owner) == self.before, "preview/wrong pin approved a new signing intent")
        record = self.owner_pending()
        if record is not None:
            require(record["owner_packet_base64"] == record["administrator_packet_base64"] ==
                    record["owner_finalization_packet_base64"] == "-" and
                    not record["selection_approved"] and not record["commit_approved"] and
                    not any(f["role"] in {"owner", "administrator", "owner_finalization", "commit"} for f in record["outbound_frames"]),
                    "preview/wrong pin signed or queued new authority/requester consent")
        read, _ = self.requester.api("GET", self.request_route)
        self.requester.view(read)

    def owner_pending(self, *, authority_allowed: bool = False):
        records = []
        for path in self.owner.host.state.rglob("*"):
            if not path.is_file():
                continue
            with path.open("rb") as stream:
                if stream.read(16) != b"SQLite format 3\x00":
                    continue
            with closing(sqlite3.connect("file:"+str(path)+"?mode=ro", uri=True)) as db, db, closing(db.cursor()) as cursor:
                if not authority_allowed and cursor.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='dec_frames'").fetchone():
                    require(not cursor.execute("SELECT 1 FROM dec_frames WHERE role IN ('owner','administrator','owner_finalization','commit')").fetchone(),
                            "preview/wrong pin persisted a new signed authority or final-consent frame")
                if cursor.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='dec_pending'").fetchone():
                    records += [strict_output(row[0].encode()) for row in cursor.execute(
                        "SELECT record FROM dec_pending WHERE request_id=?", (self.request["request_id"],))]
        require(len(records) <= 1, "cached approver request duplicated across observed databases")
        # Verified incoming caching is permitted, not required by a preview.
        return records[0] if records else None

    def owner_slots(self, terms: dict, first: dict, *, selection_only: bool = False) -> None:
        a, b = self.owner, self.requester
        route = "/v2/link/requests/"+self.request["request_id"]
        def approve() -> None:
            self.ready, _ = a.api("POST", "/v2/link/approvals", dict(terms, approve=True))
            require(set(self.ready) == {"request", "review", "signing_requests"} and
                    len(self.ready["signing_requests"]) == 1, "owner approval lacks its one ready authority packet slot")
            slot = self.ready["signing_requests"][0]
            require(set(slot) == SLOT_FIELDS and slot["object_type"] == "owner_offer_packet" and
                    slot["role"] == "authority" and slot["public_key"] == self.keys.public("alice") and
                    slot["format"] == "sshsig" and slot["intent_id"] in approved(a),
                    "owner slot role/key/format or durable approval differs")
            packet = strict_output(unb64(slot["template_base64"]))
            require(set(packet) == set("format context_id request_id role writer_host_public_key signer_public_key "
                "person_public_key issuer_id payload_base64 host_signature device_signature authority_signature_format authority_signature".split()) and
                packet["format"] == 1 and packet["role"] == "owner" and packet["context_id"] == first["context_id"] and
                packet["request_id"] == self.request["request_id"] and packet["writer_host_public_key"] == a.identity["public_key"] and
                packet["signer_public_key"] == packet["person_public_key"] == self.keys.public("alice") and
                packet["issuer_id"] == packet["device_signature"] == packet["authority_signature"] == "-" and
                packet["authority_signature_format"] == "sshsig", "owner template is not the exact fixed packet authority slot")
            payload = strict_output(unb64(packet["payload_base64"]))
            require(payload["request_packet_id"] == self.request["request_packet_id"] and payload["descriptor"]["network_id"] == first["id"] and
                    payload["root_state_id"] == first["root_state_id"] and payload["host_public_key"] == terms["expected_host_public_key"] and
                    payload["device_public_key"] == terms["expected_device_public_key"] and payload["scopes"] == terms["scopes"] and
                    payload["not_after"] == terms["not_after"], "owner template widened requested identity or terms")
            message = lines("peerspan-decentralized-packet-v1", packet["context_id"], packet["request_id"], packet["role"],
                packet["writer_host_public_key"], packet["signer_public_key"], packet["person_public_key"], packet["issuer_id"],
                packet["authority_signature_format"], sha(unb64(packet["payload_base64"])))
            require(unb64(slot["message_base64"]) == message and slot["object_id"] == "dpk_"+sha(message),
                    "owner typed slot signed a different message/semantic ID")
            self.slot, self.template, self.message = slot, packet, message
            self.fixed_owner = self.owner_pending(authority_allowed=True)
            require(self.fixed_owner is not None and self.fixed_owner["owner_packet_base64"] == "-" and
                    not self.fixed_owner["selection_approved"] and not self.fixed_owner["commit_approved"],
                    "approval completed owner packet or requester consent before external signature")
        if selection_only:
            approve()  # Minimal already-proven typed-slot setup, not a repeated case.
        else:
            a.case("owner_slots/approved_packet_has_exact_authority_role_and_independent_message", approve)
        self.signature = b64(self.keys.sshsig("alice", self.message))
        def wrong_role() -> None:
            value, _ = a.api("POST", route+"/signed", {"intent_id": self.slot["intent_id"],
                "signatures": [{"slot_id": self.slot["slot_id"], "role": "issuer", "signature": self.signature}]}, status=400)
            a.error(value, "invalid")
            require(self.owner_pending(authority_allowed=True) == self.fixed_owner,
                    "wrong packet slot role filled a signature or changed exact approval")
        if not selection_only:
            a.case("owner_slots/statement_issuer_role_cannot_fill_packet_authority", wrong_role)
        def sign() -> None:
            signed, _ = a.api("POST", route+"/signed", {"intent_id": self.slot["intent_id"],
                "signatures": [{"slot_id": self.slot["slot_id"], "role": "authority", "signature": self.signature}]})
            require(set(signed) == {"request", "review", "signing_requests"} and signed["signing_requests"] == [],
                    "filled owner signature still exposes unsigned owner work")
            record = self.owner_pending(authority_allowed=True)
            require(record is not None and record["owner_packet_base64"] != "-", "signed owner packet not durably retained")
            packet = strict_output(unb64(record["owner_packet_base64"]))
            fixed, observed = dict(self.template), dict(packet)
            for field in ("host_signature", "authority_signature"):
                fixed.pop(field); observed.pop(field)
            require(fixed == observed and packet["authority_signature"] == self.signature and
                    (self.template["host_signature"] == "-" or packet["host_signature"] == self.template["host_signature"]),
                    "external authority signature changed fixed packet or an existing host signature")
            a.verify_raw(packet["writer_host_public_key"], self.message, packet["host_signature"])
            learned, _ = b.api("POST", route+"/resume", {})
            require(set(learned) == VIEW|{"display_code"} and learned["owner_offer_id"] == self.slot["object_id"] and
                    not learned["selection_approved"] and not learned["commit_approved"] and
                    learned["selection_id"] == learned["activation_id"] == learned["outcome_id"] == "-",
                    "verified owner offer implicitly selected, committed or applied requester")
            require(b.api("GET", "/v2/networks")[0] == [], "owner offer alone adopted requester context")
        if selection_only:
            sign()  # Establish the exact live owner offer before the failed stage.
        else:
            a.case("owner_slots/exact_signed_offer_does_not_supply_requester_consent", sign)
        def select() -> None:
            before_authority = authority_rows(b)
            selection = {"owner_offer_id": self.slot["object_id"], "network_id": first["id"], "context_id": first["context_id"],
                "person_public_key": self.keys.public("alice"), "host_public_key": self.request["host_public_key"],
                "device_public_key": self.request["device_public_key"], "approve": False}
            preview, _ = b.api("POST", route+"/selection", selection)
            require(set(preview) == {"request", "review"} and preview["review"]["stage"] == "selection" and
                    not preview["request"]["selection_approved"] and not preview["request"]["commit_approved"],
                    "selection preview supplied requester consent")
            require(authority_rows(b) == before_authority,
                    "cold selection preview admitted authority, heads, maxima, provider or context")
            selected, _ = b.api("POST", route+"/selection", dict(selection, approve=True))
            request = selected["request"]
            require(set(selected) == {"request", "review"} and request["selection_approved"] and not request["commit_approved"] and
                    request["owner_offer_id"] == self.slot["object_id"] and request["selection_id"].startswith("dpk_") and
                    request["activation_id"] == request["outcome_id"] == "-" and b.api("GET", "/v2/networks")[0] == [],
                    "separate requester selection applied a full link or final consent")
            require(authority_rows(b) == before_authority,
                    "requester selection changed authoritative state before final consent/application")
            self.trace.append({"request_id": request["request_id"], "owner_offer_id": self.slot["object_id"],
                "selection_id": request["selection_id"], "selection_approved": True, "commit_approved": False,
                "packet_slot_role": "authority", "context_adopted": False})
        a.case("owner_slots/selection_preview_and_explicit_consent_remain_separate_from_commit", select)

    def run(self, *, slots_only: bool = False, selection_only: bool = False) -> None:
        a, b = self.owner, self.requester
        a.host.start(); a.identity = a.host.api("GET", "/v1/host")
        first, descriptor = create(a, "Independent owner review target")
        other = None
        if not (slots_only or selection_only):
            other, _ = create(a, "Independent different context")
        b.world.descriptor = descriptor; b.world.context_id = first["context_id"]
        b.host.start(); b.identity = b.host.api("GET", "/v1/host")
        intro, _ = a.api("POST", "/v2/networks/"+first["id"]+"/invitations",
            {"member": a.member, "expected_person_public_key": self.keys.public("alice")}, status=201)
        require(set(intro) == {"network_id", "context_id", "invitation_id", "invitation", "expires_at"} and
                intro["network_id"] == first["id"] and intro["context_id"] == first["context_id"],
                "minted introduction wrapper changed actual context")
        self.request, _ = b.api("POST", "/v2/link/requests", {"mode": "new", "network_id": first["id"],
            "person_public_key": self.keys.public("alice"), "migration_proposal_id": "-",
            "contact_invitation": intro["invitation"], "helpers": []}, status=201)
        b.decode_request(self.request)
        self.request_route = "/v2/link/requests/"+self.request["request_id"]
        self.before = approved(a)
        terms = {"code": self.request["display_code"], "network_id": first["id"],
            "person_public_key": self.keys.public("alice"), "provider_id": self.keys.public("alice"),
            "signature_format": "sshsig", "scopes": 7,
            "not_after": (b.base+timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expected_host_public_key": self.request["host_public_key"],
            "expected_device_public_key": self.request["device_public_key"], "approve": False}
        if slots_only or selection_only:
            self.owner_slots(terms, first, selection_only=selection_only)
            return
        def preview() -> None:
            value, _ = a.api("POST", "/v2/link/approvals", terms)
            require(set(value) == {"request", "review", "signing_requests"} and value["signing_requests"] == [] and
                    set(value["review"]) == REVIEW and set(value["request"]) == VIEW,
                    "owner preview wrapper/review/slots differ")
            review = value["review"]
            require(review["stage"] == "owner" and review["network_id"] == first["id"] and
                    review["context_id"] == first["context_id"] and review["person_public_key"] == self.keys.public("alice") and
                    review["host_public_key"] == terms["expected_host_public_key"] and review["device_public_key"] == terms["expected_device_public_key"] and
                    review["root_state_id"] == first["root_state_id"] and review["scopes"] == 7 and review["not_after"] == terms["not_after"] and
                    review["provider"]["kind"] == "original_person" and review["provider"]["person_public_key"] == self.keys.public("alice"),
                    "owner preview changed fixed context/target/provider/terms")
            self.unchanged()
        a.case("owner_preview/current_original_review_has_no_signature_or_approval", preview)
        def wrong_network() -> None:
            value, _ = a.api("POST", "/v2/link/approvals", dict(terms, network_id=other["id"], approve=True), status=400)
            a.error(value, "invalid"); self.unchanged()
        a.case("owner_preview/cached_code_wrong_known_network400_without_approval", wrong_network)
        def wrong_host() -> None:
            value, _ = a.api("POST", "/v2/link/approvals", dict(terms,
                expected_host_public_key=self.keys.public("not-request-target"), approve=True), status=400)
            a.error(value, "invalid"); self.unchanged()
        a.case("owner_preview/cached_code_wrong_target_host400_without_approval", wrong_host)
        self.trace.append({"request_id": self.request["request_id"], "actual_context": first["context_id"],
            "different_known_context": other["context_id"], "selection_approved": False, "commit_approved": False,
            "incoming_transport_cache_permitted": True, "new_packet_signature_or_authority_publication": False})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--slots-only", action="store_true")
    mode.add_argument("--selection-only", action="store_true", help="only the failed cold requester selection, with minimal approved-offer setup")
    args = parser.parse_args(); args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    keys = FixtureKeys(); suite = OwnerPreview(args.host.resolve(), args.work_dir.resolve(), keys)
    started, failure = time.monotonic(), None
    try:
        suite.run(slots_only=args.slots_only, selection_only=args.selection_only)
    except BaseException as error:
        failure = type(error).__name__
    finally:
        for name, instance in [("requester", suite.requester), ("owner", suite.owner)]:
            try:
                instance.host.stop()
                logs = instance.host.log_path.read_bytes() if instance.host.log_path.exists() else b""
                require(not any(v and v in logs for v in suite.requester.sensitive), "owner/requester log exposed private pairing code/secret")
            except BaseException as error:
                suite.rows.append({"name": "cleanup/"+name, "passed": False, "error_type": type(error).__name__})
                failure = failure or type(error).__name__
        keys.close()
    result = {"contract_pin": "7c5a483aa01d87a5d3715bc8fef902f4839ba214" if args.selection_only else
              "a5bdb84afb54f75c3870ca04f17e3223298b0769" if args.slots_only else "2f8ff787bc5364ac148b2564142f39707c87d1da", "implementation_source_read": False,
        "suite_sha256": sha(Path(__file__).read_bytes()), "host": str(args.host.resolve()), "host_sha256": sha(args.host.read_bytes()),
        "rows": suite.rows, "trace": suite.trace, "failure": failure, "seconds": round(time.monotonic()-started, 3),
        "scope": ("failed cold selection preview and explicit consent continuation only; no admission/provider/adoption/final commit" if args.selection_only else
                  "typed owner authority slot, exact offer and separate selection only; no admin/final commit/application authority claim" if args.slots_only else
                  "owner public preview and cached-code wrong network/host pins only; no packet slots, selection or complete link authority claim"),
        "passed": failure is None and all(r["passed"] for r in suite.rows)}
    args.results.parent.mkdir(parents=True, exist_ok=True); args.results.write_text(json.dumps(result, indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
