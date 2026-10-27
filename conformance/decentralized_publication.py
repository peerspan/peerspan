#!/usr/bin/env python3
"""Independent positive isolated complete-publication and historical retrieval.

One real original-owner/administrator daemon reviews a fixture-owned virtual
requester. Only that requester's keys are used by the raw TLS client. Its
complete commit first reaches the real participant via the isolated POST, not
via a commit mailbox frame. No daemon private key is copied or imported.
"""

from __future__ import annotations

import argparse
from datetime import timedelta
import json
import os
from pathlib import Path
import time

from decentralized_complete_link import CompleteLink, packet_message, statement_id, table_rows
from decentralized_direct_carrier import CarrierWire
from decentralized_fixtures import FixtureKeys, PublicObject, World, b64, lines, raw_json, sha, unb64
from decentralized_helper import ClientIdentity, Mailbox
from decentralized_owner_preview import authority_rows, create
from decentralized_requester import private_token
from decentralized_runtime import SLOT_FIELDS, moment
from decentralized_storage import require
from decentralized_vectors import strict_output


PIN = "7c5a483aa01d87a5d3715bc8fef902f4839ba214"
VHOST, VDEVICE = "isolated-publication-requester-host", "isolated-publication-requester-device"


def exact_object_field(payload: bytes, field: str) -> bytes:
    """Retain an actual nested typed object, byte-for-byte from signed payload.

    This supplies real candidate bytes for the new requester's manifest. It
    creates no admission row and never fabricates a normalized proof body.
    """
    decoded = strict_output(payload)
    require(isinstance(decoded[field], dict), "requested component is not a supplied typed envelope object")
    source, decoder, cursor = payload.decode("utf-8"), json.JSONDecoder(), 1
    while True:
        while source[cursor].isspace(): cursor += 1
        key, cursor = decoder.raw_decode(source, cursor)
        while source[cursor].isspace(): cursor += 1
        require(source[cursor] == ":", "signed object member lacks separator")
        cursor += 1
        while source[cursor].isspace(): cursor += 1
        start = cursor
        _, cursor = decoder.raw_decode(source, cursor)
        if key == field:
            original = source[start:cursor].encode("utf-8")
            require(strict_output(original) == decoded[field], "extracted original object changed signed component")
            return original
        while source[cursor].isspace(): cursor += 1
        require(source[cursor] == ",", "supplied signed object field not found")
        cursor += 1


class Publication(CompleteLink):
    def setup_virtual(self) -> None:
        a = self.owner
        a.host.start(); a.identity = a.host.api("GET", "/v1/host")
        self.network, descriptor = create(a, "Independent isolated publication")
        endpoint = dict(self.endpoints["owner"], public_key=a.identity["public_key"])
        self.wire = CarrierWire(endpoint)
        self.client = ClientIdentity(self.keys, VHOST)
        w = self.world = World(self.keys)
        w.descriptor, w.descriptor_bytes, w.context_id = descriptor, raw_json(descriptor), self.network["context_id"]
        created, expires = self.requester.at(0), self.requester.at(300)
        request_payload = {"mode": "new", "host_public_key": self.keys.public(VHOST),
            "device_public_key": self.keys.public(VDEVICE), "request_nonce": b64(os.urandom(32)),
            "expected_network_id": self.network["id"], "expected_context_id": self.network["context_id"],
            "expected_person_public_key": self.keys.public("alice"), "migration_proposal_id": "-",
            "renewed_device_lease_id": "-", "created_at": created, "expires_at": expires}
        request_id = "link_"+sha(lines("peerspan-decentralized-request-id-v1", sha(raw_json(request_payload))))
        request = w.packet("request", request_payload, request_id, writer=VHOST, signer=VDEVICE, context_id="-")
        self.request = {"request_id": request_id, "request_packet_id": request.packet_id,
                        "host_public_key": self.keys.public(VHOST), "device_public_key": self.keys.public(VDEVICE)}
        self.request_route = "/v2/link/requests/"+request_id
        self.request_packet = request
        box = self.box = object.__new__(Mailbox)
        box.keys, box.secret, box.request_id = self.keys, os.urandom(16), request_id
        box.created_at, box.expires_at = created, expires
        box.locator = sha(lines("peerspan-decentralized-locator-v1", b64(box.secret)))
        box.capability = sha(lines("peerspan-decentralized-read-cap-v1", b64(box.secret)))
        box.frames, box.frame_bytes = [], []
        box.first = box.frame("request", VHOST, raw_json({"packet_base64": b64(request.body), "catalog_base64": "-", "contacts": []}))
        code = private_token("psl2-", raw_json({"format": 1, "request_id": request_id,
            "secret_base64": b64(box.secret), "request_packet_base64": b64(request.body), "contacts": [], "helpers": [endpoint]}))
        self.requester.sensitive.update({code.encode(), box.secret, b64(box.secret).encode(), box.capability.encode()})
        response = self.wire.request(self.client, "POST", "/bootstrap/v1/mailboxes", body=box.create(), capability=box.capability)
        require(response.status == 201, "virtual requester first mailbox creation did not return201")
        self.terms = {"code": code, "network_id": self.network["id"], "person_public_key": self.keys.public("alice"),
            "provider_id": self.keys.public("alice"), "signature_format": "sshsig", "scopes": 7,
            "not_after": self.requester.at(3600), "expected_host_public_key": self.keys.public(VHOST),
            "expected_device_public_key": self.keys.public(VDEVICE), "approve": True}
        ready, _ = a.api("POST", "/v2/link/approvals", self.terms)
        self.wrapper(ready, "owner")
        require(len(ready["signing_requests"]) == 1, "owner setup lacks its one fixed authority packet slot")
        slot = ready["signing_requests"][0]
        require(set(slot) == SLOT_FIELDS and slot["object_type"] == "owner_offer_packet" and slot["role"] == "authority" and
                slot["public_key"] == self.keys.public("alice") and slot["format"] == "sshsig", "owner packet slot changed signer/role/type")
        packet = strict_output(unb64(slot["template_base64"])); message = packet_message(packet)
        payload = strict_output(unb64(packet["payload_base64"]))
        require(packet["role"] == "owner" and packet["request_id"] == request_id and packet["context_id"] == w.context_id and
                packet["writer_host_public_key"] == a.identity["public_key"] and packet["signer_public_key"] == packet["person_public_key"] == self.keys.public("alice") and
                packet["authority_signature_format"] == "sshsig" and packet["authority_signature"] == packet["issuer_id"] == packet["device_signature"] == "-" and
                payload["request_packet_id"] == request.packet_id and payload["descriptor"] == descriptor and
                payload["root_state_id"] == self.network["root_state_id"] and payload["host_public_key"] == self.keys.public(VHOST) and
                payload["device_public_key"] == self.keys.public(VDEVICE) and payload["scopes"] == 7 and payload["not_after"] == self.terms["not_after"] and
                slot["object_id"] == "dpk_"+sha(message) and unb64(slot["message_base64"]) == message,
                "owner packet changed independently reviewed exact virtual target/context/terms/message")
        signature = b64(self.keys.sshsig("alice", message))
        self.signatures[(slot["object_id"], "authority")] = signature
        a.api("POST", self.request_route+"/signed", {"intent_id": slot["intent_id"],
            "signatures": [{"slot_id": slot["slot_id"], "role": "authority", "signature": signature}]})
        state = self.pending(False)
        self.selection_packet = w.packet("selection", {"request_packet_id": request.packet_id,
            "owner_offer_id": state["owner_offer_id"], "context_id": w.context_id, "person_public_key": self.keys.public("alice"),
            "host_public_key": self.keys.public(VHOST), "device_public_key": self.keys.public(VDEVICE), "selected_at": created},
            request_id, writer=VHOST, signer=VDEVICE, person="alice")
        selection = box.frame("selection", VHOST, raw_json({"packet_base64": b64(self.selection_packet.body), "catalog_base64": "-", "contacts": []}))
        response = self.wire.request(self.client, "POST", "/bootstrap/v1/mailboxes/"+box.locator+"/frames",
            body=b'{"frame":'+selection+b'}', capability=box.capability)
        require(response.status == 200, "virtual requester selection frame was not retained")
        time.sleep(2.05)  # Real transport cache window; authority clock stays fixed.
        terms = {key: self.terms[key] for key in ("code", "network_id", "person_public_key", "provider_id", "signature_format",
                                                "expected_host_public_key", "expected_device_public_key")}
        terms.update(owner_offer_id=state["owner_offer_id"], selection_id=self.selection_packet.packet_id, approve=True)
        ready, _ = a.api("POST", "/v2/link/admissions", terms)
        self.finish(ready, "administrator", "administrator_packet_base64")
        state = self.pending(False)
        terms = {key: state[key] for key in ("owner_offer_id", "selection_id", "administrator_offer_id")}
        terms.update(network_id=self.network["id"], context_id=w.context_id, person_public_key=self.keys.public("alice"),
                     host_public_key=self.keys.public(VHOST), device_public_key=self.keys.public(VDEVICE), approve=True)
        ready, _ = a.api("POST", self.request_route+"/finalization", terms)
        self.finish(ready, "owner_finalization", "owner_finalization_packet_base64")
        self.prepare_complete()

    def prepare_complete(self) -> None:
        state, w = self.pending(False), self.world
        final = strict_output(unb64(state["owner_finalization_packet_base64"]))
        final_payload = strict_output(unb64(final["payload_base64"]))
        binding = final_payload["binding_lease"]
        require(isinstance(binding, dict), "new-host finalization did not supply a typed pending binding")
        binding_ds = statement_id(binding)
        hosts = [s for s in binding["signatures"] if s["role"] == "host"]
        require(hosts == [{"role": "host", "public_key": self.keys.public(VHOST), "format": "ed25519", "signature": "-"}],
                "pending binding lacks the exact unfilled virtual requester host role")
        host_signature = b64(self.keys.sign(VHOST, lines("peerspan-decentralized-signature-v1", binding_ds, "host", self.keys.public(VHOST))))
        hosts[0]["signature"] = host_signature
        binding_body = raw_json(binding)
        binding_obj = PublicObject("binding_lease", w.context_id, unb64(binding["payload_base64"]), binding_body, binding_ds)
        catalog, _ = self.owner.api("GET", "/v2/networks/"+self.network["id"]+"/catalog")
        catalogs = [catalog["catalog"]]
        if state["catalog_base64"] != "-":
            catalogs.append(strict_output(unb64(state["catalog_base64"])))
        objects = {}
        for catalog in catalogs:
            for entry in catalog["objects"]:
                envelope = strict_output(unb64(entry["body_base64"]))
                # Only the documented nested binding host placeholder is
                # incomplete. The virtual target now supplies its OWN exact
                # host signature, creating the final original proof below.
                if entry["kind"] == "binding_lease" and statement_id(envelope) == binding_ds and any(s["signature"] == "-" for s in envelope["signatures"]):
                    continue
                obj = PublicObject(entry["kind"], w.context_id, unb64(envelope["payload_base64"]),
                    unb64(entry["body_base64"]), statement_id(envelope))
                require(obj.proof_id == entry["id"], "actual supplied proof ID differs from original envelope bytes")
                objects[obj.proof_id] = obj
        objects[binding_obj.proof_id] = binding_obj
        device_ds = statement_id(final_payload["device_lease"])
        admin = strict_output(unb64(state["administrator_packet_base64"]))
        admin_bytes = unb64(admin["payload_base64"])
        admin_payload = strict_output(admin_bytes)
        components = [(unb64(final["payload_base64"]), "device_lease")]
        components += [(admin_bytes, field) for field in ("person_lease", "host_lease") if isinstance(admin_payload[field], dict)]
        component_objects = {}
        for payload_bytes, field in components:
            original = exact_object_field(payload_bytes, field)
            envelope = strict_output(original)
            require(envelope["kind"] == field and envelope["context_id"] == w.context_id,
                    "supplied exact component changed kind/context")
            obj = PublicObject(field, w.context_id, unb64(envelope["payload_base64"]), original, statement_id(envelope))
            objects[obj.proof_id] = obj
            component_objects[field] = obj
        device = component_objects["device_lease"]
        require(device.statement_id == device_ds, "exact original device component changed semantic identity")
        by_ds = {o.statement_id: o for o in objects.values()}
        selected = [final_payload["person_lease_id"], final_payload["host_lease_id"], binding_ds, device_ds]
        reached, todo = set(), set(selected)
        while todo:
            current = todo.pop()
            if current in reached: continue
            require(current in by_ds, "selected literal ancestor proof body is missing")
            reached.add(current); payload = strict_output(by_ds[current].payload)
            refs = {p["id"] for p in payload.get("parents", [])}
            for field in ("predecessors", "resolves", "retained_statement_ids", "kept_statement_ids"):
                refs |= set(payload.get(field, []))
            for ref in (payload.get("root_state_id", "-"), payload.get("ratifies", "-"), payload.get("target", {}).get("statement_id", "-")):
                if ref != "-": refs.add(ref)
            todo |= refs-reached
        manifest = {"format": 1, "context_id": w.context_id, "request_id": self.request["request_id"],
            "request_packet_id": self.request_packet.packet_id, "owner_offer_id": state["owner_offer_id"],
            "selection_id": self.selection_packet.packet_id, "administrator_offer_id": state["administrator_offer_id"],
            "owner_finalization_id": state["owner_finalization_id"], "root_state_id": self.network["root_state_id"],
            "person_lease_id": selected[0], "host_lease_id": selected[1], "binding_lease_id": binding_ds, "device_lease_id": device_ds,
            "binding_proof_id": binding_obj.proof_id, "device_proof_id": device.proof_id,
            "ancestor_statement_ids": sorted(reached-{device_ds}), "proof_ids": sorted(objects)}
        self.virtual_manifest = raw_json(manifest)
        commit = w.packet("commit", {"manifest_base64": b64(self.virtual_manifest), "binding_host_signature": host_signature,
            "committed_at": self.requester.at(0)}, self.request["request_id"], writer=VHOST, signer=VDEVICE, person="alice")
        self.activation = raw_json({"format": 1, "context_id": w.context_id,
            "request": strict_output(self.request_packet.body), "owner": strict_output(unb64(state["owner_packet_base64"])),
            "selection": strict_output(self.selection_packet.body), "administrator": strict_output(unb64(state["administrator_packet_base64"])),
            "owner_finalization": final, "commit": strict_output(commit.body)})
        self.catalog = w.catalog(list(objects.values()))
        self.public_body = b'{"activation":'+self.activation+b',"catalog":'+self.catalog+b'}'
        require(len(self.public_body) <= 20*1024*1024, "independent complete publication exceeded whole-body bound")
        # This fixture never publishes the commit in a mailbox. A real
        # application outcome before the explicit POST would violate setup.
        require(not table_rows(self.owner.host, "dec_operations", "request_id", " WHERE request_id=?", (self.request["request_id"],)),
                "actual owner already applied before the first isolated participant POST")
        require(self.pending(False)["commit_packet_base64"] == "-", "fixture accidentally delivered its final commit before isolated POST")

    def response(self, response) -> dict:
        require(response.status == 200, "isolated participant route status"+str(response.status)+", expected200; body_sha256="+sha(response.body))
        value = strict_output(response.body)
        require(set(value) == {"outcome", "activation", "catalog"}, "isolated participant response fields differ")
        operation = self.operation(self.owner)
        record = strict_output(operation[5].encode())
        require(value == {"outcome": strict_output(unb64(record["outcome_packet_base64"])),
                          "activation": strict_output(unb64(record["activation_base64"])),
                          "catalog": strict_output(unb64(record["catalog_base64"]))}, "wire response differs from actual retained local outcome/activation/catalog")
        require(value["activation"] == strict_output(self.activation), "participant substituted a different complete signed transcript")
        return value

    def run(self) -> None:
        self.setup_virtual()
        a = self.owner
        route = "/bootstrap/v1/operations/"+self.request["request_id"]
        def first_post() -> None:
            self.first = self.response(self.wire.request(self.client, "POST", "/bootstrap/v1/activations", body=self.public_body))
            self.original_operation = self.operation(a)
            self.manifest = self.verify_complete(self.original_operation, a.identity["public_key"])
            require(self.manifest == strict_output(self.virtual_manifest), "real participant applied a different frozen requester manifest")
            network, _ = a.api("GET", "/v2/networks/"+self.network["id"])
            require(network["provider"] == self.network["provider"] and network["provider"]["kind"] == "original_person" and
                    network["host_public_key"] == a.identity["public_key"],
                    "remote target completion replaced the real owner's provider/identity")
            self.trace.append({"request_id": self.request["request_id"], "activation_id": self.original_operation[3],
                "participant_tls_public_key": self.client.public, "actual_server_public_key": a.identity["public_key"],
                "first_application_was_isolated_post": True, "no_pairing_bearer_on_publication": True,
                "no_daemon_key_copy": True, "virtual_requester_owns_its_host_and_device_keys": True})
        a.case("isolated_publication/first_authenticated_complete_post_creates_actual_local_outcome", first_post)

        def secret_free_reopen() -> None:
            removed = self.wire.request(self.client, "DELETE", "/bootstrap/v1/mailboxes/"+self.box.locator, capability=self.box.capability)
            require(removed.status == 204, "actual mailbox deletion did not return204")
            missing = self.wire.request(self.client, "GET", "/bootstrap/v1/mailboxes/"+self.box.locator, capability=self.box.capability)
            require(missing.status == 404, "deleted opaque mailbox still exposes frames")
            before = authority_rows(a)
            require(self.response(self.wire.request(self.client, "GET", route)) == self.first,
                    "secret-free historical GET changed exact original outcome")
            a.host.stop(); a.host.start()
            require(a.host.api("GET", "/v1/host") == a.identity, "real participant restart changed actual host pin")
            require(self.response(self.wire.request(self.client, "GET", route)) == self.first and
                    self.response(self.wire.request(self.client, "POST", "/bootstrap/v1/activations", body=self.public_body)) == self.first and
                    self.operation(a) == self.original_operation and authority_rows(a) == before,
                    "historical GET/POST or restart changed exact outcome/authority")
            self.trace.append({"mailbox_deleted": True, "historical_get_and_post_bearer_absent": True, "restart_outcome_unchanged": True})
        a.case("isolated_publication/deleted_mailbox_and_restart_preserve_bearer_free_get_and_post", secret_free_reopen)

        def expired_current() -> None:
            expiry = moment(self.terms["not_after"])+timedelta(seconds=1)
            self.requester.set_time(expiry.strftime("%Y-%m-%dT%H:%M:%SZ"))
            members, _ = a.api("GET", "/v2/networks/"+self.network["id"]+"/members")
            require(all(m["host_public_key"] != self.keys.public(VHOST) for m in members["members"]),
                    "signed finite target membership remained current after its exact expiry")
            before = authority_rows(a)
            require(self.response(self.wire.request(self.client, "GET", route)) == self.first and
                    self.response(self.wire.request(self.client, "POST", "/bootstrap/v1/activations", body=self.public_body)) == self.first and
                    self.operation(a) == self.original_operation and authority_rows(a) == before,
                    "expired historical return reapplied authority or rewrote original outcome")
            self.trace.append({"request_and_target_grants_expired": True, "current_target_membership_absent": True,
                "historical_participant_get_and_post_still_exact": True, "no_authority_reapplication": True})
        a.case("isolated_publication/expired_current_grants_do_not_change_exact_historical_routes", expired_current)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args(); args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    keys = FixtureKeys(); suite = Publication(args.host.resolve(), args.host.resolve(), args.work_dir.resolve(), keys)
    started, failure, detail = time.monotonic(), None, None
    try:
        suite.run()
    except BaseException as error:
        failure, detail = type(error).__name__, str(error) if type(error).__name__ == "CheckFailure" else "fixture/transport failure"
    finally:
        try:
            suite.owner.host.stop()
            logs = suite.owner.host.log_path.read_bytes() if suite.owner.host.log_path.exists() else b""
            require(not any(v and v in logs for v in suite.requester.sensitive), "real participant log exposed private pairing material")
        except BaseException as error:
            suite.rows.append({"name": "cleanup/actual_owner", "passed": False, "error_type": type(error).__name__})
            failure = failure or type(error).__name__
        keys.close()
    result = {"contract_pin": PIN, "implementation_source_read": False, "suite_sha256": sha(Path(__file__).read_bytes()),
        "support_sha256": {name: sha(Path(__file__).with_name(name).read_bytes()) for name in (
            "decentralized_complete_link.py", "decentralized_owner_preview.py", "decentralized_direct_carrier.py", "decentralized_fixtures.py",
            "decentralized_helper.py", "decentralized_storage.py", "decentralized_requester.py", "decentralized_runtime.py", "decentralized_vectors.py")},
        "host": str(args.host.resolve()), "host_sha256": sha(args.host.read_bytes()), "rows": suite.rows, "trace": suite.trace,
        "failure": failure, "detail": detail, "seconds": round(time.monotonic()-started, 3),
        "scope": "positive isolated complete POST and bearer-free historical participant GET/POST after mailbox deletion, restart and current grant expiry; one actual host plus independent virtual requester; no timing/crash/CLI/up/relay/installed claim",
        "passed": failure is None and len(suite.rows) == 3 and all(row["passed"] for row in suite.rows)}
    args.results.parent.mkdir(parents=True, exist_ok=True); args.results.write_text(json.dumps(result, indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
