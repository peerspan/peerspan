#!/usr/bin/env python3
"""Independent real-time initial DEC creation/consent/reopen API acceptance.

Only public contracts and our own fixture primitives/support are used.  This
first slice deliberately requires no coordinator/helper/peer, original key in
the daemon, test clock or unpinned crash hook.  Run only on an implementation
which explicitly claims the new owner-local creation API.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import subprocess
import time

from decentralized_fixtures import FixtureKeys, b64, lines, raw_json, sha, unb64
from decentralized_storage import Host, UnixHTTP, CheckFailure, require, all_database_snapshots as snapshot
from decentralized_vectors import same_json, strict_output


PIN = "84bc914e1a61023d87717ecd63a87f0d646be7a0"
CREATION_FIELDS = {"creation_id", "review", "signing_requests", "network", "committed"}
REVIEW_FIELDS = {"name", "member", "descriptor", "root_state_id", "person_public_key",
                 "host_public_key", "not_after", "authority_warning"}
NETWORK_FIELDS = {"id", "name", "mode", "context_id", "genesis_root_public_key", "root_state_id",
                  "root_public_key", "root_epoch", "member", "host_public_key", "person_public_key",
                  "provider", "provider_state", "authority", "delivery", "created_at"}
SLOT_FIELDS = {"intent_id", "slot_id", "object_type", "object_id", "role", "public_key", "format",
               "template_base64", "message_base64"}


def moment(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class CreationSuite:
    def __init__(self, binary: Path, root: Path, keys: FixtureKeys) -> None:
        self.root, self.keys = root, keys
        self.host = Host(binary, root / "state", root, "runtime-create")
        self.rows: list[dict] = []
        self.submitted: dict[tuple[str, str], str] = {}
        self.seen_slots: dict[tuple[str, int, str], tuple[str, str]] = {}
        self.name, self.member = "Independent local creation", "Fixture owner"
        self.responses = root / "public-responses"
        self.responses.mkdir(mode=0o700)
        self.response_count = 0

    def case(self, name: str, function):
        started = time.monotonic()
        try:
            value = function()
        except BaseException as error:
            self.rows.append({"name": name, "passed": False, "error_type": type(error).__name__,
                              "detail": str(error) if isinstance(error, CheckFailure) else "fixture/transport failure",
                              "seconds": round(time.monotonic() - started, 3)})
            print("FAIL " + name, flush=True)
            raise
        self.rows.append({"name": name, "passed": True, "seconds": round(time.monotonic() - started, 3)})
        print("PASS " + name, flush=True)
        return value

    def api(self, method: str, path: str, body: dict | None = None, *, status: int = 200, timeout: float = 10) -> tuple[object, bytes]:
        connection = UnixHTTP(self.host.state / "admin.sock", timeout=timeout)
        try:
            connection.request(method, path, body=None if body is None else raw_json(body),
                               headers={} if body is None else {"Content-Type": "application/json"})
            response = connection.getresponse(); raw = response.read(32 * 1024 * 1024 + 1)
            self.response_count += 1
            saved = self.responses / f"{self.response_count:03}.json"
            saved.write_bytes(raw); saved.chmod(0o600)
            meta = saved.with_suffix(".meta.json")
            meta.write_bytes(raw_json({"method": method, "path": path, "status": response.status, "body_sha256": sha(raw)})); meta.chmod(0o600)
            require(len(raw) <= 32 * 1024 * 1024, "owner-local response exceeds32MiB")
            require(response.status == status, f"{method} {path} status{response.status}, expected{status}; response_sha256={sha(raw)}")
            if raw.startswith(b"{"):
                value = strict_output(raw)
            else:
                value = json.loads(raw)
            return value, raw
        finally:
            connection.close()

    def error(self, value: dict, code: str) -> None:
        require(set(value) == {"code", "error", "details"} and value["code"] == code, "v2 error envelope/code differs")
        require(set(value["details"]) == {"network_id", "context_id", "request_id", "stage", "required_ids", "conflict_ids", "next"},
                "v2 error details fields differ")
        require(value["details"]["required_ids"] == sorted(set(value["details"]["required_ids"])) and
                value["details"]["conflict_ids"] == sorted(set(value["details"]["conflict_ids"])), "v2 error IDs not sorted unique")

    def creation_shape(self, value: dict, committed: bool) -> None:
        require(set(value) == CREATION_FIELDS and type(value["committed"]) is bool and value["committed"] == committed,
                "creation wrapper shape/committed differs")
        require(re.fullmatch(r"create_[0-9a-f]{64}", value["creation_id"]) is not None, "creation ID is not canonical")
        review = value["review"]
        require(set(review) == REVIEW_FIELDS, "creation review fields differ")
        require(review["name"] == self.name and review["member"] == self.member and
                review["person_public_key"] == self.keys.public("alice") and review["host_public_key"] == self.identity["public_key"],
                "creation review changed requested identity")
        descriptor = review["descriptor"]
        require(set(descriptor) == {"format", "protocol", "network_id", "name", "genesis_root_public_key"} and
                type(descriptor["format"]) is int and descriptor["format"] == 1 and descriptor["protocol"] == "peerspan-decentralized-v1",
                "creation descriptor is not exact coordinator-free format")
        require(descriptor["name"] == self.name and descriptor["network_id"] == "net_" + sha(unb64(descriptor["genesis_root_public_key"])),
                "creation descriptor identity digest differs")
        require(re.fullmatch(r"ds_[0-9a-f]{64}", review["root_state_id"]) is not None, "creation root review ID malformed")
        self.descriptor = descriptor
        self.context_id = "ctx_" + sha(lines("peerspan-decentralized-context-v1", descriptor["protocol"],
                                           descriptor["network_id"], self.name, descriptor["genesis_root_public_key"]))
        require((value["network"] is not None) if committed else (value["network"] is None), "pending creation exposed active network")

    def slot_signature(self, slot: dict, *, signer: str = "alice") -> dict:
        require(set(slot) == SLOT_FIELDS, "typed signing slot fields differ")
        require(slot["object_type"] in {"binding_lease", "policy"} and slot["role"] == "issuer" and
                slot["public_key"] == self.keys.public("alice") and slot["format"] == "sshsig", "creation requested unrelated signer/format/type")
        require(re.fullmatch(r"dint_[0-9a-f]{32}", slot["intent_id"]) is not None and
                type(slot["slot_id"]) is int and 1 <= slot["slot_id"] < 2**64, "slot identity/index malformed")
        template = strict_output(unb64(slot["template_base64"]))
        require(set(template) == {"format", "kind", "context_id", "payload_base64", "signatures"} and
                template["format"] == 1 and template["kind"] == slot["object_type"] and template["context_id"] == self.context_id,
                "typed template shape/kind/context differs")
        payload = unb64(template["payload_base64"])
        object_id = "ds_" + sha(lines("peerspan-decentralized-statement-v1", template["kind"], self.context_id, sha(payload)))
        message = lines("peerspan-decentralized-signature-v1", object_id, "issuer", self.keys.public("alice"))
        require(slot["object_id"] == object_id and unb64(slot["message_base64"]) == message,
                "typed slot message/semantic ID differs from independently decoded template")
        issuer = [entry for entry in template["signatures"] if entry["role"] == "issuer"]
        require(len(issuer) == 1 and issuer[0] == {"role": "issuer", "public_key": self.keys.public("alice"),
                "format": "sshsig", "signature": "-"}, "typed issuer slot is not the exact unfilled original signature")
        decoded = strict_output(payload)
        require(decoded["root_state_id"] == self.preview["review"]["root_state_id"] and decoded["operation_id"] == "-" and
                decoded["issuer"] == {"kind": "person", "person_public_key": self.keys.public("alice")}, "typed slot changed root/operation/owner")
        if slot["object_type"] == "binding_lease":
            require(decoded["subject"] == {"person_public_key": self.keys.public("alice"), "host_public_key": self.identity["public_key"],
                    "device_public_key": "-", "member": "-", "scopes": 2}, "binding template changed target identity/scope")
        else:
            body = strict_output(unb64(decoded["body_base64"]))
            require(body["network_id"] == self.descriptor["network_id"] and body["person_public_key"] == self.keys.public("alice") and
                    body["version"] == 1, "policy template changed network/person/initial version")
        key = (slot["intent_id"], slot["slot_id"], slot["role"])
        exact = (slot["template_base64"], slot["message_base64"])
        require(self.seen_slots.get(key, exact) == exact, "persisted typed slot changed on resume")
        self.seen_slots[key] = exact
        signature = b64(self.keys.sshsig(signer, message))
        if signer == "alice":
            self.submitted[(object_id, "issuer")] = signature
        return {"slot_id": slot["slot_id"], "role": slot["role"], "signature": signature}

    def verify_raw(self, public: str, message: bytes, signature: str) -> None:
        pub, msg, sig = [self.keys.directory / name for name in ("runtime-public.der", "runtime-message", "runtime-signature")]
        pub.write_bytes(bytes.fromhex("302a300506032b6570032100") + unb64(public))
        msg.write_bytes(message); sig.write_bytes(unb64(signature))
        result = subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER", "-inkey", str(pub),
                                 "-sigfile", str(sig), "-in", str(msg)], capture_output=True)
        require(result.returncode == 0, "committed public raw signature does not verify independently")

    def verify_catalog(self) -> dict[str, tuple[str, dict]]:
        value, _ = self.api("GET", "/v2/networks/" + self.descriptor["network_id"] + "/catalog")
        require(set(value) == {"catalog"}, "catalog route wrapper fields differ")
        catalog = value["catalog"]
        require(set(catalog) == {"format", "context_id", "objects"} and catalog["format"] == 1 and
                catalog["context_id"] == self.context_id, "committed catalog shape/context differs")
        require([v["id"] for v in catalog["objects"]] == sorted({v["id"] for v in catalog["objects"]}), "catalog proofs not sorted unique")
        objects = {}
        for entry in catalog["objects"]:
            require(set(entry) == {"id", "kind", "body_base64"}, "catalog entry fields differ")
            raw = unb64(entry["body_base64"]); body = strict_output(raw)
            require(entry["id"] == "dp_" + sha(lines("peerspan-decentralized-proof-v1", entry["kind"], sha(raw))), "catalog exact proof hash differs")
            require(body["kind"] == entry["kind"] and body["context_id"] == self.context_id, "catalog envelope kind/context differs")
            payload = strict_output(unb64(body["payload_base64"]))
            ds = "ds_" + sha(lines("peerspan-decentralized-statement-v1", body["kind"], self.context_id, sha(unb64(body["payload_base64"]))))
            require(body["kind"] in {"root_state", "admin_lease", "person_lease", "host_lease", "binding_lease", "policy"}, "local creation minted an unrelated/device object")
            require(body["kind"] not in objects or objects[body["kind"]][0] == ds, "local creation minted extra semantic generations")
            objects[body["kind"]] = (ds, payload)
            issuer = self.keys.public("alice") if body["kind"] in {"binding_lease", "policy"} else self.descriptor["genesis_root_public_key"]
            expected_roles = [("issuer", issuer, "sshsig" if body["kind"] in {"binding_lease", "policy"} else "ed25519")]
            if body["kind"] in {"host_lease", "binding_lease"}:
                expected_roles.append(("host", self.identity["public_key"], "ed25519"))
            require([(s["role"], s["public_key"], s["format"]) for s in body["signatures"]] == sorted(expected_roles),
                    "creation statement has wrong role/key/format set")
            for signature in body["signatures"]:
                message = lines("peerspan-decentralized-signature-v1", ds, signature["role"], signature["public_key"])
                if signature["format"] == "sshsig":
                    require(signature["public_key"] == self.keys.public("alice") and signature["signature"] == self.submitted.get((ds, signature["role"])),
                            "committed original signature changed from the exact independently signed slot")
                else:
                    require(signature["format"] == "ed25519" and signature["public_key"] in
                            {self.identity["public_key"], self.descriptor["genesis_root_public_key"]}, "unexpected creation signature key/format")
                    self.verify_raw(signature["public_key"], message, signature["signature"])
        require(set(objects) == {"root_state", "admin_lease", "person_lease", "host_lease", "binding_lease", "policy"}, "creation omitted a required ordinary object")
        require(objects["root_state"][0] == self.preview["review"]["root_state_id"] and
                objects["root_state"][1]["epoch"] == 0 and objects["root_state"][1]["migration_proposal_id"] == "-" and
                objects["root_state"][1]["root_public_key"] == self.descriptor["genesis_root_public_key"], "creation root differs from approved genesis")
        for kind in set(objects) - {"root_state"}:
            payload = objects[kind][1]
            require(payload["root_state_id"] == objects["root_state"][0] and payload["operation_id"] == "-" and payload["sequence"] == 1,
                    "local genesis changed root/initial sequence/ordinary operation")
            require(0 < (moment(payload["not_after"]) - moment(payload["issued_at"])).total_seconds() <= (86400 if kind == "policy" else 7 * 86400),
                    "creation exceeded finite interval")
            require(payload["predecessors"] == [] and payload["resolves"] == [], "creation invented old stream history")
        expected_subjects = {
            "admin_lease": {"person_public_key": self.keys.public("alice"), "host_public_key": "-", "device_public_key": "-", "member": "-", "scopes": 8},
            "person_lease": {"person_public_key": self.keys.public("alice"), "host_public_key": "-", "device_public_key": "-", "member": self.member, "scopes": 0},
            "host_lease": {"person_public_key": "-", "host_public_key": self.identity["public_key"], "device_public_key": "-", "member": self.member, "scopes": 0},
            "binding_lease": {"person_public_key": self.keys.public("alice"), "host_public_key": self.identity["public_key"], "device_public_key": "-", "member": "-", "scopes": 2},
        }
        for kind, subject in expected_subjects.items():
            require(objects[kind][1]["subject"] == subject, "creation changed signed subject/scope")
        person, host = objects["person_lease"][0], objects["host_lease"][0]
        require(objects["binding_lease"][1]["parents"] == sorted([
            {"role": "issuer_person", "id": person}, {"role": "subject_person", "id": person},
            {"role": "subject_host", "id": host}], key=lambda value: value["role"]), "binding lacks exact creator P/H ancestry")
        require(objects["policy"][1]["parents"] == [{"role": "issuer_person", "id": person}], "policy lacks exact creator P ancestry")
        return objects

    def run(self) -> None:
        self.host.start()
        self.identity = self.host.api("GET", "/v1/host")
        body = {"name": self.name, "member": self.member, "person_public_key": self.keys.public("alice"), "approve": False}
        self.case("create/fresh_host_no_network", lambda: require(self.api("GET", "/v2/networks")[0] == [], "fresh host already has a network"))
        def preview() -> tuple[dict, bytes]:
            value, raw = self.api("POST", "/v2/networks", body)
            self.creation_shape(value, False)
            require(value["signing_requests"] == [], "unapproved preview exposed signing requests")
            return value, raw
        self.preview, _ = self.case("create/unapproved_exact_review", preview)
        route = "/v2/network-creations/" + self.preview["creation_id"]
        self.case("create/prepare_retry_reuses_exact_intent", lambda: require(same_json(self.api("POST", "/v2/networks", body)[0], self.preview), "retry changed root/intent/review"))
        approval = {"context_id": self.context_id, "root_state_id": self.preview["review"]["root_state_id"],
                    "person_public_key": self.keys.public("alice"), "host_public_key": self.identity["public_key"], "approve": True}
        def wrong_pin() -> None:
            bad = dict(approval, host_public_key=self.keys.public("unrelated-host"))
            self.error(self.api("POST", route + "/approve", bad, status=400)[0], "invalid")
            require(same_json(self.api("GET", route)[0], self.preview) and self.api("GET", "/v2/networks")[0] == [], "wrong approval changed consent/active network")
        self.case("create/wrong_host_approval400_no_effect", wrong_pin)
        ready, _ = self.case("create/explicit_approval_only_typed_original_slots", lambda: self.api("POST", route + "/approve", approval))
        self.creation_shape(ready, False)
        require(bool(ready["signing_requests"]), "approved creation did not expose external original slots")
        first = ready["signing_requests"][0]
        def forged() -> None:
            signature = self.slot_signature(first, signer="unrelated-person")
            self.error(self.api("POST", route + "/signed", {"intent_id": first["intent_id"], "signatures": [signature]}, status=400)[0], "invalid")
            require(same_json(self.api("GET", route)[0], ready) and self.api("GET", "/v2/networks")[0] == [], "wrong signature changed fixed intent/active network")
        self.case("create/forged_original_signature400_no_partial_apply", forged)
        final_raw = b""
        for _ in range(8):
            slots = ready["signing_requests"]
            require(1 <= len(slots) <= 16 and len({slot["intent_id"] for slot in slots}) == 1, "ready signing batch count/intent differs")
            require([(s["slot_id"], s["role"]) for s in slots] == sorted({(s["slot_id"], s["role"]) for s in slots}), "slots not sorted unique")
            request = {"intent_id": slots[0]["intent_id"], "signatures": [self.slot_signature(slot) for slot in slots]}
            ready, final_raw = self.api("POST", route + "/signed", request)
            if ready["committed"]:
                break
            self.creation_shape(ready, False)
        else:
            raise CheckFailure("initial creation did not finish within8 fixed dependency batches")
        self.creation_shape(ready, True)
        require(ready["signing_requests"] == [], "applied creation still exposes unsigned work")
        self.final, self.final_raw, self.final_request, self.route = ready, final_raw, request, route
        network = ready["network"]
        require(set(network) == NETWORK_FIELDS and network["mode"] == "decentralized" and network["context_id"] == self.context_id and
                network["id"] == self.descriptor["network_id"] and network["person_public_key"] == self.keys.public("alice") and
                network["host_public_key"] == self.identity["public_key"] and network["root_epoch"] == 0, "applied network identity/mode differs")
        require(network["provider"]["kind"] == "original_person" and network["provider"]["device_public_key"] == "-" and
                network["provider_state"]["state"] == "unavailable" and network["provider_state"]["code"] == "signer_unavailable" and
                network["authority"]["state"] == "usable", "public membership/provider availability conflated or a device was invented")
        objects = self.case("create/independent_exact_catalog_crypto_and_finite_bounds", self.verify_catalog)
        require(network["provider"]["lease_id"] == objects["person_lease"][0], "original provider not tied to exact person admission")
        self.case("create/access_version_initial_maximum", lambda: require(self.api("GET", "/v2/networks/" + network["id"] + "/access-versions")[0] ==
            {"policies": [{"person_public_key": self.keys.public("alice"), "version": 1, "statement_ids": [objects["policy"][0]], "head_ids": [objects["policy"][0]]}], "groups": []}, "initial policy maximum differs"))
        before = snapshot(self.host.state)
        self.case("create/completed_GET_exact_original_bytes", lambda: require(self.api("GET", route)[1] == final_raw, "completed GET reconstructed original wrapper"))
        self.case("create/completed_signed_retry_exact_original_bytes", lambda: require(self.api("POST", route + "/signed", request)[1] == final_raw, "completed retry changed original result"))
        require(same_json(snapshot(self.host.state), before), "completed reads/retry changed rows/clock/provider")
        self.host.stop(); self.host.start()
        self.case("create/restart_retains_exact_completed_response", lambda: require(self.api("GET", route)[1] == final_raw, "restart lost original completed response bytes"))
        events = self.host.api("GET", "/v1/activity?limit=1000")
        self.case("create/exactly_one_application_event", lambda: require(sum(e["kind"] == "network.created" for e in events) == 1, "creation replay duplicated/lost application event"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()
    args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    keys = FixtureKeys(); suite = CreationSuite(args.host.resolve(), args.work_dir.resolve(), keys)
    started, error = time.monotonic(), None
    try:
        keys.self_check(); suite.run()
    except BaseException as failure:
        error = {"type": type(failure).__name__, "detail": str(failure) if isinstance(failure, CheckFailure) else "fixture/transport failure"}
    finally:
        try:
            suite.host.stop()
        except BaseException as failure:
            suite.rows.append({"name": "cleanup/owned_host", "passed": False, "detail": str(failure)})
        keys.close()
    result = {"contract_pin": PIN, "implementation_source_read": False, "suite_sha256": sha(Path(__file__).read_bytes()),
              "host": str(args.host.resolve()), "host_sha256": sha(args.host.read_bytes()), "rows": suite.rows,
              "scope": "real-time owner-local API initial creation/typed external signing/read-only completion/restart; no CLI/link/helper/crash claim",
              "seconds": round(time.monotonic() - started, 3), "error": error,
              "passed": error is None and all(r["passed"] for r in suite.rows)}
    args.results.parent.mkdir(parents=True, exist_ok=True); args.results.write_text(json.dumps(result, indent=2) + "\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
