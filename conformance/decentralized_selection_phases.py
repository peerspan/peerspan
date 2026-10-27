#!/usr/bin/env python3
"""Independent PR116 requester selection durable-phase crash/restart checks.

One real request crosses its separate approval, owned-signature batch and
sealed-frame commits, with a tracked process crash at each actual barrier.
Only public contracts and our own fixture/API/crypto helpers are used. No
application/outcome boundary or approver-phase completeness is claimed here.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import shutil
import stat
import subprocess
import time

from decentralized_complete_link import CompleteLink, packet_message, table_rows
from decentralized_create_controls import Call
from decentralized_direct_carrier import NODE_DECRYPT
from decentralized_fixtures import FixtureKeys, b64, lines, raw_json, sha, unb64
from decentralized_owner_preview import OwnerPreview, REVIEW, authority_rows
from decentralized_requester import VIEW
from decentralized_storage import CheckFailure, require
from decentralized_vectors import strict_output


PIN = "0ea487eba4134b851c87816b7d54776f7b8bee31"
PHASES = ("dec.approval.after_commit", "dec.signature.after_commit", "dec.frame.after_commit")


class SelectionPhases(CompleteLink):
    def __init__(self, binary: Path, root: Path, keys: FixtureKeys, *, owner_binary: Path | None = None) -> None:
        super().__init__(owner_binary or binary, binary, root, keys)
        self.markers = root/"selection-markers"
        self.markers.mkdir(mode=0o700)
        self.requester.host.environment["PEERSPAN_DEC_TEST_BARRIER_DIR"] = str(self.markers)
        self.fixed_pin, self.fixed_template = None, None
        self.fixed_signatures = {}

    def owner_slots(self, terms: dict, first: dict, *, selection_only: bool = False) -> None:
        # Reuse only the previously verified owner-offer setup. The requester's
        # selection action is the NEW operation evaluated by this slice.
        original = self.owner.case
        self.owner.case = lambda name, f: None if name.endswith("selection_preview_and_explicit_consent_remain_separate_from_commit") else f()
        try:
            OwnerPreview.owner_slots(self, terms, first, selection_only=True)
        finally:
            self.owner.case = original

    def arm(self, phase: str) -> None:
        path = self.markers/(phase+".arm")
        path.write_text(self.request["request_id"]); path.chmod(0o600)

    def wait(self, phase: str, call: Call) -> None:
        marker, deadline = self.markers/(phase+".entered"), time.monotonic()+8
        while time.monotonic() < deadline:
            if marker.exists():
                require(marker.is_file() and not marker.is_symlink() and stat.S_IMODE(marker.stat().st_mode) == 0o600 and
                        marker.read_text().removesuffix("\n") == self.request["request_id"],
                        "real ceremony marker changed identity or protected file shape")
                return
            time.sleep(0.02)
        raise CheckFailure("requested real selection barrier not reached within8s; RPC error type="+str(call.error))

    def intent(self) -> tuple[dict, dict]:
        pending = self.pending()
        reference = pending["selection_intent_id"]
        require(reference != "-" and pending["commit_intent_id"] == "-" and
                pending["selection_approved"] and not pending["commit_approved"],
                "selection consent/typed intent was not distinct from final commit")
        rows = table_rows(self.requester.host, "dec_intents", "network_id,context_id,kind,record,secret",
                          " WHERE intent_id=?", (reference,))
        require(len(rows) == 1 and rows[0][:3] == (self.network["id"], self.network["context_id"], "selection") and rows[0][4] is None,
                "requester consent lacks one exact private selection intent with SQLNULL secret")
        intent = strict_output(rows[0][3].encode())
        require(intent["operation_id"] == self.request["request_id"] and intent["approved"] and
                intent["provider"] == {"kind": "requester", "signer_public_key": self.request["device_public_key"],
                    "signature_format": "ed25519", "lease_id": "-"} and intent["terminal"] == "-" and intent["result_base64"] == "-",
                "selection intent changed role/provider/approval or fabricated an applied result")
        require(intent["person_public_key"] == self.keys.public("alice") and
                intent["host_public_key"] == self.request["host_public_key"] and
                intent["device_public_key"] == self.request["device_public_key"] and
                intent["root_state_id"] == self.network["root_state_id"], "private requester intent changed exact identity/root")
        review = strict_output(unb64(intent["review_base64"]))
        require(set(review) == REVIEW and review["stage"] == "selection" and
                review["network_id"] == self.network["id"] and review["context_id"] == self.network["context_id"] and
                review["person_public_key"] == self.keys.public("alice") and review["host_public_key"] == self.request["host_public_key"] and
                review["device_public_key"] == self.request["device_public_key"] and review["owner_offer_id"] == self.slot["object_id"] and
                review["scopes"] == self.terms["scopes"] and review["not_after"] == self.terms["not_after"],
                "durable consent review changed selected owner/target/terms")
        fixed = {k:v for k,v in intent.items() if k not in {"templates", "signatures", "completed"}}
        require(self.fixed_pin is None or self.fixed_pin == fixed, "resume changed approved terms/provider/timestamps/consent")
        self.fixed_pin = fixed
        require(len(intent["templates"]) == 1 and intent["templates"][0]["slot_id"] == 1 and
                intent["templates"][0]["object_type"] == "selection_packet", "requester intent exposes unrelated template types/slots")
        template = intent["templates"][0]["template_base64"]
        if template != "-":
            require(self.fixed_template is None or self.fixed_template == template, "fixed requester packet template changed")
            self.fixed_template = template
            packet = strict_output(unb64(template)); message = packet_message(packet)
            payload = strict_output(unb64(packet["payload_base64"]))
            require(packet["role"] == "selection" and packet["request_id"] == self.request["request_id"] and
                    packet["context_id"] == self.network["context_id"] and packet["writer_host_public_key"] == self.request["host_public_key"] and
                    packet["signer_public_key"] == self.request["device_public_key"] and packet["person_public_key"] == self.keys.public("alice") and
                    all(packet[k] == "-" for k in ("issuer_id", "host_signature", "device_signature", "authority_signature_format", "authority_signature")) and
                    payload == {"request_packet_id": self.request["request_packet_id"], "owner_offer_id": self.slot["object_id"],
                        "context_id": self.network["context_id"], "person_public_key": self.keys.public("alice"),
                        "host_public_key": self.request["host_public_key"], "device_public_key": self.request["device_public_key"],
                        "selected_at": intent["approved_at"]}, "fixed owned requester template changed signing message/roles/pins")
        else:
            require(not intent["signatures"], "signature exists before its exact typed template")
            message = None
        observed = {}
        require([(s["slot_id"], s["role"]) for s in intent["signatures"]] ==
                sorted({(s["slot_id"], s["role"]) for s in intent["signatures"]}),
                "private signature entries are not sorted unique by slot/role")
        for entry in intent["signatures"]:
            require(set(entry) == {"slot_id", "role", "signature"} and entry["slot_id"] == 1 and
                    entry["role"] in {"host", "device"} and entry["role"] not in observed and message is not None,
                    "requester intent stored duplicate/external/arbitrary signature role")
            public_key = self.request["host_public_key"] if entry["role"] == "host" else self.request["device_public_key"]
            self.owner.verify_raw(public_key, message, entry["signature"])
            observed[entry["role"]] = entry["signature"]
        require(all(observed.get(role) == signature for role, signature in self.fixed_signatures.items()),
                "persisted owned signature changed or disappeared on resume")
        self.fixed_signatures = observed
        require(authority_rows(self.requester) == self.original_authority and self.requester.api("GET", "/v2/networks")[0] == [],
                "selection durable phases admitted authority or selected a network signer")
        return pending, intent

    def selection_frames(self) -> list[bytes]:
        rows = table_rows(self.requester.host, "dec_frames", "record", " WHERE request_id=? AND role='selection'", (self.request["request_id"],))
        return [unb64(strict_output(row[0].encode())["frame_base64"]) for row in rows]

    def crash(self, call: Call, next_phase: str | None) -> None:
        host = self.requester.host
        process = host.process
        require(process is not None and process.poll() is None and os.getpgid(process.pid) == process.pid,
                "selection crash target is not exact tracked live fixture PGID")
        os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=5)
        host.process = None; host.log.close(); call.join()
        for path in self.markers.iterdir():
            require(path.is_file() and not path.is_symlink(), "unexpected fixture marker object")
            path.unlink()
        if next_phase is not None:
            self.arm(next_phase)
        host.start()
        require(host.api("GET", "/v1/host") == self.requester.identity and
                self.requester.pending(self.request["request_id"])[1:] == self.original_secret_tail,
                "phase crash/restart changed owned host identity or exact request secret/capability")

    def verify_frame(self, pending: dict, intent: dict, frames: list[bytes]) -> None:
        require(intent["completed"] and set(self.fixed_signatures) == {"host", "device"} and
                pending["selection_packet_base64"] != "-" and len(frames) == 1,
                "sealed-frame boundary lacks one complete signed packet/exact frame")
        self.fixed_frame, self.fixed_packet = frames[0], pending["selection_packet_base64"]
        frame = strict_output(self.fixed_frame)
        require(frame["role"] == "selection" and frame["request_id"] == self.request["request_id"] and
                frame["writer_host_public_key"] == self.request["host_public_key"] and
                frame["created_at"] == self.request["created_at"] and frame["expires_at"] == self.request["expires_at"],
                "selection frame changed its exact owned writer/request/window")
        ad = lines("peerspan-decentralized-frame-v1", frame["request_id"], frame["locator"], frame["role"],
            frame["writer_host_public_key"], frame["frame_id"], frame["created_at"], frame["expires_at"])
        self.owner.verify_raw(self.request["host_public_key"], lines("peerspan-decentralized-frame-envelope-v1", ad.decode(),
            sha(unb64(frame["ciphertext_base64"]))), frame["signature"])
        decrypted = subprocess.run(["/usr/bin/node", "-e", NODE_DECRYPT], input=raw_json({
            "secret": b64(self.original_secret_tail[0]), "salt": b64(bytes.fromhex(sha(lines("peerspan-decentralized-frame-salt-v1", frame["request_id"])))),
            "info": b64(lines("peerspan-decentralized-frame-key-v1", frame["request_id"], "selection", self.request["host_public_key"])),
            "nonce": b64(bytes.fromhex(sha(lines("peerspan-decentralized-frame-nonce-v1", frame["frame_id"])))[:12]),
            "ad": b64(ad), "ciphertext": frame["ciphertext_base64"]}), capture_output=True, check=True, timeout=10)
        plaintext = strict_output(unb64(strict_output(decrypted.stdout)["plaintext_base64"]))
        require(set(plaintext) == {"packet_base64", "catalog_base64", "contacts"} and
                plaintext["packet_base64"] == self.fixed_packet, "sealed frame does not carry exact durable signed selection")

    def resume_frame(self, source: Path) -> None:
        """Reopen only a stopped owned COPY of the exact original failure.

        No approval/signature case or original state is repeated/rewritten.
        The only active daemon is the copied requester, with its exact existing
        complete packet, owned keys, clock and absent frame as preconditions.
        """
        source = source.resolve()
        require(source != self.requester.root.resolve() and (source/"state").is_dir(),
                "frame continuation requires a distinct retained requester directory")
        def ignore_sockets(directory: str, names: list[str]) -> list[str]:
            return [name for name in names if stat.S_ISSOCK((Path(directory)/name).lstat().st_mode)]
        shutil.copytree(source/"state", self.requester.host.state, ignore=ignore_sockets)
        shutil.copy2(source/"clock", self.requester.clock)
        def files(directory: Path) -> dict:
            return {str(path.relative_to(directory)): sha(path.read_bytes()) for path in directory.rglob("*")
                    if path.is_file() and not path.is_symlink()}
        self.copy_source_hashes = files(source/"state")
        require(files(self.requester.host.state) == self.copy_source_hashes and
                self.requester.clock.read_bytes() == (source/"clock").read_bytes(),
                "stopped requester copy changed original data/key/clock bytes")
        rows = table_rows(self.requester.host, "dec_pending", "request_id,record,secret,terminal_read_cap")
        require(len(rows) == 1, "retained fixture does not contain one exact failed request")
        identifier, encoded, secret, read_cap = rows[0]
        pending = strict_output(encoded.encode())
        packet = strict_output(unb64(pending["request_packet_base64"]))
        payload = strict_output(unb64(packet["payload_base64"]))
        self.request = {**payload, "request_id": identifier, "host_public_key": pending["host_public_key"],
            "device_public_key": pending["device_public_key"], "request_packet_id": "dpk_"+sha(packet_message(packet))}
        self.request_route = "/v2/link/requests/"+identifier
        descriptor = strict_output(unb64(pending["descriptor_base64"]))
        self.requester.world.descriptor = descriptor
        rows = table_rows(self.requester.host, "dec_intents", "context_id,record", " WHERE intent_id=?", (pending["selection_intent_id"],))
        require(len(rows) == 1, "failed request lost its own exact selection intent")
        context, encoded = rows[0]; intent = strict_output(encoded.encode())
        self.network = {"id": descriptor["network_id"], "context_id": context, "root_state_id": intent["root_state_id"]}
        self.requester.world.context_id = context
        self.slot = {"object_id": pending["owner_offer_id"]}
        self.terms = strict_output(unb64(intent["review_base64"]))
        self.fixed_pin = {k:v for k,v in intent.items() if k not in {"templates", "signatures", "completed"}}
        require(intent["completed"] and pending["selection_packet_base64"] != "-" and
                not self.selection_frames() and secret is not None,
                "retained failure is not the completed-packet-before-frame precondition")
        self.fixed_template = intent["templates"][0]["template_base64"]
        self.fixed_signatures = {entry["role"]:entry["signature"] for entry in intent["signatures"]}
        self.original_authority, self.original_secret_tail = authority_rows(self.requester), (secret, read_cap)
        self.before_packet = pending["selection_packet_base64"]
        self.requester.sensitive.update(value for value in (secret, b64(secret).encode()) if value)
        self.arm(PHASES[2])
        self.requester.host.start()
        self.requester.identity = self.requester.host.api("GET", "/v1/host")
        require(self.requester.identity["public_key"] == self.request["host_public_key"], "copied requester changed exact original host identity")
        def continuation() -> None:
            call = Call(lambda: self.requester.api("POST", self.request_route+"/resume", {}))
            self.wait(PHASES[2], call)
            current, actual_intent = self.intent()
            require(current["selection_packet_base64"] == self.before_packet,
                    "frame continuation rewrote the already durable signed packet")
            self.verify_frame(current, actual_intent, self.selection_frames())
            self.trace.append({"barrier": PHASES[2], "request_id": identifier,
                "signatures_persisted": sorted(self.fixed_signatures), "selection_frames_persisted": 1,
                "final_consent": False, "authority_adopted": False, "copied_original_failure": True})
            self.crash(call, None)
            resumed, _ = self.requester.api("POST", self.request_route+"/resume", {})
            require(set(resumed) == VIEW|{"display_code"} and resumed["selection_approved"] and not resumed["commit_approved"] and
                    resumed["activation_id"] == resumed["outcome_id"] == "-", "frame recovery supplied final consent/application")
            current, _ = self.intent()
            require(current["selection_packet_base64"] == self.fixed_packet and self.selection_frames() == [self.fixed_frame] and
                    "owner_selected" in resumed["completed"], "frame recovery regenerated durable packet/ciphertext or lost selected stage")
            require(files(source/"state") == self.copy_source_hashes,
                    "failed-only continuation modified retained original requester state")
        self.owner.case("selection_phases/"+PHASES[2], continuation)

    def run(self) -> None:
        self.setup()
        b = self.requester
        before = self.pending()
        require(before["selection_intent_id"] == before["commit_intent_id"] == "-" and
                not before["selection_approved"] and not before["commit_approved"], "setup already supplied requester consent")
        self.original_authority = authority_rows(b)
        self.original_secret_tail = b.pending(self.request["request_id"])[1:]
        terms = {"owner_offer_id": self.slot["object_id"], "network_id": self.network["id"], "context_id": self.network["context_id"],
            "person_public_key": self.keys.public("alice"), "host_public_key": self.request["host_public_key"],
            "device_public_key": self.request["device_public_key"], "approve": True}
        self.arm(PHASES[0])
        for index, phase in enumerate(PHASES):
            def inspect(index=index, phase=phase) -> None:
                call = Call(lambda: b.api("POST", self.request_route+("/selection" if index == 0 else "/resume"), terms if index == 0 else {}))
                self.wait(phase, call)
                pending, intent = self.intent()
                frames = self.selection_frames()
                if index == 0:
                    require(not intent["signatures"] and not intent["completed"] and pending["selection_packet_base64"] == "-" and not frames,
                            "approval transaction already generated owned signatures, packet or encrypted frame")
                elif index == 1:
                    require(bool(intent["signatures"]) and not frames, "signature batch missing or already encrypted before separate frame commit")
                else:
                    self.verify_frame(pending, intent, frames)
                self.trace.append({"barrier": phase, "request_id": self.request["request_id"],
                    "signatures_persisted": sorted(self.fixed_signatures), "selection_frames_persisted": len(frames),
                    "final_consent": False, "authority_adopted": False})
                self.crash(call, PHASES[index+1] if index+1 < len(PHASES) else None)
                if index == 2:
                    resumed, _ = b.api("POST", self.request_route+"/resume", {})
                    require(set(resumed) == VIEW|{"display_code"} and resumed["selection_approved"] and not resumed["commit_approved"] and
                            resumed["activation_id"] == resumed["outcome_id"] == "-", "approved selection resume supplied final consent/application")
                    current, _ = self.intent()
                    require(current["selection_packet_base64"] == self.fixed_packet and self.selection_frames() == [self.fixed_frame] and
                            "owner_selected" in resumed["completed"], "exact resume regenerated signed packet/frame or lost its verified completed stage")
            self.owner.case("selection_phases/"+phase, inspect)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", type=Path, required=True)
    parser.add_argument("--owner", type=Path, help="working owner writer; defaults to requester host binary")
    parser.add_argument("--resume-frame-from", type=Path, help="stopped original requester fixture; copy and evaluate only its failed frame boundary")
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args(); args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    keys = FixtureKeys(); suite = SelectionPhases(args.host.resolve(), args.work_dir.resolve(), keys,
        owner_binary=args.owner.resolve() if args.owner else None)
    started, failure, detail = time.monotonic(), None, None
    try:
        suite.resume_frame(args.resume_frame_from) if args.resume_frame_from else suite.run()
    except BaseException as error:
        failure, detail = type(error).__name__, str(error) if isinstance(error, CheckFailure) else "fixture/transport failure"
    finally:
        for label, instance in (("requester", suite.requester), ("owner", suite.owner)):
            try:
                instance.host.stop()
                logs = instance.host.log_path.read_bytes() if instance.host.log_path.exists() else b""
                require(not any(v and v in logs for v in suite.requester.sensitive), "host log exposed private pairing material")
            except BaseException as error:
                suite.rows.append({"name": "cleanup/"+label, "passed": False, "error_type": type(error).__name__})
                failure = failure or type(error).__name__
        keys.close()
    result = {"contract_pin": PIN, "implementation_source_read": False, "suite_sha256": sha(Path(__file__).read_bytes()),
        "support_sha256": {name: sha(Path(__file__).with_name(name).read_bytes()) for name in (
            "decentralized_complete_link.py", "decentralized_create_controls.py", "decentralized_owner_preview.py", "decentralized_direct_carrier.py",
            "decentralized_fixtures.py", "decentralized_helper.py", "decentralized_storage.py", "decentralized_requester.py", "decentralized_runtime.py", "decentralized_vectors.py")},
        "host": str(args.host.resolve()), "host_sha256": sha(args.host.read_bytes()), "rows": suite.rows, "trace": suite.trace,
        "owner": str(suite.owner.host.binary), "owner_sha256": sha(suite.owner.host.binary.read_bytes()),
        "failure": failure, "detail": detail, "seconds": round(time.monotonic()-started, 3),
        "resume_frame_source": str(args.resume_frame_from.resolve()) if args.resume_frame_from else None,
        "copied_original_state_sha256": sha(raw_json(suite.copy_source_hashes)) if hasattr(suite, "copy_source_hashes") else None,
        "scope": ("failed frame boundary only on an exact stopped owned requester copy; already completed original intent/packet/signatures preserved, no approval/signature repeat or transport-delivery claim" if args.resume_frame_from else
                  "one requester selection through3 actual approval/signature/frame crash/restart boundaries; exact approved intent/owned keys/signatures/ciphertext preserved; no final consent/authority adoption or approver/application/outcome boundary claim"),
        "passed": failure is None and len(suite.rows) == (1 if args.resume_frame_from else 3) and all(row["passed"] for row in suite.rows)}
    args.results.parent.mkdir(parents=True, exist_ok=True); args.results.write_text(json.dumps(result, indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
