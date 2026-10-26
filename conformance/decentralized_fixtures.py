"""Independent public DEC fixtures, derived from contracts pinned at 2f8ff787.

This module imports no product or preexisting test code.  OpenSSL supplies only
the Ed25519 primitive over deterministic, fixture-owned keys.  Everything fed to
the product verifier is public; private fixture material stays in a temporary
directory and never enters an emitted vector or result receipt.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import textwrap
from dataclasses import dataclass


PIN = "2f8ff787bc5364ac148b2564142f39707c87d1da"
NOW = "2026-10-26T12:00:00Z"
BEFORE = "2026-10-26T11:00:00Z"
UNTIL = "2026-10-27T12:00:00Z"
NAMESPACE = b"peerspan-person-v1"


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def unb64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def raw_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def lines(*values: object) -> bytes:
    return "\n".join(str(v) for v in values).encode("utf-8")


def ssh_string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


@dataclass(frozen=True)
class PublicObject:
    kind: str
    context_id: str
    payload: bytes
    body: bytes
    statement_id: str

    @property
    def proof_id(self) -> str:
        return "dp_" + sha(lines("peerspan-decentralized-proof-v1", self.kind, sha(self.body)))

    def entry(self) -> dict:
        return {"id": self.proof_id, "kind": self.kind, "body_base64": b64(self.body)}


@dataclass(frozen=True)
class Packet:
    role: str
    body: bytes
    payload: bytes
    packet_id: str


@dataclass
class ActivationFixture:
    body: bytes
    request_id: str
    manifest_id: str
    activation_id: str
    manifest: bytes
    packets: dict[str, Packet]
    source_objects: list[PublicObject]
    new_objects: list[PublicObject]
    device: PublicObject
    expected: dict


class FixtureKeys:
    def __init__(self) -> None:
        self._directory = tempfile.TemporaryDirectory(prefix="peerspan-dec-owned-keys-")
        self.directory = Path(self._directory.name)
        self._keys: dict[str, tuple[Path, bytes]] = {}
        self._signatures: dict[tuple[str, bytes], bytes] = {}
        self.signatures = 0

    def close(self) -> None:
        self._directory.cleanup()

    def _key(self, name: str) -> tuple[Path, bytes]:
        if name not in self._keys:
            seed = hashlib.sha256(lines("peerspan-independent-dec-fixture-only-v1", name)).digest()
            # RFC8410 unencrypted Ed25519 PKCS#8, containing this fixture's seed.
            der = bytes.fromhex("302e020100300506032b657004220420") + seed
            path = self.directory / f"key-{len(self._keys)}.der"
            path.write_bytes(der)
            path.chmod(0o600)
            result = subprocess.run(
                ["openssl", "pkey", "-inform", "DER", "-in", str(path), "-pubout", "-outform", "DER"],
                check=True, capture_output=True,
            ).stdout
            prefix = bytes.fromhex("302a300506032b6570032100")
            if not result.startswith(prefix) or len(result) != len(prefix) + 32:
                raise RuntimeError("OpenSSL returned an unexpected Ed25519 public encoding")
            self._keys[name] = (path, result[len(prefix):])
        return self._keys[name]

    def public(self, name: str) -> str:
        return b64(self._key(name)[1])

    def sign(self, name: str, message: bytes) -> bytes:
        cache_key = (name, message)
        if cache_key not in self._signatures:
            key_path, _ = self._key(name)
            message_path = self.directory / "message"
            message_path.write_bytes(message)
            result = subprocess.run(
                ["openssl", "pkeyutl", "-sign", "-rawin", "-keyform", "DER",
                 "-inkey", str(key_path), "-in", str(message_path)],
                check=True, capture_output=True,
            ).stdout
            if len(result) != 64:
                raise RuntimeError("OpenSSL returned an unexpected Ed25519 signature")
            self._signatures[cache_key] = result
            self.signatures += 1
        return self._signatures[cache_key]

    def sshsig(self, name: str, message: bytes, *, namespace: bytes = NAMESPACE,
               hash_algorithm: bytes = b"sha512") -> bytes:
        public_blob = ssh_string(b"ssh-ed25519") + ssh_string(self._key(name)[1])
        digest = hashlib.new(hash_algorithm.decode(), message).digest()
        signed = (b"SSHSIG" + ssh_string(namespace) + ssh_string(b"")
                  + ssh_string(hash_algorithm) + ssh_string(digest))
        signature_blob = ssh_string(b"ssh-ed25519") + ssh_string(self.sign(name, signed))
        return (b"SSHSIG" + struct.pack(">I", 1) + ssh_string(public_blob)
                + ssh_string(namespace) + ssh_string(b"") + ssh_string(hash_algorithm)
                + ssh_string(signature_blob))

    def self_check(self) -> None:
        """Cross-check the fixture SSHSIG container with the actual SSH verifier."""
        name, message = "fixture-primitive-check", b"independent fixture signature check\n"
        public_blob = ssh_string(b"ssh-ed25519") + ssh_string(self._key(name)[1])
        allowed = self.directory / "allowed_signers"
        allowed.write_text("fixture ssh-ed25519 " + b64(public_blob) + "\n")
        signature = self.directory / "check.sig"
        signature.write_text("-----BEGIN SSH SIGNATURE-----\n"
                             + "\n".join(textwrap.wrap(b64(self.sshsig(name, message)), 70))
                             + "\n-----END SSH SIGNATURE-----\n")
        subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", "fixture",
             "-n", NAMESPACE.decode(), "-s", str(signature)],
            input=message, check=True, capture_output=True,
        )


class World:
    def __init__(self, keys: FixtureKeys, name: str = "Independent DEC") -> None:
        self.keys = keys
        self.descriptor = {
            "format": 1, "protocol": "peerspan-decentralized-v1",
            "network_id": "net_" + sha(unb64(keys.public("root"))),
            "name": name, "genesis_root_public_key": keys.public("root"),
        }
        self.descriptor_bytes = raw_json(self.descriptor)
        self.context_id = "ctx_" + sha(lines(
            "peerspan-decentralized-context-v1", self.descriptor["protocol"],
            self.descriptor["network_id"], name, self.descriptor["genesis_root_public_key"],
        ))
        self.genesis_payload = {
            "epoch": 0, "predecessors": [], "resolves": [], "migration_proposal_id": "-",
            "root_public_key": keys.public("root"), "issued_at": NOW,
            "retained_statement_ids": [],
        }
        self.genesis = self.statement("root_state", self.genesis_payload, [("issuer", "root", "ed25519")])

    def statement(self, kind: str, payload: object | bytes,
                  signers: list[tuple[str, str, str]], *, context_id: str | None = None) -> PublicObject:
        payload_bytes = payload if isinstance(payload, bytes) else raw_json(payload)
        context = self.context_id if context_id is None else context_id
        statement_id = "ds_" + sha(lines("peerspan-decentralized-statement-v1", kind, context, sha(payload_bytes)))
        signatures = []
        for role, key_name, signature_format in sorted(signers):
            public_key = self.keys.public(key_name)
            message = lines("peerspan-decentralized-signature-v1", statement_id, role, public_key)
            signature = (self.keys.sign(key_name, message) if signature_format == "ed25519"
                         else self.keys.sshsig(key_name, message))
            signatures.append({"role": role, "public_key": public_key,
                               "format": signature_format, "signature": b64(signature)})
        body = raw_json({"format": 1, "kind": kind, "context_id": context,
                         "payload_base64": b64(payload_bytes), "signatures": signatures})
        return PublicObject(kind, context, payload_bytes, body, statement_id)

    def alias(self, obj: PublicObject) -> PublicObject:
        body = json.dumps(json.loads(obj.body), ensure_ascii=False, indent=2, sort_keys=True).encode()
        return PublicObject(obj.kind, obj.context_id, obj.payload, body, obj.statement_id)

    def lease_payload(self, kind: str, *, person: str = "alice", host: str = "host-a",
                      device: str = "device-a", sequence: int = 1,
                      predecessors: list[str] | None = None, parents: list[dict] | None = None,
                      not_after: str = UNTIL, **changes: object) -> dict:
        subject = {"person_public_key": "-", "host_public_key": "-", "device_public_key": "-",
                   "member": "-", "scopes": 0}
        if kind in {"admin_lease", "person_lease", "binding_lease", "device_lease"}:
            subject["person_public_key"] = self.keys.public(person)
        if kind in {"host_lease", "binding_lease", "device_lease"}:
            subject["host_public_key"] = self.keys.public(host)
        if kind == "device_lease":
            subject["device_public_key"] = self.keys.public(device)
        if kind in {"person_lease", "host_lease"}:
            subject["member"] = person.capitalize()
        subject["scopes"] = {"admin_lease": 8, "binding_lease": 2, "device_lease": 15}.get(kind, 0)
        value = {"root_state_id": self.genesis.statement_id, "operation_id": "-", "sequence": sequence,
                 "predecessors": predecessors or [], "resolves": [], "retained_statement_ids": [],
                 "subject": subject, "issuer": {"kind": "root", "person_public_key": "-"},
                 "parents": sorted(parents or [], key=lambda p: p["role"]),
                 "issued_at": NOW, "not_before": NOW, "not_after": not_after}
        value.update(copy.deepcopy(changes))
        return value

    def catalog(self, objects: list[PublicObject]) -> bytes:
        return raw_json({"format": 1, "context_id": self.context_id,
                         "objects": sorted((o.entry() for o in objects), key=lambda e: e["id"])})

    def prior(self, objects: list[PublicObject], maxima: list[dict], *, root_ids: list[str] | None = None,
              restrictions: list[str] | None = None, activations: list[str] | None = None,
              clock_guard: str = NOW, admitted_ids: list[str] | None = None) -> dict:
        restricted = set(restrictions or [])
        return {"format": 1, "context_id": self.context_id, "catalog_base64": b64(self.catalog(objects)),
                "admitted_statement_ids": sorted(set(admitted_ids) if admitted_ids is not None else
                                                 {o.statement_id for o in objects if o.statement_id not in restricted}),
                "admitted_restriction_ids": sorted(restricted), "admitted_activation_ids": sorted(activations or []),
                "root_head_ids": sorted(root_ids or [self.genesis.statement_id]),
                "maxima": sorted(maxima, key=lambda row: row["stream"]),
                "migration_proposal_id": "-", "clock_guard": clock_guard}

    def access(self, kind: str, *, person: str = "alice", sequence: int = 1,
               predecessors: list[str] | None = None, resolves: list[str] | None = None,
               person_lease: PublicObject | None = None, not_after: str = UNTIL,
               issued_at: str = NOW, **changes: object) -> PublicObject:
        if kind == "policy":
            body = {"format": 2, "network_id": self.descriptor["network_id"],
                    "person_public_key": self.keys.public(person), "version": sequence,
                    "issued_at": issued_at, "valid_until": not_after, "rules": [],
                    "capability_rules": [], "trusted_hosts": [], "edits": []}
            if person_lease is None:
                raise ValueError("policy fixture needs its exact original-person parent")
            issuer = {"kind": "person", "person_public_key": self.keys.public(person)}
            parents = [{"role": "issuer_person", "id": person_lease.statement_id}]
            signers = [("issuer", person, "sshsig")]
        elif kind == "group":
            body = {"network_id": self.descriptor["network_id"], "name": "operators",
                    "version": sequence, "defined_at": issued_at, "members": []}
            issuer = {"kind": "root", "person_public_key": "-"}
            parents, signers = [], [("issuer", "root", "ed25519")]
        else:
            raise ValueError("not an access fixture kind")
        payload = {"root_state_id": self.genesis.statement_id, "operation_id": "-",
                   "sequence": sequence, "predecessors": sorted(predecessors or []),
                   "resolves": sorted(resolves or []), "issuer": issuer, "parents": parents,
                   "issued_at": issued_at, "not_before": issued_at, "not_after": not_after,
                   "body_base64": b64(raw_json(body))}
        payload.update(copy.deepcopy(changes))
        return self.statement(kind, payload, signers)

    def restriction(self, kind: str, *, person: str = "bob", host: str = "host-b",
                    issued_at: str = NOW, **changes: object) -> PublicObject:
        target = {"statement_id": "-", "person_public_key": "-", "host_public_key": "-",
                  "device_public_key": "-"}
        if kind == "person_remove":
            target["person_public_key"] = self.keys.public(person)
        elif kind == "host_revoke":
            target["host_public_key"] = self.keys.public(host)
        else:
            raise ValueError("fixture needs explicit target for this restriction")
        payload = {"root_state_id": self.genesis.statement_id,
                   "issuer": {"kind": "root", "person_public_key": "-"}, "parents": [],
                   "issued_at": issued_at, "target": target, "kept_statement_ids": [], "ratifies": "-"}
        payload.update(copy.deepcopy(changes))
        return self.statement(kind, payload, [("issuer", "root", "ed25519")])

    def packet(self, role: str, payload: dict | bytes, request_id: str, *, writer: str,
               signer: str | None, person: str = "-", issuer_id: str = "-",
               context_id: str | None = None, signature_format: str = "-") -> Packet:
        context = self.context_id if context_id is None else context_id
        payload_bytes = payload if isinstance(payload, bytes) else raw_json(payload)
        writer_key = self.keys.public(writer)
        signer_key = self.keys.public(signer) if signer else "-"
        person_key = self.keys.public(person) if person != "-" else "-"
        message = lines("peerspan-decentralized-packet-v1", context, request_id, role,
                        writer_key, signer_key, person_key, issuer_id, signature_format, sha(payload_bytes))
        packet_id = "dpk_" + sha(message)
        device_signature = authority_signature = "-"
        if role in {"request", "selection", "commit"}:
            if signer is None or signature_format != "-":
                raise ValueError("requester packet needs its exact raw device signer")
            device_signature = b64(self.keys.sign(signer, message))
        elif role != "outcome":
            if signer is None or signature_format not in {"ed25519", "sshsig"}:
                raise ValueError("authority packet needs its explicit selected format")
            authority_signature = b64(self.keys.sign(signer, message) if signature_format == "ed25519"
                                      else self.keys.sshsig(signer, message))
        value = {"format": 1, "context_id": context, "request_id": request_id, "role": role,
                 "writer_host_public_key": writer_key, "signer_public_key": signer_key,
                 "person_public_key": person_key, "issuer_id": issuer_id,
                 "payload_base64": b64(payload_bytes), "host_signature": b64(self.keys.sign(writer, message)),
                 "device_signature": device_signature, "authority_signature_format": signature_format,
                 "authority_signature": authority_signature}
        return Packet(role, raw_json(value), payload_bytes, packet_id)

    def original_link(self, *, person: str = "alice", owner_host: str = "host-a",
                      target_host: str = "host-b", target_device: str = "device-b",
                      scopes: int = 15, not_after: str = UNTIL,
                      migration_proposal_id: str = "-") -> ActivationFixture:
        """Complete existing-person/new-host ceremony; every signature is owned.

        This constructs public bytes only. It does not assert local ownership,
        admitted state, or application on any product host.
        """
        person_obj = self.statement("person_lease", self.lease_payload("person_lease", person=person),
                                    [("issuer", "root", "ed25519")])
        owner_host_obj = self.statement("host_lease", self.lease_payload("host_lease", person=person, host=owner_host),
                                        [("issuer", "root", "ed25519"), ("host", owner_host, "ed25519")])
        owner_binding = self.statement("binding_lease", self.lease_payload("binding_lease", person=person,
            host=owner_host, issuer={"kind": "person", "person_public_key": self.keys.public(person)}, parents=[
                {"role": "subject_person", "id": person_obj.statement_id},
                {"role": "issuer_person", "id": person_obj.statement_id},
                {"role": "subject_host", "id": owner_host_obj.statement_id}]),
            [("issuer", person, "sshsig"), ("host", owner_host, "ed25519")])
        request_payload = {"mode": "new", "host_public_key": self.keys.public(target_host),
                           "device_public_key": self.keys.public(target_device),
                           "request_nonce": b64(hashlib.sha256(lines("fixture-request-nonce-v1", target_host, target_device)).digest()),
                           "expected_network_id": self.descriptor["network_id"], "expected_context_id": self.context_id,
                           "expected_person_public_key": self.keys.public(person),
                           "migration_proposal_id": migration_proposal_id, "renewed_device_lease_id": "-",
                           "created_at": NOW, "expires_at": "2026-10-26T12:05:00Z"}
        request_id = "link_" + sha(lines("peerspan-decentralized-request-id-v1", sha(raw_json(request_payload))))
        request = self.packet("request", request_payload, request_id, writer=target_host,
                              signer=target_device, context_id="-")
        owner_payload = {"request_packet_id": request.packet_id, "descriptor": self.descriptor,
                         "root_state_id": self.genesis.statement_id, "person_lease_id": person_obj.statement_id,
                         "issuer_lease_ids": [person_obj.statement_id], "mode": "new", "member": person.capitalize(),
                         "host_public_key": self.keys.public(target_host), "device_public_key": self.keys.public(target_device),
                         "scopes": scopes, "not_after": not_after, "renewed_device_lease_id": "-"}
        owner = self.packet("owner", owner_payload, request_id, writer=owner_host, signer=person,
                            person=person, signature_format="sshsig")
        selection_payload = {"request_packet_id": request.packet_id, "owner_offer_id": owner.packet_id,
                             "context_id": self.context_id, "person_public_key": self.keys.public(person),
                             "host_public_key": self.keys.public(target_host), "device_public_key": self.keys.public(target_device),
                             "selected_at": NOW}
        selection = self.packet("selection", selection_payload, request_id, writer=target_host,
                                signer=target_device, person=person)
        host_obj = self.statement("host_lease", self.lease_payload("host_lease", person=person, host=target_host,
                                  operation_id=request_id, not_after=not_after), [("issuer", "root", "ed25519")])
        admin_payload = {"selection_id": selection.packet_id, "owner_offer_id": owner.packet_id,
                         "root_state_id": self.genesis.statement_id, "issuer_lease_ids": [],
                         "person_lease": person_obj.statement_id, "host_lease": json.loads(host_obj.body)}
        administrator = self.packet("administrator", admin_payload, request_id, writer=owner_host,
                                    signer="root", issuer_id=self.genesis.statement_id, signature_format="ed25519")
        binding_obj = self.statement("binding_lease", self.lease_payload("binding_lease", person=person,
            host=target_host, operation_id=request_id, not_after=not_after,
            issuer={"kind": "person", "person_public_key": self.keys.public(person)}, parents=[
                {"role": "subject_person", "id": person_obj.statement_id},
                {"role": "issuer_person", "id": person_obj.statement_id},
                {"role": "subject_host", "id": host_obj.statement_id}]),
            [("issuer", person, "sshsig"), ("host", target_host, "ed25519")])
        draft_binding = json.loads(binding_obj.body)
        for signature in draft_binding["signatures"]:
            if signature["role"] == "host":
                signature["signature"] = "-"
        device_obj = self.statement("device_lease", self.lease_payload("device_lease", person=person,
            host=target_host, device=target_device, operation_id=request_id, not_after=not_after,
            issuer={"kind": "person", "person_public_key": self.keys.public(person)}, parents=[
                {"role": "subject_person", "id": person_obj.statement_id},
                {"role": "issuer_person", "id": person_obj.statement_id},
                {"role": "subject_host", "id": host_obj.statement_id},
                {"role": "subject_binding", "id": binding_obj.statement_id}]), [("issuer", person, "sshsig")])
        device_payload = json.loads(device_obj.payload)
        device_payload["subject"]["scopes"] = scopes
        device_obj = self.statement("device_lease", device_payload, [("issuer", person, "sshsig")])
        final_payload = {"selection_id": selection.packet_id, "administrator_offer_id": administrator.packet_id,
                         "root_state_id": self.genesis.statement_id, "person_lease_id": person_obj.statement_id,
                         "host_lease_id": host_obj.statement_id, "binding_lease": draft_binding,
                         "device_lease": json.loads(device_obj.body)}
        owner_finalization = self.packet("owner_finalization", final_payload, request_id, writer=owner_host,
                                         signer=person, person=person, signature_format="sshsig")
        required_objects = [self.genesis, person_obj, host_obj, binding_obj, device_obj]
        manifest = raw_json({"format": 1, "context_id": self.context_id, "request_id": request_id,
                            "request_packet_id": request.packet_id, "owner_offer_id": owner.packet_id,
                            "selection_id": selection.packet_id, "administrator_offer_id": administrator.packet_id,
                            "owner_finalization_id": owner_finalization.packet_id,
                            "root_state_id": self.genesis.statement_id, "person_lease_id": person_obj.statement_id,
                            "host_lease_id": host_obj.statement_id, "binding_lease_id": binding_obj.statement_id,
                            "device_lease_id": device_obj.statement_id, "binding_proof_id": binding_obj.proof_id,
                            "device_proof_id": device_obj.proof_id,
                            "ancestor_statement_ids": sorted(o.statement_id for o in required_objects if o != device_obj),
                            "proof_ids": sorted(o.proof_id for o in required_objects)})
        manifest_id = "dm_" + sha(lines("peerspan-decentralized-manifest-v1", sha(manifest)))
        host_signature = next(s["signature"] for s in json.loads(binding_obj.body)["signatures"] if s["role"] == "host")
        commit = self.packet("commit", {"manifest_base64": b64(manifest), "binding_host_signature": host_signature,
                                        "committed_at": NOW}, request_id, writer=target_host, signer=target_device, person=person)
        packets = {p.role: p for p in [request, owner, selection, administrator, owner_finalization, commit]}
        body = raw_json({"format": 1, "context_id": self.context_id,
                         **{role: json.loads(packet.body) for role, packet in packets.items()}})
        activation_id = "da_" + sha(lines("peerspan-decentralized-activation-v1", self.context_id,
                                          request_id, manifest_id, commit.packet_id))
        expected = {"request_id": request_id, "context_id": self.context_id, "mode": "new",
                    "person_public_key": self.keys.public(person), "host_public_key": self.keys.public(target_host),
                    "device_public_key": self.keys.public(target_device), "renewed_device_lease_id": "-",
                    "owner_offer_id": owner.packet_id, "selection_id": selection.packet_id,
                    "administrator_offer_id": administrator.packet_id, "scopes": scopes, "not_after": not_after}
        return ActivationFixture(body, request_id, manifest_id, activation_id, manifest, packets,
                                 [self.genesis, person_obj, owner_host_obj, owner_binding],
                                 [host_obj, binding_obj, device_obj], device_obj, expected)


def changed(value: dict, **updates: object) -> dict:
    result = copy.deepcopy(value)
    result.update(updates)
    return result
