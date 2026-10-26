"""Independent DEC fixtures from reviewed merged public DEC contract pins.

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
from datetime import datetime, timedelta


PIN = "b26aefddbf92d0efd30bef9f70fb4c117ecff09d"
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


@dataclass
class MigrationFixture:
    body: bytes
    proposal: PublicObject
    root: PublicObject
    host: PublicObject
    acknowledgment: PublicObject
    commit: PublicObject
    prepared_catalog: bytes
    source_catalog: bytes
    source_state: bytes
    legacy_prior: dict
    activation: ActivationFixture | None = None


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
                                                 {o.statement_id for o in objects
                                                  if o.statement_id.startswith("ds_") and o.statement_id not in restricted}),
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
                      scopes: int = 7, not_after: str = UNTIL,
                      migration_proposal_id: str = "-", owner_packet_format: str = "sshsig",
                      root_packet_format: str = "ed25519", current_host: PublicObject | None = None,
                      administrator_role: dict | None = None,
                      additional_proof_objects: list[PublicObject] | None = None,
                      created_at: str = NOW,
                      owner_device: ActivationFixture | None = None,
                      owner_device_key: str = "device-b",
                      binding_predecessor: PublicObject | None = None,
                      binding_retained: list[PublicObject] | None = None) -> ActivationFixture:
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
        # A separate already complete ceremony may supply a same-person owner
        # device. Its exact host/binding and consent provenance are retained;
        # no freshly signed ordinary lookalike replaces its operation-bound H/B.
        if owner_device is not None:
            owner_source = {o.statement_id: o for o in owner_device.source_objects+owner_device.new_objects if o.statement_id}
            owner_roles = {r["role"]: r["id"] for r in json.loads(owner_device.device.payload)["parents"]}
            owner_host_obj = owner_source[owner_roles["subject_host"]]
            owner_binding = owner_source[owner_roles["subject_binding"]]
            if json.loads(owner_device.device.payload)["subject"]["host_public_key"] != self.keys.public(owner_host):
                raise ValueError("fixture owner device must belong to its writer host")
            if json.loads(owner_device.device.payload)["subject"]["device_public_key"] != self.keys.public(owner_device_key):
                raise ValueError("fixture owner signer must be the selected device's exact owned key")
            additional_proof_objects = list(additional_proof_objects or []) + owner_device.source_objects + owner_device.new_objects + [
                PublicObject("activation", self.context_id, b"", owner_device.body, "")]
        owner_signer = owner_device_key if owner_device is not None else person
        owner_format = "ed25519" if owner_device is not None else owner_packet_format
        owner_issuer = owner_device.device.statement_id if owner_device is not None else "-"
        owner_parents = [{"role": "issuer_device", "id": owner_issuer}] if owner_device is not None else []
        if binding_predecessor is not None:
            previous = json.loads(binding_predecessor.payload)
            if binding_predecessor.kind != "binding_lease" or previous["subject"]["person_public_key"] != self.keys.public(person) or previous["subject"]["host_public_key"] != self.keys.public(target_host):
                raise ValueError("binding predecessor must be the same exact owner and target host")
            additional_proof_objects = list(additional_proof_objects or [])+[binding_predecessor]+list(binding_retained or [])
        elif binding_retained:
            raise ValueError("a first binding generation cannot retain unrelated old statements")
        request_payload = {"mode": "new", "host_public_key": self.keys.public(target_host),
                           "device_public_key": self.keys.public(target_device),
                           "request_nonce": b64(hashlib.sha256(lines("fixture-request-nonce-v1", target_host, target_device)).digest()),
                           "expected_network_id": self.descriptor["network_id"], "expected_context_id": self.context_id,
                           "expected_person_public_key": self.keys.public(person),
                           "migration_proposal_id": migration_proposal_id, "renewed_device_lease_id": "-",
                           "created_at": created_at,
                           "expires_at": (datetime.strptime(created_at,"%Y-%m-%dT%H:%M:%SZ")+timedelta(seconds=300)).strftime("%Y-%m-%dT%H:%M:%SZ")}
        request_id = "link_" + sha(lines("peerspan-decentralized-request-id-v1", sha(raw_json(request_payload))))
        request = self.packet("request", request_payload, request_id, writer=target_host,
                              signer=target_device, context_id="-")
        owner_payload = {"request_packet_id": request.packet_id, "descriptor": self.descriptor,
                         "root_state_id": self.genesis.statement_id, "person_lease_id": person_obj.statement_id,
                         "issuer_lease_ids": sorted([person_obj.statement_id]+([owner_issuer] if owner_device is not None else [])), "mode": "new", "member": person.capitalize(),
                         "host_public_key": self.keys.public(target_host), "device_public_key": self.keys.public(target_device),
                         "scopes": scopes, "not_after": not_after, "renewed_device_lease_id": "-"}
        owner = self.packet("owner", owner_payload, request_id, writer=owner_host, signer=owner_signer,
                            person=person, issuer_id=owner_issuer, signature_format=owner_format)
        selection_payload = {"request_packet_id": request.packet_id, "owner_offer_id": owner.packet_id,
                             "context_id": self.context_id, "person_public_key": self.keys.public(person),
                             "host_public_key": self.keys.public(target_host), "device_public_key": self.keys.public(target_device),
                             "selected_at": created_at}
        selection = self.packet("selection", selection_payload, request_id, writer=target_host,
                                signer=target_device, person=person)
        host_obj = current_host if current_host is not None else self.statement("host_lease",
            self.lease_payload("host_lease", person=person, host=target_host, operation_id=request_id,
                               not_after=not_after,issued_at=created_at,not_before=created_at),
            [("issuer", "root", "ed25519")])
        administrator_identity = administrator_role or {"writer": owner_host, "signer": "root", "person": "-",
            "issuer_id": self.genesis.statement_id, "signature_format": root_packet_format, "issuer_lease_ids": []}
        admin_payload = {"selection_id": selection.packet_id, "owner_offer_id": owner.packet_id,
                         "root_state_id": self.genesis.statement_id,
                         "issuer_lease_ids": sorted(administrator_identity["issuer_lease_ids"]),
                         "person_lease": person_obj.statement_id,
                         "host_lease": host_obj.statement_id if current_host is not None else json.loads(host_obj.body)}
        administrator = self.packet("administrator", admin_payload, request_id,
            **{k:v for k,v in administrator_identity.items() if k != "issuer_lease_ids"})
        binding_obj = self.statement("binding_lease", self.lease_payload("binding_lease", person=person,
            host=target_host, operation_id=request_id, not_after=not_after, issued_at=created_at,not_before=created_at,
            sequence=(json.loads(binding_predecessor.payload)["sequence"]+1 if binding_predecessor is not None else 1),
            predecessors=([binding_predecessor.statement_id] if binding_predecessor is not None else []),
            retained_statement_ids=sorted(o.statement_id for o in binding_retained or []),
            issuer={"kind": "device" if owner_device is not None else "person", "person_public_key": self.keys.public(person)}, parents=owner_parents+[
                {"role": "subject_person", "id": person_obj.statement_id},
                {"role": "issuer_person", "id": person_obj.statement_id},
                {"role": "subject_host", "id": host_obj.statement_id}]),
            [("issuer", owner_signer, owner_format), ("host", target_host, "ed25519")])
        draft_binding = json.loads(binding_obj.body)
        for signature in draft_binding["signatures"]:
            if signature["role"] == "host":
                signature["signature"] = "-"
        device_obj = self.statement("device_lease", self.lease_payload("device_lease", person=person,
            host=target_host, device=target_device, operation_id=request_id, not_after=not_after,issued_at=created_at,not_before=created_at,
            issuer={"kind": "device" if owner_device is not None else "person", "person_public_key": self.keys.public(person)}, parents=owner_parents+[
                {"role": "subject_person", "id": person_obj.statement_id},
                {"role": "issuer_person", "id": person_obj.statement_id},
                {"role": "subject_host", "id": host_obj.statement_id},
                {"role": "subject_binding", "id": binding_obj.statement_id}]), [("issuer", owner_signer, owner_format)])
        device_payload = json.loads(device_obj.payload)
        device_payload["subject"]["scopes"] = scopes
        device_obj = self.statement("device_lease", device_payload, [("issuer", owner_signer, owner_format)])
        final_payload = {"selection_id": selection.packet_id, "administrator_offer_id": administrator.packet_id,
                         "root_state_id": self.genesis.statement_id, "person_lease_id": person_obj.statement_id,
                         "host_lease_id": host_obj.statement_id, "binding_lease": draft_binding,
                         "device_lease": json.loads(device_obj.body)}
        owner_finalization = self.packet("owner_finalization", final_payload, request_id, writer=owner_host,
                                         signer=owner_signer, person=person, issuer_id=owner_issuer, signature_format=owner_format)
        required_objects = [self.genesis, person_obj, host_obj, binding_obj, device_obj]
        if owner_device is not None or binding_predecessor is not None:
            # Public107 literal statement-reference closure, including the
            # selected owner's predecessor and retained-child provenance.
            source = {o.statement_id: o for o in required_objects+(additional_proof_objects or []) if o.statement_id}
            if owner_device is not None:
                required_objects += [owner_host_obj, owner_binding, owner_device.device]
            source.update({o.statement_id:o for o in required_objects})
            reached, todo = set(), [o.statement_id for o in required_objects]
            while todo:
                current = todo.pop()
                if current in reached:
                    continue
                reached.add(current)
                obj = source[current]
                payload = json.loads(obj.payload)
                refs = [payload.get("root_state_id", "-"), payload.get("ratifies", "-"),
                        payload.get("target", {}).get("statement_id", "-")]
                refs += [p["id"] for p in payload.get("parents", [])]
                for field in ("predecessors", "resolves", "retained_statement_ids", "kept_statement_ids"):
                    refs += payload.get(field, [])
                todo += [r for r in refs if r != "-"]
            required_objects = [source[identifier] for identifier in sorted(reached)]
        manifest = raw_json({"format": 1, "context_id": self.context_id, "request_id": request_id,
                            "request_packet_id": request.packet_id, "owner_offer_id": owner.packet_id,
                            "selection_id": selection.packet_id, "administrator_offer_id": administrator.packet_id,
                            "owner_finalization_id": owner_finalization.packet_id,
                            "root_state_id": self.genesis.statement_id, "person_lease_id": person_obj.statement_id,
                            "host_lease_id": host_obj.statement_id, "binding_lease_id": binding_obj.statement_id,
                            "device_lease_id": device_obj.statement_id, "binding_proof_id": binding_obj.proof_id,
                            "device_proof_id": device_obj.proof_id,
                            "ancestor_statement_ids": sorted(o.statement_id for o in required_objects if o != device_obj),
                            "proof_ids": sorted({o.proof_id for o in required_objects+(additional_proof_objects or [])})})
        manifest_id = "dm_" + sha(lines("peerspan-decentralized-manifest-v1", sha(manifest)))
        host_signature = next(s["signature"] for s in json.loads(binding_obj.body)["signatures"] if s["role"] == "host")
        commit = self.packet("commit", {"manifest_base64": b64(manifest), "binding_host_signature": host_signature,
                                        "committed_at": created_at}, request_id, writer=target_host, signer=target_device, person=person)
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
                                 [self.genesis, person_obj, owner_host_obj, owner_binding]
                                 +([current_host] if current_host is not None else [])+(additional_proof_objects or []),
                                 ([host_obj] if current_host is None else [])+[binding_obj, device_obj], device_obj, expected)

    def retaining_device_renewal(self, old: ActivationFixture, child: ActivationFixture, *, scopes: int = 7) -> ActivationFixture:
        """Original owner narrows D15 to D7 while retaining an already live child.

        Unchanged exact current P/H/B skip administrator/new-binding stages.
        Retained old D, child B and child D keep their signed bytes and ceilings;
        the device replacement contributes only its narrowed effective scopes.
        """
        now = "2026-10-26T12:00:02Z"
        p = old.source_objects[1]
        h, b, old_d = old.new_objects
        _, child_b, child_d = child.new_objects
        request_payload = {"mode": "renew", "host_public_key": self.keys.public("host-b"),
            "device_public_key": self.keys.public("device-b"),
            "request_nonce": b64(hashlib.sha256(b"independent-retained-device-scope-renewal-v1" if scopes == 7 else
                lines("independent-retained-device-scope-renewal-v1", scopes)).digest()),
            "expected_network_id": self.descriptor["network_id"], "expected_context_id": self.context_id,
            "expected_person_public_key": self.keys.public("alice"), "migration_proposal_id": "-",
            "renewed_device_lease_id": old_d.statement_id, "created_at": now, "expires_at": "2026-10-26T12:05:02Z"}
        request_id = "link_"+sha(lines("peerspan-decentralized-request-id-v1", sha(raw_json(request_payload))))
        request = self.packet("request", request_payload, request_id, writer="host-b", signer="device-b", context_id="-")
        owner = self.packet("owner", {"request_packet_id": request.packet_id, "descriptor": self.descriptor,
            "root_state_id": self.genesis.statement_id, "person_lease_id": p.statement_id, "issuer_lease_ids": [p.statement_id],
            "mode": "renew", "member": "Alice", "host_public_key": self.keys.public("host-b"),
            "device_public_key": self.keys.public("device-b"), "scopes": scopes, "not_after": UNTIL,
            "renewed_device_lease_id": old_d.statement_id}, request_id, writer="host-a", signer="alice",
            person="alice", signature_format="sshsig")
        selection = self.packet("selection", {"request_packet_id": request.packet_id, "owner_offer_id": owner.packet_id,
            "context_id": self.context_id, "person_public_key": self.keys.public("alice"),
            "host_public_key": self.keys.public("host-b"), "device_public_key": self.keys.public("device-b"),
            "selected_at": now}, request_id, writer="host-b", signer="device-b", person="alice")
        d_payload = self.lease_payload("device_lease", host="host-b", device="device-b", sequence=2,
            predecessors=[old_d.statement_id], operation_id=request_id, issued_at=now, not_before=now,
            retained_statement_ids=sorted([old_d.statement_id, child_b.statement_id, child_d.statement_id]),
            issuer={"kind": "person", "person_public_key": self.keys.public("alice")}, parents=[
                {"role": "issuer_person", "id": p.statement_id}, {"role": "subject_person", "id": p.statement_id},
                {"role": "subject_host", "id": h.statement_id}, {"role": "subject_binding", "id": b.statement_id}])
        d_payload["subject"]["scopes"] = scopes
        d = self.statement("device_lease", d_payload, [("issuer", "alice", "sshsig")])
        finalization = self.packet("owner_finalization", {"selection_id": selection.packet_id,
            "administrator_offer_id": "-", "root_state_id": self.genesis.statement_id, "person_lease_id": p.statement_id,
            "host_lease_id": h.statement_id, "binding_lease": b.statement_id, "device_lease": json.loads(d.body)},
            request_id, writer="host-a", signer="alice", person="alice", signature_format="sshsig")
        history = old.source_objects+old.new_objects+child.source_objects+child.new_objects+[
            PublicObject("activation", self.context_id, b"", old.body, ""),
            PublicObject("activation", self.context_id, b"", child.body, "")]
        source = sorted({o.proof_id:o for o in history}.values(), key=lambda o:o.proof_id)
        # Every dependency of old D and the retained child's signed B/D is exact;
        # owner writer convenience H/B is source evidence but no device ancestor.
        ancestors = [self.genesis, p, h, b, old_d, child.new_objects[0], child_b, child_d]
        manifest = raw_json({"format": 1, "context_id": self.context_id, "request_id": request_id,
            "request_packet_id": request.packet_id, "owner_offer_id": owner.packet_id, "selection_id": selection.packet_id,
            "administrator_offer_id": "-", "owner_finalization_id": finalization.packet_id,
            "root_state_id": self.genesis.statement_id, "person_lease_id": p.statement_id, "host_lease_id": h.statement_id,
            "binding_lease_id": b.statement_id, "device_lease_id": d.statement_id, "binding_proof_id": b.proof_id,
            "device_proof_id": d.proof_id, "ancestor_statement_ids": sorted(o.statement_id for o in ancestors),
            "proof_ids": sorted(o.proof_id for o in source+[d])})
        manifest_id = "dm_"+sha(lines("peerspan-decentralized-manifest-v1", sha(manifest)))
        commit = self.packet("commit", {"manifest_base64": b64(manifest), "binding_host_signature": "-", "committed_at": now},
            request_id, writer="host-b", signer="device-b", person="alice")
        packets = {pkt.role:pkt for pkt in [request, owner, selection, finalization, commit]}
        body = raw_json({"format": 1, "context_id": self.context_id, "request": json.loads(request.body),
            "owner": json.loads(owner.body), "selection": json.loads(selection.body), "administrator": "-",
            "owner_finalization": json.loads(finalization.body), "commit": json.loads(commit.body)})
        activation_id = "da_"+sha(lines("peerspan-decentralized-activation-v1", self.context_id,
            request_id, manifest_id, commit.packet_id))
        expected = {"request_id": request_id, "context_id": self.context_id, "mode": "renew",
            "person_public_key": self.keys.public("alice"), "host_public_key": self.keys.public("host-b"),
            "device_public_key": self.keys.public("device-b"), "renewed_device_lease_id": old_d.statement_id,
            "owner_offer_id": owner.packet_id, "selection_id": selection.packet_id, "administrator_offer_id": "-",
            "scopes": scopes, "not_after": UNTIL}
        return ActivationFixture(body, request_id, manifest_id, activation_id, manifest, packets, source, [d], d, expected)

    def unbound_migration(self, *, nonce_name: str = "unbound-migration",
                          source_state_size: int | None = None,
                          host_not_after: str = UNTIL) -> MigrationFixture:
        """Public all-host cutover from one unbound legacy admitted host.

        It exercises the independently specified pre-feature source and avoids
        inventing an owner, device, activation, feature or coordinator receipt.
        """
        network = self.descriptor["network_id"]
        host_key = self.keys.public("host-a")
        legacy_descriptor = raw_json({"network_id": network, "name": self.descriptor["name"],
            "genesis_root_public_key": self.keys.public("root"), "coordinator_address": "legacy.example:443",
            "coordinator_public_key": self.keys.public("legacy-coordinator")})
        admission = {"network_id": network, "epoch": 0, "host_public_key": host_key,
                     "member": "Alice", "admitted_at": BEFORE}
        admission["signature"] = b64(self.keys.sign("root", lines("peerspan-host-admit-v1", network,
            0, host_key, "Alice", BEFORE)))
        admission_body = raw_json(admission)
        old_proof = "pf_"+sha(lines("peerspan-link-proof-v1", "host_admission", sha(admission_body)))
        source_catalog = raw_json({"format": 1, "network_id": network,
            "objects": [{"id": old_proof, "kind": "host_admission", "body_base64": b64(admission_body)}]})
        source_state = raw_json({"format": 1, "network_id": network, "legacy_root_highwater": 0,
            "known_admitted_hosts": [host_key], "access_maxima": [], "admitted_restrictions": []})
        if source_state_size is not None:
            if source_state_size < len(source_state):
                raise ValueError("requested source snapshot size is smaller than its fixed fields")
            # JSON whitespace is part of the exact signed/hash-pinned source.
            # All proposal/ACK/root/commit dependencies below are independently
            # regenerated for these bytes, without a mismatched-hash shortcut.
            source_state += b" " * (source_state_size - len(source_state))
        proposal = self.statement("migration_proposal", {
            "proposal_nonce": b64(hashlib.sha256(lines("fixture-migration-proposal-nonce-v1", nonce_name)).digest()),
            "legacy_descriptor_base64": b64(legacy_descriptor), "legacy_feature_id": "-", "legacy_epoch": 0,
            "legacy_root_public_key": self.keys.public("root"), "source_catalog_sha256": sha(source_catalog),
            "source_state_sha256": sha(source_state), "new_descriptor": self.descriptor,
            "roster": [{"host_public_key": host_key, "member": "Alice", "person_public_key": "-",
                        "device_public_key": "-", "scopes": 0}], "issued_at": NOW, "expires_at": UNTIL},
            [("issuer", "root", "ed25519")])
        root = self.statement("root_state", changed(self.genesis_payload, migration_proposal_id=proposal.statement_id),
                              [("issuer", "root", "ed25519")])
        host = self.statement("host_lease", self.lease_payload("host_lease", root_state_id=root.statement_id,
            operation_id=proposal.statement_id, not_after=host_not_after),
            [("issuer", "root", "ed25519"), ("host", "host-a", "ed25519")])
        prepared_catalog = self.catalog([proposal, root, host])
        acknowledgment = self.statement("migration_ack", {"proposal_id": proposal.statement_id,
            "root_state_id": root.statement_id, "prepared_catalog_sha256": sha(prepared_catalog),
            "host_public_key": host_key, "person_public_key": "-", "device_public_key": "-",
            "host_lease_id": host.statement_id, "binding_lease_id": "-", "device_lease_id": "-", "activation_id": "-",
            "acknowledged_at": NOW}, [("host", "host-a", "ed25519")])
        commit = self.statement("migration_commit", {"proposal_id": proposal.statement_id,
            "root_state_id": root.statement_id, "prepared_catalog_sha256": sha(prepared_catalog),
            "acknowledgment_ids": [acknowledgment.statement_id], "committed_at": NOW}, [("issuer", "root", "ed25519")])
        body = raw_json({"format": 1, "proposal": json.loads(proposal.body), "source_catalog_base64": b64(source_catalog),
            "source_state_base64": b64(source_state), "prepared_catalog_base64": b64(prepared_catalog),
            "acknowledgments": [json.loads(acknowledgment.body)], "commit": json.loads(commit.body)})
        legacy_prior = {"format": 1, "legacy_descriptor_base64": b64(legacy_descriptor),
            "legacy_catalog_base64": b64(source_catalog), "legacy_feature_id": "-", "legacy_epoch": 0,
            "legacy_root_public_key": self.keys.public("root"), "source_state_base64": b64(source_state),
            "clock_guard": NOW, "pending_operation_ids": [], "acknowledged_proposal_id": proposal.statement_id,
            "acknowledged_prepared_sha256": sha(prepared_catalog), "acknowledgment_base64": b64(acknowledgment.body),
            "adopted_context_id": "-", "adopted_proposal_id": "-"}
        return MigrationFixture(body, proposal, root, host, acknowledgment, commit,
                                prepared_catalog, source_catalog, source_state, legacy_prior)

    def owned_migration(self) -> MigrationFixture:
        """One genuinely bound legacy host, same owner/host and a reviewed D.

        The legacy person admission/binding use the public coordination
        statement messages.  No legacy device bridge or asserted source owner
        is used.  All new device power has the complete original-key ceremony.
        """
        base = self.unbound_migration(nonce_name="owned-migration")
        network, host_key, person_key = self.descriptor["network_id"], self.keys.public("host-a"), self.keys.public("alice")
        admission = {"network_id": network, "epoch": 0, "person_public_key": person_key,
                     "member": "Alice", "admitted_at": BEFORE}
        admission["signature"] = b64(self.keys.sign("root", lines("peerspan-person-admit-v1",
            network, 0, person_key, "Alice", BEFORE)))
        binding_message = lines("peerspan-host-bind-v1", network, person_key, host_key, BEFORE)
        binding = {"network_id": network, "person_public_key": person_key, "host_public_key": host_key,
                   "bound_at": BEFORE, "signature": b64(self.keys.sshsig("alice", binding_message)),
                   "host_signature": b64(self.keys.sign("host-a", binding_message))}
        source = json.loads(base.source_catalog)
        for kind, body in [("person_admission", admission), ("host_binding", binding)]:
            raw = raw_json(body)
            source["objects"].append({"id": "pf_" + sha(lines("peerspan-link-proof-v1", kind, sha(raw))),
                                      "kind": kind, "body_base64": b64(raw)})
        source["objects"].sort(key=lambda o:o["id"])
        source_catalog = raw_json(source)
        proposal_payload = json.loads(base.proposal.payload)
        proposal_payload["source_catalog_sha256"] = sha(source_catalog)
        proposal_payload["roster"] = [{"host_public_key": host_key, "member": "Alice",
            "person_public_key": person_key, "device_public_key": self.keys.public("device-a"), "scopes": 7}]
        proposal = self.statement("migration_proposal", proposal_payload, [("issuer", "root", "ed25519")])
        root = self.statement("root_state", changed(self.genesis_payload, migration_proposal_id=proposal.statement_id),
                              [("issuer", "root", "ed25519")])
        staged = copy.copy(self)
        staged.genesis, staged.genesis_payload = root, json.loads(root.payload)
        activation = staged.original_link(owner_host="host-a", target_host="host-a", target_device="device-a",
                                          migration_proposal_id=proposal.statement_id)
        # Only the shared ordinary P and ceremony's exact H/B/D are prepared.
        # The same host is its own original-key owner machine; unrelated
        # ordinary owner H/B conveniences must not create parallel seq1 heads.
        prepared = [proposal, root, activation.source_objects[1], *activation.new_objects,
                    PublicObject("activation", self.context_id, b"", activation.body, "")]
        prepared_catalog = self.catalog(prepared)
        host, bound, device = activation.new_objects
        acknowledgment = self.statement("migration_ack", {"proposal_id": proposal.statement_id,
            "root_state_id": root.statement_id, "prepared_catalog_sha256": sha(prepared_catalog),
            "host_public_key": host_key, "person_public_key": person_key,
            "device_public_key": self.keys.public("device-a"), "host_lease_id": host.statement_id,
            "binding_lease_id": bound.statement_id, "device_lease_id": device.statement_id,
            "activation_id": activation.activation_id, "acknowledged_at": NOW},
            [("host", "host-a", "ed25519"), ("device", "device-a", "ed25519")])
        commit = self.statement("migration_commit", {"proposal_id": proposal.statement_id,
            "root_state_id": root.statement_id, "prepared_catalog_sha256": sha(prepared_catalog),
            "acknowledgment_ids": [acknowledgment.statement_id], "committed_at": NOW}, [("issuer", "root", "ed25519")])
        body = raw_json({"format": 1, "proposal": json.loads(proposal.body), "source_catalog_base64": b64(source_catalog),
            "source_state_base64": b64(base.source_state), "prepared_catalog_base64": b64(prepared_catalog),
            "acknowledgments": [json.loads(acknowledgment.body)], "commit": json.loads(commit.body)})
        legacy_prior = changed(base.legacy_prior, legacy_catalog_base64=b64(source_catalog),
            acknowledged_proposal_id=proposal.statement_id, acknowledged_prepared_sha256=sha(prepared_catalog),
            acknowledgment_base64=b64(acknowledgment.body))
        return MigrationFixture(body, proposal, root, host, acknowledgment, commit, prepared_catalog,
                                source_catalog, base.source_state, legacy_prior, activation)

    def renewal_after_expired_target(self, *, host_from_this_ceremony: bool = False
                                     ) -> tuple[ActivationFixture, ActivationFixture]:
        """Two-operation DAG: old short target, fresh ordinary H/B, renewed D.

        The original owner authorizes renewal; the expired target supplies only
        identity/PoP history.  Unchanged independently current P/H/B are exact
        references, so neither an admin packet nor a new binding consent exists.
        """
        old = self.original_link(scopes=7, not_after="2026-10-26T12:00:01Z")
        now = "2026-10-26T12:00:02Z"
        p = old.source_objects[1]
        old_h, old_b, old_d = old.new_objects
        request_payload = {"mode": "renew", "host_public_key": self.keys.public("host-b"),
            "device_public_key": self.keys.public("device-b"),
            "request_nonce": b64(hashlib.sha256(b"independent-renew-after-expired-target-v1").digest()),
            "expected_network_id": self.descriptor["network_id"], "expected_context_id": self.context_id,
            "expected_person_public_key": self.keys.public("alice"), "migration_proposal_id": "-",
            "renewed_device_lease_id": old_d.statement_id, "created_at": now, "expires_at": "2026-10-26T12:05:02Z"}
        request_id = "link_"+sha(lines("peerspan-decentralized-request-id-v1", sha(raw_json(request_payload))))
        h = self.statement("host_lease", self.lease_payload("host_lease", host="host-b", sequence=2,
            predecessors=[old_h.statement_id], issued_at=now, not_before=now,
            operation_id=request_id if host_from_this_ceremony else "-"),
            [("issuer", "root", "ed25519")] if host_from_this_ceremony else
            [("issuer", "root", "ed25519"), ("host", "host-b", "ed25519")])
        b = self.statement("binding_lease", self.lease_payload("binding_lease", host="host-b", sequence=2,
            predecessors=[old_b.statement_id], issued_at=now, not_before=now,
            issuer={"kind": "person", "person_public_key": self.keys.public("alice")}, parents=[
                {"role": "issuer_person", "id": p.statement_id}, {"role": "subject_person", "id": p.statement_id},
                {"role": "subject_host", "id": h.statement_id}]),
            [("issuer", "alice", "sshsig"), ("host", "host-b", "ed25519")])
        request = self.packet("request", request_payload, request_id, writer="host-b", signer="device-b", context_id="-")
        owner = self.packet("owner", {"request_packet_id": request.packet_id, "descriptor": self.descriptor,
            "root_state_id": self.genesis.statement_id, "person_lease_id": p.statement_id, "issuer_lease_ids": [p.statement_id],
            "mode": "renew", "member": "Alice", "host_public_key": self.keys.public("host-b"),
            "device_public_key": self.keys.public("device-b"), "scopes": 7, "not_after": UNTIL,
            "renewed_device_lease_id": old_d.statement_id}, request_id, writer="host-a", signer="alice",
            person="alice", signature_format="sshsig")
        selection = self.packet("selection", {"request_packet_id": request.packet_id, "owner_offer_id": owner.packet_id,
            "context_id": self.context_id, "person_public_key": self.keys.public("alice"),
            "host_public_key": self.keys.public("host-b"), "device_public_key": self.keys.public("device-b"),
            "selected_at": now}, request_id, writer="host-b", signer="device-b", person="alice")
        d_payload = self.lease_payload("device_lease", host="host-b", device="device-b", sequence=2,
            predecessors=[old_d.statement_id], operation_id=request_id, issued_at=now, not_before=now,
            issuer={"kind": "person", "person_public_key": self.keys.public("alice")}, parents=[
                {"role": "issuer_person", "id": p.statement_id}, {"role": "subject_person", "id": p.statement_id},
                {"role": "subject_host", "id": h.statement_id}, {"role": "subject_binding", "id": b.statement_id}])
        d_payload["subject"]["scopes"] = 7
        d = self.statement("device_lease", d_payload, [("issuer", "alice", "sshsig")])
        finalization = self.packet("owner_finalization", {"selection_id": selection.packet_id,
            "administrator_offer_id": "-", "root_state_id": self.genesis.statement_id, "person_lease_id": p.statement_id,
            "host_lease_id": h.statement_id, "binding_lease": b.statement_id, "device_lease": json.loads(d.body)},
            request_id, writer="host-a", signer="alice", person="alice", signature_format="sshsig")
        old_proof = PublicObject("activation", self.context_id, b"", old.body, "")
        source_objects = old.source_objects+old.new_objects+[old_proof, h, b]
        required = [self.genesis, p, old_h, old_b, old_d, h, b, d]
        manifest = raw_json({"format": 1, "context_id": self.context_id, "request_id": request_id,
            "request_packet_id": request.packet_id, "owner_offer_id": owner.packet_id, "selection_id": selection.packet_id,
            "administrator_offer_id": "-", "owner_finalization_id": finalization.packet_id,
            "root_state_id": self.genesis.statement_id, "person_lease_id": p.statement_id, "host_lease_id": h.statement_id,
            "binding_lease_id": b.statement_id, "device_lease_id": d.statement_id, "binding_proof_id": b.proof_id,
            "device_proof_id": d.proof_id, "ancestor_statement_ids": sorted(o.statement_id for o in required if o != d),
            "proof_ids": sorted([o.proof_id for o in required]+[old_proof.proof_id])})
        manifest_id = "dm_"+sha(lines("peerspan-decentralized-manifest-v1", sha(manifest)))
        commit = self.packet("commit", {"manifest_base64": b64(manifest), "binding_host_signature": "-", "committed_at": now},
            request_id, writer="host-b", signer="device-b", person="alice")
        packets = {pkt.role: pkt for pkt in [request, owner, selection, finalization, commit]}
        body = raw_json({"format": 1, "context_id": self.context_id, "request": json.loads(request.body),
            "owner": json.loads(owner.body), "selection": json.loads(selection.body), "administrator": "-",
            "owner_finalization": json.loads(finalization.body), "commit": json.loads(commit.body)})
        activation_id = "da_"+sha(lines("peerspan-decentralized-activation-v1", self.context_id,
                                       request_id, manifest_id, commit.packet_id))
        expected = {"request_id": request_id, "context_id": self.context_id, "mode": "renew",
            "person_public_key": self.keys.public("alice"), "host_public_key": self.keys.public("host-b"),
            "device_public_key": self.keys.public("device-b"), "renewed_device_lease_id": old_d.statement_id,
            "owner_offer_id": owner.packet_id, "selection_id": selection.packet_id, "administrator_offer_id": "-",
            "scopes": 7, "not_after": UNTIL}
        return old, ActivationFixture(body, request_id, manifest_id, activation_id, manifest, packets,
                                       source_objects, [d], d, expected)


def changed(value: dict, **updates: object) -> dict:
    result = copy.deepcopy(value)
    result.update(updates)
    return result
