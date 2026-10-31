#!/usr/bin/env python3
"""Slim suite 5, delivery: the five delivery paths of a join request and the optional helper.

Two hosts, erin and finn, advertise only dead addresses and list one `peerspan-helper` as their mailbox
helper and relay, so they cannot reach each other directly: every stage travels through the helper's
mailboxes, the finished activation through the relay, and later work through the relay too. The suite also
talks to the first-contact listener and the helper as an outsider, over TLS with a throwaway Ed25519 key.
Written from docs/decentralized-spec.md section 9 and the wire appendix sections 10 to 14, 17 and 18.
"""
import base64
import hashlib
import json
import os
import socket
import ssl
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone

from harness import (Clock, Suite, attention, check, create_network, finalize, free_port, invite, join_request, link_view,
                     pull_until, rfc3339, select, commit, ssh_key, wait_for, wait_linked)

suite = Suite("delivery", __doc__)
state = {}
HELPER = suite.host_bin.parent / "peerspan-helper"


def need(*names):
    missing = [n for n in names if n not in state]
    check(not missing, f"an earlier case did not finish ({', '.join(missing)} missing)")
    return [state[n] for n in names]


def report_join_failure(committed, requester, inviter, request_id):
    """Failure-only, closed public evidence (GU.impl27f); never print raw responses."""
    unknown = "unknown"
    states = {"pending", "needs_selection", "needs_administrator", "needs_owner_finalization",
              "needs_commit", "finalizing", "linked", "cancelled", "expired", "blocked"}
    stages = ("request_created", "owner_offered", "owner_selected", "administrator_offered",
              "owner_finalized", "commit_persisted", "locally_applied")

    def enum(value, allowed):
        return value if isinstance(value, str) and value in allowed else unknown

    def present(value, prefix):
        if value == "-":
            return False
        if (isinstance(value, str) and value.startswith(prefix) and len(value) == len(prefix) + 64
                and all(c in "0123456789abcdef" for c in value[len(prefix):])):
            return True
        return unknown

    def summarize(status, response):
        response = response if isinstance(response, dict) else {}
        request = response.get("request", response)
        request = request if isinstance(request, dict) else {}
        review = response.get("review")
        review = review if isinstance(review, dict) else {}
        completed = request.get("completed")
        attention_values = request.get("attention")
        return {
            "http_status": status if type(status) is int and 100 <= status <= 599 else unknown,
            "state": enum(request.get("state"), states),
            "stage": enum(review.get("stage"), {"selection", "commit"}),
            "completed": [enum(item, stages) for item in completed[:7]]
            if isinstance(completed, list) else unknown,
            "attention": [enum(item, {"delivery_pending"}) for item in attention_values[:32]]
            if isinstance(attention_values, list) else unknown,
            "retained": {field: present(request.get(field), prefix) for field, prefix in (
                ("request_packet_id", "dpk_"), ("owner_offer_id", "dpk_"),
                ("selection_id", "dpk_"), ("administrator_offer_id", "dpk_"),
                ("owner_finalization_id", "dpk_"), ("manifest_id", "dm_"),
                ("activation_id", "da_"), ("outcome_id", "dpk_"))},
            "selection_approved": request.get("selection_approved")
            if type(request.get("selection_approved")) is bool else unknown,
            "commit_approved": request.get("commit_approved")
            if type(request.get("commit_approved")) is bool else unknown,
            "locally_applied": "locally_applied" in completed
            if isinstance(completed, list) else unknown,
        }

    summary = {"commit": summarize(200, committed)}
    for role, host in (("requester", requester), ("inviter", inviter)):
        try:
            status, response = host.api("GET", f"/v2/link/requests/{request_id}", timeout=2)
            summary[role] = summarize(status, response)
        except Exception:
            summary[role] = summarize(unknown, None)
    print("join_failure_public=" + json.dumps(summary, sort_keys=True), flush=True)


def install_join_timing(host):
    """Enable existing debug observations on daemons only, including restarts."""
    original_start = host.start
    def start():
        original_env = host.extra_env
        host.extra_env = {**original_env, "PEERSPAN_TIMING": "1"}
        try:
            return original_start()
        finally:
            host.extra_env = original_env
    host.start = start


def join_timing_offsets(requester, inviter):
    offsets = {}
    for role, host in (("requester", requester), ("inviter", inviter)):
        try:
            offsets[role] = (host.log, host.log.stat().st_size)
        except Exception:
            offsets[role] = None
    return offsets


def report_join_details(committed, requester, inviter, request_id, offsets):
    """GU.impl33f: bounded failure-only projections; never drive or repair work."""
    import re
    import sqlite3
    unknown = "unknown"
    codes = {"-", "invalid", "forbidden", "not_found", "state_conflict", "operation_conflict", "quota_exceeded",
             "expired", "rate_limited", "transport_unavailable", "authority_expired", "proof_required", "internal"}
    frame_roles = {"request", "owner", "selection", "administrator", "owner_finalization", "commit", "outcome", "proofs"}

    def enum(value, values):
        return value if type(value) is str and value in values else unknown

    def count(value, maximum=65536):
        return value if type(value) is int and 0 <= value <= maximum else unknown

    def obj(value, limit=262144):
        if type(value) is not str or len(value.encode()) > limit:
            raise ValueError
        def pairs(items):
            result = dict(items)
            if len(result) != len(items):
                raise ValueError
            return result
        def invalid(_):
            raise ValueError
        result = json.loads(value, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
        if type(result) is not dict:
            raise ValueError
        return result

    def binary(value, maximum=131072):
        if type(value) is not str or len(value) > 4 * ((maximum + 2) // 3):
            raise ValueError
        decoded = base64.b64decode(value, validate=True)
        if len(decoded) > maximum or base64.b64encode(decoded).decode() != value:
            raise ValueError
        return decoded

    def version(record, fields):
        if set(record) != set(fields.split()) or type(record.get("format")) is not int or record["format"] != 1:
            raise ValueError
        return record

    def canonical_key(value):
        return len(binary(value, 32)) == 32

    def helper_match(address, public_key):
        if type(address) is not str or not 1 <= len(address) <= 260 or not address.isascii() or not canonical_key(public_key):
            return unknown
        return address == helper.address and public_key == helper.public_key

    def when(value):
        if type(value) is not str or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value):
            raise ValueError
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def code_category(value):
        if type(value) is not str or len(value) > 4096:
            return unknown
        if value == "delivery_pending":
            return value
        if value in {"transport_recovery_required", "recovery_required"}:
            return "recovery_required"
        if value in {"transport_quota_exceeded", "quota_exceeded"}:
            return "quota_exceeded"
        if re.search(r"(?<![a-z_])transport_unavailable(?![a-z_])", value):
            return "transport_unavailable"
        for category, markers in (("timeout", ("timeout", "timed out")),
            ("connection_refused", ("connection refused",)), ("connection_reset", ("connection reset", "reset by peer")),
            ("tls", ("tls", "certificate", "handshake")), ("quic", ("quic",)),
            ("relay", ("relay",)), ("unreachable", ("unreachable", "no route to host"))):
            if any(marker in value.lower() for marker in markers):
                return category
        return unknown

    def database(host, other, role):
        summary = {"participant": role, "state": unknown, "pending": unknown, "outcome": unknown,
                   "frames": unknown, "outbox_scope": "network_candidates", "outbox_count": unknown, "outbox": unknown,
                   "contacts": unknown, "stored_helpers": unknown}
        path = host.state / "host.db"
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=1)
        try:
            db.execute("BEGIN")
            now = host.now()
            row = db.execute("SELECT deadline,CASE WHEN length(record)<=262144 THEN record ELSE NULL END,"
                "length(secret),length(terminal_read_cap) FROM dec_pending WHERE request_id=?", (request_id,)).fetchone()
            if row is not None:
                pending = {"present": True, "terminal": unknown, "roles": unknown, "request_expired": unknown,
                    "secret_present": row[2] == 16 if row[2] in (None, 16) else unknown,
                    "read_cap_present": row[3] == 32 if row[3] in (None, 32) else unknown,
                    "outcome_present": unknown, "carriers": unknown, "outbound_frames": unknown}
                try:
                    pending["request_expired"] = when(row[0]) <= now
                    record = version(obj(row[1]), "format roles mode migration_proposal_id expected_network_id expected_context_id "
                        "expected_person_public_key contact_invitation_base64 descriptor_base64 host_public_key device_public_key request_nonce "
                        "request_packet_base64 owner_packet_base64 selection_packet_base64 administrator_packet_base64 owner_finalization_packet_base64 "
                        "commit_packet_base64 outcome_packet_base64 catalog_base64 owner_offer_id selection_id administrator_offer_id owner_finalization_id "
                        "manifest_id activation_id selection_approved commit_approved owner_intent_id administrator_intent_id selection_intent_id "
                        "commit_intent_id terminal carrier_endpoints outbound_frames")
                    pending["terminal"] = enum(record.get("terminal"), {"-", "applied", "cancelled", "expired", "stopped", "migration_prepared", "migration_adopted"})
                    roles = record.get("roles")
                    if type(roles) is list and len(roles) <= 3:
                        pending["roles"] = [enum(item, {"requester", "owner", "administrator"}) for item in roles]
                    outcome = record.get("outcome_packet_base64")
                    pending["outcome_present"] = False if outcome == "-" else bool(binary(outcome))
                    carriers = record.get("carrier_endpoints")
                    if type(carriers) is list and len(carriers) <= 32:
                        pending["carriers"] = [{"kind": enum(item.get("kind"), {"helper", "participant"}),
                            "matches_fixture_helper": helper_match(item.get("address"), item.get("public_key")),
                            "is_other_participant": item.get("public_key") == other.public_key if canonical_key(item.get("public_key")) else unknown}
                            if type(item) is dict and set(item) == {"kind", "address", "public_key"} else unknown for item in carriers]
                    outbound = record.get("outbound_frames")
                    if type(outbound) is list and len(outbound) <= 64:
                        groups = {}
                        for frame in outbound:
                            if (type(frame) is not dict or set(frame) != {"role", "writer_public_key", "frame_id", "acknowledged_by"}
                                    or type(frame.get("acknowledged_by")) is not list or len(frame["acknowledged_by"]) > 32):
                                raise ValueError
                            name = enum(frame.get("role"), frame_roles)
                            group = groups.setdefault(name, {"role": name, "count": 0, "helper_ack_count": 0,
                                "participant_ack_count": 0, "unknown_ack_count": 0})
                            group["count"] += 1
                            for ack in frame["acknowledged_by"]:
                                if type(ack) is not dict or set(ack) != {"address", "public_key"}:
                                    raise ValueError
                                category = "helper_ack_count" if ack.get("address") == helper.address and ack.get("public_key") == helper.public_key else (
                                    "participant_ack_count" if ack.get("public_key") in (host.public_key, other.public_key) else "unknown_ack_count")
                                group[category] += 1
                        pending["outbound_frames"] = [groups[key] for key in sorted(groups)][:9]
                except Exception:
                    pass
                summary["pending"] = pending
            else:
                summary["pending"] = {"present": False}
            outcomes = db.execute("SELECT locally_applied,CASE WHEN length(record)<=262144 THEN record ELSE NULL END "
                "FROM dec_operations WHERE network_id=? AND request_id=? LIMIT 2", (state.get("net"), request_id)).fetchall()
            summary["outcome"] = {"selected_count": len(outcomes), "locally_applied": unknown, "outcome_present": unknown}
            if len(outcomes) == 1:
                summary["outcome"]["locally_applied"] = True if type(outcomes[0][0]) is int and outcomes[0][0] == 1 else unknown
                try:
                    record = version(obj(outcomes[0][1]), "format activation_base64 catalog_base64 outcome_packet_base64 applied_at")
                    summary["outcome"]["outcome_present"] = bool(binary(record["outcome_packet_base64"]))
                except Exception:
                    pass
            frames = db.execute("SELECT role,writer_key FROM dec_frames WHERE request_id=? ORDER BY role,writer_key,frame_id LIMIT 65", (request_id,)).fetchall()
            frame_counts = {}
            for name, writer in frames[:64]:
                key = (enum(name, frame_roles), "local" if writer == host.public_key else "other" if writer == other.public_key else unknown)
                frame_counts[key] = frame_counts.get(key, 0) + 1
            summary["frames"] = {"count": len(frames) if len(frames) < 65 else unknown,
                "categories": [{"role": key[0], "writer_role": key[1], "count": value} for key, value in sorted(frame_counts.items())][:16]}
            summary["outbox_count"] = count(db.execute("SELECT count(*) FROM dec_outbox WHERE network_id=?", (state.get("net"),)).fetchone()[0], 4096)
            deliveries = db.execute("SELECT target_key,CASE WHEN length(record)<=262144 THEN record ELSE NULL END "
                "FROM dec_outbox WHERE network_id=? ORDER BY delivery_id LIMIT 8", (state.get("net"),)).fetchall()
            summary["outbox"] = []
            for target, encoded in deliveries:
                item = {"kind": unknown, "target_role": "other" if target == other.public_key else "local" if target == host.public_key else unknown,
                        "request_matches": unknown, "attempts": unknown, "retry_due": unknown, "error_code": unknown}
                try:
                    delivery = version(obj(encoded), "format kind body_base64 proof_ids created_at attempts next_attempt_at last_error_code last_error_detail")
                    item["kind"] = enum(delivery.get("kind"), {"proofs", "activation", "migration"})
                    if item["kind"] == "activation":
                        body = obj(binary(delivery["body_base64"]).decode())
                        if set(body) != {"activation", "catalog"} or type(body["activation"]) is not dict:
                            raise ValueError
                        activation = version(body["activation"], "format context_id request owner selection administrator owner_finalization commit")
                        packet = activation["request"]
                        if type(packet) is not dict or not re.fullmatch(r"link_[0-9a-f]{64}", packet.get("request_id", "")):
                            raise ValueError
                        item["request_matches"] = packet["request_id"] == request_id
                    if item["request_matches"] is True:
                        item.update(attempts=count(delivery.get("attempts"), 2**64 - 1),
                            retry_due=when(delivery.get("next_attempt_at")) <= now,
                            error_code=enum(delivery.get("last_error_code"), codes))
                except Exception:
                    pass
                summary["outbox"].append(item)
            contacts = db.execute("SELECT network_id,context_id,host_key,CASE WHEN length(record)<=65536 THEN record ELSE NULL END "
                "FROM dec_contacts WHERE network_id IN (?,'-') AND host_key IN (?,?) ORDER BY network_id,context_id,host_key LIMIT 8",
                (state.get("net"), host.public_key, other.public_key)).fetchall()
            summary["contacts"] = []
            for network, context_id, key, encoded in contacts:
                item = {"host_role": "local" if key == host.public_key else "other", "context_role": "unbound" if network == context_id == "-" else (
                            "bound_network" if network == state.get("net") and type(context_id) is str and re.fullmatch(r"ctx_[0-9a-f]{64}", context_id) else unknown),
                        "conflicted": unknown, "contact_count": unknown, "bodies": unknown}
                try:
                    record = version(obj(encoded, 65536), "format message_hashes conflicted contacts_base64")
                    item["conflicted"] = record.get("conflicted") if type(record.get("conflicted")) is bool else unknown
                    bodies = record.get("contacts_base64")
                    if type(bodies) is not list or len(bodies) > 2:
                        raise ValueError
                    item["contact_count"] = len(bodies); item["bodies"] = []
                    for encoded_body in bodies:
                        body = version(obj(binary(encoded_body, 8192).decode(), 8192),
                            "format context_id host_public_key sequence issued_at expires_at payload_base64 signature")
                        if body["context_id"] != context_id or body["host_public_key"] != key:
                            raise ValueError
                        payload = obj(binary(body["payload_base64"], 8192).decode(), 8192)
                        if set(payload) != {"quic_addresses", "bootstrap_addresses", "relays"}:
                            raise ValueError
                        relays = payload.get("relays")
                        item["bodies"].append({"expired": when(body["expires_at"]) <= now,
                            "relay_hint_count": count(len(relays), 8) if type(relays) is list else unknown,
                            "has_fixture_relay": any(type(relay) is dict and relay.get("address") == helper.address and relay.get("public_key") == helper.public_key
                                for relay in relays) if type(relays) is list and len(relays) <= 8 else unknown})
                except Exception:
                    pass
                summary["contacts"].append(item)
            rows = db.execute("SELECT kind,address,public_key,CASE WHEN length(record)<=4096 THEN record ELSE NULL END "
                              "FROM dec_helpers ORDER BY kind,address,public_key LIMIT 16").fetchall()
            summary["stored_helpers"] = []
            for kind, address, public_key, encoded in rows:
                enabled = unknown
                try:
                    record = version(obj(encoded, 4096), "format enabled")
                    if type(record.get("enabled")) is bool:
                        enabled = record["enabled"]
                except Exception:
                    pass
                summary["stored_helpers"].append({"kind": enum(kind, {"rendezvous", "relay"}), "enabled": enabled,
                    "matches_fixture_helper": helper_match(address, public_key)})
            summary["state"] = "observed"
        finally:
            db.close()
        return summary

    def timing(captured, role):
        """Request-class metadata is a log-context tag, never caller attribution."""
        summary = {"participant": role, "state": unknown, "spans": unknown, "unrecognized_count": unknown, "read_limit_reached": unknown}
        if captured is None:
            return summary
        path, offset = captured
        if type(offset) is not int or offset < 0:
            return summary
        with path.open("rb") as stream:
            stream.seek(offset); data = stream.read(65536)
        groups = {}; unrecognized = 0
        for line in data.decode(errors="replace").splitlines():
            match = re.fullmatch(r"timing #(0|[1-9][0-9]{0,19}) (peer|serve|step|cli|total) (.{1,4096}) ([0-9]{1,9}(?:\.[0-9]{1,6})?)(?:\s*ms)?", line.strip()) if len(line) <= 4096 else None
            if match is None:
                unrecognized += 1; continue
            number, kind, what, duration = match.groups()
            if kind not in {"peer", "serve"}:
                continue
            duration = float(duration)
            if not 0 <= duration <= 600000:
                unrecognized += 1; continue
            routes = re.findall(r"(?:^|\s)(/(?:bootstrap|v2)/[^\s]*)", what)
            route = routes[0].split("?", 1)[0] if len(routes) == 1 else None
            route_class = "completion" if route == "/bootstrap/v1/activations" or (route is not None and re.fullmatch(r"/bootstrap/v1/operations/link_[0-9a-f]{64}", route)) else (
                "local_resume" if route is not None and re.fullmatch(r"/v2/link/requests/link_[0-9a-f]{64}/resume", route) else "other")
            status = re.findall(r"(?:^|\s)(?:status=|HTTP(?:/1\.[01])?\s+)([1-5][0-9]{2})(?:\s|$)", what)
            if not status and kind == "serve":
                status = re.findall(r"(?:^|\s)([1-5][0-9]{2})$", what)
            status = int(status[0]) if len(status) == 1 else unknown
            key = ("background" if number == "0" else "served", route_class, status)
            group = groups.setdefault(key, {"count": 0, "duration_total_ms": 0.0, "duration_max_ms": 0.0})
            group["count"] += 1; group["duration_total_ms"] = min(1000000000.0, group["duration_total_ms"] + duration)
            group["duration_max_ms"] = max(group["duration_max_ms"], duration)
        summary.update(state="observed" if groups else unknown, unrecognized_count=unrecognized, read_limit_reached=len(data) == 65536,
            spans=[{"request_class": key[0], "route_class": key[1], "http_status": key[2], "count": value["count"],
                    "duration_total_ms": round(value["duration_total_ms"], 3), "duration_max_ms": round(value["duration_max_ms"], 3)}
                for key, value in sorted(groups.items(), key=lambda item: json.dumps(item[0]))[:16]] if groups else unknown)
        return summary

    try:
        values = committed.get("attention") if type(committed) is dict else None
        summary = {"commit_attention": [code_category(value) for value in values[:32]] if type(values) is list else unknown,
                   "participants": []}
        for role, host, other in (("requester", requester, inviter), ("inviter", inviter, requester)):
            item = {"participant": role, "database": unknown, "timing": unknown}
            try:
                item["database"] = database(host, other, role)
            except Exception:
                pass
            try:
                item["timing"] = timing(offsets.get(role), role)
            except Exception:
                pass
            summary["participants"].append(item)
        print("join_failure_details_public=" + json.dumps(summary, sort_keys=True), flush=True)
    except Exception:
        pass  # Extra diagnostic observations cannot mask the original wait exception.


def H(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()


def L(*parts):
    return "\n".join(parts)


# An outsider: a TLS client key of our own (it proves possession at TLS, spec 9.1), and Ed25519 signatures made
# with it through openssl.

class Key:
    def __init__(self, name):
        self.dir = suite.work / f"key-{name}"
        self.dir.mkdir()
        self.key, self.cert = self.dir / "key.pem", self.dir / "cert.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(self.key)], check=True,
                       capture_output=True)
        subprocess.run(["openssl", "req", "-x509", "-key", str(self.key), "-out", str(self.cert), "-subj", "/CN=slim",
                        "-days", "2"], check=True, capture_output=True)
        der = subprocess.run(["openssl", "pkey", "-in", str(self.key), "-pubout", "-outform", "DER"], check=True,
                             capture_output=True).stdout
        self.public = base64.b64encode(der[-32:]).decode()

    def sign(self, message):
        path = self.dir / "message"
        path.write_bytes(message.encode())
        out = subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(self.key), "-in", str(path)],
                             check=True, capture_output=True).stdout
        return base64.b64encode(out).decode()

    def tls(self, address, alpn, timeout=15):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # we pin nothing here: these cases test the server side
        context.load_cert_chain(str(self.cert), str(self.key))
        context.set_alpn_protocols([alpn])
        host, port = address.rsplit(":", 1)
        raw = socket.create_connection((host, int(port)), timeout=timeout)
        return context.wrap_socket(raw, server_hostname="peerspan")

    def http(self, address, method, path, body=None, headers=(), raw_body=None, paced=True):
        """One HTTP/1.1 request on peerspan-bootstrap/1; returns (status, decoded JSON or text, header text).

        PACED waits out a 429 (the listener's rates, appendix 21) and asks again, so a case that is not about
        rates is not refused by them."""
        for _ in range(12):
            status, value, top = self._http(address, method, path, body, headers, raw_body)
            if status != 429 or not paced:
                break
            wait = next((line.split(":", 1)[1].strip() for line in top.splitlines()
                         if line.lower().startswith("retry-after:")), "1")
            time.sleep(min(float(wait) if wait.isdigit() else 1.0, 5.0))
        return status, value, top

    def _http(self, address, method, path, body, headers, raw_body):
        s = self.tls(address, "peerspan-bootstrap/1")
        data = raw_body if raw_body is not None else (b"" if body is None else json.dumps(body).encode())
        head = f"{method} {path} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Length: {len(data)}\r\n"
        if data:
            head += "Content-Type: application/json\r\n"
        for name, value in headers:
            head += f"{name}: {value}\r\n"
        s.sendall(head.encode() + b"\r\n" + data)
        out = b""
        try:
            while chunk := s.recv(65536):
                out += chunk
        except (ConnectionError, ssl.SSLError):
            pass
        s.close()
        top, _, payload = out.partition(b"\r\n\r\n")
        check(top.startswith(b"HTTP/1.1 "), f"{method} {path}: not an HTTP response: {out[:80]!r}")
        try:
            value = json.loads(payload) if payload.strip() else None
        except ValueError:
            value = payload.decode(errors="replace")
        return int(top.split()[1]), value, top.decode(errors="replace")


class Mailbox:
    """One opaque mailbox (appendix 11 and 12), written by KEY; the ciphertext is random bytes, which only the
    two participants could tell from real frames."""

    def __init__(self, key, address, seconds=600):
        self.key, self.address = key, address
        secret = base64.b64encode(os.urandom(16)).decode()
        self.locator = H(L("peerspan-decentralized-locator-v1", secret))
        self.cap = H(L("peerspan-decentralized-read-cap-v1", secret))
        self.request_id = "link_" + os.urandom(32).hex()
        now = datetime.now(timezone.utc)
        self.created_at, self.expires_at = rfc3339(now), rfc3339(now + timedelta(seconds=seconds))

    def frame(self, role="request", writer=None, frame_id=None, ciphertext=None):
        writer = writer or self.key
        frame_id = frame_id or os.urandom(32).hex()
        ciphertext = ciphertext or os.urandom(48)
        ad = L("peerspan-decentralized-frame-v1", self.request_id, self.locator, role, writer.public, frame_id,
               self.created_at, self.expires_at)
        signature = writer.sign(L("peerspan-decentralized-frame-envelope-v1", ad, H(ciphertext)))
        return {"format": 1, "request_id": self.request_id, "locator": self.locator, "role": role,
                "writer_host_public_key": writer.public, "frame_id": frame_id, "created_at": self.created_at,
                "expires_at": self.expires_at, "ciphertext_base64": base64.b64encode(ciphertext).decode(),
                "signature": signature}

    def auth(self, cap=None):
        return [("Authorization", f"Bearer {cap or self.cap}")]

    def create(self, frame=None, cap=None, paced=True):
        self.first = frame or self.frame()
        body = {"format": 1, "request_id": self.request_id, "locator": self.locator, "read_cap_hash": H(self.cap),
                "created_at": self.created_at, "expires_at": self.expires_at, "frame": self.first}
        return self.key.http(self.address, "POST", "/bootstrap/v1/mailboxes", body, self.auth(cap), paced=paced)

    def append(self, frame):
        return self.key.http(self.address, "POST", f"/bootstrap/v1/mailboxes/{self.locator}/frames", {"frame": frame},
                             self.auth())

    def read(self, cap=None, headers=None, paced=True):
        return self.key.http(self.address, "GET", f"/bootstrap/v1/mailboxes/{self.locator}", None,
                             self.auth(cap) if headers is None else headers, paced=paced)

    def delete(self):
        return self.key.http(self.address, "DELETE", f"/bootstrap/v1/mailboxes/{self.locator}", None, self.auth())


# The helper process.

class Helper:
    def __init__(self, name, tokens=None, clock=None):
        self.dir = suite.work / name
        self.dir.mkdir(mode=0o700)
        self.tokens, self.clock = tokens, clock
        self.start()

    def start(self):
        args = [str(HELPER), "--state", str(self.dir), "serve", "--listen", "127.0.0.1:0"]
        if self.tokens is not None:
            path = self.dir / "tokens.json"
            path.write_text(json.dumps({"format": 1, "accounts": [{"id": "slim", "tokens": sorted(
                base64.b64encode(t.encode()).decode() for t in self.tokens)}]}))
            path.chmod(0o600)
            args += ["--tokens-file", str(path)]
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.dir)}
        if self.clock is not None:
            env["PEERSPAN_TEST_CLOCK_OFFSET_FILE"] = str(self.clock.path)
        self.process = suite.spawn(args, stdout=subprocess.PIPE, stderr=(self.dir / "helper.log").open("ab"), env=env)
        line = self.process.stdout.readline()
        check(line, f"{self.dir.name}: serve printed nothing")
        self.listen = json.loads(line)
        self.address, self.public_key = self.listen["address"], self.listen["public_key"]

    def pin(self):
        return {"address": self.address, "public_key": self.public_key, "token_file": "-"}


def relay_frame(kind, payload=b""):
    return bytes([kind]) + len(payload).to_bytes(2, "big") + payload


def read_frame(s):
    head = b""
    while len(head) < 3:
        chunk = s.recv(3 - len(head))
        if not chunk:
            return None
        head += chunk
    n = int.from_bytes(head[1:3], "big")
    body = b""
    while len(body) < n:
        chunk = s.recv(n - len(body))
        if not chunk:
            return None
        body += chunk
    return head[0], body


def closed_after(s, limit):
    """Seconds until the peer closes S (reads nothing more), or None if it stays open for LIMIT seconds."""
    began = time.monotonic()
    s.settimeout(limit)
    try:
        while s.recv(4096):
            pass
    except socket.timeout:
        return None
    except (ConnectionError, ssl.SSLError, OSError):
        pass
    return time.monotonic() - began


def probe(state_dir, host, path, alpn, method="GET", body=None):
    args = [str(suite.probe_bin), "--address", host.peer_address, "--alpn", alpn, "--path", path, "--method", method]
    args += ["--state", str(state_dir)] if state_dir else ["--seed-hex", os.urandom(32).hex()]
    if body is not None:
        args.append("--body-stdin")
    p = subprocess.run(args, input=(body or "").encode(), capture_output=True, timeout=45)
    try:
        return json.loads(p.stdout)
    except ValueError:
        return {"exit": p.returncode, "stderr": p.stderr.decode(errors="replace")[-200:]}


helper = Helper("helper-one")
outsider = Key("outsider")
dead_tcp, dead_udp = free_port(socket.SOCK_STREAM), free_port()


def transport(host, helpers, publish=False):
    """A transport file (appendix 17) that advertises only dead addresses, so peers find no direct path."""
    path = host.root / "transport.json"
    path.write_text(json.dumps({
        "format": 1, "advertise_bootstrap": [f"127.0.0.1:{dead_tcp}"], "advertise_quic": [f"127.0.0.1:{dead_udp}"],
        "rendezvous": [h.pin() for h in helpers], "relays": [h.pin() for h in helpers], "publish_contacts": publish}))
    path.chmod(0o600)
    host.extra_args = ["--transport-config", str(path)]


e, f = suite.host("erin", start=False), suite.host("finn", start=False)
for _h in (e, f):
    transport(_h, [helper])
    install_join_timing(_h)
    _h.start()


# Slow bounds run in the background from the start and are reported at the end.
background = {}


idle_key = Key("idle")


def idle_relay_connection():
    s = idle_key.tls(helper.address, "peerspan-relay/4")
    s.sendall(relay_frame(0x00))
    got = read_frame(s)
    background["idle_auth"] = got
    background["idle_closed_after"] = closed_after(s, 90)


def silent_bootstrap_connection():
    raw = socket.create_connection(("127.0.0.1", e.bootstrap_port), timeout=30)
    background["handshake_closed_after"] = closed_after(raw, 20)


def _run(target):
    try:
        target()
    except Exception as error:  # noqa: BLE001 - reported by the case
        background[target.__name__ + "_error"] = error


threads = [threading.Thread(target=_run, args=(t,), daemon=True)
           for t in (idle_relay_connection, silent_bootstrap_connection)]
for _t in threads:
    _t.start()


@suite.case("helper_serve_and_info", "spec 9.7; appendix 18")
def _():
    check(helper.listen["protocols"] == ["peerspan-bootstrap/1", "peerspan-relay/4"], f"serve printed {helper.listen}")
    check(len(base64.b64decode(helper.public_key)) == 32, "the helper key is not 32 bytes")
    info = subprocess.run([str(HELPER), "--state", str(helper.dir), "info"], capture_output=True, timeout=30)
    check(info.returncode == 0, f"info: exit {info.returncode}")
    check(json.loads(info.stdout) == {"public_key": helper.public_key, "protocols": helper.listen["protocols"]},
          f"info printed {info.stdout[:200]!r}")
    empty = suite.work / "helper-never-served"
    empty.mkdir(mode=0o700)
    info = subprocess.run([str(HELPER), "--state", str(empty), "info"], capture_output=True, timeout=30)
    check(info.returncode != 0 and not any(empty.iterdir()), "info on a fresh directory created a key or state")
    check(not any(p.name.endswith(".db") and "host" in p.name for p in helper.dir.iterdir()),
          "the helper opened a host database")


@suite.case("join_with_no_direct_path", "spec 9.2, 9.3, 9.6; 8.1; 20 items 29, 42")
def _():
    net = create_network(e, "nodirect", "erin")
    state["net"] = net["id"]
    made = invite(e, "finn", net["id"])
    payload = json.loads(base64.b64decode(json.loads(base64.urlsafe_b64decode(
        made["invitation"][5:] + "=" * (-len(made["invitation"][5:]) % 4)))["payload_base64"]))
    check([h["public_key"] for h in payload["helpers"]] == [helper.public_key], f"invite helpers {payload['helpers']}")
    key = ssh_key(f.root, "finn")
    state["finn_key"] = key
    request = join_request(f, made["invitation"], key)
    rid, code = request["request_id"], request["display_code"]
    state["rid"] = rid
    try:  # the automatic return through the helper (spec 8.1 step 4)
        wait_for(lambda: any(v["request_id"] == rid for v in e.api("GET", "/v2/link/requests")[1]), timeout=5)
        state["returned"] = True
    except AssertionError:
        state["returned"] = False
    f.ok_incomplete("link", "approve", "--network", net["id"], "--person-key", key, "--code-stdin", "--approve",
                    input=code + "\n")
    view = pull_until(f, rid, "owner_offer_id", timeout=45)
    if view["state"] == "needs_selection":
        select(f, view)
    view = link_view(f, rid)
    e.ok_incomplete("link", "admit", "--network", net["id"], "--owner-offer", view["owner_offer_id"], "--selection",
                    view["selection_id"], "--person", view["person_public_key"], "--expect-host-key",
                    view["host_public_key"], "--expect-device-key", view["device_public_key"], "--code-stdin",
                    "--approve", input=code + "\n")
    view = pull_until(f, rid, "administrator_offer_id", timeout=60)
    finalize(f, view, key)
    view = pull_until(f, rid, "owner_finalization_id", timeout=60)
    join_offsets = join_timing_offsets(f, e)
    committed = commit(f, view)
    # Neither host can reach the other's first-contact listener (both advertise a dead one), so the activation
    # can only arrive over QUIC completion through the relay (path 3).
    try:
        wait_linked(f, e, rid, timeout=60)
    except Exception:
        try:
            report_join_failure(committed, f, e, rid)
        except Exception:
            pass  # Diagnostic errors must never mask the original wait failure.
        try:
            report_join_details(committed, f, e, rid, join_offsets)
        except Exception:
            pass  # Preserve the existing public diagnostic and original wait failure.
        raise
    members = {m["host_public_key"] for m in e.api("GET", f"/v2/networks/{net['id']}/members")[1]["members"]}
    check(f.public_key in members, "erin does not list finn after the join")
    state["linked"] = True


@suite.case("request_returns_through_helper", "spec 8.1 step 4 (DEC-Q3); 20 item 29")
def _():
    (returned,) = need("returned")
    check(returned, "the join request never reached the inviter through the helper's return mailbox")


@suite.case("work_through_relay", "spec 9.6: two hosts with no direct path use a relay both reach")
def _():
    net, _ = need("net", "linked")
    fay = f.agent("fay")
    f.ok("allow", "erin", "--person-key", state["finn_key"])
    sent = e.ok("send", "finn/fay", "through the relay")
    check(sent["state"] == "accepted", f"send through the relay: {sent['state']}")
    got = fay.next_message(timeout=30)
    check(got["request"]["content"] == "through the relay", f"fay got {got['request']}")
    path = e.ok("peer", "path", f.id)
    check(path["path"] == "relay", f"erin's path to finn after the message: {path}")


@suite.case("first_contact_serves_only_bootstrap_routes", "spec 9.1, 3; 20 item 40")
def _():
    address = f"127.0.0.1:{e.bootstrap_port}"
    net = state.get("net", "net_" + "0" * 64)
    for path in ("/v1/host", "/v2/status", "/v2/networks", f"/peer/v2/networks/{net}/catalog",
                 f"/repair/v1/networks/{net}/catalog", "/adapter/v1/session", "/"):
        status, body, _ = outsider.http(address, "GET", path)
        check(status == 404, f"GET {path} on the first-contact listener: {status} {body}")
    status, _, _ = outsider.http(address, "GET", "/bootstrap/v1/mailboxes/" + "0" * 64)
    check(status == 403, f"a mailbox read without a read capability: {status}, want 403")
    try:
        s = outsider.tls(address, "peerspan-peer/1")
        alpn = s.selected_alpn_protocol()
        s.close()
        check(alpn is None, f"the first-contact listener accepted ALPN {alpn}")
    except (ssl.SSLError, ConnectionError, OSError):
        pass  # refused during the handshake: as specified


@suite.case("mailbox_lifecycle", "spec 9.2; appendix 11, 12; 20 item 41")
def _():
    for where, address in (("helper", helper.address), ("host", f"127.0.0.1:{e.bootstrap_port}")):
        box = Mailbox(outsider, address)
        status, body, _ = box.create()
        check(status == 201 and body == {"request_id": box.request_id, "locator": box.locator},
              f"{where}: create: {status} {body}")
        status, _, _ = box.create(box.first)
        check(status == 200, f"{where}: the same create again: {status}, want 200")
        status, body, _ = box.read()
        check(status == 200 and [fr["frame_id"] for fr in body["frames"]] == [box.first["frame_id"]]
              and body["frames"][0]["ciphertext_base64"] == box.first["ciphertext_base64"],
              f"{where}: read: {status} {body}")
        second = box.frame("owner")
        status, body, _ = box.append(second)
        check(status == 200 and body == {"frame_id": second["frame_id"]}, f"{where}: append: {status} {body}")
        status, _, _ = box.append(second)
        check(status == 200, f"{where}: the same frame again: {status}, want 200")
        status, body, _ = box.append(box.frame("owner", frame_id=second["frame_id"]))
        check(status == 409, f"{where}: the same frame ID with other bytes: {status} {body}, want 409")
        stranger = Key(f"stranger-{where}")
        status, body, _ = box.append(box.frame("selection", writer=stranger))
        check(status == 403, f"{where}: a frame written by another key than the TLS client: {status}, want 403")
        status, _, _ = box.read(cap="f" * 64)
        check(status == 403, f"{where}: a wrong read capability: {status}, want 403")
        status, _, _ = box.read(headers=[])
        check(status == 403, f"{where}: no read capability: {status}, want 403")
        status, _, _ = box.read(headers=[("Authorization", "Bearer not-hex")])
        check(status == 400, f"{where}: a malformed read capability: {status}, want 400")
        status, _, _ = box.read(headers=box.auth() + box.auth())
        check(status == 400, f"{where}: two Authorization headers: {status}, want 400")
        status, body, _ = box.read()
        roles = [fr["role"] for fr in body["frames"]]
        check(roles == sorted(roles) and len(roles) == 2, f"{where}: frames after the refusals: {roles}")
        status, _, _ = box.delete()
        check(status == 204, f"{where}: delete: {status}, want 204")
        status, _, _ = box.delete()
        check(status == 204, f"{where}: delete again: {status}, want 204")
        status, _, _ = box.read()
        check(status == 404, f"{where}: read after delete: {status}, want 404")
        status, _, _ = box.create(box.first)
        check(status == 410, f"{where}: create on a tombstone: {status}, want 410")


@suite.case("mailbox_expiry_and_tombstone", "spec 9.2 (DEC-Q1); appendix 12")
def _():
    clock = Clock(suite.work / "helper-clock-offset")
    clocked = Helper("helper-clock", clock=clock)  # on its own debug test clock (developer guide)
    box = Mailbox(outsider, clocked.address, seconds=120)
    status, body, _ = box.create()
    check(status == 201, f"create: {status} {body}")
    status, _, _ = box.read()
    check(status == 200, f"read inside the window: {status}")
    clock.set(125)
    status, _, _ = box.read()
    check(status == 410, f"read after the window: {status}, want 410")
    status, _, _ = box.append(box.frame("owner"))
    check(status == 410, f"append after the window: {status}, want 410")
    status, _, _ = box.create(box.first)
    check(status == 410, f"create on the expired box's tombstone: {status}, want 410")
    late = Mailbox(outsider, clocked.address, seconds=60)  # its window ended by the helper's clock
    status, _, _ = late.create()
    check(status == 410, f"create of a mailbox whose window has passed: {status}, want 410")


@suite.case("mailbox_quota_and_rates", "spec 9.2 limits; appendix 12, 21; 20 item 41")
def _():
    key = Key("quota")
    boxes = [Mailbox(key, helper.address) for _ in range(5)]
    results = [b.create()[:2] for b in boxes]
    check(all(s == 201 for s, _ in results[:4]), f"the first four mailboxes: {[s for s, _ in results[:4]]}")
    status, body = results[4]
    check(status == 409 and isinstance(body, dict) and body.get("code") == "quota_exceeded",
          f"a fifth active mailbox for one client key: {status} {body}, want 409 quota_exceeded")
    reads = []
    for _ in range(8):
        status, body, head = boxes[0].read(paced=False)
        reads.append(status)
        if status == 429:
            check("retry-after:" in head.lower(), "a 429 without Retry-After")
            check(body.get("code") == "rate_limited", f"429 body {body}")
            break
    check(429 in reads, f"eight reads at once (rate 1/s, burst 4) all answered: {reads}")
    for b in boxes[:4]:
        b.delete()


@suite.case("completion_routes_participants_only", "spec 9.3, 9.4; appendix 13; 20 items 42, 43")
def _():
    rid, _ = need("rid", "linked")
    address = f"127.0.0.1:{e.bootstrap_port}"
    status, body, _ = outsider.http(address, "GET", f"/bootstrap/v1/operations/{rid}")
    check(status == 403, f"a non-participant reading the outcome over HTTP: {status} {body}, want 403")
    status, body, _ = outsider.http(address, "POST", "/bootstrap/v1/activations", {"activation": {}, "catalog": {}})
    check(status in (400, 403), f"a non-participant posting an activation: {status}, want 403 (or 400 invalid)")
    status, body, _ = outsider.http(helper.address, "GET", f"/bootstrap/v1/operations/{rid}")
    check(status == 404, f"the helper serving a completion route: {status}, want 404")
    first = probe(f.state, e, f"/bootstrap/v1/operations/{rid}", "peerspan-completion/1")
    check(first.get("status") == 200 and first["body"]["outcome"], f"finn reading the outcome over QUIC: {first}")
    again = probe(f.state, e, f"/bootstrap/v1/operations/{rid}", "peerspan-completion/1")
    check(again == first, "a repeated outcome read differs from the first")
    stranger = probe(None, e, f"/bootstrap/v1/operations/{rid}", "peerspan-completion/1")
    check(stranger.get("status") == 403, f"a non-participant over QUIC completion: {stranger}, want 403")
    check(not str(stranger.get("body", "")).count("activation"), "a non-participant was shown the activation")


@suite.case("resume_resends_and_reports_transport", "spec 9.5; 20 item 44")
def _():
    rid, _ = need("rid", "linked")
    began = time.monotonic()
    status, view = f.api("POST", f"/v2/link/requests/{rid}/resume", {})
    check(status == 200 and view["state"] == "linked", f"resume of an applied request: {status} {view}")
    check(time.monotonic() - began <= 35, f"resume took {time.monotonic() - began:.0f}s, want within 30 s")
    check(not view.get("attention"), f"resume with erin reachable reports {view.get('attention')}")
    e.stop()
    try:
        status, view = f.api("POST", f"/v2/link/requests/{rid}/resume", {}, timeout=90)
        check(status == 200 and view["state"] == "linked", f"resume with no path: {status} {view}, want 200 linked")
        kinds, _ = attention(f)
        transport_items = [k for k in kinds if "transport" in f"{k[0]} {k[1]}".lower()]
        check(view.get("attention") or transport_items,
              f"resume with erin stopped shows no transport attention (view {view.get('attention')}, status {kinds})")
        check(f.api("GET", "/v2/networks")[1][0]["id"] == state["net"], "finn lost the network after a failed resume")
    finally:
        e.start()


@suite.case("helper_replacement_changes_no_record", "spec 9.6, 9.8; 1 (helpers are optional); 20 item 46")
def _():
    net, _ = need("net", "linked")

    def records(host):
        return sorted(o["proof_id"] if "proof_id" in o else json.dumps(o, sort_keys=True)
                      for o in host.api("GET", f"/v2/networks/{net}/catalog")[1]["catalog"]["objects"])

    def view(host):
        v = host.api("GET", f"/v2/networks/{net}")[1]
        return {k: v[k] for k in ("id", "context_id", "root_state_id", "root_public_key", "member", "host_public_key")}

    before = {h.name: (records(h), view(h)) for h in (e, f)}
    second = Helper("helper-two")
    for h, helpers in ((f, [second]), (e, [])):  # finn moves to a new helper; erin drops hers
        h.stop()
        transport(h, helpers)
        h.start()
    after = {h.name: (records(h), view(h)) for h in (e, f)}
    for name in before:
        check(before[name][1] == after[name][1], f"{name}'s network view changed with the helpers")
        check(set(before[name][0]) <= set(after[name][0]), f"{name} lost records when its helpers changed")
    added = {n: set(after[n][0]) - set(before[n][0]) for n in after}
    check(not any(added.values()), f"changing helpers added records: {added}")


@suite.case("publish_contacts_true_refused", "spec 9.8 (DEC-Q20); appendix 17; 20 item 46")
def _():
    g = suite.host("gail", start=False)
    transport(g, [helper], publish=True)
    log = (g.root / "daemon.log").open("ab")
    p = suite.spawn([str(suite.host_bin), "--state", str(g.state), "run", "--peer-listen", g.peer_address,
                     "--bootstrap-listen", f"127.0.0.1:{g.bootstrap_port}", *g.extra_args],
                    stdout=log, stderr=log, env=g.env)
    try:
        code = p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        code = None
    if code is None:  # still running: it must at least refuse to use the file
        g.process = p
        made = g.cli("network", "create", "gail", "--as", "gail")
        hand_out = g.cli("invite", "x", "--network", made.json["id"]) if made.ok and made.json else made
        check(not hand_out.ok, "a daemon started with publish_contacts:true and handed out an invite with it")
    else:
        check(code != 0, "a daemon given publish_contacts:true exited 0")


@suite.case("relay_auth_and_replacement", "spec 9.6; appendix 14; 20 item 45")
def _():
    s = outsider.tls(helper.address, "peerspan-relay/4")
    s.sendall(relay_frame(0x00))
    got = read_frame(s)
    check(got == (0x07, b""), f"anonymous AUTH: {got}, want AUTH_OK")
    s.sendall(relay_frame(0x04))  # PING keeps it
    replacement = outsider.tls(helper.address, "peerspan-relay/4")
    replacement.sendall(relay_frame(0x00))
    check(read_frame(replacement) == (0x07, b""), "the same key's second connection was not authenticated")
    gone = closed_after(s, 10)
    check(gone is not None, "the replaced connection for the same key stayed open")
    s = outsider.tls(helper.address, "peerspan-relay/4")
    s.sendall(relay_frame(0x01, os.urandom(32) + b"x"))  # SEND while AUTH is pending
    check(closed_after(s, 10) is not None, "SEND before AUTH did not close the connection")
    s = outsider.tls(helper.address, "peerspan-relay/4")
    s.sendall(bytes([0x09, 0, 0]))
    check(closed_after(s, 10) is not None, "an unknown frame type did not close the connection")
    replacement.close()
    guarded = Helper("helper-tokens", tokens=["right-token"])
    for token, want in (("wrong-token", 0x08), ("", 0x08), ("right-token", 0x07)):
        s = outsider.tls(guarded.address, "peerspan-relay/4")
        s.sendall(relay_frame(0x00, token.encode()))
        got = read_frame(s)
        check(got is not None and got[0] == want, f"AUTH {token or 'anonymous'} on a helper with tokens: {got}")
        s.close()
    box = Mailbox(outsider, guarded.address)
    status, _, _ = box.create()
    check(status == 403, f"a mailbox on a token helper without a token: {status}, want 403")


@suite.case("relay_auth_deadline", "spec 9.6: AUTH within 5 seconds; appendix 14")
def _():
    s = outsider.tls(helper.address, "peerspan-relay/4")
    gone = closed_after(s, 15)
    check(gone is not None and 4 <= gone <= 8, f"a relay connection with no AUTH closed after {gone}, want about 5 s")


@suite.case("first_contact_handshake_deadline", "spec 9.1 bounds: 5-second handshake; appendix 21")
def _():
    threads[1].join(timeout=25)
    gone = background.get("handshake_closed_after")
    error = background.get("silent_bootstrap_connection_error")
    check(error is None, f"silent connection: {error}")
    check(gone is not None and gone <= 8, f"a connection that never starts TLS closed after {gone}, want about 5 s")


@suite.case("relay_idle_close", "spec 9.6: idle close at 60 seconds; appendix 14; 20 item 45")
def _():
    threads[0].join(timeout=100)
    error = background.get("idle_relay_connection_error")
    check(error is None, f"idle relay connection: {error}")
    check(background.get("idle_auth") == (0x07, b""), f"idle connection AUTH: {background.get('idle_auth')}")
    gone = background.get("idle_closed_after")
    check(gone is not None and 50 <= gone <= 75, f"an idle authenticated relay connection closed after {gone}, want 60 s")


suite.finish()
