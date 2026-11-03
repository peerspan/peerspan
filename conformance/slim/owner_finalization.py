#!/usr/bin/env python3
"""Pure original finalization inspection, guided contract section24.

Independent public API/CLI and genuine two-host/two-person protocol fixtures.
No production imports or protocol/authority-row edits. Typed ordinary external
SSH signing and explicit transport supply retained administrator parents BEFORE
measurement. Short invitation return windows are retired using synchronized
public test clocks; absent daemon original-key/agent sources prevent automatic
original signatures. Transparent relays count actual pinned TLS traffic.
Ordinary setup may already materialize eligible B/D/F drafts: whole-record
snapshots prove inspection changes none; a pre-materialization interval, missing
selection-only, device/folded paths, catalog corruption, microscopic crossings
and original-file read syscalls remain explicit source/fault limits. Restart
keeps the ordinary startup-detach rule, not parent resurrection. No native,
installed/physical/model receipt or new grant/readiness claim is inferred.
Live requester reads start with a consumed authentic TLS ClientHello held outside
the daemon database, and require that same open connection through measurement.
Both relays still count every connection and received byte. This isolates an
observed background attempt without disabling workers or excluding any records.
"""
import base64
import hashlib
import http.client
import json
import math
import re
import select as socket_select
import socket
import socketserver
import sqlite3
import ssl
import subprocess
import threading
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from harness import (Adapter, Clock, Suite, UnixHTTPConnection, check, commit,
                     create_network, finalize, link_view, parse_time, pull_until,
                     rfc3339, select, ssh_key, ssh_public_base64, wait_for, wait_linked)

suite = Suite("owner_finalization", __doc__)
BASE = "/v1/onboarding/join-flows"
PROJECT = "/v1/onboarding/project-flows"
PREFIXES = ('psi2-', 'psl2-', 'peerspan-invite-v1.', 'peerspan-member-invite-v1.',
            'peerspan-person-invite-v1.', 'token_', 'instance_')
EFFECTS = {"verify_original_owner": True, "verify_requester_selection": True,
           "verify_administrator_admission": True, "verify_owner_finalization_bounds": True,
           "prepare_finalization": False, "sign_original": False, "publish_finalization": False,
           "commit_request": False, "grant_membership": False, "grant_agent_access": False,
           "share_files": False, "share_conversation": False, "capability_calls": False}
TOP = set("version host_id flow_id join_review_id owner_review_id context observed_at request review_id review next_action".split())
REVIEW = set("version kind host_id context flow_id join_review_id owner_review_id request_id intent_id network member person_public_key host_public_key device_public_key request_packet_id owner_offer_id selection_id administrator_offer_id root_state_id person_lease_id host_lease_id administrator scopes binding_scopes not_after created_at expires_at effects".split())
LINK_KEYS = set("request_id role mode state network_id context_id migration_proposal_id person_public_key host_public_key device_public_key created_at expires_at request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id manifest_id activation_id outcome_id selection_approved commit_approved completed attention next".split())
shared = {}

def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def digest(domain, value):
    body = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return "review_" + hashlib.sha256(domain.encode() + b"\n" + body).hexdigest()


def get(h, path):
    status, value = h.api("GET", path)
    check(status == 200, f"{h.name}: observation HTTP {status}")
    return value


def db_path(h):
    matches = []
    for p in h.state.glob("*.db"):
        with closing(sqlite3.connect(f"file:{p}?mode=ro", uri=True)) as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='networks'").fetchone():
                matches.append(p)
    check(len(matches) == 1, "expected one host database")
    return matches[0]


def records(h):
    with closing(sqlite3.connect(f"file:{db_path(h)}?mode=ro", uri=True, timeout=5)) as db, db:
        db.execute("BEGIN")
        result = {"$schema": tuple(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name")),
                  "$version": db.execute("PRAGMA user_version").fetchone()}
        for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
            result[name] = tuple(sorted(db.execute('SELECT * FROM "' + name.replace('"', '""') + '"'), key=repr))
        return result


def private_files(root):
    # Durable DB content is compared logically. WAL/SHM are mutable read locks
    # and checkpoint bookkeeping and can be created by our own read connections.
    result = {}
    for p in root.rglob("*"):
        if any(str(p).endswith(suffix) and str(p)[:-len(suffix)].endswith(".db") and Path(str(p)[:-len(suffix)]).is_file()
               for suffix in ("-wal", "-shm")):
            continue
        result[str(p.relative_to(root))] = (p.lstat().st_mode,
            hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() and not str(p).endswith(".db") else None)
    return result


def project(h, name, *, replace=None, old=None):
    body = {"project_root": old["review"]["project_root"] if old else str(suite.work / ("private " + name)),
            "native_session_id": old["review"]["native_session_id"] if old else "private-conversation-" + name,
            "integration": "claude-code", "agent": {"kind": "new", "name": 'Agent "東京" ' + name, "owner": "Owner é"}}
    if replace:
        body["replace_flow_id"] = replace
    status, flow = h.api("POST", PROJECT, body)
    check(status == 201, f"project prepare HTTP {status}")
    status, flow = h.api("POST", PROJECT + "/" + flow["flow_id"] + "/decision", {
        **{key: body[key] for key in ("project_root", "native_session_id", "integration")},
        "review_id": flow["review_id"], "decision": "approve"})
    check(status == 200 and flow["state"] == "attached", "public parent attachment failed")
    return flow


def context(parent):
    return {"project_flow_id": parent["flow_id"], "project_review_id": parent["review_id"],
            **{key: parent["review"][key] for key in ("project_root", "native_session_id", "integration")}}


def advance_to(h, moment):
    h.clock.set(math.ceil((moment - datetime.now(timezone.utc)).total_seconds()))


def pending(h, rid):
    with closing(sqlite3.connect(f"file:{db_path(h)}?mode=ro", uri=True)) as db:
        row = db.execute("SELECT record,secret FROM dec_pending WHERE request_id=?", (rid,)).fetchone()
    check(row is not None, "ordinary request vanished")
    return json.loads(row[0]), row[1]


def packet_message(packet):
    # Wire9.2: semantic packet message excludes every signature.
    fields = ["peerspan-decentralized-packet-v1", packet["context_id"], packet["request_id"], packet["role"],
              packet["writer_host_public_key"], packet["signer_public_key"], packet["person_public_key"],
              packet["issuer_id"], packet["authority_signature_format"],
              hashlib.sha256(base64.b64decode(packet["payload_base64"], validate=True)).hexdigest()]
    return "\n".join(fields).encode()


def packet_id(packet):
    return "dpk_" + hashlib.sha256(packet_message(packet)).hexdigest()


def settled(h):
    # Approval permits subsequent host-owned signing. Observe that maintenance
    # independently before attributing any state change to a pure retry/read.
    previous = records(h)
    def stable():
        nonlocal previous
        current = records(h); same = current == previous; previous = current
        return current if same else None
    time.sleep(0.1)
    return wait_for(stable, timeout=3, interval=0.1, message="quiescent ordinary host-owned maintenance")


def sshsig(key, message):
    signed = subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", str(key), "-n", "peerspan-person-v1"],
                            input=message, check=True, capture_output=True, timeout=5).stdout.decode()
    return "".join(line for line in signed.splitlines() if not line.startswith("-----"))


class Relay:
    """Transparent pinned TLS bytes; fault modes affect transport only."""
    def __init__(self, target):
        self.target = target; self._mode = "pass"; self.connections = 0; self.received = 0
        self.lock = threading.Lock(); self.stop = threading.Event(); self.sockets = set()
        self.held = {}; self.generation = 0
        outer = self
        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                with outer.lock:
                    outer.connections += 1; mode = outer._mode; outer.sockets.add(self.request)
                upstream = None
                generation = None
                try:
                    if mode == "drop":
                        return
                    if mode == "stall":
                        outer.stop.wait(5); return
                    if mode == "hold":
                        # Consume/count a real complete ClientHello before the
                        # barrier. Withhold server bytes, never impersonate TLS.
                        self.request.settimeout(.2)
                        deadline = time.monotonic() + 1
                        def receive(size):
                            value = bytearray()
                            while len(value) < size and time.monotonic() < deadline:
                                try:
                                    data = self.request.recv(size - len(value))
                                except socket.timeout:
                                    continue
                                if not data:
                                    return None
                                with outer.lock:
                                    outer.received += len(data)
                                value.extend(data)
                            return bytes(value) if len(value) == size else None
                        header = receive(5)
                        if header is None or header[0] != 22 or header[1] != 3:
                            return
                        size = int.from_bytes(header[3:5], 'big')
                        if not 4 <= size <= 65535:
                            return
                        hello = receive(size)
                        if hello is None or hello[0] != 1:
                            return
                        self.request.setblocking(False)
                        with outer.lock:
                            if outer._mode != 'hold':
                                return
                            outer.generation += 1; generation = outer.generation
                            outer.held[generation] = self.request
                        while not outer.stop.is_set() and outer.mode == 'hold':
                            ready, _, _ = socket_select.select([self.request], [], [], .02)
                            if ready:
                                data = self.request.recv(65536)
                                if not data:
                                    return
                                with outer.lock:
                                    outer.received += len(data)
                        return
                    upstream = socket.create_connection(outer.target, timeout=1)
                    with outer.lock:
                        outer.sockets.add(upstream)
                    while not outer.stop.is_set():
                        ready, _, _ = socket_select.select([self.request, upstream], [], [], .1)
                        for source in ready:
                            data = source.recv(65536)
                            if not data:
                                return
                            if source is self.request:
                                with outer.lock:
                                    outer.received += len(data)
                            (upstream if source is self.request else self.request).sendall(data)
                except OSError:
                    pass
                finally:
                    with outer.lock:
                        if generation is not None:
                            outer.held.pop(generation, None)
                        outer.sockets.discard(self.request)
                        if upstream:
                            outer.sockets.discard(upstream)
                    if upstream:
                        upstream.close()
        self.server = Server(("127.0.0.1", 0), Handler)
        while self.server.server_address[1] == target[1]:
            # The real host has reserved its port logically but has not yet
            # started; avoid a relay ever binding its own upstream address.
            self.server.server_close()
            self.server = Server(("127.0.0.1", 0), Handler)
        self.address = "127.0.0.1:" + str(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
        self.thread.start()
        import atexit
        atexit.register(self.close)

    def counts(self):
        with self.lock:
            return self.connections, self.received

    @property
    def mode(self):
        with self.lock:
            return self._mode

    @mode.setter
    def mode(self, value):
        with self.lock:
            changed = self._mode != value; self._mode = value
            sockets = list(self.sockets) if changed else []
        for item in sockets:
            try:
                item.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def refresh_hold(self):
        self.mode = 'hold'
        with self.lock:
            sockets = list(self.sockets)
        for item in sockets:
            try:
                item.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def live_generations(self):
        with self.lock:
            entries = list(self.held.items())
        result = []
        for generation, stream in entries:
            try:
                # EOF, pending bytes or a closed descriptor do not establish a
                # quiescent live hold. A stale handler/event is insufficient.
                stream.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
            except (BlockingIOError, socket.timeout):
                result.append(generation)
            except OSError:
                pass
        return result

    def close(self):
        if self.stop.is_set():
            return
        self.stop.set()
        with self.lock:
            sockets = list(self.sockets)
        for item in sockets:
            try:
                item.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=1)


def host(name, *, live=False):
    h = suite.host(name, start=False, clock=Clock(suite.work / (name + '.clock')))
    h.relay = Relay(('127.0.0.1', h.bootstrap_port)) if live else None
    config = h.root / 'transport.json'
    config.write_bytes(compact({'format': 1, 'advertise_bootstrap': [h.relay.address] if live else [],
        'advertise_quic': [], 'rendezvous': [], 'relays': [], 'publish_contacts': False}))
    config.chmod(0o600)
    h.extra_args = ['--transport-config', config, '--person-key-file', h.root / 'absent-daemon-person-key']
    h.extra_env = {'SSH_AUTH_SOCK': str(h.root / 'absent-agent.sock')}
    return h.start()


def snapshot(h):
    guard = getattr(h, '_transport_hold', None)
    if guard:
        guard()
    value = records(h), private_files(h.state), private_files(h.home)
    if guard:
        guard()
    return value


def differences(before, after):
    return {label: sorted(k for k in set(old) | set(new) if old.get(k) != new.get(k))
            for label, old, new in zip(('tables', 'state_paths', 'home_paths'), before, after)}


def report_contact_purity_failure(f, before, after):
    """GU.impl29c: closed metadata from captured snapshots; never change a verdict."""
    if after == before:
        return
    unknown = 'unknown'
    summary = {key: unknown for key in ('before_contact_count', 'after_contact_count',
        'added_primary_key_count', 'removed_primary_key_count', 'changed_primary_key_count',
        'changed_existing_rows')}
    try:
        def canonical_base64(value):
            return (type(value) is str and
                    base64.b64encode(base64.b64decode(value, validate=True)).decode() == value)

        def index(rows):
            result = {}
            for row in rows:
                if (type(row) is not tuple or len(row) != 5 or
                    not all(type(value) is str for value in row[:3]) or
                    not ((row[0] == '-' and row[1] == '-') or
                         (re.fullmatch(r'net_[0-9a-f]{64}', row[0]) and
                          re.fullmatch(r'ctx_[0-9a-f]{64}', row[1]))) or
                    not canonical_base64(row[2]) or len(base64.b64decode(row[2])) != 32 or
                    row[:3] in result):
                    raise ValueError
                result[row[:3]] = row
            return result

        def unique_object(pairs):
            value = dict(pairs)
            if len(value) != len(pairs):
                raise ValueError
            return value

        def record(value):
            try:
                if type(value) is not str:
                    return None
                value = json.loads(value, object_pairs_hook=unique_object)
                if (type(value) is not dict or
                    set(value) != {'format', 'message_hashes', 'conflicted', 'contacts_base64'} or
                    type(value['format']) is not int or value['format'] != 1 or
                    type(value['conflicted']) is not bool or
                    type(value['message_hashes']) is not list or
                    not all(type(item) is str and re.fullmatch(r'[0-9a-f]{64}', item)
                            for item in value['message_hashes']) or
                    type(value['contacts_base64']) is not list or
                    not all(canonical_base64(item) for item in value['contacts_base64'])):
                    return None
                return value
            except Exception:
                return None

        def sequence(value):
            return ((type(value) is int and 0 <= value < 2**63) or
                    (type(value) is bytes and len(value) == 8 and
                     int.from_bytes(value, 'big') >= 2**63))

        old_rows, new_rows = before[0]['dec_contacts'], after[0]['dec_contacts']
        if type(old_rows) is not tuple or type(new_rows) is not tuple:
            raise ValueError
        summary['before_contact_count'], summary['after_contact_count'] = len(old_rows), len(new_rows)
        old, new = index(old_rows), index(new_rows)
        old_keys, new_keys = set(old), set(new)
        changed = [key for key in old_keys & new_keys if old[key] != new[key]]
        summary.update(added_primary_key_count=len(new_keys - old_keys),
                       removed_primary_key_count=len(old_keys - new_keys),
                       changed_primary_key_count=len(changed))
        metadata = []
        for key in changed:
            left, right = old[key], new[key]
            item = {name: unknown for name in ('sequence_changed', 'matches_known_network_context',
                'host_is_other_participant', 'format_changed', 'message_hashes_changed',
                'conflicted_changed', 'contacts_base64_changed', 'before_message_hashes_count',
                'after_message_hashes_count', 'before_contacts_count', 'after_contacts_count',
                'before_conflicted', 'after_conflicted')}
            if sequence(left[3]) and sequence(right[3]):
                item['sequence_changed'] = left[3] != right[3]
            known_context = f.get('owner', {}).get('request', {}).get('context_id')
            known_network = f.get('network', {}).get('id')
            if type(known_network) is str and type(known_context) is str:
                item['matches_known_network_context'] = key[:2] == (known_network, known_context)
            other = getattr(f.get('a'), 'public_key', None)
            if type(other) is str:
                item['host_is_other_participant'] = key[2] == other
            left_record, right_record = record(left[4]), record(right[4])
            if left_record is not None and right_record is not None:
                for field in ('format', 'message_hashes', 'conflicted', 'contacts_base64'):
                    item[field + '_changed'] = left_record[field] != right_record[field]
            for side, value in (('before', left_record), ('after', right_record)):
                if value is not None:
                    item[side + '_message_hashes_count'] = len(value['message_hashes'])
                    item[side + '_contacts_count'] = len(value['contacts_base64'])
                    item[side + '_conflicted'] = value['conflicted']
            metadata.append(item)
        summary['changed_existing_rows'] = sorted(metadata, key=lambda item: json.dumps(item, sort_keys=True))
    except Exception:
        pass  # Retain unknown metadata without disclosing or replacing the original failure.
    try:
        print('contact_purity_failure_public=' + json.dumps(summary, sort_keys=True), flush=True)
    except Exception:
        pass  # A failed diagnostic output must not mask the unchanged assertion below.


def report_contact_purity_phase_failure(f, before, after, phase):
    """GU.impl40a: failure-only phase/key/lifecycle metadata from captured rows."""
    unknown = 'unknown'
    summary = {'phase': phase if type(phase) is str and phase in
               ('before_F', 'after_F', 'after_expiry', 'unknown') else unknown,
               'changed_rows': unknown}
    try:
        if after == before:
            return

        def unique_object(pairs):
            result = dict(pairs)
            if len(result) != len(pairs):
                raise ValueError
            return result

        def invalid_number(_):
            raise ValueError

        def integer(text):
            if not re.fullmatch(r'[0-9]{1,20}', text) or int(text) >= 2**64:
                raise ValueError
            return int(text)

        def strict_json(value, maximum):
            if type(value) is bytes:
                value = value.decode('utf-8')
            if type(value) is not str or len(value.encode('utf-8')) > maximum:
                raise ValueError
            return json.loads(value, object_pairs_hook=unique_object, parse_int=integer,
                              parse_float=invalid_number, parse_constant=invalid_number)

        def binary(value, maximum):
            if type(value) is not str or len(value) > 4 * ((maximum + 2) // 3):
                raise ValueError
            decoded = base64.b64decode(value, validate=True)
            if len(decoded) > maximum or base64.b64encode(decoded).decode() != value:
                raise ValueError
            return decoded

        def key(value):
            if len(binary(value, 32)) != 32:
                raise ValueError
            return value

        def sequence(value):
            if type(value) is int and 0 <= value < 2**63:
                return value
            if type(value) is bytes and len(value) == 8:
                result = int.from_bytes(value, 'big')
                if result >= 2**63:
                    return result
            raise ValueError

        def timestamp(value):
            if type(value) is not str or not re.fullmatch(
                    r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', value):
                raise ValueError
            return datetime.fromisoformat(value[:-1] + '+00:00')

        def endpoint(value):
            if type(value) is not str or not value.isascii() or len(value) > 260:
                raise ValueError
            host, separator, port = value.rpartition(':')
            if not separator or not re.fullmatch(r'[1-9][0-9]{0,4}', port) or int(port) > 65535:
                raise ValueError
            if host.startswith('['):
                if not host.endswith(']'):
                    raise ValueError
                address = host[1:-1]
                halves = address.split('::')
                if len(halves) > 2:
                    raise ValueError
                left = halves[0].split(':') if halves[0] else []
                right = halves[1].split(':') if len(halves) == 2 and halves[1] else []
                if not all(re.fullmatch(r'[0-9a-f]{1,4}', part) for part in left + right):
                    raise ValueError
                if len(halves) == 1:
                    groups = [int(part, 16) for part in left]
                else:
                    missing = 8 - len(left) - len(right)
                    if missing < 1:
                        raise ValueError
                    groups = [int(part, 16) for part in left] + [0] * missing + [int(part, 16) for part in right]
                if (len(groups) != 8 or not any(groups) or
                    (groups[:5] == [0] * 5 and groups[5] == 65535)):
                    raise ValueError
                runs, start = [], 0
                while start < 8:
                    end = start
                    while end < 8 and groups[end] == 0:
                        end += 1
                    if end - start >= 2:
                        runs.append((start, end))
                    start = max(start + 1, end)
                parts = [format(part, 'x') for part in groups]
                if runs:
                    start, end = max(runs, key=lambda run: run[1] - run[0])
                    canonical = ':'.join(parts[:start]) + '::' + ':'.join(parts[end:])
                else:
                    canonical = ':'.join(parts)
                if address != canonical:
                    raise ValueError
            elif re.fullmatch(r'[0-9.]+', host):
                parts = host.split('.')
                if (len(parts) != 4 or not all(re.fullmatch(r'0|[1-9][0-9]{0,2}', part)
                    and int(part) <= 255 for part in parts) or not any(int(part) for part in parts)):
                    raise ValueError
            elif (not 1 <= len(host) <= 253 or
                  not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
                          for part in host.split('.'))):
                raise ValueError

        def payload_record(payload):
            value = strict_json(payload, 8192)
            if type(value) is not dict or set(value) != {'quic_addresses', 'bootstrap_addresses', 'relays'}:
                raise ValueError
            for field in ('quic_addresses', 'bootstrap_addresses'):
                items = value[field]
                if (type(items) is not list or len(items) > 8 or
                    not all(type(item) is str for item in items) or items != sorted(set(items))):
                    raise ValueError
                for item in items:
                    endpoint(item)
            if type(value['relays']) is not list or len(value['relays']) > 8:
                raise ValueError
            relays = []
            for relay in value['relays']:
                if type(relay) is not dict or set(relay) != {'address', 'public_key'}:
                    raise ValueError
                endpoint(relay['address']); key(relay['public_key'])
                relays.append((relay['address'], relay['public_key']))
            if (relays != sorted(set(relays)) or
                sum(len(value[field]) for field in ('quic_addresses', 'bootstrap_addresses', 'relays')) > 16):
                raise ValueError

        def index(rows):
            if type(rows) is not tuple or len(rows) > 65536:
                raise ValueError
            result = {}
            for row in rows:
                if (type(row) is not tuple or len(row) != 5 or
                    not all(type(value) is str for value in row[:3]) or
                    not ((row[0] == row[1] == '-') or
                         (re.fullmatch(r'net_[0-9a-f]{64}', row[0]) and
                          re.fullmatch(r'ctx_[0-9a-f]{64}', row[1]))) or
                    key(row[2]) != row[2] or row[:3] in result):
                    raise ValueError
                sequence(row[3])
                result[row[:3]] = row
            return result

        def singleton(row):
            if type(row[4]) is not str:
                raise ValueError
            value = strict_json(row[4], 65536)
            if (type(value) is not dict or
                set(value) != {'format', 'message_hashes', 'conflicted', 'contacts_base64'} or
                type(value['format']) is not int or value['format'] != 1 or
                type(value['conflicted']) is not bool or
                type(value['message_hashes']) is not list or
                not all(type(item) is str and re.fullmatch(r'[0-9a-f]{64}', item)
                        for item in value['message_hashes']) or
                value['message_hashes'] != sorted(set(value['message_hashes'])) or
                type(value['contacts_base64']) is not list):
                raise ValueError
            if len(value['contacts_base64']) != 1:
                return None
            body = strict_json(binary(value['contacts_base64'][0], 8192), 8192)
            if (type(body) is not dict or
                set(body) != {'format', 'context_id', 'host_public_key', 'sequence',
                              'issued_at', 'expires_at', 'payload_base64', 'signature'} or
                type(body['format']) is not int or body['format'] != 1 or
                body['context_id'] != row[1] or body['host_public_key'] != row[2] or
                type(body['sequence']) is not int or body['sequence'] != sequence(row[3]) or
                len(binary(body['signature'], 64)) != 64):
                raise ValueError
            issued, expires = timestamp(body['issued_at']), timestamp(body['expires_at'])
            if not 0 < (expires - issued).total_seconds() <= 300:
                raise ValueError
            payload = binary(body['payload_base64'], 8192)
            payload_record(payload)
            message = '\n'.join(('peerspan-decentralized-contact-v1', body['context_id'],
                body['host_public_key'], str(body['sequence']), body['issued_at'], body['expires_at'],
                hashlib.sha256(payload).hexdigest())).encode()
            if hashlib.sha256(message).hexdigest() not in value['message_hashes']:
                raise ValueError
            return issued, expires, payload

        requester, issuer = key(f['h'].public_key), key(f['a'].public_key)
        if requester == issuer:
            raise ValueError
        deadline = timestamp(f['owner']['request']['expires_at'])
        old, new = index(before[0]['dec_contacts']), index(after[0]['dec_contacts'])
        metadata = []
        for row_key in old.keys() | new.keys():
            if old.get(row_key) == new.get(row_key):
                continue
            item = {name: unknown for name in ('host_role', 'sequence_increased',
                'issued_changed', 'expiry_changed', 'payload_changed',
                'before_issued_after_request_deadline', 'after_issued_after_request_deadline',
                'before_expiry_after_request_deadline', 'after_expiry_after_request_deadline')}
            try:
                left, right = old.get(row_key), new.get(row_key)
                item['host_role'] = ('requester' if row_key[2] == requester else
                                     'issuer' if row_key[2] == issuer else 'other')
                if left is not None and right is not None:
                    item['sequence_increased'] = sequence(right[3]) > sequence(left[3])
                left_contact = singleton(left) if left is not None else None
                right_contact = singleton(right) if right is not None else None
                if left_contact is not None and right_contact is not None:
                    for column, field in enumerate(('issued_changed', 'expiry_changed', 'payload_changed')):
                        item[field] = left_contact[column] != right_contact[column]
                for side, contact in (('before', left_contact), ('after', right_contact)):
                    if contact is not None:
                        item[side + '_issued_after_request_deadline'] = contact[0] > deadline
                        item[side + '_expiry_after_request_deadline'] = contact[1] > deadline
            except Exception:
                item = {name: unknown for name in item}
            metadata.append(item)
        summary['changed_rows'] = sorted(metadata, key=lambda item: json.dumps(item, sort_keys=True))
    except Exception:
        pass  # Malformed diagnostics remain unknown without replacing the original failure.
    try:
        print('contact_purity_phase_failure_public=' + json.dumps(summary, sort_keys=True), flush=True)
    except Exception:
        pass  # Diagnostic parsing/output never masks the unchanged snapshot assertion.


def public(value, *secrets):
    text = json.dumps(value, ensure_ascii=False, default=str)
    for n, marker in enumerate((*PREFIXES, 'payload_base64', 'template_base64', 'message_base64', 'secret_base64',
        'signing_requests', 'return_secret', 'admin.sock', 'adapter.sock', '"signature"', '"seed"', *secrets)):
        check(not marker or marker not in text, f'finalization response/diagnostic leaked private material rule{n}')


def join(h, parent, code, person, *, publish=True):
    status, flow = h.api('POST', BASE, {'context': context(parent), 'invitation': code, 'person_public_key': person})
    check(status == 201 and flow['state'] == 'review', f'join preparation HTTP {status}')
    if publish:
        status, flow = h.api('POST', BASE + '/' + flow['flow_id'] + '/decision', {
            'context': context(parent), 'review_id': flow['review_id'], 'decision': 'approve', 'invitation': code})
        check(status == 200 and flow['state'] == 'requested', f'join publication HTTP {status}')
    return flow


def endpoint(f):
    return BASE + '/' + f['flow']['flow_id'] + '/owner/finalization/inspect'


def payload(f):
    return {'context': context(f['parent']), 'join_review_id': f['flow']['review_id'], 'owner_review_id': f['owner']['owner']['review_id']}


def owner(f, action, prepared=None):
    body = {'context': context(f['parent']), 'join_review_id': f['flow']['review_id']}
    if action == 'approve':
        body['owner_review_id'] = prepared['owner']['review_id']
    status, value = f['h'].api('POST', BASE + '/' + f['flow']['flow_id'] + '/owner/' + action, body)
    check(status == 200, f'ordinary guided owner {action} HTTP {status}')
    return value


def make_pair(name, *, live=True, prepared=True, approved=True, signed=True, admitted=True):
    a, h = host(name + 'a', live=live), host(name + 'b', live=live)
    net = create_network(a, 'Finalization "é東京" ' + name, 'Administrator ' + name)
    key = ssh_key(suite.work, name + '-original'); person = ssh_public_base64(key)
    check(person != net['person_public_key'] and a.public_key != h.public_key, 'fixture must use distinct genuine people and hosts')
    parent = project(h, name)
    status, issued = a.api('POST', '/v2/networks/' + net['id'] + '/invitations', {
        'member': 'New original "é東京" ' + name, 'expected_person_public_key': person,
        'expires_at': rfc3339(a.now() + timedelta(seconds=65 if live else 3600))})
    check(status == 201, f'genuine signed invitation HTTP {status}')
    flow = join(h, parent, issued['invitation'], person)
    f = dict(a=a, h=h, network=net, parent=parent, flow=flow, rid=flow['outcome']['request_id'],
             key=key, person=person, code=issued['invitation'], invitation=issued, owner=None, live=live)
    status, retained = h.api('POST', '/v2/link/requests', {'mode': 'new', 'network_id': net['id'], 'person_public_key': person,
        'migration_proposal_id': '-', 'contact_invitation': issued['invitation'], 'helpers': []})
    check(status == 200 and retained['request_id'] == f['rid'] and retained.get('display_code'), 'ordinary handoff did not reuse exact guided request')
    f['reply'] = retained['display_code']
    if not prepared:
        f['owner'] = {'owner': {'review_id': 'review_' + '0' * 64}}
        a.stop()
        return f
    f['owner'] = owner(f, 'prepare')
    if approved:
        f['owner'] = owner(f, 'approve', f['owner'])
    if not signed:
        if not live:
            a.stop()
        return f
    check(approved, 'ordinary external signing requires explicit exact owner approval')
    sign_original(f)
    view = pull_until(h, f['rid'], 'owner_offer_id', timeout=15)
    if view['state'] == 'needs_selection':
        select(h, view)
    view = pull_until(h, f['rid'], 'selection_id', timeout=10)
    check(view['state'] == 'needs_administrator' and view['selection_approved'] and not view['commit_approved'], 'exact original/selection setup changed consent separation')
    if live:
        # Automatic return must happen before retiring its independent window.
        wait_for(lambda: next((v for v in get(a, '/v2/link/requests') if v['request_id'] == f['rid']), None),
                 timeout=15, interval=.1, message='genuine automatic return before invitation retirement')
        target = max(parse_time(issued['expires_at']) + timedelta(seconds=1), a.now(), h.now())
        check(target < parse_time(view['expires_at']), 'invitation isolation consumed request window')
        for local in (a, h):
            advance_to(local, target)
        def retired():
            with closing(sqlite3.connect(f'file:{db_path(a)}?mode=ro', uri=True)) as db:
                row = db.execute('SELECT secret FROM dec_pending WHERE request_id=?', (issued['invitation_id'],)).fetchone()
            return row is None or row[0] is None
        wait_for(retired, timeout=5, interval=.1, message='ordinary invitation-return retirement')
    if admitted:
        check(live, 'positive evidence uses actual public transport')
        a.ok_incomplete('link', 'admit', '--network', net['id'], '--owner-offer', view['owner_offer_id'], '--selection', view['selection_id'],
            '--person', person, '--expect-host-key', view['host_public_key'], '--expect-device-key', view['device_public_key'],
            '--code-stdin', '--approve', input=f['reply'] + '\n', timeout=20)
        view = pull_until(h, f['rid'], 'administrator_offer_id', timeout=20)
        check(view['state'] == 'needs_owner_finalization' and not view['commit_approved'] and view['owner_finalization_id'] == '-', 'administrator evidence supplied original F/commit')
    a.stop()
    f['view'] = view
    if live:
        a.relay.mode = h.relay.mode = 'drop'
    quiet(f)
    return f


def sign_original(f):
    h, rid = f['h'], f['rid']; iid = f['owner']['owner']['review']['intent_id']
    def ready():
        status, value = h.api('GET', '/v2/link/requests/' + rid + '/approval')
        check(status == 200, f'ordinary original signing lookup HTTP {status}')
        if any(slot['role'] == 'authority' for slot in value['signing_requests']):
            return value
        h.cli('link', 'resume', rid, timeout=10)
        return None
    value = wait_for(ready, timeout=10, interval=.1, message='exact external original owner slot')
    for _ in range(4):
        slots = value['signing_requests']
        check(all(r['intent_id'] == iid and r['object_type'] == 'owner_offer_packet' and
            ((r['role'] == 'authority' and r['format'] == 'sshsig' and r['public_key'] == f['person']) or
             (r['role'] == 'host' and r['format'] == 'ed25519' and r['public_key'] == h.public_key)) for r in slots),
              'ordinary original slot changed type/intent/host/person')
        external = [r for r in slots if r['role'] == 'authority']
        if not external:
            return
        for r in external:
            packet = json.loads(base64.b64decode(r['template_base64'], validate=True))
            check(packet['request_id'] == rid and r['object_id'] == packet_id(packet) and
                  base64.b64decode(r['message_base64'], validate=True) == packet_message(packet), 'ordinary original slot message mismatch')
        status, value = h.api('POST', '/v2/link/requests/' + rid + '/signed', {'intent_id': iid, 'signatures': [
            {'slot_id': r['slot_id'], 'role': 'authority', 'signature': sshsig(f['key'], base64.b64decode(r['message_base64'], validate=True))} for r in external]})
        check(status == 200, f'genuine original signature submission HTTP {status}')
    check(not any(r['role'] == 'authority' for r in value['signing_requests']), 'original signature did not complete bounded batch')


def traffic(f):
    return tuple(h.relay.counts() for h in (f['a'], f['h']) if h.relay)


def quiet(f):
    h = f['h']; relays = [v.relay for v in (f['a'], h) if v.relay]
    record, _ = pending(h, f['rid'])
    active = f['live'] and record['terminal'] == '-' and h.now() < parse_time(f['owner']['request']['expires_at'])
    h._transport_hold = None
    if active:
        held = f.get('_held', [])
        fresh = (time.monotonic() - f.get('_held_at', 0) < 2 and held and
                 all(generation in relay.live_generations() for relay, generation in held))
        if not fresh:
            for relay in relays:
                relay.refresh_hold()
        def captured():
            return [(relay, generation) for relay in relays for generation in relay.live_generations()] or None
        # A real current attempt on either endpoint is sufficient; no claim
        # that the protocol polls all configured endpoints concurrently.
        if not fresh:
            held = wait_for(captured, timeout=5, interval=.02, message='authentic requester ClientHello held outside database')
            f['_held'], f['_held_at'] = held, time.monotonic()
        def guard():
            if all(relay.mode == 'hold' for relay in relays):
                check(all(generation in relay.live_generations() for relay, generation in held),
                      'fixture requester transport hold ended during pure measurement')
        h._transport_hold = guard
    else:
        for relay in relays:
            relay.mode = 'drop'
    settled(f['h']); previous = traffic(f)
    def stable():
        nonlocal previous
        now = traffic(f); same = now == previous; previous = now
        return same
    time.sleep(.15)
    wait_for(stable, timeout=2, interval=.15, message='settled genuine carrier traffic before pure inspection')


def main():
    if not shared:
        shared['building'] = True
        try:
            value = make_pair('main')
        except Exception:
            shared['failed'] = True
            raise
        shared.clear(); shared.update(value)
    check(not shared.get('failed'), 'earlier genuine positive fixture setup failed')
    return shared


def statement_id(envelope):
    if isinstance(envelope, str):
        return envelope
    message = '\n'.join(('peerspan-decentralized-statement-v1', envelope['kind'], envelope['context_id'],
                         hashlib.sha256(base64.b64decode(envelope['payload_base64'], validate=True)).hexdigest()))
    return 'ds_' + hashlib.sha256(message.encode()).hexdigest()


def ed25519(public_key, signature, message, label):
    pub, sig, body = (suite.work / ('verify-' + label + suffix) for suffix in ('.der', '.sig', '.msg'))
    pub.write_bytes(bytes.fromhex('302a300506032b6570032100') + base64.b64decode(public_key, validate=True))
    sig.write_bytes(base64.b64decode(signature, validate=True)); body.write_bytes(message)
    result = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-keyform', 'DER', '-inkey', str(pub),
        '-rawin', '-in', str(body), '-sigfile', str(sig)], capture_output=True, timeout=5)
    check(result.returncode == 0, 'independent public Ed25519 verification failed: ' + label)


def validate(f, value):
    h, flow = f['h'], f['flow']; owner_review = f['owner']['owner']['review']; rid = f['rid']
    check(type(value) is dict and set(value) == TOP and type(value['version']) is int and value['version'] == 1, 'closed finalization wrapper')
    check(value['host_id'] == h.id and value['flow_id'] == flow['flow_id'] and value['join_review_id'] == flow['review_id'] and
          value['owner_review_id'] == f['owner']['owner']['review_id'] and value['context'] == context(f['parent']), 'exact finalization wrapper binding')
    check(re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value['observed_at']) and
          abs((parse_time(value['observed_at']) - h.now()).total_seconds()) < 5, 'whole-second guarded observation')
    view, review = value['request'], value['review']
    check(set(view) == LINK_KEYS and view == link_view(h, rid), 'exact retained public LINK_VIEW')
    check(set(review) == REVIEW and type(review['version']) is int and review['version'] == 1 and review['kind'] == 'inspect_new_original_finalization', 'closed finalization review')
    for key, expected in {'host_id': h.id, 'context': context(f['parent']), 'flow_id': flow['flow_id'], 'join_review_id': flow['review_id'],
        'owner_review_id': f['owner']['owner']['review_id'], 'request_id': rid, 'intent_id': owner_review['intent_id'],
        'network': owner_review['network'], 'member': owner_review['member'], 'person_public_key': f['person'],
        'host_public_key': h.public_key, 'device_public_key': view['device_public_key'], 'not_after': owner_review['not_after'],
        'created_at': view['created_at'], 'expires_at': view['expires_at']}.items():
        check(review[key] == expected, 'finalization review changed exact target term: ' + key)
    check(review['scopes'] == 7 and type(review['scopes']) is int and review['binding_scopes'] == 2 and type(review['binding_scopes']) is int and
          review['effects'] == EFFECTS and all(type(v) is bool for v in review['effects'].values()), 'finalization powers/effects widened')
    check(parse_time(review['not_after']) == parse_time(view['created_at']) + timedelta(days=7), 'fixed seven-day original target')
    record, _ = pending(h, rid)
    admin = json.loads(base64.b64decode(record['administrator_packet_base64'], validate=True))
    contents = json.loads(base64.b64decode(admin['payload_base64'], validate=True))
    for field in ('request_packet_id', 'owner_offer_id', 'selection_id', 'administrator_offer_id'):
        check(review[field] == view[field], 'finalization selected a different retained transcript parent: ' + field)
    check(packet_id(admin) == view['administrator_offer_id'] and admin['request_id'] == rid and admin['role'] == 'administrator', 'genuine administrator packet binding')
    expected_admin = {'signer_public_key': admin['signer_public_key'], 'host_public_key': admin['writer_host_public_key'],
                      'signature_format': admin['authority_signature_format'], 'issuer_id': admin['issuer_id']}
    check(set(review['administrator']) == set(expected_admin) and review['administrator'] == expected_admin, 'administrator authority attribution changed')
    check(review['root_state_id'] == contents['root_state_id'] == f['network']['root_state_id'] and
          review['person_lease_id'] == statement_id(contents['person_lease']) and review['host_lease_id'] == statement_id(contents['host_lease']), 'exact independently verified root/P/H parents')
    check(admin['signer_public_key'] == f['network']['root_public_key'] and admin['writer_host_public_key'] == f['a'].public_key and admin['authority_signature_format'] == 'ed25519', 'distinct administrator/root fixture changed')
    ed25519(admin['signer_public_key'], admin['authority_signature'], packet_message(admin), 'admin-authority')
    ed25519(admin['writer_host_public_key'], admin['host_signature'], packet_message(admin), 'admin-host')
    check(value['review_id'] == digest('peerspan-original-finalization-inspection-v1', review) and value['next_action'] == 'review_original_finalization', 'canonical finalization digest/action')
    check(view['owner_finalization_id'] == view['manifest_id'] == view['activation_id'] == view['outcome_id'] == '-' and not view['commit_approved'] and
          get(h, '/v2/networks') == [], 'inspection fabricated F/commit/adoption')
    public(value, f['code'], f.get('reply', ''))


def inspect(f, *, status=200, code=None, body=None, path=None, pure=True, diagnostic_phase='unknown'):
    h = f['h']
    if pure:
        quiet(f); before, network = snapshot(h), traffic(f)
    actual, value = h.api('POST', path or endpoint(f), payload(f) if body is None else body)
    check(actual == status, f'finalization inspect HTTP {actual}, want {status}')
    if code:
        check(isinstance(value, dict) and value.get('code') == code, f'finalization error code {value.get("code") if isinstance(value, dict) else None}, want {code}')
    if pure:
        after, after_network = snapshot(h), traffic(f)
        report_contact_purity_failure(f, before, after)
        report_contact_purity_phase_failure(f, before, after, diagnostic_phase)
        check(after == before, f'pure finalization inspection changed state: {differences(before, after)}; relay_changed={network != after_network}')
        check(after_network == network, f'pure finalization inspection attempted carrier IO; before={network}, after={after_network}')
    if status == 200:
        validate(f, value)
    else:
        public(value, f['code'], f.get('reply', ''))
    return value

@suite.case('exact_verified_original_administrator_parents_api_cli_and_no_materialization', 'guided24 verification1')
def _():
    f = main(); h = f['h']; before = snapshot(h)
    value = inspect(f)
    check(snapshot(h) == before, 'first read materialized B/D/F, consent, authority or private files')
    body = {'flow_id': f['flow']['flow_id'], **payload(f)}
    quiet(f); before, network = snapshot(h), traffic(f)
    result = h.cli('onboarding', 'join', 'owner', 'finalization', 'inspect', '--stdin', input=compact(body).decode(), timeout=8)
    check(result.ok, 'private finalization CLI failed without any available person-key/agent source')
    check(snapshot(h) == before and traffic(f) == network, 'read-only finalization CLI changed records/files or attempted carrier IO')
    validate(f, result.json)
    check(result.json['review'] == value['review'] and result.json['review_id'] == value['review_id'], 'API/CLI exact review parity')
    public(result.stdout + result.stderr, f['code'], f['reply'], str(h.root / 'absent-daemon-person-key'))
    f['first'] = value


@suite.case('stable_live_repeats_restart_detachment_and_retained_original_history_are_pure', 'guided24 verification2')
def _():
    f = make_pair('rst'); h = f['h']
    first, second = inspect(f), inspect(f)
    check(first['review'] == second['review'] and first['review_id'] == second['review_id'], 'unchanged administrator parents changed review/digest')
    record, _ = pending(h, f['rid'])
    keys = ('request_packet_base64', 'owner_packet_base64', 'selection_packet_base64', 'administrator_packet_base64',
            'owner_offer_id', 'selection_id', 'administrator_offer_id', 'owner_intent_id', 'catalog_base64')
    fixed = {k: record[k] for k in keys}
    original = owner(f, 'lookup')['owner']
    h.restart(kill=True); quiet(f)
    inspect(f, status=409, code='review_changed')
    after, _ = pending(h, f['rid'])
    check({k: after[k] for k in keys} == fixed, 'restart changed immutable retained transcript/owner intent')
    before = snapshot(h); historical = owner(f, 'lookup')
    check(historical['owner'] == original and snapshot(h) == before, 'startup detach changed or rewrote immutable section16 history')
    inspect(f, status=409, code='review_changed')
    h.stop()


@suite.case('missing_unapproved_original_or_administrator_and_wrong_exact_bindings_refuse_pure', 'guided24 verification3')
def _():
    f = make_pair('neg', live=False, prepared=False, approved=False, signed=False, admitted=False)
    inspect(f, status=409)
    f['owner'] = owner(f, 'prepare')
    inspect(f, status=409, code='finalization_inspection_unavailable')
    f['owner'] = owner(f, 'approve', f['owner'])
    inspect(f, status=409, code='finalization_inspection_unavailable')
    sign_original(f)
    view = pull_until(f['h'], f['rid'], 'owner_offer_id', timeout=15)
    if view['state'] == 'needs_selection':
        select(f['h'], view)
    view = pull_until(f['h'], f['rid'], 'selection_id', timeout=10)
    check(view['administrator_offer_id'] == '-' and view['selection_approved'], 'missing-admin control did not have genuine original/selection')
    inspect(f, status=409, code='finalization_inspection_unavailable')
    new_parent = project(f['h'], 'draft')
    draft = join(f['h'], new_parent, f['code'], f['person'], publish=False)
    alternative = {**f, 'parent': new_parent, 'flow': draft}
    inspect(alternative, status=409, code='state_conflict')
    f['h'].stop()
    good = main()
    for change in ({'join_review_id': 'review_' + '0' * 64}, {'owner_review_id': 'review_' + '0' * 64},
                   {'context': {**context(good['parent']), 'native_session_id': 'different-conversation'}},
                   {'context': {**context(good['parent']), 'project_root': str(suite.work / 'different root')}}):
        inspect(good, status=409, code='review_changed', body={**payload(good), **change})
    inspect(good, status=404, path=BASE + '/flow_' + '0' * 32 + '/owner/finalization/inspect')


@suite.case('signed_deadline_inactivity_and_public_cancellation_fail_closed_without_time_writes', 'guided24 verification4')
def _():
    f = make_pair('tm'); h = f['h']; first = inspect(f)
    record, _ = pending(h, f['rid']); prior = h.clock.offset
    for moment in (parse_time(record['stage_at']) + timedelta(minutes=11), parse_time(first['request']['expires_at']) + timedelta(seconds=1)):
        quiet(f); before, network = snapshot(h), traffic(f)
        advance_to(h, moment)
        inspect(f, status=409, code='review_expired', pure=False)
        after = snapshot(h)
        check(after == before, f'clock-bound read/ambient maintenance changed persisted highwater/evidence: {differences(before, after)}')
        check(traffic(f) == network, 'clock-bound read attempted carrier IO')
        # This restoration is permitted ONLY after strict proof that persisted
        # decision time, public evidence, terminal state and private files did
        # not change. No database or highwater is edited by this fixture.
        h.clock.set(prior)
    recovered = inspect(f)
    check(recovered['review'] == first['review'] and recovered['review_id'] == first['review_id'], 'pure expiry observation extended/replaced review')
    status, cancelled = h.api('POST', '/v2/link/requests/' + f['rid'] + '/cancel', {})
    check(status == 200 and cancelled['state'] == 'cancelled', 'public cancellation fixture failed')
    inspect(f, status=409, code='finalization_inspection_unavailable')
    h.stop()


def raw_post(h, path, raw):
    connection = UnixHTTPConnection(str(h.state / 'admin.sock'), timeout=8)
    try:
        try:
            connection.request('POST', path, body=raw, headers={'Content-Type': 'application/json'})
        except BrokenPipeError:
            pass
        response = connection.getresponse(); body = response.read()
        return response.status, json.loads(body) if body else None
    finally:
        connection.close()


@suite.case('strict_private_json_cli_bounds_methods_missing_host_and_router_isolation', 'guided24 verification5')
def _():
    f = main(); h = f['h']; body = payload(f); encoded = compact(body)
    api_max = encoded + b' ' * (65536 - len(encoded))
    quiet(f); before, network = snapshot(h), traffic(f)
    status, value = raw_post(h, endpoint(f), api_max)
    check(status == 200, f'exact64KiB API ceiling HTTP {status}'); validate(f, value)
    cli = compact({'flow_id': f['flow']['flow_id'], **body})
    result = h.cli('onboarding', 'join', 'owner', 'finalization', 'inspect', '--stdin',
        input=(cli + b' ' * (65536 - len(cli))).decode(), timeout=8)
    check(result.ok, 'exact64KiB CLI ceiling'); validate(f, result.json)
    ctx = compact(body['context'])
    malformed = [b'null', b'[]', b'{', encoded + b'{}', api_max + b' ',
        b'{"context":' + ctx + b',"context":' + ctx + b',"join_review_id":' + compact(body['join_review_id']) + b',"owner_review_id":' + compact(body['owner_review_id']) + b'}',
        encoded.replace(b'"integration":"claude-code"', b'"integration":"claude-code","integration":"claude-code"'),
        compact({**body, 'context': None}), compact({**body, 'join_review_id': None}), compact({**body, 'owner_review_id': 'review_bad'}),
        compact({k: v for k, v in body.items() if k != 'owner_review_id'}),
        compact({**body, 'context': {**body['context'], 'extra': 'PRIVATE_CANARY'}})]
    for field in ('code', 'key', 'file', 'provider', 'scopes', 'deadline', 'packet', 'message', 'signatures', 'administrator_offer_id'):
        malformed.append(compact({**body, field: 'PRIVATE_CANARY'}))
    for index, raw in enumerate(malformed):
        status, denied = raw_post(h, endpoint(f), raw)
        check(status == 400 and denied.get('code') == 'invalid', f'malformed API variant{index}: HTTP {status}'); public(denied, 'PRIVATE_CANARY')
        cli_raw = b'{"flow_id":' + compact(f['flow']['flow_id']) + b',' + raw[1:] if raw.startswith(b'{') else raw
        result = h.cli('onboarding', 'join', 'owner', 'finalization', 'inspect', '--stdin', input=cli_raw.decode(), timeout=8)
        check(not result.ok, f'CLI accepted malformed/duplicate/trailing/oversized variant{index}')
        public(result.stdout + result.stderr, 'PRIVATE_CANARY', str(h.root / 'absent-daemon-person-key'))
    check(snapshot(h) == before, f'boundary reads changed DB/files: {differences(before, snapshot(h))}')
    check(traffic(f) == network, 'boundary reads attempted carrier IO')
    for method in ('GET', 'PUT', 'DELETE'):
        status, denied = h.api(method, endpoint(f))
        check(status == 405, f'alternate method {method}: HTTP {status}'); public(denied)
    for args in ((), ('--stdin', 'flow_' + '0' * 32), ('--stdin', '--person-key', 'PRIVATE_CANARY')):
        result = h.cli('onboarding', 'join', 'owner', 'finalization', 'inspect', *args, input=cli.decode(), timeout=8)
        check(not result.ok, 'CLI accepted implicit stdin/positional/provider input'); public(result.stdout + result.stderr, 'PRIVATE_CANARY')
    missing = suite.host('nd', start=False); empty = private_files(missing.root)
    result = missing.cli('onboarding', 'join', 'owner', 'finalization', 'inspect', '--stdin', input=cli.decode(), timeout=8)
    check(not result.ok and private_files(missing.root) == empty, 'CLI initialized state/daemon for missing host')
    public(result.stdout + result.stderr, str(missing.root))
    credential = h.ok('adapter', 'create', '--session', f['parent']['review']['session_id'], '--expires-at', rfc3339(h.now() + timedelta(hours=1)))
    adapter = Adapter(h, f['parent']['review']['agent'], f['parent']['review']['session_id'], credential)
    status, _ = adapter.call('POST', '/adapter/v1/connect', {'adapter_id': adapter.adapter_id, 'session_id': adapter.session_id, 'instance_id': adapter.instance})
    check(status == 200, 'real scoped credential fixture')
    status, denied = adapter.call('POST', endpoint(f), body)
    check(status == 404, f'scoped adapter exposed finalization inspect HTTP {status}'); public(denied, adapter.token)
    peer, bootstrap = host('p'), host('z')
    for local, remote in ((h, peer), (peer, h)):
        local.ok('peer', 'add', '--id', remote.id, '--public-key', remote.public_key, '--address', remote.peer_address)
    result = subprocess.run([str(suite.probe_bin), '--state', str(peer.state), '--address', h.peer_address, '--alpn', 'peerspan-peer/1',
        '--method', 'POST', '--path', endpoint(f), '--body-stdin'], input=encoded, capture_output=True, timeout=8)
    check(result.returncode == 0 and json.loads(result.stdout)['status'] == 404, 'authenticated peer exposed finalization inspect')
    cert, key = suite.work / 'cert.pem', suite.work / 'tls-key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ed25519', '-nodes', '-subj', '/CN=boundary', '-days', '1',
        '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True, timeout=5)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); tls.check_hostname = False; tls.verify_mode = ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key)); tls.set_alpn_protocols(['peerspan-bootstrap/1'])
    with socket.create_connection(('127.0.0.1', bootstrap.bootstrap_port), timeout=5) as raw:
        with tls.wrap_socket(raw, server_hostname='peerspan') as stream:
            stream.sendall((f'POST {endpoint(f)} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(encoded)}\r\n\r\n').encode() + encoded)
            response = http.client.HTTPResponse(stream); response.begin(); response.read()
            check(response.status == 404, f'bootstrap exposed finalization inspect HTTP {response.status}')
    peer.stop(); bootstrap.stop()


@suite.case('same_request_explicit_original_F_and_requester_commit_then_pure_refusal_and_owner_history', 'guided24 verification6')
def _():
    f = main(); h, a, rid = f['h'], f['a'], f['rid']
    before_owner = owner(f, 'lookup')['owner']; before = inspect(f, diagnostic_phase='before_F')
    a.relay.mode = h.relay.mode = 'pass'
    a.start()
    finalize(h, before['request'], f['key'])
    view = pull_until(h, rid, 'owner_finalization_id', timeout=20)
    check(view['state'] == 'needs_commit' and not view['commit_approved'] and get(h, '/v2/networks') == [], 'F supplied requester commit/adoption')
    pull_until(a, rid, 'owner_finalization_id', timeout=15)
    a.stop(); a.relay.mode = h.relay.mode = 'drop'; quiet(f)
    inspect(f, status=409, code='finalization_inspection_unavailable', diagnostic_phase='after_F')
    check(owner(f, 'lookup')['owner'] == before_owner, 'original F changed immutable first owner consent')
    a.relay.mode = h.relay.mode = 'pass'
    a.start(); commit(h, view); wait_linked(h, a, rid, timeout=25)
    a.stop()
    # Retire any terminal outcome worker before measuring a pure later-stage
    # refusal: documented fresh unsigned creation/cancel runs expiry maintenance.
    advance_to(h, parse_time(view['expires_at']) + timedelta(seconds=1))
    spare_key = ssh_key(suite.work, 'cleanup-original'); spare_person = ssh_public_base64(spare_key)
    status, spare = h.api('POST', '/v2/link/requests', {'mode': 'new', 'network_id': '-', 'person_public_key': spare_person,
        'migration_proposal_id': '-', 'contact_invitation': '-', 'helpers': []})
    check(status == 201 and not spare['selection_approved'] and not spare['commit_approved'], 'genuine unapproved maintenance fixture')
    status, cancelled = h.api('POST', '/v2/link/requests/' + spare['request_id'] + '/cancel', {})
    check(status == 200 and cancelled['state'] == 'cancelled', 'maintenance fixture cancellation')
    a.relay.mode = h.relay.mode = 'drop'
    quiet(f)
    # Both later-stage and expiry are refusal conditions; do not attribute this
    # combined historical refusal to one particular validation precedence.
    inspect(f, status=409, diagnostic_phase='after_expiry')
    state = snapshot(h); network = traffic(f); historical = owner(f, 'lookup')
    check(historical['owner'] == before_owner and historical['request']['state'] == 'linked' and snapshot(h) == state and traffic(f) == network,
          'later application/expiry changed or recreated first immutable owner consent')
    public(get(h, '/v1/activity?limit=1000'), f['code'], f['reply'])


suite.finish()
