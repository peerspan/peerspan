#!/usr/bin/env python3
"""Bounded exact existing-person requester completion, guided section47.

Independent public contracts/test sources only. Two genuine folded-F worlds
reuse remote device15 and remote original/capped authority. The target owns
only its host/device; original files stay on the EXISTING computer. No eager
suite/product imports, authority/approval/signature/queue/clock-row edits or
worker disabling. Only one temporary schema-only dec_operations INSERT ABORT.
Full both-host DB/schema/state/home and BOTH bidirectional TCP/UDP stay strict
for settled pure refusals/history. Unsigned readers use real consumed TLS;
signed work requires actual all-carrier ACKs and outbox/journal drain.

A single explicit fresh completion is forwarded once and its real response is
lost; saved private fixture memory verifies actual application before pure
Lookup recovery. This is not an unmeasured warming completion or automatic
retry. Application rollback permits earlier genuine signing/frame/IO phases,
never partial adoption/proof outbox/outcome/secret retirement. Actual retained
signature/template/packet/frame bytes remain exact.

Limits: advanced-only approval without guided metadata is already covered46,
not newly executed47. Cancellation and positive original-provider completion
are source/fault-only here; original finite-cap/signing/refusal barriers are real.
Isolated unsigned-stage/fixed-powers expiry, reused
binding/separate admin/corrupt-pruned authority, exact key/commit/deadline races
and global worker attribution stay source/fault-only. No model/native/installed
or physical readiness claim. All67 prior files/full native415 stay unchanged.
Root executes committed source; the independent author only parses/audits it.
"""
import base64
import hashlib
import http.client
import http.server
import json
import math
import re
import select as socket_select
import shutil
import socket
import socketserver
import sqlite3
import ssl
import struct
import subprocess
import threading
import time
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from harness import (Adapter, Clock, Suite, UnixHTTPConnection, check, link_view,
                     parse_time, rfc3339, ssh_key, ssh_public_base64, wait_for, wait_linked)
from counted_peer import CountedUDP, exchange_current_contacts, peer_address

suite = Suite('machine_requester_completion', __doc__)
BASE = '/v1/onboarding/join-flows'
PROJECT = '/v1/onboarding/project-flows'
MACHINE = '/v1/onboarding/machine-owner-consent'
PREFIXES = ('psi2-', 'psl2-', 'peerspan-invite-v1.', 'peerspan-member-invite-v1.',
            'peerspan-person-invite-v1.', 'token_', 'instance_')
INSPECT_TOP = set('version host_id context flow_id join_review_id observed_at request review_id review next_action'.split())
INSPECT_REVIEW = set('version kind host_id context agent flow_id join_review_id request_id network member person_public_key host_public_key device_public_key request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id owner_root_state_id root_state_id person_lease_id host_lease_id binding_lease_id device_lease_id owner_provider host_admission reused_binding scopes binding_scopes not_after created_at expires_at request_stage_deadline'.split()) | {'effects'}
PROVIDER = set('kind person_public_key host_public_key device_public_key lease_id root_state_id scopes not_after'.split())
LINK = set('request_id role mode state network_id context_id migration_proposal_id person_public_key host_public_key device_public_key created_at expires_at request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id manifest_id activation_id outcome_id selection_approved commit_approved completed attention next'.split())
INSPECT_EFFECTS = {**{k: True for k in ('verify_existing_owner', 'verify_requester_selection', 'verify_host_admission', 'verify_owner_finalization')},
    **{k: False for k in ('prepare_commit_intent', 'approve_commit_intent', 'sign_requester_commit', 'publish_requester_commit',
                         'apply_network', 'grant_membership', 'grant_machine_powers', 'grant_agent_access', 'share_files', 'share_conversation', 'capability_calls')}}
CODES = {'invalid', 'not_found', 'review_changed', 'request_unavailable', 'review_expired', 'machine_requester_inspection_unavailable'}
shared = {}

def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def digest(domain, value):
    return 'review_' + hashlib.sha256(domain.encode() + b'\n' + canonical(value)).hexdigest()


class Relay:
    """Transparent pinned TLS bytes; fault modes affect transport only."""
    def __init__(self, target):
        self.target = target; self._mode = "pass"; self.connections = 0; self.received = 0; self.returned = 0
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
                            else:
                                with outer.lock:
                                    outer.returned += len(data)
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
            return self.connections, self.received, self.returned

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


def host(name):
    h = suite.host(name, start=False, clock=Clock(suite.work / (name + '.clock')))
    h.relay = Relay(('127.0.0.1', h.bootstrap_port))
    h.counted_peer = CountedUDP(('127.0.0.1', h.peer_port))
    config = h.root / 'transport.json'
    config.write_bytes(compact({'format': 1, 'advertise_bootstrap': [h.relay.address],
        'advertise_quic': [h.counted_peer.address], 'rendezvous': [], 'relays': [], 'publish_contacts': False}))
    config.chmod(0o600)
    h.extra_args = ['--transport-config', config, '--person-key-file', h.root / 'absent-person-key']
    h.barrier = h.root / 'barriers'; h.barrier.mkdir(mode=0o700)
    h.extra_env = {'SSH_AUTH_SOCK': str(h.root / 'absent-agent.sock'), 'PEERSPAN_DEC_TEST_MODE': '1',
                   'PEERSPAN_DEC_TEST_BARRIER_DIR': str(h.barrier)}
    return h.start()


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
    result = {}
    for path in sorted(h.state.glob("*.db")):
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)) as db, db:
            db.execute("BEGIN")
            value = {"$schema": tuple(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name")),
                     "$version": db.execute("PRAGMA user_version").fetchone()}
            for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
                value[name] = tuple(sorted(db.execute('SELECT * FROM "' + name.replace('"', '""') + '"'), key=repr))
            result[path.name] = value
    check(result, "no actual databases in machine-owner snapshot")
    return result


def files(root):
    result = {}
    for path in [root, *sorted(root.rglob("*"))] if root.exists() else []:
        # Logical DB rows include every table. SQLite WAL/SHM are read-lock and
        # checkpoint bookkeeping, including files our read connection creates.
        if any(str(path).endswith(s) and Path(str(path)[:-len(s)]).suffix == ".db" for s in ("-wal", "-shm")):
            continue
        result[str(path.relative_to(root))] = (path.lstat().st_mode,
            hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() and path.suffix != ".db" else None)
    return result


def project(h, name, *, replace=None, old=None, agent_name=None):
    body = {"project_root": old["review"]["project_root"] if old else str(suite.work / ("private " + name)),
            "native_session_id": old["review"]["native_session_id"] if old else "private-conversation-" + name,
            "integration": "claude-code", "agent": {"kind": "new", "name": agent_name or 'Agent "東京" ' + name, "owner": "Owner é"}}
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


def ed25519(public_key, signature, message, label):
    pub, sig, body = (suite.work / ('verify-' + label + suffix) for suffix in ('.der', '.sig', '.msg'))
    pub.write_bytes(bytes.fromhex('302a300506032b6570032100') + base64.b64decode(public_key, validate=True))
    sig.write_bytes(base64.b64decode(signature, validate=True)); body.write_bytes(message)
    result = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-keyform', 'DER', '-inkey', str(pub),
        '-rawin', '-in', str(body), '-sigfile', str(sig)], capture_output=True, timeout=5)
    check(result.returncode == 0, 'independent public Ed25519 verification failed: ' + label)


def public(value, *secrets):
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    for n, marker in enumerate((*PREFIXES, 'payload_base64', 'template_base64', 'message_base64',
        'return_secret', 'signing_requests', 'admin.sock', 'adapter.sock', '"seed"', '"signature"', *secrets)):
        check(not marker or marker not in text, f'machine inspection leaked private material rule{n}')


def verify_signature(fmt, key, signature, message, label):
    if fmt == 'ed25519':
        ed25519(key, signature, message, label)
        return
    check(fmt == 'sshsig', 'unexpected actual signature format')
    stem = suite.work / label
    blob = ssh_string(b'ssh-ed25519') + ssh_string(base64.b64decode(key, validate=True))
    stem.with_suffix('.allowed').write_text('fixture ssh-ed25519 ' + base64.b64encode(blob).decode() + '\n')
    stem.with_suffix('.sig').write_text('-----BEGIN SSH SIGNATURE-----\n' + '\n'.join(signature[n:n + 70] for n in range(0, len(signature), 70)) + '\n-----END SSH SIGNATURE-----\n')
    result = subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', str(stem.with_suffix('.allowed')), '-I', 'fixture',
        '-n', 'peerspan-person-v1', '-s', str(stem.with_suffix('.sig'))], input=message, capture_output=True, timeout=5)
    check(result.returncode == 0, 'independent SSHSIG verification of exact typed message failed')


def retired_expired_helper(h):
    """Observe real collection on the live original; do not start its peer."""
    last = {}
    def retired():
        now = int(h.now().timestamp()); data = records(h); last['captured'] = data
        found = False
        for database in data.values():
            if not ({'mailboxes', 'frames'} & set(database)):
                continue
            found = True
            check({'mailboxes', 'frames'} <= set(database), 'public embedded helper format1 tables missing')
            frames = database['frames']
            check(all(len(row) == 6 for row in frames), 'public helper frame column layout mismatch')
            for row in database['mailboxes']:
                check(len(row) == 12 and type(row[5]) is int and type(row[11]) is int,
                      'public helper mailbox column layout mismatch')
                if row[5] <= now and (row[10] not in ('deleted', 'expired') or row[11] != 0
                                     or any(frame[0] == row[0] for frame in frames)):
                    return False
        check(found, 'public embedded helper schema prerequisite absent')
        return True
    try:
        wait_for(retired, timeout=5, interval=.1, message='actual expired helper ciphertext retirement')
    except Exception:
        try:
            print('machine_requester_retirement_failure_public=' + json.dumps({'expired_helper_not_retired': True}), flush=True)
        except Exception:
            pass
        raise


def ssh_string(value):
    return struct.pack('>I', len(value)) + value


def statement_id(envelope):
    if isinstance(envelope, str):
        return envelope
    raw = base64.b64decode(envelope['payload_base64'], validate=True)
    message = '\n'.join(('peerspan-decentralized-statement-v1', envelope['kind'],
                         envelope['context_id'], hashlib.sha256(raw).hexdigest()))
    return 'ds_' + hashlib.sha256(message.encode()).hexdigest()


def snapshot(h):
    return records(h), files(h.state), files(h.home)


def whole(f):
    return snapshot(f['a']), snapshot(f['b'])


def traffic(f):
    return (f['a'].relay.counts(), f['b'].relay.counts(),
            f['a'].counted_peer.counts(), f['b'].counted_peer.counts())


def no_original(f):
    b = f['b']
    check(not (b.root / 'absent-person-key').exists() and not (b.root / 'absent-agent.sock').exists()
          and not (b.home / '.config/peerspan/person_ed25519').exists(), 'requester acquired an original source')
    with closing(sqlite3.connect(f'file:{db_path(b)}?mode=ro', uri=True)) as db:
        check(not db.execute("SELECT 1 FROM dec_intents WHERE kind='owner' AND json_extract(record,'$.operation_id')=?", (f['rid'],)).fetchone(),
              'requester acquired a local original owner intent')


def signed_drained(f):
    """Actual byte-storage ACKs; neither application nor a worker/TLS fence."""
    requester, _ = pending(f['b'], f['rid'])
    if requester['commit_packet_base64'] == '-' or requester['commit_intent_id'] == '-':
        return False
    ordinary = load_intent(f['b'], requester['commit_intent_id'])['record']
    if not ordinary['approved'] or not ordinary['completed'] or not ordinary['signatures']:
        return False
    for h in (f['a'], f['b']):
        record, _ = pending(h, f['rid'])
        check(all(set(e) == {'kind', 'address', 'public_key'} for e in record['carrier_endpoints']),
              'malformed actual retained carrier endpoint')
        endpoints = {(e['address'], e['public_key']) for e in record['carrier_endpoints']}
        if not endpoints or not record['outbound_frames']:
            return False
        for frame in record['outbound_frames']:
            check(set(frame) == {'role', 'writer_public_key', 'frame_id', 'acknowledged_by'}
                  and all(set(ack) == {'address', 'public_key'} for ack in frame['acknowledged_by']),
                  'malformed actual outbound ACK schema')
            if not endpoints <= {(ack['address'], ack['public_key']) for ack in frame['acknowledged_by']}:
                return False
        with closing(sqlite3.connect(f'file:{db_path(h)}?mode=ro', uri=True)) as db:
            if db.execute('SELECT count(*) FROM dec_outbox').fetchone()[0] or list(h.state.glob('*-journal')):
                return False
    return True


def quiet(f):
    """Unsigned live TLS hold or actual signed drain; all comparisons strict."""
    b = f['b']; record, _ = pending(b, f['rid'])
    active = record['terminal'] == '-' and b.now() < parse_time(link_view(b, f['rid'])['expires_at'])
    f['_guard'] = None
    if record['terminal'] == '-' and record['commit_packet_base64'] != '-':
        wait_for(lambda: signed_drained(f), timeout=5, interval=.02, message='actual signed publication ACKs/outbox/journal drain')
        def guard():
            check(signed_drained(f), 'actual signed ACK/outbox/journal prerequisite changed during pure measurement')
        f['_guard'] = guard
    elif active:
        relays = (f['a'].relay, f['b'].relay)
        held = f.get('_held', [])
        fresh = bool(held) and time.monotonic() - f.get('_held_at', 0) < 1 and all(
            relay.mode == 'hold' and generation in relay.live_generations() for relay, generation in held)
        if not fresh:
            for relay in relays:
                relay.refresh_hold()
            held = wait_for(lambda: [(relay, n) for relay in relays for n in relay.live_generations()] or None,
                timeout=5, interval=.02, message='actual requester TLS ClientHello outside database')
            f['_held'], f['_held_at'] = held, time.monotonic()
        def guard():
            check(all(relay.mode == 'hold' and n in relay.live_generations() for relay, n in held),
                  'confirmed live requester transport hold ended during inspection')
        f['_guard'] = guard
    else:
        for relay in (f['a'].relay, f['b'].relay):
            relay.mode = 'drop'
    previous = (whole(f), traffic(f))
    def stable():
        nonlocal previous
        current = (whole(f), traffic(f)); same = current == previous; previous = current
        return same
    time.sleep(.1)
    wait_for(stable, timeout=3, interval=.1, message='whole-state requester inspection baseline')
    if f['_guard']:
        f['_guard']()


def strict(f, before, counters, phase):
    after, current = whole(f), traffic(f)
    if after != before or current != counters:
        # Captured categories only: never dump rows, paths, private hashes or IDs.
        tables = set('networks network_members peers agents sessions adapter_connections adapter_credentials events dec_contexts dec_objects dec_admissions dec_restrictions dec_activations dec_heads dec_highwater dec_signers dec_clock dec_intents dec_pending dec_frames dec_operations dec_outbox dec_contacts dec_helpers onboarding_project_flows onboarding_join_flows helper_format mailboxes frames sqlite_sequence'.split())
        sides = []
        for side, old, new in zip(('existing', 'requester'), before, after):
            changed = set(); schema = version = False
            for name in set(old[0]) | set(new[0]):
                x, y = old[0].get(name, {}), new[0].get(name, {})
                schema |= x.get('$schema') != y.get('$schema'); version |= x.get('$version') != y.get('$version')
                changed |= {t if t in tables else 'unknown' for t in (set(x) | set(y)) - {'$schema', '$version'} if x.get(t) != y.get(t)}
            sides.append({'side': side, 'tables': sorted(changed), 'schema_changed': schema, 'version_changed': version,
                          'database_set_changed': set(old[0]) != set(new[0]), 'state_changed': old[1] != new[1], 'home_changed': old[2] != new[2]})
        print('machine_requester_purity_public=' + json.dumps({'phase': phase, 'sides': sides,
            'carrier_changed_positions': [[i for i, (x, y) in enumerate(zip(a, b)) if x != y] for a, b in zip(counters, current)]}, sort_keys=True), flush=True)
    check(after == before, 'inspection changed whole logical DB/schema/state/home')
    check(current == counters, 'inspection performed counted bidirectional TCP/UDP IO')
    if f.get('_guard'):
        f['_guard']()
    no_original(f)


def inspection_endpoint(f):
    return BASE + '/' + f['flow']['flow_id'] + '/machine-commit/inspect'


def inspection_body(f):
    return {'context': context(f['parent']), 'join_review_id': f['flow']['review_id']}


def raw_post(h, path, raw):
    conn = UnixHTTPConnection(str(h.state / 'admin.sock'), timeout=5)
    try:
        conn.request('POST', path, body=raw, headers={'Content-Type': 'application/json'})
        response = conn.getresponse(); data = response.read()
        return response.status, json.loads(data) if data.strip() else None
    finally:
        conn.close()


def inspect_machine(f, *, status=200, code=None, cli=False, override=None, path=None, pure=True):
    if pure:
        quiet(f)
        before, counters = whole(f), traffic(f)
    data = inspection_body(f) if override is None else override
    if cli:
        result = f['b'].cli('onboarding', 'join', 'machine-commit', 'inspect', '--stdin',
            input=compact({'flow_id': f['flow']['flow_id'], **data}).decode(), timeout=8)
        check(result.ok == (status == 200), 'machine requester CLI success/refusal mismatch')
        public(result.stdout + result.stderr, *f['secrets'], str(f['b'].root))
        value = result.json if result.ok else None
    else:
        actual, value = f['b'].api('POST', path or inspection_endpoint(f), data, timeout=5)
        check(actual == status, f'machine requester inspection HTTP {actual}, expected {status}')
        if code:
            actual_code = value.get('code') if type(value) is dict else None
            check(actual_code == code, 'inspection controlled code ' + (actual_code if actual_code in CODES else 'unknown') + ', expected ' + code)
        public(value, *f['secrets'])
    if pure:
        strict(f, before, counters, 'success' if status == 200 else 'refusal')
    return value


def base_world(name='device'):
    if name in shared:
        check(shared[name].get('_base'), 'earlier genuine setup failed before base publication')
        return shared[name]
    f = {}; shared[name] = f
    a, b = host(name + 'a'), host(name + 'b')
    key = ssh_key(suite.work, name + '-remote-original')
    net = a.ok('network', 'create', 'Remote machine "東京" ' + name, '--as', 'Existing "é" owner', '--person-key-file', key)
    owner_parent, parent = project(a, name + 'a'), project(b, name + 'b')
    people = get(a, '/v2/networks/' + net['id'] + '/persons')['persons']
    person = ssh_public_base64(key); rows = [r for r in people if r['person_public_key'] == person]
    check(len(rows) == 1 and a.public_key != b.public_key, 'distinct real hosts and admitted existing person required')
    creation = max(a.now(), b.now()) + timedelta(seconds=2)
    for h in (a, b):
        advance_to(h, creation)
    status, issued = a.api('POST', '/v2/networks/' + net['id'] + '/invitations', {
        'member': rows[0]['member'], 'expected_person_public_key': person,
        'expires_at': rfc3339(a.now() + timedelta(seconds=65))})
    check(status == 201 and issued.get('invitation'), f'genuine pinned existing-person introduction HTTP {status}')
    status, flow = b.api('POST', BASE, {'context': context(parent), 'invitation': issued['invitation'], 'person_public_key': person})
    check(status == 201 and flow['state'] == 'review', f'genuine exact guided join preparation HTTP {status}')
    status, flow = b.api('POST', BASE + '/' + flow['flow_id'] + '/decision', {
        'context': context(parent), 'review_id': flow['review_id'], 'decision': 'approve', 'invitation': issued['invitation']})
    check(status == 200 and flow['state'] == 'requested', f'genuine public-key-only machine publication HTTP {status}')
    rid = flow['outcome']['request_id']
    # The documented identical ordinary publication returns the SAME private
    # advanced handoff, without another request or original identity.
    status, same = b.api('POST', '/v2/link/requests', {'mode': 'new', 'network_id': net['id'], 'person_public_key': person,
        'migration_proposal_id': '-', 'contact_invitation': issued['invitation'], 'helpers': []})
    check(status == 200 and same['request_id'] == rid and same.get('display_code'), 'ordinary exact publication did not reuse guided request')
    f.update(a=a, b=b, key=key, person=person, network=net, parent=parent, owner_parent=owner_parent,
             flow=flow, rid=rid, reply=same['display_code'], issued=issued,
             secrets=[issued['invitation'], same['display_code'], str(key)])
    incoming = wait_for(lambda: next((v for v in get(a, '/v2/link/requests') if v['request_id'] == rid), None),
        timeout=15, interval=.1, message='genuine automatic machine request return')
    check(incoming['role'] == 'approver' and incoming['state'] == 'pending' and incoming['owner_offer_id'] == '-', 'automatic return changed owner consent')
    target = max(a.now(), b.now(), parse_time(issued['expires_at']) + timedelta(seconds=1))
    check(target < parse_time(same['expires_at']), 'invitation retirement consumed request bound')
    for h in (a, b):
        advance_to(h, target)
    def retired():
        with closing(sqlite3.connect(f'file:{db_path(a)}?mode=ro', uri=True)) as db:
            row = db.execute('SELECT secret FROM dec_pending WHERE request_id=?', (issued['invitation_id'],)).fetchone()
        return row is None or row[0] is None
    wait_for(retired, timeout=5, interval=.1, message='actual automatic-return secret retirement')
    for h in (a, b):
        retired_expired_helper(h)
    provider = get(a, '/v2/networks/' + net['id'])['provider']
    check(provider['kind'] == 'device' and provider['scopes'] == 15, 'creator-device15 public authority prerequisite')
    if name == 'original':
        status, selected = a.api('POST', '/v2/networks/' + net['id'] + '/provider', {
            'provider_id': person, 'person_public_key': person, 'host_public_key': a.public_key, 'approve': True})
        check(status == 200 and selected['provider']['kind'] == 'original_person', 'genuine remote original public selection')
        provider = selected['provider']
    f['provider'] = provider; f['_base'] = True
    no_original(f)
    return f


def finalize_failure_diagnostic(f, result):
    """Failure-only public metadata; never changes the original verdict."""
    known = {'invalid', 'not_found', 'forbidden', 'proof_required', 'state_conflict', 'operation_conflict',
             'clock_rollback', 'signer_unavailable', 'quota_exceeded', 'review_required', 'review_expired',
             'review_changed', 'not_yet_valid', 'authority_expired', 'recovery_required', 'version_exhausted'}
    summary = {'exit_code': result.code if type(result.code) is int else 'unknown', 'json_error_code': 'unknown',
               'public_code_tokens': [], 'http_status': 'unknown', 'owner_present': 'unknown',
               'selection_present': 'unknown', 'finalization_present': 'unknown'}
    try:
        code = result.json.get('code') if type(result.json) is dict else None
        summary['json_error_code'] = code if code in known else 'unknown'
        summary['public_code_tokens'] = sorted(code for code in known if re.search(
            r'(?<![A-Za-z0-9_])' + re.escape(code) + r'(?![A-Za-z0-9_])', result.stderr))
        status, value = f['a'].api('GET', '/v2/link/requests/' + f['rid'], timeout=2)
        if type(status) is int and 100 <= status <= 599:
            summary['http_status'] = status
        if status == 200 and type(value) is dict and set(value) == LINK:
            for output, field in (('owner_present', 'owner_offer_id'), ('selection_present', 'selection_id'),
                                  ('finalization_present', 'owner_finalization_id')):
                reference = value.get(field)
                if reference == '-' or (isinstance(reference, str) and re.fullmatch(r'dpk_[0-9a-f]{64}', reference)):
                    summary[output] = reference != '-'
    except Exception:
        pass  # Bounded diagnostics never mask the unchanged failing check.
    print('machine_requester_finalize_failure_public=' + json.dumps(summary, sort_keys=True), flush=True)


def progress(f):
    if f.get('_ready'):
        return f
    a, b, rid = f['a'], f['b'], f['rid']
    for relay in (a.relay, b.relay):
        relay.mode = 'pass'
    status, inspected = a.api('POST', '/v1/onboarding/machine-owner-inspection', {'context': context(f['owner_parent']), 'request_id': rid})
    check(status == 200, f'genuine existing-computer inspection HTTP {status}')
    status, prepared = a.api('POST', MACHINE + '/prepare', {'context': context(f['owner_parent']),
        'request_id': rid, 'inspection_review_id': inspected['review_id']})
    check(status == 200 and prepared['consent']['state'] == 'review', f'genuine guided machine consent prepare HTTP {status}')
    f['owner_consent'] = prepared['consent']
    if f['provider']['kind'] == 'original_person':
        # Configured EXACT private source lives on the existing computer only.
        source = a.root / 'absent-person-key'; shutil.copyfile(f['key'], source); source.chmod(0o600)
    status, approved = a.api('POST', MACHINE + '/approve', {'context': context(f['owner_parent']), 'request_id': rid,
        'consent_id': prepared['consent']['consent_id'], 'consent_review_id': prepared['consent']['review_id']})
    check(status == 200 and approved['consent']['state'] == 'approved', f'genuine exact dual approval HTTP {status}')
    wait_for(lambda: link_view(b, rid)['owner_offer_id'] != '-', timeout=15, interval=.1, message='actual remote owner offer retained by requester')
    view = wait_for(lambda: (v if v['selection_id'] != '-' and v['selection_approved'] else None)
        if (v := link_view(b, rid)) else None, timeout=10, interval=.1, message='ordinary single-offer requester selection')
    check(view['administrator_offer_id'] == '-' and 'administrator_offered' not in view['completed'], 'folded owner acquired fake administrator stage')
    selected = dict(view)  # Capture pins before the one Finalize action.
    # A single explicit existing-computer driver may fetch genuine selection;
    # neither this inspection nor the requester performs a protocol driver.
    a.cli('link', 'resume', rid, timeout=15)
    wait_for(lambda: link_view(a, rid)['selection_id'] == view['selection_id'], timeout=10, interval=.1,
             message='existing computer retained exact requester selection')
    if link_view(b, rid)['owner_finalization_id'] == '-':
        args = ['link', 'finalize', rid, '--network', view['network_id'], '--context', view['context_id'],
            '--expect-person', view['person_public_key'], '--expect-host-key', view['host_public_key'],
            '--expect-device-key', view['device_public_key'], '--owner-offer', view['owner_offer_id'],
            '--selection', view['selection_id'], '--administrator-offer', '-', '--approve']
        if f['provider']['kind'] == 'original_person':
            args += ['--person-key', a.root / 'absent-person-key']
        result = a.cli(*args, timeout=20)
        if not (type(result.code) is int and result.code in (0, 1)):
            try:
                finalize_failure_diagnostic(f, result)
            except Exception:
                pass  # Preserve the original failure even if the observer fails.
        check(type(result.code) is int and result.code in (0, 1), 'exact existing-computer finalization failed')
    view = wait_for(lambda: v if (v := link_view(b, rid))['owner_finalization_id'] != '-' else None,
        timeout=15, interval=.1, message='actual requester received existing-person F')
    check(view['state'] == 'needs_commit' and not view['commit_approved'] and view['selection_approved']
          and view['administrator_offer_id'] == '-' and view['manifest_id'] == view['activation_id'] == view['outcome_id'] == '-',
          'genuine folded F prefix advanced independent commit/application')
    f['view'] = view
    record, _ = pending(b, rid); f['packet_evidence'] = record
    stage = record.get('stage_at', '-')
    f['stage_deadline'] = rfc3339(parse_time(view['created_at'] if stage == '-' else stage) + timedelta(seconds=600))
    verify_finalized_setup(f, selected)
    # Isolate subsequent pure reads from approved remote work. The stopped peer's
    # complete DB/files remain in every snapshot; requester stays live/held.
    a.stop()
    f['_ready'] = True
    quiet(f)
    return f

def evidence(f):
    record, _ = pending(f['b'], f['rid'])
    check(record['owner_intent_id'] == record['commit_intent_id'] == '-' and not record['commit_approved'],
          'requester has forbidden owner/commit intent before inspection')
    packets = {}
    for role, field, ref in (('request', 'request_packet_base64', 'request_packet_id'),
        ('owner', 'owner_packet_base64', 'owner_offer_id'), ('selection', 'selection_packet_base64', 'selection_id'),
        ('owner_finalization', 'owner_finalization_packet_base64', 'owner_finalization_id')):
        packet = json.loads(base64.b64decode(record[field], validate=True))
        check(packet['request_id'] == f['rid'] and packet['role'] == role and packet_id(packet) == f['view'][ref], 'exact verified retained packet identity/role')
        message = packet_message(packet)
        ed25519(packet['writer_host_public_key'], packet['host_signature'], message, f['b'].name + '-' + role + '-host')
        if role in ('request', 'selection'):
            check(packet['writer_host_public_key'] == f['b'].public_key and packet['signer_public_key'] == f['view']['device_public_key']
                  and packet['authority_signature_format'] == packet['authority_signature'] == '-', 'target-only request/selection proof')
            ed25519(packet['signer_public_key'], packet['device_signature'], message, f['b'].name + '-' + role + '-device')
        else:
            provider = f['provider']
            check(packet['writer_host_public_key'] == f['a'].public_key and packet['person_public_key'] == f['person']
                  and packet['signer_public_key'] == (f['person'] if provider['kind'] == 'original_person' else provider['device_public_key'])
                  and packet['issuer_id'] == ('-' if provider['kind'] == 'original_person' else provider['lease_id']), 'remote exact selected owner/F signer')
            verify_signature(packet['authority_signature_format'], packet['signer_public_key'], packet['authority_signature'],
                             message, f['b'].name + '-' + role + '-authority')
        packets[role] = packet
    request_bytes = base64.b64decode(packets['request']['payload_base64'], validate=True)
    expected_request = 'link_' + hashlib.sha256(('peerspan-decentralized-request-id-v1\n' + hashlib.sha256(request_bytes).hexdigest()).encode()).hexdigest()
    check(expected_request == f['rid'], 'signed request ID domain/payload mismatch')
    request = json.loads(request_bytes)
    check(request['expected_network_id'] == f['network']['id'] and request['expected_context_id'] == f['network']['context_id']
          and request['expected_person_public_key'] == f['person'] and request['host_public_key'] == f['b'].public_key
          and request['device_public_key'] == f['view']['device_public_key'], 'actual signed machine pins changed')
    catalog = json.loads(base64.b64decode(record['catalog_base64'], validate=True)); statements = set()
    check(catalog['context_id'] == f['network']['context_id'] and catalog['objects'], 'actual proof catalog absent')
    for item in catalog['objects']:
        raw = base64.b64decode(item['body_base64'], validate=True)
        proof = 'dp_' + hashlib.sha256(('peerspan-decentralized-proof-v1\n' + item['kind'] + '\n' + hashlib.sha256(raw).hexdigest()).encode()).hexdigest()
        check(proof == item['id'], 'retained proof ID does not bind exact bytes')
        envelope = json.loads(raw)
        if isinstance(envelope, dict) and {'kind', 'context_id', 'payload_base64'} <= set(envelope):
            statements.add(statement_id(envelope))
    owner = json.loads(base64.b64decode(packets['owner']['payload_base64'], validate=True))
    final = json.loads(base64.b64decode(packets['owner_finalization']['payload_base64'], validate=True))
    check(owner['root_state_id'] != '-' and owner['person_lease_id'] != '-' and owner['scopes'] == 7
          and owner['host_public_key'] == f['b'].public_key and owner['device_public_key'] == f['view']['device_public_key'],
          'owner offer is not existing-person exact7 authority')
    return record, packets, owner, final, statements


def verify_finalized_setup(f, selected):
    """Verify retained F before baseline; never pre-call the inspection API."""
    a, b, rid = f['a'], f['b'], f['rid']
    status, existing = a.api('GET', '/v2/link/requests/' + rid, timeout=5)
    requester = f['view']
    check(status == 200 and type(existing) is dict and set(existing) == LINK
          and set(requester) == LINK, 'exact existing/requester finalization status prerequisite')
    pins = ('request_id', 'network_id', 'context_id', 'person_public_key', 'host_public_key',
            'device_public_key', 'request_packet_id', 'owner_offer_id', 'selection_id', 'administrator_offer_id')
    check(selected['request_id'] == rid and selected['network_id'] == f['network']['id']
          and selected['context_id'] == f['network']['context_id'] and selected['person_public_key'] == f['person']
          and selected['host_public_key'] == b.public_key and selected['administrator_offer_id'] == '-',
          'captured selection does not bind the genuine folded machine request')
    check(all(view[key] == selected[key] for view in (existing, requester) for key in pins),
          'two-host finalization changed captured request/network/context/person/host/device/stage pins')
    check(re.fullmatch(r'dpk_[0-9a-f]{64}', requester['owner_finalization_id'])
          and existing['owner_finalization_id'] == requester['owner_finalization_id'],
          'two hosts did not retain the same canonical signed F')
    record, packets, owner, final, statements = evidence(f)
    check(packets['request']['context_id'] == packets['request']['person_public_key'] == packets['request']['issuer_id'] == '-'
          and all(packets[role]['context_id'] == selected['context_id'] for role in ('owner', 'selection', 'owner_finalization')),
          'retained signed packet context/authority domain mismatch')
    selection = json.loads(base64.b64decode(packets['selection']['payload_base64'], validate=True))
    check(all(selection[key] == selected[key] for key in ('request_packet_id', 'owner_offer_id', 'context_id',
          'person_public_key', 'host_public_key', 'device_public_key'))
          and owner['request_packet_id'] == selected['request_packet_id']
          and final['selection_id'] == selected['selection_id'] and final['administrator_offer_id'] == '-',
          'signed owner/selection/F payloads changed captured pins')
    check(owner['descriptor'] == {'format': 1, 'protocol': 'peerspan-decentralized-v1',
          'network_id': selected['network_id'], 'name': f['network']['name'],
          'genesis_root_public_key': f['network']['genesis_root_public_key']}, 'owner descriptor changed actual network')
    refs = {owner['root_state_id'], final['root_state_id'], final['person_lease_id'], final['host_lease_id']}
    check(all(re.fullmatch(r'ds_[0-9a-f]{64}', ref) for ref in refs) and refs <= statements,
          'retained F root/P/H semantic dependencies missing from verified proof catalog')
    cap = min(parse_time(selected['created_at']) + timedelta(days=7), parse_time(f['provider']['not_after']))
    check(parse_time(owner['not_after']) == cap and max(a.now(), b.now()) < cap,
          'retained signed owner powers do not have the exact finite inherited cap')
    catalog = json.loads(base64.b64decode(record['catalog_base64'], validate=True))
    envelopes = [json.loads(base64.b64decode(item['body_base64'], validate=True)) for item in catalog['objects']]
    by_id = {statement_id(value): value for value in envelopes
             if type(value) is dict and {'kind', 'context_id', 'payload_base64'} <= set(value)}
    grants = {}
    for kind, envelope in (('person_lease', by_id[final['person_lease_id']]),
                           ('host_lease', by_id[final['host_lease_id']]),
                           ('binding_lease', final['binding_lease']), ('device_lease', final['device_lease'])):
        check(type(envelope) is dict and envelope['kind'] == kind and envelope['context_id'] == selected['context_id'],
              'genuine new-machine F grant kind/context prerequisite')
        payload = json.loads(base64.b64decode(envelope['payload_base64'], validate=True)); grants[kind] = payload
        check(payload['root_state_id'] == final['root_state_id'], 'F grant changed actual root dependency')
        check(any(s['role'] == 'issuer' and s['signature'] != '-' for s in envelope['signatures']),
              'retained F grant lacks an actual issuer signature')
        for signature in envelope['signatures']:
            if signature['signature'] != '-':
                message = '\n'.join(('peerspan-decentralized-signature-v1', statement_id(envelope),
                                      signature['role'], signature['public_key'])).encode()
                verify_signature(signature['format'], signature['public_key'], signature['signature'], message,
                                 b.name + '-setup-' + kind + '-' + signature['role'])
    check(grants['person_lease']['subject']['person_public_key'] == selected['person_public_key']
          and grants['host_lease']['subject']['host_public_key'] == selected['host_public_key']
          and grants['host_lease']['issuer']['kind'] != 'root', 'actual existing-person P/folded H target prerequisite')
    binding_id = statement_id(final['binding_lease'])
    for kind, scopes in (('binding_lease', 2), ('device_lease', 7)):
        payload = grants[kind]; subject = payload['subject']; parents = {p['role']: p['id'] for p in payload['parents']}
        check(payload['operation_id'] == rid and subject['person_public_key'] == selected['person_public_key']
              and subject['host_public_key'] == selected['host_public_key'] and subject['scopes'] == scopes
              and subject['device_public_key'] == (selected['device_public_key'] if kind == 'device_lease' else '-')
              and payload['not_after'] == owner['not_after'] and parents['subject_person'] == final['person_lease_id']
              and parents['subject_host'] == final['host_lease_id']
              and (kind != 'device_lease' or parents['subject_binding'] == binding_id),
              'actual signed F B/D target/profile/deadline/parent prerequisite')


def validate_inspection(f, value):
    b, flow = f['b'], f['flow']
    check(type(value) is dict and set(value) == INSPECT_TOP and type(value['version']) is int and value['version'] == 1, 'closed machine requester wrapper')
    check(value['host_id'] == b.id and value['context'] == context(f['parent']) and value['flow_id'] == flow['flow_id']
          and value['join_review_id'] == flow['review_id'] and value['next_action'] == 'review_machine_requester_consent', 'exact flow/parent/host/action')
    check(re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value['observed_at'])
          and abs((parse_time(value['observed_at']) - b.now()).total_seconds()) < 5, 'canonical guarded observation')
    request = value['request']
    check(set(request) == LINK and request == link_view(b, f['rid']) and request['state'] == 'needs_commit'
          and request['role'] == 'requester' and request['mode'] == 'new' and request['migration_proposal_id'] == '-', 'exact current received requester prefix')
    check(request['completed'] == ['request_created', 'owner_offered', 'owner_selected', 'owner_finalized']
          and request['selection_approved'] and not request['commit_approved'] and request['administrator_offer_id'] == '-'
          and request['manifest_id'] == request['activation_id'] == request['outcome_id'] == '-', 'folded prefix invented admin/commit/application')
    record, packets, owner, final, statements = evidence(f)
    review = value['review']
    check(type(review) is dict and set(review) == INSPECT_REVIEW and type(review['version']) is int and review['version'] == 1
          and review['kind'] == 'inspect_existing_person_requester_commit', 'closed complete machine requester review')
    expected = {'host_id': b.id, 'context': context(f['parent']), 'agent': f['parent']['review']['agent'],
        'flow_id': flow['flow_id'], 'join_review_id': flow['review_id'], 'request_id': f['rid'],
        'network': {key: f['network'][key] for key in ('id', 'name', 'context_id', 'genesis_root_public_key')},
        'member': owner['member'], 'person_public_key': f['person'], 'host_public_key': b.public_key,
        'device_public_key': request['device_public_key'], 'owner_root_state_id': owner['root_state_id'],
        'owner_provider': f['provider'], 'host_admission': 'folded_owner', 'reused_binding': isinstance(final['binding_lease'], str),
        'root_state_id': final['root_state_id'], 'person_lease_id': final['person_lease_id'], 'host_lease_id': final['host_lease_id'],
        'binding_lease_id': statement_id(final['binding_lease']), 'device_lease_id': statement_id(final['device_lease']),
        'scopes': 7, 'binding_scopes': 2, 'not_after': owner['not_after'], 'created_at': request['created_at'],
        'expires_at': request['expires_at'], 'request_stage_deadline': f['stage_deadline'], 'effects': INSPECT_EFFECTS}
    for key in ('request_packet_id', 'owner_offer_id', 'selection_id', 'administrator_offer_id', 'owner_finalization_id'):
        expected[key] = request[key]
    for key, expected_value in expected.items():
        check(review[key] == expected_value, 'machine requester changed reviewed public term: ' + key)
    check(type(review['reused_binding']) is bool and type(review['scopes']) is int and type(review['binding_scopes']) is int
          and set(review['owner_provider']) == PROVIDER and all(type(v) is bool for v in review['effects'].values()), 'closed typed provider/effects/scopes')
    for key in ('owner_root_state_id', 'root_state_id', 'person_lease_id', 'host_lease_id', 'binding_lease_id', 'device_lease_id'):
        check(re.fullmatch(r'ds_[0-9a-f]{64}', review[key]), 'canonical statement reference: ' + key)
    check({review[key] for key in ('owner_root_state_id', 'root_state_id', 'person_lease_id', 'host_lease_id')} <= statements,
          'root/P/H semantic statement identities absent from genuine catalog (not proof IDs)')
    check(review['owner_provider']['host_public_key'] == f['a'].public_key and review['owner_provider']['host_public_key'] != b.public_key
          and review['owner_provider']['device_public_key'] != request['device_public_key'], 'remote provider became requester/local original')
    cap = min(parse_time(request['created_at']) + timedelta(days=7), parse_time(review['owner_provider']['not_after']))
    check(parse_time(review['not_after']) == cap and parse_time(value['observed_at']) < cap, 'finite exact signed/provider7day cap')
    check(value['review_id'] == digest('peerspan-machine-requester-inspection-v1', review), 'independent canonical UTF8 domain digest')
    check(not any(v['id'] == f['network']['id'] for v in get(b, '/v2/networks')), 'inspection adopted the remote network')
    no_original(f); public(value, *f['secrets'])


CONSENT_TOP = set('version host_id context flow_id join_review_id observed_at request consent'.split())
CONSENT_REVIEW = set('version kind consent_id host_id context agent flow_id join_review_id request_id intent_id inspection_review_id inspection created_at expires_at effects'.split())
RECORD = set('format operation_id approved approved_at review_base64 provider root_state_id person_public_key host_public_key device_public_key scopes not_after created_at expires_at templates signatures completed terminal result_base64'.split())
CONSENT_EFFECTS = {**{k: True for k in ('approve_commit_intent', 'authorize_binding_host_signature',
    'authorize_requester_commit_signatures', 'authorize_commit_publication', 'authorize_local_application')},
    **{k: False for k in ('grant_agent_access', 'share_files', 'share_conversation', 'capability_calls')}}
CODES |= {'machine_requester_consent_unavailable'}


def endpoint(f, action):
    return BASE + '/' + f['flow']['flow_id'] + '/machine-commit/' + action


def intent_rows(h, rid, kind):
    with closing(sqlite3.connect(f'file:{db_path(h)}?mode=ro', uri=True)) as db:
        return [(row[0], json.loads(row[1]), row[2]) for row in db.execute(
            "SELECT intent_id,record,secret FROM dec_intents WHERE kind=? AND json_extract(record,'$.operation_id')=? ORDER BY intent_id", (kind, rid))]


def load_intent(h, iid):
    with closing(sqlite3.connect(f'file:{db_path(h)}?mode=ro', uri=True)) as db:
        row = db.execute('SELECT network_id,context_id,kind,record,secret FROM dec_intents WHERE intent_id=?', (iid,)).fetchone()
    check(row is not None, 'exact metadata/ordinary intent vanished')
    return {'network_id': row[0], 'context_id': row[1], 'kind': row[2], 'record': json.loads(row[3]), 'secret': row[4]}


def coherent(f, consent):
    with closing(sqlite3.connect(f'file:{db_path(f["b"])}?mode=ro', uri=True)) as db, db:
        db.execute('BEGIN')
        records = [db.execute('SELECT record FROM dec_intents WHERE intent_id=?', (iid,)).fetchone()
                   for iid in (consent['consent_id'], consent['review']['intent_id'])]
        request = db.execute('SELECT record FROM dec_pending WHERE request_id=?', (f['rid'],)).fetchone()
    check(all(row is not None for row in records) and request is not None, 'coherent approval evidence missing')
    return [json.loads(row[0]) for row in records] + [json.loads(request[0])]


def core(c):
    return {key: c[key] for key in ('consent_id', 'review_id', 'review')}


def input_for(f, action, prepared=None):
    data = inspection_body(f)
    if action == 'prepare':
        data['inspection_review_id'] = f['inspection']['review_id']
    if action == 'approve':
        data['consent_review_id'] = (prepared or f.get('prepared') or {}).get('consent', {}).get('review_id', 'review_' + '0' * 64)
    return data


def validate_consent(f, value):
    b, flow = f['b'], f['flow']
    check(type(value) is dict and set(value) == CONSENT_TOP and type(value['version']) is int and value['version'] == 1, 'closed exact requester consent wrapper')
    check(value['host_id'] == b.id and value['context'] == context(f['parent']) and value['flow_id'] == flow['flow_id']
          and value['join_review_id'] == flow['review_id'], 'exact recorded flow/host/context/agent attribution')
    check(re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value['observed_at'])
          and abs((parse_time(value['observed_at']) - b.now()).total_seconds()) < 5, 'canonical effective observation')
    request = value['request']
    check(set(request) == LINK and request == link_view(b, f['rid']) and request['request_id'] == f['rid']
          and request['role'] == 'requester' and request['mode'] == 'new' and request['migration_proposal_id'] == '-'
          and request['person_public_key'] == f['person'] and request['host_public_key'] == b.public_key, 'complete exact requester LINK_VIEW')
    c = value['consent']
    if c is None:
        check(not intent_rows(b, f['rid'], 'machine_requester_review'), 'null lookup hid a metadata receipt')
        public(value, *f['secrets']); no_original(f); return
    check(type(c) is dict and set(c) == {'consent_id', 'review_id', 'review', 'state', 'next_action'}
          and re.fullmatch(r'dint_[0-9a-f]{32}', c['consent_id']), 'closed canonical consent object')
    r = c['review']; frozen = f['inspection']['review']
    check(set(r) == CONSENT_REVIEW and type(r['version']) is int and r['version'] == 1
          and r['kind'] == 'approve_existing_person_requester_commit', 'closed immutable machine requester review')
    expected = {'consent_id': c['consent_id'], 'host_id': b.id, 'context': context(f['parent']),
        'agent': f['parent']['review']['agent'], 'flow_id': flow['flow_id'], 'join_review_id': flow['review_id'],
        'request_id': f['rid'], 'inspection_review_id': f['inspection']['review_id'], 'inspection': frozen, 'effects': CONSENT_EFFECTS}
    for key, target in expected.items():
        check(r[key] == target, 'consent replaced frozen reviewed term: ' + key)
    check(r['inspection_review_id'] == digest('peerspan-machine-requester-inspection-v1', frozen)
          and c['review_id'] == digest('peerspan-machine-requester-consent-v1', r), 'independent separated inspection/consent digest')
    check(re.fullmatch(r'dint_[0-9a-f]{32}', r['intent_id']) and r['intent_id'] != c['consent_id']
          and all(type(v) is bool for v in r['effects'].values()), 'typed distinct nonsigning receipt/ordinary intent')
    metadata, ordinary = load_intent(b, c['consent_id']), load_intent(b, r['intent_id'])
    m, o = metadata['record'], ordinary['record']
    check(metadata['kind'] == 'machine_requester_review' and ordinary['kind'] == 'requester_commit'
          and set(m) == RECORD and set(o) == RECORD and metadata['secret'] is ordinary['secret'] is None,
          'closed unsigned metadata/ordinary kinds or secret duplication')
    for stored in (metadata, ordinary):
        check(stored['network_id'] == frozen['network']['id'] and stored['context_id'] == frozen['network']['context_id'], 'record changed exact network/context')
    check(m['format'] == o['format'] == 1 and m['operation_id'] == o['operation_id'] == f['rid']
          and m['templates'] == m['signatures'] == [] and m['completed'] is True and m['terminal'] == m['result_base64'] == '-',
          'metadata became a signing/protocol job or invented operation domain')
    for key in ('provider', 'root_state_id', 'person_public_key', 'host_public_key', 'device_public_key', 'scopes', 'not_after', 'created_at'):
        check(m[key] == o[key], 'metadata did not copy immutable actual ordinary term: ' + key)
    check(o['provider'] == {'kind': 'requester', 'signer_public_key': frozen['device_public_key'], 'signature_format': 'ed25519', 'lease_id': '-'}
          and o['root_state_id'] == frozen['root_state_id'] and o['person_public_key'] == f['person']
          and o['host_public_key'] == b.public_key and o['device_public_key'] == frozen['device_public_key']
          and o['scopes'] == 7 and o['not_after'] == frozen['not_after'], 'requester provider was substituted for remote original/device')
    check(base64.b64decode(m['review_base64'], validate=True) == canonical(r) and r['created_at'] == o['created_at']
          and m['expires_at'] == r['expires_at'] and parse_time(r['expires_at']) == min(
              parse_time(o['created_at']) + timedelta(minutes=15), parse_time(frozen['expires_at']),
              parse_time(frozen['request_stage_deadline']), parse_time(frozen['not_after'])), 'exact canonical frozen metadata/timestamps/window')
    check(len(intent_rows(b, f['rid'], 'machine_requester_review')) == len(intent_rows(b, f['rid'], 'requester_commit')) == 1, 'duplicate request-bound ordinary/receipt')
    states = {'approved': 'follow_machine_link', 'review': 'approve_machine_requester_commit',
              'cancelled': 'inspect_machine_link', 'expired': 'inspect_machine_link', 'invalidated': 'inspect_machine_link'}
    check(c['state'] in states and c['next_action'] == states[c['state']], 'consent state/action inconsistency')
    receipt, intent, current = coherent(f, c)
    if c['state'] == 'approved':
        check(receipt['approved'] is intent['approved'] is current['commit_approved'] is True
              and receipt['approved_at'] == intent['approved_at'] != '-' and current['commit_intent_id'] == r['intent_id'], 'non-atomic dual/pending approval/time/reference')
    else:
        check(receipt['approved'] is False and receipt['approved_at'] == '-', 'unapproved receipt gained project attribution')
        if c['state'] == 'review':
            check(intent['approved'] is False and intent['approved_at'] == '-' and intent['signatures'] == []
                  and not current['commit_approved'] and current['commit_intent_id'] == '-' and current['commit_packet_base64'] == '-', 'preparation signed/approved/published requester work')
    no_original(f); public(value, *f['secrets'])


def op(f, action, prepared=None, *, pure=False, cli=False, status=200, code=None, override=None, path=None):
    if pure:
        quiet(f); before, counters = whole(f), traffic(f)
    data = input_for(f, action, prepared) if override is None else override
    if cli:
        result = f['b'].cli('onboarding', 'join', 'machine-commit', action, '--stdin',
            input=compact({'flow_id': f['flow']['flow_id'], **data}).decode(), timeout=8)
        check(result.ok == (status == 200), 'machine requester consent CLI success/refusal mismatch')
        public(result.stdout + result.stderr, str(f['b'].root), *f['secrets'])
        value = result.json if result.ok else None
    else:
        actual, value = f['b'].api('POST', path or endpoint(f, action), data, timeout=5)
        check(actual == status, f'machine requester {action} HTTP {actual}, expected {status}')
        if code:
            current = value.get('code') if type(value) is dict else None
            check(current == code, 'controlled ' + action + ' code ' + (current if current in CODES else 'unknown') + ', expected ' + code)
        public(value, *f['secrets'])
    if status == 200:
        validate_consent(f, value)
    if pure:
        strict(f, before, counters, action)
    return value


def prepared_fixture(name='device'):
    f = progress(base_world(name))
    if 'prepared' not in f:
        f['inspection'] = inspect_machine(f)
        validate_inspection(f, f['inspection'])
        f['prepared'] = op(f, 'prepare')
    return f







def release_reader_holds(f):
    """Reader isolation ends before the genuine ordinary mutation setup."""
    a = f['a']; identity = a.id, a.public_key
    if a.process is None:
        a.start()
    check((a.id, a.public_key) == identity, 'existing computer restart changed actual pinned identity')
    for relay in (a.relay, f['b'].relay):
        relay.mode = 'pass'
    f['_guard'] = None
    f['_held'], f['_held_at'] = [], 0

def operation(h, rid):
    with closing(sqlite3.connect(f'file:{db_path(h)}?mode=ro', uri=True)) as db:
        rows = db.execute('SELECT network_id,context_id,activation_id,manifest_id,record,locally_applied '
                          'FROM dec_operations WHERE request_id=?', (rid,)).fetchall()
    check(len(rows) <= 1, 'multiple local applications for one genuine request')
    if not rows:
        return None
    row = rows[0]
    return dict(network_id=row[0], context_id=row[1], activation_id=row[2], manifest_id=row[3],
                record=json.loads(row[4]), locally_applied=row[5])



def commit_frames(h, rid):
    with closing(sqlite3.connect(f'file:{db_path(h)}?mode=ro', uri=True)) as db:
        return {(writer, frame_id): record for writer, frame_id, record in db.execute(
            "SELECT writer_key,frame_id,record FROM dec_frames WHERE request_id=? AND role='commit'", (rid,))}



class CompletionProxy:
    """One genuine private HTTP call; optional lost response after real commit."""
    def __init__(self, h):
        self.state = suite.work / 'cli-socket'; self.state.mkdir(mode=0o700)
        self.calls = []; self.lost = False; self.failure = False
        outer = self
        class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass
            def do_POST(self):
                try:
                    raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                    outer.calls.append((self.command, self.path, json.loads(raw)))
                    status, value = h.api(self.command, self.path, json.loads(raw), timeout=95)
                    outer.result = status, value
                    if outer.lost:
                        self.connection.shutdown(socket.SHUT_RDWR); return
                    data = compact(value)
                    self.send_response(status); self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(data))); self.send_header('Connection', 'close')
                    self.end_headers(); self.wfile.write(data)
                except Exception:
                    outer.failure = True
        self.server = Server(str(self.state / 'admin.sock'), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
    def __enter__(self):
        self.thread.start(); return self
    def __exit__(self, *_args):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)


DECISION = 'complete_machine_requester_commit'
COMPLETION = set('state review_id manifest_id activation_id outcome_id participant_delivery agent_access connection_readiness'.split())
CODES |= {'state_conflict', 'machine_commit_completion_unavailable'}


def completion_body(f, approved=None):
    approved = approved or f['approved']
    return {**inspection_body(f), 'consent_review_id': approved['consent']['review_id'], 'decision': DECISION}


def network_anchor(f):
    with closing(sqlite3.connect(f'file:{db_path(f["b"])}?mode=ro', uri=True)) as db:
        row = db.execute('SELECT record FROM dec_clock WHERE network_id=?', (f['network']['id'],)).fetchone()
    check(row is not None, 'target-network retained clock anchor missing')
    record = json.loads(row[0])
    check(set(record) == {'format', 'largest_local_time'} and type(record['format']) is int and record['format'] == 1
          and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', record['largest_local_time']),
          'target-network documented clock anchor malformed')
    return parse_time(record['largest_local_time'])


def validate_completion(f, value):
    """Pure retained verification also works below the ordinary rollback guard."""
    check(type(value) is dict and set(value) == CONSENT_TOP | {'completion'}
          and type(value['version']) is int and value['version'] == 1, 'closed machine completion wrapper')
    check(value['host_id'] == f['b'].id and value['context'] == context(f['parent'])
          and value['flow_id'] == f['flow']['flow_id'] and value['join_review_id'] == f['flow']['review_id']
          and value['consent'] == f['approved']['consent'], 'completion replaced exact approved receipt/flow/parent')
    expected_time = max(f['b'].now(), network_anchor(f))
    check(re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value['observed_at'])
          and abs((parse_time(value['observed_at']) - expected_time).total_seconds()) < 5,
          'completion did not use exact target-network historical clock')
    request = value['request']; frozen = f['inspection']['review']; completion = value['completion']
    check(type(request) is dict and set(request) == LINK and request['request_id'] == f['rid']
          and request['role'] == 'requester' and request['mode'] == 'new' and request['migration_proposal_id'] == '-'
          and request['network_id'] == f['network']['id'] and request['context_id'] == f['network']['context_id']
          and all(request[key] == frozen[key] for key in ('person_public_key', 'host_public_key', 'device_public_key',
              'request_packet_id', 'owner_offer_id', 'selection_id', 'administrator_offer_id', 'owner_finalization_id')),
          'completed request changed exact received remote/F/target pins')
    check(request['state'] == 'linked' and request['selection_approved'] is request['commit_approved'] is True
          and request['completed'] == ['request_created', 'owner_offered', 'owner_selected', 'owner_finalized',
                                      'commit_persisted', 'locally_applied'], 'success lacks actual folded local application')
    check(type(completion) is dict and set(completion) == COMPLETION and completion['state'] == 'locally_applied'
          and completion['review_id'] == f['approved']['consent']['review_id']
          and all(completion[key] == 'not_verified' for key in ('participant_delivery', 'agent_access', 'connection_readiness')),
          'completion overclaimed delivery/access/readiness or changed consent')
    for key, prefix in (('manifest_id', 'dm_'), ('activation_id', 'da_'), ('outcome_id', 'dpk_')):
        check(re.fullmatch(prefix + '[0-9a-f]{64}', completion[key]) and completion[key] == request[key],
              'canonical application reference disagrees with request: ' + key)
    retained = operation(f['b'], f['rid'])
    check(retained is not None and retained['locally_applied'] == 1
          and retained['network_id'] == f['network']['id'] and retained['context_id'] == f['network']['context_id']
          and all(retained[key] == completion[key] for key in ('manifest_id', 'activation_id')),
          'success lacks exact retained verified local application')
    check(load_intent(f['b'], f['approved']['consent']['consent_id']) == f['approved_receipt'],
          'completion/replay rewrote unsigned immutable consent receipt')
    receipt, ordinary, current = coherent(f, f['approved']['consent'])
    check(receipt['approved'] is ordinary['approved'] is current['commit_approved'] is True
          and receipt['approved_at'] == ordinary['approved_at'] != '-'
          and current['commit_intent_id'] == f['approved']['consent']['review']['intent_id'],
          'application lost exact dual approved intent/receipt/pending attribution')
    check(len(intent_rows(f['b'], f['rid'], 'requester_commit')) ==
          len(intent_rows(f['b'], f['rid'], 'machine_requester_review')) == 1, 'completion duplicated consent or signing job')
    no_original(f); public(value, *f['secrets'])


def complete(f, *, status=200, code=None, pure=False, cli=False, override=None, path=None):
    if pure:
        quiet(f); before, counters = whole(f), traffic(f)
    data = completion_body(f) if override is None else override
    if cli:
        result = f['b'].cli('onboarding', 'join', 'machine-commit', 'complete', '--stdin',
            input=compact({'flow_id': f['flow']['flow_id'], **data}).decode(), timeout=100)
        check(result.ok == (status == 200), 'machine completion CLI success/refusal mismatch')
        public(result.stdout + result.stderr, str(f['b'].root), *f['secrets'])
        value = result.json if result.ok else None
    else:
        actual, value = f['b'].api('POST', path or endpoint(f, 'complete'), data, timeout=95)
        check(actual == status, f'machine completion HTTP {actual}, expected {status}')
        if code:
            actual_code = value.get('code') if type(value) is dict else None
            check(actual_code == code, 'controlled completion code ' + (actual_code if actual_code in CODES else 'unknown') + ', expected ' + code)
        public(value, *f['secrets'])
    if status == 200:
        validate_completion(f, value)
    if pure:
        strict(f, before, counters, 'completed-history' if status == 200 else 'completion-refusal')
    return value


def approve(f):
    f['approved'] = op(f, 'approve', f['prepared'])
    check(f['approved']['consent']['state'] == 'approved', 'exact guided receipt was not approved')
    f['approved_receipt'] = load_intent(f['b'], f['approved']['consent']['consent_id'])
    return f['approved']


def signed_fixture(f):
    release_reader_holds(f)
    endpoints = pending(f['b'], f['rid'])[0]['carrier_endpoints']
    check(any(e['kind'] == 'participant' and e['address'] == f['b'].relay.address and e['public_key'] == f['b'].public_key
              for e in endpoints), 'genuine own first-contact mailbox is not reachable by ordinary worker')
    wait_for(lambda: pending(f['b'], f['rid'])[0]['commit_packet_base64'] != '-' and commit_frames(f['b'], f['rid']),
             timeout=15, interval=.1, message='actual approved machine commit signed and framed')
    iid = f['approved']['consent']['review']['intent_id']
    record, _ = pending(f['b'], f['rid']); ordinary = load_intent(f['b'], iid)['record']
    check(ordinary['completed'] and ordinary['signatures'] and operation(f['b'], f['rid']) is None,
          'signed/framed fixture is incomplete or already independently applied')
    wait_for(lambda: signed_drained(f), timeout=5, interval=.02, message='actual signed publication ACKs/outbox/journal drain')
    f['signed_packet'], f['signed_intent'], f['signed_frames'] = record['commit_packet_base64'], ordinary, commit_frames(f['b'], f['rid'])
    return f


def application_proof(f, value):
    """Independent wire9 transcript, manifest, activation, outcome and signer IDs."""
    b, rid = f['b'], f['rid']; retained = operation(b, rid); record = retained['record']
    check(set(record) == {'format', 'activation_base64', 'catalog_base64', 'outcome_packet_base64', 'applied_at'}
          and record['format'] == 1, 'closed retained application record')
    raw_activation = base64.b64decode(record['activation_base64'], validate=True)
    activation = json.loads(raw_activation); packet = activation['commit']
    contents = json.loads(base64.b64decode(packet['payload_base64'], validate=True))
    raw_manifest = base64.b64decode(contents['manifest_base64'], validate=True); manifest = json.loads(raw_manifest)
    manifest_id = 'dm_' + hashlib.sha256(('peerspan-decentralized-manifest-v1\n' + hashlib.sha256(raw_manifest).hexdigest()).encode()).hexdigest()
    activation_id = 'da_' + hashlib.sha256('\n'.join(('peerspan-decentralized-activation-v1',
        f['network']['context_id'], rid, manifest_id, packet_id(packet))).encode()).hexdigest()
    check(activation['format'] == 1 and activation['context_id'] == manifest['context_id'] == f['network']['context_id']
          and manifest['request_id'] == rid and activation_id == value['completion']['activation_id']
          and manifest_id == value['completion']['manifest_id'], 'independent exact manifest/activation identity failed')
    review = f['inspection']['review']
    for key in ('request_packet_id', 'owner_offer_id', 'selection_id', 'administrator_offer_id', 'owner_finalization_id',
                'root_state_id', 'person_lease_id', 'host_lease_id', 'binding_lease_id', 'device_lease_id'):
        check(manifest[key] == review[key], 'application changed reviewed dependency: ' + key)
    for role, field, ref in (('request', 'request_packet_base64', 'request_packet_id'), ('owner', 'owner_packet_base64', 'owner_offer_id'),
                           ('selection', 'selection_packet_base64', 'selection_id'),
                           ('owner_finalization', 'owner_finalization_packet_base64', 'owner_finalization_id')):
        original = json.loads(base64.b64decode(f['packet_evidence'][field], validate=True))
        check(activation[role] == original and packet_id(activation[role]) == review[ref], 'activation substituted exact signed transcript')
    check(activation['administrator'] == '-' and manifest['administrator_offer_id'] == '-', 'folded application invented administrator packet')
    check(packet['role'] == 'commit' and packet['request_id'] == rid and packet['context_id'] == f['network']['context_id']
          and packet['writer_host_public_key'] == b.public_key and packet['signer_public_key'] == review['device_public_key'],
          'commit substituted original owner for requester-owned host/device')
    ed25519(b.public_key, packet['host_signature'], packet_message(packet), b.name + '-completion-commit-host')
    ed25519(review['device_public_key'], packet['device_signature'], packet_message(packet), b.name + '-completion-commit-device')
    binding_message = '\n'.join(('peerspan-decentralized-signature-v1', review['binding_lease_id'], 'host', b.public_key)).encode()
    ed25519(b.public_key, contents['binding_host_signature'], binding_message, b.name + '-completion-binding-host')
    catalog = json.loads(base64.b64decode(record['catalog_base64'], validate=True))
    for item in catalog['objects']:
        raw = base64.b64decode(item['body_base64'], validate=True)
        check(item['id'] == 'dp_' + hashlib.sha256(('peerspan-decentralized-proof-v1\n' + item['kind'] + '\n' +
              hashlib.sha256(raw).hexdigest()).encode()).hexdigest(), 'application catalog proof changed exact bytes')
    check(set(manifest['proof_ids']) <= {item['id'] for item in catalog['objects']}, 'application missing actual manifest proofs')
    outcome = json.loads(base64.b64decode(record['outcome_packet_base64'], validate=True))
    result = json.loads(base64.b64decode(outcome['payload_base64'], validate=True))
    check(packet_id(outcome) == value['completion']['outcome_id'] and outcome['role'] == 'outcome'
          and outcome['writer_host_public_key'] == b.public_key and outcome['request_id'] == rid
          and result['manifest_id'] == manifest_id and result['activation_id'] == activation_id
          and result['activation_sha256'] == hashlib.sha256(raw_activation).hexdigest()
          and result['applied_at'] == record['applied_at'] and result['observed_root_state_id'] == review['root_state_id'],
          'actual outcome disagrees with returned application evidence')
    ed25519(b.public_key, outcome['host_signature'], packet_message(outcome), b.name + '-completion-outcome')
    current, secret = pending(b, rid)
    check(current['terminal'] == 'applied' and secret is None and current['outcome_packet_base64'] == record['outcome_packet_base64'],
          'application did not atomically retain outcome/retire pairing secret')
    check([v['id'] for v in get(b, '/v2/networks')] == [f['network']['id']], 'application adopted another network')
    with closing(sqlite3.connect(f'file:{db_path(b)}?mode=ro', uri=True)) as db:
        selected = db.execute('SELECT provider_kind,person_key,device_key,lease_id FROM dec_signers WHERE network_id=? AND context_id=?',
                              (f['network']['id'], f['network']['context_id'])).fetchall()
    check(selected == [('device', f['person'], review['device_public_key'], review['device_lease_id'])], 'application selected another device/provider')
    events = get(b, '/v1/activity?limit=1000')
    check(len([event for event in events if event['kind'] == 'network.link_applied']) == 1, 'application did not emit exactly one event')


def arm(f):
    paths = {suffix: f['b'].barrier / ('dec.apply.before_transaction.' + suffix) for suffix in ('arm', 'entered', 'continue')}
    for path in paths.values():
        path.unlink(missing_ok=True)
    paths['arm'].write_text(f['rid'] + '\n'); paths['arm'].chmod(0o600)
    return paths


def reached(f, paths):
    def entered():
        try:
            return paths['entered'].read_text().strip() == f['rid']
        except FileNotFoundError:
            return False
    wait_for(entered, timeout=5, interval=.02, message='actual machine apply transaction barrier entered')


def release(paths):
    paths['continue'].write_text('continue\n'); paths['continue'].chmod(0o600)
    paths['arm'].unlink(missing_ok=True)


def pure_clock_refusal(f, target, code):
    saved = [(h.clock, h.clock.offset) for h in (f['a'], f['b'])]
    try:
        for h in (f['a'], f['b']):
            advance_to(h, target)
            if h.process is not None:
                retired_expired_helper(h)
        quiet(f); before, counters = whole(f), traffic(f)
        complete(f, status=409, code=code)
        strict(f, before, counters, 'fresh-raw-before-created' if code == 'machine_commit_completion_unavailable' else 'fresh-signed-expiry')
    finally:
        for clock, offset in saved:
            clock.set(offset)


def terminal_rows_retired(f):
    for h in (f['a'], f['b']):
        with closing(sqlite3.connect(f'file:{db_path(h)}?mode=ro', uri=True)) as db:
            pending_count = db.execute('SELECT count(*) FROM dec_pending WHERE secret IS NOT NULL OR terminal_read_cap IS NOT NULL').fetchone()[0]
            frames = db.execute('SELECT count(*) FROM dec_frames').fetchone()[0]
            outbox = db.execute('SELECT count(*) FROM dec_outbox').fetchone()[0]
        if pending_count or frames or outbox or list(h.state.glob('*-journal')):
            return False
    return True


def exchange_contacts_observed(f):
    """Failure-only metadata from the existing bounded normal-peer probe."""
    original_run = subprocess.run
    hosts = (f['a'], f['b'])
    def emit(result, view, before, argv, timed_out=False):
        try:
            text = '' if result is None else result.stderr
            text = text.decode(errors='replace') if isinstance(text, bytes) else str(text or '')
            text = text.lower()
            classes = [name for name, terms in (
                ('timeout', ('timeout', 'timed out', 'deadline')),
                ('certificate', ('certificate', 'x509', 'x.509')),
                ('pin', ('pin',)), ('TLS', ('tls', 'handshake')),
                ('connection', ('connect', 'connection', 'refused', 'reset')))
                if any(term in text for term in terms)]
            code = result.returncode if result is not None else None
            status = view.get('status') if type(view) is dict else None
            argv = argv if isinstance(argv, (list, tuple)) else ()
            supplied = {flag: argv[argv.index(flag) + 1] if flag in argv and argv.index(flag) + 1 < len(argv) else None
                        for flag in ('--method', '--path', '--address')}
            prefix = '/peer/v2/networks/' + f['network']['id']
            operations = {('POST', prefix + '/contact'): 'contactPOST', ('GET', prefix + '/contacts'): 'contactsGET',
                          ('GET', prefix + '/catalog'): 'catalogGET'}
            address = supplied['--address']
            targets = {'counted_existing': address == hosts[0].counted_peer.address,
                       'counted_requester': address == hosts[1].counted_peer.address,
                       'direct_existing': address == hosts[0].peer_address, 'direct_requester': address == hosts[1].peer_address}
            targets['other'] = not any(targets.values())
            summary = {'exit_code': code if type(code) is int else 'unknown',
                'status': status if type(status) is int and 100 <= status <= 599 else 'unknown',
                'stderr_classes': ['timeout'] if timed_out else classes or ['other'],
                'program': 'probe' if argv and argv[0] == str(suite.probe_bin) else 'other',
                'operation': operations.get((supplied['--method'], supplied['--path']), 'other'), 'target_matches': targets,
                'carriers': [{'side': side, 'thread_alive_before': captured[1], 'thread_alive_after': h.counted_peer.thread.is_alive(),
                    'before': captured[0], 'after': h.counted_peer.counts()}
                    for side, h, captured in zip(('existing', 'requester'), hosts, before)]}
            print('machine_completion_contact_failure_public=' + json.dumps(summary, sort_keys=True), flush=True)
        except Exception:
            pass  # Diagnostic failure cannot alter the original result/assertion.
    def observed_run(*args, **kwargs):
        before = tuple((h.counted_peer.counts(), h.counted_peer.thread.is_alive()) for h in hosts)
        argv = args[0] if args else kwargs.get('args', ())
        try:
            result = original_run(*args, **kwargs)
        except subprocess.TimeoutExpired:
            emit(None, None, before, argv, timed_out=True)
            raise
        try:
            view = json.loads(result.stdout)
        except (ValueError, TypeError):
            view = None
        if result.returncode != 0 or type(view) is not dict or view.get('status') != 200 or not isinstance(view.get('body'), dict):
            emit(result, view, before, argv)
        return result
    try:
        subprocess.run = observed_run
        return exchange_current_contacts(suite, f['b'], f['a'], f['network']['id'], f['view']['expires_at'])
    finally:
        subprocess.run = original_run


def terminal_baseline(f):
    """Genuine public delivery/expiry setup, never an unmeasured Complete."""
    a, b = f['a'], f['b']; release_reader_holds(f)
    status, repaired = b.api('POST', '/v2/link/requests/' + f['rid'] + '/resume', {}, timeout=35)
    check(status == 200 and repaired['state'] == 'linked', 'one genuine completed-requester repair failed')
    wait_linked(a, f['rid'], timeout=25)
    for local, remote in ((a, b), (b, a)):
        local.ok('peer', 'add', '--id', remote.id, '--public-key', remote.public_key, '--address', peer_address(remote))
    exchange_contacts_observed(f)
    bounds = [parse_time(f['view']['expires_at']), parse_time(f['inspection']['review']['not_after'])]
    for local in (a, b):
        status, synced = local.api('POST', '/v2/networks/' + f['network']['id'] + '/sync', {}, timeout=35)
        check(status == 200 and synced['unavailable'] == [] and synced['network']['authority']['state'] == 'usable', 'ordinary terminal known-peer sync failed')
        if synced['network']['authority']['not_after'] != '-':
            bounds.append(parse_time(synced['network']['authority']['not_after']))
    retry_times = []
    for local in (a, b):
        with closing(sqlite3.connect(f'file:{db_path(local)}?mode=ro', uri=True)) as db:
            retry_times += [parse_time(row[0]) for row in db.execute("SELECT json_extract(record,'$.next_attempt_at') FROM dec_outbox")]
    shared_now = max(a.now(), b.now()); target = max([shared_now, *retry_times]) + timedelta(seconds=1)
    check(target <= shared_now + timedelta(seconds=61) and all(target < bound for bound in bounds), 'actual retry alignment exceeds live original windows')
    for local in (a, b):
        advance_to(local, target)
    def delivered():
        for local in (a, b):
            with closing(sqlite3.connect(f'file:{db_path(local)}?mode=ro', uri=True)) as db:
                if db.execute('SELECT count(*) FROM dec_outbox').fetchone()[0] or list(local.state.glob('*-journal')):
                    return False
        return True
    wait_for(delivered, timeout=5, interval=.1, message='actual terminal proof outbox and journal retirement')
    expired = parse_time(f['view']['expires_at']) + timedelta(seconds=1)
    for local in (a, b):
        advance_to(local, expired)
        spare_key = ssh_key(suite.work, local.name + '-unsigned-maintenance')
        status, spare = local.api('POST', '/v2/link/requests', {'mode': 'new', 'network_id': '-',
            'person_public_key': ssh_public_base64(spare_key), 'migration_proposal_id': '-', 'contact_invitation': '-', 'helpers': []})
        check(status == 201 and not spare['selection_approved'] and not spare['commit_approved'], 'ordinary unsigned expired-capacity maintenance failed')
        status, cancelled = local.api('POST', '/v2/link/requests/' + spare['request_id'] + '/cancel', {})
        check(status == 200 and cancelled['state'] == 'cancelled', 'ordinary maintenance cancellation failed')
        retired_expired_helper(local)
    wait_for(lambda: terminal_rows_retired(f), timeout=5, interval=.1, message='actual both-host ciphertext/readcap/frame/outbox retirement')
    a.stop()
    observe_stopped_directory(f)
    quiet(f)


def observe_stopped_directory(f):
    """Observe documented startup/current directory work before pure baseline."""
    status, value = f['b'].api('POST', '/v1/directory/refresh?network=' + f['network']['id'], {}, timeout=12)
    check(status == 200 and type(value) is dict and value.get('network_id') == f['network']['id']
          and type(value.get('hosts')) is list and type(value.get('agents')) is list, 'current project directory setup did not complete')
    rows = [row for row in value['hosts'] if type(row) is dict and row.get('host_id') == f['a'].id]
    check(len(rows) == 1 and rows[0].get('state') == 'error', 'stopped existing-computer directory query is not settled')


@suite.case('genuine_device15_missing_unapproved_exact_receipt_and_late_application_abort', 'guided47 verification1/2/4')
def _():
    f = base_world()
    absent = {**inspection_body(f), 'consent_review_id': 'review_' + '0' * 64, 'decision': DECISION}
    complete(f, status=409, code='machine_commit_completion_unavailable', pure=True, override=absent)
    progress(f); f['inspection'] = inspect_machine(f); validate_inspection(f, f['inspection'])
    complete(f, status=409, code='machine_commit_completion_unavailable', pure=True, override=absent)
    f['prepared'] = op(f, 'prepare'); f['approved'] = f['prepared']
    complete(f, status=409, code='machine_commit_completion_unavailable', pure=True)
    check(f['prepared']['consent']['state'] == 'review' and not coherent(f, f['prepared']['consent'])[0]['approved'], 'refused completion implicitly approved metadata')
    approve(f); signed_fixture(f)
    b = f['b']; iid = f['approved']['consent']['review']['intent_id']
    check(operation(b, f['rid']) is None and get(b, '/v2/networks') == [], 'SQL fault began after independent application')
    before = whole(f); counters = traffic(f); prior, secret = pending(b, f['rid']); original = load_intent(b, iid)
    with closing(sqlite3.connect(f'file:{db_path(b)}?mode=ro', uri=True)) as db:
        cap = db.execute('SELECT terminal_read_cap FROM dec_pending WHERE request_id=?', (f['rid'],)).fetchone()[0]
    check(re.fullmatch(r'link_[0-9a-f]{64}', f['rid']), 'unsafe genuine application SQL selector')
    with closing(sqlite3.connect(db_path(b))) as db, db:
        db.execute("CREATE TRIGGER machine_completion_abort BEFORE INSERT ON dec_operations WHEN NEW.request_id='" +
                   f['rid'] + "' BEGIN SELECT RAISE(ABORT,'PRIVATE_MACHINE_COMPLETION_ABORT'); END")
    f['secrets'].append('PRIVATE_MACHINE_COMPLETION_ABORT')
    try:
        complete(f, status=409, code='machine_commit_completion_unavailable')
    finally:
        with closing(sqlite3.connect(db_path(b))) as db, db:
            db.execute('DROP TRIGGER machine_completion_abort')
    f['a'].stop(); quiet(f); after = whole(f)
    phase_tables = {'dec_intents', 'dec_pending', 'dec_frames', 'dec_clock'}
    for database in set(before[1][0]) | set(after[1][0]):
        old, new = before[1][0].get(database, {}), after[1][0].get(database, {})
        check(set(old) == set(new), 'application fault changed database/table set')
        for table in set(old) | set(new):
            if table not in phase_tables:
                check(old.get(table) == new.get(table), 'application rollback changed nonphase schema/version/table: ' +
                      (table if table in {'dec_outbox', 'dec_operations', 'dec_objects', 'networks', 'network_members', 'dec_signers', 'events', '$schema', '$version'} else 'other'))
    check(after[1][1:] == before[1][1:], 'application fault changed requester private state/home files')
    current, current_secret = pending(b, f['rid'])
    check(operation(b, f['rid']) is None and get(b, '/v2/networks') == [] and current_secret == secret and secret is not None
          and current['terminal'] == prior['terminal'] == '-' and current['outcome_packet_base64'] == '-', 'application fault left adoption/outcome/retired secret')
    with closing(sqlite3.connect(f'file:{db_path(b)}?mode=ro', uri=True)) as db:
        check(db.execute('SELECT terminal_read_cap FROM dec_pending WHERE request_id=?', (f['rid'],)).fetchone()[0] == cap
              and db.execute("SELECT count(*) FROM dec_frames WHERE request_id=? AND role='outcome'", (f['rid'],)).fetchone()[0] == 0,
              'late SQL fault retained outcome/read-cap work')
    updated = load_intent(b, iid)
    check(updated == original and load_intent(b, f['approved']['consent']['consent_id']) == f['approved_receipt'], 'application fault replaced immutable exact signed intent/consent')
    check(all(y >= x for old, new in zip(counters, traffic(f)) for x, y in zip(old, new)), 'counted carrier paths were reset or excluded during explicit action')
    check(op(f, 'lookup', pure=True)['consent'] == f['approved']['consent'], 'fault lost pure exact consent recovery')
    f['fault_verified'] = True


@suite.case('actual_finite_folded_application_after_review_expiry_lost_reply_then_lookup', 'guided47 verification1/5')
def _():
    f = shared.get('device'); check(f and f.get('fault_verified'), 'genuine late application rollback prerequisite failed')
    b = f['b']; signed_fixture(f)
    after_review = parse_time(f['approved']['consent']['review']['expires_at']) + timedelta(seconds=1)
    check(max(f['a'].now(), b.now()) < after_review < min(parse_time(f['view']['expires_at']), parse_time(f['inspection']['review']['not_after'])),
          'genuine signed work has no post-review/pre-protocol-deadline interval')
    for h in (f['a'], b):
        advance_to(h, after_review)
    before, counters = whole(f), traffic(f)
    release_reader_holds(f)
    with CompletionProxy(b) as proxy:
        proxy.lost = True
        raw = compact({'flow_id': f['flow']['flow_id'], **completion_body(f)})
        result = subprocess.run([str(suite.host_bin), '--state', str(proxy.state), 'onboarding', 'join', 'machine-commit', 'complete', '--stdin'],
            input=raw, capture_output=True, env=b.env, cwd=str(b.root), timeout=100)
        check(result.returncode != 0 and not proxy.failure and proxy.calls == [('POST', endpoint(f, 'complete'), completion_body(f))],
              'lost genuine response retried/changed private bounded action')
        public(result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'), str(proxy.state), str(b.root), *f['secrets'])
        status, value = proxy.result
        check(status == 200, f'actual completion before response loss HTTP {status}')
        validate_completion(f, value); f['completion'] = value
    application_proof(f, value)
    after = whole(f); current = load_intent(b, f['approved']['consent']['review']['intent_id'])['record']
    check(current == {**f['signed_intent'], 'terminal': 'applied'} and pending(b, f['rid'])[0]['commit_packet_base64'] == f['signed_packet'],
          'completion replaced prior exact templates/signatures/packet instead of reusing them')
    remaining = commit_frames(b, f['rid'])
    check(set(remaining) <= set(f['signed_frames']) and all(remaining[key] == f['signed_frames'][key] for key in remaining), 'completion replaced retained sealed frame bytes')
    for side in (0, 1):
        check(set(after[side][0]) == set(before[side][0]) and after[side][2] == before[side][2], 'completion added a DB or original/private home source')
        for name, database in before[side][0].items():
            check(after[side][0][name]['$schema'] == database['$schema'] and after[side][0][name]['$version'] == database['$version'], 'completion changed schema/version')
    check(all(y >= x for old, new in zip(counters, traffic(f)) for x, y in zip(old, new)), 'completion reset counted TCP/UDP paths')
    release_reader_holds(f); f['a'].stop(); observe_stopped_directory(f); quiet(f)
    recovered = op(f, 'lookup', pure=True)
    check(recovered['consent'] == f['approved']['consent'] and recovered['request']['state'] == 'linked', 'pure Lookup failed actual application recovery after lost response')


@suite.case('strict_private_JSON_64KiB_ID_method_scoped_peer_bootstrap_and_no_startup', 'guided47 verification5')
def _():
    f = shared.get('device'); check(f and f.get('completion'), 'actual device application prerequisite failed')
    b = f['b']; body = completion_body(f); raw = compact(body); encoded_context = compact(body['context'])
    malformed = [b'null', b'[]', b'{', raw + b'{}', raw + b' ' * (65537 - len(raw)),
        b'{"context":' + encoded_context + b',"context":' + encoded_context + b',"join_review_id":' + compact(body['join_review_id']) +
        b',"consent_review_id":' + compact(body['consent_review_id']) + b',"decision":' + compact(DECISION) + b'}',
        raw.replace(b'"integration":"claude-code"', b'"integration":"claude-code","integration":"claude-code"'),
        compact({**body, 'decision': None}), compact({**body, 'decision': 'complete_requester_commit'}),
        compact({**body, 'consent_review_id': False}), compact({**body, 'context': {**body['context'], 'extra': 'PRIVATE_MACHINE_COMPLETE'}})]
    for key in ('provider', 'path', 'key', 'template', 'signature'):
        malformed.append(compact({**body, key: 'PRIVATE_MACHINE_COMPLETE'}))
    for index, payload in enumerate(malformed):
        quiet(f); before, counters = whole(f), traffic(f)
        status, value = raw_post(b, endpoint(f, 'complete'), payload)
        check(status == 400 and value.get('code') == 'invalid', f'malformed completeAPI variant{index} HTTP {status}')
        public(value, 'PRIVATE_MACHINE_COMPLETE', *f['secrets'])
        cli_input = b'{"flow_id":' + compact(f['flow']['flow_id']) + b',' + payload[1:] if payload.startswith(b'{') else payload
        result = b.cli('onboarding', 'join', 'machine-commit', 'complete', '--stdin', input=cli_input.decode(), timeout=8)
        check(not result.ok, 'malformed private completion CLI accepted')
        public(result.stdout + result.stderr, 'PRIVATE_MACHINE_COMPLETE', str(b.root), *f['secrets'])
        strict(f, before, counters, 'malformed-completion')
    maximum = raw + b' ' * (65536 - len(raw))
    quiet(f); before, counters = whole(f), traffic(f)
    status, value = raw_post(b, endpoint(f, 'complete'), maximum)
    check(status == 200, 'exact64KiB completed API replay refused'); validate_completion(f, value)
    strict(f, before, counters, 'maximum-completion')
    complete(f, pure=True, cli=True)
    for patch in ({'consent_review_id': 'review_' + '0' * 64}, {'join_review_id': 'review_' + '0' * 64},
                  {'context': {**body['context'], 'native_session_id': 'different-machine-conversation'}}):
        complete(f, pure=True, status=409, code='review_changed', override={**body, **patch})
    complete(f, pure=True, status=404, code='not_found', path=BASE + '/flow_' + '0' * 32 + '/machine-commit/complete')
    for method in ('GET', 'PUT', 'DELETE'):
        quiet(f); before, counters = whole(f), traffic(f)
        status, value = b.api(method, endpoint(f, 'complete')); check(status == 405, 'alternate completion method accepted')
        public(value); strict(f, before, counters, 'method-completion')
    for args in ((), ('--stdin', 'PRIVATE_MACHINE_COMPLETE'), ('--stdin', '--key', 'PRIVATE_MACHINE_COMPLETE')):
        quiet(f); before, counters = whole(f), traffic(f)
        result = b.cli('onboarding', 'join', 'machine-commit', 'complete', *args,
                       input=compact({'flow_id': f['flow']['flow_id'], **body}).decode(), timeout=8)
        check(not result.ok, 'completion accepted private positional/source selector or implicit stdin')
        public(result.stdout + result.stderr, 'PRIVATE_MACHINE_COMPLETE', str(b.root), *f['secrets']); strict(f, before, counters, 'argv-completion')
    credential = b.ok('adapter', 'create', '--session', f['parent']['review']['session_id'],
        '--expires-at', rfc3339(b.now() + timedelta(hours=1)))
    adapter = Adapter(b, f['parent']['review']['agent'], f['parent']['review']['session_id'], credential)
    status, _ = adapter.call('POST', '/adapter/v1/connect', {'adapter_id': adapter.adapter_id,
        'session_id': adapter.session_id, 'instance_id': adapter.instance})
    check(status == 200, 'genuine scoped completion credential prerequisite')
    quiet(f); before, counters = whole(f), traffic(f)
    status, value = adapter.call('POST', endpoint(f, 'complete'), body)
    check(status == 404, 'scoped adapter exposed completion'); public(value, adapter.token)
    strict(f, before, counters, 'adapter-completion')
    peer, boot = host('p'), host('t')
    for local, remote in ((b, peer), (peer, b)):
        local.ok('peer', 'add', '--id', remote.id, '--public-key', remote.public_key, '--address', peer_address(remote))
    quiet(f); before, counters = whole(f), traffic(f)
    routed = subprocess.run([str(suite.probe_bin), '--state', str(peer.state), '--address', peer_address(b),
        '--alpn', 'peerspan-peer/1', '--path', endpoint(f, 'complete'), '--method', 'POST', '--body-stdin'],
        input=compact(body), capture_output=True, timeout=15)
    check(routed.returncode == 0 and json.loads(routed.stdout)['status'] == 404, 'peer router exposed private machine completion')
    public(routed.stdout.decode(errors='replace') + routed.stderr.decode(errors='replace'), *f['secrets'])
    check(whole(f) == before, 'explicit owner-route probe changed whole DB/files')
    check(traffic(f)[:2] == counters[:2] and traffic(f)[2] == counters[2], 'peer route probe used unrelated counted path')
    # Only the selected counted peer path changes for this explicit route probe;
    # no pure Complete comparison excludes any path or direction.
    cert, key = suite.work / 'route-cert.pem', suite.work / 'route-key.pem'
    result = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ed25519', '-nodes', '-subj', '/CN=route', '-days', '1',
        '-keyout', str(key), '-out', str(cert)], capture_output=True, timeout=5)
    check(result.returncode == 0, 'actual bootstrap client certificate setup')
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); tls.check_hostname = False; tls.verify_mode = ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key)); tls.set_alpn_protocols(['peerspan-bootstrap/1'])
    with socket.create_connection(('127.0.0.1', boot.bootstrap_port), timeout=5) as raw_socket:
        with tls.wrap_socket(raw_socket, server_hostname='peerspan') as stream:
            payload = compact(body)
            stream.sendall((f'POST {endpoint(f, "complete")} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\n'
                f'Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n\r\n').encode() + payload)
            response = http.client.HTTPResponse(stream); response.begin(); answer = response.read()
            check(response.status == 404, 'bootstrap router exposed private completion')
            public(answer.decode(errors='replace'), *f['secrets'])
    peer.stop(); boot.stop()
    absent = suite.host('abs', start=False); untouched = files(absent.root)
    result = absent.cli('onboarding', 'join', 'machine-commit', 'complete', '--stdin',
        input=compact({'flow_id': f['flow']['flow_id'], **body}).decode(), timeout=8)
    check(not result.ok and files(absent.root) == untouched, 'completion initialized missing daemon/state/key')
    public(result.stdout + result.stderr, str(absent.root), *f['secrets'])


@suite.case('genuine_remote_original_cap_signed_raw_expiry_and_actual_apply_time_guard', 'guided47 verification2/3')
def _():
    f = prepared_fixture('original')
    check(f['inspection']['review']['owner_provider']['kind'] == 'original_person'
          and parse_time(f['inspection']['review']['not_after']) < parse_time(f['view']['created_at']) + timedelta(days=7), 'actual original provider cap prerequisite')
    approve(f); signed_fixture(f); f['a'].stop(); quiet(f)
    pure_clock_refusal(f, parse_time(f['approved']['consent']['review']['created_at']) - timedelta(seconds=1), 'machine_commit_completion_unavailable')
    pure_clock_refusal(f, parse_time(f['view']['expires_at']) + timedelta(seconds=1), 'review_expired')
    release_reader_holds(f); paths = arm(f)
    saved = [(h.clock, h.clock.offset) for h in (f['a'], f['b'])]
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(f['b'].api, 'POST', endpoint(f, 'complete'), completion_body(f), timeout=95)
        try:
            reached(f, paths); check(operation(f['b'], f['rid']) is None, 'independent application preceded actual time barrier')
            for h in (f['a'], f['b']):
                advance_to(h, parse_time(f['view']['expires_at']) + timedelta(seconds=1))
                retired_expired_helper(h)
            quiet(f)
            check(signed_drained(f), 'actual time-barrier baseline lacks signed publication drain')
            before, counters = whole(f), traffic(f)
            release(paths); status, denied = future.result(timeout=5)
            check(status == 409 and denied.get('code') == 'review_expired', 'actual final transaction did not recheck signed expiry')
            public(denied, *f['secrets']); strict(f, before, counters, 'apply-time-boundary')
            check(operation(f['b'], f['rid']) is None, 'expired final transaction applied')
        finally:
            release(paths)
            for clock, offset in saved:
                clock.set(offset)
    f['time_guards_verified'] = True


@suite.case('actual_unapplied_parent_barrier_and_detached_refusal_preserve_consent', 'guided47 verification2/3')
def _():
    f = shared.get('original'); check(f and f.get('time_guards_verified'), 'original actual time-guard fixture failed')
    release_reader_holds(f); check(operation(f['b'], f['rid']) is None, 'detachment began after prior application')
    paths = arm(f)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(f['b'].api, 'POST', endpoint(f, 'complete'), completion_body(f), timeout=95)
        try:
            reached(f, paths); check(operation(f['b'], f['rid']) is None, 'application preceded captured parent stimulus')
            f['b'].ok('session', 'detach', f['parent']['review']['session_id'])
            quiet(f); before, counters = whole(f), traffic(f)
            release(paths); status, denied = future.result(timeout=5)
            check(status == 409 and denied.get('code') == 'review_changed', 'final application transaction adopted detached parent')
            public(denied, *f['secrets']); strict(f, before, counters, 'apply-parent-boundary')
            check(operation(f['b'], f['rid']) is None and get(f['b'], '/v2/networks') == [], 'detached final transaction applied network')
        finally:
            release(paths)
    check(op(f, 'lookup', pure=True)['consent'] == f['approved']['consent'], 'parent change erased approved immutable consent')
    complete(f, pure=True, status=409, code='review_changed')
    f['b'].stop(); f['a'].stop()
    print('LIMIT machine_requester_completion: advanced-only without guided receipt covered46/source-only here; cancellation and original-provider positive Complete not executed; actual original cap/signed/raw/time/parent refusals covered; isolated unsigned-stage/powers expiry, complex grants, key/commit/90s races and global worker attribution remain unexecuted', flush=True)


@suite.case('verified_completed_replay_pure_after_expiry_detach_restart_and_anchor_rollback', 'guided47 verification6')
def _():
    f = shared.get('device'); check(f and f.get('completion'), 'genuine completed-device prerequisite failed')
    baseline = f['completion']['completion']; terminal_baseline(f)
    receipt = load_intent(f['b'], f['approved']['consent']['consent_id'])
    ordinary = load_intent(f['b'], f['approved']['consent']['review']['intent_id'])
    application = operation(f['b'], f['rid'])
    for phase in ('expired', 'detached', 'restarted'):
        if phase == 'detached':
            f['b'].ok('session', 'detach', f['parent']['review']['session_id'])
        if phase == 'restarted':
            f['b'].restart(kill=True); retired_expired_helper(f['b']); observe_stopped_directory(f)
        for cli in (False, True):
            value = complete(f, pure=True, cli=cli)
            check(value['completion'] == baseline and value['consent'] == f['approved']['consent'], 'pure history replaced saved application/consent')
        complete(f, pure=True, status=409, code='review_changed', override={**completion_body(f), 'consent_review_id': 'review_' + 'f' * 64})
    anchor = network_anchor(f); saved = [(h.clock, h.clock.offset) for h in (f['a'], f['b'])]
    for cli in (False, True):
        quiet(f)
        try:
            for clock, _ in saved:
                clock.set(math.floor((anchor - timedelta(seconds=301) - datetime.now(timezone.utc)).total_seconds()))
            check(f['b'].now() < anchor - timedelta(seconds=300), 'actual historical raw rollback did not exceed300s')
            before, counters = whole(f), traffic(f)
            value = complete(f, cli=cli)
            check(value['observed_at'] == rfc3339(anchor) and value['completion'] == baseline, 'rollback replay lost exact retained historical application')
            strict(f, before, counters, 'completed-rollback-history')
        finally:
            for clock, offset in saved:
                clock.set(offset)
    check(load_intent(f['b'], f['approved']['consent']['consent_id']) == receipt
          and load_intent(f['b'], f['approved']['consent']['review']['intent_id']) == ordinary
          and operation(f['b'], f['rid']) == application, 'history rewrote immutable receipt/intent/application evidence')
    application_proof(f, f['completion']); no_original(f)


suite.finish()

