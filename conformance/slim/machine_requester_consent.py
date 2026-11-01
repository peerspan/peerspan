#!/usr/bin/env python3
"""Exact durable existing-machine requester consent, guided section46.

Independent contracts/test fixtures only; no product or eager-suite imports.
Genuine guided requester publication plus remote existing-owner42/F evidence:
creator device15 and original-person. Original files stay ONLY on the old
computer. Requester remains alive; old computer is offline after F during
retained-evidence snapshots. All logical DB/schema/version/state/home files and
both bidirectional TCP+UDP paths remain strict. Actual consumed live TLS holds
ordinary requester polling outside DB, never a worker-pause flag.

Only temporary schema-only ABORT triggers inject SQL faults. No protocol,
authority, queue, approval, signature or clock-row fabrication/edit/deletion.
Atomic approval is observed coherently; authorized later signatures/publication
can run independently and are not attributed to or globally forbidden by API.
History is not current powers, application, delivery, access or readiness.

Limits: source/fault-only complex separate-admin/device7/reused-binding,
corrupt/pruned/unsafe authority, private key-resolution syscalls/exact5s cutoff,
isolated powers expiry and postapproval worker attribution. No completion or
installed/native/model/physical acceptance. All66 old files/native415 unchanged.
Root alone executes this committed suite; all author checks are static.
"""
import base64
import hashlib
import http.client
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
from datetime import datetime, timedelta, timezone
from pathlib import Path

from harness import (Adapter, Clock, Suite, UnixHTTPConnection, check, link_view,
                     parse_time, rfc3339, ssh_key, ssh_public_base64, wait_for)
from counted_peer import CountedUDP

suite = Suite('machine_requester_consent', __doc__)
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
    h.extra_env = {'SSH_AUTH_SOCK': str(h.root / 'absent-agent.sock')}
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


def quiet(f):
    """Actual live poll is held outside DB; complete state/carriers stay strict."""
    b = f['b']; record, _ = pending(b, f['rid'])
    active = record['terminal'] == '-' and b.now() < parse_time(link_view(b, f['rid'])['expires_at'])
    f['_guard'] = None
    if active:
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
        check(result.ok or (result.code == 1 and 'linking is incomplete' in result.stderr), 'exact existing-computer finalization failed')
    view = wait_for(lambda: v if (v := link_view(b, rid))['owner_finalization_id'] != '-' else None,
        timeout=15, interval=.1, message='actual requester received existing-person F')
    check(view['state'] == 'needs_commit' and not view['commit_approved'] and view['selection_approved']
          and view['administrator_offer_id'] == '-' and view['manifest_id'] == view['activation_id'] == view['outcome_id'] == '-',
          'genuine folded F prefix advanced independent commit/application')
    f['view'] = view
    record, _ = pending(b, rid); f['packet_evidence'] = record
    stage = record.get('stage_at', '-')
    f['stage_deadline'] = rfc3339(parse_time(view['created_at'] if stage == '-' else stage) + timedelta(seconds=600))
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


def prepare_writes_only(f, before, counters):
    after = whole(f)
    check(after[0] == before[0] and after[1][1:] == before[1][1:], 'preparation changed old computer/files/schema')
    check(set(after[1][0]) == set(before[1][0]), 'preparation added a database')
    for database, old in before[1][0].items():
        new = after[1][0][database]
        check(set(old) == set(new) and old['$schema'] == new['$schema'] and old['$version'] == new['$version'], 'preparation changed schema/version/table set')
        for table in old:
            if table not in ('dec_intents', 'dec_clock'):
                check(old[table] == new[table], 'preparation changed nonconsent logical table: ' + (table if table in {'dec_pending','dec_frames','dec_outbox','networks','dec_objects','dec_operations','events'} else 'other'))
    check(traffic(f) == counters, 'fresh preparation performed counted TCP/UDP IO')
    if f.get('_guard'):
        f['_guard']()


def fault(f, action, triggers, prepared=None):
    quiet(f)
    # Real time moves inside original bounds; no clock-row edit or fake grant.
    moment = max(f['a'].now(), f['b'].now()) + timedelta(seconds=2)
    check(moment < parse_time(f['inspection']['review']['request_stage_deadline']), 'fault fixture consumed stage window')
    for h in (f['a'], f['b']):
        advance_to(h, moment)
    quiet(f); before, counters = whole(f), traffic(f)
    names = []
    try:
        with closing(sqlite3.connect(db_path(f['b']))) as db, db:
            for index, sql in enumerate(triggers):
                name = 'requester_consent_abort_' + str(index); names.append(name)
                db.execute(sql.replace('$NAME', name))
        actual, denied = f['b'].api('POST', endpoint(f, action), input_for(f, action, prepared), timeout=5)
        check(not 200 <= actual < 300, 'schema-only genuine consent fault was swallowed')
        public(denied, 'PRIVATE_REQUESTER_CONSENT_ABORT', *f['secrets'])
    finally:
        with closing(sqlite3.connect(db_path(f['b']))) as db, db:
            for name in names:
                db.execute('DROP TRIGGER ' + name)
    strict(f, before, counters, 'SQL-fault')

def renew_cancelled_fixture(f):
    """One fresh genuine attempt after public cancellation, same real hosts."""
    a, b = f['a'], f['b']; old = f['rid']
    for relay in (a.relay, b.relay):
        relay.mode = 'pass'
    people = get(a, '/v2/networks/' + f['network']['id'] + '/persons')['persons']
    rows = [v for v in people if v['person_public_key'] == f['person']]
    check(len(rows) == 1, 'fresh attempt lost actual existing owner')
    status, issued = a.api('POST', '/v2/networks/' + f['network']['id'] + '/invitations', {
        'member': rows[0]['member'], 'expected_person_public_key': f['person'], 'expires_at': rfc3339(a.now() + timedelta(seconds=65))})
    check(status == 201 and issued.get('invitation'), f'fresh genuine invitation HTTP {status}')
    status, flow = b.api('POST', BASE, {'context': context(f['parent']), 'invitation': issued['invitation'], 'person_public_key': f['person']})
    check(status == 201 and flow['state'] == 'review', f'fresh join review after cancelled request HTTP {status}')
    status, flow = b.api('POST', BASE + '/' + flow['flow_id'] + '/decision', {
        'context': context(f['parent']), 'review_id': flow['review_id'], 'decision': 'approve', 'invitation': issued['invitation']})
    check(status == 200 and flow['state'] == 'requested' and flow['outcome']['request_id'] != old, 'cancelled request silently reused nonce/flow')
    status, requested = b.api('POST', '/v2/link/requests', {'mode': 'new', 'network_id': f['network']['id'], 'person_public_key': f['person'],
        'migration_proposal_id': '-', 'contact_invitation': issued['invitation'], 'helpers': []})
    check(status == 200 and requested['request_id'] == flow['outcome']['request_id'] and requested.get('display_code'), 'fresh exact request handoff mismatch')
    f.update(flow=flow, rid=requested['request_id'], reply=requested['display_code'], issued=issued)
    f['secrets'] += [issued['invitation'], requested['display_code']]
    wait_for(lambda: any(v['request_id'] == f['rid'] for v in get(a, '/v2/link/requests')), timeout=15, interval=.1, message='fresh automatic machine request return')
    target = max(a.now(), b.now(), parse_time(issued['expires_at']) + timedelta(seconds=1))
    for h in (a, b):
        advance_to(h, target)
    def retired():
        with closing(sqlite3.connect(f'file:{db_path(a)}?mode=ro', uri=True)) as db:
            row = db.execute('SELECT secret FROM dec_pending WHERE request_id=?', (issued['invitation_id'],)).fetchone()
        return row is None or row[0] is None
    wait_for(retired, timeout=5, interval=.1, message='fresh invitation reference actually retired')
    for h in (a, b):
        retired_expired_helper(h)
    return progress(f)


def history_retirement(f):
    """Public expired-slot maintenance, never edits queued/protocol records."""
    target = parse_time(f['inspection']['review']['expires_at']) + timedelta(seconds=1)
    for h in (f['a'], f['b']):
        advance_to(h, target)
    # Ordinary fresh-request capacity/expiry maintenance is the documented
    # cleanup driver; a pure read/terminal resume is not a cleanup API.
    spare = ssh_public_base64(ssh_key(suite.work, 'history-unadmitted-public-only'))
    status, created = f['b'].api('POST', '/v2/link/requests', {'mode': 'new', 'network_id': '-',
        'person_public_key': spare, 'migration_proposal_id': '-', 'contact_invitation': '-', 'helpers': []})
    check(status == 201 and created['request_id'] != f['rid'], f'genuine unsigned expiry maintenance HTTP {status}')
    status, cancelled = f['b'].api('POST', '/v2/link/requests/' + created['request_id'] + '/cancel', {})
    check(status == 200 and cancelled['state'] == 'cancelled', 'unsigned maintenance request was not publicly cancelled')
    retired_expired_helper(f['b'])
    def retired():
        record, secret = pending(f['b'], f['rid'])
        with closing(sqlite3.connect(f'file:{db_path(f["b"])}?mode=ro', uri=True)) as db:
            frames = db.execute('SELECT count(*) FROM dec_frames').fetchone()[0]
            retained = db.execute('SELECT count(*) FROM dec_pending WHERE secret IS NOT NULL OR terminal_read_cap IS NOT NULL').fetchone()[0]
            outbox = db.execute('SELECT count(*) FROM dec_outbox').fetchone()[0]
        return secret is None and not record['outbound_frames'] and frames == retained == outbox == 0 and not list(f['b'].state.glob('*-journal'))
    wait_for(retired, timeout=5, interval=.1, message='actual expired requester ciphertext/frame retirement')
    quiet(f)


@suite.case('null_missing_F_exact_prepare_device_fold_domains_and_pure_fixed_replays', 'guided46 verification1/4')
def _():
    f = base_world()
    null = op(f, 'lookup', pure=True); check(null['consent'] is None, 'Lookup prepared missing-F consent')
    op(f, 'approve', pure=True, status=409, code='machine_requester_consent_unavailable')
    op(f, 'prepare', pure=True, status=409, code='machine_requester_consent_unavailable', override={**inspection_body(f), 'inspection_review_id': 'review_' + '0' * 64})
    check(not intent_rows(f['b'], f['rid'], 'requester_commit'), 'missing receipt/F created ordinary work')
    progress(f); f['inspection'] = inspect_machine(f); validate_inspection(f, f['inspection'])
    check(op(f, 'lookup', pure=True)['consent'] is None, 'full F Lookup implicitly prepared')
    quiet(f); before, counters = whole(f), traffic(f)
    prepared = op(f, 'prepare'); f['prepared'] = prepared
    prepare_writes_only(f, before, counters)
    c = prepared['consent']
    check(c['state'] == 'review' and c['review']['inspection']['host_admission'] == 'folded_owner'
          and c['review']['inspection']['administrator_offer_id'] == '-', 'device15 fold fabricated separate administrator')
    for action, cli in (('lookup', True), ('prepare', False), ('prepare', True)):
        again = op(f, action, prepared, pure=True, cli=cli)
        check(again['consent'] == c, 'identical replay refreshed/replaced immutable consent')
    check(get(f['b'], '/v2/networks') == [], 'preparation adopted a network')


@suite.case('genuine_original_cap_prepare_INSERT_and_dual_approval_UPDATE_abort_then_exact_atomic_approval', 'guided46 verification2/3')
def _():
    f = progress(base_world('original')); f['inspection'] = inspect_machine(f); validate_inspection(f, f['inspection'])
    check(f['inspection']['review']['owner_provider']['kind'] == 'original_person'
          and parse_time(f['inspection']['review']['not_after']) < parse_time(f['inspection']['review']['created_at']) + timedelta(days=7), 'genuine remote original cap prerequisite')
    check(op(f, 'lookup', pure=True)['consent'] is None, 'original fixture unexpectedly had receipt')
    for kind in ('requester_commit', 'machine_requester_review'):
        fault(f, 'prepare', ["CREATE TRIGGER $NAME BEFORE INSERT ON dec_intents WHEN NEW.kind='" + kind +
            "' AND json_extract(NEW.record,'$.operation_id')='" + f['rid'] + "' BEGIN SELECT RAISE(ABORT,'PRIVATE_REQUESTER_CONSENT_ABORT'); END"])
        check(not intent_rows(f['b'], f['rid'], 'requester_commit') and not intent_rows(f['b'], f['rid'], 'machine_requester_review'), 'failed Prepare left one side')
    quiet(f); before, counters = whole(f), traffic(f)
    f['prepared'] = op(f, 'prepare'); prepare_writes_only(f, before, counters)
    c = f['prepared']['consent']; ids = (c['consent_id'], c['review']['intent_id'])
    check(all(re.fullmatch(r'dint_[0-9a-f]{32}', value) for value in ids), 'unsafe genuine trigger IDs')
    condition = ("(SELECT count(*) FROM dec_intents WHERE intent_id IN ('" + ids[0] + "','" + ids[1] +
        "') AND json_extract(record,'$.approved')=1)=2 AND EXISTS(SELECT 1 FROM dec_pending WHERE request_id='" + f['rid'] +
        "' AND json_extract(record,'$.commit_approved')=1 AND json_extract(record,'$.commit_intent_id')='" + ids[1] + "')")
    fault(f, 'approve', [
        "CREATE TRIGGER $NAME AFTER UPDATE OF record ON dec_intents WHEN " + condition + " BEGIN SELECT RAISE(ABORT,'PRIVATE_REQUESTER_CONSENT_ABORT'); END",
        "CREATE TRIGGER $NAME AFTER UPDATE OF record ON dec_pending WHEN " + condition + " BEGIN SELECT RAISE(ABORT,'PRIVATE_REQUESTER_CONSENT_ABORT'); END"], f['prepared'])
    prior_meta, prior_ordinary, prior_pending = coherent(f, c)
    check(prior_meta['approved'] is prior_ordinary['approved'] is prior_pending['commit_approved'] is False, 'fault left partial approval')
    f['approved'] = op(f, 'approve', f['prepared']); approved = f['approved']['consent']
    meta, ordinary, current = coherent(f, approved)
    check(approved['state'] == 'approved' and core(approved) == core(c), 'approval replaced original reviewed terms')
    check({k: v for k, v in meta.items() if k not in ('approved', 'approved_at')} ==
          {k: v for k, v in prior_meta.items() if k not in ('approved', 'approved_at')}, 'approval mutated nonsigning receipt')
    for field in ('operation_id', 'provider', 'root_state_id', 'person_public_key', 'host_public_key', 'device_public_key', 'scopes', 'not_after', 'created_at', 'expires_at'):
        check(ordinary[field] == prior_ordinary[field], 'approval replaced ordinary immutable term: ' + field)
    for field in ('expected_network_id', 'expected_context_id', 'expected_person_public_key', 'host_public_key', 'device_public_key',
                  'request_nonce', 'request_packet_base64', 'owner_packet_base64', 'selection_packet_base64', 'owner_finalization_packet_base64', 'selection_id', 'selection_intent_id'):
        check(current[field] == prior_pending[field], 'approval rebound retained actual request/selection/F evidence')
    check(meta['approved_at'] == ordinary['approved_at'] != '-' and abs((parse_time(meta['approved_at']) - f['b'].now()).total_seconds()) < 5,
          'dual approval did not retain exact same effective time')
    print('LIMIT machine_requester_consent: coherent atomic flags/time verified; authorized postcommit worker signatures/publication are neither forbidden globally nor attributed to this API', flush=True)


@suite.case('strict_nested_private_JSON_64KiB_CLI_methods_no_startup_and_all_scoped_routes', 'guided46 verification6')
def _():
    f = shared.get('device'); check(f and f.get('prepared'), 'earlier exact device preparation did not finish')
    b = f['b']; data = input_for(f, 'lookup'); encoded = compact(data); ctx = compact(data['context'])
    maximum = encoded + b' ' * (65536 - len(encoded))
    quiet(f); before, counters = whole(f), traffic(f)
    status, value = raw_post(b, endpoint(f, 'lookup'), maximum)
    check(status == 200, f'exact64KiB API Lookup HTTP {status}'); validate_consent(f, value); strict(f, before, counters, 'maximum')
    cli_data = compact({'flow_id': f['flow']['flow_id'], **data})
    quiet(f); before, counters = whole(f), traffic(f)
    result = b.cli('onboarding', 'join', 'machine-commit', 'lookup', '--stdin', input=(cli_data + b' ' * (65536 - len(cli_data))).decode(), timeout=8)
    check(result.ok, 'exact64KiB CLI Lookup refused'); validate_consent(f, result.json); strict(f, before, counters, 'maximum-CLI')
    malformed = [b'null', b'[]', b'{', encoded + b'{}', maximum + b' ',
        b'{"context":' + ctx + b',"context":' + ctx + b',"join_review_id":' + compact(data['join_review_id']) + b'}',
        encoded.replace(b'"integration":"claude-code"', b'"integration":"claude-code","integration":"claude-code"'),
        compact({**data, 'context': None}), compact({**data, 'join_review_id': False}), compact({'context': data['context']}),
        compact({**data, 'context': {**data['context'], 'unknown': 'token_PRIVATE_REQUESTER_CANARY'}})]
    for index, raw in enumerate(malformed):
        quiet(f); before, counters = whole(f), traffic(f)
        status, denied = raw_post(b, endpoint(f, 'lookup'), raw)
        check(status == 400 and denied.get('code') == 'invalid', f'malformed API variant{index} HTTP {status}')
        public(denied, 'token_PRIVATE_REQUESTER_CANARY', *f['secrets'])
        result = b.cli('onboarding', 'join', 'machine-commit', 'lookup', '--stdin', input=(
            b'{"flow_id":' + compact(f['flow']['flow_id']) + b',' + raw[1:] if raw.startswith(b'{') else raw).decode(), timeout=8)
        check(not result.ok, f'malformed CLI variant{index} accepted')
        public(result.stdout + result.stderr, 'token_PRIVATE_REQUESTER_CANARY', str(b.root), *f['secrets']); strict(f, before, counters, 'malformed')
    for action, field, invalid in (('prepare', 'inspection_review_id', None), ('approve', 'consent_review_id', 'review_bad'),
                                  ('lookup', 'provider', 'PRIVATE_REQUESTER_CANARY')):
        patch = {**input_for(f, action, f['prepared']), field: invalid}
        op(f, action, f['prepared'], pure=True, status=400, code='invalid', override=patch)
        op(f, action, f['prepared'], pure=True, cli=True, status=400, override=patch)
    for bad_flow in (None, False, 'flow_bad'):
        quiet(f); before, counters = whole(f), traffic(f)
        result = b.cli('onboarding', 'join', 'machine-commit', 'lookup', '--stdin', input=compact({'flow_id': bad_flow, **data}).decode(), timeout=8)
        check(not result.ok, 'CLI accepted malformed/wrong-type flow'); public(result.stdout + result.stderr, str(b.root)); strict(f, before, counters, 'flow')
    for action in ('lookup', 'prepare', 'approve'):
        for method in ('GET', 'PUT', 'DELETE'):
            quiet(f); before, counters = whole(f), traffic(f)
            status, denied = b.api(method, endpoint(f, action)); check(status == 405, f'{action} alternate method HTTP {status}')
            public(denied); strict(f, before, counters, 'method')
    for args in ((), ('--stdin', 'PRIVATE_REQUESTER_CANARY'), ('--stdin', '--key', 'PRIVATE_REQUESTER_CANARY')):
        quiet(f); before, counters = whole(f), traffic(f)
        result = b.cli('onboarding', 'join', 'machine-commit', 'lookup', *args, input=cli_data.decode(), timeout=8)
        check(not result.ok, 'CLI accepted implicit stdin/private positional selector')
        public(result.stdout + result.stderr, 'PRIVATE_REQUESTER_CANARY', str(b.root)); strict(f, before, counters, 'argument')
    absent = suite.host('nd', start=False); initial = files(absent.root)
    result = absent.cli('onboarding', 'join', 'machine-commit', 'lookup', '--stdin', input=cli_data.decode(), timeout=8)
    check(not result.ok and files(absent.root) == initial, 'consent initialized missing daemon/state/key')
    public(result.stdout + result.stderr, str(absent.root))
    credential = b.ok('adapter', 'create', '--session', f['parent']['review']['session_id'], '--expires-at', rfc3339(b.now() + timedelta(hours=1)))
    adapter = Adapter(b, f['parent']['review']['agent'], f['parent']['review']['session_id'], credential)
    status, _ = adapter.call('POST', '/adapter/v1/connect', {'adapter_id': adapter.adapter_id, 'session_id': adapter.session_id, 'instance_id': adapter.instance})
    check(status == 200, 'actual scoped adapter prerequisite')
    for action in ('lookup', 'prepare', 'approve'):
        quiet(f); before, counters = whole(f), traffic(f)
        status, denied = adapter.call('POST', endpoint(f, action), input_for(f, action, f['prepared']))
        check(status == 404, 'adapter exposed private consent action'); public(denied, adapter.token); strict(f, before, counters, 'adapter')
    peer, boot = host('p'), host('t')
    for local, remote in ((b, peer), (peer, b)):
        local.ok('peer', 'add', '--id', remote.id, '--public-key', remote.public_key, '--address', remote.counted_peer.address)
    cert, key = suite.work / 'route-cert.pem', suite.work / 'route-key.pem'
    result = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ed25519', '-nodes', '-subj', '/CN=route', '-days', '1',
        '-keyout', str(key), '-out', str(cert)], capture_output=True, timeout=5)
    check(result.returncode == 0, 'actual bootstrap client certificate setup')
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); tls.check_hostname = False; tls.verify_mode = ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key)); tls.set_alpn_protocols(['peerspan-bootstrap/1'])
    for action in ('lookup', 'prepare', 'approve'):
        payload = compact(input_for(f, action, f['prepared']))
        result = subprocess.run([str(suite.probe_bin), '--state', str(peer.state), '--address', b.counted_peer.address,
            '--alpn', 'peerspan-peer/1', '--method', 'POST', '--path', endpoint(f, action), '--body-stdin'], input=payload, capture_output=True, timeout=8)
        check(result.returncode == 0 and json.loads(result.stdout)['status'] == 404, 'peer exposed private requester consent')
        public(result.stdout.decode() + result.stderr.decode(), *f['secrets'])
        with socket.create_connection(('127.0.0.1', boot.bootstrap_port), timeout=5) as raw:
            with tls.wrap_socket(raw, server_hostname='peerspan') as stream:
                stream.sendall((f'POST {endpoint(f, action)} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\n\r\n').encode() + payload)
                reply = http.client.HTTPResponse(stream); reply.begin(); response = reply.read()
                check(reply.status == 404, 'bootstrap exposed private requester consent'); public(response.decode(errors='replace'), *f['secrets'])
    peer.stop(); boot.stop()


@suite.case('real_cancel_fresh_nonce_raw_creation_stage_request_expiry_and_fixed_history', 'guided46 verification4')
def _():
    f = base_world('time')
    check(op(f, 'lookup', pure=True)['consent'] is None, 'missing-F time lookup implicitly prepared')
    status, cancelled = f['b'].api('POST', '/v2/link/requests/' + f['rid'] + '/cancel', {})
    check(status == 200 and cancelled['state'] == 'cancelled', 'genuine precommit request cancellation failed')
    check(op(f, 'lookup', pure=True)['consent'] is None, 'cancelled null history gained receipt')
    op(f, 'prepare', pure=True, status=409, code='machine_requester_consent_unavailable',
       override={**inspection_body(f), 'inspection_review_id': 'review_' + '0' * 64})
    renew_cancelled_fixture(f)
    f['inspection'] = inspect_machine(f); validate_inspection(f, f['inspection'])
    # Actual backwards raw time inside the shared300s guard must not be laundered
    # into valid fresh creation by its retained effective clock clamp.
    present = max(f['a'].now(), f['b'].now()) + timedelta(seconds=1)
    quiet(f)
    for h in (f['a'], f['b']):
        advance_to(h, parse_time(f['inspection']['review']['created_at']) - timedelta(seconds=1))
    op(f, 'prepare', pure=True, status=409, code='machine_requester_consent_unavailable')
    for h in (f['a'], f['b']):
        advance_to(h, present)
    f['prepared'] = op(f, 'prepare'); c = f['prepared']['consent']
    present = max(f['a'].now(), f['b'].now()) + timedelta(seconds=1)
    quiet(f)
    for h in (f['a'], f['b']):
        advance_to(h, parse_time(c['review']['created_at']) - timedelta(seconds=1))
    op(f, 'approve', f['prepared'], pure=True, status=409, code='machine_requester_consent_unavailable')
    for h in (f['a'], f['b']):
        advance_to(h, present)
    for patch in ({'consent_review_id': 'review_' + '0' * 64},
                  {'join_review_id': 'review_' + '0' * 64},
                  {'context': {**context(f['parent']), 'native_session_id': 'different-machine-requester-conversation'}}):
        op(f, 'approve', f['prepared'], pure=True, status=409, code='review_changed', override={**input_for(f, 'approve', f['prepared']), **patch})
    op(f, 'prepare', f['prepared'], pure=True, status=409, code='review_changed',
       override={**input_for(f, 'prepare'), 'inspection_review_id': 'review_' + '0' * 64})
    stage = parse_time(f['inspection']['review']['request_stage_deadline'])
    check(parse_time(c['review']['expires_at']) == stage and stage < parse_time(f['inspection']['review']['expires_at'])
          and stage < parse_time(f['inspection']['review']['not_after']), 'genuine receipt/stage expiry did not isolate earlier than request/powers')
    quiet(f)
    for h in (f['a'], f['b']):
        advance_to(h, stage + timedelta(seconds=1))
    retired_expired_helper(f['b'])
    op(f, 'approve', f['prepared'], pure=True, status=409, code='review_expired')
    old = op(f, 'lookup', pure=True)
    check(old['consent']['state'] == 'expired' and core(old['consent']) == core(c), 'expired lookup renewed original receipt/stage window')
    check(core(op(f, 'prepare', f['prepared'], pure=True, cli=True)['consent']) == core(c), 'expired Prepare repaired/replaced exact history')
    for h in (f['a'], f['b']):
        advance_to(h, parse_time(f['inspection']['review']['expires_at']) + timedelta(seconds=1))
    retired_expired_helper(f['b'])
    op(f, 'approve', f['prepared'], pure=True, status=409, code='review_expired')
    check(op(f, 'lookup', pure=True, cli=True)['consent']['state'] == 'expired', 'signed expiry hid or reauthorized receipt')
    print('LIMIT machine_requester_consent: real stage/receipt then signed expiry exercised; isolated powers expiry/current-authority change and cancellation of an already framed commit are not fabricated', flush=True)


@suite.case('approved_history_is_pure_after_real_expiry_detach_restart_without_any_requester_original', 'guided46 verification5')
def _():
    f = shared.get('original'); check(f and f.get('approved'), 'earlier exact guided atomic approval did not finish')
    approved = f['approved']['consent']
    history_retirement(f)
    exact_receipt = load_intent(f['b'], approved['consent_id'])
    exact_ordinary = load_intent(f['b'], approved['review']['intent_id'])
    for phase in ('expired', 'detached', 'restarted'):
        if phase == 'detached':
            f['b'].ok('session', 'detach', f['parent']['review']['session_id'])
        if phase == 'restarted':
            f['b'].restart(kill=True)
            check(get(f['b'], PROJECT + '/' + f['parent']['flow_id'])['state'] == 'invalidated', 'genuine restart failed to detach original parent')
            retired_expired_helper(f['b'])
        for action in ('lookup', 'prepare', 'approve'):
            value = op(f, action, f['prepared'], pure=True, cli=(phase == 'detached' or action == 'prepare'))
            check(value['consent']['state'] == 'approved' and core(value['consent']) == core(approved), 'expired/detached/restarted history changed exact approved consent')
        op(f, 'approve', f['prepared'], pure=True, status=409, code='review_changed',
           override={**input_for(f, 'approve', f['prepared']), 'consent_review_id': 'review_' + '0' * 64})
    check(load_intent(f['b'], approved['consent_id']) == exact_receipt and load_intent(f['b'], approved['review']['intent_id']) == exact_ordinary,
          'history rewrote approval time/templates/signatures/provider/terminal evidence')
    no_original(f)
    print('LIMIT machine_requester_consent: strict history is retained evidence with old computer offline; no both-live worker attribution, unavailable owned-device syscall or local application claim', flush=True)


@suite.case('ordinary_advanced_approval_cannot_implicitly_prepare_or_gain_project_attribution', 'guided46 verification2')
def _():
    f = shared.get('device'); check(f and f.get('prepared'), 'earlier genuine device preparation did not finish')
    c = f['prepared']['consent']; before_meta = load_intent(f['b'], c['consent_id'])
    op(f, 'approve', f['prepared'], pure=True, status=409, code='review_changed',
       override={**input_for(f, 'approve', f['prepared']), 'consent_review_id': 'review_' + '0' * 64})
    view = link_view(f['b'], f['rid'])
    status, _ = f['b'].api('POST', '/v2/link/requests/' + f['rid'] + '/commit', {
        **{key: view[key] for key in ('network_id', 'context_id', 'person_public_key', 'host_public_key', 'device_public_key',
            'owner_offer_id', 'selection_id', 'administrator_offer_id', 'owner_finalization_id')}, 'approve': True}, timeout=20)
    check(status == 200, f'genuine explicit outside ordinary commit approval HTTP {status}')
    # Authorized ordinary work can concurrently sign/publish. This is a coherent
    # state-only observation, explicitly NOT a global live purity/absence claim.
    value = op(f, 'lookup')
    check(value['consent']['state'] == 'invalidated' and core(value['consent']) == core(c), 'outside approval laundered into project consent')
    meta, ordinary, current = coherent(f, c)
    check(meta['approved'] is False and meta['approved_at'] == '-' and ordinary['approved'] is current['commit_approved'] is True
          and current['commit_intent_id'] == c['review']['intent_id'], 'outside approval changed metadata attribution or pending reference')
    op(f, 'approve', f['prepared'], status=409, code='review_changed')
    check(load_intent(f['b'], c['consent_id']) == before_meta, 'rejected guided approval rewrote unapproved receipt')
    print('LIMIT machine_requester_consent: outside advanced approval lookup is state-only; no global worker/signature/transport absence or API-caller attribution is claimed', flush=True)


suite.finish()
