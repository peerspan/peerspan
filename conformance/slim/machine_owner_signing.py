#!/usr/bin/env python3
"""Bounded exact existing-machine owner signing, guided section43.

Independent public-contract/test-fixture source only. Genuine signed automatic
returns/current original+device authority and exact GUIDED dual approval. Only
schema-only ABORT triggers inject database failure. Whole logical DB/schema,
state/home files and BOTH TCP+UDP paths remain strict; SQLite WAL/SHM bookkeeping
alone is excluded. A current consumed ClientHello holds approved worker IO
outside SQLite before the configured original source is made available. No
worker disabling, authority/protocol/queue/clock row edits or eager suite imports.

Real safe-file and multi-identity agent keys exist on the existing original
computer only; no requester original or caller-selected signer. Independent
SSHSIG/Ed25519 verification uses genuine retained templates. Signature evidence
never attributes background work to this route or proves publication/readiness.
Limits: exact90s cutoff/syscalls, simultaneous key dispatch/commit races, corrupt
or quota/complex authority/seed failures and full later-stage admission lack
bounded genuine stimuli here; no native/model/installed/physical claims. All32
prior host suites/helpers and393 native cases remain unchanged. Runtime is root's.
"""
import atexit
import base64
import hashlib
import http.client
import json
import math
import os
import shutil
import struct
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

from harness import (Adapter, Clock, Suite, UnixHTTPConnection, check, link_view,
                     parse_time, rfc3339, ssh_key, ssh_public_base64, wait_for)
from counted_peer import CountedUDP

suite = Suite('machine_owner_signing', __doc__)
BASE = '/v1/onboarding/machine-owner-consent'
INSPECT = '/v1/onboarding/machine-owner-inspection'
PROJECT = '/v1/onboarding/project-flows'
TOP = set('version host_id context observed_at request inspection consent'.split())
REVIEW = set('version kind consent_id host_id context agent request_id request_packet_id inspection_review_id inspection intent_id proposed_owner_offer_id replaces_consent_id created_at expires_at request_stage_deadline effects'.split())
INSPECTION = set('version kind host_id context agent network root_state_id request_id request_packet_id person_public_key host_public_key device_public_key member person_lease_id local_host provider provider_id signature_format scopes not_after host_admission created_at expires_at effects'.split())
PROVIDER = set('kind person_public_key host_public_key device_public_key lease_id root_state_id scopes not_after'.split())
MEMBER = set('host_public_key member person_public_key host_lease_id binding_lease_id device_lease_id not_after'.split())
LINK = set('request_id role mode state network_id context_id migration_proposal_id person_public_key host_public_key device_public_key created_at expires_at request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id manifest_id activation_id outcome_id selection_approved commit_approved completed attention next'.split())
RECORD = set('format operation_id approved approved_at review_base64 provider root_state_id person_public_key host_public_key device_public_key scopes not_after created_at expires_at templates signatures completed terminal result_base64'.split())
INSPECT_EFFECTS = {'verify_request_signature': True, 'inspect_current_owner_authority': True,
    **{k: False for k in ('prepare_owner_intent', 'approve_owner_intent', 'sign_owner_offer', 'publish_owner_offer', 'grant_membership', 'grant_machine_powers', 'grant_agent_access', 'commit_request', 'share_files', 'share_conversation', 'capability_calls')}}
EFFECTS = {**{k: True for k in ('approve_owner_intent', 'authorize_owner_offer_signature',
    'publish_owner_offer_after_signatures', 'authorize_owner_finalization', 'authorize_binding_and_device_signatures')},
    **{k: False for k in ('grant_membership_now', 'grant_machine_powers_now', 'grant_agent_access',
    'authorize_requester_selection', 'commit_request', 'share_files', 'share_conversation', 'capability_calls')}}
PREFIXES = ('psi2-', 'psl2-', 'peerspan-invite-v1.', 'peerspan-member-invite-v1.',
            'peerspan-person-invite-v1.', 'token_', 'instance_')
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


def snapshot(h):
    return records(h), files(h.state), files(h.home)


def traffic(f):
    return (f["a"].relay.counts(), f["b"].relay.counts(),
            f["a"].counted_peer.counts(), f["b"].counted_peer.counts())


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


def whole(f):
    return snapshot(f['a']), snapshot(f['b'])


def quiet(f):
    settled(f['a'])
    previous = (whole(f), traffic(f))
    def stable():
        nonlocal previous
        current = (whole(f), traffic(f)); same = current == previous; previous = current
        return same
    time.sleep(.1)
    wait_for(stable, timeout=3, interval=.1, message='settled machine-owner DB/files and counted carriers')


def strict_failure_diagnostic(actual, expected, current, before):
    """GU.impl42b: categorize captured failures, never resample or alter them."""
    try:
        tables = set('networks network_members peers policy_edits agents sessions adapter_connections adapter_credentials events dec_contexts dec_objects dec_admissions dec_restrictions dec_activations dec_heads dec_highwater dec_signers dec_clock dec_intents dec_pending dec_frames dec_operations dec_outbox dec_migrations dec_contacts dec_helpers identity sqlite_sequence grants received_messages outbound_messages deliveries received_replies outbound_replies adapter_routes network_statements access_blocks received_tasks task_events outbound_tasks outbound_task_events task_deliveries task_update_notifications artifact_files task_artifacts task_children policy_deliveries adapter_outbound directory_sends tool_servers tool_values capabilities source_access received_calls outbound_calls adapter_calls call_update_notifications link_device_keys link_pending link_frames link_operations link_objects link_features link_signers link_highwater call_approvals approval_notices builtin_sources oauth_clients oauth_credentials onboarding_project_flows onboarding_adapter_flows onboarding_invitation_flows onboarding_join_flows helper_format mailboxes frames'.split())
        def file_flags(old, new):
            flags = dict.fromkeys(('regular', 'directory', 'socket', 'other', 'database', 'journal'), False)
            for name in set(old) | set(new):
                if name in old and name in new and old[name] == new[name]:
                    continue
                for entries in (old, new):
                    if name in entries:
                        kind = entries[name][0] & 0o170000
                        flags[{0o100000: 'regular', 0o040000: 'directory', 0o140000: 'socket'}.get(kind, 'other')] = True
                flags['database'] |= name.endswith('.db')
                flags['journal'] |= name.endswith('.db-journal')
            return flags
        sides = []
        for index, side in enumerate(('existing', 'requester')):
            old, new = expected[index], actual[index]
            names = set(); schema = version = False
            for database in set(old[0]) | set(new[0]):
                a, b = old[0].get(database, {}), new[0].get(database, {})
                schema |= a.get('$schema') != b.get('$schema')
                version |= a.get('$version') != b.get('$version')
                for name in (set(a) | set(b)) - {'$schema', '$version'}:
                    if name not in a or name not in b or a[name] != b[name]:
                        names.add(name if name in tables else 'unknown')
            sides.append({'side': side, 'database_set_changed': set(old[0]) != set(new[0]),
                'changed_tables': sorted(names), 'schema_changed': schema, 'version_changed': version,
                'state_categories': file_flags(old[1], new[1]), 'home_categories': file_flags(old[2], new[2])})
        carriers = []
        for index, width in enumerate((2, 2, 4, 4)):
            old = before[index] if index < len(before) else ()
            new = current[index] if index < len(current) else ()
            carriers.append({'index': index, 'shape_changed': len(old) != width or len(new) != width,
                'changed_positions': [position for position in range(width) if position >= len(old)
                    or position >= len(new) or old[position] != new[position]]})
        print('machine_consent_snapshot_failure_public=' + json.dumps({'sides': sides,
            'carrier_shape_changed': len(current) != 4 or len(before) != 4, 'carriers': carriers}, sort_keys=True), flush=True)
    except Exception:
        pass  # Preserve the original complete comparisons, even on malformed snapshots.


def strict(actual, expected, current, before, phase):
    if actual != expected or current != before:
        print('machine_owner_purity_public=' + json.dumps({'phase': phase,
            'database_or_files_changed': actual != expected,
            'carrier_changes': [dict(index=i, changed=x != y) for i, (x, y) in enumerate(zip(current, before))]}, sort_keys=True), flush=True)
        strict_failure_diagnostic(actual, expected, current, before)
    check(actual == expected, 'machine inspection changed whole DB/schema/state/home')
    check(current == before, 'machine inspection performed counted TCP/UDP traffic')


def returned_request(f):
    return next((v for v in get(f['a'], '/v2/link/requests') if v['request_id'] == f['rid']), None)


def world(name='main'):
    if name in shared:
        check(shared[name].get('_ready') is True, 'earlier genuine fixture setup did not finish')
        return shared[name]
    f = {}; shared[name] = f
    a, b = host(name + 'a'), host(name + 'b')
    key = ssh_key(suite.work, name + '-existing-original')
    net = a.ok('network', 'create', 'Machine owner "東京" ' + name, '--as', 'Existing "é" owner', '--person-key-file', key)
    check(net['mode'] == 'decentralized' and net['person_public_key'] == ssh_public_base64(key), 'actual existing original creation')
    parent, remote_parent = project(a, name + 'a'), project(b, name + 'b')
    f.update(a=a, b=b, parent=parent, remote_parent=remote_parent, network=net, key=key, person=net['person_public_key'], secrets=[])
    # Genuine later creation makes the inherited finite provider cap observable
    # even when all initial CLI operations fall in the same wall-clock second.
    creation_time = max(a.now(), b.now()) + timedelta(seconds=2)
    for h in (a, b):
        advance_to(h, creation_time)
    status, issued = a.api('POST', '/v2/networks/' + net['id'] + '/invitations', {
        'member': 'Existing person next computer', 'expected_person_public_key': f['person'],
        'expires_at': rfc3339(a.now() + timedelta(seconds=65))})
    check(status == 201 and issued.get('invitation'), f'genuine pinned invitation HTTP {status}')
    status, requested = b.api('POST', '/v2/link/requests', {'mode': 'new', 'network_id': net['id'],
        'person_public_key': f['person'], 'migration_proposal_id': '-', 'contact_invitation': issued['invitation'], 'helpers': []})
    check(status == 201 and requested.get('display_code'), f'genuine machine publication HTTP {status}')
    f.update(rid=requested['request_id'], reply=requested['display_code'], issued=issued,
             secrets=[issued['invitation'], requested['display_code'], str(key)])
    incoming = wait_for(lambda: returned_request(f), timeout=15, interval=.1, message='actual automatic pending machine return')
    check(incoming['role'] == 'approver' and incoming['state'] == 'pending' and incoming['owner_offer_id'] == '-',
          'public automatic return advanced or did not retain an incoming pending request')
    check(incoming['person_public_key'] == f['person'] and incoming['host_public_key'] == b.public_key and a.public_key != b.public_key,
          'automatic return changed genuine person/remote host pins')
    invitations = [issued]
    if name == 'main':
        other_key = ssh_key(suite.work, 'unadmitted-other-person'); other = ssh_public_base64(other_key)
        check(other != f['person'], 'wrong-owner fixture accidentally reused admitted person')
        status, wrong_invite = a.api('POST', '/v2/networks/' + net['id'] + '/invitations', {
            'member': 'Different unadmitted person', 'expected_person_public_key': other,
            'expires_at': rfc3339(a.now() + timedelta(seconds=65))})
        check(status == 201, f'genuine other-person invitation HTTP {status}')
        status, wrong = b.api('POST', '/v2/link/requests', {'mode': 'new', 'network_id': net['id'],
            'person_public_key': other, 'migration_proposal_id': '-', 'contact_invitation': wrong_invite['invitation'], 'helpers': []})
        check(status == 201, f'genuine other-person request HTTP {status}')
        f['wrong_rid'] = wrong['request_id']
        wait_for(lambda: next((v for v in get(a, '/v2/link/requests') if v['request_id'] == f['wrong_rid']
                              and v['role'] == 'approver' and v['state'] == 'pending'), None),
                 timeout=15, interval=.1, message='genuine other-person automatic return')
        invitations.append(wrong_invite)
        f['secrets'] += [wrong_invite['invitation'], wrong['display_code'], str(other_key)]
    target = max(a.now(), b.now(), *[parse_time(item['expires_at']) + timedelta(seconds=1) for item in invitations])
    check(target < parse_time(requested['expires_at']), 'invitation isolation consumed signed request lifetime')
    for h in (a, b):
        advance_to(h, target)
    def retired():
        with closing(sqlite3.connect(f'file:{db_path(a)}?mode=ro', uri=True)) as db:
            rows = [db.execute('SELECT secret FROM dec_pending WHERE request_id=?', (item['invitation_id'],)).fetchone()
                    for item in invitations]
        return all(row is None or row[0] is None for row in rows)
    wait_for(retired, timeout=5, interval=.1, message='actual automatic-return invitation secret retirement')
    b.stop(); quiet(f)
    f['device'] = get(a, '/v2/networks/' + net['id'])['provider']
    check(f['device']['kind'] == 'device' and f['device']['scopes'] == 15, 'established creator device15 prerequisite')
    check(not (b.home / '.config/peerspan/person_ed25519').exists(), 'requester unexpectedly created/copied an original key')
    f['_ready'] = True
    return f


def select_provider(f, provider):
    h = f['a']
    status, value = h.api('POST', '/v2/networks/' + f['network']['id'] + '/provider', {
        'provider_id': provider, 'person_public_key': f['person'], 'host_public_key': h.public_key, 'approve': True})
    check(status == 200, f'ordinary exact provider selection HTTP {status}')
    return value


def intent(h, iid):
    with closing(sqlite3.connect(f'file:{db_path(h)}?mode=ro', uri=True)) as db:
        row = db.execute('SELECT network_id,context_id,kind,record,secret FROM dec_intents WHERE intent_id=?', (iid,)).fetchone()
    check(row is not None, 'exact receipt/ordinary intent missing')
    return {'network_id': row[0], 'context_id': row[1], 'kind': row[2], 'record': json.loads(row[3]), 'secret': row[4]}


def dual_records(h, receipt):
    ids = (receipt['consent_id'], receipt['review']['intent_id'])
    with closing(sqlite3.connect(f'file:{db_path(h)}?mode=ro', uri=True)) as db, db:
        db.execute('BEGIN')
        rows = [db.execute('SELECT record FROM dec_intents WHERE intent_id=?', (iid,)).fetchone() for iid in ids]
    check(all(row is not None for row in rows), 'coherent approval snapshot lost one intent')
    return [json.loads(row[0]) for row in rows]


def no_keys(f):
    h = f['b']
    check(not (h.root / 'absent-person-key').exists() and not (h.root / 'absent-agent.sock').exists()
          and not (h.home / '.config/peerspan/person_ed25519').exists(), 'requester acquired an original signer')


def original(f):
    value = select_provider(f, f['person'])
    check(value['provider']['kind'] == 'original_person' and value['provider_state']['state'] == 'unavailable',
          'selected original is not genuinely publicly usable and privately unavailable')
    no_keys(f)


def standalone(f):
    status, value = f['a'].api('POST', INSPECT, {'context': context(f['parent']), 'request_id': f['rid']}, timeout=8)
    check(status == 200, f'public section41 inspection prerequisite HTTP {status}')
    return {'review_id': value['review_id'], 'review': value['review']}


def input_for(f, action, prepared=None, *, parent=None, inspected=None, replace=None):
    data = {'context': context(parent or f['parent']), 'request_id': f['rid']}
    if action == 'lookup' and prepared is not None:
        data['consent_id'] = prepared['consent']['consent_id']
    elif action == 'prepare':
        data['inspection_review_id'] = inspected['review_id'] if inspected else prepared['consent']['review']['inspection_review_id']
        if replace is not None:
            data['replace_consent_id'] = replace
    elif action == 'approve':
        data.update(consent_id=prepared['consent']['consent_id'], consent_review_id=prepared['consent']['review_id'])
    return data


def raw_post(h, action, raw):
    conn = UnixHTTPConnection(str(h.state / 'admin.sock'), timeout=8)
    try:
        try:
            conn.request('POST', BASE + '/' + action, body=raw, headers={'Content-Type': 'application/json'})
        except BrokenPipeError:
            pass  # Still demand the actual HTTP refusal; never retry transport.
        response = conn.getresponse(); body = response.read()
        return response.status, json.loads(body) if body else None
    finally:
        conn.close()


def pending_prepare_diagnostic(before, after, secret, same_secret, intent_id):
    """GU.impl42a: captured field names only, without changing the verdict."""
    try:
        if not (after['owner_intent_id'] == intent_id and same_secret == secret
                and unchanged_except(before, after, 'roles', 'owner_intent_id')):
            fields = set('format roles mode migration_proposal_id expected_network_id expected_context_id expected_person_public_key contact_invitation_base64 descriptor_base64 host_public_key device_public_key request_nonce request_packet_base64 owner_packet_base64 selection_packet_base64 administrator_packet_base64 owner_finalization_packet_base64 commit_packet_base64 outcome_packet_base64 catalog_base64 owner_offer_id selection_id administrator_offer_id owner_finalization_id manifest_id activation_id outcome_id selection_approved commit_approved owner_intent_id administrator_intent_id selection_intent_id commit_intent_id terminal carrier_endpoints outbound_frames stage_at'.split())
            changed = [name for name in set(before) | set(after)
                       if name not in before or name not in after or before[name] != after[name]]
            summary = {'changed_fields': sorted({name if name in fields else 'unknown' for name in changed}),
                       'secret_unchanged': same_secret == secret}
            print('machine_consent_pending_failure_public=' + json.dumps(summary, sort_keys=True), flush=True)
    except Exception:
        pass  # Diagnostic failure cannot replace the original captured check.


def refusal_code_diagnostic(action, status, value, expected):
    """GU.impl42a: no new request, only a closed code-mismatch summary."""
    try:
        if not (type(value) is dict and value.get('code') == expected):
            codes = {'invalid', 'not_found', 'review_changed', 'review_expired', 'machine_owner_consent_unavailable'}
            actual = value.get('code') if type(value) is dict else None
            summary = {'operation': action if action in {'lookup', 'prepare', 'approve'} else 'unknown',
                'http_status': status if type(status) is int and 100 <= status <= 599 else 'unknown',
                'actual_code': actual if isinstance(actual, str) and actual in codes else 'unknown',
                'expected_code': expected if isinstance(expected, str) and expected in codes else 'unknown'}
            print('machine_consent_code_failure_public=' + json.dumps(summary, sort_keys=True), flush=True)
    except Exception:
        pass  # Keep the original assertion and failure unchanged.


def op(f, action, prepared=None, *, parent=None, inspected=None, replace=None, override=None,
       status=200, code=None, cli=False, validate_result=True):
    h = f['a']; parent = parent or f['parent']
    data = override if override is not None else input_for(f, action, prepared, parent=parent, inspected=inspected, replace=replace)
    if cli:
        result = h.cli('onboarding', 'machine', action, '--stdin', input=compact(data).decode(), timeout=8)
        check(result.ok == (status == 200), 'private consent CLI outcome mismatch')
        public(result.stderr, str(h.state), *f['secrets'])
        if not result.ok:
            public(result.stdout, str(h.state), data['context']['project_root'], data['context']['native_session_id'], *f['secrets'])
        value = result.json
    else:
        actual, value = h.api('POST', BASE + '/' + action, data, timeout=8)
        if actual != status:
            safe_code = value.get('code') if type(value) is dict else None
            print('machine_consent_failure_public=' + json.dumps({'phase': action, 'http_status': actual,
                'code': safe_code if isinstance(safe_code, str) and safe_code in {'invalid', 'not_found', 'review_changed', 'review_expired',
                'machine_owner_consent_unavailable'} else 'unknown'}, sort_keys=True), flush=True)
        check(actual == status, f'machine consent {action} HTTP {actual}, expected {status}')
        if code:
            refusal_code_diagnostic(action, actual, value, code)
            check(type(value) is dict and value.get('code') == code, 'machine consent controlled refusal code mismatch')
    public(value, *f['secrets'])
    if status != 200:
        public(value, str(h.state), *[v for k, v in data['context'].items() if k != 'integration'],
               *[v for k, v in data.items() if k != 'context' and isinstance(v, str)])
    if status == 200 and validate_result:
        validate(f, value, parent=parent)
    return value


def pure(f, action, prepared=None, **kwargs):
    quiet(f); before, counters = whole(f), traffic(f)
    value = op(f, action, prepared, **kwargs)
    strict(whole(f), before, traffic(f), counters, action + ('-CLI' if kwargs.get('cli') else '-API'))
    return value


def core(receipt):
    return {k: v for k, v in receipt.items() if k not in ('state', 'next_action')}


def unchanged_except(before, after, *fields):
    return {k: v for k, v in before.items() if k not in fields} == {k: v for k, v in after.items() if k not in fields}


def inspection_shape(f, inspected, *, parent, request, current=False):
    check(type(inspected) is dict and set(inspected) == {'review_id', 'review'}, 'closed current inspection pair')
    review = inspected['review']
    check(type(review) is dict and set(review) == INSPECTION and type(review['version']) is int and review['version'] == 1
          and review['kind'] == 'inspect_existing_person_machine', 'closed full frozen inspection')
    check(inspected['review_id'] == digest('peerspan-machine-owner-inspection-v1', review), 'independent exact inspection digest')
    check(review['host_id'] == f['a'].id and review['context'] == context(parent)
          and review['agent'] == parent['review']['agent'], 'inspection changed exact attached agent/context')
    for key in ('request_id', 'request_packet_id', 'person_public_key', 'host_public_key', 'device_public_key', 'created_at', 'expires_at'):
        check(review[key] == request[key], 'inspection changed actual signed request pin: ' + key)
    actual_network = get(f['a'], '/v2/networks/' + f['network']['id']) if current else f['public_network']
    check(review['network'] == {k: actual_network[k] for k in ('id', 'name', 'context_id', 'genesis_root_public_key')},
          'inspection changed actual verified network')
    provider = review['provider']
    check(set(provider) == PROVIDER and set(review['local_host']) == MEMBER and provider['kind'] in ('device', 'original_person')
          and provider['person_public_key'] == f['person'] and provider['host_public_key'] == f['a'].public_key
          and provider['root_state_id'] == review['root_state_id'], 'wrong public selected authority/root/local host')
    check(type(review['scopes']) is int and review['scopes'] == 7 and provider['scopes'] & 7 == 7
          and provider['device_public_key'] != request['device_public_key'], 'scope7 exceeded selected distinct authority')
    check(review['provider_id'] == (f['person'] if provider['kind'] == 'original_person' else provider['lease_id'])
          and review['signature_format'] == ('sshsig' if provider['kind'] == 'original_person' else 'ed25519'),
          'provider reference/format substitution')
    check(review['host_admission'] == ('owner_may_fold' if provider['scopes'] & 8 else 'separate_administrator_required'),
          'incorrect potential host admission')
    check(parse_time(review['not_after']) == min(parse_time(request['created_at']) + timedelta(days=7), parse_time(provider['not_after']))
          and review['effects'] == INSPECT_EFFECTS and all(type(x) is bool for x in review['effects'].values()),
          'fixed finite powers or readonly effects widened')
    if current:
        h = f['a']; net = get(h, '/v2/networks/' + f['network']['id'])
        mine = next(row for row in get(h, '/v2/networks/' + f['network']['id'] + '/members')['members'] if row['host_public_key'] == h.public_key)
        person = next(row for row in get(h, '/v2/networks/' + f['network']['id'] + '/persons')['persons'] if row['person_public_key'] == f['person'])
        check(net['authority']['state'] == 'usable' and provider == net['provider'] and review['root_state_id'] == net['root_state_id']
              and review['local_host'] == mine and review['person_lease_id'] == person['person_lease_id']
              and review['member'] == person['member'], 'inspection differs from actual complete current P/H/B/D/provider')


def validate(f, value, *, parent=None):
    h = f['a']; parent = parent or f['parent']
    check(type(value) is dict and set(value) == TOP and type(value['version']) is int and value['version'] == 1,
          'closed machine-owner consent wrapper')
    check(value['host_id'] == h.id and value['context'] == context(parent), 'exact wrapper context/host')
    check(rfc3339(parse_time(value['observed_at'])) == value['observed_at']
          and abs((parse_time(value['observed_at']) - h.now()).total_seconds()) < 5, 'canonical actual guarded observation')
    request = value['request']
    check(type(request) is dict and set(request) == LINK and request['request_id'] == f['rid']
          and request['role'] == 'approver' and request['mode'] == 'new'
          and request['network_id'] == f['network']['id'] and request['person_public_key'] == f['person']
          and request['host_public_key'] == f['b'].public_key, 'complete actual incoming public request')
    check(request == link_view(h, f['rid']), 'wrapper request differs from ordinary public LINK_VIEW')
    if value['inspection'] is not None:
        inspection_shape(f, value['inspection'], parent=parent, request=request, current=False)
    consent = value['consent']
    if consent is None:
        check(len(compact(value)) <= 2 * 1024 * 1024, 'null response exceeds public bound')
        return
    check(type(consent) is dict and set(consent) == {'consent_id', 'review_id', 'review', 'state', 'next_action'}, 'closed consent result')
    review = consent['review']
    check(type(review) is dict and set(review) == REVIEW and type(review['version']) is int and review['version'] == 1
          and review['kind'] == 'approve_existing_person_machine', 'closed immutable machine-owner review')
    check(re.fullmatch(r'dint_[0-9a-f]{32}', consent['consent_id']) and review['consent_id'] == consent['consent_id']
          and re.fullmatch(r'dint_[0-9a-f]{32}', review['intent_id']) and review['intent_id'] != consent['consent_id'],
          'receipt is not separate from actual ordinary owner intent')
    frozen = review['inspection']
    check(set(frozen) == INSPECTION and review['inspection_review_id'] == digest('peerspan-machine-owner-inspection-v1', frozen)
          and review['host_id'] == frozen['host_id'] == h.id and review['context'] == frozen['context']
          and review['agent'] == frozen['agent'], 'frozen exact inspection/context/agent binding')
    for key in ('request_id', 'request_packet_id'):
        check(review[key] == frozen[key] == request[key], 'receipt changed actual request identity')
    check(consent['review_id'] == digest('peerspan-machine-owner-consent-v1', review), 'independent canonical whole-review digest')
    check(review['replaces_consent_id'] == '-' or re.fullmatch(r'dint_[0-9a-f]{32}', review['replaces_consent_id']), 'replacement lineage malformed')
    effects = {**EFFECTS, 'authorize_host_admission_if_folded': frozen['host_admission'] == 'owner_may_fold'}
    check(review['effects'] == effects and all(type(x) is bool for x in review['effects'].values()), 'consent widened or misstated exact effects')
    receipt, ordinary = intent(h, consent['consent_id']), intent(h, review['intent_id'])
    record, owner = receipt['record'], ordinary['record']
    check(receipt['kind'] == 'machine_owner_review' and ordinary['kind'] == 'owner'
          and receipt['secret'] is None and ordinary['secret'] is None
          and receipt['network_id'] == ordinary['network_id'] == f['network']['id']
          and receipt['context_id'] == ordinary['context_id'] == f['network']['context_id'], 'wrong existing-schema intent/secret roles')
    check(set(record) == set(owner) == RECORD and type(record['format']) is type(owner['format']) is int
          and record['format'] == owner['format'] == 1 and type(owner['approved']) is bool
          and type(record['approved']) is bool and record['completed'] is True and record['terminal'] == '-'
          and record['templates'] == [] and record['signatures'] == [] and record['result_base64'] == '-',
          'metadata receipt acquired signatures/templates/terminal authority')
    check(base64.b64decode(record['review_base64'], validate=True) == canonical(review), 'receipt did not retain exact canonical full review')
    check(record['operation_id'] == 'mrev_' + hashlib.sha256(b'peerspan-machine-owner-review-key-v1\n' +
          canonical({'host_id': h.id, 'request_id': f['rid']})).hexdigest(), 'wrong context-independent retained receipt key')
    provider = frozen['provider']
    check(owner['provider'] == {'kind': 'original' if provider['kind'] == 'original_person' else 'device',
          'signer_public_key': provider['person_public_key'] if provider['kind'] == 'original_person' else provider['device_public_key'],
          'signature_format': frozen['signature_format'], 'lease_id': '-' if provider['kind'] == 'original_person' else provider['lease_id']},
          'ordinary intent silently changed concrete selected signer')
    for field in ('provider', 'root_state_id', 'person_public_key', 'host_public_key', 'device_public_key', 'scopes', 'not_after'):
        check(record[field] == owner[field], 'receipt changed immutable ordinary field: ' + field)
    check(owner['root_state_id'] == frozen['root_state_id'] and owner['scopes'] == 7 and owner['not_after'] == frozen['not_after'],
          'ordinary preparation widened current rooted finite powers')
    templates = [t for t in owner['templates'] if t['object_type'] == 'owner_offer_packet']
    check(len(templates) == 1 and templates[0]['slot_id'] == 1 and set(templates[0]) == {'slot_id', 'object_type', 'template_base64'},
          'first ordinary owner template missing/replaced')
    template = json.loads(base64.b64decode(templates[0]['template_base64'], validate=True))
    offer = json.loads(base64.b64decode(template['payload_base64'], validate=True))
    check(review['proposed_owner_offer_id'] == packet_id(template) and template['request_id'] == f['rid']
          and template['context_id'] == f['network']['context_id'] and template['role'] == 'owner'
          and template['writer_host_public_key'] == h.public_key and template['person_public_key'] == f['person']
          and template['authority_signature_format'] == frozen['signature_format']
          and template['issuer_id'] == ('-' if provider['kind'] == 'original_person' else provider['lease_id'])
          and template['authority_signature'] == template['device_signature'] == '-'
          and template['signer_public_key'] == owner['provider']['signer_public_key'], 'actual first template/domain/provider mismatch')
    check(offer['request_packet_id'] == frozen['request_packet_id'] and offer['host_public_key'] == f['b'].public_key
          and offer['device_public_key'] == frozen['device_public_key'] and offer['mode'] == 'new'
          and offer['root_state_id'] == frozen['root_state_id'] and offer['person_lease_id'] == frozen['person_lease_id']
          and offer['member'] == frozen['member'] and offer['scopes'] == 7 and offer['not_after'] == frozen['not_after'],
          'actual proposed owner offer differs from frozen public powers')
    check(review['created_at'] == record['created_at'] and review['expires_at'] == record['expires_at']
          and parse_time(review['created_at']) < parse_time(review['expires_at']), 'receipt creation/fixed expiry mismatch')
    # request_stage_deadline is captured, never recomputed from later stages.
    check(review['request_stage_deadline'] == f['stage_deadline'], 'frozen original request stage deadline changed')
    check(parse_time(review['expires_at']) == min(parse_time(owner['created_at']) + timedelta(seconds=300),
          parse_time(request['expires_at']), parse_time(review['request_stage_deadline']), parse_time(owner['not_after'])),
          'receipt restarted ordinary signing/stage/request/authority window')
    actions = {'review': 'approve_machine_owner_intent', 'approved': 'follow_machine_link',
               'expired': 'inspect_machine_link', 'invalidated': 'inspect_machine_link', 'cancelled': 'inspect_machine_link'}
    check(consent['state'] in actions and consent['next_action'] == actions[consent['state']], 'wrong consent state/next action')
    if record['approved']:
        both = dual_records(h, consent)
        check(consent['state'] == 'approved' and all(r['approved'] is True for r in both)
              and both[0]['approved_at'] == both[1]['approved_at'] != '-', 'approval inferred without exact atomic dual flags/time')
    else:
        check(record['approved_at'] == '-' and consent['state'] != 'approved', 'unsigned receipt laundered outside approval')
    check(len(compact(value)) <= 2 * 1024 * 1024, 'public consent overflow')
    no_keys(f)


def allowed_write(f, before, counters, allowed):
    after = whole(f)
    check(after[1] == before[1], 'local consent changed remote DB/state/home')
    check(set(after[0][0]) == set(before[0][0]), 'local consent created another database')
    for name in after[0][0]:
        old, new = before[0][0][name], after[0][0][name]
        check({k: v for k, v in old.items() if k not in allowed} == {k: v for k, v in new.items() if k not in allowed},
              'consent changed tables/schema/version outside declared writes')
    check(after[0][1:] == before[0][1:], 'consent wrote durable state/home files')
    check(traffic(f) == counters, 'local consent performed TCP/UDP IO')
    return after


def ordinary_body(f, inspected, *, approve=False):
    review = inspected['review']
    return {'code': f['reply'], 'network_id': f['network']['id'], 'person_public_key': f['person'],
        'provider_id': review['provider_id'], 'signature_format': review['signature_format'], 'scopes': 7,
        'not_after': review['not_after'], 'expected_host_public_key': f['b'].public_key,
        'expected_device_public_key': review['device_public_key'], 'approve': approve}


def cancel(f):
    status, result = f['a'].api('POST', '/v2/link/requests/' + f['rid'] + '/cancel', {})
    check(status == 200 and result['state'] == 'cancelled', f'ordinary cancellation HTTP {status}')
    quiet(f)


def consent_world(name='main'):
    f = world(name)
    if 'public_network' not in f:
        f['public_network'] = get(f['a'], '/v2/networks/' + f['network']['id'])
        record, _ = pending(f['a'], f['rid'])
        start = record.get('stage_at', '-')
        if start == '-':
            start = link_view(f['a'], f['rid'])['created_at']
        f['stage_deadline'] = rfc3339(parse_time(start) + timedelta(seconds=600))
        original(f)
    return f


def held_transport(f):
    relays = (f['a'].relay, f['b'].relay)
    for relay in relays:
        relay.refresh_hold()
    held = wait_for(lambda: [(relay, n) for relay in relays for n in relay.live_generations()] or None,
        timeout=5, interval=.02, message='actual approved transport dispatch held outside database')
    def guard():
        check(all(relay.mode == 'hold' and n in relay.live_generations() for relay, n in held),
              'confirmed current transport hold ended during pure observation')
    return guard


def kind_ids(h, kind):
    with closing(sqlite3.connect(f'file:{db_path(h)}?mode=ro', uri=True)) as db:
        return {row[0] for row in db.execute('SELECT intent_id FROM dec_intents WHERE kind=?', (kind,))}


def ssh_string(value):
    return struct.pack(">I", len(value)) + value


def ssh_read_string(value, offset=0):
    size = struct.unpack(">I", value[offset:offset + 4])[0]
    end = offset + 4 + size
    check(end <= len(value), "bounded SSH-agent fixture packet")
    return value[offset + 4:end], end


def read_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise EOFError
        data.extend(chunk)
    return bytes(data)


def agent_packet(stream):
    size = struct.unpack(">I", read_exact(stream, 4))[0]
    if not 0 < size <= 1024 * 1024:
        raise ValueError("agent fixture packet bound")
    return read_exact(stream, size)


def sshsig_preimage(message):
    return b"SSHSIG" + ssh_string(b"peerspan-person-v1") + ssh_string(b"") + ssh_string(b"sha512") + ssh_string(hashlib.sha512(message).digest())


class AgentProxy:
    """Forward the real agent; controlled holds/faults never create valid rows."""
    def __init__(self, path, upstream, wrong_key):
        self.path, self.upstream, self.wrong_key = path, upstream, wrong_key
        self.lock, self.seen, self.release = threading.Lock(), threading.Event(), threading.Event()
        self.mode, self.expected_message = "reject_all", b""
        self.requests = []
        outer = self

        class Server(socketserver.ThreadingUnixStreamServer):
            daemon_threads = True

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream_socket:
                        upstream_socket.settimeout(5)
                        upstream_socket.connect(str(outer.upstream))
                        while True:
                            packet = agent_packet(self.request)
                            kind, key, message, flags = packet[0], b"", b"", 0
                            if kind == 13:  # SSH2_AGENTC_SIGN_REQUEST
                                key, offset = ssh_read_string(packet, 1)
                                message, offset = ssh_read_string(packet, offset)
                                flags = struct.unpack(">I", packet[offset:offset + 4])[0]
                            with outer.lock:
                                mode = outer.mode
                                outer.requests.append((kind, key, message, flags))
                            if mode == "reject_all":
                                self.request.sendall(ssh_string(b"\x05"))
                                continue
                            forwarded = packet
                            if kind == 13 and mode in {"wrong_key", "wrong_role", "wrong_message"}:
                                if mode == "wrong_key":
                                    key = outer.wrong_key
                                elif mode == "wrong_role":
                                    message = sshsig_preimage(outer.expected_message.replace(b"\nissuer\n", b"\nhost\n"))
                                else:
                                    message = message[:-1] + bytes([message[-1] ^ 1])
                                forwarded = bytes([kind]) + ssh_string(key) + ssh_string(message) + struct.pack(">I", flags)
                            upstream_socket.sendall(ssh_string(forwarded))
                            reply = agent_packet(upstream_socket)
                            if (kind == 11 and mode == "hold_lookup") or (kind == 13 and mode == "hold_signature"):
                                outer.seen.set()
                                if not outer.release.wait(timeout=10):
                                    return
                            if kind == 13 and mode in {"wrong_format", "wrong_signature"} and reply[0] == 14:
                                signature, _ = ssh_read_string(reply, 1)
                                algorithm, offset = ssh_read_string(signature)
                                signature, _ = ssh_read_string(signature, offset)
                                if mode == "wrong_format":
                                    algorithm = b"ssh-rsa"
                                else:
                                    signature = signature[:-1] + bytes([signature[-1] ^ 1])
                                reply = b"\x0e" + ssh_string(ssh_string(algorithm) + ssh_string(signature))
                            self.request.sendall(ssh_string(reply))
                except (OSError, EOFError, ValueError):
                    pass

        self.server = Server(str(path), Handler)
        path.chmod(0o600)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .02}, daemon=True)
        self.thread.start()
        atexit.register(self.close)

    def configure(self, mode, message=b""):
        with self.lock:
            self.mode, self.expected_message = mode, message
        self.seen.clear(); self.release.clear()

    def captured(self):
        with self.lock:
            return tuple(self.requests)

    def counts(self):
        captured = self.captured()
        return len(captured), sum(entry[0] == 11 for entry in captured), sum(entry[0] == 13 for entry in captured)

    def close(self):
        self.release.set()
        self.server.shutdown(); self.server.server_close()
        self.thread.join(timeout=1)
        self.path.unlink(missing_ok=True)


SIGNING = set('state intent_id proposed_owner_offer_id signature_count required_signatures can_sign next_action owner_offer_publication host_admission machine_powers requester_selection request_commit agent_access connection_readiness'.split())
SIGN_DECISION = 'sign_machine_owner_offer'


def configured_file(f):
    return f['a'].root / 'absent-person-key'


def configure_agent(f, mode='reject_all'):
    if 'agent' in f:
        f['agent'].configure(mode)
        return f['agent']
    h = f['a']; upstream, exposed = h.root / 'up', h.root / 'absent-agent.sock'
    check(len(str(exposed).encode()) < 104, 'short private agent socket prerequisite')
    wrong = ssh_key(suite.work, h.name + '-other-original')
    suite.spawn(['ssh-agent', '-D', '-a', str(upstream)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_for(upstream.exists, timeout=3, interval=.05, message='genuine agent socket')
    for key in (wrong, f['key']):
        result = subprocess.run(['ssh-add', str(key)], env={**h.env, 'SSH_AUTH_SOCK': str(upstream)}, capture_output=True, timeout=5)
        check(result.returncode == 0, 'multi-identity genuine agent setup')
    listed = subprocess.run(['ssh-add', '-L'], env={**h.env, 'SSH_AUTH_SOCK': str(upstream)}, capture_output=True, timeout=5)
    check(listed.returncode == 0 and len(listed.stdout.splitlines()) == 2 and ssh_public_base64(wrong) != f['person'], 'agent needs two actual distinct identities')
    proxy = AgentProxy(exposed, upstream, base64.b64decode(Path(str(wrong) + '.pub').read_text().split()[1]))
    proxy.upstream = upstream; proxy.configure(mode); f['agent'] = proxy
    return proxy


def prepared_fixture(name):
    f = consent_world(name)
    if 'prepared' not in f:
        inspected = standalone(f)
        value = op(f, 'prepare', inspected=inspected)
        check(value['consent']['state'] == 'review', 'genuine guided unsigned preparation prerequisite')
        f['prepared'] = value
    return f


def approve_and_hold(f):
    for relay in (f['a'].relay, f['b'].relay):
        relay.refresh_hold()
    f['approved'] = op(f, 'approve', f['prepared'])
    check(f['approved']['consent']['state'] == 'approved', 'actual GUIDED dual approval prerequisite')
    both = dual_records(f['a'], f['approved']['consent'])
    check(both[0]['approved'] is both[1]['approved'] is True and both[0]['approved_at'] == both[1]['approved_at'], 'guided dual flags/time disagree')
    guard = held_transport(f)
    quiet(f); guard()
    return guard


def signing_input(f, *, sign=False, prepared=None):
    value = prepared or f['prepared']
    data = {**input_for(f, 'approve', value)}
    if sign:
        data['decision'] = SIGN_DECISION
    return data


def initial_plan(f):
    consent = f['prepared']['consent']; review = consent['review']; owner = intent(f['a'], review['intent_id'])['record']
    frozen = review['inspection']; provider = owner['provider']; plan = {}
    packets = [t for t in owner['templates'] if t['object_type'] == 'owner_offer_packet']
    folds = [t for t in owner['templates'] if t['object_type'] == 'host_lease']
    check(len(packets) == 1 and packets[0]['slot_id'] == 1 and len(folds) <= 1, 'finite typed first owner/fold plan')
    packet = json.loads(base64.b64decode(packets[0]['template_base64'], validate=True))
    offer = json.loads(base64.b64decode(packet['payload_base64'], validate=True))
    check(packet_id(packet) == review['proposed_owner_offer_id'] and packet['request_id'] == f['rid']
          and packet['writer_host_public_key'] == f['a'].public_key and packet['signer_public_key'] == provider['signer_public_key']
          and packet['authority_signature_format'] == provider['signature_format'], 'actual typed packet/provider identity')
    check(offer['request_packet_id'] == review['request_packet_id'] and offer['root_state_id'] == frozen['root_state_id']
          and offer['person_lease_id'] == frozen['person_lease_id'] and offer['scopes'] == 7
          and offer['not_after'] == frozen['not_after'] and offer['member'] == frozen['member']
          and offer['host_public_key'] == f['b'].public_key and offer['device_public_key'] == frozen['device_public_key'], 'exact finite owner offer target/parents')
    with closing(sqlite3.connect(f'file:{db_path(f["a"])}?mode=ro', uri=True)) as db:
        network = json.loads(db.execute('SELECT record FROM networks WHERE id=?', (f['network']['id'],)).fetchone()[0])
    check(offer['descriptor'] == json.loads(base64.b64decode(network['descriptor_base64'], validate=True)), 'owner offer changed genuine descriptor')
    plan[(1, 'host')] = ('ed25519', f['a'].public_key, packet_message(packet))
    plan[(1, 'authority')] = (provider['signature_format'], provider['signer_public_key'], packet_message(packet))
    for fold in folds:
        envelope = json.loads(base64.b64decode(fold['template_base64'], validate=True))
        payload_bytes = base64.b64decode(envelope['payload_base64'], validate=True); body = json.loads(payload_bytes)
        statement = 'ds_' + hashlib.sha256('\n'.join(('peerspan-decentralized-statement-v1', 'host_lease',
            envelope['context_id'], hashlib.sha256(payload_bytes).hexdigest())).encode()).hexdigest()
        check(envelope['kind'] == 'host_lease' and envelope['context_id'] == f['network']['context_id']
              and envelope['signatures'] == [{'role': 'issuer', 'public_key': provider['signer_public_key'],
                  'format': provider['signature_format'], 'signature': '-'}], 'fold is not the same exact configured issuer')
        check(body['operation_id'] == f['rid'] and body['root_state_id'] == frozen['root_state_id']
              and body['subject']['host_public_key'] == f['b'].public_key and body['subject']['scopes'] == 0
              and body['not_after'] == frozen['not_after'], 'fold changed request/root/target/finite powers')
        message = '\n'.join(('peerspan-decentralized-signature-v1', statement, 'issuer', provider['signer_public_key'])).encode()
        plan[(fold['slot_id'], 'issuer')] = (provider['signature_format'], provider['signer_public_key'], message)
    check(len(plan) in (2, 3) and (len(folds) == 1) == (frozen['host_admission'] == 'owner_may_fold'), 'actual fold presence differs from frozen reviewed potential')
    return owner, packet, plan


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


def validate_signing(f, value):
    check(type(value) is dict and set(value) == TOP | {'signing'}, 'closed section43 eight-field wrapper')
    validate(f, {k: v for k, v in value.items() if k != 'signing'})
    check(core(value['consent']) == core(f['prepared']['consent']), 'signing changed complete immutable receipt/digest')
    records_now = dual_records(f['a'], value['consent'])
    if not all(r['approved'] for r in records_now):
        check(value['signing'] is None, 'unapproved/one-interface approval became signature evidence')
        return
    owner, packet, plan = initial_plan(f)
    signatures = {(s['slot_id'], s['role']): s for s in owner['signatures'] if (s['slot_id'], s['role']) in plan}
    check(len(signatures) == sum((s['slot_id'], s['role']) in plan for s in owner['signatures']), 'duplicate counted initial roles')
    count, required = len(signatures), len(plan)
    signing = value['signing']
    check(type(signing) is dict and set(signing) == SIGNING and type(signing['signature_count']) is type(signing['required_signatures']) is int
          and signing['signature_count'] == count and signing['required_signatures'] == required
          and type(signing['can_sign']) is bool, 'closed exact actual signature count/type')
    expected_state = 'unsigned' if count == 0 else 'signed' if count == required else 'partial'
    check(signing['state'] == expected_state and signing['intent_id'] == value['consent']['review']['intent_id']
          and signing['proposed_owner_offer_id'] == packet_id(packet), 'marker detached from exact first/fold typed plan')
    check(signing['next_action'] == ('follow_machine_link' if count == required else SIGN_DECISION if signing['can_sign'] else 'inspect_machine_link'), 'marker offered wrong next action')
    check(all(signing[key] == 'not_verified' for key in ('owner_offer_publication', 'host_admission', 'machine_powers',
          'requester_selection', 'request_commit', 'agent_access', 'connection_readiness')), 'signature evidence claimed delivery/admission/powers/readiness')
    if count == required:
        check(signing['can_sign'] is False, 'complete initial plan still offers fresh signing')
    if (1, 'host') in signatures and (1, 'authority') in signatures:
        record, _ = pending(f['a'], f['rid'])
        assembled = json.loads(base64.b64decode(record['owner_packet_base64'], validate=True))
        check(record['owner_offer_id'] == packet_id(packet) == packet_id(assembled)
              and unchanged_except(packet, assembled, 'host_signature', 'authority_signature')
              and assembled['host_signature'] == signatures[(1, 'host')]['signature']
              and assembled['authority_signature'] == signatures[(1, 'authority')]['signature'], 'complete marker lacks exact assembled ordinary pending packet/ID')
    check(len(compact(value)) <= 2 * 1024 * 1024, 'signing public response exceeds bound')
    public(value, *f['secrets'])


def signing_op(f, action, *, status=200, code=None, override=None, cli=False):
    h = f['a']; data = override if override is not None else signing_input(f, sign=action == 'sign')
    if cli:
        result = h.cli('onboarding', 'machine', action, '--stdin', input=compact(data).decode(), timeout=100 if action == 'sign' else 8)
        check(result.ok == (status == 200), 'private signing CLI outcome mismatch')
        value = result.json
        public(result.stderr, str(h.root), *f['secrets'])
        if not result.ok:
            public(result.stdout, str(h.root), *data['context'].values(), *f['secrets'])
    else:
        actual, value = h.api('POST', BASE + '/' + action, data, timeout=95 if action == 'sign' else 8)
        if actual != status or (code and (type(value) is not dict or value.get('code') != code)):
            allowed = {'invalid', 'not_found', 'review_changed', 'review_expired', 'machine_owner_signing_unavailable'}
            actual_code = value.get('code') if type(value) is dict else None
            print('machine_signing_failure_public=' + json.dumps({'operation': action,
                'http_status': actual, 'expected_status': status,
                'actual_code': actual_code if isinstance(actual_code, str) and actual_code in allowed else 'unknown',
                'expected_code': code if code in allowed else 'unknown'}, sort_keys=True), flush=True)
        check(actual == status, f'machine {action} HTTP {actual}, expected {status}')
        if code:
            check(type(value) is dict and value.get('code') == code, 'controlled machine signing refusal code mismatch')
    if status == 200:
        validate_signing(f, value)
    else:
        public(value, str(h.root), *[v for k, v in data['context'].items() if k != 'integration'], *f['secrets'])
    return value


def pure_signing(f, action='signing', *, guard=None, allow_agent=False, **kwargs):
    quiet(f)
    if guard:
        guard()
    before, counters = whole(f), traffic(f)
    agent_before = f['agent'].counts() if 'agent' in f else None
    key_before = files(configured_file(f))
    value = signing_op(f, action, **kwargs)
    strict(whole(f), before, traffic(f), counters, 'pure-' + action)
    check(files(configured_file(f)) == key_before, 'pure signing operation wrote configured source')
    if agent_before is not None and not allow_agent:
        check(f['agent'].counts() == agent_before, 'pure signing lookup/replay/refusal contacted agent')
    if guard:
        guard()
    return value


def sign_and_verify(f, guard, *, cli=False):
    guard(); quiet(f); guard()
    before, counters = whole(f), traffic(f)
    receipt = intent(f['a'], f['prepared']['consent']['consent_id'])
    owner, packet, plan = initial_plan(f); key_before = files(configured_file(f))
    pending_before, _ = pending(f['a'], f['rid'])
    value = signing_op(f, 'sign', cli=cli); guard()
    check(value['signing']['state'] == 'signed' and len(plan) == 3, 'positive does not prove actual reviewed first+fold signature set')
    after_owner, _, after_plan = initial_plan(f)
    check(after_plan == plan and unchanged_except(owner, after_owner, 'signatures', 'completed')
          and intent(f['a'], f['prepared']['consent']['consent_id']) == receipt, 'signing changed immutable template/approval/review/window')
    allowed_write(f, before, counters, {'dec_intents', 'dec_pending', 'dec_clock'})
    check(files(configured_file(f)) == key_before, 'signing created/replaced configured source')
    for index, sig in enumerate(after_owner['signatures']):
        role = sig['slot_id'], sig['role']
        if role in plan:
            fmt, key, message = plan[role]
            verify_signature(fmt, key, sig['signature'], message, f['a'].name + '-initial-' + str(index))
    record, _ = pending(f['a'], f['rid'])
    check(record['outbound_frames'] == pending_before['outbound_frames'], 'explicit signature storage queued publication frames')
    check(record['catalog_base64'] != '-' and json.loads(base64.b64decode(record['catalog_base64'], validate=True))['objects'], 'complete owner packet lost current public owner proof catalog')
    request = link_view(f['a'], f['rid'])
    check(not request['selection_approved'] and not request['commit_approved'] and request['selection_id'] == request['owner_finalization_id'] == request['manifest_id'] == '-', 'initial signing supplied later requester/F/commit consent')
    f['signed'] = value
    return value


def release_worker(f):
    for relay in (f['a'].relay, f['b'].relay):
        relay.mode = 'pass'


def signature_fault(f, guard):
    h = f['a']; iid = f['prepared']['consent']['review']['intent_id']; rid = f['rid']
    owner, _, plan = initial_plan(f); required = len(plan)
    check(len([s for s in owner['signatures'] if (s['slot_id'], s['role']) in plan]) < required, 'SQL fault requires genuinely incomplete first plan')
    target = max(h.now(), f['b'].now()) + timedelta(seconds=2)
    check(target < parse_time(f['prepared']['consent']['review']['expires_at']), 'atomic fault exhausted original consent')
    advance_to(h, target); guard()
    with closing(sqlite3.connect(f'file:{db_path(h)}?mode=ro', uri=True)) as db:
        clock_before = db.execute('SELECT record FROM dec_clock').fetchone()[0]
    # No write order is assumed. The last of the three genuine record updates
    # trips ABORT only after every intended piece is visible inside that TX.
    predicate = (f"(SELECT json_array_length(json_extract(record,'$.signatures')) FROM dec_intents WHERE intent_id='{iid}')>={required} "
        f"AND (SELECT json_extract(record,'$.owner_offer_id') FROM dec_pending WHERE request_id='{rid}')!='-' "
        "AND EXISTS(SELECT 1 FROM dec_clock WHERE record!=" + "'" + clock_before.replace("'", "''") + "')")
    schema_before = records(h)
    with closing(sqlite3.connect(db_path(h))) as db, db:
        for table in ('dec_intents', 'dec_pending', 'dec_clock'):
            db.execute('CREATE TRIGGER machine_sign_abort_' + table + ' AFTER UPDATE OF record ON ' + table +
                ' WHEN ' + predicate + " BEGIN SELECT RAISE(ABORT,'PRIVATE_MACHINE_SIGN_ABORT'); END")
    try:
        guard(); before, counters = whole(f), traffic(f)
        status, denied = h.api('POST', BASE + '/sign', signing_input(f, sign=True), timeout=95)
        check(not 200 <= status < 300, 'late actual signature/pending/clock ABORT succeeded')
        public(denied, 'PRIVATE_MACHINE_SIGN_ABORT', *f['secrets'])
        guard(); strict(whole(f), before, traffic(f), counters, 'whole-signature-batch-fault')
    finally:
        with closing(sqlite3.connect(db_path(h))) as db, db:
            for table in ('dec_intents', 'dec_pending', 'dec_clock'):
                db.execute('DROP TRIGGER machine_sign_abort_' + table)
    check(records(h) == schema_before, 'signature fault left schema/signatures/pending/catalog/clock change')


@suite.case('unapproved_private_signing_is_pure_and_never_contacts_configured_agent', 'guided43 verification1')
def _():
    f = prepared_fixture('file'); agent = configure_agent(f)
    owner, _, plan = initial_plan(f)
    check(len(plan) == 3 and owner['signatures'] == [] and owner['approved'] is False, 'actual unapproved creator first+fold prerequisite')
    for cli in (False, True):
        value = pure_signing(f, cli=cli)
        check(value['signing'] is None and value['consent']['state'] == 'review', 'unapproved lookup fabricated signing evidence')
        pure_signing(f, 'sign', cli=cli, status=409, code='machine_owner_signing_unavailable')
    check(agent.counts() == (0, 0, 0), 'unapproved signing/lookup probed configured identity or signed')
    agent.close()


@suite.case('configured_safe_original_file_finite_typed_batch_and_late_atomic_abort', 'guided43 verification2/5')
def _():
    f = prepared_fixture('file'); h = f['a']; guard = approve_and_hold(f)
    observed = pure_signing(f, guard=guard)
    check(observed['signing']['can_sign'] is True and observed['signing']['state'] in ('unsigned', 'partial'), 'lookup used absent signer availability as public eligibility')
    path = configured_file(f)
    wrong = ssh_key(suite.work, 'wrong-file-original')
    for mode in ('missing', 'symlink', 'directory', 'fifo', 'permissive', 'oversize', 'malformed', 'wrong'):
        if path.is_symlink() or path.exists():
            if path.is_dir() and not path.is_symlink():
                path.rmdir()
            else:
                path.unlink()
        if mode == 'symlink':
            path.symlink_to(f['key'])
        elif mode == 'directory':
            path.mkdir(mode=0o700)
        elif mode == 'fifo':
            os.mkfifo(path, 0o600)
        elif mode != 'missing':
            if mode in ('permissive', 'wrong'):
                shutil.copyfile(wrong if mode == 'wrong' else f['key'], path)
            else:
                path.write_bytes(b'x' * 16385 if mode == 'oversize' else b'PRIVATE_MACHINE_BAD_KEY')
            path.chmod(0o644 if mode == 'permissive' else 0o600)
        guard = held_transport(f)
        pure_signing(f, 'sign', guard=guard, status=409, code='machine_owner_signing_unavailable')
    guard = held_transport(f)
    path.unlink(); shutil.copyfile(f['key'], path); path.chmod(0o600); guard()
    signature_fault(f, guard)
    sign_and_verify(f, guard)
    # Neither explicit signature storage nor host-owned authorized work implies
    # that the other person has selected an offer or committed their device.
    cancel(f); release_worker(f)


@suite.case('real_multi_identity_agent_exact_messages_failures_and_dispatch_pin_changes', 'guided43 verification3')
def _():
    f = prepared_fixture('agent'); guard = approve_and_hold(f); agent = configure_agent(f)
    _, _, plan = initial_plan(f)
    expected_key = ssh_string(b'ssh-ed25519') + ssh_string(base64.b64decode(f['person'], validate=True))
    expected_messages = {sshsig_preimage(message) for fmt, _, message in plan.values() if fmt == 'sshsig'}
    for mode in ('reject_all', 'wrong_format', 'wrong_signature'):
        guard = held_transport(f); agent.configure(mode)
        before = agent.counts()
        pure_signing(f, 'sign', guard=guard, allow_agent=True, status=409, code='machine_owner_signing_unavailable')
        check(agent.counts()[2] - before[2] <= 2, 'failed finite action retried key use beyond reviewed authority/fold roles')
    removed = subprocess.run(['ssh-add', '-d', str(f['key'])], env={**f['a'].env, 'SSH_AUTH_SOCK': str(agent.upstream)}, capture_output=True, timeout=5)
    check(removed.returncode == 0, 'remove only exact agent identity prerequisite')
    guard = held_transport(f); agent.configure('pass')
    pure_signing(f, 'sign', guard=guard, allow_agent=True, status=409, code='machine_owner_signing_unavailable')
    restored = subprocess.run(['ssh-add', str(f['key'])], env={**f['a'].env, 'SSH_AUTH_SOCK': str(agent.upstream)}, capture_output=True, timeout=5)
    check(restored.returncode == 0, 'restore exact real agent identity after negative fixture')
    guard = held_transport(f); agent.configure('hold_lookup'); quiet(f); guard()
    before, counters = whole(f), traffic(f); signatures = intent(f['a'], f['prepared']['consent']['review']['intent_id'])['record']['signatures']
    box = {}
    def delayed_lookup():
        box['result'] = f['a'].api('POST', BASE + '/sign', signing_input(f, sign=True), timeout=95)
    thread = threading.Thread(target=delayed_lookup, daemon=True); thread.start()
    check(agent.seen.wait(5), 'actual agent identity reply dispatch barrier not reached')
    select_provider(f, f['device']['lease_id'])
    # Establish expected public mutation before releasing the captured key
    # lookup, so strict comparison attributes no provider-selection write to Sign.
    changed, changed_counts = whole(f), traffic(f)
    sign_count = agent.counts()[2]; agent.release.set(); thread.join(8)
    check(not thread.is_alive() and box['result'][0] == 409 and box['result'][1].get('code') == 'review_changed', 'changed selected provider after identity lookup persisted signing')
    guard(); strict(whole(f), changed, traffic(f), changed_counts, 'identity-postlookup-refusal')
    check(agent.counts()[2] == sign_count and intent(f['a'], f['prepared']['consent']['review']['intent_id'])['record']['signatures'] == signatures,
          'changed identity boundary dispatched a key or persisted a batch')
    agent.configure('reject_all'); select_provider(f, f['person'])
    guard = held_transport(f); agent.configure('pass')
    sign_and_verify(f, guard, cli=True)
    requests = [request for request in agent.captured() if request[0] == 13]
    check(requests and all(key == expected_key and message in expected_messages and flags == 0 for _, key, message, flags in requests),
          'agent received an alternate identity/arbitrary message or signature flags')
    cancel(f); release_worker(f)
    # Separate unsigned receipt isolates a real already-dispatched key result
    # after parent loss. It never rebinds an old approved receipt to a new parent.
    race = prepared_fixture('race'); guard = approve_and_hold(race); proxy = configure_agent(race)
    guard = held_transport(race); proxy.configure('hold_signature'); quiet(race); guard()
    box = {}
    def delayed_signature():
        box['result'] = race['a'].api('POST', BASE + '/sign', signing_input(race, sign=True), timeout=95)
    thread = threading.Thread(target=delayed_signature, daemon=True); thread.start()
    check(proxy.seen.wait(5), 'actual completed real-agent key operation barrier not reached')
    race['a'].ok('session', 'detach', race['parent']['review']['session_id'])
    changed, changed_counts = whole(race), traffic(race)
    proxy.release.set(); thread.join(8)
    check(not thread.is_alive() and box['result'][0] == 409 and box['result'][1].get('code') == 'review_changed', 'late key result survived parent loss')
    guard(); strict(whole(race), changed, traffic(race), changed_counts, 'key-result-parent-loss')
    cancel(race); release_worker(race)


@suite.case('guided_dual_approved_device15_exact_ed25519_set_then_ordinary_publication', 'guided43 verification4')
def _():
    f = consent_world('device'); select_provider(f, f['device']['lease_id'])
    inspected = standalone(f); f['prepared'] = op(f, 'prepare', inspected=inspected)
    check(f['prepared']['consent']['review']['inspection']['provider']['kind'] == 'device'
          and f['prepared']['consent']['review']['effects']['authorize_host_admission_if_folded'] is True, 'actual selected creator device15/fold receipt')
    guard = approve_and_hold(f)
    owner, _, plan = initial_plan(f)
    check(len(plan) == 3 and all(fmt == 'ed25519' for fmt, _, _ in plan.values()), 'genuine device first+fold typed slots absent')
    signed = sign_and_verify(f, guard)
    iid = signed['signing']['intent_id']; packet_ref = signed['signing']['proposed_owner_offer_id']
    release_worker(f)
    # One explicit ordinary read driver after release may observe automatic
    # publication; it is not supplied as hidden resume/sign/F work by this API.
    def published():
        record, _ = pending(f['a'], f['rid'])
        return record if any(frame['role'] == 'owner' for frame in record['outbound_frames']) else None
    current = wait_for(published, timeout=10, interval=.1, message='actual ordinary owner frame retention after held guided device approval')
    check(current['owner_intent_id'] == iid and current['owner_offer_id'] == packet_ref and current['catalog_base64'] != '-', 'ordinary publication lost exact intent/owner/catalog')
    catalog = json.loads(base64.b64decode(current['catalog_base64'], validate=True))
    check(catalog['context_id'] == f['network']['context_id'] and catalog['objects'], 'ordinary publication lacks retained verified owner proof catalog')
    for item in catalog['objects']:
        raw = base64.b64decode(item['body_base64'], validate=True)
        expected = 'dp_' + hashlib.sha256('\n'.join(('peerspan-decentralized-proof-v1', item['kind'], hashlib.sha256(raw).hexdigest())).encode()).hexdigest()
        check(item['id'] == expected, 'published owner catalog lost exact proof bytes')
    f['b'].start()
    # One separate ordinary requester driver may fetch the already published
    # material; it supplies no original signer or selection/commit permission.
    f['b'].cli('link', 'resume', f['rid'], timeout=15)
    def received():
        record, _ = pending(f['b'], f['rid'])
        return record if record['owner_packet_base64'] != '-' and record['catalog_base64'] != '-' else None
    remote = wait_for(received, timeout=10, interval=.1, message='actual requester retained published owner and public proofs')
    check(remote['owner_offer_id'] == packet_ref and json.loads(base64.b64decode(remote['catalog_base64'], validate=True))['objects'],
          'receiver did not retain the same owner and actual published proof catalog')
    request = link_view(f['a'], f['rid'])
    check(request['selection_id'] == request['owner_finalization_id'] == request['manifest_id'] == '-'
          and not request['selection_approved'] and not request['commit_approved'], 'guided device offer performed later requester/F/commit work')
    f['b'].stop(); cancel(f)


@suite.case('fresh_fixed_expiry_and_keyless_signed_history_after_cancel_provider_detach_restart', 'guided43 verification5')
def _():
    expired = prepared_fixture('time'); guard = approve_and_hold(expired)
    target = parse_time(expired['prepared']['consent']['review']['expires_at']) + timedelta(seconds=1)
    check(target < parse_time(expired['prepared']['request']['expires_at']), 'fixed expiry stimulus exhausted signed request instead')
    advance_to(expired['a'], target)
    expired_view = pure_signing(expired, guard=guard)
    check(expired_view['signing']['can_sign'] is False and expired_view['signing']['state'] != 'signed', 'expired fresh action remained enabled')
    pure_signing(expired, 'sign', guard=guard, status=409, code='review_expired')
    cancel(expired); release_worker(expired)
    f = prepared_fixture('file'); h = f['a']; exact = f['signed']; old_parent = f['parent']
    # A deliberately unusable configured copy makes any unexpected new key
    # resolution observable, without deleting protocol/authority or original key.
    configured_file(f).write_text('PRIVATE_HISTORY_NO_SIGNER'); configured_file(f).chmod(0o600)
    select_provider(f, f['device']['lease_id'])
    h.ok('session', 'detach', old_parent['review']['session_id'])
    h.restart(kill=True)
    check(get(h, PROJECT + '/' + old_parent['flow_id'])['state'] == 'invalidated', 'ordinary restart did not detach old parent')
    for local in (h, f['b']):
        advance_to(local, parse_time(f['prepared']['request']['expires_at']) + timedelta(seconds=1))
    quiet(f); receipt = intent(h, f['prepared']['consent']['consent_id']); owner = intent(h, f['prepared']['consent']['review']['intent_id'])
    for action in ('signing', 'sign'):
        for cli in (False, True):
            view = pure_signing(f, action, cli=cli)
            check(view['signing'] == exact['signing'] and core(view['consent']) == core(exact['consent']), 'signed historical API/CLI replay lost exact initial evidence')
    check(intent(h, f['prepared']['consent']['consent_id']) == receipt and intent(h, f['prepared']['consent']['review']['intent_id']) == owner,
          'history rewrote exact signatures/templates/approvals/window')
    wrong = {**signing_input(f, sign=True), 'context': {**context(old_parent), 'native_session_id': 'different-machine-conversation'}}
    pure_signing(f, 'sign', override=wrong, status=409, code='review_changed')
    pure_signing(f, override={**signing_input(f), 'consent_review_id': 'review_' + 'a' * 64}, status=409, code='review_changed')
    print('LIMIT machine_owner_signing: no separate-admin2-slot/full later B-D-F ceremony, exact90s cutoff, private syscall counts, complex authority/quota/corruption or microscopic dispatch/commit attribution', flush=True)


@suite.case('strict_private_json_decision_id_bounds_no_startup_and_owner_router_isolation', 'guided43 verification6')
def _():
    f = prepared_fixture('file'); h = f['a']
    for action in ('signing', 'sign'):
        data = signing_input(f, sign=action == 'sign'); raw = compact(data); maximum = raw + b' ' * (65536 - len(raw))
        quiet(f); before, counters = whole(f), traffic(f)
        status, value = raw_post(h, action, maximum)
        check(status == 200, f'exact64KiB {action} HTTP {status}'); validate_signing(f, value)
        result = h.cli('onboarding', 'machine', action, '--stdin', input=maximum.decode(), timeout=100 if action == 'sign' else 8)
        check(result.ok and result.json['signing'] == value['signing'], 'exact64KiB private CLI parity')
        malformed = [b'null', b'[]', b'{', raw + b'{}', maximum + b' ',
            raw.replace(b'"request_id":', b'"request_id":"link_' + b'0' * 64 + b'","request_id":'),
            raw.replace(b'"integration":"claude-code"', b'"integration":"claude-code","integration":"claude-code"'),
            compact({**data, 'extra': 'PRIVATE_SIGN_MACHINE'}),
            compact({**data, 'context': {**data['context'], 'extra': 'PRIVATE_SIGN_MACHINE'}})]
        malformed += [compact({**data, key: 'PRIVATE_SIGN_MACHINE'}) for key in ('provider_id', 'person_key_file', 'message_base64')]
        for key in data:
            malformed += [compact({k: v for k, v in data.items() if k != key}), compact({**data, key: None})]
        for key in ('request_id', 'consent_id', 'consent_review_id'):
            malformed += [compact({**data, key: 'PRIVATE_BAD_ID'})]
        malformed += [compact({**data, 'decision': value}) for value in (True, 'approve', 'PRIVATE_SIGN_MACHINE')]
        for index, bad in enumerate(malformed):
            status, denied = raw_post(h, action, bad)
            check(status == 400 and type(denied) is dict and denied.get('code') == 'invalid', f'{action} malformed{index} HTTP {status}')
            result = h.cli('onboarding', 'machine', action, '--stdin', input=bad.decode(), timeout=100 if action == 'sign' else 8)
            check(not result.ok, 'CLI accepted malformed machine signing input')
            public(denied, 'PRIVATE_SIGN_MACHINE', 'PRIVATE_BAD_ID', *f['secrets'])
            public(result.stdout + result.stderr, 'PRIVATE_SIGN_MACHINE', 'PRIVATE_BAD_ID', str(h.state), *f['secrets'])
        strict(whole(f), before, traffic(f), counters, action + '-private-input')
        for args in (('onboarding', 'machine', action), ('onboarding', 'machine', action, f['rid'], '--stdin'),
                     ('onboarding', 'machine', action, '--PRIVATE_SIGN_MACHINE=/private/owner', '--stdin')):
            result = h.cli(*args, input=raw.decode(), timeout=8)
            check(not result.ok, 'signing CLI accepted missing stdin/private positional option')
            public(result.stdout + result.stderr, f['rid'], 'PRIVATE_SIGN_MACHINE', '/private/owner', str(h.state))
        missing = suite.host('n' + action, start=False); prior = files(missing.root)
        result = missing.cli('onboarding', 'machine', action, '--stdin', input=raw.decode(), timeout=8)
        check(not result.ok and files(missing.root) == prior, 'missing daemon operation initialized state or started service')
        public(result.stdout + result.stderr, str(missing.root), *f['secrets'])
    parent = project(h, 'routers')
    credential = h.ok('adapter', 'create', '--session', parent['review']['session_id'], '--expires-at', rfc3339(h.now() + timedelta(hours=1)))
    adapter = Adapter(h, parent['review']['agent'], parent['review']['session_id'], credential)
    status, _ = adapter.call('POST', '/adapter/v1/connect', {'adapter_id': adapter.adapter_id, 'session_id': adapter.session_id, 'instance_id': adapter.instance})
    check(status == 200, 'scoped router genuine connection prerequisite')
    peer, bootstrap = host('p'), host('z')
    for local, remote in ((h, peer), (peer, h)):
        local.ok('peer', 'add', '--id', remote.id, '--public-key', remote.public_key, '--address', remote.counted_peer.address)
    cert, key = suite.work / 'router.pem', suite.work / 'router-key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ed25519', '-nodes', '-subj', '/CN=machine-sign-router', '-days', '1',
        '-keyout', str(key), '-out', str(cert)], capture_output=True, check=True, timeout=5)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); tls.check_hostname = False; tls.verify_mode = ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key)); tls.set_alpn_protocols(['peerspan-bootstrap/1'])
    for action in ('signing', 'sign'):
        path = BASE + '/' + action; data = signing_input(f, sign=action == 'sign')
        status, denied = adapter.call('POST', path, data)
        check(status == 404, f'adapter exposed private owner signing HTTP {status}'); public(denied, adapter.token)
        result = subprocess.run([str(suite.probe_bin), '--state', str(peer.state), '--address', h.counted_peer.address,
            '--alpn', 'peerspan-peer/1', '--method', 'POST', '--path', path, '--body-stdin'], input=compact(data), capture_output=True, timeout=10)
        check(result.returncode == 0 and json.loads(result.stdout)['status'] == 404, 'authenticated peer exposed private signing')
        with socket.create_connection(('127.0.0.1', int(bootstrap.relay.address.rsplit(':', 1)[1])), timeout=5) as raw:
            with tls.wrap_socket(raw, server_hostname='peerspan') as stream:
                encoded = compact(data)
                stream.sendall((f'POST {path} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(encoded)}\r\n\r\n').encode() + encoded)
                reply = http.client.HTTPResponse(stream); reply.begin(); reply.read()
                check(reply.status == 404, 'bootstrap exposed private owner signing')
        for method in ('GET', 'PUT', 'DELETE'):
            status, denied = h.api(method, path)
            check(status == 405, 'owner signing accepted unsupported method'); public(denied)
    peer.stop(); bootstrap.stop()
    public(get(h, '/v1/activity?limit=1000'), *f['secrets'], adapter.token)


suite.finish()
