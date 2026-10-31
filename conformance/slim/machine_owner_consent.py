#!/usr/bin/env python3
"""Exact nonsigning machine-owner consent, guided section42.

Independent public-contract/test-fixture source only. Genuine two-host pinned
requests return automatically to their existing person. Selected original
public authority has an unavailable configured private signer; device15 is a
separate authorized-work observation. No authority/protocol/pending/queue/clock
row is fabricated or edited. Only temporary schema-only ABORT triggers inject
write failure. Logical contents/schema/version of EVERY state DB and all durable
state/home entries plus BOTH counted TCP and UDP paths remain in each pure
comparison; SQLite WAL/SHM bookkeeping alone is excluded, never journals.

Source limits: no private signer syscall attribution, deterministic stalled5s
client, exhausted quotas, corrupt retained authority/receipt, owned seed failure,
root fork/restriction/ban/migration or insufficient-device/separate-admin graph.
Background signatures after explicit consent are observed separately, never
attributed to the approving route. No completed machine admission, native,
installed bundle, actual model or delivery/readiness claim. All31 old suites,
helpers and393 native cases remain byte-identical. Runtime belongs to root.
"""
import atexit
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

from harness import (Adapter, Clock, Suite, UnixHTTPConnection, check, link_view,
                     parse_time, rfc3339, ssh_key, ssh_public_base64, wait_for)
from counted_peer import CountedUDP

suite = Suite('machine_owner_consent', __doc__)
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
    for h in (f['a'], f['b']):
        check(not (h.root / 'absent-person-key').exists() and not (h.root / 'absent-agent.sock').exists(),
              'configured absent signer became available')
    check(not (f['b'].home / '.config/peerspan/person_ed25519').exists(), 'requester acquired a new/copied original')


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
        inspection_shape(f, value['inspection'], parent=parent, request=request, current=True)
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


@suite.case('null_lookup_exact_inspected_prepare_and_independent_receipt_packet_domains', 'guided42 verification1')
def _():
    f = consent_world(); h = f['a']
    initial = pure(f, 'lookup')
    check(initial['consent'] is None and initial['inspection'] == standalone(f), 'null lookup prepared consent or changed standalone inspection')
    record, secret = pending(h, f['rid'])
    packet = json.loads(base64.b64decode(record['request_packet_base64'], validate=True))
    signed_bytes = base64.b64decode(packet['payload_base64'], validate=True); signed = json.loads(signed_bytes)
    check(f['rid'] == 'link_' + hashlib.sha256(b'peerspan-decentralized-request-id-v1\n' + hashlib.sha256(signed_bytes).hexdigest().encode()).hexdigest()
          and packet['request_id'] == f['rid'] and packet_id(packet) == initial['request']['request_packet_id'], 'actual signed request/packet identity domains')
    check(signed['expected_network_id'] == f['network']['id'] and signed['expected_context_id'] == f['network']['context_id']
          and signed['expected_person_public_key'] == f['person'], 'genuine explicit signed request pins')
    ed25519(f['b'].public_key, packet['host_signature'], packet_message(packet), 'consent-request-host')
    ed25519(signed['device_public_key'], packet['device_signature'], packet_message(packet), 'consent-request-device')
    before, counters = whole(f), traffic(f)
    check(all(db['$version'] == (27,) for side in before for db in side[0].values()
              if 'dec_intents' in db), 'machine consent changed required existing schema27')
    owners, receipts = kind_ids(h, 'owner'), kind_ids(h, 'machine_owner_review')
    value = op(f, 'prepare', inspected=initial['inspection']); f['prepared'] = value
    receipt = value['consent']; owner = intent(h, receipt['review']['intent_id'])['record']
    check(receipt['state'] == 'review' and receipt['review']['replaces_consent_id'] == '-'
          and receipt['review']['inspection'] == initial['inspection']['review'], 'first exact inspected terms were not frozen')
    check(kind_ids(h, 'owner') == owners | {receipt['review']['intent_id']}
          and kind_ids(h, 'machine_owner_review') == receipts | {receipt['consent_id']}, 'preparation did not create exactly one ordinary/receipt pair')
    check(owner['approved'] is False and owner['approved_at'] == '-' and owner['signatures'] == [] and owner['completed'] is False,
          'preparation signed or approved ordinary work')
    current, same_secret = pending(h, f['rid'])
    pending_prepare_diagnostic(record, current, secret, same_secret, receipt['review']['intent_id'])
    check(current['owner_intent_id'] == receipt['review']['intent_id'] and same_secret == secret
          and unchanged_except(record, current, 'roles', 'owner_intent_id'), 'preparation changed pending evidence or pairing material')
    check(value['request'] == initial['request'], 'preparation advanced protocol stage or requester selection/commit')
    allowed_write(f, before, counters, {'dec_intents', 'dec_pending', 'dec_clock'})
    no_keys(f)


@suite.case('pure_exact_replays_and_reuse_only_matching_unapproved_ordinary_intent', 'guided42 verification2')
def _():
    f = consent_world(); prepared = f['prepared']
    for action, cli in (('lookup', False), ('prepare', True), ('prepare', False), ('lookup', True)):
        value = pure(f, action, prepared, cli=cli)
        check(value['consent'] == prepared['consent'], 'pure replay refreshed consent/provider/template/time')
    for patch in ({'inspection_review_id': 'review_' + '0' * 64},
                  {'context': {**context(f['parent']), 'native_session_id': 'different-machine-conversation'}}):
        pure(f, 'prepare', prepared, override={**input_for(f, 'prepare', prepared), **patch}, status=409, code='review_changed')
    pure(f, 'lookup', override={**input_for(f, 'lookup'), 'consent_id': 'dint_' + 'f' * 32}, status=404, code='not_found')
    pure(f, 'lookup', override={**input_for(f, 'lookup'), 'request_id': 'link_' + 'f' * 64}, status=404, code='not_found')
    other = consent_world('reuse'); h = other['a']; inspected = standalone(other)
    status, advanced = h.api('POST', '/v2/link/approvals', ordinary_body(other, inspected))
    check(status == 200, f'genuine matching ordinary unapproved preparation HTTP {status}')
    raw, _ = pending(h, other['rid']); iid = raw.get('owner_intent_id', '-')
    check(re.fullmatch(r'dint_[0-9a-f]{32}', iid), 'ordinary preparation retained no exact intent')
    original_intent = intent(h, iid)
    check(original_intent['record']['approved'] is False and original_intent['record']['signatures'] == [], 'ordinary setup was not unsigned/unapproved')
    # Standalone41 still refuses; only consent lookup's deliberately expanded
    # inspection supports this exact existing unapproved ordinary intent.
    quiet(other); before, counters = whole(other), traffic(other)
    status, denied = h.api('POST', INSPECT, {'context': context(other['parent']), 'request_id': other['rid']})
    check(status == 409 and denied.get('code') == 'machine_owner_inspection_unavailable', 'standalone inspection broadened to prepared owner intent')
    strict(whole(other), before, traffic(other), counters, 'standalone-existing-intent')
    seen = pure(other, 'lookup')
    check(seen['consent'] is None and seen['inspection'] == inspected, 'matching ordinary intent lost current expanded inspection')
    before, counters = whole(other), traffic(other)
    value = op(other, 'prepare', inspected=inspected); other['prepared'] = value
    check(value['consent']['review']['intent_id'] == iid and intent(h, iid) == original_intent
          and len(kind_ids(h, 'machine_owner_review')) == 1, 'guided preparation replaced/re-timed matching ordinary intent')
    allowed_write(other, before, counters, {'dec_intents', 'dec_clock'})


@suite.case('late_dual_approval_abort_rolls_back_clock_pending_and_both_flags_then_exact_approval', 'guided42 verification3')
def _():
    f = consent_world(); h = f['a']; prepared = f['prepared']; receipt = prepared['consent']
    ids = (receipt['consent_id'], receipt['review']['intent_id'])
    check(all(r['approved'] is False and r['approved_at'] == '-' for r in dual_records(h, receipt)), 'approval prerequisite already authorized')
    quiet(f); original_schema = records(h)
    # Schema-only fault fires only once both real updates have reached SQLite,
    # independent of receipt/ordinary update order. No authority row is edited.
    with closing(sqlite3.connect(db_path(h))) as db, db:
        db.execute(f"CREATE TRIGGER machine_consent_abort AFTER UPDATE OF record ON dec_intents WHEN NEW.intent_id IN ('{ids[0]}','{ids[1]}') "
            f"AND (SELECT count(*) FROM dec_intents WHERE intent_id IN ('{ids[0]}','{ids[1]}') AND json_extract(record,'$.approved')=1)=2 "
            "BEGIN SELECT RAISE(ABORT,'PRIVATE_MACHINE_CONSENT_ABORT'); END")
    try:
        before, counters = whole(f), traffic(f)
        status, denied = h.api('POST', BASE + '/approve', input_for(f, 'approve', prepared), timeout=8)
        check(not 200 <= status < 300, 'late dual-approval SQL fault succeeded')
        public(denied, 'PRIVATE_MACHINE_CONSENT_ABORT', *f['secrets'])
        strict(whole(f), before, traffic(f), counters, 'dual-approval-fault')
        check(all(r['approved'] is False and r['approved_at'] == '-' for r in dual_records(h, receipt)), 'fault left one approval')
    finally:
        with closing(sqlite3.connect(db_path(h))) as db, db:
            db.execute('DROP TRIGGER machine_consent_abort')
    check(records(h) == original_schema, 'fault removal failed exact DB/schema/clock/pending restoration')
    old_receipt, old_owner = dual_records(h, receipt)
    before, counters = whole(f), traffic(f)
    approved = op(f, 'approve', prepared); f['approved'] = approved
    current_receipt, current_owner = dual_records(h, receipt)
    check(approved['consent']['state'] == 'approved' and core(approved['consent']) == core(receipt)
          and current_receipt['approved'] is current_owner['approved'] is True
          and current_receipt['approved_at'] == current_owner['approved_at'] != '-', 'exact dual approval flags/time were not atomic')
    check(abs((parse_time(current_receipt['approved_at']) - h.now()).total_seconds()) < 5
          and unchanged_except(old_receipt, current_receipt, 'approved', 'approved_at')
          and unchanged_except(old_owner, current_owner, 'approved', 'approved_at', 'signatures', 'completed', 'result_base64'),
          'approval replaced exact nonsigning receipt or immutable ordinary terms/templates')
    allowed_write(f, before, counters, {'dec_intents', 'dec_clock'})
    check(get(h, '/v2/networks/' + f['network']['id'])['provider_state']['state'] == 'unavailable', 'approval acquired/substituted an original signer')
    quiet(f)
    observed = intent(h, receipt['review']['intent_id'])['record']
    check(observed['provider'] == old_owner['provider'] and observed['templates'][0] == old_owner['templates'][0]
          and all(s['role'] != 'authority' for s in observed['signatures']), 'unavailable original produced authority signature or provider fallback')
    request = link_view(h, f['rid'])
    check(request['owner_offer_id'] == '-' and not request['selection_approved'] and not request['commit_approved'], 'original approval implied possession proof or requester consent')


@suite.case('provider_parent_exact_replacement_stale_review_and_real_expiry_cancellation', 'guided42 verification4')
def _():
    f = consent_world('reuse'); h = f['a']; previous = f['prepared']; old_parent = f['parent']
    iid = previous['consent']['review']['intent_id']; ordinary = intent(h, iid)
    select_provider(f, f['device']['lease_id'])
    changed = pure(f, 'lookup', previous)
    check(changed['consent']['state'] == 'invalidated' and changed['inspection'] is None, 'provider change remained actionable or silently rebound ordinary terms')
    pure(f, 'approve', previous, status=409, code='review_changed')
    pure(f, 'prepare', previous, inspected={'review_id': 'review_' + 'a' * 64},
         replace=previous['consent']['consent_id'], status=409, code='review_changed')
    original(f)
    h.ok('session', 'detach', old_parent['review']['session_id'])
    detached = pure(f, 'lookup', previous)
    check(detached['consent']['state'] == 'invalidated' and detached['inspection'] is None, 'detached parent retained fresh write authority')
    fresh = project(h, 'replacement', replace=old_parent['flow_id'], old=old_parent); f['parent'] = fresh
    seen = pure(f, 'lookup')
    check(seen['consent']['review'] == previous['consent']['review'] and seen['consent']['state'] == 'invalidated'
          and seen['context'] == context(fresh) and seen['inspection']['review']['context'] == context(fresh)
          and seen['inspection']['review_id'] != previous['consent']['review']['inspection_review_id'], 'new parent laundered old receipt or lost current inspection')
    pure(f, 'prepare', inspected=seen['inspection'], status=409, code='review_changed')
    quiet(f); before, counters = whole(f), traffic(f)
    successor = op(f, 'prepare', inspected=seen['inspection'], replace=previous['consent']['consent_id'])
    check(successor['consent']['consent_id'] != previous['consent']['consent_id']
          and successor['consent']['review']['replaces_consent_id'] == previous['consent']['consent_id']
          and successor['consent']['review']['intent_id'] == iid and intent(h, iid) == ordinary,
          'replacement changed immutable ordinary template/provider/window')
    check(successor['consent']['review']['expires_at'] == previous['consent']['review']['expires_at']
          and len(kind_ids(h, 'owner')) == 1 and len(kind_ids(h, 'machine_owner_review')) == 2, 'replacement restarted honest signing window or replaced ordinary intent')
    allowed_write(f, before, counters, {'dec_intents', 'dec_clock'})
    retry = pure(f, 'prepare', inspected=seen['inspection'], replace=previous['consent']['consent_id'])
    check(retry['consent'] == successor['consent'], 'exact predecessor retry created another replacement')
    pure(f, 'approve', previous, parent=old_parent, status=409, code='review_changed')
    pure(f, 'prepare', successor, replace=successor['consent']['consent_id'], status=409, code='review_changed')
    pure(f, 'approve', successor, override={**input_for(f, 'approve', successor), 'consent_review_id': 'review_' + '0' * 64}, status=409, code='review_changed')
    pure(f, 'prepare', successor, override={**input_for(f, 'prepare', successor), 'request_id': 'link_' + 'f' * 64}, status=404, code='not_found')
    # A real signed wrong-person request already exists on main; never fabricate
    # person authority or mutate the signed packet for this refusal.
    main = consent_world()
    pure(main, 'prepare', main['prepared'], override={**input_for(main, 'prepare', main['prepared']), 'request_id': main['wrong_rid']}, status=409)
    for local in (h, f['b']):
        advance_to(local, parse_time(successor['consent']['review']['expires_at']) + timedelta(seconds=1))
    elapsed = pure(f, 'lookup', successor)
    check(elapsed['consent']['state'] == 'expired' and core(elapsed['consent']) == core(successor['consent']), 'fixed signing-window expiry renewed or destroyed receipt')
    pure(f, 'approve', successor, status=409, code='review_expired')
    check(pure(f, 'prepare', successor)['consent'] == elapsed['consent'], 'expired identical prepare mutated reviewed times')
    cancel(f)
    cancelled = pure(f, 'lookup', successor)
    check(cancelled['consent']['state'] == 'cancelled' and cancelled['inspection'] is None, 'cancelled precedence lost to expired/current inspection')
    pure(f, 'prepare', successor, replace=successor['consent']['consent_id'], status=409)
    f['successor'] = successor


@suite.case('approved_history_restart_detach_expiry_and_no_laundering_outside_ordinary_approval', 'guided42 verification5')
def _():
    f = consent_world(); h = f['a']; prepared = f['prepared']; approved = f['approved']; parent = f['parent']
    select_provider(f, f['device']['lease_id']); cancel(f)
    h.ok('session', 'detach', parent['review']['session_id'])
    for action, cli in (('lookup', False), ('prepare', True), ('approve', False)):
        result = pure(f, action, prepared, cli=cli)
        check(result['consent'] == approved['consent'], 'cancel/provider/detachment changed exact approved history')
    fresh = project(h, 'history', replace=parent['flow_id'], old=parent)
    other = pure(f, 'lookup', prepared, parent=fresh)
    check(other['context'] == context(fresh) and other['consent'] == approved['consent']
          and other['consent']['review']['context'] == context(parent), 'new parent acquired another project approval attribution')
    pure(f, 'approve', prepared, parent=fresh, status=409, code='review_changed')
    pure(f, 'prepare', prepared, parent=fresh, replace=prepared['consent']['consent_id'], status=409, code='review_changed')
    h.restart(kill=True)
    check(get(h, PROJECT + '/' + fresh['flow_id'])['state'] == 'invalidated', 'ordinary restart did not detach current parent')
    target = parse_time(prepared['request']['expires_at']) + timedelta(seconds=1)
    for local in (h, f['b']):
        advance_to(local, target)
    quiet(f); exact_receipt = intent(h, prepared['consent']['consent_id']); exact_owner = intent(h, prepared['consent']['review']['intent_id'])
    for action in ('lookup', 'prepare', 'approve'):
        for cli in (False, True):
            result = pure(f, action, prepared, cli=cli)
            check(result['consent'] == approved['consent'], 'expired/restarted exact API/CLI history changed approved receipt')
    check(intent(h, prepared['consent']['consent_id']) == exact_receipt and intent(h, prepared['consent']['review']['intent_id']) == exact_owner,
          'historical replay altered approval time/templates/signatures/terminal state')
    device = consent_world('external'); a = device['a']; select_provider(device, device['device']['lease_id'])
    inspected = standalone(device); external = op(device, 'prepare', inspected=inspected)
    # The genuinely unapproved requester may pull packets, but has separately
    # granted neither selection nor commit. Its real pull supplies the live
    # consumed-ClientHello barrier; no synthetic worker-pause flag is used.
    device['b'].start()
    status, advanced = a.api('POST', '/v2/link/approvals', ordinary_body(device, inspected, approve=True))
    check(status == 200, f'genuine outside ordinary approval HTTP {status}')
    wait_for(lambda: link_view(a, device['rid'])['owner_offer_id'] != '-', timeout=10, interval=.1, message='actual approved device owner offer retention')
    guard = held_transport(device)
    try:
        quiet(device); guard(); before, counters = whole(device), traffic(device)
        observed = op(device, 'lookup', external); guard()
        check(observed['consent']['state'] == 'invalidated' and observed['inspection'] is None, 'ordinary approval was laundered into project consent')
        strict(whole(device), before, traffic(device), counters, 'outside-approval-held')
    finally:
        device['b'].stop()
        a.relay.mode = device['b'].relay.mode = 'pass'
    rec, owner = dual_records(a, external['consent'])
    check(rec['approved'] is False and rec['approved_at'] == '-' and rec['signatures'] == []
          and owner['approved'] is True and link_view(a, device['rid'])['owner_offer_id'] != '-', 'outside approval fabricated receipt or device fixture did not perform real authorized work')
    check(not link_view(a, device['rid'])['selection_approved'] and not link_view(a, device['rid'])['commit_approved'], 'ordinary machine work supplied independent requester consent')
    cancel(device)
    pure(device, 'approve', external, status=409)
    print('LIMIT machine_owner_consent: post-commit host/device worker work is not route attribution; private signer syscalls, corrupt/quota/complex authority and exact stalled5s cutoff remain source-only', flush=True)


@suite.case('strict_recursive_private_json_stdin_no_startup_and_all_owner_router_boundaries', 'guided42 verification6')
def _():
    f = consent_world(); h = f['a']; prepared = f['prepared']
    for action in ('lookup', 'prepare', 'approve'):
        data = input_for(f, action, prepared); raw = compact(data); maximum = raw + b' ' * (65536 - len(raw))
        quiet(f); before, counters = whole(f), traffic(f)
        status, view = raw_post(h, action, maximum)
        check(status == 200 and view['consent'] == f['approved']['consent'], f'exact64KiB {action} refused/changed history')
        result = h.cli('onboarding', 'machine', action, '--stdin', input=maximum.decode(), timeout=8)
        check(result.ok and result.json['consent'] == view['consent'], 'exact64KiB private CLI parity')
        malformed = [b'null', b'[]', b'{', raw + b'{}', maximum + b' ',
            raw.replace(b'"request_id":', b'"request_id":"link_' + b'0' * 64 + b'","request_id":'),
            raw.replace(b'"integration":"claude-code"', b'"integration":"claude-code","integration":"claude-code"'),
            compact({**data, 'extra': 'PRIVATE_MACHINE_CONSENT'}),
            compact({**data, 'context': {**data['context'], 'extra': 'PRIVATE_MACHINE_CONSENT'}}),
            compact({**data, 'context': None}), compact({**data, 'request_id': []}),
            compact({**data, 'request_id': 'link_' + 'A' * 64})]
        for key in data:
            if not (action == 'lookup' and key == 'consent_id'):
                malformed.append(compact({k: v for k, v in data.items() if k != key}))
            malformed.append(compact({**data, key: None}))
            if key != 'context' and key != 'request_id':
                malformed.append(compact({**data, key: 'BAD_PRIVATE_MACHINE_CONSENT'}))
                token = compact(key) + b':'
                malformed.append(raw.replace(token, token + compact(data[key]) + b',' + token, 1))
        malformed += [compact({**data, 'context': {**data['context'], key: None}}) for key in data['context']]
        for index, bad in enumerate(malformed):
            status, denied = raw_post(h, action, bad)
            check(status == 400 and type(denied) is dict and denied.get('code') == 'invalid', f'{action} malformed{index} HTTP {status}')
            result = h.cli('onboarding', 'machine', action, '--stdin', input=bad.decode(), timeout=8)
            check(not result.ok, f'{action} private CLI accepted malformed{index}')
            public(denied, 'PRIVATE_MACHINE_CONSENT', 'BAD_PRIVATE_MACHINE_CONSENT',
                   *[v for k, v in data['context'].items() if k != 'integration'], *f['secrets'])
            public(result.stdout + result.stderr, 'PRIVATE_MACHINE_CONSENT', 'BAD_PRIVATE_MACHINE_CONSENT', str(h.state),
                   *[v for k, v in data['context'].items() if k != 'integration'], *f['secrets'])
        strict(whole(f), before, traffic(f), counters, action + '-strict-input')
        for args in (('onboarding', 'machine', action), ('onboarding', 'machine', action, f['rid'], '--stdin'),
                     ('onboarding', 'machine', action, '--PRIVATE_MACHINE_CONSENT=/private/owner', '--stdin')):
            result = h.cli(*args, input=raw.decode(), timeout=8)
            check(not result.ok, 'private operation accepted missing stdin or positional/private option')
            public(result.stdout + result.stderr, f['rid'], 'PRIVATE_MACHINE_CONSENT', '/private/owner', str(h.state))
        missing = suite.host('n' + action, start=False); before_missing = files(missing.root)
        result = missing.cli('onboarding', 'machine', action, '--stdin', input=raw.decode(), timeout=8)
        check(not result.ok and files(missing.root) == before_missing, 'missing owner socket started daemon or initialized state')
        public(result.stdout + result.stderr, str(missing.root), *f['secrets'])
    fresh_parent = project(h, 'router')
    credential = h.ok('adapter', 'create', '--session', fresh_parent['review']['session_id'], '--expires-at', rfc3339(h.now() + timedelta(hours=1)))
    adapter = Adapter(h, fresh_parent['review']['agent'], fresh_parent['review']['session_id'], credential)
    status, _ = adapter.call('POST', '/adapter/v1/connect', {'adapter_id': adapter.adapter_id, 'session_id': adapter.session_id, 'instance_id': adapter.instance})
    check(status == 200, 'genuine scoped adapter boundary prerequisite')
    peer, bootstrap = host('p'), host('z')
    for local, remote in ((h, peer), (peer, h)):
        local.ok('peer', 'add', '--id', remote.id, '--public-key', remote.public_key, '--address', remote.counted_peer.address)
    cert, key = suite.work / 'boundary-cert.pem', suite.work / 'boundary-key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ed25519', '-nodes', '-subj', '/CN=machine-consent-boundary', '-days', '1',
        '-keyout', str(key), '-out', str(cert)], capture_output=True, check=True, timeout=5)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); tls.check_hostname = False; tls.verify_mode = ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key)); tls.set_alpn_protocols(['peerspan-bootstrap/1'])
    for action in ('lookup', 'prepare', 'approve'):
        path = BASE + '/' + action; data = input_for(f, action, prepared)
        status, denied = adapter.call('POST', path, data)
        check(status == 404, f'scoped route leaked owner operation HTTP {status}'); public(denied, adapter.token)
        result = subprocess.run([str(suite.probe_bin), '--state', str(peer.state), '--address', h.counted_peer.address,
            '--alpn', 'peerspan-peer/1', '--method', 'POST', '--path', path, '--body-stdin'], input=compact(data), capture_output=True, timeout=10)
        check(result.returncode == 0 and json.loads(result.stdout)['status'] == 404, 'authenticated peer exposed private machine consent route')
        with socket.create_connection(('127.0.0.1', int(bootstrap.relay.address.rsplit(':', 1)[1])), timeout=5) as raw:
            with tls.wrap_socket(raw, server_hostname='peerspan') as stream:
                encoded = compact(data)
                stream.sendall((f'POST {path} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(encoded)}\r\n\r\n').encode() + encoded)
                reply = http.client.HTTPResponse(stream); reply.begin(); reply.read()
                check(reply.status == 404, f'bootstrap exposed private consent route HTTP {reply.status}')
        for method in ('GET', 'PUT', 'DELETE'):
            status, denied = h.api(method, path)
            check(status == 405, f'owner operation accepted unsupported method HTTP {status}'); public(denied)
    peer.stop(); bootstrap.stop()
    public(get(h, '/v1/activity?limit=1000'), *f['secrets'], adapter.token)


suite.finish()
