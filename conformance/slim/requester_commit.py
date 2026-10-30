#!/usr/bin/env python3
"""Exact durable requester commit consent, guided contract section27.

Independent genuine distinct-person/two-host ceremony and public API/CLI.
No production imports, original-key installation or protocol/authority edits.
The only DB writes by this suite are temporary schema-only ABORT triggers;
remove them before exact rollback comparison. Live pure calls hold a consumed
actual ClientHello outside DB and retain strict whole DB/state/home plus BOTH
full carrier counters for each measured command. Preparation writes no signing
proof; after approval the independent owned worker may sign/publish before the
response. Atomic intent/request pins are observed coherently, without claiming
that concurrent worker activity was route-driven. Exact no-sign/transport/apply
inside approval, unavailable owned-device/corrupt-root/pruned evidence and narrow
final-check crossings, fresh incompatible adoption and inaccessible owned-device
seeds remain source/fault limits. No installed/native/physical/
model readiness is inferred. Existing22 host suites and292 native cases stay.
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

suite = Suite("requester_commit", __doc__)
BASE = "/v1/onboarding/join-flows"
PROJECT = "/v1/onboarding/project-flows"
PREFIXES = ('psi2-', 'psl2-', 'peerspan-invite-v1.', 'peerspan-member-invite-v1.',
            'peerspan-person-invite-v1.', 'token_', 'instance_')
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





COMMIT_TOP = set('version host_id flow_id join_review_id context observed_at request commit'.split())
COMMIT_REVIEW = set('version kind host_id context flow_id join_review_id owner_review_id request_id intent_id network member person_public_key host_public_key device_public_key request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id root_state_id person_lease_id host_lease_id binding_lease_id device_lease_id scopes binding_scopes not_after provider created_at expires_at effects'.split())
LINK_KEYS = set('request_id role mode state network_id context_id migration_proposal_id person_public_key host_public_key device_public_key created_at expires_at request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id manifest_id activation_id outcome_id selection_approved commit_approved completed attention next'.split())
COMMIT_EFFECTS = {'approve_commit_intent': True, 'authorize_binding_host_signature': True,
    'authorize_requester_commit_signatures': True, 'authorize_commit_publication': True,
    'authorize_local_application': True, 'grant_agent_access': False, 'share_files': False,
    'share_conversation': False, 'capability_calls': False}


def endpoint(f, action):
    return BASE + '/' + f['flow']['flow_id'] + '/commit/' + action


def body(f, prepared=None):
    result = {'context': context(f['parent']), 'join_review_id': f['flow']['review_id']}
    if prepared is not None:
        result['commit_review_id'] = prepared['commit']['review_id']
    return result


def intents(h, rid):
    with closing(sqlite3.connect(f'file:{db_path(h)}?mode=ro', uri=True)) as db:
        return [(iid, json.loads(raw), secret) for iid, raw, secret in db.execute(
            "SELECT intent_id,record,secret FROM dec_intents WHERE kind='requester_commit'")
            if json.loads(raw)['operation_id'] == rid]


def intent(h, iid):
    with closing(sqlite3.connect(f'file:{db_path(h)}?mode=ro', uri=True)) as db:
        row = db.execute('SELECT network_id,context_id,kind,record,secret FROM dec_intents WHERE intent_id=?', (iid,)).fetchone()
    check(row is not None, 'guided review references no ordinary intent')
    return {'network_id': row[0], 'context_id': row[1], 'kind': row[2], 'record': json.loads(row[3]), 'secret': row[4]}


def pair(name, *, F=True):
    f = make_pair(name)
    if F:
        a, h = f['a'], f['h']; a.relay.mode = h.relay.mode = 'pass'; a.start()
        finalize(h, f['view'], f['key'])
        view = pull_until(h, f['rid'], 'owner_finalization_id', timeout=20)
        check(view['state'] == 'needs_commit' and view['selection_approved'] and not view['commit_approved'] and
              view['completed'] == ['request_created', 'owner_offered', 'owner_selected', 'administrator_offered', 'owner_finalized'] and
              all(view[k] == '-' for k in ('manifest_id', 'activation_id', 'outcome_id')), 'genuine uncommitted F prefix fixture')
        pull_until(a, f['rid'], 'owner_finalization_id', timeout=15)
        a.stop(); a.relay.mode = h.relay.mode = 'drop'; f['view'] = view; quiet(f)
        record, _ = pending(h, f['rid'])
        packet = json.loads(base64.b64decode(record['owner_finalization_packet_base64'], validate=True))
        check(packet_id(packet) == view['owner_finalization_id'] and packet['signer_public_key'] == f['person'] and
              packet['writer_host_public_key'] == h.public_key and packet['authority_signature_format'] == 'sshsig' and
              packet['authority_signature'] != '-', 'genuine original finalization proof missing')
        f['F'] = json.loads(base64.b64decode(packet['payload_base64'], validate=True))
    return f


def main():
    check(not shared.get('main_failed'), 'earlier genuine main ceremony setup failed')
    if 'main' not in shared:
        try:
            shared['main'] = pair('main')
        except Exception:
            shared['main_failed'] = True
            raise
    return shared['main']


def validate(f, value, *, current=True):
    h, flow = f['h'], f['flow']
    check(type(value) is dict and set(value) == COMMIT_TOP and type(value['version']) is int and value['version'] == 1, 'closed commit wrapper')
    check(value['host_id'] == h.id and value['flow_id'] == flow['flow_id'] and value['join_review_id'] == flow['review_id'] and
          value['context'] == context(f['parent']), 'exact commit flow/context/host binding')
    check(re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value['observed_at']) and
          abs((parse_time(value['observed_at']) - h.now()).total_seconds()) < 5, 'whole-second guarded observation')
    request = value['request']
    check(set(request) == LINK_KEYS and request['request_id'] == f['rid'] and request['role'] == 'requester' and request['mode'] == 'new' and
          request['migration_proposal_id'] == '-' and request['network_id'] == f['network']['id'] and
          request['context_id'] == f['network']['context_id'] and request['person_public_key'] == f['person'] and
          request['host_public_key'] == h.public_key, 'exact closed original requester view')
    if current:
        check(request == link_view(h, f['rid']), 'read response differs from exact retained LINK_VIEW')
    commit_value = value['commit']
    if commit_value is None:
        check(intents(h, f['rid']) == [], 'null lookup hid an ordinary requester intent')
        public(value, f['code'], f['reply']); return
    check(type(commit_value) is dict and set(commit_value) == {'review_id', 'review', 'state', 'next_action'}, 'closed commit object')
    review = commit_value['review']; owner = f['owner']['owner']['review']
    check(type(review) is dict and set(review) == COMMIT_REVIEW and type(review['version']) is int and review['version'] == 1 and
          review['kind'] == 'approve_new_original_requester_commit', 'closed public commit review')
    expected = {'host_id': h.id, 'context': context(f['parent']), 'flow_id': flow['flow_id'], 'join_review_id': flow['review_id'],
        'owner_review_id': f['owner']['owner']['review_id'], 'request_id': f['rid'], 'network': owner['network'], 'member': owner['member'],
        'person_public_key': f['person'], 'host_public_key': h.public_key, 'device_public_key': f['view']['device_public_key'],
        'not_after': owner['not_after']}
    for field in ('request_packet_id', 'owner_offer_id', 'selection_id', 'administrator_offer_id', 'owner_finalization_id'):
        expected[field] = f['view'][field]
    for field in ('root_state_id', 'person_lease_id', 'host_lease_id'):
        expected[field] = f['F'][field]
    expected['binding_lease_id'] = statement_id(f['F']['binding_lease'])
    expected['device_lease_id'] = statement_id(f['F']['device_lease'])
    expected['provider'] = {'kind': 'requester', 'host_public_key': h.public_key,
        'device_public_key': f['view']['device_public_key'], 'signature_format': 'ed25519'}
    for key, expected_value in expected.items():
        check(review[key] == expected_value, 'commit review changed exact term: ' + key)
    references = [review[k] for k in ('root_state_id', 'person_lease_id', 'host_lease_id', 'binding_lease_id', 'device_lease_id')]
    check(all(re.fullmatch('ds_[0-9a-f]{64}', ref) for ref in references) and len(set(references)) == 5, 'canonical distinct exact statement parents')
    check(type(review['scopes']) is int and review['scopes'] == 7 and type(review['binding_scopes']) is int and review['binding_scopes'] == 2 and
          review['effects'] == COMMIT_EFFECTS and all(type(v) is bool for v in review['effects'].values()), 'commit powers/effects widened')
    check(parse_time(review['not_after']) == parse_time(request['created_at']) + timedelta(days=7), 'fixed request-created seven-day end')
    check(re.fullmatch('dint_[0-9a-f]{32}', review['intent_id']), 'typed ordinary commit intent ID')
    stored = intent(h, review['intent_id']); record = stored['record']
    check(stored['kind'] == 'requester_commit' and stored['network_id'] == f['network']['id'] and stored['context_id'] == f['network']['context_id'] and
          record['operation_id'] == f['rid'] and stored['secret'] is None and
          record['provider'] == {'kind': 'requester', 'signer_public_key': f['view']['device_public_key'], 'signature_format': 'ed25519', 'lease_id': '-'},
          'wrong private ordinary requester selector/operation or duplicated secret')
    check(review['created_at'] == record['created_at'] and parse_time(review['expires_at']) == min(
          parse_time(record['created_at']) + timedelta(minutes=15), parse_time(request['expires_at']), parse_time(review['not_after'])), 'fixed ordinary creation/review deadline')
    check(commit_value['review_id'] == digest('peerspan-requester-commit-review-v1', review), 'independent UTF8 canonical public review digest')
    actions = {'review': 'approve_requester_commit', 'approved': 'follow_join_progress', 'cancelled': 'inspect_join_progress',
               'expired': 'inspect_join_progress', 'invalidated': 'inspect_join_progress'}
    check(commit_value['state'] in actions and commit_value['next_action'] == actions[commit_value['state']], 'derived review state/action')
    check(len(intents(h, f['rid'])) == 1, 'duplicate ordinary requester intent')
    public(value, f['code'], f['reply'])


def op(f, action, prepared=None, *, status=200, code=None, pure=False, data=None, current=True):
    h = f['h']
    if pure:
        quiet(f); before, network = snapshot(h), traffic(f)
    actual, value = h.api('POST', endpoint(f, action), body(f, prepared) if data is None else data)
    check(actual == status, f'commit {action}: HTTP {actual}, want {status}')
    if code:
        check(type(value) is dict and value.get('code') == code, f'commit {action}: expected controlled {code}')
    if pure:
        after = snapshot(h)
        check(after == before, f'commit {action} changed logical records/private files: {differences(before, after)}')
        check(traffic(f) == network, f'commit {action} attempted carrier IO; before={network}, after={traffic(f)}')
    if actual == 200:
        validate(f, value, current=current)
    else:
        public(value, f['code'], f['reply'], f['parent']['review']['project_root'], f['parent']['review']['native_session_id'])
    return value


def assert_unapproved(f, prepared):
    h = f['h']; stored = intent(h, prepared['commit']['review']['intent_id']); pending_value, _ = pending(h, f['rid'])
    check(prepared['commit']['state'] == 'review' and stored['record']['approved'] is False and stored['record']['approved_at'] == '-' and
          stored['record']['signatures'] == [] and not stored['record']['completed'], 'unapproved preparation signed or approved')
    check(not pending_value['commit_approved'] and pending_value['commit_intent_id'] == '-' and pending_value['commit_packet_base64'] == '-' and
          pending_value['terminal'] == '-' and get(h, '/v2/networks') == [], 'preparation recorded commitment/publication/application')


@suite.case('exact_null_prepare_public_digest_parents_provider_and_pure_fixed_retries', 'guided27 verification1')
def _():
    f = main(); h = f['h']
    null = op(f, 'lookup', pure=True); check(null['commit'] is None, 'lookup implicitly prepared requester consent')
    quiet(f); before, network = snapshot(h), traffic(f)
    result = h.cli('onboarding', 'join', 'commit', 'lookup', '--stdin',
        input=compact({'flow_id': f['flow']['flow_id'], **body(f)}).decode(), timeout=8)
    check(result.ok, 'exact private CLI null lookup'); validate(f, result.json)
    check(result.json['commit'] is None and snapshot(h) == before and traffic(f) == network, 'CLI null lookup prepared or mutated state/IO')
    quiet(f); before, network = snapshot(h), traffic(f)
    prepared = op(f, 'prepare'); shared['prepared'] = prepared
    assert_unapproved(f, prepared); after = snapshot(h)
    check(after[0]['$schema'] == before[0]['$schema'] and after[0]['$version'] == before[0]['$version'] and
          after[1:] == before[1:], 'preparation added schema/journal/key/private files')
    for table in ('dec_pending', 'dec_frames', 'dec_outbox', 'networks', 'dec_objects', 'dec_operations', 'dec_admissions'):
        check(after[0][table] == before[0][table], 'preparation changed protocol/authority table: ' + table)
    check(traffic(f) == network, 'first preparation performed carrier IO')
    for action in ('prepare', 'lookup'):
        same = op(f, action, pure=True)
        check(same['commit'] == prepared['commit'], 'retained preparation renewed or replaced review')
    data = {'flow_id': f['flow']['flow_id'], **body(f)}
    quiet(f); before, network = snapshot(h), traffic(f)
    for action in ('prepare', 'lookup'):
        quiet(f); before, network = snapshot(h), traffic(f)
        result = h.cli('onboarding', 'join', 'commit', action, '--stdin', input=compact(data).decode(), timeout=8)
        check(result.ok, 'exact private CLI retained ' + action); validate(f, result.json)
        check(result.json['commit'] == prepared['commit'] and snapshot(h) == before and traffic(f) == network, 'CLI changed fixed review or persisted state/IO')
        public(result.stdout + result.stderr, f['code'], f['reply'])


def abort_trigger(f, sql, action, prepared=None):
    h = f['h']; quiet(f); before, network = snapshot(h), traffic(f)
    with closing(sqlite3.connect(db_path(h))) as db, db:
        db.execute(sql)
    try:
        status, denied = h.api('POST', endpoint(f, action), body(f, prepared))
        check(not 200 <= status < 300, 'injected ordinary write failure was swallowed')
        public(denied, 'PRIVATE_COMMIT_ABORT', f['code'], f['reply'])
    finally:
        with closing(sqlite3.connect(db_path(h))) as db, db:
            db.execute('DROP TRIGGER conformance_commit_abort')
    after = snapshot(h)
    check(after == before, f'ABORT left partial preparation/approval/request/clock/schema/files: {differences(before, after)}')
    check(traffic(f) == network, 'failed atomic write attempted carrier IO')


@suite.case('schema_only_insert_and_approval_abort_roll_back_every_record_pin_and_clock', 'guided27 verification4')
def _():
    f = pair('fault'); shared['negative'] = f; h = f['h']
    op(f, 'approve', status=409, code='commit_review_unavailable', pure=True,
       data={**body(f), 'commit_review_id': 'review_' + '0' * 64})
    abort_trigger(f, "CREATE TRIGGER conformance_commit_abort BEFORE INSERT ON dec_intents WHEN NEW.kind='requester_commit' "
        "AND json_extract(NEW.record,'$.operation_id')='" + f['rid'] + "' BEGIN SELECT RAISE(ABORT,'PRIVATE_COMMIT_ABORT'); END", 'prepare')
    check(intents(h, f['rid']) == [], 'failed preparation retained an intent')
    prepared = op(f, 'prepare'); shared['negative_prepared'] = prepared; assert_unapproved(f, prepared)
    iid = prepared['commit']['review']['intent_id']; check(re.fullmatch('dint_[0-9a-f]{32}', iid), 'unsafe trigger identifier')
    abort_trigger(f, "CREATE TRIGGER conformance_commit_abort BEFORE UPDATE OF record ON dec_intents WHEN OLD.intent_id='" + iid +
        "' AND json_extract(OLD.record,'$.approved')=0 AND json_extract(NEW.record,'$.approved')=1 "
        "BEGIN SELECT RAISE(ABORT,'PRIVATE_COMMIT_ABORT'); END", 'approve', prepared)
    same = op(f, 'lookup', pure=True); check(same['commit'] == prepared['commit'], 'failed approval changed retained consent')
    assert_unapproved(f, same)


@suite.case('real_missing_F_binding_raw_time_deadline_parent_and_cancellation_refuse_pure', 'guided27 verification3')
def _():
    check('negative' in shared and 'negative_prepared' in shared, 'earlier genuine rollback fixture did not complete')
    f, prepared = shared['negative'], shared['negative_prepared']; h = f['h']
    for patch in ({'join_review_id': 'review_' + '0' * 64}, {'commit_review_id': 'review_' + '0' * 64},
                  {'context': {**context(f['parent']), 'native_session_id': 'different-conversation'}},
                  {'context': {**context(f['parent']), 'project_root': str(suite.work / 'different root')}}):
        op(f, 'approve', prepared, status=409, code='review_changed', pure=True, data={**body(f, prepared), **patch})
    quiet(f); before, network = snapshot(h), traffic(f)
    status, denied = h.api('POST', BASE + '/flow_' + '0' * 32 + '/commit/lookup', body(f))
    check(status == 404, f'unknown flow HTTP {status}'); public(denied, f['code'], f['reply'])
    check(snapshot(h) == before and traffic(f) == network, 'unknown-flow read mutated or attempted IO')
    original = h.clock.offset
    moments = [(parse_time(prepared['commit']['review']['created_at']) - timedelta(seconds=120), 'commit_review_unavailable'),
        (h.now() + timedelta(minutes=11), 'review_expired'),
        (parse_time(prepared['request']['expires_at']) + timedelta(seconds=1), 'review_expired')]
    for moment, code in moments:
        quiet(f); before, network = snapshot(h), traffic(f); advance_to(h, moment)
        op(f, 'approve', prepared, status=409, code=code, pure=False)
        if code == 'review_expired':
            for action in ('lookup', 'prepare'):
                value = op(f, action, pure=False)
                check(value['commit']['review'] == prepared['commit']['review'] and value['commit']['review_id'] == prepared['commit']['review_id'] and
                      value['commit']['state'] == 'expired', 'expiry renewed or rewrote retained proposal')
        after = snapshot(h)
        check(after == before and traffic(f) == network, f'clock refusal/background changed persisted state; cannot restore offset: {differences(before, after)}')
        h.clock.set(original)
    h.ok('session', 'detach', f['parent']['review']['session_id'])
    op(f, 'approve', prepared, status=409, code='review_changed', pure=True)
    invalidated = op(f, 'prepare', pure=True)
    check(invalidated['commit']['state'] == 'invalidated' and invalidated['commit']['review'] == prepared['commit']['review'], 'detachment replaced or renewed retained proposal')
    status, cancelled = h.api('POST', '/v2/link/requests/' + f['rid'] + '/cancel', {})
    check(status == 200 and cancelled['state'] == 'cancelled', 'public pending cancellation fixture')
    op(f, 'approve', prepared, status=409, pure=True)
    cancelled = op(f, 'lookup', pure=True)
    check(cancelled['commit']['state'] == 'cancelled' and cancelled['commit']['review'] == prepared['commit']['review'], 'cancellation erased or replaced immutable review')
    h.stop()
    missing = pair('noF', F=False)
    op(missing, 'lookup', pure=True)
    for action in ('prepare', 'approve'):
        op(missing, action, status=409, code='commit_review_unavailable', pure=True,
           data=body(missing) if action == 'prepare' else {**body(missing), 'commit_review_id': 'review_' + '0' * 64})
    missing['h'].stop()
    unapproved = make_pair('unapproved', live=False, approved=False, signed=False, admitted=False)
    for action in ('prepare', 'approve'):
        op(unapproved, action, status=409, code='commit_review_unavailable', pure=True,
           data=body(unapproved) if action == 'prepare' else {**body(unapproved), 'commit_review_id': 'review_' + '0' * 64})
    unapproved['h'].stop()


def raw_post(h, path, raw):
    connection = UnixHTTPConnection(str(h.state / 'admin.sock'), timeout=8)
    try:
        try:
            connection.request('POST', path, body=raw, headers={'Content-Type': 'application/json'})
        except BrokenPipeError:
            pass
        response = connection.getresponse(); data = response.read()
        return response.status, json.loads(data) if data else None
    finally:
        connection.close()


@suite.case('strict_private_JSON_CLI_ceiling_methods_missing_host_and_scoped_peer_bootstrap_boundaries', 'guided27 verification5')
def _():
    check('prepared' in shared, 'earlier exact preparation did not complete')
    f = main(); h = f['h']; data = body(f); encoded = compact(data)
    maximum = encoded + b' ' * (65536 - len(encoded))
    quiet(f); before, network = snapshot(h), traffic(f)
    status, value = raw_post(h, endpoint(f, 'lookup'), maximum)
    check(status == 200, f'exact64KiB API lookup HTTP {status}'); validate(f, value)
    check(snapshot(h) == before and traffic(f) == network, 'maximum read changed records/files or attempted IO')
    cli_data = compact({'flow_id': f['flow']['flow_id'], **data}); cli_max = cli_data + b' ' * (65536 - len(cli_data))
    quiet(f); before, network = snapshot(h), traffic(f)
    result = h.cli('onboarding', 'join', 'commit', 'lookup', '--stdin', input=cli_max.decode(), timeout=8)
    check(result.ok, 'exact64KiB CLI ceiling'); validate(f, result.json)
    check(snapshot(h) == before and traffic(f) == network, 'maximum CLI read changed records/files or attempted IO')
    ctx = compact(data['context'])
    malformed = [b'null', b'[]', b'{', encoded + b'{}', maximum + b' ',
        b'{"context":' + ctx + b',"context":' + ctx + b',"join_review_id":' + compact(data['join_review_id']) + b'}',
        encoded.replace(b'"integration":"claude-code"', b'"integration":"claude-code","integration":"claude-code"'),
        compact({**data, 'context': None}), compact({**data, 'join_review_id': None}), compact({**data, 'join_review_id': 'review_bad'}),
        compact({'context': data['context']}), compact({**data, 'context': {**data['context'], 'extra': 'PRIVATE_COMMIT_CANARY'}})]
    for field in ('code', 'key', 'path', 'provider', 'scopes', 'not_after', 'packet', 'grant', 'template', 'signature', 'owner_review_id', 'commit_review_id'):
        malformed.append(compact({**data, field: 'PRIVATE_COMMIT_CANARY'}))
    aggregate = snapshot(h)
    for index, raw in enumerate(malformed):
        quiet(f); before, network = snapshot(h), traffic(f)
        status, denied = raw_post(h, endpoint(f, 'lookup'), raw)
        check(status == 400 and denied.get('code') == 'invalid', f'malformed API variant{index}: HTTP {status}')
        public(denied, 'PRIVATE_COMMIT_CANARY', f['code'], f['reply'])
        check(snapshot(h) == before and traffic(f) == network, f'malformed API variant{index} mutated or attempted IO')
        quiet(f); before, network = snapshot(h), traffic(f)
        cli_raw = b'{"flow_id":' + compact(f['flow']['flow_id']) + b',' + raw[1:] if raw.startswith(b'{') else raw
        result = h.cli('onboarding', 'join', 'commit', 'lookup', '--stdin', input=cli_raw.decode(), timeout=8)
        check(not result.ok, f'CLI accepted malformed/duplicate/unknown/trailing/oversized variant{index}')
        public(result.stdout + result.stderr, 'PRIVATE_COMMIT_CANARY', f['code'], f['reply'], str(h.root))
        check(snapshot(h) == before and traffic(f) == network, f'malformed CLI variant{index} mutated or attempted IO')
    check(snapshot(h) == aggregate, 'strict-input corpus changed any persisted record/private file')
    for commit_id in (None, 'review_bad', False):
        invalid = {**body(f), 'commit_review_id': commit_id}
        quiet(f); before, network = snapshot(h), traffic(f)
        status, denied = raw_post(h, endpoint(f, 'approve'), compact(invalid))
        check(status == 400 and denied.get('code') == 'invalid', 'malformed approval digest accepted')
        public(denied, f['code'], f['reply'])
        result = h.cli('onboarding', 'join', 'commit', 'approve', '--stdin',
            input=compact({'flow_id': f['flow']['flow_id'], **invalid}).decode(), timeout=8)
        check(not result.ok, 'CLI accepted malformed approval digest')
        public(result.stdout + result.stderr, str(h.root))
        check(snapshot(h) == before and traffic(f) == network, 'malformed digest changed state or attempted IO')
    for action in ('lookup', 'prepare', 'approve'):
        for method in ('GET', 'PUT', 'DELETE'):
            quiet(f); before, network = snapshot(h), traffic(f)
            status, denied = h.api(method, endpoint(f, action))
            check(status == 405, f'{action} alternate{method}: HTTP {status}'); public(denied)
            check(snapshot(h) == before and traffic(f) == network, 'alternate method changed records/files or attempted IO')
    for args in ((), ('--stdin', 'PRIVATE_COMMIT_CANARY'), ('--stdin', '--person-key', 'PRIVATE_COMMIT_CANARY')):
        quiet(f); before, network = snapshot(h), traffic(f)
        result = h.cli('onboarding', 'join', 'commit', 'approve', *args, input=cli_data.decode(), timeout=8)
        check(not result.ok, 'CLI accepted implicit stdin/positional/provider option')
        public(result.stdout + result.stderr, 'PRIVATE_COMMIT_CANARY', str(h.root))
        check(snapshot(h) == before and traffic(f) == network, 'CLI argument error mutated or attempted IO')
    missing = suite.host('nd', start=False); missing_before = private_files(missing.root)
    result = missing.cli('onboarding', 'join', 'commit', 'lookup', '--stdin', input=cli_data.decode(), timeout=8)
    check(not result.ok and private_files(missing.root) == missing_before, 'CLI created state/key or started absent daemon')
    public(result.stdout + result.stderr, str(missing.root))
    credential = h.ok('adapter', 'create', '--session', f['parent']['review']['session_id'], '--expires-at', rfc3339(h.now() + timedelta(hours=1)))
    adapter = Adapter(h, f['parent']['review']['agent'], f['parent']['review']['session_id'], credential)
    status, _ = adapter.call('POST', '/adapter/v1/connect', {'adapter_id': adapter.adapter_id, 'session_id': adapter.session_id, 'instance_id': adapter.instance})
    check(status == 200, 'genuine scoped credential fixture')
    for action in ('lookup', 'prepare', 'approve'):
        payload_value = body(f, shared['prepared']) if action == 'approve' else body(f)
        status, denied = adapter.call('POST', endpoint(f, action), payload_value)
        check(status == 404, f'scoped adapter exposed {action}: HTTP {status}'); public(denied, adapter.token)
    peer, bootstrap = host('peer'), host('boot')
    for local, remote in ((h, peer), (peer, h)):
        local.ok('peer', 'add', '--id', remote.id, '--public-key', remote.public_key, '--address', remote.peer_address)
    for action in ('lookup', 'prepare', 'approve'):
        payload_value = body(f, shared['prepared']) if action == 'approve' else body(f)
        result = subprocess.run([str(suite.probe_bin), '--state', str(peer.state), '--address', h.peer_address, '--alpn', 'peerspan-peer/1',
            '--method', 'POST', '--path', endpoint(f, action), '--body-stdin'], input=compact(payload_value), capture_output=True, timeout=8)
        check(result.returncode == 0 and json.loads(result.stdout)['status'] == 404, 'authenticated peer exposed private commit action')
    cert, key = suite.work / 'boundary.pem', suite.work / 'boundary-key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ed25519', '-nodes', '-subj', '/CN=boundary', '-days', '1',
        '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True, timeout=5)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); tls.check_hostname = False; tls.verify_mode = ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key)); tls.set_alpn_protocols(['peerspan-bootstrap/1'])
    for action in ('lookup', 'prepare', 'approve'):
        payload_value = compact(body(f, shared['prepared']) if action == 'approve' else body(f))
        with socket.create_connection(('127.0.0.1', bootstrap.bootstrap_port), timeout=5) as raw:
            with tls.wrap_socket(raw, server_hostname='peerspan') as stream:
                stream.sendall((f'POST {endpoint(f, action)} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(payload_value)}\r\n\r\n').encode() + payload_value)
                response = http.client.HTTPResponse(stream); response.begin(); response.read()
                check(response.status == 404, f'bootstrap exposed {action}: HTTP {response.status}')
    peer.stop(); bootstrap.stop()


@suite.case('one_exact_ordinary_intent_approval_and_request_pins_are_atomic_without_new_consent_store', 'guided27 verification2')
def _():
    check('prepared' in shared, 'earlier exact preparation did not complete')
    f, prepared = main(), shared['prepared']; h = f['h']; iid = prepared['commit']['review']['intent_id']
    assert_unapproved(f, prepared); schema = records(h)['$schema']; files = private_files(h.home)
    result = h.cli('onboarding', 'join', 'commit', 'approve', '--stdin',
        input=compact({'flow_id': f['flow']['flow_id'], **body(f, prepared)}).decode(), timeout=8)
    check(result.ok, 'exact explicit CLI requester consent failed')
    approved = result.json; validate(f, approved, current=False); shared['approved'] = approved
    public(result.stdout + result.stderr, f['code'], f['reply'])
    check(approved['commit']['state'] == 'approved' and approved['commit']['review'] == prepared['commit']['review'] and
          approved['commit']['review_id'] == prepared['commit']['review_id'], 'approval replaced intent/terms/digest')
    coherent = records(h)
    intent_rows = coherent['dec_intents']; pending_rows = coherent['dec_pending']
    # Decode exact documented table layouts from one coherent read transaction.
    with closing(sqlite3.connect(f'file:{db_path(h)}?mode=ro', uri=True)) as db:
        intent_columns = [row[1] for row in db.execute('PRAGMA table_info(dec_intents)')]
        pending_columns = [row[1] for row in db.execute('PRAGMA table_info(dec_pending)')]
    ir = [dict(zip(intent_columns, row)) for row in intent_rows if dict(zip(intent_columns, row))['intent_id'] == iid]
    pr = [dict(zip(pending_columns, row)) for row in pending_rows if dict(zip(pending_columns, row))['request_id'] == f['rid']]
    check(len(ir) == len(pr) == 1, 'atomic approval lost exact ordinary rows')
    approved_record, pending_record = json.loads(ir[0]['record']), json.loads(pr[0]['record'])
    check(approved_record['approved'] is True and approved_record['approved_at'] != '-' and
          pending_record['commit_approved'] is True and pending_record['commit_intent_id'] == iid,
          'approval left half an ordinary intent/request consent or changed reference')
    check(coherent['$schema'] == schema and private_files(h.home) == files and len(intents(h, f['rid'])) == 1, 'approval added store/key or duplicate ordinary intent')
    # Signatures/frames may already be present from independently scheduled owned
    # work. No source attribution or global post-approval absence is inferred.
    shared['approved_signature_count'] = len(approved_record['signatures'])
    public(approved, f['code'], f['reply'])


def terminal_cleanup(f):
    h = f['h']
    advance_to(h, parse_time(f['view']['expires_at']) + timedelta(seconds=1))
    key = ssh_key(suite.work, 'unapproved-maintenance'); person = ssh_public_base64(key)
    status, spare = h.api('POST', '/v2/link/requests', {'mode': 'new', 'network_id': '-', 'person_public_key': person,
        'migration_proposal_id': '-', 'contact_invitation': '-', 'helpers': []})
    check(status == 201 and not spare['selection_approved'] and not spare['commit_approved'], 'ordinary unsigned expiry maintenance fixture')
    status, cancelled = h.api('POST', '/v2/link/requests/' + spare['request_id'] + '/cancel', {})
    check(status == 200 and cancelled['state'] == 'cancelled', 'maintenance request cancellation')


def terminal_delivery_baseline(h, issuer, network_id):
    # Public setup after both local applications. Register only the real pinned
    # participants; no consent/signing/provider work or private-record changes.
    for local, remote in ((h, issuer), (issuer, h)):
        local.ok('peer', 'add', '--id', remote.id, '--public-key', remote.public_key,
                 '--address', remote.peer_address)
    for local in (h, issuer):
        status, value = local.api('POST', '/v2/networks/' + network_id + '/sync', {}, timeout=35)
        check(status == 200 and value['unavailable'] == [],
              f'{local.name}: genuine terminal sync setup HTTP {status}')
    def retired():
        for local in (h, issuer):
            with closing(sqlite3.connect(f'file:{db_path(local)}?mode=ro', uri=True)) as db:
                if db.execute('SELECT count(*) FROM dec_outbox').fetchone()[0] != 0:
                    return False
            if list(local.state.glob('*-journal')):
                return False
        return True
    wait_for(retired, timeout=5, interval=.1,
             message='actual terminal proof outbox retirement and rollback-journal quiescence')


@suite.case('same_request_explicit_completion_then_keyless_detached_restart_expired_immutable_history', 'guided27 verification6')
def _():
    check('prepared' in shared and 'approved' in shared, 'earlier exact requester approval did not complete')
    f, prepared, approved = main(), shared['prepared'], shared['approved']; h, a = f['h'], f['a']
    a.relay.mode = h.relay.mode = 'pass'; a.start()
    commit(h, link_view(h, f['rid'])); wait_linked(h, a, f['rid'], timeout=25)
    check(link_view(h, f['rid'])['state'] == 'linked' and len(get(h, '/v2/networks')) == 1, 'separate ordinary requester completion failed')
    # No remaining phase needs original key material; remove the fixture's sole
    # external original file. It was never installed in the participant's home.
    terminal_delivery_baseline(h, a, f['network']['id'])
    f['key'].unlink(); a.stop(); terminal_cleanup(f); a.relay.mode = h.relay.mode = 'drop'; quiet(f)
    for action in ('lookup', 'prepare', 'approve'):
        same = op(f, action, prepared if action == 'approve' else None, pure=True)
        check(same['commit'] == approved['commit'] and same['request']['state'] == 'linked', 'application/expiry changed immutable approved consent')
    op(f, 'approve', prepared, status=409, code='review_changed', pure=True,
       data={**body(f, prepared), 'commit_review_id': 'review_' + 'f' * 64})
    h.ok('session', 'detach', f['parent']['review']['session_id'])
    same = op(f, 'approve', prepared, pure=True)
    check(same['commit'] == approved['commit'], 'explicit detachment lost approved history')
    h.restart(kill=True); quiet(f)
    for action in ('lookup', 'prepare', 'approve'):
        same = op(f, action, prepared if action == 'approve' else None, pure=True)
        check(same['commit'] == approved['commit'] and len(intents(h, f['rid'])) == 1, 'restart recreated or rebound approved intent/review')
    public(get(h, '/v1/activity?limit=1000'), f['code'], f['reply'])


suite.finish()
