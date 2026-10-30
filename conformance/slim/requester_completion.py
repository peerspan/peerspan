#!/usr/bin/env python3
"""Bounded already-approved requester completion, guided contract section28.

Independent public two-person/two-host ceremonies; no production imports.
Only schema-only dec_operations INSERT ABORT fault injection writes the DB;
all authority/protocol data comes from genuine public operations. Confirmed
live consumed ClientHello holds isolate pure measurements; every such interval
compares whole logical DB/state/home and BOTH complete carrier counters.
Application rollback permits preceding authorized signature/frame/publication
phases, but never partial network/provider/outcome/secret-retirement state.
Existing protocol barriers synchronize actual dispatch before parent/time
stimuli. Unsigned-stage expiry stays a source/barrier limit without reliable
public isolation: a partial-signature barrier is not a live transport hold.
Worker activity is global evidence, not attributed to this command.
External original keys are never installed in either requester daemon or its
agent; no seed/key deletion or worker-disabling fixture. Unavailable devices,
corrupt/pruned/root/adoption and microscopic final-key/commit crossings remain
source/fault limits without genuine public stimuli. No participant delivery,
agent access, connection/physical/installed/model readiness is inferred.
Existing23 suites and292 native cases remain unchanged. Foundation helpers
reuse prior independently authored requester_commit fixtures, copied here so
importing a previous eager-running suite is unnecessary.
"""
import base64
import hashlib
import http.client
import http.server
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
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from harness import (Adapter, Clock, Suite, UnixHTTPConnection, check, commit,
                     create_network, finalize, link_view, parse_time, pull_until,
                     rfc3339, select, ssh_key, ssh_public_base64, wait_for, wait_linked)

suite = Suite("requester_completion", __doc__)
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
    h.barrier = h.root / 'barriers'; h.barrier.mkdir(mode=0o700)
    h.extra_env = {'SSH_AUTH_SOCK': str(h.root / 'absent-agent.sock'), 'PEERSPAN_DEC_TEST_MODE': '1',
                   'PEERSPAN_DEC_TEST_BARRIER_DIR': str(h.barrier)}
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


DECISION = 'complete_requester_commit'
COMPLETION_KEYS = set('state review_id manifest_id activation_id outcome_id participant_delivery agent_access connection_readiness'.split())


def completion_endpoint(f):
    return endpoint(f, 'complete')


def completion_body(f, prepared):
    return {**body(f, prepared), 'decision': DECISION}


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


def validate_completion(f, value, prepared):
    check(type(value) is dict and set(value) == COMMIT_TOP | {'completion'}, 'closed completion wrapper')
    validate(f, {key: value[key] for key in COMMIT_TOP})
    check(value['commit'] == prepared['commit'] and value['commit']['state'] == 'approved',
          'completion changed immutable approved requester review/digest')
    completion = value['completion']; request = value['request']
    check(type(completion) is dict and set(completion) == COMPLETION_KEYS and
          completion['state'] == 'locally_applied' and completion['review_id'] == prepared['commit']['review_id'] and
          all(completion[key] == 'not_verified' for key in ('participant_delivery', 'agent_access', 'connection_readiness')),
          'completion overclaimed delivery/access/readiness or changed captured review')
    for key, prefix in (('manifest_id', 'dm_'), ('activation_id', 'da_'), ('outcome_id', 'dpk_')):
        check(re.fullmatch(prefix + '[0-9a-f]{64}', completion[key]) and completion[key] == request[key],
              'completion changed retained public reference: ' + key)
    check(request['state'] == 'linked' and request['commit_approved'] and request['completed'] == [
        'request_created', 'owner_offered', 'owner_selected', 'administrator_offered', 'owner_finalized',
        'commit_persisted', 'locally_applied'], 'success without exact local complete application')
    retained = operation(f['h'], f['rid'])
    check(retained is not None and retained['locally_applied'] == 1 and
          retained['network_id'] == f['network']['id'] and retained['context_id'] == f['network']['context_id'] and
          all(retained[key] == completion[key] for key in ('manifest_id', 'activation_id')),
          'success lacks independently retained application')
    public(value, f['code'], f['reply'])


def complete(f, prepared, *, status=200, code=None, pure=False, data=None):
    h = f['h']
    if pure:
        quiet(f); before, network = snapshot(h), traffic(f)
    actual, value = h.api('POST', completion_endpoint(f), completion_body(f, prepared) if data is None else data,
                          timeout=95)
    check(actual == status, f'completion HTTP {actual}, want {status}')
    if code:
        check(type(value) is dict and value.get('code') == code, 'completion expected controlled ' + code)
    if pure:
        after = snapshot(h)
        check(after == before, f'pure completion changed records/private files: {differences(before, after)}')
        check(traffic(f) == network, f'pure completion attempted carrier IO: before={network}, after={traffic(f)}')
    if actual == 200:
        validate_completion(f, value, prepared)
    else:
        public(value, f['code'], f['reply'], f['parent']['review']['project_root'], f['parent']['review']['native_session_id'])
    return value


def controls(f, name):
    directory = f['h'].barrier
    return {suffix: directory / (name + '.' + suffix) for suffix in ('arm', 'entered', 'continue')}


def marker(path, text):
    path.write_text(text); path.chmod(0o600)


def arm(f, name):
    files = controls(f, name)
    for path in files.values():
        path.unlink(missing_ok=True)
    marker(files['arm'], f['rid'] + '\n')
    return files


def reached(f, files):
    def entered():
        try:
            return files['entered'].read_text().strip() == f['rid']
        except FileNotFoundError:
            return False
    wait_for(entered, timeout=5, interval=.02, message='actual protocol barrier dispatch before stimulus')


def release(files):
    marker(files['continue'], 'continue\n')
    files['arm'].unlink(missing_ok=True)


def finish_F(f):
    a, h = f['a'], f['h']; a.relay.mode = h.relay.mode = 'pass'; a.start()
    finalize(h, f['view'], f['key'])
    view = pull_until(h, f['rid'], 'owner_finalization_id', timeout=20)
    check(view['state'] == 'needs_commit' and view['selection_approved'] and not view['commit_approved'] and
          all(view[key] == '-' for key in ('manifest_id', 'activation_id', 'outcome_id')), 'genuine uncommitted F fixture')
    pull_until(a, f['rid'], 'owner_finalization_id', timeout=15)
    a.stop(); a.relay.mode = h.relay.mode = 'drop'; f['view'] = view; quiet(f)
    record, _ = pending(h, f['rid'])
    packet = json.loads(base64.b64decode(record['owner_finalization_packet_base64'], validate=True))
    check(packet_id(packet) == view['owner_finalization_id'] and packet['signer_public_key'] == f['person'] and
          packet['writer_host_public_key'] == h.public_key and packet['authority_signature_format'] == 'sshsig' and
          packet['authority_signature'] != '-', 'genuine original finalization proof missing')
    f['F'] = json.loads(base64.b64decode(packet['payload_base64'], validate=True))


def application_proof(f, value):
    """Independent wire9 IDs and genuine host/device outcome signatures."""
    h, rid = f['h'], f['rid']; retained = operation(h, rid); record = retained['record']
    check(set(record) == {'format', 'activation_base64', 'catalog_base64', 'outcome_packet_base64', 'applied_at'} and
          record['format'] == 1, 'closed actual local application record')
    raw_activation = base64.b64decode(record['activation_base64'], validate=True)
    activation = json.loads(raw_activation); packet = activation['commit']
    contents = json.loads(base64.b64decode(packet['payload_base64'], validate=True))
    raw_manifest = base64.b64decode(contents['manifest_base64'], validate=True); manifest = json.loads(raw_manifest)
    manifest_id = 'dm_' + hashlib.sha256(('peerspan-decentralized-manifest-v1\n' +
                                        hashlib.sha256(raw_manifest).hexdigest()).encode()).hexdigest()
    activation_id = 'da_' + hashlib.sha256('\n'.join(('peerspan-decentralized-activation-v1',
        f['network']['context_id'], rid, manifest_id, packet_id(packet))).encode()).hexdigest()
    check(activation['format'] == 1 and activation['context_id'] == f['network']['context_id'] and
          manifest['request_id'] == rid and manifest['context_id'] == f['network']['context_id'] and
          activation_id == value['completion']['activation_id'] and manifest_id == value['completion']['manifest_id'],
          'independent exact manifest/activation identity failed')
    review = value['commit']['review']
    for key in ('request_packet_id', 'owner_offer_id', 'selection_id', 'administrator_offer_id', 'owner_finalization_id',
                'root_state_id', 'person_lease_id', 'host_lease_id', 'binding_lease_id', 'device_lease_id'):
        check(manifest[key] == review[key], 'application changed exact reviewed dependency: ' + key)
    for role, key in (('request', 'request_packet_id'), ('owner', 'owner_offer_id'), ('selection', 'selection_id'),
                      ('administrator', 'administrator_offer_id'), ('owner_finalization', 'owner_finalization_id')):
        check(packet_id(activation[role]) == review[key], 'activation substituted a retained transcript packet')
    check(packet['role'] == 'commit' and packet['request_id'] == rid and packet['writer_host_public_key'] == h.public_key and
          packet['signer_public_key'] == f['view']['device_public_key'], 'commit changed requester-owned signer')
    ed25519(h.public_key, packet['host_signature'], packet_message(packet), 'completion-commit-host')
    ed25519(f['view']['device_public_key'], packet['device_signature'], packet_message(packet), 'completion-commit-device')
    outcome = json.loads(base64.b64decode(record['outcome_packet_base64'], validate=True))
    outcome_value = json.loads(base64.b64decode(outcome['payload_base64'], validate=True))
    check(packet_id(outcome) == value['completion']['outcome_id'] and outcome['role'] == 'outcome' and
          outcome['writer_host_public_key'] == h.public_key and outcome['request_id'] == rid and
          outcome_value['manifest_id'] == manifest_id and outcome_value['activation_id'] == activation_id and
          outcome_value['activation_sha256'] == hashlib.sha256(raw_activation).hexdigest() and
          outcome_value['applied_at'] == record['applied_at'] and outcome_value['observed_root_state_id'] == review['root_state_id'],
          'actual signed application outcome disagrees with returned evidence')
    ed25519(h.public_key, outcome['host_signature'], packet_message(outcome), 'completion-outcome-host')
    current, secret = pending(h, rid)
    check(current['terminal'] == 'applied' and secret is None and current['outcome_packet_base64'] == record['outcome_packet_base64'],
          'application did not atomically retain outcome and retire pairing secret')
    check(len(get(h, '/v2/networks')) == 1, 'local application missing or adopted an extra network')
    with closing(sqlite3.connect(f'file:{db_path(h)}?mode=ro', uri=True)) as db:
        rows = db.execute('SELECT provider_kind,person_key,device_key,lease_id FROM dec_signers '
                          'WHERE network_id=? AND context_id=?', (f['network']['id'], f['network']['context_id'])).fetchall()
    check(rows == [('device', f['person'], f['view']['device_public_key'], review['device_lease_id'])],
          'application failed to select the exact requester device provider')
    events = get(h, '/v1/activity?limit=1000')
    check(len([event for event in events if event['kind'] == 'network.link_applied']) == 1, 'application did not emit exactly one event')


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
    for local, remote in ((h, issuer), (issuer, h)):
        local.ok('peer', 'add', '--id', remote.id, '--public-key', remote.public_key, '--address', remote.peer_address)
    for local in (h, issuer):
        status, value = local.api('POST', '/v2/networks/' + network_id + '/sync', {}, timeout=35)
        check(status == 200 and value['unavailable'] == [], 'genuine terminal sync setup')
    def retired():
        for local in (h, issuer):
            with closing(sqlite3.connect(f'file:{db_path(local)}?mode=ro', uri=True)) as db:
                if db.execute('SELECT count(*) FROM dec_outbox').fetchone()[0] != 0:
                    return False
            if list(local.state.glob('*-journal')):
                return False
        return True
    wait_for(retired, timeout=5, interval=.1, message='actual terminal outbox retirement and journal quiescence')


@suite.case('missing_unapproved_F_binding_cancellation_and_unknown_flow_refuse_without_new_consent', 'guided28 verification2')
def _():
    f = make_pair('main'); shared['main'] = f
    absent = {'commit': {'review_id': 'review_' + '0' * 64}}
    check(op(f, 'lookup', pure=True)['commit'] is None, 'pre-F lookup prepared requester intent')
    complete(f, absent, status=409, code='commit_completion_unavailable', pure=True)
    check(intents(f['h'], f['rid']) == [] and operation(f['h'], f['rid']) is None, 'missing F/intent produced consent/application')
    finish_F(f)
    prepared = op(f, 'prepare'); shared['prepared'] = prepared; assert_unapproved(f, prepared)
    complete(f, prepared, status=409, code='commit_completion_unavailable', pure=True)
    for patch in ({'join_review_id': 'review_' + '0' * 64}, {'commit_review_id': 'review_' + '0' * 64},
                  {'context': {**context(f['parent']), 'native_session_id': 'different-conversation'}},
                  {'context': {**context(f['parent']), 'project_root': str(suite.work / 'different root')}}):
        complete(f, prepared, status=409, code='review_changed', pure=True,
                 data={**completion_body(f, prepared), **patch})
    unknown = {**f, 'flow': {**f['flow'], 'flow_id': 'flow_' + '0' * 32}}
    complete(unknown, prepared, status=404, pure=True)
    assert_unapproved(f, prepared)
    negative = make_pair('cancel', live=False, approved=False, signed=False, admitted=False)
    status, value = negative['h'].api('POST', '/v2/link/requests/' + negative['rid'] + '/cancel', {})
    check(status == 200 and value['state'] == 'cancelled', 'genuine unapproved public cancellation')
    complete(negative, absent, status=409, code='commit_completion_unavailable', pure=True)
    check(intents(negative['h'], negative['rid']) == [] and operation(negative['h'], negative['rid']) is None,
          'cancelled completion created requester consent or application')
    negative['h'].stop()


@suite.case('strict_private_stdin_JSON_64KiB_methods_credential_and_no_startup_boundaries', 'guided28 verification5')
def _():
    check('prepared' in shared, 'genuine main preparation did not complete')
    f, prepared = main(), shared['prepared']; h = f['h']; data = completion_body(f, prepared); encoded = compact(data)
    maximum = encoded + b' ' * (65536 - len(encoded))
    quiet(f); before, network = snapshot(h), traffic(f)
    status, denied = raw_post(h, completion_endpoint(f), maximum)
    check(status == 409 and denied.get('code') == 'commit_completion_unavailable', 'exact64KiB body was not parsed as valid unapproved completion')
    check(snapshot(h) == before and traffic(f) == network, 'valid bound refusal changed state or attempted IO')
    public(denied, f['code'], f['reply'])
    ctx = compact(data['context']); canary = 'PRIVATE_COMPLETION_CANARY'
    malformed = [b'null', b'[]', b'{', encoded + b'{}', maximum + b' ',
        b'{"context":' + ctx + b',"context":' + ctx + b',"join_review_id":' + compact(data['join_review_id']) +
        b',"commit_review_id":' + compact(data['commit_review_id']) + b',"decision":' + compact(DECISION) + b'}',
        encoded.replace(b'"integration":"claude-code"', b'"integration":"claude-code","integration":"claude-code"'),
        encoded.replace(b'"decision":' + compact(DECISION), b'"decision":' + compact(DECISION) + b',"decision":' + compact(DECISION)),
        compact({**data, 'context': None}), compact({**data, 'join_review_id': None}), compact({**data, 'commit_review_id': 'review_bad'}),
        compact({**data, 'decision': None}), compact({**data, 'decision': 'approve'}),
        compact({key: value for key, value in data.items() if key != 'decision'}),
        compact({**data, 'context': {**data['context'], 'extra': canary}})]
    for field in ('code', 'key', 'path', 'provider', 'scopes', 'not_after', 'packet', 'grant', 'template', 'signature', 'owner_review_id'):
        malformed.append(compact({**data, field: canary}))
    for prefix in PREFIXES:
        malformed.append(compact({**data, 'context': {**data['context'], 'native_session_id': prefix + 'SHORTSECRET'}}))
    aggregate = snapshot(h)
    for index, raw in enumerate(malformed):
        quiet(f); before, network = snapshot(h), traffic(f)
        status, denied = raw_post(h, completion_endpoint(f), raw)
        check(status == 400 and denied.get('code') == 'invalid', f'malformed completion API variant{index}: HTTP {status}')
        public(denied, canary, 'SHORTSECRET', f['code'], f['reply'])
        check(snapshot(h) == before and traffic(f) == network, f'malformed API variant{index} changed records/files or carrier IO')
        quiet(f); before, network = snapshot(h), traffic(f)
        cli_raw = b'{"flow_id":' + compact(f['flow']['flow_id']) + b',' + raw[1:] if raw.startswith(b'{') else raw
        result = h.cli('onboarding', 'join', 'commit', 'complete', '--stdin', input=cli_raw.decode(), timeout=8)
        check(not result.ok, f'malformed completion CLI variant{index} accepted')
        public(result.stdout + result.stderr, canary, 'SHORTSECRET', f['code'], f['reply'], str(h.root))
        check(snapshot(h) == before and traffic(f) == network, f'malformed CLI variant{index} changed records/files or carrier IO')
    check(snapshot(h) == aggregate, 'malformed corpus changed any persisted record or private file')
    for method in ('GET', 'PUT', 'DELETE'):
        quiet(f); before, network = snapshot(h), traffic(f)
        status, denied = h.api(method, completion_endpoint(f))
        check(status == 405, f'alternate completion method{method}: HTTP {status}'); public(denied)
        check(snapshot(h) == before and traffic(f) == network, 'alternate method changed state or attempted IO')
    quiet(f); before, network = snapshot(h), traffic(f)
    invalid_path = BASE + '/flow_bad/commit/complete'
    status, denied = h.api('POST', invalid_path, data)
    check(status == 400 and denied.get('code') == 'invalid', 'malformed route flow ID was not invalid')
    public(denied, f['code'], f['reply'])
    check(snapshot(h) == before and traffic(f) == network, 'malformed route changed state or attempted IO')
    cli_data = compact({'flow_id': f['flow']['flow_id'], **data})
    for args in ((), ('--stdin', canary), ('--stdin', '--person-key', canary)):
        quiet(f); before, network = snapshot(h), traffic(f)
        result = h.cli('onboarding', 'join', 'commit', 'complete', *args, input=cli_data.decode(), timeout=8)
        check(not result.ok, 'completion accepted implicit stdin/private argv/provider option')
        public(result.stdout + result.stderr, canary, str(h.root))
        check(snapshot(h) == before and traffic(f) == network, 'CLI argument error changed state or attempted IO')
    missing = suite.host('nd', start=False); files = private_files(missing.root)
    result = missing.cli('onboarding', 'join', 'commit', 'complete', '--stdin', input=cli_data.decode(), timeout=8)
    check(not result.ok and private_files(missing.root) == files, 'completion initialized absent state or started daemon')
    public(result.stdout + result.stderr, str(missing.root))
    credential = h.ok('adapter', 'create', '--session', f['parent']['review']['session_id'], '--expires-at', rfc3339(h.now() + timedelta(hours=1)))
    adapter = Adapter(h, f['parent']['review']['agent'], f['parent']['review']['session_id'], credential)
    status, _ = adapter.call('POST', '/adapter/v1/connect', {'adapter_id': adapter.adapter_id, 'session_id': adapter.session_id, 'instance_id': adapter.instance})
    check(status == 200, 'genuine scoped credential fixture')
    status, denied = adapter.call('POST', completion_endpoint(f), data)
    check(status == 404, f'scoped adapter exposed private completion: HTTP {status}'); public(denied, adapter.token)
    peer, bootstrap = host('peer'), host('boot')
    for local, remote in ((h, peer), (peer, h)):
        local.ok('peer', 'add', '--id', remote.id, '--public-key', remote.public_key, '--address', remote.peer_address)
    result = subprocess.run([str(suite.probe_bin), '--state', str(peer.state), '--address', h.peer_address, '--alpn', 'peerspan-peer/1',
        '--method', 'POST', '--path', completion_endpoint(f), '--body-stdin'], input=compact(data), capture_output=True, timeout=8)
    check(result.returncode == 0 and json.loads(result.stdout)['status'] == 404, 'authenticated peer exposed private completion')
    cert, key = suite.work / 'boundary.pem', suite.work / 'boundary-key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ed25519', '-nodes', '-subj', '/CN=boundary', '-days', '1',
        '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True, timeout=5)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); tls.check_hostname = False; tls.verify_mode = ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key)); tls.set_alpn_protocols(['peerspan-bootstrap/1'])
    with socket.create_connection(('127.0.0.1', bootstrap.bootstrap_port), timeout=5) as raw:
        with tls.wrap_socket(raw, server_hostname='peerspan') as stream:
            payload_value = compact(data)
            stream.sendall((f'POST {completion_endpoint(f)} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(payload_value)}\r\n\r\n').encode() + payload_value)
            response = http.client.HTTPResponse(stream); response.begin(); response.read()
            check(response.status == 404, f'bootstrap exposed private completion: HTTP {response.status}')
    peer.stop(); bootstrap.stop(); assert_unapproved(f, prepared)


@suite.case('genuine_owned_signed_work_time_guards_lost_response_and_verified_exact_completion', 'guided28 verification1/2')
def _():
    check('prepared' in shared, 'genuine main preparation did not complete')
    f, prepared = main(), shared['prepared']; h = f['h']; schema = records(h)['$schema']; home = private_files(h.home)
    approved = op(f, 'approve', prepared); shared['approved'] = approved
    # Observe only ordinary already-authorized progress; never invoke Complete
    # or resume in a loop, and never attribute this worker's signatures to it.
    # The requester's genuine own first-contact mailbox remains reachable for
    # ordinary polling. Drop faults start after this signed/framed observation,
    # never as a substitute for the prerequisite successful carrier read.
    carriers = pending(h, f['rid'])[0]['carrier_endpoints']
    check(any(item['kind'] == 'participant' and item['address'] == h.relay.address and item['public_key'] == h.public_key
              for item in carriers), 'genuine requester mailbox endpoint was not retained by public setup')
    f['a'].relay.mode = 'drop'; h.relay.mode = 'pass'
    wait_for(lambda: pending(h, f['rid'])[0]['commit_packet_base64'] != '-' and commit_frames(h, f['rid']),
             timeout=15, interval=.1, message='genuine already-approved signed and framed requester commit retention')
    retained, _ = pending(h, f['rid']); existing = intent(h, prepared['commit']['review']['intent_id'])['record']
    signed_bytes = retained['commit_packet_base64']; existing_frames = commit_frames(h, f['rid'])
    check(existing['approved'] and existing['completed'] and existing['signatures'] and operation(h, f['rid']) is None,
          'already-signed requester fixture lacks exact signatures or already applied')
    original_offset = h.clock.offset
    moments = [(parse_time(existing['created_at']) - timedelta(seconds=120), 'commit_completion_unavailable'),
               (parse_time(f['view']['expires_at']) + timedelta(seconds=1), 'review_expired')]
    for moment, code in moments:
        quiet(f); before, network = snapshot(h), traffic(f); advance_to(h, moment)
        complete(f, approved, status=409, code=code)
        after = snapshot(h)
        check(after == before and traffic(f) == network,
              f'clock refusal/background changed state; offset cannot be restored: {differences(before, after)}')
        h.clock.set(original_offset)
    # Signed/framed work has already crossed the unsigned stage. Expiring its
    # finite human review cannot revoke or rewrite the recorded approval.
    after_review = parse_time(approved['commit']['review']['expires_at']) + timedelta(seconds=1)
    check(h.now() < after_review < min(parse_time(f['view']['expires_at']), parse_time(approved['commit']['review']['not_after'])),
          'genuine signed/framed fixture has no post-review/pre-protocol-deadline interval')
    for local in (h, f['a']):
        advance_to(local, after_review)
    f['a'].relay.mode = h.relay.mode = 'drop'
    with CompletionProxy(h) as proxy:
        proxy.lost = True
        raw = compact({'flow_id': f['flow']['flow_id'], **completion_body(f, approved)}).decode()
        result = subprocess.run([str(suite.host_bin), '--state', str(proxy.state), 'onboarding', 'join', 'commit', 'complete', '--stdin'],
            input=raw.encode(), capture_output=True, env=h.env, cwd=str(h.root), timeout=100)
        check(not result.returncode == 0 and not proxy.failure and len(proxy.calls) == 1 and
              proxy.calls[0] == ('POST', completion_endpoint(f), completion_body(f, approved)),
              'lost genuine completion response retried, changed private payload or failed before response')
        public(result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'), f['code'], f['reply'], str(proxy.state), str(h.root))
        status, completed = proxy.result
        check(status == 200, f'genuine approved completion failed before response loss: HTTP {status}')
        validate_completion(f, completed, approved); shared['completion'] = completed
    application_proof(f, completed)
    now = intent(h, prepared['commit']['review']['intent_id'])['record']
    remaining_frames = commit_frames(h, f['rid'])
    check(pending(h, f['rid'])[0]['commit_packet_base64'] == signed_bytes and
          now == {**existing, 'terminal': 'applied'} and len(intents(h, f['rid'])) == 1 and set(remaining_frames) <= set(existing_frames) and
          all(remaining_frames[key] == existing_frames[key] for key in remaining_frames),
          'completion replaced prior exact signature/template/consent/frame bytes instead of reusing them')
    check(records(h)['$schema'] == schema and private_files(h.home) == home, 'completion added schema/store/original key source')
    recovered = op(f, 'lookup')
    check(recovered['request']['state'] == 'linked' and recovered['commit'] == approved['commit'], 'pure lookup could not recover global application after lost response')


@suite.case('late_application_INSERT_abort_rolls_back_adoption_provider_outcome_event_and_secret_retirement', 'guided28 verification4')
def _():
    f = pair('fault'); shared['fault'] = f; h = f['h']; prepared = op(f, 'prepare')
    approved = op(f, 'approve', prepared); shared['fault_approved'] = approved
    check(operation(h, f['rid']) is None and get(h, '/v2/networks') == [], 'application fault started after an independent application')
    before = records(h); state_files, home_files = private_files(h.state), private_files(h.home)
    before_pending, secret = pending(h, f['rid']); iid = prepared['commit']['review']['intent_id']; before_intent = intent(h, iid)['record']
    with closing(sqlite3.connect(f'file:{db_path(h)}?mode=ro', uri=True)) as db:
        before_cap = db.execute('SELECT terminal_read_cap FROM dec_pending WHERE request_id=?', (f['rid'],)).fetchone()[0]
    check(re.fullmatch('link_[0-9a-f]{64}', f['rid']), 'unsafe genuine application-trigger selector')
    with closing(sqlite3.connect(db_path(h))) as db, db:
        db.execute("CREATE TRIGGER conformance_completion_abort BEFORE INSERT ON dec_operations WHEN NEW.request_id='" +
                   f['rid'] + "' BEGIN SELECT RAISE(ABORT,'PRIVATE_COMPLETION_ABORT'); END")
    try:
        actual, denied = h.api('POST', completion_endpoint(f), completion_body(f, approved), timeout=95)
        check(not 200 <= actual < 300, 'application INSERT ABORT was swallowed or reported as successful completion')
        public(denied, 'PRIVATE_COMPLETION_ABORT', f['code'], f['reply'])
    finally:
        with closing(sqlite3.connect(db_path(h))) as db, db:
            db.execute('DROP TRIGGER conformance_completion_abort')
    quiet(f); after = records(h); after_pending, after_secret = pending(h, f['rid'])
    # Earlier authorized signatures/materialization/carrier-frame sealing and
    # their clock may persist. The proof-publication outbox is an application
    # effect and rolls back with authority/provider/owned keys/metadata/events.
    earlier_phase_tables = {'dec_intents', 'dec_pending', 'dec_frames', 'dec_clock'}
    for table in set(before) | set(after):
        if table not in earlier_phase_tables:
            check(before.get(table) == after.get(table), 'failed application changed nonphase table: ' + table)
    check(private_files(h.state) == state_files and private_files(h.home) == home_files, 'failed application left a private file/key/journal')
    check(operation(h, f['rid']) is None and get(h, '/v2/networks') == [] and after_secret == secret and secret is not None and
          after_pending['terminal'] == before_pending['terminal'] == '-' and
          after_pending['outcome_packet_base64'] == '-', 'failed application left partial outcome/adoption/secret retirement')
    with closing(sqlite3.connect(f'file:{db_path(h)}?mode=ro', uri=True)) as db:
        check(db.execute('SELECT terminal_read_cap FROM dec_pending WHERE request_id=?', (f['rid'],)).fetchone()[0] == before_cap,
              'failed application left a partial terminal read capability')
        check(db.execute("SELECT count(*) FROM dec_frames WHERE request_id=? AND role='outcome'", (f['rid'],)).fetchone()[0] == 0,
              'failed application retained an outcome frame')
    after_intent = intent(h, iid)['record']
    check(all(after_intent[key] == before_intent[key] for key in ('operation_id', 'approved', 'approved_at', 'review_base64', 'provider', 'created_at', 'expires_at')) and
          all(signature in after_intent['signatures'] for signature in before_intent['signatures']) and len(intents(h, f['rid'])) == 1,
          'application rollback changed the earlier exact ordinary approval/signatures')
    same = op(f, 'lookup', pure=True)
    check(same['commit'] == approved['commit'], 'application fault lost immutable consent recovery')


@suite.case('actual_pre_application_barrier_rechecks_changed_parent_before_the_final_transaction', 'guided28 verification3')
def _():
    check('fault' in shared and 'fault_approved' in shared, 'genuine application rollback fixture did not complete')
    f, approved = shared['fault'], shared['fault_approved']; h = f['h']
    check(operation(h, f['rid']) is None, 'barrier stimulus began after another valid application')
    files = arm(f, 'dec.apply.before_transaction'); f['a'].relay.mode = h.relay.mode = 'drop'
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(h.api, 'POST', completion_endpoint(f), completion_body(f, approved), timeout=95)
        try:
            reached(f, files)
            check(operation(h, f['rid']) is None, 'application happened before actual before-transaction barrier')
            h.ok('session', 'detach', f['parent']['review']['session_id'])
            quiet(f); before, network = snapshot(h), traffic(f)
            release(files)
            actual, denied = future.result(timeout=5)
            check(actual == 409 and denied.get('code') == 'review_changed', f'changed pre-application parent HTTP {actual}')
            public(denied, f['code'], f['reply'])
            after = snapshot(h)
            check(after == before, f'late changed parent wrote after final guard: {differences(before, after)}')
            check(traffic(f) == network, 'late changed parent attempted further carrier IO')
            check(operation(h, f['rid']) is None and get(h, '/v2/networks') == [], 'late changed parent allowed new local application')
        finally:
            release(files)
    same = op(f, 'lookup', pure=True)
    check(same['commit'] == approved['commit'], 'context loss revoked or rewrote historical requester consent')
    h.stop()


@suite.case('pure_verified_completed_API_CLI_replay_after_detach_restart_expiry_with_original_sources_absent', 'guided28 verification6')
def _():
    check('approved' in shared and 'completion' in shared, 'genuine local application did not complete')
    f, approved, baseline = main(), shared['approved'], shared['completion']; h, a = f['h'], f['a']
    a.relay.mode = h.relay.mode = 'pass'; a.start()
    # This separate ordinary repair checks actual participant application. It is
    # not attributed to the completion marker or needed to claim local success.
    status, repaired = h.api('POST', '/v2/link/requests/' + f['rid'] + '/resume', {}, timeout=35)
    check(status == 200 and repaired['state'] == 'linked', 'one explicit completed-requester delivery repair failed')
    public(repaired, f['code'], f['reply'])
    wait_linked(a, f['rid'], timeout=25)
    terminal_delivery_baseline(h, a, f['network']['id'])
    a.stop(); terminal_cleanup(f); a.relay.mode = h.relay.mode = 'drop'; quiet(f)
    check(not (h.home / '.config/peerspan/person_ed25519').exists() and not (h.root / 'absent-agent.sock').exists(),
          'external original unexpectedly installed in requester daemon or agent')
    for phase in ('expired', 'detached', 'restarted'):
        if phase == 'detached':
            h.ok('session', 'detach', f['parent']['review']['session_id'])
        elif phase == 'restarted':
            h.restart(kill=True); quiet(f)
        for mode in ('API', 'CLI'):
            quiet(f); before, network = snapshot(h), traffic(f)
            if mode == 'API':
                value = complete(f, approved)
            else:
                raw = compact({'flow_id': f['flow']['flow_id'], **completion_body(f, approved)})
                raw += b' ' * (65536 - len(raw))
                result = h.cli('onboarding', 'join', 'commit', 'complete', '--stdin', input=raw.decode(), timeout=8)
                check(result.ok, 'completed private CLI replay failed: ' + phase)
                public(result.stdout + result.stderr, str(h.root), f['code'], f['reply'])
                value = result.json; validate_completion(f, value, approved)
            check(value['completion'] == baseline['completion'] and value['commit'] == baseline['commit'], 'history changed exact completion/consent')
            after = snapshot(h)
            check(after == before, f'{phase} completed{mode} replay changed DB/state/home: {differences(before, after)}')
            check(traffic(f) == network, f'{phase} completed{mode} replay performed carrier IO')
        complete(f, approved, status=409, code='review_changed', pure=True,
                 data={**completion_body(f, approved), 'commit_review_id': 'review_' + 'f' * 64})
    application_proof(f, baseline)
    public(get(h, '/v1/activity?limit=1000'), f['code'], f['reply'])


suite.finish()
