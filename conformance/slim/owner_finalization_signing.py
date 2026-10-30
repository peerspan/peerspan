#!/usr/bin/env python3
"""Bounded original finalization signing, guided contract section25.

Independent real two-host/two-person ceremonies, genuine SSH agents and
public owner/signing boundaries. Host proxy faults derive from authentic typed
views/templates; no production imports or fabricated protocol/authority rows.
Live pure observations require the same consumed authentic ClientHello/socket
held outside DB throughout measurement; all logical DB/state/home and both
relay counters remain strict. This section26b setup correction preserves every
case assertion, delay and timeout. Observable agent operations and submitted/retained issuer
signatures do not count internal generated-key calls. At most one explicit
recovery invocation follows proven B/D retention and external public F readiness;
no sign-until-green or hidden protocol driver. Public clock/maintenance and
retirement isolate historical purity. Microscopic final-dispatch races, exact
file-open syscalls, installed/physical/native/model acceptance remain source or
separate gates. No requester commit or membership follows from F alone.
"""
import base64
import copy
import http.server
import os
import shutil
import stat
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

from harness import (Result, Adapter, Clock, Suite, UnixHTTPConnection, check, commit,
                     create_network, finalize, link_view, parse_time, pull_until,
                     rfc3339, select, ssh_key, ssh_public_base64, wait_for, wait_linked)

suite = Suite("owner_finalization_signing", __doc__)
BASE = "/v1/onboarding/join-flows"
PROJECT = "/v1/onboarding/project-flows"
PREFIXES = ('psi2-', 'psl2-', 'peerspan-invite-v1.', 'peerspan-member-invite-v1.',
            'peerspan-person-invite-v1.', 'token_', 'instance_')
EFFECTS = {"verify_original_owner": True, "verify_requester_selection": True,
           "verify_administrator_admission": True, "verify_owner_finalization_bounds": True,
           "prepare_finalization": False, "sign_original": False, "publish_finalization": False,
           "commit_request": False, "grant_membership": False, "grant_agent_access": False,
           "share_files": False, "share_conversation": False, "capability_calls": False}
INSPECTION_TOP = set("version host_id flow_id join_review_id owner_review_id context observed_at request review_id review next_action".split())
INSPECTION_REVIEW = set("version kind host_id context flow_id join_review_id owner_review_id request_id intent_id network member person_public_key host_public_key device_public_key request_packet_id owner_offer_id selection_id administrator_offer_id root_state_id person_lease_id host_lease_id administrator scopes binding_scopes not_after created_at expires_at effects".split())
LINK_KEYS = set("request_id role mode state network_id context_id migration_proposal_id person_public_key host_public_key device_public_key created_at expires_at request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id manifest_id activation_id outcome_id selection_approved commit_approved completed attention next".split())
shared = {}

OWNER_TOP = set("version host_id flow_id join_review_id context observed_at request owner".split())
OWNER_REVIEW = set("version kind host_id context flow_id join_review_id request_id intent_id network member person_public_key host_public_key device_public_key proposed_owner_offer_id scopes not_after expires_at effects".split())
OWNER_EFFECTS = {"approve_owner_intent": True, "authorize_original_signature": True, "authorize_bounded_owner_finalization": True, "auto_select_single_offer_after_signature": True, "publish_owner_offer_after_signature": True, "grant_membership": False, "grant_agent_access": False, "approve_network_administrator": False, "commit_request": False, "share_files": False, "share_conversation": False, "capability_calls": False}

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


def validate_inspection(f, value):
    h, flow = f['h'], f['flow']; owner_review = f['owner']['owner']['review']; rid = f['rid']
    check(type(value) is dict and set(value) == INSPECTION_TOP and type(value['version']) is int and value['version'] == 1, 'closed finalization wrapper')
    check(value['host_id'] == h.id and value['flow_id'] == flow['flow_id'] and value['join_review_id'] == flow['review_id'] and
          value['owner_review_id'] == f['owner']['owner']['review_id'] and value['context'] == context(f['parent']), 'exact finalization wrapper binding')
    check(re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value['observed_at']) and
          abs((parse_time(value['observed_at']) - h.now()).total_seconds()) < 5, 'whole-second guarded observation')
    view, review = value['request'], value['review']
    check(set(view) == LINK_KEYS and view == link_view(h, rid), 'exact retained public LINK_VIEW')
    check(set(review) == INSPECTION_REVIEW and type(review['version']) is int and review['version'] == 1 and review['kind'] == 'inspect_new_original_finalization', 'closed finalization review')
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


def inspect(f, *, status=200, code=None, body=None, path=None, pure=True):
    h = f['h']
    if pure:
        quiet(f); before, network = snapshot(h), traffic(f)
    actual, value = h.api('POST', path or endpoint(f), payload(f) if body is None else body)
    check(actual == status, f'finalization inspect HTTP {actual}, want {status}')
    if code:
        check(isinstance(value, dict) and value.get('code') == code, f'finalization error code {value.get("code") if isinstance(value, dict) else None}, want {code}')
    if pure:
        after, after_network = snapshot(h), traffic(f)
        check(after == before, f'pure finalization inspection changed state: {differences(before, after)}; relay_changed={network != after_network}')
        check(after_network == network, f'pure finalization inspection attempted carrier IO; before={network}, after={after_network}')
    if status == 200:
        validate_inspection(f, value)
    else:
        public(value, f['code'], f.get('reply', ''))
    return value


def intent(h, intent_id):
    with closing(sqlite3.connect(f"file:{db_path(h)}?mode=ro", uri=True)) as db:
        row = db.execute("SELECT network_id,context_id,kind,record,secret FROM dec_intents WHERE intent_id=?", (intent_id,)).fetchone()
    check(row is not None, "review references no ordinary durable intent")
    return {"network_id": row[0], "context_id": row[1], "kind": row[2], "record": json.loads(row[3]), "secret": row[4]}


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class HostProxy:
    """HTTP boundary faults on authentic responses, never protocol-row edits."""
    def __init__(self, h, name):
        self.host = h; self.state = suite.work / name
        self.state.mkdir(mode=0o700)
        self.calls = []; self.mutate = lambda method, endpoint, body, status, value: (status, value)
        self.drop_signed = False
        outer = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def handle_request(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                body = json.loads(raw) if raw else None
                outer.calls.append((self.command, self.path, copy.deepcopy(body)))
                conn = UnixHTTPConnection(str(h.state / "admin.sock"), timeout=10)
                try:
                    conn.request(self.command, self.path, body=raw if raw else None,
                                 headers={"Content-Type": "application/json"} if raw else {})
                    response = conn.getresponse(); data = response.read(); status = response.status
                finally:
                    conn.close()
                value = json.loads(data) if data else None
                status, value = outer.mutate(self.command, self.path, body, status, copy.deepcopy(value))
                if self.path.endswith("/signed") and outer.drop_signed:
                    outer.drop_signed = False
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                data = compact(value) if value is not None else b""
                self.send_response(status); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data))); self.send_header("Connection", "close")
                self.end_headers(); self.wfile.write(data)
            do_GET = handle_request
            do_POST = handle_request
        self.server = UnixServer(str(self.state / "admin.sock"), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)

    def __enter__(self):
        self.thread.start(); return self

    def __exit__(self, *_args):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)

    @property
    def submissions(self):
        return [body for method, endpoint, body in self.calls if method == "POST" and endpoint.endswith("/signed")]


def read_exact(stream, size):
    value = bytearray()
    while len(value) < size:
        chunk = stream.recv(size - len(value))
        if not chunk:
            raise EOFError("closed agent frame")
        value.extend(chunk)
    return bytes(value)


def ssh_string(value, offset=0):
    size = int.from_bytes(value[offset:offset + 4], "big")
    return value[offset + 4:offset + 4 + size], offset + 4 + size


class AgentProxy:
    """Counts messages while forwarding to a real ssh-agent with genuine keys."""
    def __init__(self, name, keys):
        self.actual = suite.work / (name + "a.sock"); self.path = suite.work / (name + "p.sock")
        log = (suite.work / (name + "-agent.log")).open("ab")
        self.process = suite.spawn(["ssh-agent", "-D", "-a", str(self.actual)], stdout=log, stderr=log)
        log.close(); wait_for(lambda: self.actual.exists(), timeout=5, message="real SSH agent socket")
        for key in keys:
            result = subprocess.run(["ssh-add", str(key)], env={**os.environ, "SSH_AUTH_SOCK": str(self.actual)}, capture_output=True, timeout=5)
            check(result.returncode == 0, "real ssh-add fixture failed")
        self.messages = []; self.errors = []; self.before = lambda _kind: None
        outer = self
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as remote:
                        remote.settimeout(15); remote.connect(str(outer.actual))
                        while True:
                            prefix = read_exact(self.request, 4); size = int.from_bytes(prefix, "big")
                            check(0 < size <= 1_048_576, "bounded real agent request")
                            message = read_exact(self.request, size)
                            outer.messages.append(message); outer.before(message[0])
                            remote.sendall(prefix + message)
                            prefix = read_exact(remote, 4); answer = read_exact(remote, int.from_bytes(prefix, "big"))
                            self.request.sendall(prefix + answer)
                except (EOFError, ConnectionError, OSError):
                    return
                except Exception as error:
                    outer.errors.append(type(error).__name__)
        self.server = UnixServer(str(self.path), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)

    def __enter__(self):
        self.thread.start(); return self

    def __exit__(self, *_args):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)
        check(not self.errors, f"real agent boundary fixture failed: {self.errors}")

    @property
    def signatures(self):
        return [message for message in self.messages if message[0] == 13]


def generated_path(h):
    return h.home / ".config" / "peerspan" / "person_ed25519"


def validate_owner(h, flow, value, *, owner_required=True):
    check(type(value) is dict and set(value) == OWNER_TOP and type(value["version"]) is int and value["version"] == 1,
          "exact owner wrapper shape/version")
    check(value["host_id"] == h.id and value["flow_id"] == flow["flow_id"] and
          value["join_review_id"] == flow["review_id"] and value["context"] == flow["review"]["context"],
          "owner wrapper changed exact host/publication/context binding")
    check(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value["observed_at"]) and
          abs((parse_time(value["observed_at"]) - h.now()).total_seconds()) < 5, "guarded whole-second observation time")
    rid = flow["outcome"]["request_id"]
    check(value["request"] == get(h, "/v2/link/requests/" + rid), "owner response is not exact ordinary LINK_VIEW")
    if value["owner"] is None:
        check(not owner_required, "missing prepared owner review")
        public(value); return
    owner = value["owner"]
    check(set(owner) == {"review_id", "review", "state", "next_action"}, "exact owner object shape")
    review = owner["review"]
    check(set(review) == OWNER_REVIEW and type(review["version"]) is int and review["version"] == 1 and
          review["kind"] == "approve_new_original_owner", "exact new-original review shape")
    nested = flow["review"]["invitation"]
    check(review["host_id"] == h.id and review["flow_id"] == flow["flow_id"] and review["join_review_id"] == flow["review_id"] and
          review["context"] == flow["review"]["context"] and review["request_id"] == rid,
          "review changed exact consent context/request")
    check(review["network"] == nested["network"] and review["member"] == nested["invitation"]["member"] and
          review["person_public_key"] == flow["review"]["person_public_key"] and review["host_public_key"] == h.public_key and
          review["device_public_key"] == value["request"]["device_public_key"], "review changed signed identity/descriptor/label")
    check(re.fullmatch(r"dint_[0-9a-f]{32}", review["intent_id"]) and re.fullmatch(r"dpk_[0-9a-f]{64}", review["proposed_owner_offer_id"]),
          "malformed ordinary intent/proposed packet reference")
    check(type(review["scopes"]) is int and review["scopes"] == 7 and review["effects"] == OWNER_EFFECTS and
          all(type(item) is bool for item in review["effects"].values()), "owner review widened authority/effects")
    record = intent(h, review["intent_id"])["record"]
    check(parse_time(review["not_after"]) == parse_time(value["request"]["created_at"]) + timedelta(days=7), "fixed signed-request seven-day target lifetime")
    check(parse_time(review["expires_at"]) == min(parse_time(value["request"]["expires_at"]), parse_time(record["created_at"]) + timedelta(minutes=15)),
          "owner review extended its immutable decision deadline")
    check(owner["review_id"] == digest("peerspan-onboarding-original-owner-review-v1", review), "canonical recursive UTF-8 owner digest")
    actions = {"review": "approve_owner_intent", "cancelled": "inspect_join_progress", "expired": "inspect_join_progress",
               "invalidated": "inspect_join_progress"}
    if owner["state"] == "approved":
        expected = "provide_original_signature" if value["request"]["owner_offer_id"] == "-" else "follow_join_progress"
    else:
        check(owner["state"] in actions, "unknown owner state")
        expected = actions[owner["state"]]
    check(owner["next_action"] == expected, "owner state/action claims a completed stage or omits next consent")
    public(value)



fixtures = {}


def fixture(name):
    if name not in fixtures:
        f = make_pair(name)
        f['inspection'] = inspect(f)
        f['ordinary'] = ready_view(f, 'issuers')
        fixtures[name] = f
    return fixtures[name]


def ready_view(f, phase):
    def ready():
        status, value = f['h'].api('GET', '/v2/link/requests/' + f['rid'] + '/approval')
        check(status == 200, f'ordinary public readiness HTTP {status}')
        slots = value['signing_requests']
        if phase == 'issuers' and any(r['slot_id'] in (2, 3) and r['role'] == 'issuer' for r in slots):
            return value
        if phase == 'F' and any(r['slot_id'] == 4 and r['role'] == 'authority' for r in slots):
            return value
        return None
    return wait_for(ready, timeout=10, interval=.1, message='ordinary approved worker ' + phase + ' readiness (no resume)')


def install_key(f, key=None):
    target = generated_path(f['h'])
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True); target.parent.chmod(0o700)
    target.write_bytes((key or f['key']).read_bytes()); target.chmod(0o600)
    return target


def decision(f):
    return {'flow_id': f['flow']['flow_id'], **payload(f), 'finalization_review_id': f['inspection']['review_id'],
            'decision': 'sign_original_finalization'}


def command(f, *, proxy=None, agent=None, data=None, env=None, stdin=True, args=()):
    h = f['h']; body = compact(decision(f)) if data is None else data
    environment = {**h.env, 'SSH_AUTH_SOCK': str(agent.path if agent else h.root / 'absent-agent.sock'), **(env or {})}
    argv = [str(suite.host_bin), '--state', str(proxy.state if proxy else h.state), 'onboarding', 'join', 'owner', 'finalization', 'sign']
    if stdin:
        argv.append('--stdin')
    argv.extend(args)
    result = subprocess.run(argv, input=body, env=environment, cwd=h.root, capture_output=True, timeout=95)
    for marker in (b'PRIVATE_SIGNING_MARKER', b'PRIVATE_AGENT_COMMENT', b'BEGIN OPENSSH PRIVATE KEY',
        str(generated_path(h)).encode(), str(environment['SSH_AUTH_SOCK']).encode(),
        str((proxy.state if proxy else h.state) / 'admin.sock').encode(), str(h.home / '.config').encode()):
        check(marker not in result.stdout + result.stderr, 'bounded finalization output leaked input/key/provider material')
    answer = Result(argv, result.returncode, result.stdout.decode(errors='replace'), result.stderr.decode(errors='replace'))
    public(answer.stdout + answer.stderr, f['code'], f['reply'])
    if answer.ok:
        check(type(answer.json) is dict and set(answer.json) == OWNER_TOP | {'original_finalization'}, 'closed finalization signing outcome')
        proof = answer.json['original_finalization']
        check(set(proof) == {'state', 'review_id', 'packet_id'} and proof['state'] == 'recorded' and
              proof['review_id'] == f['inspection']['review_id'] and re.fullmatch(r'dpk_[0-9a-f]{64}', proof['packet_id']), 'exact recorded-F proof')
        validate_owner(h, f['flow'], {k: v for k, v in answer.json.items() if k != 'original_finalization'})
        check(answer.json['owner']['review'] == f['owner']['owner']['review'] and answer.json['owner']['review_id'] == f['owner']['owner']['review_id'] and
              answer.json['request']['owner_finalization_id'] == proof['packet_id'], 'F outcome changed immutable owner/packet binding')
    return answer


def check_batches(f, batches, *, first='issuers'):
    check(0 < len(batches) <= 2, 'one invocation exceeded two submissions or supplied no genuine proof')
    total = 0
    for index, batch in enumerate(batches):
        check(set(batch) == {'intent_id', 'signatures'} and batch['intent_id'] == f['owner']['owner']['review']['intent_id'], 'mixed ordinary intent/submission shape')
        entries = batch['signatures']; total += len(entries)
        identities = [(entry['slot_id'], entry['role']) for entry in entries]
        check(all(set(entry) == {'slot_id', 'role', 'signature'} for entry in entries), 'submission exposed extra protocol authority')
        if first == 'F' or index:
            check(identities == [(4, 'authority')], 'dependent batch signed host/commit/foreign work')
        else:
            check(identities in ([(2, 'issuer')], [(3, 'issuer')], [(2, 'issuer'), (3, 'issuer')]), 'B/D batch mixed phases/order/roles')
    check(total <= 3, 'one invocation exceeded three original signatures')


def assert_no_driver(proxy, start=0):
    calls = proxy.calls[start:]
    check(not any(path.endswith(('/resume', '/finalization', '/commit', '/selection', '/admissions')) for _, path, _ in calls), 'CLI drove protocol preparation/consent/transport')
    check(sum(method == 'GET' and path.endswith('/approval') for method, path, _ in calls) <= 2, 'CLI polled ordinary readiness')
    check(len([1 for method, path, _ in calls if method == 'POST' and path.endswith('/signed')]) <= 2, 'CLI retried/submitted excess batches')


def retained(f, slot):
    entries = intent(f['h'], f['owner']['owner']['review']['intent_id'])['record']['signatures']
    role = 'authority' if slot == 4 else 'issuer'
    return [entry for entry in entries if entry['slot_id'] == slot and entry['role'] == role]


def verify_sshsig(f, signature, message, label):
    allowed = suite.work / ('allowed-' + label)
    key = subprocess.run(['ssh-keygen', '-y', '-P', '', '-f', str(f['key'])], capture_output=True, check=True, timeout=5).stdout
    allowed.write_bytes(b'fixture ' + key); allowed.chmod(0o600)
    path = suite.work / (label + '.sshsig')
    path.write_text('-----BEGIN SSH SIGNATURE-----\n' + '\n'.join(signature[i:i + 70] for i in range(0, len(signature), 70)) + '\n-----END SSH SIGNATURE-----\n'); path.chmod(0o600)
    result = subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', str(allowed), '-I', 'fixture', '-n', 'peerspan-person-v1', '-s', str(path)],
        input=message, capture_output=True, timeout=5)
    check(result.returncode == 0, 'independent actual original SSHSIG verification failed: ' + label)


def verify_F(f):
    def complete():
        view = link_view(f['h'], f['rid'])
        return view if view['owner_finalization_id'] != '-' else None
    view = wait_for(complete, timeout=10, interval=.1, message='ordinary retained F after explicit bounded submission (no resume)')
    record, _ = pending(f['h'], f['rid'])
    packet = json.loads(base64.b64decode(record['owner_finalization_packet_base64'], validate=True))
    check(packet_id(packet) == view['owner_finalization_id'] and packet['role'] == 'owner_finalization' and packet['signer_public_key'] == f['person'] and
          packet['writer_host_public_key'] == f['h'].public_key and packet['issuer_id'] == '-' and packet['authority_signature_format'] == 'sshsig', 'retained F changed original target/writer')
    verify_sshsig(f, packet['authority_signature'], packet_message(packet), 'F-' + f['h'].name)
    value = json.loads(base64.b64decode(packet['payload_base64'], validate=True)); expected = f['inspection']['review']
    for key in ('selection_id', 'administrator_offer_id', 'root_state_id', 'person_lease_id', 'host_lease_id'):
        check(value[key] == expected[key], 'retained F changed independently verified parent: ' + key)
    for slot, name, scopes in ((2, 'binding_lease', 2), (3, 'device_lease', 7)):
        envelope = value[name]; payload_value = json.loads(base64.b64decode(envelope['payload_base64'], validate=True))
        check(payload_value['operation_id'] == f['rid'] and payload_value['root_state_id'] == expected['root_state_id'] and
              payload_value['subject']['person_public_key'] == f['person'] and payload_value['subject']['host_public_key'] == f['h'].public_key and
              payload_value['subject']['device_public_key'] == ('-' if slot == 2 else f['inspection']['request']['device_public_key']) and
              payload_value['subject']['member'] == '-' and payload_value['subject']['scopes'] == scopes and payload_value['not_after'] == expected['not_after'] and
              payload_value['issuer'] == {'kind': 'person', 'person_public_key': f['person']} and
              payload_value['issued_at'] == payload_value['not_before'] and
              parse_time(expected['created_at']) <= parse_time(payload_value['issued_at']) <= f['h'].now(), 'retained B/D widened exact target/profile/end/issuer/time')
        parents = {'subject_person': expected['person_lease_id'], 'subject_host': expected['host_lease_id'], 'issuer_person': expected['person_lease_id']}
        if slot == 3:
            parents['subject_binding'] = statement_id(value['binding_lease'])
        check({p['role']: p['id'] for p in payload_value['parents']} == parents and len(payload_value['parents']) == len(parents), 'retained B/D gained foreign/delegated parents')
        signatures = [s for s in envelope['signatures'] if s['role'] == 'issuer']
        check(len(signatures) == 1 and signatures[0]['public_key'] == f['person'] and signatures[0]['format'] == 'sshsig' and len(retained(f, slot)) == 1, 'missing/duplicate genuine issuer proof')
        message = '\n'.join(('peerspan-decentralized-signature-v1', statement_id(envelope), 'issuer', f['person'])).encode()
        verify_sshsig(f, signatures[0]['signature'], message, name + '-' + f['h'].name)
    check(len(retained(f, 4)) == 1 and retained(f, 4)[0]['signature'] == packet['authority_signature'], 'retained F authority duplicated/replaced')
    check(view['state'] == 'needs_commit' and not view['commit_approved'] and get(f['h'], '/v2/networks') == [], 'bounded F committed/adopted/granted access')
    return view


def complete_once(f, proxy, *, agent=None, agent_signatures=3):
    at = len(proxy.calls); start = len(proxy.submissions); sigs = len(agent.signatures) if agent else 0
    answer = command(f, proxy=proxy, agent=agent); first = proxy.submissions[start:]
    check_batches(f, first); assert_no_driver(proxy, at)
    if len(first) == 1 and first[0]['signatures'][0]['slot_id'] in (2, 3):
        check(not answer.ok and not retained(f, 4), 'uncertain issuer-only outcome claimed or signed F')
        check(len(retained(f, 2)) == len(retained(f, 3)) == 1, 'issuer-only recovery lacked proven retained B/D')
        ready_view(f, 'F')
        at = len(proxy.calls); start = len(proxy.submissions)
        answer = command(f, proxy=proxy, agent=agent)
        check_batches(f, proxy.submissions[start:], first='F'); assert_no_driver(proxy, at)
    verify_F(f)
    if agent:
        check(len(agent.signatures) - sigs == agent_signatures, 'genuine complete B/D/F sequence signed duplicate/extra original objects')
    return answer


def keyless_refusal(f, proxy, agent=None, *, data=None):
    quiet(f); before, network = snapshot(f['h']), traffic(f)
    at = len(proxy.calls); messages = len(agent.messages) if agent else 0; submitted = len(proxy.submissions)
    answer = command(f, proxy=proxy, agent=agent, data=data)
    check(not answer.ok, 'already recorded F claimed fresh signing success')
    calls = proxy.calls[at:]
    check(len(calls) == 1 and calls[0][0] == 'POST' and calls[0][1].endswith('/owner/lookup'), 'recorded F refusal did more than pure owner lookup')
    check(len(proxy.submissions) == submitted and (agent is None or len(agent.messages) == messages), 'recorded F refusal touched ordinary signing/key/agent')
    after = snapshot(f['h'])
    check(after == before, f'recorded F refusal changed DB/files: {differences(before, after)}')
    check(traffic(f) == network, 'recorded F refusal attempted carrier IO')
    return answer


def settle_F(f):
    # Explicit ordinary transport setup AFTER the CLI, never hidden CLI work.
    f['a'].relay.mode = f['h'].relay.mode = 'pass'; f['a'].start()
    pull_until(f['a'], f['rid'], 'owner_finalization_id', timeout=15)
    f['a'].stop(); f['a'].relay.mode = f['h'].relay.mode = 'drop'; quiet(f)


def alter_packets(view, change):
    for slot in view['signing_requests']:
        if slot['object_type'] != 'owner_finalization_packet': continue
        packet = json.loads(base64.b64decode(slot['template_base64'])); change(packet)
        slot['template_base64'] = base64.b64encode(compact(packet)).decode(); slot['object_id'] = packet_id(packet)
        slot['message_base64'] = base64.b64encode(packet_message(packet)).decode()


def alter_statements(view, change):
    for slot in view['signing_requests']:
        if slot['object_type'] not in ('binding_lease', 'device_lease'): continue
        envelope = json.loads(base64.b64decode(slot['template_base64']))
        value = json.loads(base64.b64decode(envelope['payload_base64'])); change(value, envelope['kind'])
        envelope['payload_base64'] = base64.b64encode(compact(value)).decode()
        slot['template_base64'] = base64.b64encode(compact(envelope)).decode(); slot['object_id'] = statement_id(envelope)
        slot['message_base64'] = base64.b64encode('\n'.join(('peerspan-decentralized-signature-v1', slot['object_id'], 'issuer', slot['public_key'])).encode()).decode()


@suite.case('generated_original_exact_B_D_then_F_same_intent_real_proofs_and_no_commit', 'guided25 verification1')
def _():
    f = fixture('gen'); target = install_key(f)
    before_home = private_files(f['h'].home); before_schema = records(f['h'])['$schema']
    with AgentProxy('g', [f['key']]) as agent, HostProxy(f['h'], 'gp') as proxy:
        reappeared = []
        def dependent_view(method, path, body, status, value):
            if method == 'GET' and path.endswith('/approval') and proxy.submissions and not reappeared:
                reappeared.append(True)
                return status, copy.deepcopy(f['ordinary'])
            return status, value
        proxy.mutate = dependent_view
        answer = complete_once(f, proxy, agent=agent, agent_signatures=0)
        check(reappeared == [True], 'controlled dependent issuer-reappearance boundary was not observed')
        check(agent.messages == [], 'matching generated original contacted unrelated SSH-agent fixture')
        check(private_files(f['h'].home) == before_home and records(f['h'])['$schema'] == before_schema, 'signing created/changed key files or schema')
        check(len(proxy.submissions) <= 2 and sum(len(b['signatures']) for b in proxy.submissions) == 3, 'generated sequence did not record exactly remaining B/D/F signatures')
        # Internal generated-key call count remains source evidence. Exact
        # submitted and independently verified retained authority is observable.
        f['returned_success'] = answer.ok
    settle_F(f)
    check(target.is_file() and get(f['h'], '/v2/networks') == [], 'F action removed original or adopted network')


@suite.case('safe_generated_sources_and_unavailable_signer_fail_closed', 'guided25 verification2')
def _():
    f = fixture('safe'); target = install_key(f); original = target.read_bytes()
    wrong = ssh_key(suite.work, 'PRIVATE_AGENT_COMMENT-wrong')
    with AgentProxy('u', [wrong, f['key']]) as agent, HostProxy(f['h'], 'up') as proxy:
        for fault in ('insecure', 'malformed', 'oversized', 'symlink', 'directory', 'fifo', 'private-directory',
                      'ancestor-writable', 'parent-symlink', 'relative', 'traversal', 'redundant-slash', 'dot-component'):
            target.unlink(); environment = {}
            if fault == 'symlink': target.symlink_to(f['key'])
            elif fault == 'directory': target.mkdir(mode=0o700)
            elif fault == 'fifo': os.mkfifo(target, 0o600)
            else:
                target.write_bytes(b'PRIVATE_SIGNING_MARKER invalid' if fault == 'malformed' else b'x' * 65537 if fault == 'oversized' else original)
                target.chmod(0o644 if fault == 'insecure' else 0o600)
            if fault == 'private-directory': target.parent.chmod(0o755)
            if fault == 'ancestor-writable': target.parent.parent.chmod(0o777)
            if fault == 'parent-symlink':
                target.parent.rename(target.parent.with_name('held-private')); target.parent.symlink_to(target.parent.with_name('held-private'), target_is_directory=True)
            if fault == 'relative': environment['XDG_CONFIG_HOME'] = '.config'
            if fault == 'traversal': environment['XDG_CONFIG_HOME'] = str(f['h'].home / 'child' / '..' / '.config')
            if fault == 'redundant-slash': environment['XDG_CONFIG_HOME'] = str(f['h'].home) + '/.config//'
            if fault == 'dot-component': environment['XDG_CONFIG_HOME'] = str(f['h'].home) + '/./.config'
            quiet(f); before = snapshot(f['h']); listed = len(agent.messages); sent = len(proxy.submissions)
            answer = command(f, proxy=proxy, agent=agent, env=environment)
            check(not answer.ok and len(agent.messages) == listed and len(proxy.submissions) == sent, 'unsafe source fell back or signed: ' + fault)
            check(snapshot(f['h']) == before, 'unsafe source repaired/mutated keys or daemon: ' + fault)
            if fault == 'parent-symlink': target.parent.unlink(); target.parent.with_name('held-private').rename(target.parent)
            target.parent.chmod(0o700); target.parent.parent.chmod(0o700)
            if target.is_dir() and not target.is_symlink(): target.rmdir()
            else: target.unlink()
            target.write_bytes(original); target.chmod(0o600)
        target.unlink()
        with AgentProxy('w', [wrong]) as unavailable:
            check(not command(f, proxy=proxy, agent=unavailable).ok and not unavailable.signatures and not proxy.submissions, 'missing exact key chose another identity')
        with AgentProxy('d', [f['key']]) as failed:
            failed.before = lambda _kind: failed.process.terminate()
            check(not command(f, proxy=proxy, agent=failed).ok and not proxy.submissions, 'failed genuine agent produced a submission')
    # Preserve this genuinely unsigned fixture for typed faults/guard tests.


@suite.case('exact_multi_identity_agent_lost_B_D_stops_F_then_F_only_recovery_and_keyless_refusal', 'guided25 verification3')
def _():
    f = fixture('lost')
    wrong = ssh_key(suite.work, 'PRIVATE_AGENT_COMMENT-lost-wrong')
    different = install_key(f, wrong); before_home = private_files(f['h'].home)
    with AgentProxy('l', [wrong, f['key']]) as agent, HostProxy(f['h'], 'lp') as proxy:
        proxy.drop_signed = True; at = len(proxy.calls)
        answer = command(f, proxy=proxy, agent=agent)
        check(not answer.ok and len(proxy.submissions) == 1 and len(agent.signatures) == 2 and not retained(f, 4), 'lost issuer POST continued/retried F')
        check_batches(f, proxy.submissions); assert_no_driver(proxy, at)
        check(len(retained(f, 2)) == len(retained(f, 3)) == 1, 'lost issuer response did not retain exact authentic B/D')
        authentic_F = ready_view(f, 'F')
        # Reappearing issuer entries after a committed first batch are not
        # authority for another key use or a protocol-driving retry.
        before_messages = len(agent.messages); before_posts = len(proxy.submissions)
        for label in ('bad-nested-signature', 'extra-nested-grant', 'foreign-host'):
            changed = copy.deepcopy(authentic_F)
            if label == 'foreign-host':
                changed['signing_requests'].append({**copy.deepcopy(changed['signing_requests'][0]), 'role': 'host', 'format': 'ed25519', 'public_key': f['a'].public_key})
            else:
                def change(packet):
                    payload_value = json.loads(base64.b64decode(packet['payload_base64']))
                    if label == 'bad-nested-signature':
                        payload_value['binding_lease']['signatures'][0]['signature'] = base64.b64encode(b'\0' * 64).decode()
                    else:
                        payload_value['extra_grant'] = copy.deepcopy(payload_value['binding_lease'])
                    packet['payload_base64'] = base64.b64encode(compact(payload_value)).decode()
                alter_packets(changed, change)
            proxy.mutate = lambda method, path, body, status, value: (status, copy.deepcopy(changed) if path.endswith('/approval') else value)
            check(not command(f, proxy=proxy, agent=agent).ok, 'malformed dependent batch signed: ' + label)
            check(len(agent.messages) == before_messages and len(proxy.submissions) == before_posts, 'dependent batch fault reached signer/submission: ' + label)
        proxy.mutate = lambda method, path, body, status, value: (status, value)
        at = len(proxy.calls); before_posts = len(proxy.submissions)
        command(f, proxy=proxy, agent=agent)
        check_batches(f, proxy.submissions[before_posts:], first='F'); assert_no_driver(proxy, at)
        check(len(agent.signatures) == 3, 'explicit remaining-F recovery re-signed issuer work')
        verify_F(f)
        check(all(message[0] in (11, 13) for message in agent.messages), 'CLI mutated agent identities')
        for message in agent.signatures:
            blob, _ = ssh_string(message, 1); algorithm, offset = ssh_string(blob); raw, _ = ssh_string(blob, offset)
            check(algorithm == b'ssh-ed25519' and base64.b64encode(raw).decode() == f['person'], 'agent signed with another original')
        check(private_files(f['h'].home) == before_home and different.is_file(), 'agent path replaced different generated original')
    settle_F(f)
    with AgentProxy('k', [f['key']]) as agent, HostProxy(f['h'], 'kp') as proxy:
        altered = {**decision(f), 'finalization_review_id': 'review_' + 'f' * 64}
        keyless_refusal(f, proxy, agent, data=compact(altered))
    f['h'].stop()
    generated = fixture('gen'); generated_path(generated['h']).unlink()
    with AgentProxy('h', [generated['key']]) as agent, HostProxy(generated['h'], 'hp') as proxy:
        keyless_refusal(generated, proxy, agent)
        check(generated['h'].api('POST', '/v1/sessions/' + generated['parent']['review']['session_id'] + '/detach', {})[0] == 200, 'public detach history fixture')
        keyless_refusal(generated, proxy, agent, data=compact({**decision(generated), 'finalization_review_id': 'review_' + 'e' * 64}))






@suite.case('authentic_typed_B_D_faults_strict_private_stdin_and_no_start_refuse_before_signer', 'guided25 verification5')
def _():
    f = fixture('safe'); h = f['h']; authentic = ready_view(f, 'issuers')
    check([(r['slot_id'], r['role']) for r in authentic['signing_requests']] == [(2, 'issuer'), (3, 'issuer')], 'typed-fault fixture needs both genuine unsigned B/D slots')
    with AgentProxy('t', [f['key']]) as agent, HostProxy(h, 'tp') as proxy:
        faults = [
            ('slot', lambda v: v['signing_requests'][0].update(slot_id=1)),
            ('role', lambda v: v['signing_requests'][0].update(role='authority')),
            ('intent', lambda v: v['signing_requests'][0].update(intent_id='dint_' + 'f' * 32)),
            ('key', lambda v: v['signing_requests'][0].update(public_key=f['a'].public_key)),
            ('format', lambda v: v['signing_requests'][0].update(format='ed25519')),
            ('message', lambda v: v['signing_requests'][0].update(message_base64=base64.b64encode(b'PRIVATE_SIGNING_MARKER').decode())),
            ('objectID', lambda v: v['signing_requests'][0].update(object_id='ds_' + 'f' * 64)),
            ('duplicates', lambda v: v['signing_requests'].append(copy.deepcopy(v['signing_requests'][0]))),
            ('order', lambda v: v['signing_requests'].reverse()),
            ('mixed', lambda v: v['signing_requests'][0].update(object_type='owner_finalization_packet', slot_id=4, role='authority')),
            ('provider', lambda v: v['review']['provider'].update(kind='network_root')),
            ('profile', lambda v: v['review'].update(scopes=15)),
            ('root', lambda v: v['review'].update(root_state_id='ds_' + 'f' * 64)),
            ('parent', lambda v: v['review'].update(person_lease_id='ds_' + 'f' * 64)),
            ('admin', lambda v: v['review'].update(administrator_offer_id='dpk_' + 'f' * 64)),
            ('issuer', lambda v: alter_statements(v, lambda p, _kind: p['issuer'].update(kind='device'))),
            ('operation', lambda v: alter_statements(v, lambda p, _kind: p.update(operation_id='link_' + 'f' * 64))),
            ('target', lambda v: alter_statements(v, lambda p, _kind: p['subject'].update(host_public_key=f['a'].public_key))),
            ('member', lambda v: alter_statements(v, lambda p, _kind: p['subject'].update(member='other member'))),
            ('scopes', lambda v: alter_statements(v, lambda p, _kind: p['subject'].update(scopes=15))),
            ('lifetime', lambda v: alter_statements(v, lambda p, _kind: p.update(not_after=rfc3339(h.now() + timedelta(days=8))))),
            ('dependency', lambda v: alter_statements(v, lambda p, _kind: p['parents'][0].update(id='ds_' + 'f' * 64))),
            ('future', lambda v: alter_statements(v, lambda p, _kind: p.update(issued_at=rfc3339(h.now() + timedelta(minutes=1)), not_before=rfc3339(h.now() + timedelta(minutes=1))))),
        ]
        quiet(f); before = snapshot(h)
        for label, change in faults:
            changed = copy.deepcopy(authentic); change(changed)
            proxy.mutate = lambda method, path, body, status, value: (status, copy.deepcopy(changed) if path.endswith('/approval') else value)
            check(not command(f, proxy=proxy, agent=agent).ok, 'typed fault signed: ' + label)
            check(not agent.messages and not proxy.submissions, 'typed fault reached key/agent/submission: ' + label)
        check(snapshot(h) == before, 'rejected typed first batches changed daemon/key state')
        proxy.mutate = lambda method, path, body, status, value: (status, value)
        data = compact(decision(f)); maximum = data + b' ' * (65536 - len(data))
        context_json = compact(decision(f)['context'])
        malformed = [b'null', b'[]', b'{', data + b'{}', maximum + b' ',
            data.replace(b'"decision":"sign_original_finalization"', b'"decision":"sign_original_finalization","decision":"sign_original_finalization"'),
            data.replace(b'"context":' + context_json, b'"context":null'), compact({**decision(f), 'decision': 'approve'}),
            compact({**decision(f), 'finalization_review_id': 'review_bad'}), compact({**decision(f), 'owner_review_id': None})]
        for field in ('path', 'key', 'provider', 'code', 'scopes', 'deadline', 'template', 'message', 'signatures', 'administrator_offer_id'):
            malformed.append(compact({**decision(f), field: 'PRIVATE_SIGNING_MARKER'}))
        calls_before = len(proxy.calls)
        for index, raw in enumerate(malformed):
            check(not command(f, proxy=proxy, agent=agent, data=raw).ok, f'CLI accepted malformed variant{index}')
        check(len(proxy.calls) == calls_before and not agent.messages and not proxy.submissions, 'malformed input performed daemon/key IO')
        check(not command(f, proxy=proxy, agent=agent, stdin=False).ok, 'CLI consumed implicit stdin')
        check(not command(f, proxy=proxy, agent=agent, args=('PRIVATE_SIGNING_MARKER',)).ok, 'CLI accepted positional ID')
        # Exact64KiB valid JSON reaches normal eligibility, then unavailable
        # ready work refuses before key use. No valid signing attempt is hidden.
        proxy.mutate = lambda method, path, body, status, value: (status, {**value, 'signing_requests': []} if path.endswith('/approval') else value)
        at = len(proxy.calls)
        check(not command(f, proxy=proxy, agent=agent, data=maximum).ok and len(proxy.calls) > at and not agent.messages and not proxy.submissions, 'exact64KiB ceiling did not reach controlled ready-work refusal')
    missing = suite.host('nd', start=False); original_host = f['h']; f['h'] = missing
    before = private_files(missing.root)
    check(not command(f).ok and private_files(missing.root) == before, 'signing initialized missing host/state/key files')
    f['h'] = original_host


@suite.case('genuine_missing_consent_expiry_and_changed_binding_or_cancellation_stop_each_key_and_dispatch', 'guided25 verification4')
def _():
    f = fixture('safe'); h = f['h']
    with AgentProxy('r', [f['key']]) as agent, HostProxy(h, 'rp') as proxy:
        for field in ('join_review_id', 'owner_review_id', 'finalization_review_id'):
            data = {**decision(f), field: 'review_' + 'e' * 64}
            check(not command(f, proxy=proxy, agent=agent, data=compact(data)).ok and not agent.messages and not proxy.submissions, 'changed captured review reached signer: ' + field)
        original_offset = h.clock.offset; quiet(f); state = snapshot(h)
        advance_to(h, parse_time(f['inspection']['request']['expires_at']) + timedelta(seconds=1))
        check(not command(f, proxy=proxy, agent=agent).ok and not agent.messages and not proxy.submissions, 'expired request signed')
        check(snapshot(h) == state, 'expiry refusal/ambient worker changed persisted state; cannot restore fixture time')
        h.clock.set(original_offset)
        fired = []
        def cancel(kind):
            if kind != 13 or fired: return
            fired.append(True)
            check(h.api('POST', '/v2/link/requests/' + f['rid'] + '/cancel', {})[0] == 200, 'public during-key cancellation failed')
        agent.before = cancel
        check(not command(f, proxy=proxy, agent=agent).ok and fired, 'actual key-use cancellation boundary was not reached')
        check(len(agent.signatures) == 1 and not proxy.submissions, 'cancellation did not stop next original operation or batch dispatch')
    h.stop()
    negative = make_pair('ng', live=False, prepared=False, approved=False, signed=False, admitted=False)
    negative['inspection'] = {'review_id': 'review_' + '0' * 64}
    with AgentProxy('n', [negative['key']]) as agent, HostProxy(negative['h'], 'np') as proxy:
        check(not command(negative, proxy=proxy, agent=agent).ok, 'missing owner consent signed')
        negative['owner'] = owner(negative, 'prepare')
        check(not command(negative, proxy=proxy, agent=agent).ok, 'unapproved owner consent signed')
        check(not agent.messages and not proxy.submissions, 'missing/unapproved consent touched signer')
    negative['h'].stop()


@suite.case('same_F_separate_requester_commit_and_keyless_expired_detached_restart_history', 'guided25 verification6')
def _():
    f = fixture('gen'); h, a, rid = f['h'], f['a'], f['rid']; before_owner = owner(f, 'lookup')['owner']
    view = verify_F(f)
    a.relay.mode = h.relay.mode = 'pass'; a.start()
    commit(h, view); wait_linked(h, a, rid, timeout=25); a.stop()
    advance_to(h, parse_time(view['expires_at']) + timedelta(seconds=1))
    spare_key = ssh_key(suite.work, 'history-spare')
    status, spare = h.api('POST', '/v2/link/requests', {'mode': 'new', 'network_id': '-', 'person_public_key': ssh_public_base64(spare_key),
        'migration_proposal_id': '-', 'contact_invitation': '-', 'helpers': []})
    check(status == 201 and spare['selection_approved'] is False and spare['commit_approved'] is False, 'ordinary unapproved expiry-maintenance fixture')
    check(h.api('POST', '/v2/link/requests/' + spare['request_id'] + '/cancel', {})[0] == 200, 'maintenance fixture cancellation')
    a.relay.mode = h.relay.mode = 'drop'
    with AgentProxy('z', [f['key']]) as agent, HostProxy(h, 'zp') as proxy:
        keyless_refusal(f, proxy, agent)
        state = snapshot(h); historical = owner(f, 'lookup')
        check(historical['request']['state'] == 'linked' and historical['owner'] == before_owner and snapshot(h) == state, 'application/expiry changed immutable owner history')
        h.restart(kill=True); quiet(f)
        keyless_refusal(f, proxy, agent, data=compact({**decision(f), 'finalization_review_id': 'review_' + 'a' * 64}))
        check(owner(f, 'lookup')['owner'] == before_owner and not agent.messages and not proxy.submissions, 'restarted recorded F read recreated authority/key work')


suite.finish()
