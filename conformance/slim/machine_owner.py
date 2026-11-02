#!/usr/bin/env python3
"""Pure existing-computer machine owner inspection, guided section41.

Independent contract/public-fixture source only. Genuine pinned automatic return
and original/device public authority; no authority/protocol/queue/clock row edits.
The daemon has absent configured original-file/agent paths from initial launch;
the creator CLI alone uses an external original. Complete logical DB/schema and
state/home files plus BOTH TCP and UDP paths are compared. Only SQLite WAL/SHM
bookkeeping bytes/names are excluded, never journals. Invitation-return expiry
is actually observed; a stopped remote or consumed live TLS hold isolates reads.
Limits: insufficient-device/separate-admin, root forks/restrictions/bans/migration,
foreign-person admitted requester, unavailable owned seed, malformed signed proof
and incoming dash-pins lack bounded independent authority fixtures here. They
remain source-only, not claimed successes. No physical/native/installed/model
or completed machine admission is inferred. All old suites/helpers stay exact.
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

suite = Suite("machine_owner", __doc__)
BASE = "/v1/onboarding/machine-owner-inspection"
PROJECT = "/v1/onboarding/project-flows"
TOP = set("version host_id context observed_at request review_id review next_action".split())
REVIEW = set("version kind host_id context agent network root_state_id request_id request_packet_id person_public_key host_public_key device_public_key member person_lease_id local_host provider provider_id signature_format scopes not_after host_admission created_at expires_at effects".split())
PROVIDER = set("kind person_public_key host_public_key device_public_key lease_id root_state_id scopes not_after".split())
MEMBER = set("host_public_key member person_public_key host_lease_id binding_lease_id device_lease_id not_after".split())
LINK = set("request_id role mode state network_id context_id migration_proposal_id person_public_key host_public_key device_public_key created_at expires_at request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id manifest_id activation_id outcome_id selection_approved commit_approved completed attention next".split())
EFFECTS = {"verify_request_signature": True, "inspect_current_owner_authority": True,
           **{name: False for name in ("prepare_owner_intent", "approve_owner_intent", "sign_owner_offer", "publish_owner_offer", "grant_membership", "grant_machine_powers", "grant_agent_access", "commit_request", "share_files", "share_conversation", "capability_calls")}}
PREFIXES = ('psi2-', 'psl2-', 'peerspan-invite-v1.', 'peerspan-member-invite-v1.',
            'peerspan-person-invite-v1.', 'token_', 'instance_')
shared = {}

def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def digest(domain, value):
    body = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return "review_" + hashlib.sha256(domain.encode() + b"\n" + body).hexdigest()


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


def payload(parent, rid):
    return {'context': context(parent), 'request_id': rid}


def inspect(h, parent, rid, *, status=200, code=None, data=None):
    actual, value = h.api('POST', BASE, payload(parent, rid) if data is None else data, timeout=8)
    check(actual == status, f'machine inspection HTTP {actual}, expected {status}')
    if code:
        check(type(value) is dict and value.get('code') == code, 'machine inspection controlled code mismatch')
    public(value)
    return value


def raw_post(h, raw):
    conn = UnixHTTPConnection(str(h.state / 'admin.sock'), timeout=8)
    try:
        try:
            conn.request('POST', BASE, body=raw, headers={'Content-Type': 'application/json'})
        except BrokenPipeError:
            pass  # An early refusal may close before the entire oversized body.
        reply = conn.getresponse(); data = reply.read()
        return reply.status, json.loads(data) if data else None
    finally:
        conn.close()


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


def strict(actual, expected, current, before, phase):
    if actual != expected or current != before:
        print('machine_owner_purity_public=' + json.dumps({'phase': phase,
            'database_or_files_changed': actual != expected,
            'carrier_changes': [dict(index=i, changed=x != y) for i, (x, y) in enumerate(zip(current, before))]}, sort_keys=True), flush=True)
    check(actual == expected, 'machine inspection changed whole DB/schema/state/home')
    check(current == before, 'machine inspection performed counted TCP/UDP traffic')


def owner_prepare_diagnostic(actual, status, response):
    """GU.impl41a: captured failure only; retain the original short circuit."""
    try:
        if not actual:
            codes = {'invalid', 'expired', 'forbidden', 'state_conflict', 'operation_conflict', 'proof_required',
                     'clock_rollback', 'signer_unavailable', 'authority_expired', 'not_yet_valid', 'internal'}
            code = response.get('code') if type(response) is dict else None
            summary = {'http_status': status if type(status) is int and 100 <= status <= 599 else 'unknown',
                       'code': code if isinstance(code, str) and code in codes else 'unknown',
                       'owner_intent_retained': actual if status == 200 and type(actual) is bool else 'unknown'}
            print('machine_owner_prepare_failure_public=' + json.dumps(summary, sort_keys=True), flush=True)
    except Exception:
        pass  # No diagnostic failure may replace the original prerequisite.
    return actual


def pure(f, *, h=None, parent=None, rid=None, status=200, code=None, data=None, cli=False, hold=None):
    h = h or f['a']; parent = parent or f['parent']; rid = rid or f['rid']
    quiet(f)
    if hold:
        hold()
    before, counters = whole(f), traffic(f)
    if cli:
        result = h.cli('onboarding', 'machine', 'inspect', '--stdin', input=compact(payload(parent, rid) if data is None else data).decode(), timeout=8)
        public(result.stdout + result.stderr, str(h.state), *f['secrets'])
        check(result.ok == (status == 200), 'private machine CLI success/refusal mismatch')
        value = result.json
    else:
        value = inspect(h, parent, rid, status=status, code=code, data=data)
    after, current = whole(f), traffic(f)
    if hold:
        hold()
    strict(after, before, current, counters, 'CLI' if cli else 'API')
    return value


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


def validate(f, value, parent=None):
    h, b, net = f['a'], f['b'], f['network']; parent = parent or f['parent']
    check(type(value) is dict and set(value) == TOP and type(value['version']) is int and value['version'] == 1, 'closed machine-owner wrapper')
    check(value['host_id'] == h.id and value['context'] == context(parent) and value['next_action'] == 'review_machine_owner_consent', 'exact wrapper host/context/next')
    observed = parse_time(value['observed_at'])
    check(rfc3339(observed) == value['observed_at'] and abs((observed - h.now()).total_seconds()) < 5, 'canonical current observation')
    request, review = value['request'], value['review']
    check(set(request) == LINK and request == link_view(h, f['rid']) and request['role'] == 'approver'
          and request['mode'] == 'new' and request['state'] == 'pending', 'complete current incoming pending LINK_VIEW')
    check(not request['selection_approved'] and not request['commit_approved'] and request['completed'] == ['request_created'], 'inspection granted protocol consent')
    for key in ('owner_offer_id', 'selection_id', 'administrator_offer_id', 'owner_finalization_id', 'manifest_id', 'activation_id', 'outcome_id', 'migration_proposal_id'):
        check(request[key] == '-', 'unexpected advanced protocol reference')
    check(set(review) == REVIEW and type(review['version']) is int and review['version'] == 1
          and review['kind'] == 'inspect_existing_person_machine', 'closed machine-owner review')
    check(review['host_id'] == h.id and review['context'] == context(parent) and review['agent'] == parent['review']['agent'], 'exact attached project/agent')
    current = get(h, '/v2/networks/' + net['id'])
    check(current['authority']['state'] == 'usable' and review['network'] == {k: current[k] for k in ('id', 'name', 'context_id', 'genesis_root_public_key')}
          and review['root_state_id'] == current['root_state_id'], 'actual verified current network/root')
    for key in ('request_id', 'request_packet_id', 'person_public_key', 'host_public_key', 'device_public_key', 'created_at', 'expires_at'):
        check(review[key] == request[key], 'signed request pin mismatch: ' + key)
    people = get(h, '/v2/networks/' + net['id'] + '/persons')['persons']
    person = next(row for row in people if row['person_public_key'] == f['person'])
    mine = next(row for row in get(h, '/v2/networks/' + net['id'] + '/members')['members'] if row['host_public_key'] == h.public_key)
    check(review['person_public_key'] == f['person'] and review['host_public_key'] == b.public_key
          and review['member'] == person['member'] and review['person_lease_id'] == person['person_lease_id'], 'verified existing owner/remote requester')
    check(set(review['local_host']) == MEMBER and review['local_host'] == mine, 'complete exact local P/H/B/D member response')
    provider = review['provider']; check(set(provider) == PROVIDER and provider == current['provider'], 'actual persisted selected public provider')
    check(provider['kind'] in ('device', 'original_person') and provider['person_public_key'] == f['person']
          and provider['host_public_key'] == h.public_key and provider['root_state_id'] == review['root_state_id'], 'no root/foreign-owner fallback')
    check(type(provider['scopes']) is int and provider['scopes'] & 7 == 7 and provider['device_public_key'] != request['device_public_key'], 'full fixed powers within current distinct authority')
    check(review['provider_id'] == (provider['lease_id'] if provider['kind'] == 'device' else f['person'])
          and review['signature_format'] == ('ed25519' if provider['kind'] == 'device' else 'sshsig'), 'concrete selected signer reference/format')
    check(type(review['scopes']) is int and review['scopes'] == 7 and review['scopes'] & 8 == 0, 'fixed nonadministrator profile7')
    check(review['host_admission'] == ('owner_may_fold' if provider['scopes'] & 8 else 'separate_administrator_required'), 'truthful public fold potential')
    cap = min(parse_time(request['created_at']) + timedelta(days=7), parse_time(provider['not_after']))
    check(parse_time(review['not_after']) == cap and observed < cap and observed < parse_time(request['expires_at']), 'effective-provider and signed seven-day cap')
    check(review['effects'] == EFFECTS and all(type(v) is bool for v in review['effects'].values()), 'exact read-only effects')
    check(value['review_id'] == digest('peerspan-machine-owner-inspection-v1', review), 'independent recursive UTF8 closed-review digest')
    refs = {review['root_state_id'], review['person_lease_id'], *[mine[k] for k in ('host_lease_id', 'binding_lease_id', 'device_lease_id')], provider['lease_id']}
    catalog = get(h, '/v2/networks/' + net['id'] + '/catalog')['catalog']
    statements = set()
    for item in catalog['objects']:
        envelope_bytes = base64.b64decode(item['body_base64'], validate=True)
        proof_message = '\n'.join(('peerspan-decentralized-proof-v1', item['kind'], hashlib.sha256(envelope_bytes).hexdigest()))
        check(item['id'] == 'dp_' + hashlib.sha256(proof_message.encode()).hexdigest(), 'catalog proof differs from exact signed envelope bytes')
        if item['kind'] in ('root_state', 'person_lease', 'host_lease', 'binding_lease', 'device_lease'):
            envelope = json.loads(envelope_bytes)
            check(envelope['kind'] == item['kind'] and envelope['context_id'] == catalog['context_id'] == review['network']['context_id'],
                  'ordinary dependency envelope changed kind/context')
            raw_payload = base64.b64decode(envelope['payload_base64'], validate=True)
            statement_message = '\n'.join(('peerspan-decentralized-statement-v1', envelope['kind'], envelope['context_id'],
                                          hashlib.sha256(raw_payload).hexdigest()))
            statements.add('ds_' + hashlib.sha256(statement_message.encode()).hexdigest())
    check(refs - {'-'} <= statements, 'review dependencies lack actual semantic statement identities in public proofs')
    check(len(compact(value)) <= 2 * 1024 * 1024, 'public inspection overflow')
    record, _ = pending(h, f['rid'])
    check(record.get('owner_intent_id', '-') == '-', 'inspection prepared an ordinary owner intent')
    public(value, *f['secrets'])


def hold_transport(f):
    relays = (f['a'].relay, f['b'].relay)
    for relay in relays:
        relay.refresh_hold()
    held = wait_for(lambda: [(relay, n) for relay in relays for n in relay.live_generations()] or None,
                    timeout=5, interval=.02, message='actual pending requester TLS held outside DB')
    def guard():
        check(all(relay.mode == 'hold' and n in relay.live_generations() for relay, n in held),
              'genuine pending transport hold ended during inspection')
    return guard


def select_provider(f, provider):
    h = f['a']
    status, value = h.api('POST', '/v2/networks/' + f['network']['id'] + '/provider', {
        'provider_id': provider, 'person_public_key': f['person'], 'host_public_key': h.public_key, 'approve': True})
    check(status == 200, f'ordinary exact provider selection HTTP {status}')
    return value


@suite.case('actual_pending_existing_person_device_authority_closed_review_digest_and_no_consent', 'guided41 verification1')
def _():
    f = world(); a, b = f['a'], f['b']
    record, _ = pending(a, f['rid'])
    packet = json.loads(base64.b64decode(record['request_packet_base64'], validate=True))
    raw = base64.b64decode(packet['payload_base64'], validate=True); signed = json.loads(raw)
    check(packet['role'] == 'request' and packet['writer_host_public_key'] == b.public_key
          and packet['signer_public_key'] == signed['device_public_key'], 'actual signed host/device request roles')
    check(signed['expected_network_id'] == f['network']['id'] and signed['expected_context_id'] == f['network']['context_id']
          and signed['expected_person_public_key'] == f['person'], 'genuine request has different explicit signed pins')
    check(f['rid'] == 'link_' + hashlib.sha256(('peerspan-decentralized-request-id-v1\n' + hashlib.sha256(raw).hexdigest()).encode()).hexdigest(),
          'independent actual request content reference')
    ed25519(b.public_key, packet['host_signature'], packet_message(packet), 'request-host')
    ed25519(signed['device_public_key'], packet['device_signature'], packet_message(packet), 'request-device')
    original = pure(f); validate(f, original)
    check(packet['request_id'] == f['rid'] and original['request']['request_packet_id'] == packet_id(packet),
          'inspection request packet reference differs from independently verified signed packet')
    check(original['review']['provider'] == f['device'] and original['review']['host_admission'] == 'owner_may_fold', 'creator device/fold potential changed')
    check(parse_time(original['review']['provider']['not_after']) < parse_time(original['request']['created_at']) + timedelta(days=7),
          'genuine fixture did not exercise earlier effective provider deadline')
    for cli in (False, True):
        repeated = pure(f, cli=cli); validate(f, repeated)
        check(repeated['review'] == original['review'] and repeated['review_id'] == original['review_id'], 'unchanged public authority changed review/digest')
    f['initial'] = original


@suite.case('exact_private_stdin_bounds_nested_duplicates_types_argv_redaction_and_missing_daemon', 'guided41 verification2')
def _():
    f = world(); h = f['a']; data = payload(f['parent'], f['rid']); raw = compact(data)
    maximum = raw + b' ' * (65536 - len(raw))
    quiet(f); before, counters = whole(f), traffic(f)
    status, value = raw_post(h, maximum); check(status == 200, f'exact64KiB request HTTP {status}'); validate(f, value)
    result = h.cli('onboarding', 'machine', 'inspect', '--stdin', input=maximum.decode(), timeout=8)
    check(result.ok, 'exact64KiB private CLI refused'); validate(f, result.json)
    malformed = [b'null', b'[]', b'{', raw + b'{}', maximum + b' ',
        raw.replace(b'"request_id":', b'"request_id":"link_' + b'0' * 64 + b'","request_id":'),
        raw.replace(b'"integration":"claude-code"', b'"integration":"claude-code","integration":"claude-code"')]
    malformed += [compact({**data, 'request_id': value}) for value in (None, [], 1, 'link_bad', 'link_' + 'A' * 64)]
    malformed += [compact({**data, 'context': value}) for value in (None, [], 'PRIVATE_MACHINE_INPUT')]
    malformed += [compact({**data, 'context': {**data['context'], key: None}}) for key in data['context']]
    malformed += [compact({**data, 'extra': 'PRIVATE_MACHINE_INPUT'}),
                  compact({**data, 'context': {**data['context'], 'extra': 'PRIVATE_MACHINE_INPUT'}}),
                  compact({'context': data['context']}), compact({'request_id': f['rid']})]
    for index, bad in enumerate(malformed):
        status, denied = raw_post(h, bad)
        check(status == 400 and denied.get('code') == 'invalid', f'malformed variant{index} HTTP {status}')
        result = h.cli('onboarding', 'machine', 'inspect', '--stdin', input=bad.decode(), timeout=8)
        check(not result.ok, f'CLI accepted malformed variant{index}')
        public(denied, 'PRIVATE_MACHINE_INPUT', *f['secrets'])
        public(result.stdout + result.stderr, 'PRIVATE_MACHINE_INPUT', str(h.state), *f['secrets'])
    strict(whole(f), before, traffic(f), counters, 'strict-input')
    for args in (('onboarding', 'machine', 'inspect'), ('onboarding', 'machine', 'inspect', f['rid'], '--stdin'),
                 ('onboarding', 'machine', 'inspect', '--PRIVATE_MACHINE_INPUT=/private/machine', '--stdin')):
        result = h.cli(*args, input=raw.decode(), timeout=8)
        check(not result.ok, 'CLI accepted missing stdin or public/unsafe positional option')
        public(result.stdout + result.stderr, f['rid'], 'PRIVATE_MACHINE_INPUT', '/private/machine', str(h.state))
    missing = suite.host('nd', start=False); files_before = files(missing.root)
    result = missing.cli('onboarding', 'machine', 'inspect', '--stdin', input=raw.decode(), timeout=8)
    check(not result.ok and files(missing.root) == files_before, 'missing socket started a daemon or initialized state')
    public(result.stdout + result.stderr, str(missing.root), *f['secrets'])


@suite.case('missing_request_requester_local_exact_context_and_restart_replacement_remain_pure', 'guided41 verification3')
def _():
    f = world(); a, b, parent = f['a'], f['b'], f['parent']
    pure(f, rid='link_' + 'f' * 64, status=404, code='not_found')
    pure(f, rid=f['wrong_rid'], status=409, code='machine_owner_inspection_unavailable')
    for key, value in (('project_root', str(suite.work / 'other private root')),
                       ('native_session_id', 'other-machine-conversation'), ('project_review_id', 'review_' + '0' * 64)):
        pure(f, status=409, code='review_changed', data={'context': {**context(parent), key: value}, 'request_id': f['rid']})
    b.start()
    status, cancelled = b.api('POST', '/v2/link/requests/' + f['wrong_rid'] + '/cancel', {})
    check(status == 200 and cancelled['state'] == 'cancelled', 'retire only the auxiliary requester before live transport hold')
    remote = project(b, 'local-role', replace=f['remote_parent']['flow_id'], old=f['remote_parent'])
    guard = hold_transport(f)
    try:
        pure(f, h=b, parent=remote, status=409, code='machine_owner_inspection_unavailable', hold=guard)
    finally:
        b.stop(); a.relay.mode = b.relay.mode = 'pass'
    previous = pure(f); a.restart(kill=True)
    pure(f, status=409, code='review_changed')
    current = project(a, 'restart', replace=parent['flow_id'], old=parent)
    pure(f, status=409, code='review_changed')
    f['parent'] = current; restored = pure(f); validate(f, restored)
    check(restored['review_id'] != previous['review_id'] and
          {k: v for k, v in restored['review'].items() if k not in ('context', 'agent')} ==
          {k: v for k, v in previous['review'].items() if k not in ('context', 'agent')},
          'explicit new attachment changed request/authority or reused old context digest')
    for method in ('GET', 'PUT', 'DELETE'):
        status, denied = a.api(method, BASE)
        check(status == 405, f'unsupported inspection method {method} HTTP {status}'); public(denied)


@suite.case('selected_original_public_authority_survives_absent_private_signer_and_selection_changes_digest', 'guided41 verification4')
def _():
    f = world(); before = pure(f)
    selected = select_provider(f, f['person'])
    check(selected['provider']['kind'] == 'original_person' and selected['provider_state']['state'] == 'unavailable'
          and not (f['a'].root / 'absent-person-key').exists() and not (f['a'].root / 'absent-agent.sock').exists(),
          'ordinary selected-original fixture is not publicly valid but privately unavailable')
    observed = pure(f); validate(f, observed)
    check(observed['review']['provider_id'] == f['person'] and observed['review']['signature_format'] == 'sshsig'
          and observed['review_id'] != before['review_id'], 'selected original was substituted or old device review reused')
    cli = pure(f, cli=True); check(cli['review'] == observed['review'] and cli['review_id'] == observed['review_id'], 'private signer availability changed public review')
    select_provider(f, f['device']['lease_id']); restored = pure(f); validate(f, restored)
    check(restored['review'] == before['review'] and restored['review_id'] == before['review_id'], 'restored exact current device changed unchanged public terms')
    print('LIMIT machine_owner: no bounded insufficient-device7/separate-admin or unavailable-owned-seed fixture; no private-key read/sign-call attribution', flush=True)


@suite.case('unsafe_metadata_genuine_owner_intent_cancel_and_actual_stage_request_expiry_refuse', 'guided41 verification5')
def _():
    f = world(); a = f['a']
    for index, label in enumerate(('token_SHORTMACHINE', 'to\u202eken_SHORTMACHINE')):
        private_parent = project(a, 'private' + str(index), agent_name=label)
        denied = pure(f, parent=private_parent, status=409, code='machine_owner_inspection_unavailable')
        public(denied, label, 'SHORTMACHINE')
    value = pure(f); request = value['request']; provider = value['review']['provider']
    ordinary = {'code': f['reply'], 'network_id': f['network']['id'], 'person_public_key': f['person'],
        'provider_id': provider['lease_id'], 'signature_format': 'ed25519', 'scopes': 7,
        'not_after': value['review']['not_after'], 'expected_host_public_key': request['host_public_key'],
        'expected_device_public_key': request['device_public_key'], 'approve': False}
    status, advanced = a.api('POST', '/v2/link/approvals', ordinary)
    check(owner_prepare_diagnostic(status == 200 and pending(a, f['rid'])[0].get('owner_intent_id', '-') != '-', status, advanced), 'ordinary unapproved owner review prerequisite')
    pure(f, status=409, code='machine_owner_inspection_unavailable')
    status, advanced = a.api('POST', '/v2/link/approvals', {**ordinary, 'approve': True})
    check(status == 200, f'ordinary explicit owner approval HTTP {status}')
    wait_for(lambda: link_view(a, f['rid'])['owner_offer_id'] != '-', timeout=10, interval=.1, message='genuine retained later owner packet')
    status, cancelled = a.api('POST', '/v2/link/requests/' + f['rid'] + '/cancel', {})
    check(status == 200 and cancelled['state'] == 'cancelled', 'genuine local cancellation')
    pure(f, status=409, code='machine_owner_inspection_unavailable')
    expired = world('exp'); first = pure(expired); validate(expired, first)
    target = parse_time(first['observed_at']) + timedelta(minutes=11)
    check(target < parse_time(first['request']['expires_at']), 'stage expiry stimulus already exhausted signed request')
    advance_to(expired['a'], target)
    pure(expired, status=409, code='machine_owner_inspection_unavailable')
    advance_to(expired['a'], parse_time(first['request']['expires_at']) + timedelta(seconds=1))
    pure(expired, status=409, code='machine_owner_inspection_unavailable')
    print('LIMIT machine_owner: packet-stage refusal measured with cancellation after real owner work; incoming dash-pins, changed context proofs, blocked/fork/migration and admitted-other-person require separate genuine fixtures', flush=True)


@suite.case('repeat_refusal_whole_state_and_all_carriers_with_scoped_peer_bootstrap_isolation', 'guided41 verification6')
def _():
    f = world(); h = f['a']; data = payload(f['parent'], f['rid'])
    for cli in (False, True):
        pure(f, status=409, code='machine_owner_inspection_unavailable', cli=cli)
    credential = h.ok('adapter', 'create', '--session', f['parent']['review']['session_id'], '--expires-at', rfc3339(h.now() + timedelta(hours=1)))
    adapter = Adapter(h, f['parent']['review']['agent'], f['parent']['review']['session_id'], credential)
    status, _ = adapter.call('POST', '/adapter/v1/connect', {'adapter_id': adapter.adapter_id,
        'session_id': adapter.session_id, 'instance_id': adapter.instance})
    check(status == 200, 'genuine scoped connection prerequisite')
    status, denied = adapter.call('POST', BASE, data)
    check(status == 404, f'scoped adapter exposed machine-owner administration HTTP {status}'); public(denied, adapter.token)
    peer, bootstrap = host('peer'), host('boot')
    for local, remote in ((h, peer), (peer, h)):
        local.ok('peer', 'add', '--id', remote.id, '--public-key', remote.public_key, '--address', remote.counted_peer.address)
    result = subprocess.run([str(suite.probe_bin), '--state', str(peer.state), '--address', h.counted_peer.address,
        '--alpn', 'peerspan-peer/1', '--method', 'POST', '--path', BASE, '--body-stdin'], input=compact(data), capture_output=True, timeout=10)
    check(result.returncode == 0, 'genuine authenticated peer boundary transport failed')
    check(json.loads(result.stdout)['status'] == 404, 'authenticated peer exposed private machine-owner route')
    cert, key = suite.work / 'boundary-cert.pem', suite.work / 'boundary-key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ed25519', '-nodes', '-subj', '/CN=machine-boundary', '-days', '1',
        '-keyout', str(key), '-out', str(cert)], capture_output=True, check=True, timeout=5)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); tls.check_hostname = False; tls.verify_mode = ssl.CERT_NONE
    tls.load_cert_chain(str(cert), str(key)); tls.set_alpn_protocols(['peerspan-bootstrap/1'])
    with socket.create_connection(('127.0.0.1', int(bootstrap.relay.address.rsplit(':', 1)[1])), timeout=5) as raw:
        with tls.wrap_socket(raw, server_hostname='peerspan') as stream:
            encoded = compact(data)
            stream.sendall((f'POST {BASE} HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(encoded)}\r\n\r\n').encode() + encoded)
            response = http.client.HTTPResponse(stream); response.begin(); response.read()
            check(response.status == 404, f'bootstrap exposed private machine-owner route HTTP {response.status}')
    peer.stop(); bootstrap.stop()
    public(get(h, '/v1/activity?limit=1000'), *f['secrets'], adapter.token)


suite.finish()
