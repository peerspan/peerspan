#!/usr/bin/env python3
"""Real completion publication under brief rate pressure (final acceptance).

Independent public contracts/harness only. Two genuine original people reach F
with commit unapproved. Authenticated malformed bootstrap POSTs must observe
400/invalid and429/rate_limited over public QUIC completion ALPN; pressure lasts
at most2s. One real commit's
response and both immediate GET states are frozen before any repair. After
pressure and one prescribed1s diagnostic refill interval, one exact completed
requester resume diagnoses retained-publication repair. It cannot satisfy the
first-attempt assertion. That final behavior remains a separate required gate.
No fabricated authority, original-key transfer, clock jump or product delay.
Root runs committed source; the independent author never runs the product.
"""
import base64
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import ssl
import struct
import subprocess
import threading
import time
import traceback

from harness import (Failure, Skip, Suite, check, create_network, finalize, invite,
                     join_request, link_view, parse_time, pull_until, select, ssh_key,
                     ssh_public_base64, stage_body)


suite = Suite('completion_rate_limit', __doc__)
shared = {}
STATES = set('pending needs_selection needs_administrator needs_owner_finalization needs_commit finalizing linked cancelled expired blocked'.split())
CODES = set('invalid forbidden not_found state_conflict operation_conflict quota_exceeded expired rate_limited transport_unavailable authority_expired proof_required internal'.split())
PINS = 'network_id context_id person_public_key host_public_key device_public_key request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id'.split()


def emit(value):
    print('completion_rate_limit_public=' + json.dumps(value, sort_keys=True), flush=True)


def get(host, path):
    status, value = host.api('GET', path, timeout=5)
    check(status == 200, 'bounded public observation unavailable')
    return value


def public_view(status, value):
    value = value if type(value) is dict else {}
    request = value.get('request', value)
    request = request if type(request) is dict else {}
    attention = request.get('attention', [])
    return {'http_status': status if type(status) is int and 100 <= status <= 599 else None,
        'state': request.get('state') if request.get('state') in STATES else 'other',
        'commit_approved': request.get('commit_approved') is True,
        'locally_applied': request.get('state') == 'linked',
        'attention': [v if type(v) is str and v in CODES else 'other' for v in attention[:32]]
            if type(attention) is list else [],
        'code': value.get('code') if type(value.get('code')) is str and value['code'] in CODES else 'other'}


def rows(host, query, params=()):
    databases = []
    for path in host.state.glob('*.db'):
        with closing(sqlite3.connect(f'file:{path}?mode=ro', uri=True)) as database:
            if database.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='networks'").fetchone():
                databases.append(path)
    check(len(databases) == 1, 'expected one actual host database')
    with closing(sqlite3.connect(f'file:{databases[0]}?mode=ro', uri=True)) as database:
        return database.execute(query, params).fetchall()


def operation(host, rid):
    values = rows(host, 'SELECT network_id,context_id,activation_id,manifest_id,record,locally_applied FROM dec_operations WHERE request_id=?', (rid,))
    check(len(values) <= 1, 'duplicate actual application')
    return values[0] if values else None


def consent(host, rid):
    values = rows(host, "SELECT intent_id,record FROM dec_intents WHERE kind='requester_commit' AND json_extract(record,'$.operation_id')=?", (rid,))
    check(len(values) == 1 and json.loads(values[0][1])['approved'] is True, 'missing exact single approved requester intent')
    return values


def packet_message(packet):
    return '\n'.join(('peerspan-decentralized-packet-v1', packet['context_id'], packet['request_id'], packet['role'],
        packet['writer_host_public_key'], packet['signer_public_key'], packet['person_public_key'], packet['issuer_id'],
        packet['authority_signature_format'], hashlib.sha256(base64.b64decode(packet['payload_base64'], validate=True)).hexdigest())).encode()


def packet_id(packet):
    return 'dpk_' + hashlib.sha256(packet_message(packet)).hexdigest()


def verify(fmt, key, signature, message):
    stem = suite.work / 'public-verification'
    if fmt == 'ed25519':
        stem.with_suffix('.der').write_bytes(bytes.fromhex('302a300506032b6570032100') + base64.b64decode(key, validate=True))
        stem.with_suffix('.sig').write_bytes(base64.b64decode(signature, validate=True))
        stem.with_suffix('.msg').write_bytes(message)
        result = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-keyform', 'DER', '-inkey', str(stem.with_suffix('.der')),
            '-rawin', '-in', str(stem.with_suffix('.msg')), '-sigfile', str(stem.with_suffix('.sig'))], capture_output=True, timeout=5)
    else:
        check(fmt == 'sshsig', 'unexpected actual authority signature format')
        blob = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + base64.b64decode(key, validate=True)
        stem.with_suffix('.allowed').write_text('fixture ssh-ed25519 ' + base64.b64encode(blob).decode() + '\n')
        stem.with_suffix('.sig').write_text('-----BEGIN SSH SIGNATURE-----\n' + '\n'.join(signature[n:n+70] for n in range(0, len(signature), 70)) + '\n-----END SSH SIGNATURE-----\n')
        result = subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', str(stem.with_suffix('.allowed')), '-I', 'fixture',
            '-n', 'peerspan-person-v1', '-s', str(stem.with_suffix('.sig'))], input=message, capture_output=True, timeout=5)
    check(result.returncode == 0, 'actual retained typed signature failed independent verification')


def verify_application(host, f):
    saved = operation(host, f['rid'])
    check(saved is not None and saved[5] == 1 and saved[:2] == (f['net']['id'], f['net']['context_id']), 'no actual matching local application')
    record = json.loads(saved[4])
    raw_activation = base64.b64decode(record['activation_base64'], validate=True)
    activation = json.loads(raw_activation)
    commit = activation['commit']
    body = json.loads(base64.b64decode(commit['payload_base64'], validate=True))
    raw_manifest = base64.b64decode(body['manifest_base64'], validate=True)
    manifest = json.loads(raw_manifest)
    mid = 'dm_' + hashlib.sha256(b'peerspan-decentralized-manifest-v1\n' + hashlib.sha256(raw_manifest).hexdigest().encode()).hexdigest()
    aid = 'da_' + hashlib.sha256('\n'.join(('peerspan-decentralized-activation-v1', f['net']['context_id'], f['rid'], mid, packet_id(commit))).encode()).hexdigest()
    check(saved[2:4] == (aid, mid), 'retained activation/manifest identity mismatch')
    for key in ('root_state_id', 'person_lease_id', 'host_lease_id', 'binding_lease_id', 'device_lease_id'):
        check(manifest[key] == f['review'][key], 'actual application changed exact reviewed grant dependency')
    for role, reference in (('request', 'request_packet_id'), ('owner', 'owner_offer_id'), ('selection', 'selection_id'),
                            ('administrator', 'administrator_offer_id'), ('owner_finalization', 'owner_finalization_id'), ('commit', None)):
        packet = activation[role]
        check(packet['role'] == role and packet['request_id'] == f['rid'] and (reference is None or packet_id(packet) == f['view'][reference]), 'actual transcript changed exact selected stage')
        message = packet_message(packet)
        verify('ed25519', packet['writer_host_public_key'], packet['host_signature'], message)
        if role in ('request', 'selection', 'commit'):
            check(packet['writer_host_public_key'] == f['b'].public_key and packet['signer_public_key'] == f['view']['device_public_key'], 'requester host/device changed')
            verify('ed25519', packet['signer_public_key'], packet['device_signature'], message)
        else:
            key = f['net']['root_public_key'] if role == 'administrator' else f['person']
            check(packet['signer_public_key'] == key, 'actual selected original/root signer changed')
            verify(packet['authority_signature_format'], key, packet['authority_signature'], message)
    catalog = json.loads(base64.b64decode(record['catalog_base64'], validate=True))
    proofs, envelopes = set(), {}
    for item in catalog['objects']:
        raw = base64.b64decode(item['body_base64'], validate=True)
        pid = 'dp_' + hashlib.sha256(('peerspan-decentralized-proof-v1\n' + item['kind'] + '\n' + hashlib.sha256(raw).hexdigest()).encode()).hexdigest()
        check(item['id'] == pid, 'actual proof ID changed retained bytes')
        proofs.add(pid)
        envelope = json.loads(raw)
        if type(envelope) is dict and {'kind', 'context_id', 'payload_base64', 'signatures'} <= envelope.keys():
            sid = 'ds_' + hashlib.sha256(('peerspan-decentralized-statement-v1\n' + envelope['kind'] + '\n' + envelope['context_id'] + '\n' + hashlib.sha256(base64.b64decode(envelope['payload_base64'], validate=True)).hexdigest()).encode()).hexdigest()
            envelopes[sid] = envelope
    check(set(manifest['proof_ids']) <= proofs, 'actual application lacks complete selected proof closure')
    for kind, field in (('person_lease', 'person_lease_id'), ('host_lease', 'host_lease_id'), ('binding_lease', 'binding_lease_id'), ('device_lease', 'device_lease_id')):
        sid = manifest[field]; envelope = envelopes[sid]
        check(envelope['kind'] == kind and envelope['context_id'] == f['net']['context_id'], 'actual typed grant/context changed')
        for signature in envelope['signatures']:
            verify(signature['format'], signature['public_key'], signature['signature'], '\n'.join(('peerspan-decentralized-signature-v1', sid, signature['role'], signature['public_key'])).encode())
        payload = json.loads(base64.b64decode(envelope['payload_base64'], validate=True))
        if kind in ('binding_lease', 'device_lease'):
            check(payload['subject']['scopes'] == (2 if kind == 'binding_lease' else 7)
                and payload['subject']['person_public_key'] == f['person'] and payload['subject']['host_public_key'] == f['b'].public_key
                and payload['not_after'] == f['review']['not_after'], 'actual finite binding/device authority changed')
    outcome = json.loads(base64.b64decode(record['outcome_packet_base64'], validate=True))
    result = json.loads(base64.b64decode(outcome['payload_base64'], validate=True))
    check(outcome['role'] == 'outcome' and outcome['writer_host_public_key'] == host.public_key and result['activation_id'] == aid
          and result['manifest_id'] == mid and result['activation_sha256'] == hashlib.sha256(raw_activation).hexdigest()
          and result['applied_at'] == record['applied_at'], 'actual outcome/application identity mismatch')
    verify('ed25519', host.public_key, outcome['host_signature'], packet_message(outcome))
    current = get(host, '/v2/networks/' + f['net']['id'])
    check(current['authority']['state'] == 'usable', 'applied current authority is not actually usable')
    members = get(host, '/v2/networks/' + f['net']['id'] + '/members')['members']
    check(len(members) == 2 and any(m['host_public_key'] == f['b'].public_key and m['person_public_key'] == f['person']
          and m['device_lease_id'] == manifest['device_lease_id'] for m in members), 'actual participant membership missing')
    return saved


class Pressure:
    """Real authenticated probes only; all new dispatches end by original2s."""
    def __init__(self, sender, receiver):
        self.sender, self.receiver = sender, receiver
        self.lock, self.ready = threading.Lock(), threading.Event()
        self.counts = {'invalid': 0, 'rate_limited': 0, 'unexpected': 0, 'transport_error': 0, 'deadline_cancelled': 0}
        self.dispatched = 0
        self.deadline = None
        self.threads = []

    def start(self):
        self.deadline = time.monotonic() + 2
        self.threads = [threading.Thread(target=self.run, daemon=True) for _ in range(3)]
        for thread in self.threads:
            thread.start()

    def run(self):
        while time.monotonic() < self.deadline:
            with self.lock:
                if self.dispatched >= 128:
                    return
                self.dispatched += 1
            category = 'unexpected'
            try:
                result = subprocess.run([str(suite.probe_bin), '--state', str(self.sender.state), '--address',
                    self.receiver.peer_address, '--alpn', 'peerspan-completion/1', '--method', 'POST',
                    '--path', '/bootstrap/v1/activations', '--body-stdin'], input=b'{}', capture_output=True,
                    timeout=max(.001, self.deadline-time.monotonic()), env=self.sender.env)
                if result.returncode == 0:
                    response = json.loads(result.stdout)
                    body = response.get('body')
                    code = body.get('code') if type(body) is dict else None
                    if response.get('status') == 400 and code == 'invalid':
                        category = 'invalid'
                    elif response.get('status') == 429 and code == 'rate_limited':
                        category = 'rate_limited'
                else:
                    category = 'transport_error'
            except subprocess.TimeoutExpired:
                category = 'deadline_cancelled' if time.monotonic() >= self.deadline else 'transport_error'
            except (OSError, ValueError, TypeError, AttributeError, KeyError):
                category = 'transport_error'
            with self.lock:
                self.counts[category] += 1
                if self.counts['invalid'] and self.counts['rate_limited']:
                    self.ready.set()

    def finish(self):
        for thread in self.threads:
            thread.join(timeout=max(0, self.deadline-time.monotonic()) + 1)
        check(not any(t.is_alive() for t in self.threads), 'bounded real pressure did not stop')
        emit({'phase': 'pressure', 'dispatched': self.dispatched, 'counts': dict(self.counts), 'dispatch_window_seconds': 2})
        check(self.counts['invalid'] > 0 and self.counts['rate_limited'] > 0, 'pressure fixture missed actual invalid/rate-limited responses')
        check(self.counts['unexpected'] == self.counts['transport_error'] == 0, 'pressure fixture had an unsupported response or transport failure')


def expired(_number, _frame):
    raise Failure('completion rate-pressure suite exceeded120 seconds')


previous_alarm = signal.signal(signal.SIGALRM, expired)
signal.setitimer(signal.ITIMER_REAL, 120)


@suite.case('genuine_rate_pressure_one_commit_frozen_first_states_and_separate_exact_repair', 'final acceptance exact completion publication')
def experiment():
    phase, pressure = 'genuine_setup', None
    try:
        a, b = suite.host('alice', start=False), suite.host('bob', start=False)
        for host in (a, b):
            config = host.root / 'direct.json'
            config.write_text(json.dumps({'format': 1, 'advertise_bootstrap': ['127.0.0.1:' + str(host.bootstrap_port)],
                'advertise_quic': [], 'rendezvous': [], 'relays': [], 'publish_contacts': False}))
            config.chmod(0o600)
            host.extra_args = ['--transport-config', config]
            host.start()
        net = create_network(a, 'rate-pressure', 'alice')
        key = ssh_key(b.root, 'bob-original'); person = ssh_public_base64(key)
        check(person != net['person_public_key'], 'fixture people are not distinct')
        originals = {p: hashlib.sha256(p.read_bytes()).digest() for p in (a.home / '.config/peerspan/person_ed25519', key)}
        request = join_request(b, invite(a, 'bob', net['id'])['invitation'], key)
        rid, reply = request['request_id'], request['display_code']
        b.ok_incomplete('link', 'approve', '--network', net['id'], '--person-key', key, '--code-stdin', '--approve', input=reply+'\n', timeout=30)
        view = pull_until(b, rid, 'owner_offer_id', timeout=15)
        if view['state'] == 'needs_selection':
            select(b, view)
        view = link_view(b, rid)
        a.ok_incomplete('link', 'admit', '--network', net['id'], '--owner-offer', view['owner_offer_id'], '--selection', view['selection_id'],
            '--person', person, '--expect-host-key', view['host_public_key'], '--expect-device-key', view['device_public_key'],
            '--code-stdin', '--approve', input=reply+'\n', timeout=30)
        view = pull_until(b, rid, 'administrator_offer_id', timeout=15)
        finalize(b, view, key)
        view = pull_until(b, rid, 'owner_finalization_id', timeout=15)
        check(view['state'] == 'needs_commit' and not view['commit_approved'] and get(b, '/v2/networks') == [], 'F bypassed separate requester commitment')
        body = stage_body(view, **{k: view[k] for k in ('owner_offer_id', 'selection_id', 'administrator_offer_id', 'owner_finalization_id')}, approve=False)
        status, preview = b.api('POST', '/v2/link/requests/' + rid + '/commit', body, timeout=5)
        check(status == 200 and not preview['request']['commit_approved'] and preview['review']['scopes'] == 7, 'exact unapproved commit preview unavailable')
        f = dict(a=a, b=b, net=net, person=person, rid=rid, view=view, review=preview['review'])
        authority_before = get(a, '/v2/networks/' + net['id'] + '/catalog'), get(a, '/v2/networks/' + net['id'] + '/members')
        check(operation(a, rid) is None and operation(b, rid) is None, 'fixture applied before requester consent')
        phase = 'real_pressure_precondition'
        pressure = Pressure(b, a); pressure.start()
        check(pressure.ready.wait(max(0, pressure.deadline-time.monotonic())), 'pressure fixture missed actual429 before commit')
        check((get(a, '/v2/networks/' + net['id'] + '/catalog'), get(a, '/v2/networks/' + net['id'] + '/members')) == authority_before
              and operation(a, rid) is None and operation(b, rid) is None and get(b, '/v2/networks') == [], 'malformed activations changed authority/application')
        check(time.monotonic() < pressure.deadline and any(t.is_alive() for t in pressure.threads), 'pressure ended before first commit dispatch')
        phase = 'one_commit_and_immediate_states'
        status, first = b.api('POST', '/v2/link/requests/' + rid + '/commit', {**body, 'approve': True}, timeout=35)
        alice_status, alice = a.api('GET', '/v2/link/requests/' + rid, timeout=5)
        bob_status, bob = b.api('GET', '/v2/link/requests/' + rid, timeout=5)
        first_alice_linked = alice_status == 200 and alice.get('state') == 'linked'
        emit({'phase': 'first_attempt_before_repair', 'commit': public_view(status, first),
            'requester': public_view(bob_status, bob), 'original_participant': public_view(alice_status, alice)})
        check(status == bob_status == alice_status == 200 and bob['state'] == 'linked' and bob['commit_approved'], 'first requester commit did not actually apply')
        saved_bob, saved_consent = operation(b, rid), consent(b, rid)
        check(saved_bob is not None and all(bob[k] == view[k] for k in PINS), 'first application changed exact selected terms')
        finished, pressure = pressure, None
        finished.finish()
        # Explicit diagnostic precondition after all first-result states froze.
        # This cannot repair/satisfy the first-attempt gate; no second commit.
        phase = 'one_post_pressure_diagnostic_resume'
        threading.Event().wait(1)
        repair_status, repair = b.api('POST', '/v2/link/requests/' + rid + '/resume', {}, timeout=35)
        after_a_status, after_a = a.api('GET', '/v2/link/requests/' + rid, timeout=5)
        after_b_status, after_b = b.api('GET', '/v2/link/requests/' + rid, timeout=5)
        emit({'phase': 'separate_post_refill_repair', 'resume': public_view(repair_status, repair),
            'requester': public_view(after_b_status, after_b), 'original_participant': public_view(after_a_status, after_a),
            'first_original_participant_linked': first_alice_linked, 'diagnostic_refill_seconds': 1})
        check(repair_status == after_a_status == after_b_status == 200 and after_a['state'] == after_b['state'] == 'linked', 'one exact post-pressure repair did not apply both participants')
        check(operation(b, rid) == saved_bob and consent(b, rid) == saved_consent, 'exact repair changed application bytes or requester consent')
        check(all(after_b[k] == bob[k] for k in PINS + ['manifest_id', 'activation_id', 'outcome_id']), 'exact repair changed immutable requester application IDs')
        phase = 'signed_applied_authority_and_immutable_identity'
        verify_application(b, f); verify_application(a, f)
        check(all(hashlib.sha256(p.read_bytes()).digest() == value for p, value in originals.items()), 'owning original key changed')
        check(not (b.home / '.config/peerspan/person_ed25519').exists(), 'requester acquired another original source')
        shared.update(complete=True, first_alice_linked=first_alice_linked)
        emit({'phase': 'verified_result', 'real_hosts': 2, 'distinct_people': 2, 'malformed_authority_effects': False,
            'first_original_participant_linked': first_alice_linked, 'one_commit': True, 'one_diagnostic_resume': True,
            'repair_applied_both': True, 'signed_authority_verified': True, 'requester_consent_unchanged': True,
            'requester_application_unchanged': True, 'original_keys_stayed_owned': True})
    except Exception as error:
        # Receive-only stack frames identify the exact failed assertion without
        # retaining locals or printing exception text/protocol bodies publicly.
        category = 'assertion' if isinstance(error, AssertionError) else 'missing_local_file' if isinstance(error, FileNotFoundError) else (
            'missing_response_field' if isinstance(error, KeyError) else 'bounded_process_timeout' if isinstance(error, subprocess.TimeoutExpired)
            else 'read_only_database' if isinstance(error, sqlite3.Error) else 'other_fixture_error')
        try:
            descriptor = os.open(suite.work / 'completion-rate-failure.private.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w') as output:
                traceback.print_tb(error.__traceback__, file=output)
                output.write('closed_category=' + category + '\n')
        except OSError:
            pass
        emit({'phase': phase, 'experiment_complete': False, 'failure_category': category})
        raise Failure('completion rate-pressure diagnostic prerequisite or proof failed at ' + phase) from None
    finally:
        if pressure is not None:
            pressure.finish()


@suite.case('original_participant_applies_by_first_commit_return_under_brief_real_rate_pressure',
    'final acceptance exact completion publication')
def first_attempt_gate():
    if not shared.get('complete'):
        raise Skip('pressure experiment did not establish its required real preconditions and immutable proof')
    check(shared['first_alice_linked'], 'original participant was not applied at the first bounded commit result; later exact repair is separate')


def bootstrap_identity(root, label):
    """Fresh self-signed transport key; it supplies no network authority."""
    cert, key = root / (label + '-cert.pem'), root / (label + '-key.pem')
    result = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ed25519', '-nodes', '-subj', '/CN=boundary', '-days', '1',
        '-keyout', str(key), '-out', str(cert)], capture_output=True, timeout=5)
    check(result.returncode == 0, 'real bootstrap transport certificate creation failed')
    public = subprocess.run(['openssl', 'x509', '-in', str(cert), '-pubkey', '-noout'], capture_output=True, timeout=5)
    check(public.returncode == 0, 'real bootstrap transport public key observation failed')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(cert), str(key))
    context.set_alpn_protocols(['peerspan-bootstrap/1'])
    return context, public.stdout


def bootstrap_post(host, context, path, deadline):
    remaining = deadline - time.monotonic()
    check(remaining > 0, 'bootstrap charged-bucket observation exceeded its2second bound')
    with socket.create_connection(('127.0.0.1', host.bootstrap_port), timeout=min(5, remaining)) as connection:
        with context.wrap_socket(connection, server_hostname='peerspan') as stream:
            check(stream.version() == 'TLSv1.3' and stream.selected_alpn_protocol() == 'peerspan-bootstrap/1',
                  'real bootstrap TLS1.3/ALPN was not established')
            stream.settimeout(max(.001, deadline-time.monotonic()))
            stream.sendall(('POST ' + path + ' HTTP/1.1\r\nHost: peerspan\r\nConnection: close\r\n'
                'Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}').encode())
            response = http.client.HTTPResponse(stream)
            response.begin()
            raw = response.read(4097)
            check(len(raw) <= 4096, 'bootstrap response exceeded bounded diagnostic metadata')
            body = json.loads(raw)
            code = body.get('code') if type(body) is dict else None
            retry = response.getheader('Retry-After')
            return {'status': response.status, 'code': code if type(code) is str and code in CODES else 'other',
                'retry_after': 'absent' if retry is None else 'positive_integer'
                    if retry.isascii() and retry.isdecimal() and 0 < int(retry) <= 30 else 'invalid'}


@suite.case('real_bootstrap_charged_source_bucket_fresh_identity_owner_route_and_known_controls',
    'final acceptance bootstrap owner-route absence under a charged rate bucket')
def bootstrap_boundary_experiment():
    phase = 'bootstrap_transport_fixture'
    try:
        host = suite.host('bootstrap-boundary', start=False)
        config = host.root / 'direct.json'
        config.write_text(json.dumps({'format': 1, 'advertise_bootstrap': ['127.0.0.1:' + str(host.bootstrap_port)],
            'advertise_quic': [], 'rendezvous': [], 'relays': [], 'publish_contacts': False}))
        config.chmod(0o600)
        host.extra_args = ['--transport-config', config]
        host.start()
        first, first_key = bootstrap_identity(host.root, 'first')
        second, second_key = bootstrap_identity(host.root, 'second')
        check(first_key != second_key, 'bootstrap transport identities are not distinct')
        # Both identities/contexts exist before charging starts. No setup IO,
        # refill wait or further identity generation occurs between controls.
        phase = 'bootstrap_initial_invalid_control'
        deadline = time.monotonic() + 2
        initial = bootstrap_post(host, first, '/bootstrap/v1/activations', deadline)
        emit({'phase': phase, 'response': initial})
        check(initial['status'] == 400 and initial['code'] == 'invalid', 'malformed known bootstrap activation did not return400/invalid')
        phase = 'bootstrap_real_rate_pressure'
        attempts, charged = 1, None
        while attempts < 32 and time.monotonic() < deadline:
            charged = bootstrap_post(host, first, '/bootstrap/v1/activations', deadline)
            attempts += 1
            if charged['status'] == 429:
                break
            check(charged['status'] == 400 and charged['code'] == 'invalid', 'known bootstrap pressure returned an unsupported response')
        emit({'phase': phase, 'known_attempts': attempts, 'response': charged})
        check(charged is not None and charged['status'] == 429 and charged['code'] == 'rate_limited'
              and charged['retry_after'] == 'positive_integer', 'bootstrap fixture missed real429/rate_limited with Retry-After')
        phase = 'bootstrap_fresh_identity_owner_observation'
        # Exact BASE from the unchanged access_onboarding public fixture.
        owner = bootstrap_post(host, second, '/v1/onboarding/access-inspection', deadline)
        phase = 'bootstrap_charged_known_after_control'
        after = bootstrap_post(host, second, '/bootstrap/v1/activations', deadline)
        emit({'phase': 'bootstrap_owner_route_frozen', 'owner': owner, 'known_after': after,
              'known_attempts': attempts, 'distinct_transport_keys': True, 'same_loopback_source': True,
              'transport_identity_is_network_authority': False})
        check(after['status'] == 429 and after['code'] == 'rate_limited' and after['retry_after'] == 'positive_integer',
              'known bootstrap route lost charged-bucket control after owner observation')
        check((owner['status'], owner['code']) in ((404, 'not_found'), (429, 'rate_limited')),
              'bootstrap owner-route observation had an unsupported status/code')
        shared.update(bootstrap_boundary_complete=True, bootstrap_owner=owner)
    except Exception as error:
        try:
            descriptor = os.open(suite.work / 'bootstrap-boundary-failure.private.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w') as output:
                traceback.print_tb(error.__traceback__, file=output)
        except OSError:
            pass
        emit({'phase': phase, 'bootstrap_boundary_complete': False})
        raise Failure('bootstrap charged-bucket fixture/control failed at ' + phase) from None


@suite.case('bootstrap_owner_access_inspection_remains_absent_under_charged_source_bucket',
    'final acceptance bootstrap owner-route absence under a charged rate bucket',
    known='observed charged bootstrap bucket masks genuine owner-route absence with429')
def bootstrap_owner_absence_gate():
    if not shared.get('bootstrap_boundary_complete'):
        raise Skip('real bootstrap charged-bucket controls were not established')
    owner = shared['bootstrap_owner']
    check(owner['status'] == 404 and owner['code'] == 'not_found', 'bootstrap owner route did not return required404/not_found under real rate pressure')


try:
    suite.finish()
finally:
    signal.setitimer(signal.ITIMER_REAL, 0)
    signal.signal(signal.SIGALRM, previous_alarm)
