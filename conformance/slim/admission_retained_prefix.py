#!/usr/bin/env python3
"""Exact retained O/S admission with unavailable carriers, final contract430fd14.

Real public owner fixtures create every packet and approval. SQLite is observed
only. A stopped administrator genuinely misses O/S bytes; no rows are removed.
Opaque counted TLS relays never impersonate a host or construct protocol data.
Frozen owner cases are neither executed nor changed: only their independent
non-case helper definitions are reused. This suite has one 120-second budget.
"""
import ast
import base64
from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import select as socket_select
import signal
import socket
import socketserver
import sqlite3
import subprocess
import threading
import time
from datetime import timedelta

from harness import Clock, Failure, Suite, check, create_network, link_view, parse_time, pull_until, select, ssh_key, ssh_public_base64, wait_for
import owner_publication_prerequisite as publication


DERIVED_REVIEW_FIELDS = ('administrator_offer_id', 'person_lease_id', 'host_lease_id')
STATIC_REVIEW_FIELDS = tuple('stage network_id context_id person_id person_public_key host_public_key '
    'device_public_key root_state_id provider owner_offer_id selection_id binding_lease_id '
    'device_lease_id scopes not_after authority_warning'.split())
FIXED_INTENT_FIELDS = tuple('provider root_state_id person_public_key host_public_key device_public_key '
                           'scopes not_after created_at expires_at'.split())
ERROR_CODES = frozenset('invalid forbidden authority_expired device_revoked not_yet_valid '
    'authority_would_be_invalidated not_found proof_required state_conflict operation_conflict '
    'version_exhausted quota_exceeded clock_rollback review_required signer_unavailable '
    'recovery_required expired upgrade_required rate_limited internal transport_unavailable'.split())


def approved_review(status, preview, decision):
    before = preview.get('review') if type(preview) is dict else None
    after = decision.get('review') if type(decision) is dict else None
    fields = set(STATIC_REVIEW_FIELDS) | set(DERIVED_REVIEW_FIELDS)
    shape = type(before) is dict and type(after) is dict and set(before) == set(after) == fields
    mismatches = [field for field in STATIC_REVIEW_FIELDS if not shape or before[field] != after[field]]
    progress = {}
    for field in DERIVED_REVIEW_FIELDS:
        old, new = (before[field], after[field]) if shape else (None, None)
        prefix = 'dpk_' if field == 'administrator_offer_id' else 'ds_'
        filled = old == '-' and type(new) is str and re.fullmatch(prefix + r'[0-9a-f]{64}', new) is not None
        progress[field] = {'unchanged': shape and old == new, 'filled_from_unresolved': filled}
    code = decision.get('code') if type(decision) is dict else None
    print('admission_prefix_approval_public=' + json.dumps({
        'http_status': status if type(status) is int and 100 <= status <= 599 else 'unknown',
        'refused': status != 200, 'error_code': code if type(code) is str and code in ERROR_CODES else 'none_or_unknown',
        'review_shape_matches': shape, 'static_changed_fields': mismatches,
        'derived_progress': progress}, sort_keys=True), flush=True)
    check(status == 200, 'explicit unavailable-carrier approval refused exact terms')
    check(shape and not mismatches and all(value['unchanged'] or value['filled_from_unresolved']
          for value in progress.values()), 'explicit approval changed static review terms or replaced resolved IDs')
    return after


def helpers(suite):
    """Reuse independent fixture helpers, excluding all frozen case bodies."""
    path = Path(__file__).with_name('owner_onboarding.py')
    tree = ast.parse(path.read_text(), filename=str(path))
    nodes = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            nodes.append(node)
        elif isinstance(node, ast.Assign) and not any(isinstance(target, ast.Name) and target.id == 'suite' for target in node.targets):
            nodes.append(node)
        elif isinstance(node, ast.FunctionDef) and not node.decorator_list:
            nodes.append(node)
    namespace = {'__name__': 'independent_owner_helpers', '__file__': str(path), 'suite': suite}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace


def relay_class():
    # This is the independent transparent fixture relay, never runtime code.
    path = Path(__file__).with_name('machine_owner.py')
    tree = ast.parse(path.read_text(), filename=str(path))
    node = next(item for item in tree.body if isinstance(item, ast.ClassDef) and item.name == 'Relay')
    namespace = dict(globals())
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), 'exec'), namespace)
    return namespace['Relay']


def verify_ed25519(suite, key, signature, message, label):
    raw_key = base64.b64decode(key, validate=True)
    raw_signature = base64.b64decode(signature, validate=True)
    check(len(raw_key) == 32 and len(raw_signature) == 64, 'signed result key/signature length')
    public, signed, data = (suite.work / (label + suffix) for suffix in ('.der', '.sig', '.msg'))
    public.write_bytes(bytes.fromhex('302a300506032b6570032100') + raw_key)
    signed.write_bytes(raw_signature); data.write_bytes(message)
    result = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-keyform', 'DER',
        '-inkey', str(public), '-rawin', '-in', str(data), '-sigfile', str(signed)],
        capture_output=True, timeout=5)
    check(result.returncode == 0, 'independent signed-result Ed25519 verification failed')


def verify_lease(suite, envelope, kind, network, view, person, label, maximum_not_after):
    check(type(envelope) is dict and envelope['format'] == 1 and envelope['kind'] == kind
          and envelope['context_id'] == network['context_id'], 'admission grant envelope changed kind/context')
    payload = base64.b64decode(envelope['payload_base64'], validate=True)
    body = json.loads(payload)
    check(body['root_state_id'] == network['root_state_id'] and body['operation_id'] == view['request_id']
          and body['issuer']['kind'] == 'root', 'admission grant changed exact root/request/issuer')
    check(parse_time(body['not_after']) <= parse_time(maximum_not_after), 'signed admission grant extended reviewed lifetime')
    subject = body['subject']
    check(subject['scopes'] == 0, 'administrator person/host grant widened scopes')
    check(subject['person_public_key'] == (person if kind == 'person_lease' else '-')
          and subject['host_public_key'] == (view['host_public_key'] if kind == 'host_lease' else '-'),
          'admission grant changed exact target person/host')
    unsigned = '\n'.join(('peerspan-decentralized-statement-v1', kind, network['context_id'],
                           hashlib.sha256(payload).hexdigest())).encode()
    statement = 'ds_' + hashlib.sha256(unsigned).hexdigest()
    signatures = envelope['signatures']
    check(len(signatures) == 1 and signatures[0]['role'] == 'issuer'
          and signatures[0]['public_key'] == network['root_public_key']
          and signatures[0]['format'] == 'ed25519', 'admission grant changed root signature role/key')
    message = '\n'.join(('peerspan-decentralized-signature-v1', statement, 'issuer', network['root_public_key'])).encode()
    verify_ed25519(suite, network['root_public_key'], signatures[0]['signature'], message, label)
    return statement


def run_case(suite, ns):
    end = time.monotonic() + 120
    relays = []
    Relay = relay_class()

    def host(name):
        h = suite.host(name, start=False, clock=Clock(suite.work / (name + '.clock')))
        relay = Relay(('127.0.0.1', h.bootstrap_port)); relays.append(relay)
        config = h.root / 'transport.json'
        config.write_text(json.dumps({'format': 1, 'advertise_bootstrap': [relay.address],
            'advertise_quic': [], 'rendezvous': [], 'relays': [], 'publish_contacts': False}))
        config.chmod(0o600); h.extra_args = ['--transport-config', config]
        original_api, original_cli = h.api, h.cli
        def api(*args, **kwargs):
            kwargs['timeout'] = min(kwargs.get('timeout', 10), 10, max(.01, end - time.monotonic()))
            return original_api(*args, **kwargs)
        def cli(*args, **kwargs):
            kwargs['timeout'] = min(kwargs.get('timeout', 10), 10, max(.01, end - time.monotonic()))
            return original_cli(*args, **kwargs)
        h.api, h.cli = api, cli
        return h.start()

    def modes(value):
        for relay in relays:
            relay.mode = value

    def counts():
        return tuple(relay.counts() for relay in relays)

    def optional_pending(issuer, rid):
        with closing(sqlite3.connect(ns['db_path'](issuer).as_uri() + '?mode=ro', uri=True, timeout=1)) as db:
            row = db.execute('SELECT record FROM dec_pending WHERE request_id=?', (rid,)).fetchone()
        return json.loads(row[0]) if row is not None else None

    def no_consent(issuer, rid):
        record = optional_pending(issuer, rid)
        check(record is None or (record.get('administrator_offer_id', '-') == '-'
              and record.get('administrator_packet_base64', '-') == '-'), 'negative admission created a signed administrator packet')
        iid = record.get('administrator_intent_id', '-') if record is not None else '-'
        if iid != '-':
            check(ns['intent'](issuer, iid)['record']['approved'] is False, 'negative admission approved administrator consent')
        with closing(sqlite3.connect(ns['db_path'](issuer).as_uri() + '?mode=ro', uri=True, timeout=1)) as db:
            intents = [json.loads(row[0]) for row in db.execute("SELECT record FROM dec_intents WHERE kind='administrator'")]
            signed_frames = db.execute("SELECT count(*) FROM dec_frames WHERE request_id=? AND role='administrator'", (rid,)).fetchone()[0]
        check(signed_frames == 0, 'negative admission retained an administrator frame')
        check(all(intent['approved'] is False and intent['signatures'] == [] for intent in intents
                  if intent.get('operation_id') == rid), 'negative admission retained approved or signed administrator work')

    try:
        issuer, requester = host('administrator'), host('requester')
        network = create_network(issuer, 'retained prefix', 'administrator')
        key = ssh_key(suite.work, 'independent-original')
        person = ssh_public_base64(key)
        parent = ns['project'](requester, 'retained-prefix')
        status, issued = issuer.api('POST', '/v2/networks/' + network['id'] + '/invitations', {
            'member': 'new original', 'expected_person_public_key': person,
            'expires_at': ns['rfc3339'](issuer.now() + timedelta(hours=1))})
        check(status == 201, 'genuine retained-prefix invitation failed')
        code = issued['invitation']
        ns['shared'].update(issuer=issuer, network=network, key=key, person=person, code=code)
        flow = ns['join'](requester, parent, code, person)
        publication.publication_complete(ns, requester, flow, require_all=True)
        rid = flow['outcome']['request_id']
        issuer.stop()  # Before O/S exist: missing bytes are genuine history.
        prepared = ns['owner'](requester, flow, 'prepare')
        approved = ns['owner'](requester, flow, 'approve', prepared)
        iid = approved['owner']['review']['intent_id']
        status, ordinary = requester.api('POST', '/v2/link/requests', {
            'mode': 'new', 'network_id': network['id'], 'person_public_key': person,
            'migration_proposal_id': '-', 'contact_invitation': code, 'helpers': []})
        check(status == 200 and ordinary['request_id'] == rid, 'ordinary reply lookup changed exact request')
        ns['sign_ready'](requester, rid, iid, key)
        view = pull_until(requester, rid, 'owner_offer_id', timeout=15)
        if view['state'] == 'needs_selection':
            select(requester, view)
        view = link_view(requester, rid)
        check(view['state'] == 'needs_administrator' and view['selection_id'] != '-', 'genuine exact O/S was not created')
        original, _ = ns['pending'](requester, rid)
        prefix = {field: original[field] for field in ('owner_packet_base64', 'selection_packet_base64')}
        check(all(type(value) is str and value not in ('', '-') for value in prefix.values()), 'requester lacks genuine O/S bytes')
        body = {'code': ordinary['display_code'], 'network_id': network['id'], 'person_public_key': person,
                'provider_id': 'network_root', 'signature_format': 'ed25519',
                'owner_offer_id': view['owner_offer_id'], 'selection_id': view['selection_id'],
                'expected_host_public_key': requester.public_key,
                'expected_device_public_key': view['device_public_key'], 'approve': False}
        requester.stop(); modes('drop'); issuer.start()
        # A carrier storage ACK does not itself open an ordinary administrator
        # operation. Either an unopened request or a genuine row without O/S
        # bytes supplies this negative precondition; successful preview below
        # still must retain the exact row and both complete packet bytes.
        absent = optional_pending(issuer, rid)
        check(absent is None or all(absent.get(field, '-') == '-' for field in prefix),
              'administrator unexpectedly retained O/S before their creation')
        for approve in (False, True):
            status, _ = issuer.api('POST', '/v2/link/admissions', {**body, 'approve': approve})
            check(not 200 <= status < 300, 'missing packet bytes gained retained-prefix admission')
            no_consent(issuer, rid)

        issuer.stop(); modes('pass'); requester.start(); issuer.start()
        status, live_preview = issuer.api('POST', '/v2/link/admissions', body)
        check(status == 200, 'one genuine available-carrier preview failed to retain O/S')
        retained, _ = ns['pending'](issuer, rid)
        check(all(retained[field] == value for field, value in prefix.items()), 'administrator retained different O/S packet bytes')
        endpoints = retained['carrier_endpoints']
        expected_endpoints = {(relays[0].address, issuer.public_key), (relays[1].address, requester.public_key)}
        # An approver opened from the reply need not retain its own endpoint.
        # Require the genuine requester front and count every actual carrier.
        check(endpoints and all(endpoint['kind'] == 'participant'
              and (endpoint['address'], endpoint['public_key']) in expected_endpoints for endpoint in endpoints)
              and (relays[1].address, requester.public_key) in {
                  (endpoint['address'], endpoint['public_key']) for endpoint in endpoints},
              'ordinary request has an uncounted carrier or helper path')
        requester.stop(); modes('drop')
        for field, approve in (('owner_offer_id', False), ('selection_id', True)):
            wrong = 'dpk_' + ('f' * 64 if body[field] != 'dpk_' + 'f' * 64 else 'e' * 64)
            status, _ = issuer.api('POST', '/v2/link/admissions', {**body, field: wrong, 'approve': approve})
            check(not 200 <= status < 300, 'different requested packet ID gained retained-prefix admission')
            no_consent(issuer, rid)
        before = counts()
        status, preview = issuer.api('POST', '/v2/link/admissions', body)
        check(status == 200 and counts() == before, 'exact retained unapproved preview polled unavailable carriers')
        check(preview['review'] == live_preview['review'], 'unavailable-carrier preview changed exact administrator terms')
        unapproved, _ = ns['pending'](issuer, rid)
        fixed_intent = ns['intent'](issuer, unapproved['administrator_intent_id'])['record']
        status, decision = issuer.api('POST', '/v2/link/admissions', {**body, 'approve': True})
        review = approved_review(status, preview, decision)
        rec, _ = ns['pending'](issuer, rid)
        admin_intent = ns['intent'](issuer, rec['administrator_intent_id'])['record']
        check(admin_intent['approved'] is True, 'exact explicit administrator approval was not retained')
        check(all(admin_intent[field] == fixed_intent[field] for field in FIXED_INTENT_FIELDS),
              'approval changed fixed provider/root/target/scopes/lifetime or intent deadline')
        def signed():
            record, _ = ns['pending'](issuer, rid)
            return record if record.get('administrator_packet_base64', '-') not in ('', '-') else None
        record = wait_for(signed, timeout=10, interval=.1, message='genuine exact approved administrator signature storage')
        packet = json.loads(base64.b64decode(record['administrator_packet_base64'], validate=True))
        check(packet['role'] == 'administrator' and packet['request_id'] == rid
              and packet['context_id'] == network['context_id'] and packet['writer_host_public_key'] == issuer.public_key
              and packet['signer_public_key'] == network['root_public_key']
              and packet['issuer_id'] == network['root_state_id'] and packet['person_public_key'] == '-'
              and packet['device_signature'] == '-' and packet['authority_signature_format'] == 'ed25519'
              and ns['packet_id'](packet) == record['administrator_offer_id'], 'signed administrator packet changed exact root/request/writer')
        message = ns['packet_message'](packet)
        verify_ed25519(suite, issuer.public_key, packet['host_signature'], message, 'administrator-host')
        verify_ed25519(suite, network['root_public_key'], packet['authority_signature'], message, 'administrator-root')
        payload = json.loads(base64.b64decode(packet['payload_base64'], validate=True))
        check(payload['owner_offer_id'] == body['owner_offer_id'] and payload['selection_id'] == body['selection_id']
              and payload['root_state_id'] == network['root_state_id'], 'signed administrator packet substituted the exact retained prefix')
        person_id = verify_lease(suite, payload['person_lease'], 'person_lease', network, view, person, 'person-lease', review['not_after'])
        host_id = verify_lease(suite, payload['host_lease'], 'host_lease', network, view, person, 'host-lease', review['not_after'])
        derived_ids = {'administrator_offer_id': record['administrator_offer_id'],
                       'person_lease_id': person_id, 'host_lease_id': host_id}
        check(all(response['review'][field] in ('-', expected) for response in (preview, decision)
                  for field, expected in derived_ids.items()), 'review derived IDs do not match actual signed packet/grants')
        check(all(record[field] == value for field, value in prefix.items()), 'approval/signing changed retained O/S bytes')
        print('admission_retained_prefix_public=' + json.dumps({'missing_bytes_refused': True,
            'wrong_ids_refused': True, 'exact_preview_carrier_changes': False,
            'unavailable_carrier_approval_retained': True, 'signed_packet_verified': True,
            'signed_grant_count': 2, 'counted_carrier_endpoint_count': len(endpoints),
            'approval_or_publication_carriers_changed': counts() != before}, sort_keys=True), flush=True)
    finally:
        for relay in relays:
            relay.close()


def main():
    suite = Suite('admission_retained_prefix', __doc__)
    namespace = helpers(suite)
    def expired(_signum, _frame):
        raise Failure('retained-prefix suite exceeded its complete 120-second budget')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 120)
    try:
        suite.case('exact_retained_prefix_without_carrier_and_negative_missing_or_wrong_prefix',
                   'final acceptance retained administrator prefix')(lambda: run_case(suite, namespace))
        suite.finish()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


if __name__ == '__main__':
    main()
