#!/usr/bin/env python3
"""Combined genuine guided two-host machine-link acceptance, section49.

Independent public contracts and independently authored fixtures only. One
selected creator device15/folded ceremony, three shared cases: pinned guided
return and automatic owner F; one response-lost real Complete and CLI Lookup;
actual membership, unchanged preexisting policy/grants and separate readiness.
The original is generated only in A's normal private home. Both hosts remain
live. No advanced protocol driver, original transfer, clock jump, fabricated
signed data/rows, stopped worker or hidden mutation retry supplies progress.

Public crypto verification is copied from independent section45/46/47 fixtures;
those eager suites are never imported. Counted TCP/UDP carry real encrypted
traffic in both directions. This live-progress suite makes no global DB/zero-IO
purity or interface-attribution claim. All74 prior files/native440 stay exact.
Limits: original-provider/separate-admin/reused-binding/fault/expiry/race
matrices remain existing coverage; GUI/reload/restart/installed/physical/model
and full upgrade/#35 acceptance remain later gates. Root executes committed
source; the independent author only reads/parses/audits it.
"""
import atexit
import base64
import hashlib
import http.server
import json
import re
import select
import socket
import socketserver
import sqlite3
import stat
import struct
import subprocess
import threading
import time
import urllib.parse
from contextlib import closing
from datetime import timedelta

from harness import Suite, UnixHTTPConnection, check, parse_time, rfc3339, ssh_public_base64, wait_for
from counted_peer import CountedUDP

suite = Suite('guided_machine', __doc__)
PROJECT = '/v1/onboarding/project-flows'
INVITATIONS = '/v1/onboarding/invitation-flows'
BASE = '/v1/onboarding/join-flows'
MACHINE = '/v1/onboarding/machine-owner-consent'
PREFIXES = ('psi2-', 'psl2-', 'peerspan-invite-v1.', 'peerspan-member-invite-v1.',
            'peerspan-person-invite-v1.', 'token_', 'instance_')
shared = {}

INSPECT_TOP = set('version host_id context flow_id join_review_id observed_at request review_id review next_action'.split())
INSPECT_REVIEW = set('version kind host_id context agent flow_id join_review_id request_id network member person_public_key host_public_key device_public_key request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id owner_root_state_id root_state_id person_lease_id host_lease_id binding_lease_id device_lease_id owner_provider host_admission reused_binding scopes binding_scopes not_after created_at expires_at request_stage_deadline'.split()) | {'effects'}
PROVIDER = set('kind person_public_key host_public_key device_public_key lease_id root_state_id scopes not_after'.split())
LINK = set('request_id role mode state network_id context_id migration_proposal_id person_public_key host_public_key device_public_key created_at expires_at request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id manifest_id activation_id outcome_id selection_approved commit_approved completed attention next'.split())
INSPECT_EFFECTS = {**{k: True for k in ('verify_existing_owner', 'verify_requester_selection', 'verify_host_admission', 'verify_owner_finalization')},
    **{k: False for k in ('prepare_commit_intent', 'approve_commit_intent', 'sign_requester_commit', 'publish_requester_commit',
                         'apply_network', 'grant_membership', 'grant_machine_powers', 'grant_agent_access', 'share_files', 'share_conversation', 'capability_calls')}}
CONSENT_TOP = set('version host_id context flow_id join_review_id observed_at request consent'.split())
CONSENT_REVIEW = set('version kind consent_id host_id context agent flow_id join_review_id request_id intent_id inspection_review_id inspection created_at expires_at effects'.split())
RECORD = set('format operation_id approved approved_at review_base64 provider root_state_id person_public_key host_public_key device_public_key scopes not_after created_at expires_at templates signatures completed terminal result_base64'.split())
CONSENT_EFFECTS = {**{k: True for k in ('approve_commit_intent', 'authorize_binding_host_signature',
    'authorize_requester_commit_signatures', 'authorize_commit_publication', 'authorize_local_application')},
    **{k: False for k in ('grant_agent_access', 'share_files', 'share_conversation', 'capability_calls')}}
DECISION = 'complete_machine_requester_commit'
COMPLETION = set('state review_id manifest_id activation_id outcome_id participant_delivery agent_access connection_readiness'.split())

def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()

def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()

def digest(domain, value):
    return 'review_' + hashlib.sha256(domain.encode() + b'\n' + canonical(value)).hexdigest()

def db_path(h):
    matches = []
    for p in h.state.glob("*.db"):
        with closing(sqlite3.connect(f"file:{p}?mode=ro", uri=True)) as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='networks'").fetchone():
                matches.append(p)
    check(len(matches) == 1, "expected one host database")
    return matches[0]

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

def ssh_string(value):
    return struct.pack('>I', len(value)) + value

def statement_id(envelope):
    if isinstance(envelope, str):
        return envelope
    raw = base64.b64decode(envelope['payload_base64'], validate=True)
    message = '\n'.join(('peerspan-decentralized-statement-v1', envelope['kind'],
                         envelope['context_id'], hashlib.sha256(raw).hexdigest()))
    return 'ds_' + hashlib.sha256(message.encode()).hexdigest()

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

def validate_consent(f, value):
    b, flow = f['b'], f['flow']
    check(type(value) is dict and set(value) == CONSENT_TOP and type(value['version']) is int and value['version'] == 1, 'closed exact requester consent wrapper')
    check(value['host_id'] == b.id and value['context'] == context(f['parent']) and value['flow_id'] == flow['flow_id']
          and value['join_review_id'] == flow['review_id'], 'exact recorded flow/host/context/agent attribution')
    check(re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value['observed_at'])
          and abs((parse_time(value['observed_at']) - b.now()).total_seconds()) < 5, 'canonical effective observation')
    request = value['request']
    check(set(request) == LINK and all(request[key] == f['view'][key] for key in ('request_id', 'network_id', 'context_id', 'person_public_key', 'host_public_key', 'device_public_key', 'request_packet_id', 'owner_offer_id', 'selection_id', 'administrator_offer_id', 'owner_finalization_id')) and request['request_id'] == f['rid']
          and request['role'] == 'requester' and request['mode'] == 'new' and request['migration_proposal_id'] == '-'
          and request['person_public_key'] == f['person'] and request['host_public_key'] == b.public_key, 'complete exact requester LINK_VIEW')
    phases = ['request_created', 'owner_offered', 'owner_selected', 'owner_finalized', 'commit_persisted', 'locally_applied']
    check(type(request['completed']) is list and 4 <= len(request['completed']) <= 6
          and request['completed'] == phases[:len(request['completed'])], 'live requester history regressed or invented folded stages')
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
        check(request['commit_approved'] is True and receipt['approved'] is intent['approved'] is current['commit_approved'] is True
              and receipt['approved_at'] == intent['approved_at'] != '-' and current['commit_intent_id'] == r['intent_id'], 'non-atomic dual/pending approval/time/reference')
    else:
        check(receipt['approved'] is False and receipt['approved_at'] == '-', 'unapproved receipt gained project attribution')
        if c['state'] == 'review':
            check(intent['approved'] is False and intent['approved_at'] == '-' and intent['signatures'] == []
                  and not current['commit_approved'] and current['commit_intent_id'] == '-' and current['commit_packet_base64'] == '-', 'preparation signed/approved/published requester work')
    no_original(f); public(value, *f['secrets'])

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

def application_proof(f, value, h):
    """Independent wire9 transcript, manifest, activation, outcome and signer IDs."""
    b, rid = f['b'], f['rid']; retained = operation(h, rid); record = retained['record']
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
    check((h is not b or packet_id(outcome) == value['completion']['outcome_id']) and outcome['role'] == 'outcome'
          and outcome['writer_host_public_key'] == h.public_key and outcome['request_id'] == rid
          and result['manifest_id'] == manifest_id and result['activation_id'] == activation_id
          and result['activation_sha256'] == hashlib.sha256(raw_activation).hexdigest()
          and result['applied_at'] == record['applied_at'] and result['observed_root_state_id'] == review['root_state_id'],
          'actual outcome disagrees with returned application evidence')
    ed25519(h.public_key, outcome['host_signature'], packet_message(outcome), h.name + '-completion-outcome')
    current, secret = pending(h, rid)
    check(current['terminal'] == 'applied' and secret is None and current['outcome_packet_base64'] == record['outcome_packet_base64'],
          'application did not atomically retain outcome/retire pairing secret')
    check([v['id'] for v in get(b, '/v2/networks')] == [f['network']['id']], 'application adopted another network')
    if h is b:
        with closing(sqlite3.connect(f'file:{db_path(b)}?mode=ro', uri=True)) as db:
            selected = db.execute('SELECT provider_kind,person_key,device_key,lease_id FROM dec_signers WHERE network_id=? AND context_id=?',
                (f['network']['id'], f['network']['context_id'])).fetchall()
        check(selected == [('device', f['person'], review['device_public_key'], review['device_lease_id'])], 'application selected another device/provider')
    events = get(h, '/v1/activity?limit=1000')
    check(len([event for event in events if event['kind'] == 'network.link_applied']) == 1, 'participant lacks exactly one actual application event')
    return retained

class CountedTCP:
    """Opaque bootstrap relay; every advertised TCP direction stays counted."""
    def __init__(self, target):
        self.target, self.lock = target, threading.Lock()
        self.connections = self.sent = self.returned = 0
        outer = self
        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                with outer.lock:
                    outer.connections += 1
                try:
                    with socket.create_connection(outer.target, timeout=5) as upstream:
                        while True:
                            ready, _, _ = select.select([self.request, upstream], [], [], .1)
                            for source in ready:
                                data = source.recv(65536)
                                if not data:
                                    return
                                with outer.lock:
                                    if source is self.request:
                                        outer.sent += len(data)
                                    else:
                                        outer.returned += len(data)
                                (upstream if source is self.request else self.request).sendall(data)
                except OSError:
                    return
        self.server = Server(('127.0.0.1', 0), Handler)
        while self.server.server_address[1] == target[1]:
            self.server.server_close()
            self.server = Server(('127.0.0.1', 0), Handler)
        self.address = '127.0.0.1:' + str(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
        self.thread.start()
        atexit.register(self.close)
    def counts(self):
        with self.lock:
            return self.connections, self.sent, self.returned
    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=1)


def host(name):
    h = suite.host(name, start=False)
    h.relay = CountedTCP(('127.0.0.1', h.bootstrap_port))
    h.counted_peer = CountedUDP(('127.0.0.1', h.peer_port))
    path = h.root / 'transport.json'
    path.write_bytes(compact({'format': 1, 'advertise_bootstrap': [h.relay.address],
        'advertise_quic': [h.counted_peer.address], 'rendezvous': [], 'relays': [], 'publish_contacts': False}))
    path.chmod(0o600)
    h.original = h.home / '.config/peerspan/person_ed25519'
    h.extra_args = ['--transport-config', str(path)]
    h.start()
    return h


def traffic(f):
    return tuple(counts for h in (f['a'], f['b']) for counts in (h.relay.counts(), h.counted_peer.counts()))


def api(h, method, path, data=None, *, expected=200, timeout=5):
    status, value = h.api(method, path, data, timeout=timeout)
    public(value, *shared.get('secrets', []))
    check(status == expected, 'guided public operation HTTP ' + str(status))
    return value


def get(h, path):
    return api(h, 'GET', path)


def link_view(h, rid):
    value = get(h, '/v2/link/requests/' + rid)
    check(type(value) is dict and set(value) == LINK, 'closed real public request view')
    return value


def project(h, name):
    data = {'project_root': str(h.root / 'private-project'), 'native_session_id': 'private-conversation-' + name,
        'integration': 'claude-code', 'agent': {'kind': 'new', 'name': 'Agent "東京" ' + name, 'owner': 'Owner é'}}
    value = api(h, 'POST', PROJECT, data, expected=201)
    check(value['state'] == 'review' and value['review_id'] == digest('peerspan-project-review-v1', value['review']),
          'exact independent project review')
    approved = api(h, 'POST', PROJECT + '/' + value['flow_id'] + '/decision', {
        **{key: data[key] for key in ('project_root', 'native_session_id', 'integration')},
        'review_id': value['review_id'], 'decision': 'approve'})
    check(approved['state'] == 'attached' and approved['review'] == value['review'], 'exact project attachment')
    return approved


def context(parent):
    return {'project_flow_id': parent['flow_id'], 'project_review_id': parent['review_id'],
        **{key: parent['review'][key] for key in ('project_root', 'native_session_id', 'integration')}}


def no_original(f):
    a, b = f['a'], f['b']
    check(a.original.is_file() and (hashlib.sha256(a.original.read_bytes()).hexdigest(), stat.S_IMODE(a.original.stat().st_mode)) == f['original'],
          'existing original file/hash/mode changed')
    check(not b.original.exists() and not (b.home / '.ssh').exists()
          and 'SSH_AUTH_SOCK' not in b.env, 'fresh host acquired an original/SSH-agent source')


def rows(h, query, params=()):
    with closing(sqlite3.connect(f'file:{db_path(h)}?mode=ro', uri=True)) as db:
        return db.execute(query, params).fetchall()


def policy_artifacts(h, net, person):
    path = '/v2/networks/' + net + '/policy/' + urllib.parse.quote(person, safe='')
    status, value = h.api('GET', path, timeout=5)
    check(status in (200, 404), 'current signed policy read failed')
    if status == 200:
        check(type(value) is dict and set(value) == {'statement_id', 'statement_base64'}, 'complete current signed policy')
        envelope = json.loads(base64.b64decode(value['statement_base64'], validate=True))
        check(statement_id(envelope) == value['statement_id'], 'policy semantic identity mismatch')
        for index, signature in enumerate(envelope['signatures']):
            message = '\n'.join(('peerspan-decentralized-signature-v1', value['statement_id'], signature['role'], signature['public_key'])).encode()
            verify_signature(signature['format'], signature['public_key'], signature['signature'], message, 'policy-' + h.name + str(index))
    # Complete public current signed bytes and complete ordinary grant records;
    # no normalization or assertion that same-person effective access is empty.
    grants = get(h, '/v1/grants')
    check(type(grants) is list, 'ordinary complete grants projection must be an array')
    return status, value, grants


def inspection_body(f):
    return {'context': context(f['parent']), 'join_review_id': f['flow']['review_id']}


def requester_endpoint(f, action):
    return BASE + '/' + f['flow']['flow_id'] + '/machine-commit/' + action


def checkpoint(f, predicate, *, seconds, message):
    last = {}
    def observed():
        for role, h in (('existing', f['a']), ('requester', f['b'])):
            status, value = h.api('GET', '/v2/link/requests/' + f['rid'], timeout=5)
            last[role] = status, value
        return predicate(last)
    try:
        return wait_for(observed, timeout=seconds, interval=.1, message=message)
    except Exception:
        try:
            states = {'pending', 'needs_owner', 'needs_selection', 'needs_administrator', 'needs_finalization',
                      'needs_commit', 'linked', 'expired', 'cancelled', 'invalidated'}
            codes = {'not_found', 'request_unavailable', 'proof_required', 'expired', 'state_conflict', 'invalid'}
            report = []
            for role, (status, value) in last.items():
                value = value if type(value) is dict else {}
                report.append({'role': role, 'http_status': status if type(status) is int else None,
                    'state': value.get('state') if value.get('state') in states else 'unknown',
                    'code': value.get('code') if value.get('code') in codes else 'unknown',
                    'present': {key: type(value.get(key)) is str and value[key] != '-' for key in (
                        'owner_offer_id', 'selection_id', 'owner_finalization_id', 'manifest_id', 'activation_id', 'outcome_id')},
                    'selection_approved': value.get('selection_approved') if type(value.get('selection_approved')) is bool else None,
                    'commit_approved': value.get('commit_approved') if type(value.get('commit_approved')) is bool else None})
            print('guided_machine_checkpoint_public=' + json.dumps(report, sort_keys=True), flush=True)
        except Exception:
            pass
        raise


def owner_consent(f, value, state):
    check(set(value) == set('version host_id context observed_at request inspection consent'.split())
          and value['version'] == 1 and value['host_id'] == f['a'].id and value['context'] == context(f['owner_parent']),
          'closed exact existing-computer consent wrapper')
    consent = value['consent']; review = consent['review']; inspected = f['owner_inspection']
    check(set(consent) == {'consent_id', 'review_id', 'review', 'state', 'next_action'} and consent['state'] == state
          and set(review) == set('version kind consent_id host_id context agent request_id request_packet_id inspection_review_id inspection intent_id proposed_owner_offer_id replaces_consent_id created_at expires_at request_stage_deadline effects'.split()),
          'closed machine owner receipt')
    check(consent['review_id'] == digest('peerspan-machine-owner-consent-v1', review)
          and review['inspection_review_id'] == inspected['review_id'] and review['inspection'] == inspected['review']
          and review['context'] == context(f['owner_parent']) and review['agent'] == f['owner_parent']['review']['agent']
          and review['request_id'] == f['rid'] and review['request_packet_id'] == inspected['review']['request_packet_id']
          and review['consent_id'] == consent['consent_id'] and review['replaces_consent_id'] == '-', 'exact owner receipt digest/pins')
    expected_effects = {**{k: True for k in ('approve_owner_intent', 'authorize_owner_offer_signature',
        'publish_owner_offer_after_signatures', 'authorize_owner_finalization', 'authorize_binding_and_device_signatures', 'authorize_host_admission_if_folded')},
        **{k: False for k in ('grant_membership_now', 'grant_machine_powers_now', 'grant_agent_access',
        'authorize_requester_selection', 'commit_request', 'share_files', 'share_conversation', 'capability_calls')}}
    check(review['version'] == 1 and review['kind'] == 'approve_existing_person_machine'
          and review['host_id'] == f['a'].id and review['effects'] == expected_effects,
          'owner approval kind/host/effects changed')
    receipt, ordinary = (load_intent(f['a'], review[key]) for key in ('consent_id', 'intent_id'))
    m, o = receipt['record'], ordinary['record']
    check(receipt['kind'] == 'machine_owner_review' and ordinary['kind'] == 'owner'
          and receipt['secret'] is ordinary['secret'] is None and set(m) == set(o) == RECORD
          and m['templates'] == m['signatures'] == [] and m['completed'] is True and m['terminal'] == m['result_base64'] == '-'
          and base64.b64decode(m['review_base64'], validate=True) == canonical(review), 'unsigned owner metadata became authority')
    check(m['operation_id'] == 'mrev_' + hashlib.sha256(b'peerspan-machine-owner-review-key-v1\n' + canonical({'host_id': f['a'].id, 'request_id': f['rid']})).hexdigest(),
          'owner receipt storage domain mismatch')
    check(o['provider'] == {'kind': 'device', 'signer_public_key': f['provider']['device_public_key'],
        'signature_format': 'ed25519', 'lease_id': f['provider']['lease_id']}
        and all(m[key] == o[key] for key in ('provider', 'root_state_id', 'person_public_key', 'host_public_key', 'device_public_key', 'scopes', 'not_after'))
        and o['scopes'] == 7 and o['not_after'] == inspected['review']['not_after'], 'ordinary owner changed selected finite device authority')
    request, _secret = pending(f['a'], f['rid'])
    check(review['created_at'] == m['created_at'] and review['expires_at'] == m['expires_at']
          and parse_time(review['expires_at']) == min(parse_time(o['created_at']) + timedelta(seconds=300),
              parse_time(request['expires_at']), parse_time(review['request_stage_deadline']), parse_time(o['not_after'])),
          'owner receipt restarted fixed ordinary/request/stage/authority deadline')
    check(m['approved'] is o['approved'] is (state == 'approved')
          and m['approved_at'] == o['approved_at'] and (m['approved_at'] != '-') == (state == 'approved'), 'owner dual approval/time is not coherent')
    check(len(rows(f['a'], "SELECT intent_id FROM dec_intents WHERE kind='machine_owner_review'")) == 1,
          'duplicate owner receipt')
    return consent


def initial_signatures(f, value):
    consent = f['owner_consent']; review = consent['review']
    check(set(value) == set('version host_id context observed_at request inspection consent signing'.split())
          and core(value['consent']) == core(consent), 'signing changed approved owner receipt')
    owner = load_intent(f['a'], review['intent_id'])['record']; templates = owner['templates']
    first = [t for t in templates if t['object_type'] == 'owner_offer_packet']
    folds = [t for t in templates if t['object_type'] == 'host_lease']
    check(len(first) == len(folds) == 1 and first[0]['slot_id'] == 1, 'actual initial three-slot folded template prerequisite')
    packet = json.loads(base64.b64decode(first[0]['template_base64'], validate=True))
    fold = json.loads(base64.b64decode(folds[0]['template_base64'], validate=True))
    check(packet_id(packet) == review['proposed_owner_offer_id'] and packet['signer_public_key'] == f['provider']['device_public_key']
          and fold['kind'] == 'host_lease', 'initial typed owner/fold identities changed')
    plan = {(1, 'host'): (f['a'].public_key, packet_message(packet)),
            (1, 'authority'): (f['provider']['device_public_key'], packet_message(packet)),
            (folds[0]['slot_id'], 'issuer'): (f['provider']['device_public_key'], '\n'.join((
                'peerspan-decentralized-signature-v1', statement_id(fold), 'issuer', f['provider']['device_public_key'])).encode())}
    signatures = [s for s in owner['signatures'] if (s['slot_id'], s['role']) in plan]
    check(len(signatures) == len({(s['slot_id'], s['role']) for s in signatures}), 'duplicate initial signature slot')
    for index, signature in enumerate(signatures):
        key, message = plan[(signature['slot_id'], signature['role'])]
        ed25519(key, signature['signature'], message, 'initial-' + str(index))
    marker = value['signing']
    check(type(marker) is dict and set(marker) == set('state intent_id proposed_owner_offer_id signature_count required_signatures can_sign next_action owner_offer_publication host_admission machine_powers requester_selection request_commit agent_access connection_readiness'.split())
          and marker['required_signatures'] == 3 and marker['intent_id'] == review['intent_id']
          and marker['proposed_owner_offer_id'] == packet_id(packet), 'exact initial signature marker')
    check(all(marker[key] == 'not_verified' for key in ('owner_offer_publication', 'host_admission', 'machine_powers',
          'requester_selection', 'request_commit', 'agent_access', 'connection_readiness')), 'signing marker overclaimed global progress')
    # The worker may complete more slots after this captured marker. Verify the
    # captured count's range here; the final marker and all3 stored signatures
    # are required together after the one explicit continuation when necessary.
    check(type(marker['signature_count']) is int and 0 <= marker['signature_count'] <= len(signatures) <= 3,
          'marker signature evidence exceeds actual initial plan')
    if marker['state'] == 'signed':
        check(marker['signature_count'] == len(signatures) == 3 and marker['can_sign'] is False, 'signed marker lacks three exact signatures')
    else:
        check(marker['state'] in {'unsigned', 'partial'} and marker['signature_count'] < 3, 'inconsistent incomplete signing state')
    return marker


class LostCompletion:
    """Forward exactly one unchanged private HTTP body; lose only its real200."""
    def __init__(self, h):
        self.state = suite.work / 'lost-response-socket'
        self.state.mkdir(mode=0o700)
        self.calls, self.result, self.failed = [], None, False
        outer = self
        class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass
            def do_POST(self):
                try:
                    raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                    outer.calls.append((self.command, self.path, raw))
                    check(len(outer.calls) == 1, 'response drop forwarded more than one completion')
                    conn = UnixHTTPConnection(str(h.state / 'admin.sock'), timeout=95)
                    try:
                        conn.request(self.command, self.path, body=raw, headers={'Content-Type': 'application/json'})
                        response = conn.getresponse()
                        data = response.read()
                        outer.result = response.status, json.loads(data)
                    finally:
                        conn.close()
                    self.connection.shutdown(socket.SHUT_RDWR)
                except Exception:
                    outer.failed = True
        self.server = Server(str(self.state / 'admin.sock'), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
    def __enter__(self):
        self.thread.start()
        return self
    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def current_access(f, h, parent):
    data = {'context': context(parent), 'network_id': f['network']['id'], 'person_public_key': f['person']}
    value = api(h, 'POST', '/v1/onboarding/access-inspection', data)
    check(set(value) == set('version host_id context observed_at review_id review next_action'.split())
          and value['version'] == 1 and value['host_id'] == h.id and value['context'] == context(parent)
          and value['next_action'] == 'review_agent_access', 'closed exact current access inspection')
    r = value['review']
    check(value['review_id'] == digest('peerspan-project-access-inspection-v1', r)
          and r['kind'] == 'inspect_project_agent_access' and r['agent'] == parent['review']['agent']
          and r['context'] == context(parent) and r['network']['id'] == f['network']['id']
          and r['network']['context_id'] == f['network']['context_id'] and r['participant']['person_public_key'] == f['person'],
          'current access changed explicit project/person/network selection')
    expected_hosts = get(h, '/v2/networks/' + f['network']['id'] + '/members')['members']
    check(r['participant']['hosts'] == [row for row in expected_hosts if row['person_public_key'] == f['person']],
          'current access omitted actual participant host authority')
    status, policy, _grants = policy_artifacts(h, f['network']['id'], f['person'])
    if status == 404:
        check(r['policy'] is None, 'missing genuine current policy became permission')
    else:
        envelope = json.loads(base64.b64decode(policy['statement_base64'], validate=True))
        signed = json.loads(base64.b64decode(envelope['payload_base64'], validate=True))
        body = json.loads(base64.b64decode(signed['body_base64'], validate=True))
        check(r['policy']['statement_id'] == policy['statement_id'] and r['policy']['body'] == body,
              'current policy projection changed signed complete body')
    check(r['effects'] == {'inspect_current_membership': True, 'inspect_current_policy': True,
        **{k: False for k in ('prepare_access', 'approve_access', 'sign_policy', 'publish_policy', 'grant_agent_access',
            'share_files', 'share_conversation', 'capability_calls')}}, 'access inspection manufactured a grant')
    ready = api(h, 'POST', '/v1/onboarding/readiness', data)
    check(set(ready) == {'version', 'host_id', 'context', 'observed_at', 'inspection', 'readiness'}
          and ready['context'] == context(parent) and ready['host_id'] == h.id, 'closed exact readiness wrapper')
    inspected = ready['inspection']
    check(set(inspected) == {'review_id', 'review'} and inspected['review_id'] == digest('peerspan-project-access-inspection-v1', inspected['review'])
          and inspected['review'] == r, 'separate readiness changed current access facts')
    readiness = ready['readiness']
    check(set(readiness) == set('direction session_id adapter_connections peers peer_reachability model_receipt connection_readiness'.split())
          and readiness['direction'] == 'participant_hosts_to_project_agent'
          and readiness['session_id'] == parent['review']['session_id'] and readiness['adapter_connections'] == []
          and all(readiness[k] == 'not_verified' for k in ('peer_reachability', 'model_receipt', 'connection_readiness')),
          'membership/link/access inferred adapter, peer, model or overall readiness')
    peers = readiness['peers']
    expected = sorted(('host_' + hashlib.sha256(base64.b64decode(row['host_public_key'], validate=True)).hexdigest(), row['host_public_key'])
        for row in r['participant']['hosts'] if row['host_public_key'] != h.public_key)
    check([(p['host_id'], p['host_public_key']) for p in peers] == expected, 'readiness selected another machine')
    expected_self = {'kind': 'self', 'actions': ['message.append', 'task.submit', 'task.delegate'],
        'max_message_bytes': 65536, 'max_artifact_bytes': 1073741824}
    for peer in peers:
        check(set(peer) == {'host_id', 'host_public_key', 'authorizations'} and peer['authorizations']
              and peer['authorizations'][0] == expected_self, 'same-person self authorization was denied or misrepresented')
        for authorization in peer['authorizations']:
            check(authorization.get('kind') in {'self', 'policy'} and type(authorization.get('actions')) is list
                  and set(authorization['actions']) <= {'message.append', 'task.submit', 'task.delegate'},
                  'link/readiness introduced a grant or widened actions')
    return value, ready


@suite.case('guided_pinned_return_exact_device15_owner_consent_and_automatic_folded_finalization', 'guided49 verification1')
def _():
    f = shared
    a, b = host('existing'), host('requester')
    f.update(a=a, b=b, secrets=[])
    check(a.id != b.id and a.public_key != b.public_key and not a.original.exists() and not b.original.exists(),
          'genuine isolated fresh hosts/original prerequisite')
    result = a.cli('network', 'create', 'Combined "東京" network', '--as', 'Existing "é" person', timeout=60)
    check(result.code == 0 and type(result.json) is dict, 'ordinary local network creation failed')
    net = result.json
    check(net['id'] == 'net_' + hashlib.sha256(base64.b64decode(net['genesis_root_public_key'], validate=True)).hexdigest()
          and net['mode'] == 'decentralized' and net['authority']['state'] == 'usable'
          and net['provider']['kind'] == 'device' and net['provider']['scopes'] == 15, 'actual creator device15 prerequisite')
    check(a.original.is_file() and stat.S_IMODE(a.original.stat().st_mode) == 0o600, 'normal protected original was not generated on existing computer')
    person = ssh_public_base64(a.original)
    f.update(network=net, person=person, provider=net['provider'],
        original=(hashlib.sha256(a.original.read_bytes()).hexdigest(), stat.S_IMODE(a.original.stat().st_mode)))
    f['owner_parent'], f['parent'] = project(a, 'existing'), project(b, 'requester')
    f['policy_before'] = policy_artifacts(a, net['id'], person)
    people = get(a, '/v2/networks/' + net['id'] + '/persons')['persons']
    people = [p for p in people if p['person_public_key'] == person]
    check(len(people) == 1, 'current verified existing person missing/ambiguous')
    person_row = people[0]
    proposal = api(a, 'POST', INVITATIONS, {'context': context(f['owner_parent']), 'network_id': net['id'],
        'member': person_row['member'], 'expected_person_public_key': person}, expected=201)
    check(proposal['state'] == 'review' and proposal['invitation'] is None
          and proposal['review_id'] == digest('peerspan-invitation-review-v1', proposal['review']), 'exact guided invitation review')
    inv_review = proposal['review']
    check(inv_review['network'] == {k: net[k] for k in ('id', 'name', 'context_id', 'genesis_root_public_key')}
          and inv_review['member'] == person_row['member'] and inv_review['expected_person_public_key'] == person
          and inv_review['inviter_host_public_key'] == a.public_key, 'guided invitation changed verified member/person/network pin')
    issued = api(a, 'POST', INVITATIONS + '/' + proposal['flow_id'] + '/decision', {
        'context': context(f['owner_parent']), 'review_id': proposal['review_id'], 'decision': 'approve'})
    check(issued['state'] == 'issued' and issued['review'] == inv_review, 'invitation decision changed exact review')
    status, handoff = a.api('POST', INVITATIONS + '/' + proposal['flow_id'] + '/handoff', {
        'context': context(f['owner_parent']), 'review_id': proposal['review_id']}, timeout=5)
    check(status == 200 and set(handoff) == set('version flow_id review_id network_id context_id invitation_id invitation expires_at'.split())
          and handoff['invitation_id'] == issued['invitation']['invitation_id'] and handoff['invitation'].startswith('psi2-'),
          'authentic guided private invitation handoff failed')
    code = handoff['invitation']; f['secrets'].append(code)
    preview = api(b, 'POST', '/v1/onboarding/invitation-preview', {'context': context(f['parent']), 'invitation': code})
    check(preview['review_id'] == digest('peerspan-invitation-preview-v1', preview['review'])
          and preview['review']['invitation']['automatic_return'] is True
          and preview['review']['invitation']['expected_person_public_key'] == person
          and preview['review']['invitation']['member'] == person_row['member'], 'authentic public pinned preview/automatic return')
    check(get(b, '/v2/link/requests') == [] and get(b, '/v2/networks') == [], 'preview created a request or adoption')
    proposed = api(b, 'POST', BASE, {'context': context(f['parent']), 'invitation': code, 'person_public_key': person}, expected=201)
    check(proposed['state'] == 'review' and proposed['outcome'] is None
          and proposed['review_id'] == digest('peerspan-join-review-v1', proposed['review'])
          and proposed['review']['invitation_review_id'] == preview['review_id']
          and proposed['review']['person_public_key'] == person, 'exact guided machine request terms')
    check(get(b, '/v2/link/requests') == [] and not b.original.exists(), 'unapproved proposal created identity/request')
    flow = api(b, 'POST', BASE + '/' + proposed['flow_id'] + '/decision', {'context': context(f['parent']),
        'review_id': proposed['review_id'], 'decision': 'approve', 'invitation': code}, timeout=30)
    check(flow['state'] == 'requested' and flow['review'] == proposed['review']
          and flow['outcome']['network_id'] == net['id'] and flow['outcome']['context_id'] == net['context_id']
          and flow['outcome']['person_public_key'] == person, 'guided exact request publication failed')
    f.update(flow=flow, rid=flow['outcome']['request_id'])
    incoming = wait_for(lambda: next((v for v in get(a, '/v2/link/requests') if v['request_id'] == f['rid']), None),
        timeout=15, interval=.1, message='actual guided automatic incoming return')
    check(incoming['role'] == 'approver' and incoming['state'] == 'pending' and incoming['owner_offer_id'] == '-',
          'automatic return bypassed existing-computer owner approval')
    inspected = api(a, 'POST', '/v1/onboarding/machine-owner-inspection', {'context': context(f['owner_parent']), 'request_id': f['rid']})
    oi = inspected['review']
    check(set(inspected) == set('version host_id context observed_at request review_id review next_action'.split())
          and set(oi) == set('version kind host_id context agent network root_state_id request_id request_packet_id person_public_key host_public_key device_public_key member person_lease_id local_host provider provider_id signature_format scopes not_after host_admission created_at expires_at effects'.split())
          and oi['kind'] == 'inspect_existing_person_machine' and oi['version'] == 1,
          'closed full public existing-computer inspection')
    own_member = [m for m in get(a, '/v2/networks/' + net['id'] + '/members')['members'] if m['host_public_key'] == a.public_key]
    check(len(own_member) == 1 and oi['local_host'] == own_member[0] and oi['person_lease_id'] == person_row['person_lease_id']
          and oi['member'] == person_row['member'] and oi['effects'] == {'verify_request_signature': True, 'inspect_current_owner_authority': True,
              **{k: False for k in ('prepare_owner_intent', 'approve_owner_intent', 'sign_owner_offer', 'publish_owner_offer',
              'grant_membership', 'grant_machine_powers', 'grant_agent_access', 'commit_request', 'share_files', 'share_conversation', 'capability_calls')}},
          'owner inspection changed current actual P/H/member or read-only effects')
    check(inspected['review_id'] == digest('peerspan-machine-owner-inspection-v1', oi)
          and oi['context'] == context(f['owner_parent']) and oi['agent'] == f['owner_parent']['review']['agent']
          and oi['provider'] == f['provider'] and oi['provider']['host_public_key'] == a.public_key
          and oi['provider_id'] == f['provider']['lease_id'] and oi['signature_format'] == 'ed25519'
          and oi['scopes'] == 7 and oi['host_admission'] == 'owner_may_fold'
          and all(oi[k] == incoming[k] for k in ('request_id', 'request_packet_id', 'person_public_key', 'host_public_key', 'device_public_key'))
          and parse_time(oi['not_after']) == min(parse_time(incoming['created_at']) + timedelta(days=7), parse_time(f['provider']['not_after'])),
          'exact public device15 folded owner inspection/powers')
    f['owner_inspection'] = {'review_id': inspected['review_id'], 'review': oi}
    prepared = api(a, 'POST', MACHINE + '/prepare', {'context': context(f['owner_parent']), 'request_id': f['rid'],
        'inspection_review_id': inspected['review_id']})
    consent = owner_consent(f, prepared, 'review')
    approved = api(a, 'POST', MACHINE + '/approve', {'context': context(f['owner_parent']), 'request_id': f['rid'],
        'consent_id': consent['consent_id'], 'consent_review_id': consent['review_id']})
    f['owner_consent'] = owner_consent(f, approved, 'approved')
    check(core(f['owner_consent']) == core(consent), 'approval changed exact frozen owner consent')
    sign_body = {'context': context(f['owner_parent']), 'request_id': f['rid'],
        'consent_id': consent['consent_id'], 'consent_review_id': consent['review_id']}
    status = api(a, 'POST', MACHINE + '/signing', sign_body)
    marker = initial_signatures(f, status)
    if marker['state'] != 'signed':
        check(marker['can_sign'] is True, 'incomplete reviewed owner work cannot explicitly sign')
        signed = api(a, 'POST', MACHINE + '/sign', {**sign_body, 'decision': 'sign_machine_owner_offer'}, timeout=95)
        check(initial_signatures(f, signed)['state'] == 'signed', 'explicit bounded initial owner signing incomplete')
    # GET observation alone must close this gap; no ordinary finalize/resume,
    # code import, manually supplied packet, driver retry or provider switch.
    def finalized(last):
        if not all(status == 200 and type(v) is dict for status, v in last.values()):
            return None
        av, bv = last['existing'][1], last['requester'][1]
        return bv if bv['selection_id'] != '-' and bv['owner_finalization_id'] != '-' and av['owner_finalization_id'] == bv['owner_finalization_id'] else None
    f['view'] = checkpoint(f, finalized, seconds=30, message='automatic exact single-offer selection and owner finalization')
    check(f['view']['state'] == 'needs_commit' and f['view']['completed'] == ['request_created', 'owner_offered', 'owner_selected', 'owner_finalized']
          and f['view']['administrator_offer_id'] == '-' and not f['view']['commit_approved']
          and f['view']['manifest_id'] == f['view']['activation_id'] == f['view']['outcome_id'] == '-', 'automatic folded F bypassed requester consent')
    record, _secret = pending(b, f['rid']); f['packet_evidence'] = record
    stage = record.get('stage_at', '-')
    f['stage_deadline'] = rfc3339(parse_time(f['view']['created_at'] if stage == '-' else stage) + timedelta(seconds=600))
    verify_finalized_setup(f, f['view'])
    check(get(b, '/v2/networks') == [] and record['commit_intent_id'] == '-' and not record['commit_approved'], 'B adopted/approved before requester consent')
    check(policy_artifacts(a, net['id'], person) == f['policy_before'] and get(b, '/v1/grants') == [], 'link prefix changed policy/grants')
    no_original(f)
    f['ready'] = True


@suite.case('exact_requester_consent_one_lost_complete_then_CLI_lookup_and_two_host_application', 'guided49 verification2')
def _():
    f = shared
    check(f.get('ready') is True, 'shared guided F prerequisite failed')
    b = f['b']; body = inspection_body(f)
    inspected = api(b, 'POST', requester_endpoint(f, 'inspect'), body)
    validate_inspection(f, inspected); f['inspection'] = inspected
    null = api(b, 'POST', requester_endpoint(f, 'lookup'), body)
    validate_consent(f, null); check(null['consent'] is None, 'requester consent exists before explicit preparation')
    prepared = api(b, 'POST', requester_endpoint(f, 'prepare'), {**body, 'inspection_review_id': inspected['review_id']})
    f['prepared'] = prepared
    validate_consent(f, prepared)
    check(prepared['consent']['state'] == 'review', 'exact requester preparation is not unapproved review')
    approved = api(b, 'POST', requester_endpoint(f, 'approve'), {**body, 'consent_review_id': prepared['consent']['review_id']})
    f['approved'] = approved
    validate_consent(f, approved)
    check(approved['consent']['state'] == 'approved' and core(approved['consent']) == core(prepared['consent']), 'approval changed or omitted exact requester receipt')
    f['approved_receipt'] = load_intent(b, approved['consent']['consent_id'])
    complete_body = {**body, 'consent_review_id': approved['consent']['review_id'], 'decision': DECISION}
    cli_body = {'flow_id': f['flow']['flow_id'], **complete_body}
    with LostCompletion(b) as proxy:
        result = subprocess.run([str(suite.host_bin), '--state', str(proxy.state), 'onboarding', 'join', 'machine-commit', 'complete', '--stdin'],
            input=compact(cli_body), capture_output=True, timeout=95, cwd=str(b.root), env=b.env)
        check(result.returncode == 1 and not proxy.failed and proxy.result is not None
              and proxy.result[0] == 200 and len(proxy.calls) == 1, 'one real completion/lost caller response prerequisite')
        method, path, raw = proxy.calls[0]
        check(method == 'POST' and path == requester_endpoint(f, 'complete') and json.loads(raw) == complete_body,
              'response drop changed exact private completion request')
        completed = proxy.result[1]
    public(result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'), *f['secrets'])
    validate_completion(f, completed)
    f['completion'] = completed
    # Fresh private CLI Lookup; no repeated mutation and no replacement project.
    lookup = b.cli('onboarding', 'join', 'machine-commit', 'lookup', '--stdin',
        input=compact({'flow_id': f['flow']['flow_id'], **body}).decode(), timeout=5)
    check(lookup.code == 0, 'fresh pure CLI consent Lookup failed after lost200')
    public(lookup.stdout + lookup.stderr, *f['secrets'])
    recovered = lookup.json; validate_consent(f, recovered)
    check(recovered['consent'] == approved['consent'] and recovered['request']['state'] == 'linked'
          and all(recovered['request'][key] == completed['request'][key] for key in ('request_id', 'manifest_id', 'activation_id', 'outcome_id')),
          'Lookup did not recover same exact consent/global application')
    def applied(last):
        return all(status == 200 and type(v) is dict and v['state'] == 'linked'
            and 'locally_applied' in v['completed'] for status, v in last.values())
    checkpoint(f, applied, seconds=25, message='ordinary actual application on both participating hosts')
    for h in (f['a'], b):
        application_proof(f, completed, h)
        requests = [v for v in get(h, '/v2/link/requests') if v['request_id'].startswith('link_')]
        check(len(requests) == 1 and requests[0]['request_id'] == f['rid'] and requests[0]['state'] == 'linked'
              and len(rows(h, 'SELECT activation_id FROM dec_operations WHERE request_id=?', (f['rid'],))) == 1,
              'lost result duplicated request/application or lacked one actual operation')
    check(len(intent_rows(b, f['rid'], 'machine_requester_review')) == len(intent_rows(b, f['rid'], 'requester_commit')) == 1,
          'lost response duplicated requester receipt/ordinary intent')
    check(policy_artifacts(f['a'], f['network']['id'], f['person']) == f['policy_before'], 'actual application introduced policy/grant changes')
    no_original(f)
    f['applied'] = True


@suite.case('current_finite_membership_unchanged_policy_and_truthful_separate_unverified_readiness', 'guided49 verification3')
def _():
    f = shared
    check(f.get('applied') is True, 'shared real two-host application prerequisite failed')
    review = f['inspection']['review']
    for h in (f['a'], f['b']):
        net = get(h, '/v2/networks/' + f['network']['id'])
        check(net['authority']['state'] == 'usable' and net['root_state_id'] == review['root_state_id'], 'applied network has no actual current authority')
        members = get(h, '/v2/networks/' + f['network']['id'] + '/members')['members']
        person = [p for p in get(h, '/v2/networks/' + f['network']['id'] + '/persons')['persons'] if p['person_public_key'] == f['person']]
        target = [m for m in members if m['host_public_key'] == f['b'].public_key]
        check(len(members) == 2 and len(person) == len(target) == 1 and person[0]['person_lease_id'] == review['person_lease_id']
              and target[0]['person_public_key'] == f['person'] and target[0]['host_lease_id'] == review['host_lease_id']
              and target[0]['binding_lease_id'] == review['binding_lease_id'] and target[0]['device_lease_id'] == review['device_lease_id']
              and target[0]['not_after'] == review['not_after'], 'current actual P/H/B/D finite membership differs from reviewed application')
        if h is f['b']:
            check(net['provider']['kind'] == 'device' and net['provider']['scopes'] == 7
                  and net['provider']['lease_id'] == review['device_lease_id'] and net['provider']['not_after'] == review['not_after'],
                  'new computer lacks exact finite device7 provider')
        else:
            check(net['provider'] == f['provider'], 'link changed existing creator device15 provider')
        current_access(f, h, f['owner_parent'] if h is f['a'] else f['parent'])
    check(policy_artifacts(f['a'], f['network']['id'], f['person']) == f['policy_before']
          and get(f['b'], '/v1/grants') == [], 'link introduced policy/grant artifacts')
    no_original(f)
    counts = traffic(f)
    check(len(counts) == 4 and all(all(type(n) is int and n >= 0 for n in path) for path in counts), 'incomplete bidirectional counted TCP/UDP evidence')
    print('guided_machine_public=' + json.dumps({'hosts': 2, 'requests': 1, 'requester_receipts': 1,
        'operations': 2, 'folded': True, 'finite_device_scopes': 7, 'binding_scopes': 2,
        'new_agent_grants': 0, 'original_unchanged': True, 'requester_has_original': False,
        'adapter_verified': False, 'peer_verified': False, 'model_verified': False,
        'overall_verified': False, 'carrier_counts': counts}, sort_keys=True), flush=True)
    print('LIMIT guided49: live-worker global purity/route attribution, original-provider/separate-admin/reused-binding/expiry races, GUI/restart/installed/physical/model/upgrade acceptance are not claimed.', flush=True)


suite.finish()
