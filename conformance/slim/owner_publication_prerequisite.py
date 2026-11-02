#!/usr/bin/env python3
"""Run the two unchanged owner suites after actual initial request publication.

Section49/be99b2f: every published join waits for its exact saved request's own
storage ACK; only two literal live-history cases require every participant ACK,
including the distinct signed inviter, and no helpers. Reuse the unchanged safe
own-request witness. An unapproved review is returned without any observation.
No send/API/clock/row/file mutation, worker switch, changed original comparison,
timeout or verdict. Section49/946343c additionally waits before signing's
original settled call for its already-approved initial host slot; no authority
signer or owner offer is supplied. Phase evidence attributes no earlier failure.
"""
import base64
from contextlib import closing
from functools import wraps
import hashlib
import json
from pathlib import Path
import re
import runpy
import sqlite3
import sys

import harness
import join_onboarding_prerequisite as publication


LIVE_CASES = {
    'owner_onboarding': 'same_intent_advanced_signing_admin_finalization_commit_and_stable_history',
    'owner_signing': 'same_intent_real_administrator_finalization_commit_and_pure_history_without_keys',
}


def witness(host, outcome, record, frames, *, require_all, inviter):
    ready, summary = publication.witness(host, outcome, record, frames)
    summary['all_participants_required'] = require_all
    if not ready or not require_all:
        return ready, summary
    endpoints = record['carrier_endpoints']
    participants = {(endpoint['address'], endpoint['public_key']) for endpoint in endpoints if endpoint['kind'] == 'participant'}
    acknowledgments = {(ack['address'], ack['public_key']) for ack in record['outbound_frames'][0]['acknowledged_by']}
    summary.update(participant_endpoints=len(participants),
        inviter_participant_endpoints=sum(key == inviter for _address, key in participants),
        participant_acknowledgments=len(participants & acknowledgments),
        no_helpers=all(endpoint['kind'] == 'participant' for endpoint in endpoints))
    ready = (summary['no_helpers'] and type(inviter) is str and bool(inviter) and inviter != host.public_key
        and summary['inviter_participant_endpoints'] > 0 and bool(participants) and participants <= acknowledgments)
    summary['satisfied'] = bool(ready)
    return bool(ready), summary


def publication_complete(namespace, host, result, *, require_all):
    check = namespace['check']
    check(type(result) is dict and result.get('state') == 'requested' and type(result.get('outcome')) is dict,
          'owner publication prerequisite lacks original successful request')
    outcome = result['outcome']
    check(set(outcome) == {'request_id', 'network_id', 'context_id', 'person_public_key'}
          and type(outcome['request_id']) is str and re.fullmatch(r'link_[0-9a-f]{64}', outcome['request_id']),
          'owner publication prerequisite lacks exact original outcome')
    inviter = None
    if require_all:
        review = result.get('review')
        invitation = review.get('invitation') if type(review) is dict else None
        inviter = invitation.get('inviter_host_public_key') if type(invitation) is dict else None
    database = namespace['db_path'](host)
    last = {'satisfied': False, 'all_participants_required': require_all}
    def observed():
        nonlocal last
        try:
            with closing(sqlite3.connect(f'file:{database}?mode=ro', uri=True, timeout=.1)) as db, db:
                db.execute('BEGIN')
                row = db.execute('SELECT record FROM dec_pending WHERE request_id=?', (outcome['request_id'],)).fetchone()
                frames = list(db.execute('SELECT role,writer_key,frame_id,record FROM dec_frames WHERE request_id=?', (outcome['request_id'],)))
            record = json.loads(row[0]) if row is not None else None
            ready, last = witness(host, outcome, record, frames, require_all=require_all, inviter=inviter)
            return ready
        except (sqlite3.Error, ValueError, TypeError, KeyError):
            check(False, 'owner initial-publication witness unavailable')
    try:
        namespace['wait_for'](observed, timeout=5, interval=.1,
            message='actual owner-fixture initial request storage acknowledgment')
    finally:
        try:
            print('owner_publication_prerequisite_public=' + json.dumps(last, sort_keys=True), flush=True)
        except BaseException:
            pass


def decoded_object(value, maximum):
    if type(value) is not str or len(value.encode()) > 4 * ((maximum + 2) // 3):
        raise ValueError
    raw = base64.b64decode(value, validate=True)
    if len(raw) > maximum:
        raise ValueError
    result = json.loads(raw)
    if type(result) is not dict:
        raise ValueError
    return result


def host_job_witness(host, pending, owners, adopted, operations):
    """Stored host-slot phase only; later signature validity stays in old tests."""
    summary = {'initial_jobs': 0, 'stored_host_slots': 0, 'skipped_jobs': 0, 'satisfied': False}
    def require(condition):
        if not condition:
            raise ValueError
    for rid, request in pending:
        iid = request.get('owner_intent_id', '-')
        if iid == '-':
            continue
        require(iid in owners)
        network, context, owner, secret = owners[iid]
        require(type(owner) is dict and type(owner.get('approved')) is bool
            and type(request.get('terminal')) is str and type(owner.get('terminal')) is str
            and type(request.get('owner_offer_id')) is str)
        if (not owner['approved'] or request.get('terminal') != '-'
                or owner.get('terminal') != '-' or request.get('owner_offer_id') != '-'):
            summary['skipped_jobs'] += 1
            continue
        summary['initial_jobs'] += 1
        require(owner.get('completed') is False and secret is None and owner.get('operation_id') == rid
            and owner.get('result_base64') == '-' and type(request.get('roles')) is list
            and 'requester' in request['roles'] and set(request['roles']) <= {'requester', 'owner'}
            and request.get('mode') == 'new' and request.get('migration_proposal_id') == '-'
            and request.get('host_public_key') == host.public_key
            and network == request.get('expected_network_id') and context == request.get('expected_context_id')
            and network not in adopted and rid not in operations
            and request.get('selection_approved') is False and request.get('commit_approved') is False
            and all(request.get(field) == '-' for field in publication.DASH if field != 'owner_intent_id'))
        person, device = request['expected_person_public_key'], request['device_public_key']
        require(owner.get('provider') == {'kind': 'original', 'signer_public_key': person,
                'signature_format': 'sshsig', 'lease_id': '-'}
            and owner.get('person_public_key') == person and owner.get('host_public_key') == host.public_key
            and owner.get('device_public_key') == device and owner.get('root_state_id') == '-'
            and owner.get('scopes') == 7)
        templates = owner.get('templates')
        require(type(templates) is list)
        initial = [template for template in templates if type(template) is dict and template.get('object_type') == 'owner_offer_packet']
        require(len(initial) == 1)
        template = initial[0]
        require(type(template) is dict and set(template) == {'slot_id', 'object_type', 'template_base64'}
            and type(template['slot_id']) is int and template['slot_id'] == 1 and template['object_type'] == 'owner_offer_packet')
        packet = decoded_object(template['template_base64'], 1024 * 1024)
        require(set(packet) == set('format context_id request_id role writer_host_public_key signer_public_key person_public_key issuer_id payload_base64 host_signature device_signature authority_signature_format authority_signature'.split())
            and packet['format'] == 1 and packet['request_id'] == rid and packet['context_id'] == context
            and packet['role'] == 'owner' and packet['writer_host_public_key'] == host.public_key
            and packet['signer_public_key'] == packet['person_public_key'] == person
            and packet['issuer_id'] == packet['host_signature'] == packet['device_signature'] == packet['authority_signature'] == '-'
            and packet['authority_signature_format'] == 'sshsig')
        original = decoded_object(request['request_packet_base64'], 8 * 1024)
        require(original['role'] == 'request' and original['request_id'] == rid
            and original['writer_host_public_key'] == host.public_key and original['signer_public_key'] == device)
        message = '\n'.join(('peerspan-decentralized-packet-v1', original['context_id'], original['request_id'], original['role'],
            original['writer_host_public_key'], original['signer_public_key'], original['person_public_key'], original['issuer_id'],
            original['authority_signature_format'], hashlib.sha256(base64.b64decode(original['payload_base64'], validate=True)).hexdigest())).encode()
        request_reference = 'dpk_' + hashlib.sha256(message).hexdigest()
        body = decoded_object(packet['payload_base64'], 256 * 1024)
        require(body.get('mode') == 'new' and body.get('request_packet_id') == request_reference
            and body.get('host_public_key') == host.public_key
            and body.get('device_public_key') == device and body.get('scopes') == 7
            and body.get('root_state_id') == body.get('person_lease_id') == '-'
            and body.get('not_after') == owner.get('not_after')
            and type(body.get('descriptor')) is dict and body['descriptor'].get('network_id') == network)
        signatures = owner.get('signatures')
        require(type(signatures) is list and len(signatures) <= 1)
        if signatures:
            signature = signatures[0]
            require(type(signature) is dict and set(signature) == {'slot_id', 'role', 'signature'}
                and type(signature['slot_id']) is int and signature['slot_id'] == 1 and signature['role'] == 'host'
                and type(signature['signature']) is str and len(signature['signature']) == 88)
            raw = base64.b64decode(signature['signature'], validate=True)
            require(len(raw) == 64 and base64.b64encode(raw).decode() == signature['signature'])
            summary['stored_host_slots'] += 1
    summary['satisfied'] = summary['initial_jobs'] == summary['stored_host_slots']
    return summary['satisfied'], summary


def initial_host_complete(namespace, host):
    database = namespace['db_path'](host)
    last = {'initial_jobs': 0, 'stored_host_slots': 0, 'skipped_jobs': 0, 'satisfied': False}
    def observed():
        nonlocal last
        try:
            with closing(sqlite3.connect(f'file:{database}?mode=ro', uri=True, timeout=.1)) as db, db:
                db.execute('BEGIN')
                pending = [(rid, json.loads(record)) for rid, record in db.execute('SELECT request_id,record FROM dec_pending')]
                owners = {iid: (network, context, json.loads(record), secret) for iid, network, context, record, secret in db.execute(
                    "SELECT intent_id,network_id,context_id,record,secret FROM dec_intents WHERE kind='owner'")}
                adopted = {row[0] for row in db.execute('SELECT id FROM networks')}
                operations = {row[0] for row in db.execute('SELECT request_id FROM dec_operations')}
            ready, last = host_job_witness(host, pending, owners, adopted, operations)
            return ready
        except (sqlite3.Error, ValueError, TypeError, KeyError):
            namespace['check'](False, 'initial original-host signature witness unavailable')
    try:
        namespace['wait_for'](observed, timeout=5, interval=.1,
            message='actual approved initial original-host signature storage')
    finally:
        try:
            print('owner_host_job_prerequisite_public=' + json.dumps(last, sort_keys=True), flush=True)
        except BaseException:
            pass


def observed_case(original, selected):
    @wraps(original)
    def case(suite, *args, **kwargs):
        decorator = original(suite, *args, **kwargs)
        name = args[0] if args else kwargs.get('name')
        def register(function):
            namespace = function.__globals__
            join = namespace['join']
            settled = namespace['settled'] if selected == 'owner_signing' else None
            @wraps(join)
            def after_join(*args, **kwargs):
                result = join(*args, **kwargs)
                if type(result) is dict and result.get('state') == 'review':
                    return result
                host = args[0] if args else kwargs['h']
                publication_complete(namespace, host, result, require_all=name == LIVE_CASES[selected])
                return result
            if settled is not None:
                @wraps(settled)
                def before_settled(*args, **kwargs):
                    host = args[0] if args else kwargs['h']
                    initial_host_complete(namespace, host)
                    return settled(*args, **kwargs)
            try:
                namespace['join'] = after_join
                if settled is not None:
                    namespace['settled'] = before_settled
                return decorator(function)
            finally:
                namespace['join'] = join
                if settled is not None:
                    namespace['settled'] = settled
        return register
    return case


def main():
    original_argv, original_case = sys.argv, harness.Suite.case
    if len(original_argv) < 2 or original_argv[1] not in LIVE_CASES:
        raise SystemExit('select owner_onboarding or owner_signing')
    selected = original_argv[1]
    subject = str(Path(__file__).with_name(selected + '.py'))
    try:
        sys.argv = [subject, *original_argv[2:]]
        harness.Suite.case = observed_case(original_case, selected)
        return runpy.run_path(subject, run_name='__main__')
    finally:
        sys.argv, harness.Suite.case = original_argv, original_case


if __name__ == '__main__':
    main()
