#!/usr/bin/env python3
"""Run unchanged join_onboarding after its exact own-request publication phase.

Section49/7901877: only the named progress case waits (5 real seconds) for the
already authorized request's durable storage ACK at every actual own participant
endpoint. The stopped inviter need not acknowledge. No new send/API/clock/row
mutation, worker switch or changed original action/assertion/comparison/timeout.
All original decide arguments/results/exceptions and suite argv/verdict remain.
"""
from contextlib import closing
from functools import wraps
import json
from pathlib import Path
import re
import runpy
import sqlite3

import harness


CASE = 'published_progress_exact_read_only_snapshot_cli_bounds_and_owner_routes'
DASH = ('owner_packet_base64', 'selection_packet_base64', 'administrator_packet_base64',
        'owner_finalization_packet_base64', 'commit_packet_base64', 'outcome_packet_base64',
        'owner_offer_id', 'selection_id', 'administrator_offer_id', 'owner_finalization_id',
        'manifest_id', 'activation_id', 'owner_intent_id', 'administrator_intent_id',
        'selection_intent_id', 'commit_intent_id', 'terminal')


def witness(host, outcome, record, frames):
    """Only captured public storage shapes; values/addresses never leave here."""
    summary = {'unfinished': False, 'saved_own_request_frames': 0,
               'own_participant_endpoints': 0, 'own_acknowledged_endpoints': 0,
               'satisfied': False}
    if type(record) is not dict or type(frames) is not list:
        return False, summary
    summary['unfinished'] = (record.get('format') == 1 and record.get('roles') == ['requester']
        and record.get('mode') == 'new' and record.get('migration_proposal_id') == '-'
        and record.get('host_public_key') == host.public_key
        and all(record.get('expected_' + key) == outcome[key] for key in ('network_id', 'context_id', 'person_public_key'))
        and type(record.get('request_packet_base64')) is str and record['request_packet_base64'] not in ('', '-')
        and record.get('selection_approved') is False and record.get('commit_approved') is False
        and all(record.get(field) == '-' for field in DASH))
    own_frames = [row for row in frames if type(row) is tuple and len(row) == 4
                  and row[0] == 'request' and row[1] == host.public_key
                  and type(row[2]) is str and re.fullmatch(r'[0-9a-f]{64}', row[2])]
    summary['saved_own_request_frames'] = len(own_frames)
    endpoints, outbound = record.get('carrier_endpoints'), record.get('outbound_frames')
    if not (summary['unfinished'] and len(frames) == len(own_frames) == 1
            and type(endpoints) is list and type(outbound) is list and len(outbound) == 1):
        return False, summary
    try:
        saved = json.loads(own_frames[0][3])
        if not (type(saved) is dict and set(saved) == {'frame_base64'}
                and type(saved['frame_base64']) is str and saved['frame_base64'] not in ('', '-')):
            return False, summary
        if not all(type(endpoint) is dict and set(endpoint) == {'kind', 'address', 'public_key'}
                and endpoint['kind'] in {'participant', 'helper'}
                and type(endpoint['address']) is str and endpoint['address']
                and type(endpoint['public_key']) is str and endpoint['public_key'] for endpoint in endpoints):
            return False, summary
        own = {(endpoint['address'], endpoint['public_key']) for endpoint in endpoints
               if endpoint['kind'] == 'participant' and endpoint['public_key'] == host.public_key}
        summary['own_participant_endpoints'] = len(own)
        frame = outbound[0]
        if not (type(frame) is dict and set(frame) == {'role', 'writer_public_key', 'frame_id', 'acknowledged_by'}
                and (frame['role'], frame['writer_public_key'], frame['frame_id']) == own_frames[0][:3]
                and type(frame['acknowledged_by']) is list
                and all(type(ack) is dict and set(ack) == {'address', 'public_key'}
                    and type(ack['address']) is str and type(ack['public_key']) is str
                    for ack in frame['acknowledged_by'])):
            return False, summary
        acknowledgments = {(ack['address'], ack['public_key']) for ack in frame['acknowledged_by']}
        summary['own_acknowledged_endpoints'] = len(own & acknowledgments)
        summary['satisfied'] = bool(own) and own <= acknowledgments
        return summary['satisfied'], summary
    except (ValueError, TypeError, KeyError):
        return False, summary


def publication_complete(namespace, host, result):
    check = namespace['check']
    check(type(result) is dict and result.get('state') == 'requested' and type(result.get('outcome')) is dict,
          'own-request prerequisite lacks original successful publication')
    outcome = result['outcome']
    check(set(outcome) == {'request_id', 'network_id', 'context_id', 'person_public_key'}
          and type(outcome['request_id']) is str and re.fullmatch(r'link_[0-9a-f]{64}', outcome['request_id']),
          'own-request prerequisite lacks exact original outcome')
    database = namespace['db_path'](host)
    last = {'unfinished': False, 'saved_own_request_frames': 0, 'own_participant_endpoints': 0,
            'own_acknowledged_endpoints': 0, 'satisfied': False}
    def observed():
        nonlocal last
        try:
            with closing(sqlite3.connect(f'file:{database}?mode=ro', uri=True, timeout=.1)) as db, db:
                db.execute('BEGIN')
                row = db.execute('SELECT record FROM dec_pending WHERE request_id=?', (outcome['request_id'],)).fetchone()
                frames = list(db.execute('SELECT role,writer_key,frame_id,record FROM dec_frames WHERE request_id=?', (outcome['request_id'],)))
            record = json.loads(row[0]) if row is not None else None
            ready, last = witness(host, outcome, record, frames)
            return ready
        except (sqlite3.Error, ValueError, TypeError, KeyError):
            check(False, 'own-request publication witness unavailable')
    try:
        namespace['wait_for'](observed, timeout=5, interval=.1,
            message='actual own-request frame storage acknowledgment')
    finally:
        try:
            print('join_publication_prerequisite_public=' + json.dumps(last, sort_keys=True), flush=True)
        except BaseException:
            pass


def observed_case(original):
    @wraps(original)
    def case(suite, *args, **kwargs):
        decorator = original(suite, *args, **kwargs)
        name = args[0] if args else kwargs.get('name')
        if name != CASE:
            return decorator
        def register(function):
            namespace = function.__globals__
            decide = namespace['decide']
            @wraps(decide)
            def after_publication(*args, **kwargs):
                result = decide(*args, **kwargs)
                host = args[0] if args else kwargs['h']
                publication_complete(namespace, host, result)
                return result
            try:
                namespace['decide'] = after_publication
                return decorator(function)
            finally:
                namespace['decide'] = decide
        return register
    return case


def main():
    original = harness.Suite.case
    try:
        harness.Suite.case = observed_case(original)
        return runpy.run_path(str(Path(__file__).with_name('join_onboarding.py')), run_name='__main__')
    finally:
        harness.Suite.case = original


if __name__ == '__main__':
    main()
