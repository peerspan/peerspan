#!/usr/bin/env python3
"""Run the two unchanged owner suites after actual initial request publication.

Section49/be99b2f: every published join waits for its exact saved request's own
storage ACK; only two literal live-history cases require every participant ACK,
including the distinct signed inviter, and no helpers. Reuse the unchanged safe
own-request witness. An unapproved review is returned without any observation.
No send/API/clock/row/file mutation, worker switch, changed original comparison,
timeout or verdict. This run's phase evidence attributes no earlier failure.
"""
from contextlib import closing
from functools import wraps
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


def observed_case(original, selected):
    @wraps(original)
    def case(suite, *args, **kwargs):
        decorator = original(suite, *args, **kwargs)
        name = args[0] if args else kwargs.get('name')
        def register(function):
            namespace = function.__globals__
            join = namespace['join']
            @wraps(join)
            def after_join(*args, **kwargs):
                result = join(*args, **kwargs)
                if type(result) is dict and result.get('state') == 'review':
                    return result
                host = args[0] if args else kwargs['h']
                publication_complete(namespace, host, result, require_all=name == LIVE_CASES[selected])
                return result
            try:
                namespace['join'] = after_join
                return decorator(function)
            finally:
                namespace['join'] = join
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
