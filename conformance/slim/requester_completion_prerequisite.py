#!/usr/bin/env python3
"""GU.impl48: observe completed outbox attempts before the original alignment.

Contract68ee627/a736560; independent test-only prerequisite. No new protocol
IO, clock write, retry or old-file change. The original receive-only launcher
and suite retain all actions, comparisons, timeouts, argv and final verdict.
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

import harness


FIELDS = set('format kind body_base64 proof_ids created_at attempts next_attempt_at last_error_code last_error_detail'.split())
ERRORS = set('invalid forbidden authority_expired device_revoked not_yet_valid authority_would_be_invalidated '
             'not_found proof_required state_conflict operation_conflict version_exhausted quota_exceeded '
             'clock_rollback migration_pending review_required signer_unavailable recovery_required expired '
             'upgrade_required rate_limited internal transport_unavailable'.split())


def unique(pairs):
    result = {}
    for key, value in pairs:
        harness.check(key not in result, 'outbox prerequisite found duplicate record fields')
        result[key] = value
    return result


def timestamp(value):
    harness.check(type(value) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', value),
                  'outbox prerequisite timestamp is not canonical')
    try:
        return harness.parse_time(value)
    except (ValueError, TypeError, OverflowError):
        harness.check(False, 'outbox prerequisite timestamp cannot be parsed')


def completed_attempts(namespace, hosts):
    generations = {}

    def settled():
        nonlocal generations
        current = {}; ready = True
        for side, local in enumerate(hosts):
            with closing(sqlite3.connect(f'file:{namespace["db_path"](local)}?mode=ro', uri=True, timeout=2)) as db:
                db.execute('BEGIN')
                rows = db.execute('SELECT delivery_id,network_id,context_id,target_key,record FROM dec_outbox').fetchall()
            harness.check(len(rows) <= 4096, 'outbox prerequisite row bound exceeded')
            decoded_bytes = record_bytes = 0
            for delivery, network, context, target, text in rows:
                for value, prefix, size in ((delivery, 'ddel', 32), (network, 'net', 64), (context, 'ctx', 64)):
                    harness.check(type(value) is str and re.fullmatch(prefix + r'_[0-9a-f]{' + str(size) + '}', value),
                                  'outbox prerequisite identity is not canonical')
                try:
                    key = base64.b64decode(target, validate=True)
                    harness.check(len(key) == 32 and base64.b64encode(key).decode() == target,
                                  'outbox prerequisite target is not canonical')
                    harness.check(type(text) is str and len(text) <= 1024**3,
                                  'outbox prerequisite record bound exceeded')
                    record_bytes += len(text.encode('utf-8'))
                    record = json.loads(text, object_pairs_hook=unique)
                    harness.check(type(record) is dict and set(record) == FIELDS,
                                  'outbox prerequisite requires the closed documented record')
                    encoded = record['body_base64']
                    harness.check(type(encoded) is str and len(encoded) <= 4 * ((20 * 1024**2 + 2) // 3),
                                  'outbox prerequisite publication bound exceeded')
                    body = base64.b64decode(encoded, validate=True)
                    harness.check(len(body) <= 20 * 1024**2 and base64.b64encode(body).decode() == encoded,
                                  'outbox prerequisite body is not canonical base64')
                    decoded_bytes += len(body)
                except (ValueError, TypeError, UnicodeError):
                    harness.check(False, 'outbox prerequisite record is malformed')
                harness.check(type(record['format']) is int and record['format'] == 1
                              and record['kind'] in ('proofs', 'activation', 'migration')
                              and type(record['attempts']) is int and 0 <= record['attempts'] <= 2**64 - 1,
                              'outbox prerequisite record has invalid typed fields')
                proofs = record['proof_ids']
                harness.check(type(proofs) is list and len(proofs) <= 4096
                              and all(type(value) is str and re.fullmatch(r'dp_[0-9a-f]{64}', value) for value in proofs),
                              'outbox prerequisite proof references are malformed')
                timestamp(record['created_at']); next_attempt = timestamp(record['next_attempt_at'])
                code, detail = record['last_error_code'], record['last_error_detail']
                harness.check(type(code) is str and code in ERRORS | {'-'} and type(detail) is str,
                              'outbox prerequisite result fields are malformed')
                try:
                    harness.check(len(detail.encode('utf-8')) <= 1024, 'outbox prerequisite result detail bound exceeded')
                except UnicodeError:
                    harness.check(False, 'outbox prerequisite result detail is not UTF8')
                generation = (side, delivery, network, context, target, record['kind'],
                              hashlib.sha256(body).digest(), tuple(proofs), record['created_at'])
                current[generation] = (record['attempts'], code, detail, record['next_attempt_at'])
                ready = ready and record['attempts'] > 0 and code in ERRORS and next_attempt > local.now()
            harness.check(decoded_bytes <= 512 * 1024**2 and record_bytes <= 1024**3,
                          'outbox prerequisite byte bound exceeded')
            ready = ready and not list(local.state.glob('*-journal'))
        generations = current
        return ready

    return namespace['wait_for'](settled, timeout=35, interval=.1,
        message='completed actual publication generations before one retry alignment')


def wrap_case(original):
    @wraps(original)
    def case(suite, *args, **kwargs):
        decorator = original(suite, *args, **kwargs)

        def register(function):
            namespace = function.__globals__
            saved = namespace.get('make_terminal_retries_eligible')
            if saved is None:
                return decorator(function)

            @wraps(saved)
            def align(h, issuer, *args, **kwargs):
                completed_attempts(namespace, (h, issuer))
                return saved(h, issuer, *args, **kwargs)

            namespace['make_terminal_retries_eligible'] = align
            try:
                return decorator(function)
            finally:
                namespace['make_terminal_retries_eligible'] = saved
        return register
    return case


def main():
    original = harness.Suite.case
    try:
        harness.Suite.case = wrap_case(original)
        return runpy.run_path(str(Path(__file__).with_name('requester_completion_carrier_diagnostic.py')), run_name='__main__')
    finally:
        harness.Suite.case = original


if __name__ == '__main__':
    main()
