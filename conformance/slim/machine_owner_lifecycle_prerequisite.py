#!/usr/bin/env python3
"""Finish due carrier expiry inside the frozen machine-owner quiet deadline.

Only the eighth pure call of one literal case, after its original clock jump.
Observe the snapshot already held by quiet.stable AFTER calling it once. Reuse
its original wait_for timeout3/interval.1 and all original reads/sleeps/guards.
No added IO, clock call, wait, reset, filtering, authority or protocol mutation.
The previous CI's changed tables/actor remain unclassified without evidence.
"""
from functools import wraps
from inspect import unwrap
import json
from pathlib import Path
import re
import runpy
import sys
from types import CodeType

import harness


CASE = 'unsafe_metadata_genuine_owner_intent_cancel_and_actual_stage_request_expiry_refuse'
QUIET_MESSAGE = 'settled machine-owner DB/files and counted carriers'


PUBLIC_COLUMNS = {
    'mailboxes': ('locator', 'request_id', 'read_cap_hash', 'created_at', 'expires_at',
                  'expires_unix', 'creator_key', 'source_bucket', 'account_id',
                  'creation_identity_hash', 'state', 'ciphertext_bytes'),
    'frames': ('locator', 'frame_id', 'role', 'writer_key', 'body', 'ciphertext_bytes'),
}


def columns(database, table):
    """Validate the held schema against the documented public column order."""
    definitions = [sql for kind, name, _parent, sql in database['$schema'] if kind == 'table' and name == table]
    harness.check(len(definitions) == 1 and type(definitions[0]) is str,
                  'held carrier snapshot lacks its table definition')
    names = re.findall(r'(?:\(|,)\s*["`\[]?([A-Za-z_][A-Za-z_0-9]*)["`\]]?\s+'
                       r'(?:TEXT|INTEGER|BLOB|REAL|NUMERIC)\b', definitions[0], re.IGNORECASE)
    expected = PUBLIC_COLUMNS[table]
    harness.check(tuple(names) == expected, 'held carrier schema has an unexpected public column order')
    return {name: index for index, name in enumerate(expected)}, len(expected)


def lifecycle(snapshot, cutoff):
    databases = snapshot[0]
    summary = {'resource_store_count': 0, 'mailbox_count': 0, 'frame_count': 0,
               'due_mailbox_count': 0, 'due_active_count': 0,
               'due_ciphertext_bytes': 0, 'due_frame_count': 0, 'orphan_frame_count': 0,
               'past_tombstone_mailbox_count': 0}
    for database in databases.values():
        if not {'mailboxes', 'frames'} & database.keys():
            continue
        harness.check({'helper_format', 'mailboxes', 'frames'} <= database.keys(),
                      'held carrier expiry snapshot lacks documented helper tables')
        mailboxes, frames = database['mailboxes'], database['frames']
        box_columns, box_size = columns(database, 'mailboxes')
        frame_columns, frame_size = columns(database, 'frames')
        locator, expiry, state, size = (box_columns[name] for name in ('locator', 'expires_unix', 'state', 'ciphertext_bytes'))
        frame_locator = frame_columns['locator']
        harness.check(all(type(row) is tuple and len(row) == box_size and type(row[expiry]) is int
                      and row[state] in ('active', 'deleted', 'expired') and type(row[size]) is int and row[size] >= 0
                      for row in mailboxes), 'held carrier mailbox snapshot has an unexpected public shape')
        harness.check(all(type(row) is tuple and len(row) == frame_size for row in frames),
                      'held carrier frame snapshot has an unexpected public shape')
        summary['resource_store_count'] += 1
        summary['mailbox_count'] += len(mailboxes); summary['frame_count'] += len(frames)
        locators = {row[locator] for row in mailboxes}
        summary['orphan_frame_count'] += sum(row[frame_locator] not in locators for row in frames)
        for row in mailboxes:
            summary['past_tombstone_mailbox_count'] += cutoff > row[expiry] + 24 * 60 * 60
            if row[expiry] > cutoff:
                continue
            summary['due_mailbox_count'] += 1
            summary['due_active_count'] += row[state] == 'active'
            summary['due_ciphertext_bytes'] += row[size]
            summary['due_frame_count'] += sum(frame[frame_locator] == row[locator] for frame in frames)
    harness.check(summary['resource_store_count'] > 0, 'held quiet snapshot lacks an actual carrier resource store')
    ready = all(summary[field] == 0 for field in (
        'due_active_count', 'due_ciphertext_bytes', 'due_frame_count', 'orphan_frame_count', 'past_tombstone_mailbox_count'))
    return ready, summary


def emit(first, last, observations, satisfied):
    try:
        print('machine_owner_lifecycle_prerequisite_public=' + json.dumps({
            'phase': 'signed_request_expired_before_inspection', 'observations': observations,
            'first': first, 'last': last, 'lifecycle_counts_changed_before_baseline': first != last,
            'maintenance_complete_before_baseline': satisfied}, sort_keys=True), flush=True)
    except (ValueError, TypeError, AttributeError, KeyError, IndexError, OSError):
        pass


def observed_case(original):
    @wraps(original)
    def case(suite, *args, **kwargs):
        decorator = original(suite, *args, **kwargs)
        name = args[0] if args else kwargs.get('name')
        if name != CASE:
            return decorator

        def register(function):
            namespace = unwrap(function).__globals__
            saved = {name: namespace[name] for name in ('pure', 'advance_to', 'wait_for')}
            stable_codes = {value for value in namespace['quiet'].__code__.co_consts
                            if isinstance(value, CodeType) and value.co_name == 'stable'}
            ordinal, active, advanced = 0, None, None

            @wraps(saved['advance_to'])
            def advance(*args, **kwargs):
                nonlocal advanced
                result = saved['advance_to'](*args, **kwargs)
                values = dict(zip(('h', 'moment'), args)); values.update(kwargs)
                advanced = values['h'], values['moment']
                return result

            @wraps(saved['pure'])
            def pure(*args, **kwargs):
                nonlocal ordinal, active
                ordinal += 1
                previous = active
                fixture = args[0] if args else kwargs['f']
                if ordinal == 8:
                    harness.check(advanced is not None and advanced[0] is fixture['a'],
                                  'expiry checkpoint lacks original owner clock stimulus')
                    active = fixture, int(advanced[1].timestamp())
                try:
                    return saved['pure'](*args, **kwargs)
                finally:
                    active = previous

            @wraps(saved['wait_for'])
            def wait(*args, **kwargs):
                if active is None or kwargs.get('message') != QUIET_MESSAGE:
                    return saved['wait_for'](*args, **kwargs)
                predicate = args[0] if args else kwargs['predicate']
                harness.check(predicate.__code__ in stable_codes,
                              'expiry checkpoint did not receive the unchanged quiet predicate')
                first = last = None
                observations = 0
                satisfied = False

                @wraps(predicate)
                def stable():
                    nonlocal first, last, observations, satisfied
                    result = predicate()
                    cells = dict(zip(predicate.__code__.co_freevars, predicate.__closure__))
                    harness.check(cells['f'].cell_contents is active[0],
                                  'held quiet snapshot belongs to another fixture')
                    held = cells['previous'].cell_contents
                    ready, last = lifecycle(held[0][0], active[1])
                    observations += 1
                    if first is None:
                        first = dict(last)
                    satisfied = bool(result) and ready
                    return result if satisfied else False

                forwarded, named = list(args), dict(kwargs)
                if forwarded:
                    forwarded[0] = stable
                else:
                    named['predicate'] = stable
                try:
                    return saved['wait_for'](*forwarded, **named)
                finally:
                    emit(first, last, observations, satisfied)

            try:
                namespace.update(pure=pure, advance_to=advance, wait_for=wait)
                return decorator(function)
            finally:
                namespace.update(saved)
        return register
    return case


def main():
    argv, original = sys.argv, harness.Suite.case
    subject = str(Path(__file__).with_name('combined_purity_diagnostic.py'))
    try:
        sys.argv = [subject, 'machine_owner', *argv[1:]]
        harness.Suite.case = observed_case(original)
        return runpy.run_path(subject, run_name='__main__')
    finally:
        sys.argv, harness.Suite.case = argv, original


if __name__ == '__main__':
    main()
