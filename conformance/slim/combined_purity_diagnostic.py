#!/usr/bin/env python3
"""Observe two unchanged combined-gate purity failures from held objects only.

Final acceptance, Combined regression follow-up: no additional host/API/DB/file/
socket/process observations, actions, waits or retries. All original cases,
snapshots, arguments, actions, assertions, deadlines and verdicts remain exact.
Only fixed labels/public table names, booleans and counts leave this observer.
Requester completion retains its existing prerequisite -> carrier -> suite chain.

Usage: combined_purity_diagnostic.py machine_owner|requester_completion [suite args]
"""
from collections import Counter
from functools import wraps
import json
from pathlib import Path
import runpy
import sys

import harness


CASES = {
    'machine_owner': 'unsafe_metadata_genuine_owner_intent_cancel_and_actual_stage_request_expiry_refuse',
    'requester_completion': 'pure_verified_completed_API_CLI_replay_after_detach_restart_expiry_with_original_sources_absent',
}
MACHINE_PHASES = ('unsafe_metadata_first', 'unsafe_metadata_second', 'current_owner',
                  'unapproved_owner_intent', 'cancelled_owner_request', 'expiry_fixture_current',
                  'owner_stage_expired', 'signed_request_expired')
TABLES = frozenset('''
agents sessions events activity identity host_identity networks policies policy_edits
peers grants blocks messages message_replies deliveries outbound_messages outbound_replies
adapter_credentials adapter_routes adapter_connections adapter_deliveries adapter_calls
call_update_notifications directory_hosts directory_agents directory_sends policy_deliveries
task_children task_artifacts artifact_files task_update_notifications task_deliveries
outbound_task_events outbound_tasks task_events received_tasks tool_servers tool_values
capabilities source_access received_calls outbound_calls call_approvals approval_notices
builtin_sources oauth_clients oauth_credentials link_signers link_highwater link_features
link_objects link_operations link_frames link_pending link_device_keys dec_activations
dec_admissions dec_clock dec_contacts dec_contexts dec_frames dec_heads dec_helpers
dec_highwater dec_intents dec_migrations dec_objects dec_operations dec_outbox dec_pending
dec_restrictions dec_signers onboarding_project_flows onboarding_adapter_flows
onboarding_invitation_flows onboarding_join_flows conversations conversation_messages
conversation_targets conversation_invites conversation_roster_outbound
conversation_notifications conversation_reads conversation_events sqlite_sequence
'''.split())
CARRIERS = (
    ('issuer', 'TCP', ('connections', 'received_bytes')),
    ('requester', 'TCP', ('connections', 'received_bytes')),
    ('issuer', 'UDP', ('received_datagrams', 'received_bytes', 'returned_datagrams', 'returned_bytes')),
    ('requester', 'UDP', ('received_datagrams', 'received_bytes', 'returned_datagrams', 'returned_bytes')),
)


def file_summary(before, after):
    old_keys, new_keys = set(before), set(after)
    common = old_keys & new_keys
    return {'changed': before != after,
            'before_entry_count': len(before), 'after_entry_count': len(after),
            'added_entry_count': len(new_keys - old_keys),
            'removed_entry_count': len(old_keys - new_keys),
            'changed_existing_entry_count': sum(before[key] != after[key] for key in common),
            'mode_changed_entry_count': sum(before[key][0] != after[key][0] for key in common),
            'content_changed_entry_count': sum(before[key][1] != after[key][1] for key in common)}


def database_summary(before, after):
    changes, unknown_count = [], 0
    names = (set(before) | set(after)) - {'$schema', '$version'}
    for name in sorted(names):
        old, new = before.get(name, ()), after.get(name, ())
        if old == new and (name in before) == (name in after):
            continue
        if name not in TABLES:
            unknown_count += 1
            continue
        old_counts, new_counts = Counter(old), Counter(new)
        changes.append({'table': name, 'present_before': name in before, 'present_after': name in after,
                        'before_row_count': len(old), 'after_row_count': len(new),
                        'removed_row_count': sum((old_counts - new_counts).values()),
                        'added_row_count': sum((new_counts - old_counts).values())})
    return {'schema_changed': before.get('$schema') != after.get('$schema'),
            'version_changed': before.get('$version') != after.get('$version'),
            'changed_public_table_count': len(changes), 'changed_unknown_table_count': unknown_count,
            'tables': changes}


def snapshot_summary(before, after, multiple_databases):
    old_db, old_state, old_home = before
    new_db, new_state, new_home = after
    databases = []
    if multiple_databases:
        for index, name in enumerate(sorted(set(old_db) | set(new_db))):
            databases.append({'index': index, 'present_before': name in old_db, 'present_after': name in new_db,
                              **database_summary(old_db.get(name, {}), new_db.get(name, {}))})
    else:
        databases.append({'index': 0, 'present_before': True, 'present_after': True,
                          **database_summary(old_db, new_db)})
    return {'snapshot_changed': before != after, 'databases': databases,
            'state_files': file_summary(old_state, new_state), 'home_files': file_summary(old_home, new_home)}


def carrier_summary(actual, expected):
    if actual is None or expected is None or len(actual) != len(CARRIERS) or len(expected) != len(CARRIERS):
        return {'available': False}
    changes = []
    for (participant, kind, fields), old, new in zip(CARRIERS, expected, actual):
        if len(old) != len(fields) or len(new) != len(fields) or any(
                type(value) is not int or value < 0 for value in (*old, *new)):
            return {'available': False}
        changes.append({'participant': participant, 'kind': kind, 'changed': old != new,
                        'counts': [{'field': field, 'before': before, 'after': after,
                                    'increased': after > before, 'decreased': after < before,
                                    'delta_magnitude': abs(after - before)}
                                   for field, before, after in zip(fields, old, new)]})
    return {'available': True, 'changed': actual != expected, 'carriers': changes}


def emit(value):
    try:
        print('combined_purity_difference_public=' + json.dumps(value, sort_keys=True), flush=True)
    except BaseException:
        pass  # Diagnostic output must never replace an original verdict.


def machine_hooks(namespace):
    saved = {name: namespace[name] for name in ('pure', 'strict')}
    ordinal = 0

    @wraps(saved['pure'])
    def pure(*args, **kwargs):
        nonlocal ordinal
        ordinal += 1
        return saved['pure'](*args, **kwargs)

    @wraps(saved['strict'])
    def strict(*args, **kwargs):
        try:
            values = dict(zip(('actual', 'expected', 'current', 'before', 'phase'), args))
            values.update(kwargs)
            actual, expected = values['actual'], values['expected']
            current, before = values['current'], values['before']
            if actual != expected or current != before:
                emit({'suite': 'machine_owner',
                      'phase': MACHINE_PHASES[ordinal - 1] if 1 <= ordinal <= len(MACHINE_PHASES) else 'unknown',
                      'pure_call_count': ordinal,
                      'mode': values['phase'] if values['phase'] in ('API', 'CLI') else 'unknown',
                      'participants': [{'participant': role, **snapshot_summary(old, new, True)}
                                       for role, old, new in zip(('owner', 'requester'), expected, actual)],
                      'carrier_observation': carrier_summary(current, before)})
        except BaseException:
            pass
        return saved['strict'](*args, **kwargs)

    namespace.update(pure=pure, strict=strict)
    return saved


def completion_hooks(namespace, function):
    saved = {'terminal_carrier_diagnostic': namespace['terminal_carrier_diagnostic']}
    captured = None

    @wraps(saved['terminal_carrier_diagnostic'])
    def terminal(*args, **kwargs):
        nonlocal captured
        try:
            values = dict(zip(('actual', 'expected', 'phase', 'mode'), args))
            values.update(kwargs)
            captured = values
        except BaseException:
            pass
        return saved['terminal_carrier_diagnostic'](*args, **kwargs)

    @wraps(function)
    def observed_function(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except BaseException as error:
            try:
                frames = []
                trace = error.__traceback__
                while trace is not None:
                    if trace.tb_frame.f_globals is namespace:
                        frames.append(trace.tb_frame)
                    trace = trace.tb_next
                # The exact existing terminal case or its pure wrong-review
                # completion call already holds both snapshots. No new read.
                frame = next((item for item in reversed(frames)
                              if item.f_code.co_name in ('complete', function.__name__)
                              and {'before', 'after'} <= item.f_locals.keys()), None)
                if frame is not None:
                    values = frame.f_locals
                    wrong_review = frame.f_code.co_name == 'complete'
                    phase = values.get('diagnostic_phase' if wrong_review else 'phase')
                    mode = 'API' if wrong_review else values.get('mode')
                    counters = captured if captured is not None and (
                        captured.get('phase') == phase and captured.get('mode') == mode
                        and captured.get('expected') == values.get('network')) else {}
                    emit({'suite': 'requester_completion',
                          'phase': phase if phase in ('expired', 'detached', 'restarted') else 'unknown',
                          'mode': mode if mode in ('API', 'CLI') else 'unknown',
                          'operation': 'wrong_review' if wrong_review else 'history_replay',
                          'participants': [{'participant': 'requester',
                                            **snapshot_summary(values['before'], values['after'], False)}],
                          'carrier_observation': carrier_summary(counters.get('actual'), counters.get('expected'))})
            except BaseException:
                pass
            raise  # Preserve the same exception, assertion and suite verdict.

    namespace['terminal_carrier_diagnostic'] = terminal
    return saved, observed_function


def observed_case(original, selected):
    @wraps(original)
    def case(suite, *args, **kwargs):
        decorator = original(suite, *args, **kwargs)
        name = args[0] if args else kwargs.get('name')
        if name != CASES[selected]:
            return decorator

        def register(function):
            namespace = function.__globals__
            saved = {}
            try:
                if selected == 'machine_owner':
                    saved = machine_hooks(namespace)
                else:
                    saved, function = completion_hooks(namespace, function)
                return decorator(function)
            finally:
                namespace.update(saved)
        return register
    return case


def main():
    argv, original = sys.argv, harness.Suite.case
    if len(argv) < 2 or argv[1] not in CASES:
        raise SystemExit('select machine_owner or requester_completion')
    selected = argv[1]
    entrypoint = 'requester_completion_prerequisite.py' if selected == 'requester_completion' else 'machine_owner.py'
    subject = str(Path(__file__).with_name(entrypoint))
    try:
        sys.argv = [subject, *argv[2:]]
        harness.Suite.case = observed_case(original, selected)
        return runpy.run_path(subject, run_name='__main__')
    finally:
        sys.argv, harness.Suite.case = argv, original


if __name__ == '__main__':
    main()
