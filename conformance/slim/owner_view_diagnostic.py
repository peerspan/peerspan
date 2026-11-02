#!/usr/bin/env python3
"""Observe existing owner LINK_VIEW comparison failures without another read.

Section49/eae8b39: only two literal live-history cases, supplied validate.request
versus its one existing follow-up get. No extra host/API/database/transport work,
wait, mutation, changed value/assertion/verdict or eager subject import. Private
references and attention text remain private; output is fixed fields/counts/states.
"""
from functools import wraps
import json
from pathlib import Path
import runpy
import sys

import harness


CASES = {
    'owner_onboarding': 'same_intent_advanced_signing_admin_finalization_commit_and_stable_history',
    'owner_signing': 'same_intent_real_administrator_finalization_commit_and_pure_history_without_keys',
}
FIELDS = set('request_id role mode state network_id context_id migration_proposal_id person_public_key host_public_key device_public_key created_at expires_at request_packet_id owner_offer_id selection_id administrator_offer_id owner_finalization_id manifest_id activation_id outcome_id selection_approved commit_approved completed attention next'.split())
STATES = set('pending needs_selection needs_administrator needs_owner_finalization needs_commit finalizing linked migration_prepared migration_adopted cancelled expired blocked'.split())
REFERENCES = ('owner_offer_id', 'selection_id', 'administrator_offer_id', 'owner_finalization_id',
              'manifest_id', 'activation_id', 'outcome_id')


def project_view(value):
    if type(value) is not dict:
        return {'field_count': None, 'state': 'unknown', 'completed_count': None,
                'attention_count': None, 'work_reference_count': None, 'approval_count': None}
    return {'field_count': len(value), 'state': value.get('state') if value.get('state') in STATES else 'unknown',
            'completed_count': len(value['completed']) if type(value.get('completed')) is list else None,
            'attention_count': len(value['attention']) if type(value.get('attention')) is list else None,
            'work_reference_count': sum(type(value.get(key)) is str and value[key] != '-' for key in REFERENCES),
            'approval_count': sum(value.get(key) is True for key in ('selection_approved', 'commit_approved'))}


def report(supplied, actual):
    if supplied == actual:
        return
    try:
        fields = sorted({name if name in FIELDS else 'unknown' for name in supplied.keys() | actual.keys()
                         if name not in supplied or name not in actual or supplied[name] != actual[name]}) if (
                             type(supplied) is dict and type(actual) is dict) else ['unknown']
        print('owner_view_difference_public=' + json.dumps({'changed_fields': fields,
            'supplied': project_view(supplied), 'followup': project_view(actual)}, sort_keys=True), flush=True)
    except BaseException:
        try:
            print('owner_view_diagnostic_unavailable', flush=True)
        except BaseException:
            pass


def observed_case(original, selected):
    @wraps(original)
    def case(suite, *args, **kwargs):
        decorator = original(suite, *args, **kwargs)
        name = args[0] if args else kwargs.get('name')
        if name != CASES[selected]:
            return decorator
        def register(function):
            namespace = function.__globals__
            validate, get = namespace['validate'], namespace['get']
            current = None
            @wraps(validate)
            def observed_validate(*args, **kwargs):
                nonlocal current
                previous = current
                try:
                    values = dict(zip(('h', 'flow', 'value'), args)); values.update(kwargs)
                    current = {'host': values['h'], 'path': '/v2/link/requests/' + values['flow']['outcome']['request_id'],
                               'supplied': values['value']['request'], 'seen': False}
                except BaseException:
                    current = None
                try:
                    return validate(*args, **kwargs)
                finally:
                    current = previous
            @wraps(get)
            def observed_get(*args, **kwargs):
                result = get(*args, **kwargs)
                try:
                    values = dict(zip(('h', 'path'), args)); values.update(kwargs)
                    if current is not None and not current['seen'] and values['h'] is current['host'] and values['path'] == current['path']:
                        current['seen'] = True
                        report(current['supplied'], result)
                except BaseException:
                    pass  # Never replace the exact original get result/verdict.
                return result
            try:
                namespace['validate'], namespace['get'] = observed_validate, observed_get
                return decorator(function)
            finally:
                namespace['validate'], namespace['get'] = validate, get
        return register
    return case


def main():
    original_argv, original_case = sys.argv, harness.Suite.case
    if len(original_argv) < 2 or original_argv[1] not in CASES:
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
