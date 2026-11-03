#!/usr/bin/env python3
"""Receive-only public prefix for one unchanged requester-commit history case.

Run under link_response_diagnostic.py with the original requester_commit args.
Only the original pre-commit GET and ordinary commit input/response are observed.
No calls, reads, actions, assertions, retries, waits or deadlines are added.
"""
from functools import wraps
from inspect import unwrap
import json
from pathlib import Path
import re
import runpy
import sys

import harness
from link_response_diagnostic import CODES, STATES


CASE = 'same_request_explicit_completion_then_keyless_detached_restart_expired_immutable_history'
STAGES = frozenset('request_created owner_offered owner_selected administrator_offered '
                   'owner_finalized commit_persisted locally_applied'.split())
PINS = ('network_id', 'context_id', 'person_public_key', 'host_public_key', 'device_public_key',
        'owner_offer_id', 'selection_id', 'administrator_offer_id', 'owner_finalization_id')
ARTIFACTS = ('request_packet_id', 'owner_offer_id', 'selection_id', 'administrator_offer_id',
             'owner_finalization_id', 'manifest_id', 'activation_id', 'outcome_id')
METADATA_ERRORS = (ValueError, TypeError, AttributeError, KeyError, IndexError, OSError, re.error)


def present(value):
    return type(value) is str and value not in ('', '-')


def equal_pins(left, right, fields):
    return {field: present(left.get(field)) and present(right.get(field))
            and left[field] == right[field] for field in fields}


def public_result(result):
    status, value = result
    value = value if type(value) is dict else {}
    view = value.get('request', value)
    view = view if type(view) is dict else {}
    completed, attention = view.get('completed'), view.get('attention')
    completed = completed if type(completed) is list else []
    attention = attention if type(attention) is list else []
    categories = set()
    for item in attention[:16]:
        found = {code for code in CODES if type(item) is str and re.search(
            r'(?<![A-Za-z0-9_])' + re.escape(code) + r'(?![A-Za-z0-9_])', item)}
        categories.update(found or {'other'})
    state, code = view.get('state'), value.get('code')
    return {'http_status': status if type(status) is int and 100 <= status <= 599 else 'other',
            'error_code': code if type(code) is str and code in CODES else 'other',
            'public_view_present': 'request_id' in view,
            'state': state if type(state) is str and state in STATES else 'other',
            'selection_approved': view.get('selection_approved') is True,
            'commit_approved': view.get('commit_approved') is True,
            'completed_stages': [stage if type(stage) is str and stage in STAGES else 'other'
                                 for stage in completed[:7]],
            'completed_truncated': len(completed) > 7,
            'commit_present': 'commit_persisted' in completed,
            'artifact_presence': {field: present(view.get(field)) for field in ARTIFACTS},
            'attention_codes': sorted(categories), 'attention_truncated': len(attention) > 16}


def emit(value):
    print('requester_commit_prefix_public=' + json.dumps(value, sort_keys=True), flush=True)


def observed_case(original):
    @wraps(original)
    def case(suite, *args, **kwargs):
        decorator = original(suite, *args, **kwargs)
        if (args[0] if args else kwargs.get('name')) != CASE:
            return decorator

        def register(function):
            namespace = unwrap(function).__globals__
            shared = namespace['shared']
            fixture = shared.get('main', {})
            approved = shared.get('approved', {})
            consent = approved.get('commit', {})
            review = consent.get('review', {})
            network = review.get('network', {})
            pins = {**review, 'network_id': network.get('id'), 'context_id': network.get('context_id')}
            host, request = fixture.get('h'), fixture.get('rid')
            path = '/v2/link/requests/' + request if type(request) is str else None
            api = harness.Host.api
            previous, received_get, received_commit = {}, False, False

            @wraps(api)
            def observed_api(local, *args, **kwargs):
                nonlocal previous, received_get, received_commit
                result = api(local, *args, **kwargs)
                try:
                    values = dict(zip(('method', 'path', 'body'), args)); values.update(kwargs)
                    if local is not host or received_commit or path is None:
                        return result
                    if values.get('method') == 'GET' and values.get('path') == path and not received_get:
                        received_get = True
                        previous = result[1] if type(result[1]) is dict else {}
                        emit({'phase': 'public_get_before_commit', **public_result(result),
                              'approved_consent_present': type(approved.get('commit')) is dict,
                              'approved_consent_state_approved': consent.get('state') == 'approved',
                              'pins_equal_approved_review': equal_pins(previous, pins, (*PINS, 'request_id', 'request_packet_id'))})
                    elif values.get('method') == 'POST' and values.get('path') == path + '/commit':
                        received_commit = True
                        body = values.get('body'); body = body if type(body) is dict else {}
                        emit({'phase': 'ordinary_commit_response', **public_result(result),
                              'precommit_get_observed': received_get,
                              'input_approve_true': body.get('approve') is True,
                              'input_pins_equal_get': equal_pins(body, previous, PINS),
                              'input_pins_equal_approved_review': equal_pins(body, pins, PINS)})
                except METADATA_ERRORS:
                    pass  # Original failures, skips, deadlines and interrupts propagate.
                return result

            try:
                harness.Host.api = observed_api
                return decorator(function)
            finally:
                harness.Host.api = api
        return register
    return case


def main():
    argv, original = sys.argv, harness.Suite.case
    subject = str(Path(__file__).with_name('requester_commit.py'))
    try:
        sys.argv = [subject, *argv[1:]]
        harness.Suite.case = observed_case(original)
        return runpy.run_path(subject, run_name='__main__')
    finally:
        sys.argv, harness.Suite.case = argv, original


if __name__ == '__main__':
    main()
