#!/usr/bin/env python3
"""Receive-only machine-commit Complete metadata around an unchanged CI entrypoint.

Usage: machine_requester_completion_apply_diagnostic.py TARGET_SCRIPT [original arguments ...]
No calls, waits, retries, assertions, values or deadlines are added to a target.
For each POST to a machine-commit `complete` endpoint, only its case, ordinal,
HTTP status and closed response categories are printed, at most 64 in total.
"""
from functools import wraps
import json
from pathlib import Path
import runpy
import sys
import threading

import harness


CODES = frozenset('machine_commit_completion_unavailable review_expired review_changed '
                  'request_unavailable machine_requester_consent_unavailable clock_rollback '
                  'state_conflict operation_conflict invalid not_found internal signer_unavailable '
                  'quota_exceeded review_required forbidden authority_expired expired'.split())
STATES = frozenset('pending needs_selection needs_administrator needs_owner_finalization '
                   'needs_commit finalizing linked cancelled expired blocked'.split())
METADATA_ERRORS = (ValueError, TypeError, AttributeError, KeyError, IndexError, OSError)


class Observer:
    def __init__(self):
        self.lock = threading.Lock()
        self.case = None
        self.total = 0

    def receive(self, result):
        status, value = result
        value = value if type(value) is dict else {}
        request = value.get('request'); request = request if type(request) is dict else {}
        code, state = value.get('code'), request.get('state')
        with self.lock:
            if self.total >= 64:
                return
            self.total += 1
            print('machine_requester_completion_apply_public=' + json.dumps({
                'case': self.case if type(self.case) is str else 'other',
                'observation_ordinal': self.total,
                'http_status': status if type(status) is int and 100 <= status <= 599 else 'other',
                'code': code if type(code) is str and code in CODES else ('none' if code is None else 'other'),
                'request_state': state if type(state) is str and state in STATES else 'other',
                'completion': type(value.get('completion')) is dict}, sort_keys=True), flush=True)


def instrument_api(original, observer):
    @wraps(original)
    def api(host, *args, **kwargs):
        result = original(host, *args, **kwargs)
        try:
            values = dict(zip(('method', 'path'), args)); values.update(kwargs)
            path = values.get('path')
            if values.get('method') == 'POST' and type(path) is str and path.endswith('/machine-commit/complete'):
                observer.receive(result)
        except METADATA_ERRORS:
            pass  # Suite failures, skips, hard deadlines and interrupts propagate.
        return result
    return api


def instrument_case(original, observer):
    @wraps(original)
    def case(suite, *args, **kwargs):
        decorator = original(suite, *args, **kwargs)
        name = args[0] if args else kwargs.get('name')

        def register(function):
            @wraps(function)
            def named():
                previous, observer.case = observer.case, name
                try:
                    return function()
                finally:
                    observer.case = previous
            decorator(named)
            return function
        return register
    return case


def main():
    argv, search_path = sys.argv, sys.path[:]
    api, case = harness.Host.api, harness.Suite.case
    if len(argv) < 2:
        raise SystemExit('supply TARGET_SCRIPT and its original arguments')
    target = argv[1]
    try:
        sys.argv = [target, *argv[2:]]
        sys.path[0] = str(Path(target).resolve().parent)
        observer = Observer()
        harness.Host.api = instrument_api(api, observer)
        harness.Suite.case = instrument_case(case, observer)
        return runpy.run_path(target, run_name='__main__')
    finally:
        sys.argv, harness.Host.api, harness.Suite.case = argv, api, case
        sys.path[:] = search_path


if __name__ == '__main__':
    main()
