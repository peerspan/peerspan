#!/usr/bin/env python3
"""Publish private debug barriers atomically in one unchanged requester case.

Final acceptance2deb495: only the literal pre-application barrier case. Original
arm/release calls, exact bytes, actions, assertions, clocks, deadlines and verdict
stay intact. Same-directory0600 complete files become visible by atomic rename.
Receive-only completion status/code metadata precedes the original assertion.
No claim that marker publication caused the earlier unclassified409 response.
"""
from functools import wraps
from inspect import unwrap
import json
import os
from pathlib import Path
import runpy
import stat
import sys
import tempfile

import harness


CASE = 'actual_pre_application_barrier_rechecks_changed_parent_before_the_final_transaction'
CODES = frozenset({'review_changed', 'review_expired', 'commit_completion_unavailable', 'state_conflict',
                   'request_unavailable', 'not_found', 'invalid_request', 'forbidden', 'internal'})


def atomic_marker(path, text):
    data = text.encode('utf-8')
    descriptor, name = tempfile.mkstemp(prefix='.barrier-publication-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'wb') as target:
            os.fchmod(target.fileno(), 0o600)
            metadata = os.fstat(target.fileno())
            harness.check(stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o600
                          and metadata.st_nlink == 1, 'atomic barrier temporary file is not private regular single-link')
            harness.check(target.write(data) == len(data), 'atomic barrier publication did not write exact complete bytes')
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def report(result):
    try:
        status, response = result
        code = response.get('code') if type(response) is dict else None
        print('requester_barrier_response_public=' + json.dumps({
            'http_status': status if type(status) is int and 100 <= status <= 599 else 'other',
            'code': code if type(code) is str and code in CODES else 'other'}, sort_keys=True), flush=True)
    except BaseException:
        pass  # Observer failure must not replace the original response/verdict.


def observed_case(original):
    @wraps(original)
    def case(suite, *args, **kwargs):
        decorator = original(suite, *args, **kwargs)
        name = args[0] if args else kwargs.get('name')
        if name != CASE:
            return decorator

        def register(function):
            namespace = unwrap(function).__globals__
            marker, api = namespace['marker'], harness.Host.api

            @wraps(api)
            def observed_api(host, *args, **kwargs):
                result = api(host, *args, **kwargs)
                try:
                    values = dict(zip(('method', 'path'), args)); values.update(kwargs)
                    path = values.get('path')
                    if (values.get('method') == 'POST' and type(path) is str
                            and path.startswith(namespace['BASE'] + '/') and path.endswith('/commit/complete')):
                        report(result)
                except BaseException:
                    pass
                return result

            try:
                namespace['marker'] = atomic_marker
                harness.Host.api = observed_api
                return decorator(function)
            finally:
                namespace['marker'], harness.Host.api = marker, api
        return register
    return case


def main():
    argv, original = sys.argv, harness.Suite.case
    subject = str(Path(__file__).with_name('requester_completion_directory_prerequisite.py'))
    try:
        sys.argv = [subject, *argv[1:]]
        harness.Suite.case = observed_case(original)
        return runpy.run_path(subject, run_name='__main__')
    finally:
        sys.argv, harness.Suite.case = argv, original


if __name__ == '__main__':
    main()
