#!/usr/bin/env python3
"""Receive-only metadata for the frozen access inspection bootstrap check.

Usage: bootstrap_response_diagnostic.py TARGET_SCRIPT [original arguments ...]
Composes the existing link response observer. Only HTTPResponse.begin called
directly from access_onboarding.py is observed; headers are already received.
No body/socket read, request, retry, assertion, wait or deadline is changed.
"""
from functools import wraps
import http.client
import json
from pathlib import Path
import re
import runpy
import sys


def instrument(original):
    captured = 0

    @wraps(original)
    def begin(response, *args, **kwargs):
        nonlocal captured
        result = original(response, *args, **kwargs)
        try:
            caller = sys._getframe(1).f_code.co_filename
            if caller.replace('\\', '/').rsplit('/', 1)[-1] != 'access_onboarding.py' or captured >= 64:
                return result
            values = response.headers.get_all('Retry-After', [])
            value = values[0].strip(' \t') if len(values) == 1 and type(values[0]) is str else ''
            positive = re.fullmatch(r'[0-9]+', value) is not None and any(char != '0' for char in value)
            status = response.status
            captured += 1
            print('bootstrap_response_public=' + json.dumps({
                'http_status': status if type(status) is int and 100 <= status <= 599 else 'other',
                'retry_after_valid_positive': positive}, sort_keys=True), flush=True)
        except (ValueError, TypeError, AttributeError, KeyError, IndexError, OSError, re.error):
            pass  # Failures/skips, hard deadlines, SystemExit and interrupts propagate.
        return result
    return begin


def main():
    argv, original = sys.argv, http.client.HTTPResponse.begin
    if len(argv) < 2:
        raise SystemExit('supply TARGET_SCRIPT and its original arguments')
    subject = str(Path(__file__).with_name('link_response_diagnostic.py'))
    try:
        sys.argv = [subject, *argv[1:]]
        http.client.HTTPResponse.begin = instrument(original)
        return runpy.run_path(subject, run_name='__main__')
    finally:
        sys.argv, http.client.HTTPResponse.begin = argv, original


if __name__ == '__main__':
    main()
