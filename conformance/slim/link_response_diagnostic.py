#!/usr/bin/env python3
"""Receive-only commit/resume metadata around an unchanged CI entrypoint.

Usage: link_response_diagnostic.py TARGET_SCRIPT [original arguments ...]
No calls, waits, retries, assertions, values or deadlines are added to a target.
Only closed response categories are printed, at most eight per host/64 total.
"""
from functools import wraps
import json
from pathlib import Path
import re
import runpy
import sys
import threading

import harness


STATES = frozenset('pending needs_selection needs_administrator needs_owner_finalization needs_commit '
    'finalizing linked migration_prepared migration_adopted cancelled expired blocked'.split())
CODES = frozenset('invalid forbidden authority_expired device_revoked not_yet_valid '
    'authority_would_be_invalidated not_found proof_required state_conflict operation_conflict '
    'version_exhausted quota_exceeded clock_rollback review_required signer_unavailable recovery_required '
    'expired upgrade_required rate_limited internal transport_unavailable review_changed review_expired '
    'commit_completion_unavailable request_unavailable invalid_request'.split())
ROUTE = re.compile(r'/v2/link/requests/link_[0-9a-f]{64}/(commit|resume)')


class Observer:
    def __init__(self):
        self.lock = threading.Lock()
        self.hosts = []
        self.per_host = []
        self.total = 0

    def receive(self, host, operation, result):
        status, value = result
        view = value.get('request', value) if type(value) is dict else None
        view = view if type(view) is dict else {}
        state = view.get('state')
        code = value.get('code') if type(value) is dict else None
        attention = view.get('attention')
        categories = set()
        if type(attention) is list:
            for item in attention[:16]:
                found = {code for code in CODES if type(item) is str and re.search(
                    r'(?<![A-Za-z0-9_])' + re.escape(code) + r'(?![A-Za-z0-9_])', item)}
                categories.update(found or {'other'})
        with self.lock:
            if self.total >= 64:
                return
            index = next((index for index, known in enumerate(self.hosts) if known is host), None)
            if index is None:
                index = len(self.hosts)
                self.hosts.append(host); self.per_host.append(0)
            if self.per_host[index] >= 8:
                return
            self.per_host[index] += 1; self.total += 1
            print('link_response_public=' + json.dumps({'host_ordinal': index + 1,
                'observation_ordinal': self.total, 'operation': operation,
                'http_status': status if type(status) is int and 100 <= status <= 599 else 'other',
                'state': state if type(state) is str and state in STATES else 'other',
                'error_code': code if type(code) is str and code in CODES else 'other',
                'attention_count': len(attention) if type(attention) is list else 0,
                'attention_codes': sorted(categories),
                'attention_truncated': type(attention) is list and len(attention) > 16}, sort_keys=True), flush=True)


def instrument(original, observer):
    @wraps(original)
    def api(host, *args, **kwargs):
        result = original(host, *args, **kwargs)
        try:
            values = dict(zip(('method', 'path'), args)); values.update(kwargs)
            path = values.get('path')
            match = ROUTE.fullmatch(path) if type(path) is str and values.get('method') == 'POST' else None
            if match is not None:
                observer.receive(host, match.group(1), result)
        except (ValueError, TypeError, AttributeError, KeyError, IndexError, OSError, re.error):
            pass  # Suite failures, skips, hard deadlines and interrupts propagate.
        return result
    return api


def main():
    argv, search_path, original = sys.argv, sys.path[:], harness.Host.api
    if len(argv) < 2:
        raise SystemExit('supply TARGET_SCRIPT and its original arguments')
    target = argv[1]
    try:
        sys.argv = [target, *argv[2:]]
        sys.path[0] = str(Path(target).resolve().parent)
        harness.Host.api = instrument(original, Observer())
        return runpy.run_path(target, run_name='__main__')
    finally:
        sys.argv, harness.Host.api = argv, original
        sys.path[:] = search_path


if __name__ == '__main__':
    main()
