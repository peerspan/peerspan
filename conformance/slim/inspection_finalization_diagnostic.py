#!/usr/bin/env python3
"""Run unchanged machine_requester_inspection with closed failure metadata.

GU.impl47/1023749: no extra host, API, storage, network or subprocess work.
Only the existing link/finalize Result or exception is observed. The original
suite argv, calls, assertions, timeouts and exit remain authoritative.
"""
import json
from pathlib import Path
import re
import runpy
import subprocess

import harness


PUBLIC_CODES = frozenset('invalid forbidden authority_expired device_revoked not_yet_valid '
    'authority_would_be_invalidated not_found proof_required state_conflict operation_conflict '
    'version_exhausted quota_exceeded clock_rollback review_required signer_unavailable recovery_required '
    'expired upgrade_required rate_limited internal'.split())
STATES = frozenset('pending needs_selection needs_administrator needs_owner_finalization needs_commit '
                   'finalizing linked cancelled expired blocked'.split())


def exception_kind(error):
    for kind, cls in (('timeout', subprocess.TimeoutExpired), ('host_failure', harness.Failure),
                      ('os_error', OSError), ('system_exit', SystemExit), ('keyboard_interrupt', KeyboardInterrupt)):
        if isinstance(error, cls):
            return kind
    return 'other'


def metadata(result=None, error=None):
    summary = {'exit_code': 'unknown', 'exception_kind': exception_kind(error) if error is not None else 'none',
               'stderr_categories': [], 'stdout_object': False, 'state': 'unknown',
               'owner_present': 'unknown', 'selection_present': 'unknown', 'finalization_present': 'unknown'}
    if result is None:
        return summary
    summary['exit_code'] = result.code if type(result.code) is int else 'unknown'
    summary['stderr_categories'] = sorted(code for code in PUBLIC_CODES if re.search(
        r'(?<![A-Za-z0-9_])' + re.escape(code) + r'(?![A-Za-z0-9_])', result.stderr))
    value = result.json
    summary['stdout_object'] = type(value) is dict
    if type(value) is not dict:
        return summary
    request = value.get('request', value)
    if type(request) is not dict:
        return summary
    state = request.get('state')
    summary['state'] = state if isinstance(state, str) and state in STATES else 'unknown'
    for label, field in (('owner_present', 'owner_offer_id'), ('selection_present', 'selection_id'),
                         ('finalization_present', 'owner_finalization_id')):
        reference = request.get(field)
        if reference == '-':
            summary[label] = False
        elif isinstance(reference, str) and re.fullmatch(r'dpk_[0-9a-f]{64}', reference):
            summary[label] = True
    return summary


def emit(result=None, error=None):
    try:
        print('inspection_finalize_failure_public=' + json.dumps(metadata(result, error), sort_keys=True), flush=True)
    except BaseException:
        try:
            print('inspection_finalize_diagnostic_unavailable', flush=True)
        except BaseException:
            pass  # Only observer errors are suppressed; original verdict remains.


def instrument(original):
    def observed_cli(host, *args, **kwargs):
        if args[:2] != ('link', 'finalize'):
            return original(host, *args, **kwargs)
        try:
            result = original(host, *args, **kwargs)
        except BaseException as error:
            emit(error=error)
            raise
        try:
            # Exactly the unchanged old45 success/incomplete guard.
            if not (result.ok or (result.code == 1 and 'linking is incomplete' in result.stderr)):
                emit(result=result)
        except BaseException:
            # A projection/observer failure cannot replace the original Result.
            try:
                print('inspection_finalize_diagnostic_unavailable', flush=True)
            except BaseException:
                pass
        return result
    return observed_cli


def main():
    original = harness.Host.cli
    try:
        harness.Host.cli = instrument(original)
        # run_path temporarily sets argv[0]; all suite options remain unchanged.
        return runpy.run_path(str(Path(__file__).with_name('machine_requester_inspection.py')), run_name='__main__')
    finally:
        harness.Host.cli = original


if __name__ == '__main__':
    main()
