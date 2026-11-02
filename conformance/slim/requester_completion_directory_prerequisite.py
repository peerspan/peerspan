#!/usr/bin/env python3
"""Observe truthful stopped-issuer directory state before terminal history.

Final acceptance d964f7f: only the final literal requester-completion case.
Call original terminal_cleanup once unchanged, then the existing public12s
terminal_restart_directory prerequisite once, before returning to frozen quiet
and strict snapshots/counters. No daemon restart, filtering, counter reset,
authority/SQL edits, new approval, or mutation retry. The first packet remains
unattributed. Existing outbox and receive-only launchers remain composed.
"""
from functools import wraps
from inspect import unwrap
import json
from pathlib import Path
import runpy
import sys

import harness


CASE = 'pure_verified_completed_API_CLI_replay_after_detach_restart_expiry_with_original_sources_absent'


def report(satisfied):
    try:
        print('terminal_directory_prerequisite_public=' + json.dumps({
            'phase': 'after_terminal_cleanup_before_history_baseline',
            'truthful_stopped_issuer_observed': satisfied}, sort_keys=True), flush=True)
    except BaseException:
        pass  # Diagnostic output never replaces a prerequisite verdict.


def observed_case(original):
    @wraps(original)
    def case(suite, *args, **kwargs):
        decorator = original(suite, *args, **kwargs)
        name = args[0] if args else kwargs.get('name')
        if name != CASE:
            return decorator

        def register(function):
            # The combined observer may already have wrapped this callback.
            # Discover its original globals while forwarding the same callback.
            namespace = unwrap(function).__globals__
            cleanup = namespace['terminal_cleanup']

            @wraps(cleanup)
            def after_cleanup(*args, **kwargs):
                result = cleanup(*args, **kwargs)
                fixture = args[0] if args else kwargs['f']
                try:
                    namespace['terminal_restart_directory'](
                        fixture['h'], fixture['a'], fixture['network']['id'])
                except BaseException:
                    report(False)
                    raise
                report(True)
                return result

            try:
                namespace['terminal_cleanup'] = after_cleanup
                return decorator(function)
            finally:
                namespace['terminal_cleanup'] = cleanup
        return register
    return case


def main():
    argv, original = sys.argv, harness.Suite.case
    subject = str(Path(__file__).with_name('combined_purity_diagnostic.py'))
    try:
        sys.argv = [subject, 'requester_completion', *argv[1:]]
        harness.Suite.case = observed_case(original)
        return runpy.run_path(subject, run_name='__main__')
    finally:
        sys.argv, harness.Suite.case = argv, original


if __name__ == '__main__':
    main()
