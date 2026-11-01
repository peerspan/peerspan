#!/usr/bin/env python3
"""GU.impl48/64eb756: completed-attempt witness before machine-history alignment.

Independent public-contract adapter only; reuse the unchanged test prerequisite.
No new API/probe/send/clock/retry or subject warmup. All original suite actions,
guards, counters, snapshots, bounds, argv and verdict remain authoritative.
The prior CI timeout's row/journal/caller remains unknown; this is no fix claim.
"""
from functools import wraps
from pathlib import Path
import runpy

import harness
from requester_completion_prerequisite import completed_attempts


CASE = 'verified_completed_replay_pure_after_expiry_detach_restart_and_anchor_rollback'


def wrap_case(original):
    @wraps(original)
    def case(suite, *args, **kwargs):
        decorator = original(suite, *args, **kwargs)
        name = args[0] if args else kwargs.get('name')

        def register(function):
            if name != CASE:
                return decorator(function)
            namespace = function.__globals__
            baseline = namespace['terminal_baseline']

            @wraps(baseline)
            def terminal(f, *args, **kwargs):
                local = f['b']; missing = object()
                previous = vars(local).get('api', missing)
                original_api = local.api
                path = '/v2/networks/' + f['network']['id'] + '/sync'
                used = False

                @wraps(original_api)
                def api(*args, **kwargs):
                    nonlocal used
                    result = original_api(*args, **kwargs)
                    method = args[0] if args else kwargs.get('method')
                    requested_path = args[1] if len(args) > 1 else kwargs.get('path')
                    if not used and method == 'POST' and requested_path == path:
                        try:
                            status, synced = result
                            valid = (status == 200 and synced['unavailable'] == []
                                     and synced['network']['authority']['state'] == 'usable')
                        except BaseException:
                            valid = False  # Original malformed result reaches its original guard.
                        if valid:
                            used = True
                            completed_attempts(namespace, (f['a'], local))
                    return result

                local.api = api
                try:
                    return baseline(f, *args, **kwargs)
                finally:
                    if previous is missing:
                        del local.api
                    else:
                        local.api = previous

            namespace['terminal_baseline'] = terminal
            try:
                return decorator(function)
            finally:
                namespace['terminal_baseline'] = baseline
        return register
    return case


def main():
    original = harness.Suite.case
    try:
        harness.Suite.case = wrap_case(original)
        return runpy.run_path(str(Path(__file__).with_name('machine_requester_completion.py')), run_name='__main__')
    finally:
        harness.Suite.case = original


if __name__ == '__main__':
    main()
