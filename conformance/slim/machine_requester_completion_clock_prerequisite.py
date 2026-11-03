#!/usr/bin/env python3
"""Keep one moving raw-creation negative stimulus before the frozen baseline.

Only the literal original-provider time case. Original quiet runs first; the
same captured consent-created-minus-one target is reapplied with floor once,
before original whole/traffic snapshots. Dispatch must still precede consent
creation. Signed expiry, original calls/restoration/guards and history chain
stay unchanged. Closed observations do not attribute the earlier CI failure.
"""
from datetime import datetime, timedelta, timezone
from functools import wraps
from inspect import unwrap
import json
import math
from pathlib import Path
import runpy
import sys

import harness


CASE = 'genuine_remote_original_cap_signed_raw_expiry_and_actual_apply_time_guard'
RAW_CODE = 'machine_commit_completion_unavailable'
CODES = frozenset('machine_commit_completion_unavailable review_expired review_changed '
                  'request_unavailable machine_requester_consent_unavailable clock_rollback '
                  'state_conflict operation_conflict invalid not_found internal signer_unavailable '
                  'quota_exceeded review_required'.split())
STATES = frozenset('pending needs_selection needs_administrator needs_owner_finalization '
                   'needs_commit finalizing linked cancelled expired blocked'.split())
METADATA_ERRORS = (ValueError, TypeError, AttributeError, KeyError, IndexError, OSError)


def boundaries(fixture):
    raw = datetime.now(timezone.utc) + timedelta(seconds=fixture['b'].clock.offset)
    return {'before_request_creation': raw < harness.parse_time(fixture['view']['created_at']),
            'before_consent_creation': raw < harness.parse_time(fixture['approved']['consent']['review']['created_at']),
            'before_signed_expiry': raw < harness.parse_time(fixture['view']['expires_at'])}


def emit(observation, point, result=None):
    try:
        value = {'phase': observation['phase'], 'point': point}
        for field in ('before_baseline', 'after_rearm', 'at_dispatch', 'lost_before_rearm',
                      'rearmed_same_target', 'clock_outside_measured_roots'):
            if field in observation:
                value[field] = observation[field]
        if result is not None:
            status, body = result
            body = body if type(body) is dict else {}
            request = body.get('request'); request = request if type(request) is dict else {}
            state, code = request.get('state'), body.get('code')
            value.update(http_status=status if type(status) is int and 100 <= status <= 599 else 'other',
                         code=code if type(code) is str and code in CODES else 'other',
                         request_state=state if type(state) is str and state in STATES else 'other')
        print('machine_requester_completion_clock_public=' + json.dumps(value, sort_keys=True), flush=True)
    except METADATA_ERRORS:
        pass  # Failures, skips, hard deadlines and interrupts propagate.


def observed_case(original):
    @wraps(original)
    def case(suite, *args, **kwargs):
        decorator = original(suite, *args, **kwargs)
        if (args[0] if args else kwargs.get('name')) != CASE:
            return decorator

        def register(function):
            namespace = unwrap(function).__globals__
            refusal, quiet, api = namespace['pure_clock_refusal'], namespace['quiet'], harness.Host.api
            active = None

            @wraps(refusal)
            def clock_refusal(*args, **kwargs):
                nonlocal active
                values = dict(zip(('f', 'target', 'code'), args)); values.update(kwargs)
                code = values['code']
                observation = {'fixture': values['f'], 'target': values['target'], 'code': code,
                               'phase': 'raw_before_consent_creation' if code == RAW_CODE else 'signed_request_expiry'}
                previous, active = active, observation
                try:
                    return refusal(*args, **kwargs)
                finally:
                    active = previous

            @wraps(quiet)
            def settled(*args, **kwargs):
                result = quiet(*args, **kwargs)
                fixture = args[0] if args else kwargs['f']
                if active is not None and fixture is active['fixture']:
                    active['before_baseline'] = boundaries(fixture)
                    if active['code'] == RAW_CODE:
                        harness.check(not active.get('rearmed_same_target'), 'raw creation fixture attempted a second rearm')
                        expected = harness.parse_time(fixture['approved']['consent']['review']['created_at']) - timedelta(seconds=1)
                        harness.check(active['target'] == expected, 'raw creation fixture changed its original target')
                        hosts = (fixture['a'], fixture['b'])
                        external = all(Path(host.clock.path).is_absolute() and not Path(host.clock.path).is_relative_to(root)
                                       for host in hosts for participant in hosts for root in (participant.state, participant.home))
                        harness.check(external, 'raw creation clock is inside measured fixture roots')
                        active['clock_outside_measured_roots'] = external
                        active['lost_before_rearm'] = not active['before_baseline']['before_consent_creation']
                        offset = math.floor((active['target'] - datetime.now(timezone.utc)).total_seconds())
                        for host in hosts:
                            host.clock.set(offset)
                        active['rearmed_same_target'] = True
                        active['after_rearm'] = boundaries(fixture)
                        emit(active, 'before_original_baseline')
                        harness.check(active['after_rearm']['before_consent_creation'], 'raw creation pre-baseline stimulus was lost')
                    else:
                        emit(active, 'before_original_baseline')
                return result

            @wraps(api)
            def observed_api(host, *args, **kwargs):
                values = dict(zip(('method', 'path'), args)); values.update(kwargs)
                observation = active
                selected = (observation is not None and host is observation['fixture']['b']
                            and values.get('method') == 'POST'
                            and values.get('path') == namespace['endpoint'](observation['fixture'], 'complete'))
                if selected:
                    observation['at_dispatch'] = boundaries(observation['fixture'])
                    if observation['code'] == RAW_CODE:
                        emit(observation, 'original_dispatch_precondition')
                        harness.check(observation.get('rearmed_same_target') and observation['at_dispatch']['before_consent_creation'],
                                      'raw creation stimulus was lost after original baseline; no dispatch retry')
                result = api(host, *args, **kwargs)
                if selected:
                    emit(observation, 'original_response', result)
                return result

            try:
                namespace['pure_clock_refusal'], namespace['quiet'], harness.Host.api = clock_refusal, settled, observed_api
                return decorator(function)
            finally:
                namespace['pure_clock_refusal'], namespace['quiet'], harness.Host.api = refusal, quiet, api
        return register
    return case


def main():
    argv, original = sys.argv, harness.Suite.case
    subject = str(Path(__file__).with_name('machine_requester_completion_prerequisite.py'))
    try:
        sys.argv = [subject, *argv[1:]]
        harness.Suite.case = observed_case(original)
        return runpy.run_path(subject, run_name='__main__')
    finally:
        sys.argv, harness.Suite.case = argv, original


if __name__ == '__main__':
    main()
