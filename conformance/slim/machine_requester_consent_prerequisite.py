#!/usr/bin/env python3
"""Preserve one raw-before-created fixture precondition; observe frozen failures.

Final acceptance contract: wrap only the unchanged section46 time case. The
debug clock is real UTC plus an integer offset, not a frozen instant. Its
created_at-1 target can pass during op(pure=True)'s existing quiet/snapshots.
Only the raw-created Approve/unavailable branch reapplies that SAME target with
floor immediately before its original API dispatch. Clock sidecars must lie
outside both hosts' measured state/home roots. No other clock adjustment, API,
DB/file observation, protocol mutation, retry, wait or deadline change is added.
Original case bodies, requests, purity categories, assertions and verdicts stay.

Closed phase/status/boundary diagnostics describe this execution only. They do
not identify the branch of the earlier CI failure, whose log was ambiguous.
Root alone runs this launcher with the original suite arguments.
"""
import ast
from datetime import datetime, timedelta, timezone
from functools import wraps
import hashlib
import json
import math
from pathlib import Path
import runpy
import sys
import time

import harness


CASE = 'real_cancel_fresh_nonce_raw_creation_stage_request_expiry_and_fixed_history'
CALLS = (
    ('lookup', 'pending_history'), ('lookup', 'cancelled_history'), ('prepare', 'cancelled_prepare'),
    ('prepare', 'raw_request_creation'), ('prepare', 'fresh_prepare'), ('approve', 'raw_intent_creation'),
    ('approve', 'changed_consent_pins'), ('prepare', 'changed_inspection_pin'),
    ('approve', 'stage_receipt_expiry'), ('lookup', 'stage_expired_history'),
    ('prepare', 'stage_expired_prepare_history'), ('approve', 'signed_request_expiry'),
    ('lookup', 'signed_expired_history'),
)
CODES = {'invalid', 'not_found', 'review_changed', 'request_unavailable', 'review_expired',
         'machine_requester_consent_unavailable', 'clock_rollback'}
STATES = {'review', 'approved', 'cancelled', 'expired', 'invalidated'}


def call_phases(source):
    tree = ast.parse(source)
    functions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        and any(isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr == 'case'
                and dec.args and isinstance(dec.args[0], ast.Constant) and dec.args[0].value == CASE
                for dec in node.decorator_list)]
    if len(functions) != 1:
        raise SystemExit('frozen machine requester time case unavailable')
    calls = sorted((node for node in ast.walk(functions[0]) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name) and node.func.id == 'op'), key=lambda n: (n.lineno, n.col_offset))
    actions = [node.args[1].value if len(node.args) > 1 and isinstance(node.args[1], ast.Constant) else None for node in calls]
    if actions != [action for action, _phase in CALLS]:
        raise SystemExit('frozen machine requester time call shape changed')
    return {line: phase for node, (_action, phase) in zip(calls, CALLS)
            for line in range(node.lineno, node.end_lineno + 1)}


def emit(value):
    try:
        print('machine_requester_clock_public=' + json.dumps(value, sort_keys=True), flush=True)
    except BaseException:
        pass  # Diagnostics cannot replace an original assertion or verdict.


def boundaries(raw, fixture, prepared):
    """Only relative public-window booleans; never output times or native IDs."""
    inspection = fixture.get('inspection', {}).get('review', {})
    consent = prepared.get('consent', {}).get('review', {}) if type(prepared) is dict else {}
    result = {}
    for label, value in (
        ('before_request_creation', inspection.get('created_at')),
        ('before_intent_creation', consent.get('created_at')),
        ('before_stage_deadline', inspection.get('request_stage_deadline')),
        ('before_request_expiry', inspection.get('expires_at')),
        ('before_receipt_expiry', consent.get('expires_at')),
        ('before_powers_end', inspection.get('not_after')),
    ):
        if type(value) is str:
            try:
                result[label] = raw < harness.parse_time(value)
            except (TypeError, ValueError):
                pass
    return result


def hooks(namespace, phases):
    original_op, original_api = namespace['op'], harness.Host.api
    active = None

    @wraps(original_api)
    def api(host, method, path, *args, **kwargs):
        observation = active
        selected = observation is not None and host is observation['fixture']['b'] and method == 'POST'
        if selected:
            selected = path == namespace['endpoint'](observation['fixture'], observation['action'])
        if selected:
            fixture, prepared = observation['fixture'], observation['prepared']
            sample = datetime.now(timezone.utc)
            raw = sample + timedelta(seconds=host.clock.offset)
            observation['before'] = boundaries(raw, fixture, prepared)
            observation['dispatch_after_op_ms'] = min(120000, max(0, int((time.monotonic() - observation['began']) * 1000)))
            if observation['phase'] == 'raw_intent_creation':
                harness.check(observation['action'] == 'approve' and observation['expected_status'] == 409
                    and observation['expected_code'] == 'machine_requester_consent_unavailable',
                    'machine requester raw-created dispatch precondition unavailable')
                target = harness.parse_time(prepared['consent']['review']['created_at']) - timedelta(seconds=1)
                hosts = (fixture['a'], fixture['b'])
                external = all(not Path(h.clock.path).is_relative_to(root)
                    for h in hosts for participant in hosts for root in (participant.state, participant.home))
                harness.check(external, 'machine requester raw-created clock is inside measured fixture roots')
                # Same canonical target; floor preserves its backward direction,
                # as in this frozen suite's existing anchor-301s regression.
                offset = math.floor((target - sample).total_seconds())
                for participant in hosts:
                    participant.clock.set(offset)
                raw = datetime.now(timezone.utc) + timedelta(seconds=host.clock.offset)
                observation['rearmed_same_target'] = True
                observation['clock_outside_measured_roots'] = external
                observation['after'] = boundaries(raw, fixture, prepared)
                harness.check(observation['after'].get('before_intent_creation') is True,
                    'machine requester raw-created dispatch precondition unavailable')
        result = original_api(host, method, path, *args, **kwargs)
        if selected:
            observation['actual_status'] = result[0] if type(result[0]) is int and 100 <= result[0] <= 599 else None
            body = result[1] if type(result[1]) is dict else {}
            code = body.get('code')
            observation['actual_code'] = code if type(code) is str and code in CODES else 'other'
            consent = body.get('consent')
            state = consent.get('state') if type(consent) is dict else None
            observation['consent_state'] = state if type(state) is str and state in STATES else 'unavailable'
        return result

    @wraps(original_op)
    def op(fixture, action, prepared=None, *args, **kwargs):
        nonlocal active
        line = sys._getframe(1).f_lineno
        observation = {'phase': phases.get(line, 'unknown'), 'action': action if action in {'lookup', 'prepare', 'approve'} else 'other',
            'expected_status': kwargs.get('status', 200), 'expected_code': kwargs.get('code'),
            'fixture': fixture, 'prepared': prepared, 'began': time.monotonic()}
        previous, active = active, observation
        try:
            result = original_op(fixture, action, prepared, *args, **kwargs)
            if observation.get('rearmed_same_target'):
                report(observation, failed=False, precondition_only=True)
            return result
        except BaseException:
            report(observation, failed=True)
            raise  # Preserve the original failure object and all suite handling.
        finally:
            active = previous

    namespace['op'], harness.Host.api = op, api
    return original_op, original_api


def report(observation, *, failed, precondition_only=False):
    try:
        result = {'phase': observation['phase'], 'action': observation['action'], 'failed_operation': failed,
                  'precondition_only': precondition_only}
        for key in ('actual_status', 'dispatch_after_op_ms', 'rearmed_same_target', 'clock_outside_measured_roots',
                    'actual_code', 'consent_state', 'before', 'after'):
            if key in observation:
                result[key] = observation[key]
        value = observation.get('expected_status')
        result['expected_status'] = value if type(value) is int and 100 <= value <= 599 else None
        value = observation.get('expected_code')
        result['expected_code'] = value if type(value) is str and value in CODES else 'other'
        emit(result)
    except BaseException:
        pass


def observed_case(original, phases):
    @wraps(original)
    def case(suite, *args, **kwargs):
        decorator = original(suite, *args, **kwargs)
        if (args[0] if args else kwargs.get('name')) != CASE:
            return decorator
        def register(function):
            namespace = function.__globals__
            original_op, original_api = hooks(namespace, phases)
            try:
                return decorator(function)
            finally:
                namespace['op'], harness.Host.api = original_op, original_api
        return register
    return case


def main():
    subject = Path(__file__).with_name('machine_requester_consent.py')
    source = subject.read_bytes()
    phases = call_phases(source)
    emit({'phase': 'source_observation', 'frozen_source_sha256': hashlib.sha256(source).hexdigest()})
    argv, original = sys.argv, harness.Suite.case
    try:
        sys.argv = [str(subject), *argv[1:]]
        harness.Suite.case = observed_case(original, phases)
        return runpy.run_path(str(subject), run_name='__main__')
    finally:
        sys.argv, harness.Suite.case = argv, original


if __name__ == '__main__':
    main()
