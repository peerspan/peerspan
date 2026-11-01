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


FIELDS = tuple('network_id context_id person_public_key host_public_key device_public_key scopes not_after '
               'root_state_id owner_offer_id selection_id administrator_offer_id person_lease_id host_lease_id '
               'binding_lease_id device_lease_id'.split())
REFERENCE_FIELDS = ('person_lease_id', 'host_lease_id', 'binding_lease_id', 'device_lease_id')
ENGLISH_LITERALS = (
    ('provider_root_changed', ('link signing changed the approved provider/root',)),
    ('context_changed', ('linking context changed',)),
    ('original_key_format_changed', ('original signing key/format changed',)),
    ('key_mismatch', ('keep the exact reviewed original/root key on its own machine',)),
    ('local_timeout', ('local host daemon request timed out',)),
    ('missing_file', ('No such file or directory',)), ('denied_file', ('Permission denied',)),
    ('invalid_slot', ('invalid signing intent/slot', 'invalid slot')),
    ('invalid_batch', ('invalid signing batch',)), ('too_many_slots', ('too many ready signature slots',)),
    ('duplicate_slots', ('unordered/duplicate signature slots',)), ('mixed_intents', ('mixed signing intentions',)),
    ('dependency_batches', ('too many dependency signature batches; resume the exact retained request',)),
    ('signing_response_changed', ('signing response changes request',)), ('typed_object_changed', ('typed object ID changed',)),
    ('typed_role_not_ready', ('typed signature role is not ready',)),
    ('typed_message_changed', ('typed signature message/key/format differs',)),
    ('packet_role_unreviewed', ('unreviewed packet signing role',)), ('grant_role_unreviewed', ('unreviewed grant signing role',)),
    ('packet_target_changed', ('packet changes reviewed ceremony/key/role',)),
    ('packet_issuer_changed', ('root packet changes reviewed issuer',)), ('packet_signer_changed', ('packet changes original signer',)),
    ('grant_terms_changed', ('grant changes reviewed operation/finite terms',)),
    ('grant_person_changed', ('grant changes target person',)), ('grant_host_changed', ('grant changes target host',)),
    ('grant_powers_changed', ('grant changes reviewed device/powers',)), ('typed_parents_invalid', ('invalid typed grant parents',)),
    ('signing_window_expired', ('link signing window expired; retain and inspect this request',)),
)


def classify_english(stderr):
    # Expand trusted finite fields, never capture or emit any supplied suffix.
    patterns = (
        ('link signing changed reviewed {}', 'reviewed_field_changed', FIELDS),
        ('link signing changed the fixed {}', 'fixed_field_changed', FIELDS),
        ('pending self-consent changed provider {}', 'pending_provider_changed',
         ('kind', 'person_public_key', 'host_public_key', 'device_public_key')),
        ('packet changes reviewed {}', 'packet_field_changed', (*FIELDS, 'request_packet_id')),
        ('grant differs from the concrete reviewed {}', 'grant_reference_changed', REFERENCE_FIELDS),
        ('grant changes reviewed parent {}', 'grant_parent_changed', REFERENCE_FIELDS),
    )
    for template, category, fields in patterns:
        for field in fields:
            if template.format(field) in stderr:
                return category, field
    for category, literals in ENGLISH_LITERALS:
        if any(literal in stderr for literal in literals):
            return category, 'unknown'
    return 'unknown', 'unknown'


def exception_kind(error):
    for kind, cls in (('timeout', subprocess.TimeoutExpired), ('host_failure', harness.Failure),
                      ('os_error', OSError), ('system_exit', SystemExit), ('keyboard_interrupt', KeyboardInterrupt)):
        if isinstance(error, cls):
            return kind
    return 'other'


def metadata(result=None, error=None):
    summary = {'exit_code': 'unknown', 'exception_kind': exception_kind(error) if error is not None else 'none',
               'stderr_categories': [], 'stdout_object': False, 'state': 'unknown',
               'owner_present': 'unknown', 'selection_present': 'unknown', 'finalization_present': 'unknown',
               'english_class': 'unknown', 'english_field': 'unknown'}
    if result is None:
        return summary
    summary['exit_code'] = result.code if type(result.code) is int else 'unknown'
    summary['english_class'], summary['english_field'] = classify_english(result.stderr)
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
