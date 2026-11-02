#!/usr/bin/env python3
"""Collect sanitized installed-acceptance evidence, including partial failures.

Only explicit receipt/trace fields and named source, archive and log files are
read. Raw logs, API bodies, screens, state, backups, keys and configuration are
never copied. Collection exits zero for missing/invalid/partial gate evidence;
the original CI gate verdict must remain a separate required check.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat


HISTORIES = ('old23', 'main24', 'feature27')
SUITES = ('teammate', 'machine')
SOURCES = ('acceptance_receipts.py', 'installed_terminal.py', 'installed_upgrade.py',
           'installed_participants.py', 'installed_participant_support.py',
           'onboarding_bundle.py', 'requirements-terminal.txt', 'slim/harness.py', 'slim/counted_peer.py')
TERMINAL_PHASES = {'initialization', 'installed_host_start', 'real_pending_review', 'pending_daemon_restart',
    'real_human_approval', 'attached_restart_invalidation', 'failed_and_declined_review', 'real_lost_decision_reply'}
PARTICIPANT_PHASES = {'startup', 'distinct_people_and_attached_projects',
    'pinned_guided_invitation_recipient_review_and_automatic_return',
    'second_invitation_same_endpoint_distinct_request_and_destination', 'exact_original_owner_consent_and_signing',
    'incoming_proof_checkpoint_and_exact_administrator_consent',
    'original_finalization_then_separate_requester_commit_completion',
    'membership_denied_then_guided_access_then_owner_withdrawal', 'unavailable_first_contact_private_manual_fallback',
    'machine_guided_automatic_return_owner_consent_and_automatic_F', 'machine_one_lost_completion_and_lookup_recovery',
    'machine_retained_finite_authority_and_separate_readiness', 'suite_deadline', 'worker_exit'}
FAILURES = {'Failure', 'CheckFailure', 'AssertionError', 'TimeoutExpired', 'WorkerExit', 'OSError',
    'ValueError', 'KeyError', 'TypeError', 'FileNotFoundError', 'PermissionError', 'ConnectionError',
    'ConnectionRefusedError', 'ConnectionResetError', 'BrokenPipeError', 'TimeoutError', 'JSONDecodeError'}
PROMPTS = {'style', 'key', 'security', 'trust'}


def boolean(value):
    return type(value) is bool


def count(value):
    return type(value) is int and 0 <= value <= 1000000


def timing(value):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 3600


def digest(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def enum(values):
    return lambda value: type(value) is str and value in values


def fields(value, schema):
    """Unknown fields/invalid values are counted, never echoed."""
    if type(value) is not dict:
        return {}, 1
    clean, invalid = {}, len(set(value) - set(schema))
    for key, validator in schema.items():
        if key in value:
            if validator(value[key]):
                clean[key] = value[key]
            else:
                invalid += 1
    return clean, invalid


def input_file(root, relative):
    """No symlink traversal into an unrelated file with an allowed filename."""
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or '..' in parts:
        raise ValueError('invalid relative input')
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    mode = os.fstat(descriptor)
    if not stat.S_ISREG(mode.st_mode) or mode.st_size > 2 * 1024 ** 3:
        os.close(descriptor)
        raise ValueError('input is not a bounded regular file')
    return os.fdopen(descriptor, 'rb')


def file_hash(root, relative):
    try:
        with input_file(root, relative) as stream:
            return {'status': 'retained_hash', 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}
    except FileNotFoundError:
        return {'status': 'missing'}
    except (OSError, ValueError):
        return {'status': 'unreadable_or_invalid'}


def read_json(root, relative):
    try:
        with input_file(root, relative) as stream:
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            return None, 'invalid'
        value = json.loads(raw, parse_constant=lambda _value: None, object_pairs_hook=unique_object)
        return value, 'present'
    except FileNotFoundError:
        return None, 'missing'
    except (OSError, ValueError, UnicodeError, RecursionError):
        return None, 'invalid'


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate field')
        result[key] = value
    return result


def hashed_detail(value):
    return hashlib.sha256(value.encode('utf-8', errors='surrogatepass')).hexdigest() if type(value) is str else None


def stamp(result, status, invalid, passed=None):
    result['metadata_status'] = 'partial' if status == 'present' and invalid else status
    result['invalid_or_unknown_fields'] = invalid
    result['gate_result'] = 'passed' if passed is True else 'failed' if passed is False else 'unreported'
    return result


def terminal(root):
    value, status = read_json(root, 'terminal-failure.json')
    clean, invalid = fields(value, {'phase': enum(TERMINAL_PHASES),
        'category': enum({'contract', 'local_input_or_terminal'}), 'check': lambda x: type(x) is str and len(x) <= 65536})
    detail = clean.pop('check', None)
    if detail is not None:
        clean['check_sha256'] = hashed_detail(detail)
    valid_failure = len(clean) == 3
    if status == 'present':
        invalid += 3 - len(clean)
    result = stamp(clean, status, invalid if status == 'present' else 0, False if valid_failure else None)
    # No failure file is not proof that the terminal gate passed.
    result['logs'] = {label: file_hash(root, name) for label, name in (
        ('daemon', 'private daemon.log'), ('normal_terminal', 'normal project.pty'),
        ('declined_terminal', 'declined project.pty'), ('lost_reply_terminal', 'lost reply project.pty'))}
    result['startup_traces'] = []
    names = ['normal project.startup.jsonl', 'declined project.startup.jsonl', 'lost reply project.startup.jsonl']
    try:
        names += sorted(p.name for p in root.iterdir()
            if re.fullmatch(r'public[A-Za-z0-9_.-]{0,80}\.startup\.jsonl', p.name))[:16]
    except OSError:
        pass
    for name in names:
        result['startup_traces'].append(startup_trace(root, name))
    return result


def startup_trace(root, name):
    result = file_hash(root, name)
    if result['status'] != 'retained_hash':
        return result
    events, invalid, last = [], 0, -1
    try:
        with input_file(root, name) as stream:
            raw = stream.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            raise ValueError('trace size')
        lines = raw.splitlines()
        if not lines or len(lines) > 256:
            raise ValueError('trace count')
        schema = {'event': enum({'view', 'send', 'ready', 'deadline'}),
            'matched_prompt': lambda x: type(x) is list and len(x) <= 4 and all(enum(PROMPTS)(v) for v in x) and len(set(x)) == len(x),
            'active_prompt': lambda x: x is None or enum(PROMPTS)(x),
            'active_phase': lambda x: x is None or enum({'select', 'confirm'})(x),
            'rendered_selected_yes': boolean, 'sent': enum({'none', 'confirm', 'arrow_up', 'arrow_down'}),
            'elapsed_ms': lambda x: type(x) is int and 0 <= x <= 60000}
        for line in lines:
            event = json.loads(line, object_pairs_hook=unique_object)
            clean, bad = fields(event, schema)
            if bad or len(clean) != len(schema) or clean['elapsed_ms'] < last:
                invalid += 1
                continue
            last = clean['elapsed_ms']
            events.append(clean)
    except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
        invalid += 1
    # Partial traces retain only individually validated closed events.
    return {**result, 'status': 'partial' if invalid else 'validated', 'invalid_events': invalid, 'events': events}


HISTORY_SCHEMA = {'original_schema': lambda x: type(x) is int and x in (23, 24, 27),
    'upgraded_schema': lambda x: type(x) is int and x == 28,
    **{key: boolean for key in ('backup_mode_hash_match', 'public_history_retained', 'pending_review_retained',
        'new_review', 'old_binary_refused_without_db_mutation', 'complete_restore_reopened')}, 'backup_manifest_sha256': digest}
ARTIFACT_SCHEMA = {key: digest for key in ('host_sha256', 'probe_sha256', 'archive_sha256')}
SOURCE_SCHEMA = {Path(name).name: digest for name in SOURCES}
EVIDENCE_SCHEMA = {**{key: count for key in ('host_fixtures', 'physical_machines', 'distinct_people',
    'invitations_same_endpoint', 'distinct_destinations', 'automatic_returns', 'main_applications', 'receiver_denials',
    'receiver_appends', 'guided_access_grants', 'explicit_withdrawals', 'copied_original_keys', 'finite_device_scopes',
    'binding_scopes', 'completion_invocations', 'new_agent_grants')},
    **{key: boolean for key in ('unavailable_manual_fallback', 'adapter_connection', 'incoming_acknowledgment',
    'receiver_message_receipt', 'outbound_peer_observation', 'model_receipt', 'distinct_host_keys', 'distinct_device_keys',
    'lost_completion_recovered')}}
SUITE_SCHEMA = {'passed': boolean, 'suite': enum(SUITES), 'stage': enum(PARTICIPANT_PHASES),
    'failure_type': enum(FAILURES), 'seconds': timing, 'suite_log_sha256': digest, 'failure_log_sha256': digest,
    'daemon_log_sha256': lambda x: type(x) is list and len(x) <= 8 and all(digest(v) for v in x)}


def upgrade(root):
    value, status = read_json(root, 'receipt.json')
    schema = {'suite': enum({'installed_upgrade'}), 'contract': enum({'guided-final-acceptance section1'}),
        **{key: digest for key in ('source_sha256', 'archive_sha256', 'installed_binary_sha256', 'log_manifest_sha256')},
        'passed': boolean, 'elapsed_seconds': timing, 'failure_stage': enum({'input_artifacts', *HISTORIES})}
    clean, invalid = fields(value, {**schema, 'histories': lambda x: type(x) is dict,
        'old_binary_sha256': lambda x: type(x) is dict, 'failure': lambda x: type(x) is str and len(x) <= 65536})
    failure = clean.pop('failure', None)
    if failure is not None:
        clean['failure_sha256'] = hashed_detail(failure)
    for key, sub_schema in (('old_binary_sha256', {name: digest for name in HISTORIES}),):
        if key in clean:
            clean[key], bad = fields(clean[key], sub_schema)
            invalid += bad
    histories = clean.pop('histories', {})
    clean['histories'] = {}
    invalid += len(set(histories) - set(HISTORIES))
    for name in HISTORIES:
        if name in histories:
            clean['histories'][name], bad = fields(histories[name], HISTORY_SCHEMA)
            invalid += bad + len(HISTORY_SCHEMA) - len(clean['histories'][name])
    if status == 'present':
        invalid += len(set(schema) - {'failure_stage'} - set(clean)) + (len(clean['histories']) != 3)
    clean['logs'] = {'manifest': file_hash(root, 'log hashes.json')}
    for name in HISTORIES:
        for suffix, role in (('', 'original'), (' restored', 'restored')):
            directory = root / (name + suffix)
            logs = {}
            try:
                filenames = sorted(p.name for p in directory.iterdir() if re.fullmatch(
                    r'(?:daemon-[0-9]{3,6}\.log|(?:api|cli)-[0-9]{3,6}\.json)', p.name))[:512]
            except OSError:
                filenames = []
            for filename in filenames:
                # Only these explicit operational log names, at this one level.
                logs[filename] = file_hash(root, name + suffix + '/' + filename)
            clean['logs'][name + '_' + role] = logs
    return stamp(clean, status, invalid if status == 'present' else 0, clean.get('passed'))


def participants(root):
    value, status = read_json(root, 'receipt.json')
    clean, invalid = fields(value, {'artifacts': lambda x: type(x) is dict,
        'source_sha256': lambda x: type(x) is dict, 'suites': lambda x: type(x) is list and len(x) <= 2,
        'required_separate_gates': lambda x: type(x) is list and len(x) <= 4 and all(enum(
            {'unchanged_negative_suites', 'native_terminal', 'upgrade', 'actual_model_receipt'})(v) for v in x),
        'topology': enum({'two isolated host fixtures on one machine; direct loopback TCP/UDP; no helpers/coordinator'})})
    for key, schema in (('artifacts', ARTIFACT_SCHEMA), ('source_sha256', SOURCE_SCHEMA)):
        if key in clean:
            clean[key], bad = fields(clean[key], schema)
            invalid += bad
    source_suites = clean.pop('suites', [])
    if status == 'present':
        invalid += len({'artifacts', 'source_sha256', 'required_separate_gates', 'topology'} - set(clean))
    clean['suites'] = {}
    for name in SUITES:
        matches = [v for v in source_suites if type(v) is dict and v.get('suite') == name]
        raw, source_status = (matches[0], 'present') if len(matches) == 1 else read_json(root, name + '/outcome.json')
        record, bad = fields(raw, {**SUITE_SCHEMA, 'evidence': lambda x: type(x) is dict})
        if 'evidence' in record:
            record['evidence'], bad_evidence = fields(record['evidence'], EVIDENCE_SCHEMA)
            bad += bad_evidence
        if source_status == 'present':
            bad += len({'passed', 'suite', 'seconds'} - set(record))
            if record.get('passed') is True:
                bad += len({'host_fixtures', 'physical_machines', 'distinct_people', 'main_applications',
                    'adapter_connection', 'incoming_acknowledgment', 'outbound_peer_observation', 'model_receipt'}
                    - set(record.get('evidence', {})))
            elif record.get('passed') is False:
                bad += len({'stage', 'failure_type'} - set(record))
        record['logs'] = {label: file_hash(root, name + '/' + filename) for label, filename in (
            ('suite', 'suite.private.log'), ('failure', 'failure.private.txt'))}
        for host in (('inviter', 'teammate') if name == 'teammate' else ('existing', 'requester')):
            record['logs'][host] = file_hash(root, name + '/' + host + '/daemon.log')
        clean['suites'][name] = stamp(record, source_status, bad if source_status == 'present' else 0, record.get('passed'))
        invalid += bad + (len(matches) > 1)
    results = [v['gate_result'] for v in clean['suites'].values()]
    if status == 'present':
        invalid += any(result == 'unreported' for result in results)
    passed = False if 'failed' in results else True if results == ['passed', 'passed'] else None
    return stamp(clean, status, invalid if status == 'present' else 0, passed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('terminal-work', 'upgrade-work', 'participants-work', 'archive-dir', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    archives = []
    try:
        names = sorted(p.name for p in args.archive_dir.iterdir() if re.fullmatch(
            r'peerspan-(?:[A-Za-z0-9.+-]{1,100}-linux-(?:amd64|arm64)-rust|helper-[A-Za-z0-9.+-]{1,100}-linux-(?:amd64|arm64))\.tar\.gz', p.name))[:16]
        archives = [file_hash(args.archive_dir, name) for name in names]
    except OSError:
        pass
    report = {'format': 1, 'collection_only': True, 'original_gate_verdicts_unchanged': True,
        'complete_final_acceptance': False, 'terminal': terminal(args.terminal_work),
        'upgrade': upgrade(args.upgrade_work), 'participants': participants(args.participants_work),
        'archives': archives, 'archive_status': 'missing' if not archives else 'present'
            if all(v['status'] == 'retained_hash' for v in archives) else 'partial',
        'current_test_source_hashes': {name: file_hash(Path(__file__).parent, name) for name in SOURCES}}
    path = args.output / 'acceptance-receipt.json'
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        json.dump(report, output, sort_keys=True, indent=2, allow_nan=False)
        output.write('\n')
    print('Sanitized acceptance receipt collected; original gate verdicts unchanged.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
