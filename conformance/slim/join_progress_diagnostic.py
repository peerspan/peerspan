#!/usr/bin/env python3
"""Run unchanged join_onboarding with captured-only progress failure metadata.

Section49/2d604a3: observe only the targeted case's direct records/private_files
returns. Every complete result, argument, exception, comparison, timeout and
suite verdict remains unchanged. No extra host/API/database/files/network work,
wait, clock, mutation, driver or retry. First/latest snapshots identify changed
categories, never their actor. Raw rows/values/IDs/keys/packets/paths stay private.
"""
from functools import wraps
import json
from pathlib import Path
import runpy
import sys

import harness


CASE = 'published_progress_exact_read_only_snapshot_cli_bounds_and_owner_routes'
TABLES = set('networks network_members peers policy_edits agents sessions adapter_connections adapter_credentials events dec_contexts dec_objects dec_admissions dec_restrictions dec_activations dec_heads dec_highwater dec_signers dec_clock dec_intents dec_pending dec_frames dec_operations dec_outbox dec_migrations dec_contacts dec_helpers identity sqlite_sequence grants received_messages outbound_messages deliveries received_replies outbound_replies adapter_routes network_statements access_blocks received_tasks task_events outbound_tasks outbound_task_events task_deliveries task_update_notifications artifact_files task_artifacts task_children policy_deliveries adapter_outbound directory_sends tool_servers tool_values capabilities source_access received_calls outbound_calls adapter_calls call_update_notifications link_device_keys link_pending link_frames link_operations link_objects link_features link_signers link_highwater call_approvals approval_notices builtin_sources oauth_clients oauth_credentials onboarding_project_flows onboarding_adapter_flows onboarding_invitation_flows onboarding_join_flows'.split())
FIELDS = set('format roles mode migration_proposal_id expected_network_id expected_context_id expected_person_public_key contact_invitation_base64 descriptor_base64 host_public_key device_public_key request_nonce request_packet_base64 owner_packet_base64 selection_packet_base64 administrator_packet_base64 owner_finalization_packet_base64 commit_packet_base64 outcome_packet_base64 catalog_base64 owner_offer_id selection_id administrator_offer_id owner_finalization_id manifest_id activation_id selection_approved commit_approved owner_intent_id administrator_intent_id selection_intent_id commit_intent_id terminal carrier_endpoints outbound_frames stage_at frame_base64 operation_id approved approved_at review_base64 provider root_state_id person_public_key scopes not_after created_at expires_at templates signatures completed result_base64 largest_local_time kind body_base64 proof_ids attempts next_attempt_at last_error_code last_error_detail message_hashes conflicted contacts_base64 applied_at'.split())
# Public storage8/9/11 and intent/clock schema: private primary keys pair rows;
# output contains only these literal column/record-field names and counts.
LAYOUTS = {
    'dec_pending': ((0,), 2, ('request_id', 'deadline', 'record', 'secret', 'terminal_read_cap')),
    'dec_frames': ((0, 1, 2, 3), 4, ('request_id', 'role', 'writer_key', 'frame_id', 'record')),
    'dec_outbox': ((0,), 4, ('delivery_id', 'network_id', 'context_id', 'target_key', 'record')),
    'dec_contacts': ((0, 1, 2), 4, ('network_id', 'context_id', 'host_key', 'sequence', 'record')),
    'dec_intents': ((0,), 4, ('intent_id', 'network_id', 'context_id', 'kind', 'record', 'secret')),
    'dec_clock': ((0,), 1, ('network_id', 'record')),
}


def table_summary(name, before, after):
    result = {'table': name if name in TABLES else 'unknown',
              'before_count': len(before), 'after_count': len(after),
              'changed_columns': [], 'changed_record_fields': []}
    if name not in LAYOUTS:
        result['record_layout_unknown'] = True
        return result
    keys, record_index, columns = LAYOUTS[name]
    if any(type(row) is not tuple or len(row) != len(columns) for row in (*before, *after)):
        result['record_layout_unknown'] = True
        return result
    old = {tuple(row[i] for i in keys): row for row in before}
    new = {tuple(row[i] for i in keys): row for row in after}
    changed_columns, fields = set(), set()
    unavailable = len(old) != len(before) or len(new) != len(after)
    for key in old.keys() | new.keys():
        a, b = old.get(key), new.get(key)
        if a == b:
            continue
        for index, column in enumerate(columns):
            if a is None or b is None or a[index] != b[index]:
                changed_columns.add(column)
        try:
            aa = {} if a is None else json.loads(a[record_index])
            bb = {} if b is None else json.loads(b[record_index])
            if type(aa) is not dict or type(bb) is not dict:
                raise ValueError
            for field in aa.keys() | bb.keys():
                if field not in aa or field not in bb or aa[field] != bb[field]:
                    fields.add(field if field in FIELDS else 'unknown')
        except BaseException:
            unavailable = True
    result.update(changed_columns=sorted(changed_columns), changed_record_fields=sorted(fields),
                  record_layout_unknown=unavailable)
    return result


def file_summary(before, after):
    changed = [name for name in before.keys() | after.keys() if before.get(name) != after.get(name)]
    result = {key: False for key in ('database', 'journal', 'socket', 'original_key', 'other')}
    for name in changed:
        leaf = str(name).rsplit('/', 1)[-1]
        if leaf.endswith('.db'):
            category = 'database'
        elif leaf.endswith(('-journal', '-wal', '-shm')):
            category = 'journal'
        elif leaf.endswith('.sock'):
            category = 'socket'
        elif leaf in {'person_ed25519', 'person_ed25519.pub'}:
            category = 'original_key'
        else:
            category = 'other'
        result[category] = True
    return result


class Observer:
    def __init__(self, code):
        self.code = code
        self.databases, self.files = {}, {}

    def capture(self, kind, argument, value):
        if kind == 'records':
            key = id(argument)
            if key not in self.databases:
                self.databases[key] = [argument, value, value, 1]
            else:
                self.databases[key][2] = value
                self.databases[key][3] += 1
        else:
            if argument not in self.files:
                self.files[argument] = [value, value, 1]
            else:
                self.files[argument][1] = value
                self.files[argument][2] += 1

    def report(self):
        try:
            databases, files = [], []
            for host, before, after, count in self.databases.values():
                changed = [name for name in before.keys() | after.keys() if before.get(name) != after.get(name)]
                databases.append({'capture_count': count, 'schema_changed': before.get('$schema') != after.get('$schema'),
                    'version_changed': before.get('$version') != after.get('$version'),
                    'tables': [table_summary(name, before.get(name, ()), after.get(name, ()))
                               for name in sorted(changed) if name not in {'$schema', '$version'}]})
                for role, root in (('state', host.state), ('home', host.home)):
                    pair = self.files.get(root)
                    if pair is not None:
                        files.append({'category': role, 'capture_count': pair[2],
                                      'changed': pair[0] != pair[1] if pair[2] > 1 else None,
                                      'file_categories': file_summary(pair[0], pair[1]) if pair[2] > 1 else None})
            print('join_progress_failure_public=' + json.dumps({'databases': databases, 'files': files}, sort_keys=True), flush=True)
        except BaseException:
            try:
                print('join_progress_diagnostic_unavailable', flush=True)
            except BaseException:
                pass  # The original case exception/verdict is authoritative.


def observed_capture(original, observer, kind):
    @wraps(original)
    def capture(*args, **kwargs):
        result = original(*args, **kwargs)
        try:
            if sys._getframe(1).f_code is observer.code:
                argument = args[0] if args else kwargs['h' if kind == 'records' else 'root']
                observer.capture(kind, argument, result)
        except BaseException:
            pass
        return result
    return capture


def observed_case(original):
    @wraps(original)
    def case(suite, *args, **kwargs):
        decorator = original(suite, *args, **kwargs)
        name = args[0] if args else kwargs.get('name')
        if name != CASE:
            return decorator
        def register(function):
            namespace = function.__globals__
            saved = {key: namespace[key] for key in ('records', 'private_files')}
            observer = Observer(function.__code__)
            @wraps(function)
            def run():
                try:
                    return function()
                except BaseException:
                    try:
                        observer.report()
                    except BaseException:
                        pass
                    raise
            try:
                namespace['records'] = observed_capture(saved['records'], observer, 'records')
                namespace['private_files'] = observed_capture(saved['private_files'], observer, 'private_files')
                return decorator(run)
            finally:
                namespace.update(saved)
        return register
    return case


def main():
    original = harness.Suite.case
    try:
        harness.Suite.case = observed_case(original)
        return runpy.run_path(str(Path(__file__).with_name('join_onboarding.py')), run_name='__main__')
    finally:
        harness.Suite.case = original


if __name__ == '__main__':
    main()
