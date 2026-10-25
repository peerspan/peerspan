#!/usr/bin/env python3
"""Independent schema-7 complete-evidence backup and atomic restore checks.

Public routes create all evidence. Faults discover opaque SQL columns and match
known public values; no implementation layout or module is read. Saved evidence
is checked at its original time, without claiming present signing authority.
"""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile

from linking_activations import payload, proof, semantic_id, shift
from linking_coordinator import Suite as CoordinatorSuite
from linking_imports import Suite as ImportSuite
from linking_mailboxes import Runtime, Suite as RuntimeSuite, need
from linking_readers import b64, lines, unb64, wire


def quoted(name):
    return '"' + name.replace('"', '""') + '"'


def rows(db, table=None):
    tables = ([table] if table else [row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")])
    for name in tables:
        cursor = db.execute('SELECT * FROM ' + quoted(name))
        columns = [column[0] for column in cursor.description]
        for row in cursor.fetchall():
            yield name, columns, row


def predicate(columns):
    return ' AND '.join(quoted(column) + ' IS ?' for column in columns)


def raw_cell(value):
    return value.encode() if isinstance(value, str) else bytes(value) if isinstance(value, bytes) else None


def delete_matching(path, table, value):
    with sqlite3.connect(path) as db:
        found = [entry for entry in rows(db, table) if value in entry[2]]
        need(len(found) == 1, 'one opaque row matches the exact public identity', table, value, len(found))
        name, columns, row = found[0]
        need(db.execute('DELETE FROM ' + quoted(name) + ' WHERE ' + predicate(columns), row).rowcount == 1,
             'remove exactly one required evidence row')


def change_body(path, entry):
    original = unb64(entry['body_base64'])
    with sqlite3.connect(path) as db:
        found = [(name, columns, row, index) for name, columns, row in rows(db, 'link_objects')
                 for index, cell in enumerate(row) if raw_cell(cell) == original]
        need(len(found) == 1, 'exact original public body found once before corruption')
        name, columns, row, index = found[0]
        changed = b' ' + original  # Valid equivalent JSON; the exact transport PF must change.
        value = changed.decode() if isinstance(row[index], str) else changed
        need(db.execute('UPDATE ' + quoted(name) + ' SET ' + quoted(columns[index]) + '=? WHERE ' +
                        predicate(columns), (value, *row)).rowcount == 1, 'mutate one original public body')


def replace_exact_proof(path, original, replacement):
    """Change one public PF and body together, preserving their byte-derived ID.

    This isolates provenance verification from the separate PF-integrity gate.
    """
    old, new = unb64(original['body_base64']), unb64(replacement['body_base64'])
    with sqlite3.connect(path) as db:
        found = [(name, columns, row) for name, columns, row in rows(db, 'link_objects')
                 if original['id'] in row and any(raw_cell(cell) == old for cell in row)]
        need(len(found) == 1, 'one exact public proof row matches before provenance substitution')
        name, columns, row = found[0]
        changed = list(row)
        indexes = []
        for index, cell in enumerate(row):
            if cell == original['id']:
                changed[index] = replacement['id']
                indexes.append(index)
            elif raw_cell(cell) == old:
                changed[index] = new.decode() if isinstance(cell, str) else new
                indexes.append(index)
        need(len(indexes) == 2, 'replace only exact public transport identity and original body')
        update = ','.join(quoted(columns[index]) + '=?' for index in indexes)
        need(db.execute('UPDATE ' + quoted(name) + ' SET ' + update + ' WHERE ' + predicate(columns),
                        (*[changed[index] for index in indexes], *row)).rowcount == 1,
             'one valid-SQLite public provenance object is substituted')


def append_exact_proof(path, template, added):
    """Add a public alias while preserving every originally referenced proof."""
    old, new = unb64(template['body_base64']), unb64(added['body_base64'])
    need(template['kind'] == added['kind'], 'alias fixture preserves the public catalog kind')
    with sqlite3.connect(path) as db:
        found = [(columns, row) for _, columns, row in rows(db, 'link_objects')
                 if template['id'] in row and any(raw_cell(cell) == old for cell in row)]
        need(len(found) == 1, 'one exact public proof row supplies only the opaque SQL representation')
        columns, row = found[0]
        changed = [added['id'] if cell == template['id'] else
                   new.decode() if isinstance(cell, str) and raw_cell(cell) == old else
                   new if raw_cell(cell) == old else cell for cell in row]
        need(sum(a != b for a, b in zip(row, changed)) == 2, 'new alias changes only public identity and body')
        db.execute('INSERT INTO link_objects (' + ','.join(quoted(column) for column in columns) + ') VALUES (' +
                   ','.join('?' for _ in columns) + ')', changed)


def replace_saved_public(path, original, replacement, container_fields=None):
    """Match exact public JSON, including Base64 cells, without naming private fields.

    A None replacement deletes the matching outcome row instead of its value.
    """
    def replace(value):
        if value == original:
            return copy.deepcopy(replacement), 1
        if isinstance(value, dict):
            result, count = {}, 0
            for key, child in value.items():
                result[key], number = replace(child)
                count += number
            return result, count
        if isinstance(value, list):
            result, count = [], 0
            for child in value:
                changed, number = replace(child)
                result.append(changed)
                count += number
            return result, count
        if isinstance(value, str):
            try:
                decoded = json.loads(unb64(value))
            except (ValueError, UnicodeDecodeError):
                return value, 0
            if decoded == original:
                return b64(wire(replacement)), 1
        return value, 0

    with sqlite3.connect(path) as db:
        found = []
        for name, columns, row in rows(db):
            for index, cell in enumerate(row):
                raw = raw_cell(cell)
                if raw is None:
                    continue
                try:
                    value = json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    continue
                if container_fields is not None and (not isinstance(value, dict) or set(value) != container_fields):
                    continue
                changed, count = replace(value)
                if count:
                    found.append((name, columns, row, index, changed, count))
        need(len(found) == 1 and found[0][-1] == 1,
             'one exact saved public object matches the known public bytes', len(found))
        name, columns, row, index, changed, _ = found[0]
        if replacement is None:
            need(db.execute('DELETE FROM ' + quoted(name) + ' WHERE ' + predicate(columns), row).rowcount == 1,
                 'remove only the matched outcome row')
            return
        encoded = wire(changed)
        value = encoded.decode() if isinstance(row[index], str) else encoded
        need(db.execute('UPDATE ' + quoted(name) + ' SET ' + quoted(columns[index]) + '=? WHERE ' +
                        predicate(columns), (value, *row)).rowcount == 1, 'change only the saved public snapshot')


class Suite(RuntimeSuite):
    author = CoordinatorSuite.author
    authorization = ImportSuite.authorization
    import_body = staticmethod(ImportSuite.body)

    def __init__(self, args, root):
        super().__init__(args, root)
        self.corruptions = 0

    def backup(self, runtime, name):
        path = runtime.root / (name + '.backup')
        result = runtime.command('backup', str(path))
        need(result.returncode == 0, 'complete public evidence backup succeeds', result.stderr)
        return path

    def rejected(self, runtime, original, name, mutate):
        corrupted = runtime.root / (name + '.backup')
        shutil.copy2(original, corrupted)
        mutate(corrupted)
        with sqlite3.connect(corrupted) as db:
            need(db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok', 'fault leaves valid SQLite, not a corrupt file', name)
        target = runtime.root / ('target-' + name)
        restored = runtime.command('restore', str(original), state=target)
        need(restored.returncode == 0, 'positive source restores before replacement fault', name, restored.stderr)
        before = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in target.iterdir() if path.is_file()}
        rejected = runtime.command('restore', '--replace', str(corrupted), state=target)
        after = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in target.iterdir() if path.is_file()}
        need(rejected.returncode != 0 and before == after,
             'incomplete saved evidence refuses before replacing any target file', name, rejected.returncode, rejected.stderr)
        self.corruptions += 1
        print('PASS corruption/' + name, flush=True)

    def operation_evidence(self, runtime):
        a = self.author(runtime)
        a.activate()
        activation = a.rebind(label='backup/local-operation')
        result = a.check_result(a.call('POST', '/' + a.network + '/link-operations',
                                a.operation_body(activation), host='host_b'), activation)
        current = a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b'))
        backup = self.backup(runtime, 'local-operation')
        activation_id = proof('activation', activation)['id']
        feature_entry = next(entry for entry in current['catalog']['objects'] if entry['kind'] == 'feature')
        # A result includes exact public dependencies as well as its own activation.
        dependency = next(entry for entry in payload(result)['catalog']['objects']
                          if entry['kind'] not in ('activation', 'feature'))
        for name, table, identity in (
                ('operation_activation_missing', 'link_objects', activation_id),
                ('operation_result_dependency_missing', 'link_objects', dependency['id']),
                ('operation_outcome_missing', 'link_operations', activation['request']['request_id']),
                ('feature_proof_missing', 'link_objects', feature_entry['id']),
                ('feature_index_missing', 'link_features', a.network),
                ('proof_network_missing', 'networks', a.network)):
            self.rejected(runtime, backup, name, lambda path, table=table, identity=identity: delete_matching(path, table, identity))
        self.rejected(runtime, backup, 'proof_body_alias_without_new_pf', lambda path: change_body(path, dependency))
        forged = dict(result, authority_signature=b64(bytes(64)))
        self.rejected(runtime, backup, 'operation_result_signature_forged',
                      lambda path: replace_saved_public(path, result, forged))
        # Restoring complete evidence does not require the original actors to be live now.
        runtime.stop()
        state = runtime.root / 'complete-expired-state'
        need(runtime.command('restore', str(backup), state=state).returncode == 0, 'complete historical operation restores')
        late = Runtime(runtime.binary, runtime.root / 'complete-expired', initial=shift(runtime.now, 100 * 86400),
                       state=state, port=runtime.port)
        try:
            a.runtime = late
            need(a.call('GET', '/' + a.network + '/link-operations/' + activation['request']['request_id'], host='host_b')[2] == result,
                 'saved signed result stays retrievable after actor expiry')
        finally:
            self.requests += late.requests
            late.close()

    def redemption_evidence(self, runtime):
        a = self.author(runtime)
        a.activate()
        earlier = a.check_map(a.call('GET', '/' + a.network + '/map'))
        host = a.hosts['host_b'].b64
        redemption = a.redemption('member', 'skip', host=host, person=a.person, label='alice',
                                  invite=a.key('backup/redemption/invite'), expires=shift(runtime.now, 86400), joined=runtime.now)
        ack = a.ack(host)
        # An independently valid ack for another host lets wrong-host join
        # references fail for their subject, rather than only a missing PF.
        roster_ack = a.ack(a.hosts['host_a'].b64)
        body = {'redemption': redemption, 'catalog': a.with_proofs(a.catalog, [('join_ack', roster_ack)]),
                'address': '', 'candidates': [], 'join_ack': ack}
        result = a.check_map(a.call('POST', '/' + a.network + '/invite-redemptions', body, host='host_b'),
                             ('host_a', 'host_q', 'host_b'), status=201)
        backup = self.backup(runtime, 'completed-redemption')
        identity = proof('invite_redemption', redemption)['id']
        self.rejected(runtime, backup, 'redemption_global_pf_missing', lambda path: delete_matching(path, 'link_objects', identity))
        def omit_own_snapshot_pf(path):
            changed = copy.deepcopy(result)
            changed['catalog']['objects'] = [entry for entry in changed['catalog']['objects'] if entry['id'] != identity]
            replace_saved_public(path, result, changed)
        self.rejected(runtime, backup, 'redemption_snapshot_own_pf_missing', omit_own_snapshot_pf)
        self.rejected(runtime, backup, 'redemption_snapshot_replaced_with_earlier_map',
                      lambda path: replace_saved_public(path, result, earlier))
        self.rejected(runtime, backup, 'redemption_outcome_missing',
                      lambda path: replace_saved_public(path, result, None))
        self.member_references(runtime, backup, result)

        # Later restrictions do not rewrite or invalidate an exact old saved
        # receipt. Restore validates committed evidence at its original time.
        removed = a.signed_legacy('host_revocation',
                                 {'host_public_key': host, 'revoked_at': runtime.now}, a.root)
        a.check_map(a.call('POST', '/' + a.network + '/statements',
                          {'catalog': a.with_proofs(a.catalog, [('host_revocation', removed)])}))
        revoked = self.backup(runtime, 'completed-redemption-later-revoked')
        runtime.stop()
        state = runtime.root / 'redemption-expired-restored'
        restored = runtime.command('restore', str(revoked), state=state)
        need(restored.returncode == 0, 'complete revoked redemption snapshot restores', restored.stderr)
        late = Runtime(runtime.binary, runtime.root / 'redemption-expired', initial=shift(runtime.now, 100 * 86400),
                       state=state, port=runtime.port)
        try:
            a.runtime = late
            retry = a.call('POST', '/' + a.network + '/invite-redemptions', body, host='host_b')
            need(retry[0] == 200 and retry[2] == result,
                 'complete expired and later-revoked redemption returns its original saved receipt', retry)
        finally:
            self.requests += late.requests
            late.close()

    def member_references(self, runtime, backup, result):
        rows_by_host = {member['host_public_key']: member for member in result['members']}
        need(len(rows_by_host) == len(result['members']) >= 3, 'positive snapshot has three distinct canonical host rows')
        entries = result['catalog']['objects']
        feature = next(entry['id'] for entry in entries if entry['kind'] == 'feature')
        binding_rows = [member for member in result['members'] if member['binding_proof_id'] != '-']
        need(len(binding_rows) >= 2, 'positive snapshot has independently bound hosts')
        later = next(member for member in result['members'] if member['join_proof_id'] != '-')
        other = next(member for member in result['members'] if member['host_public_key'] != later['host_public_key'])
        wrong_ack = next(entry['id'] for entry in entries if entry['kind'] == 'join_ack' and
                         json.loads(unb64(entry['body_base64']))['host_public_key'] != later['host_public_key'])
        absent = 'pf_' + '0' * 64
        need(all(entry['id'] != absent for entry in entries), 'missing-reference identity absent from original snapshot')
        changes = []
        for field, target, wrong_host in (
                ('membership_proof_id', later, other['membership_proof_id']),
                ('binding_proof_id', binding_rows[0], binding_rows[1]['binding_proof_id']),
                ('join_proof_id', later, wrong_ack)):
            for label, reference in (('missing', absent), ('wrong_kind', feature), ('wrong_host', wrong_host)):
                changed = copy.deepcopy(result)
                row = next(member for member in changed['members'] if member['host_public_key'] == target['host_public_key'])
                row[field] = reference
                changes.append(('member_' + field.removesuffix('_proof_id') + '_' + label, changed))
        changed = copy.deepcopy(result)
        next(member for member in changed['members'] if member['host_public_key'] == later['host_public_key'])['join_proof_id'] = '-'
        changes.append(('member_nonroster_join_sentinel', changed))
        changed = copy.deepcopy(result)
        changed['members'].append(copy.deepcopy(changed['members'][0]))
        changed['members'].sort(key=lambda member: member['host_id'])
        changes.append(('member_duplicate_host_id', changed))
        for name, changed in changes:
            self.rejected(runtime, backup, name,
                          lambda path, changed=changed: replace_saved_public(path, result, changed))

    def registration_evidence(self, runtime):
        """Post-feature legacy registrations have no linking outcome to index.

        Their exact membership and feature acknowledgment remain mandatory
        historical evidence independently of the SQL registration itself.
        """
        a = self.author(runtime)
        a.activate()
        host_b = a.hosts['host_b'].b64
        invite = a.key('backup/direct-registration/invite')
        expires = shift(runtime.now, 1)
        membership = {'network_id': a.network, 'member': 'alice',
                      'invite_public_key': invite, 'invite_expires_at': expires,
                      'invite_signature': b64(a.signers[a.root].raw(lines(
                          'peerspan-invite-v1', a.network, invite, 'alice', expires))),
                      'host_public_key': host_b, 'joined_at': runtime.now,
                      'host_signature': b64(a.signers[invite].raw(lines(
                          'peerspan-member-v1', a.network, invite, host_b, runtime.now)))}
        admission = a.signed_legacy('host_admission', {'epoch': 0,
                                    'host_public_key': a.hosts['host_c'].b64,
                                    'member': 'alice', 'admitted_at': runtime.now}, a.root)
        registrations = [('invite', 'host_b', 'host_membership', 'membership', membership),
                         ('root_admission', 'host_c', 'host_admission', 'admission', admission)]
        for label, host, kind, field, signed in registrations:
            ack = a.ack(a.hosts[host].b64)
            reply = a.call('POST', '/' + a.network + '/members',
                           {field: signed, 'address': '', 'candidates': [],
                            'join_ack': ack, 'linking_version': 1}, host=host)
            expected_hosts = ('host_a', 'host_q', 'host_b') if host == 'host_b' else ('host_a', 'host_q', 'host_b', 'host_c')
            current = a.check_map(reply, expected_hosts, status=201)
            member = next(row for row in current['members'] if row['host_public_key'] == a.hosts[host].b64)
            membership_id = proof(kind, signed)['id']
            join_id = proof('join_ack', ack)['id']
            need(member['membership_proof_id'] == membership_id and member['join_proof_id'] == join_id,
                 'direct post-feature registration cites its exact independently signed membership and acknowledgment')
            backup = self.backup(runtime, 'direct-' + label)
            for missing, identity in (('membership', membership_id), ('join_ack', join_id)):
                self.rejected(runtime, backup, 'registration_' + label + '_' + missing + '_missing',
                              lambda path, identity=identity: delete_matching(path, 'link_objects', identity))
        # The invitation is genuinely elapsed at the injected clock. Complete
        # backup validation checks historical evidence, not current admission.
        runtime.advance(100 * 86400)
        complete = self.backup(runtime, 'direct-registrations-expired')
        target = runtime.root / 'direct-registrations-expired-restored'
        restored = runtime.command('restore', str(complete), state=target)
        need(restored.returncode == 0, 'complete direct registrations restore after invitation expiry', restored.stderr)

    def registration_issuer_provenance(self, runtime):
        a = self.author(runtime)
        a.activate()
        administrator = a.key('backup/post-feature-original-administrator')
        admitted = a.signed_legacy('person_admission', {'epoch': 0, 'person_public_key': administrator,
                                   'member': 'nora', 'admitted_at': runtime.now}, a.root)
        delegation = {'network_id': a.network, 'epoch': 0, 'person_public_key': administrator,
                      'delegated_at': runtime.now}
        delegation['signature'] = b64(a.signers[a.root].raw(lines('peerspan-admin-delegate-v1', a.network,
                                      0, administrator, runtime.now)))
        first = a.check_map(a.call('POST', '/' + a.network + '/statements',
                                  {'catalog': a.with_proofs(a.catalog, [('person_admission', admitted),
                                               ('admin_delegation', delegation)])}))
        a.catalog = first['catalog']
        host = a.hosts['host_b'].b64
        admission = a.record('host-admit-v1', a.root_person(administrator, a.catalog),
                             {'network_id': a.network, 'epoch': 0, 'host_public_key': host,
                              'member': 'nora', 'admitted_at': runtime.now})
        ack = a.ack(host)
        result = a.check_map(a.call('POST', '/' + a.network + '/statements',
                                   {'catalog': a.with_proofs(a.catalog, [('person_record', admission), ('join_ack', ack)])}),
                             ('host_a', 'host_q', 'host_b'))
        member = next(value for value in result['members'] if value['host_public_key'] == host)
        need(member['membership_proof_id'] == proof('person_record', admission)['id'] and
             member['join_proof_id'] == proof('join_ack', ack)['id'],
             'direct ordinary admission retains its exact original-person proof and feature acknowledgment')
        backup = self.backup(runtime, 'ordinary-original-issuer')
        entry = proof('admin_delegation', delegation)
        self.rejected(runtime, backup, 'registration_original_issuer_delegation_missing',
                      lambda path: delete_matching(path, 'link_objects', entry['id']))
        forged = dict(delegation, signature=b64(bytes(64)))
        self.rejected(runtime, backup, 'registration_original_issuer_delegation_forged',
                      lambda path: replace_exact_proof(path, entry, proof('admin_delegation', forged)))
        other = a.key('backup/unrelated-delegation-person')
        wrong_person = dict(delegation, person_public_key=other)
        wrong_person['signature'] = b64(a.signers[a.root].raw(lines('peerspan-admin-delegate-v1', a.network,
                                        0, other, runtime.now)))
        self.rejected(runtime, backup, 'registration_original_issuer_delegation_wrong_person',
                      lambda path: replace_exact_proof(path, entry, proof('admin_delegation', wrong_person)))
        a.catalog = result['catalog']
        withdrawal = a.removal(administrator, ['record:' + semantic_id('person_record', admission)],
                               version=2, revoke=False, removed_at=runtime.now)
        a.check_map(a.call('POST', '/' + a.network + '/statements',
                          {'catalog': a.with_proofs(a.catalog, [('admin_removal', withdrawal)])}),
                    ('host_a', 'host_q', 'host_b'))
        complete = self.backup(runtime, 'ordinary-withdrawn-original-issuer')
        restored = runtime.command('restore', str(complete), state=runtime.root / 'ordinary-withdrawn-restored')
        need(restored.returncode == 0, 'complete archive restores despite its original admission issuer losing current administrator role',
             restored.stderr)

    def import_evidence(self, runtime):
        a = ImportSuite.author(self, runtime)
        pending = a.rebind(label='backup/import-inert-pending')
        certificate = payload(pending['owner'])['certificate']
        entry = proof('certificate', certificate)
        a.catalog = a.with_proofs(a.catalog, [('certificate', certificate)])
        a.epoch, a.tip = 0, a.root
        authorization = self.authorization(a)
        result = a.check_map(a.call('POST', '/import', self.import_body(a, authorization)),
                             ('host_a', 'host_q', 'host_b'), status=201)
        need(any(item['id'] == entry['id'] for item in result['catalog']['objects']),
             'original authorized catalog contains a valid inert pending certificate')
        backup = self.backup(runtime, 'feature-import')
        self.rejected(runtime, backup, 'import_global_authorized_pf_missing', lambda path: delete_matching(path, 'link_objects', entry['id']))
        def omit_authorized_snapshot_pf(path):
            changed = copy.deepcopy(result)
            changed['catalog']['objects'] = [item for item in changed['catalog']['objects'] if item['id'] != entry['id']]
            replace_saved_public(path, result, changed)
        self.rejected(runtime, backup, 'import_snapshot_authorized_inert_pf_missing', omit_authorized_snapshot_pf)
        forged = dict(authorization, signature=b64(bytes(64)))
        self.rejected(runtime, backup, 'import_authorization_signature_forged',
                      lambda path: replace_saved_public(path, authorization, forged,
                                  {'authorization_base64', 'catalog_base64', 'map_base64'}))
        changed_catalog = copy.deepcopy(a.catalog)
        changed_catalog['objects'] = [item for item in changed_catalog['objects'] if item['id'] != entry['id']]
        self.rejected(runtime, backup, 'import_original_authorized_catalog_changed',
                      lambda path: replace_saved_public(path, a.catalog, changed_catalog))
        self.rejected(runtime, backup, 'import_outcome_missing',
                      lambda path: replace_saved_public(path, result, None))
        self.rejected(runtime, backup, 'import_provenance_reference_missing',
                      lambda path: replace_saved_public(path, authorization, None, set(authorization)))

    def equivalent_rotation_signatures(self, runtime):
        """Equivalent JSON aliases retain every parsed field and signature.

        Re-spelling a body cannot make a changed or forged signature acceptable
        historical evidence. Distinct authentication forms are not aliases.
        """
        a = ImportSuite.author(self, runtime, rotated=True)
        raw_entry = next(entry for entry in a.catalog['objects'] if entry['kind'] == 'rotation')
        raw_rotation = json.loads(unb64(raw_entry['body_base64']))
        rotation_message = lines('peerspan-root-rotate-v1', *(raw_rotation[field] for field in
                                ('network_id', 'epoch', 'previous_root_public_key', 'root_public_key', 'rotated_at')))
        alias_raw = json.dumps(dict(reversed(list(raw_rotation.items()))), indent=2).encode()
        alias_entry = proof('rotation', raw=alias_raw)
        need(alias_entry['id'] != raw_entry['id'] and json.loads(alias_raw) == raw_rotation,
             'rotation alias changes exact JSON bytes while preserving all parsed fields and signature')
        a.catalog['objects'].append(alias_entry)
        a.catalog['objects'].sort(key=lambda entry: entry['id'])
        result = a.check_map(a.call('POST', '/import', self.import_body(a, self.authorization(a))),
                             ('host_a', 'host_q', 'host_b'), status=201)
        need(raw_entry in result['catalog']['objects'] and alias_entry in result['catalog']['objects'],
             'public imported snapshot retains the exact original and equivalent JSON alias')
        backup = self.backup(runtime, 'equivalent-rotation-signatures')
        restored = runtime.command('restore', str(backup), state=runtime.root / 'equivalent-rotation-restored')
        need(restored.returncode == 0, 'complete equivalent JSON rotation archive restores', restored.stderr)
        forged_alias = dict(raw_rotation, signature=a.signers[a.quinn].sshsig(rotation_message))
        self.rejected(runtime, backup, 'equivalent_rotation_forged_signature_alias',
                      lambda path: append_exact_proof(path, alias_entry, proof('rotation', forged_alias)))

    def build(self):
        for name in ('operation_evidence', 'redemption_evidence', 'registration_evidence',
                     'registration_issuer_provenance', 'import_evidence', 'equivalent_rotation_signatures'):
            self.run(name, getattr(self, name))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--coordinator', required=True)
    parser.add_argument('--section', action='append')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='peerspan-link-backups-') as temporary:
        suite = Suite(args, Path(temporary))
        suite.build()
        print(f'{suite.sections} backup sections passed; {suite.failures} failed; '
              f'{suite.corruptions} corruptions refused atomically; {suite.requests} authenticated requests.', flush=True)
        return int(bool(suite.failures))


if __name__ == '__main__':
    sys.exit(main())
