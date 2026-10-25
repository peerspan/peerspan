#!/usr/bin/env python3
"""Independent current-root feature import and historical repair conformance.

Public signed fixtures/helpers and linking-recovery-checks.md define these
cases. Importing evidence never authorizes a host pin switch or first linking.
"""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

from coord_successor import check_successor_object
from linking_activations import Transcript, payload, proof, semantic_id, shift
from linking_coordinator import Author
from linking_mailboxes import Runtime, Suite as RuntimeSuite, START, error, need, ok
from linking_readers import b64, digest, lines, unb64, wire
from linking_roots import Author as RootAuthor
from linking_readers import FixtureSigner
from launch_service import Key
from peer_messaging import available_port


ROOT = Path(__file__).resolve().parents[1]
DAY = 86400


class Suite(RuntimeSuite):
    def author(self, runtime, rotated=False):
        runtime.set_time(shift(START, 2 * DAY))
        vectors = {path.name: json.loads(path.read_bytes()) for path in (ROOT / 'conformance' / 'vectors').glob('*.json')}
        a = Author(vectors, runtime)
        a.catalog = copy.deepcopy(a.b['catalog'])
        a.completed[a.hosts['host_b'].b64] = [a.base['activation']]
        a.epoch, a.tip = 0, a.root
        if rotated:
            root = RootAuthor(vectors)
            a.catalog = root.catalog(current=True, source=a.catalog)
            a.signers.update(root.signers)
            a.epoch, a.tip = 1, root.roots[1]
        return a

    def withdrawn_activation_is_inert_provenance(self, runtime):
        a = self.author(runtime)
        policy = {'format': 2, 'network_id': a.network, 'person_public_key': a.person,
                  'version': 77, 'issued_at': runtime.now, 'valid_until': shift(runtime.now, DAY),
                  'rules': [], 'capability_rules': [], 'trusted_hosts': [], 'edits': []}
        group = {'network_id': a.network, 'name': 'withdrawn-history', 'version': 17,
                 'defined_at': runtime.now, 'members': ['person_' + digest(unb64(a.person))]}
        records = [a.record('policy-v2', a.b, policy), a.record('group-v1', a.b, group)]
        removal = a.removal(a.person, revoke=True, removed_at=runtime.now)
        a.catalog = a.with_proofs(a.catalog, [('person_record', record) for record in records] +
                                 [('admin_removal', removal)])
        complete = copy.deepcopy(a.catalog)
        original_activation = proof('activation', a.base['activation'])
        need(any(entry == original_activation for entry in complete['objects']),
             'positive source retains the original exact complete activation')
        forged = copy.deepcopy(a.base['activation'])
        forged['owner']['authority_signature'] = b64(bytes(64))
        a.catalog = a.with_proofs(a.without(complete, lambda kind, obj: kind == 'activation'),
                                 [('activation', forged)])
        error(a.call('POST', '/import', self.body(a, self.authorization(a))), 400, 'invalid')
        self.absent(a)
        a.catalog = a.without(complete, lambda kind, obj: kind == 'activation')
        missing = a.call('POST', '/import', self.body(a, self.authorization(a)))
        error(missing, 409, 'proof_required')
        need(missing[2]['details']['required_ids'] == [a.base['activation']['request']['request_id']],
             'retained inactive access observations still require their exact complete device activation')
        self.absent(a)
        a.catalog = complete
        result = a.check_map(a.call('POST', '/import', self.body(a, self.authorization(a))),
                             ('host_a', 'host_q'), status=201)
        need(all(entry in result['catalog']['objects'] for entry in complete['objects']),
             'recognized withdrawal retains complete signed transcripts and exact high-water candidates without restoring their membership')
        a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q'))

    def authorization(self, a, raw=None, signer=None, ssh=False, **changes):
        value = {'format': 1, 'network_id': a.network, 'network_name': a.descriptor['name'],
                 'epoch': a.epoch, 'feature_id': a.feature_id,
                 'coordinator_address': a.descriptor['coordinator_address'],
                 'coordinator_public_key': a.descriptor['coordinator_public_key'],
                 'catalog_sha256': hashlib.sha256(raw if raw is not None else wire(a.catalog)).hexdigest(),
                 'issued_at': a.runtime.now, 'expires_at': shift(a.runtime.now, 300)}
        value.update(changes)
        msg = lines('peerspan-link-feature-import-v1', *(value[field] for field in
                    ('network_id', 'network_name', 'epoch', 'feature_id', 'coordinator_address',
                     'coordinator_public_key', 'catalog_sha256', 'issued_at', 'expires_at')))
        key = a.signers[signer or a.tip]
        value['signature'] = key.sshsig(msg) if ssh else b64(key.raw(msg))
        return value

    @staticmethod
    def body(a, authorization, raw=None):
        if raw is None:
            return {'network': a.descriptor, 'catalog': a.catalog, 'feature_authorization': authorization}
        return (b'{"network":' + wire(a.descriptor) + b',"catalog":' + raw +
                b',"feature_authorization":' + wire(authorization) + b'}')

    def absent(self, a):
        error(a.call('GET', '/' + a.network + '/map'), 404, 'not_found')

    def bindings_and_retry(self, runtime):
        a = self.author(runtime)
        body = self.body(a, '-')
        failed = a.call('POST', '/import', body)
        error(failed, 409, 'proof_required')
        need(failed[2]['details']['required_ids'] == [a.feature_id], 'missing durable feature requires exact immutable LF')
        self.absent(a)
        for field, value in (('network_id', 'net_' + '0' * 64), ('network_name', 'changed-name'),
                             ('epoch', 1), ('feature_id', 'lf_' + '0' * 64),
                             ('coordinator_address', 'other.example:443'), ('coordinator_public_key', a.quinn),
                             ('catalog_sha256', '0' * 64), ('expires_at', shift(runtime.now, 301))):
            bad = self.authorization(a, **{field: value})
            error(a.call('POST', '/import', self.body(a, bad)), 409 if field == 'feature_id' else 400,
                  'state_conflict' if field == 'feature_id' else 'invalid')
            self.absent(a)
        for label, authorization in (
                ('administrator_signature', self.authorization(a, signer=a.quinn)),
                ('future', self.authorization(a, issued_at=shift(runtime.now, 1), expires_at=shift(runtime.now, 301))),
                ('exclusive_expiry', self.authorization(a, issued_at=shift(runtime.now, -300), expires_at=runtime.now))):
            error(a.call('POST', '/import', self.body(a, authorization)), 410 if label == 'exclusive_expiry' else 400,
                  'expired' if label == 'exclusive_expiry' else 'invalid')
            self.absent(a)
        valid = self.authorization(a)
        for bad in (dict(valid, signature='-'), dict(valid, approved=True), dict(valid, network_name=None)):
            error(a.call('POST', '/import', self.body(a, bad)), 400, 'invalid')
            self.absent(a)
        canonical = wire(a.catalog)
        alias = canonical[:-1] + b' }'
        error(a.call('POST', '/import', self.body(a, valid, alias)), 400, 'invalid')
        self.absent(a)
        raw = wire(self.body(a, valid))
        for malformed in (raw + b'{}', raw[:-1] + b',"network":null}', b'{"network":"\xff"}',
                          raw + b' ' * (1024 * 1024 + 1 - len(raw))):
            error(a.call('POST', '/import', malformed), 400, 'invalid')
            self.absent(a)
        # A different, valid JSON spelling succeeds only with its exact hash.
        authorized_alias = self.authorization(a, alias, ssh=True)
        body = self.body(a, authorized_alias, alias)
        padded = body + b' ' * (1024 * 1024 - len(body))
        original = a.check_map(a.call('POST', '/import', padded), ('host_a', 'host_q', 'host_b'), status=201)
        runtime.advance(300)
        need(a.check_map(a.call('POST', '/import', body), ('host_a', 'host_q', 'host_b')) == original,
             'exact root authorization retry returns original outcome after exclusive deadline')
        error(a.call('POST', '/import', self.body(a, authorized_alias, canonical)), 409, 'state_conflict')
        runtime.restart()
        need(a.check_map(a.call('POST', '/import', body), ('host_a', 'host_q', 'host_b')) == original,
             'restart retains exact authorized catalog bytes and immutable outcome')

    def membership_and_sticky_state(self, runtime):
        a = self.author(runtime)
        authorization = self.authorization(a)
        body = self.body(a, authorization)
        error(a.call('POST', '/import', body, host='host_c'), 403, 'forbidden')
        self.absent(a)
        original = a.check_map(a.call('POST', '/import', body), ('host_a', 'host_q', 'host_b'), status=201)
        revoked = a.signed_legacy('host_revocation', {'host_public_key': a.hosts['host_b'].b64, 'revoked_at': runtime.now})
        addition = a.with_proofs({'format': 1, 'network_id': a.network, 'objects': []}, [('host_revocation', revoked)])
        a.check_map(a.call('POST', '/' + a.network + '/statements', {'catalog': addition}))
        repaired = a.check_map(a.call('POST', '/import', self.body(a, '-')))
        need(any(entry['id'] == proof('host_revocation', revoked)['id'] for entry in repaired['catalog']['objects']),
             'historical repair retains sticky restriction absent from submitted old snapshot')
        error(a.call('POST', '/import', self.body(a, '-'), host='host_b'), 403, 'forbidden')
        runtime.advance(300)
        need(a.check_map(a.call('POST', '/import', body), ('host_a', 'host_q', 'host_b')) == original,
             'committed import retry is historical snapshot, not current membership')
        a.check_map(a.call('GET', '/' + a.network + '/map'))

    def repair_authenticates_prior_sender(self, runtime):
        a = self.author(runtime)
        authorized = self.body(a, self.authorization(a))
        original = a.check_map(a.call('POST', '/import', authorized, host='host_b'),
                               ('host_a', 'host_q', 'host_b'), status=201)
        revoked = a.signed_legacy('host_revocation',
                                 {'host_public_key': a.hosts['host_b'].b64, 'revoked_at': runtime.now})
        a.catalog = a.with_proofs(a.catalog, [('host_revocation', revoked)])
        repaired = a.check_map(a.call('POST', '/import', self.body(a, '-'), host='host_b'))
        need(any(entry['id'] == proof('host_revocation', revoked)['id'] for entry in repaired['catalog']['objects']),
             'prior-current member can repair its own valid withdrawal before that withdrawal changes membership')
        before = a.check_map(a.call('GET', '/' + a.network + '/map'))
        error(a.call('POST', '/import', self.body(a, '-'), host='host_b'), 403, 'forbidden')
        admission = a.signed_legacy('host_admission',
                                   {'epoch': 0, 'host_public_key': a.hosts['host_b'].b64,
                                    'member': 'alice', 'admitted_at': runtime.now})
        a.catalog = a.with_proofs(a.catalog, [('host_admission', admission), ('join_ack', a.ack(a.hosts['host_b'].b64))])
        error(a.call('POST', '/import', self.body(a, '-'), host='host_b'), 403, 'forbidden')
        need(a.check_map(a.call('GET', '/' + a.network + '/map')) == before,
             'incoming valid grant cannot replace prior sticky denial or partially write its new proofs')
        need(a.check_map(a.call('POST', '/import', authorized, host='host_b'),
                         ('host_a', 'host_q', 'host_b')) == original,
             'exact immutable root-authorized outcome retrieval remains historical despite later removal')
        admission = a.signed_legacy('host_admission',
                                   {'epoch': 0, 'host_public_key': a.hosts['host_c'].b64,
                                    'member': 'repair-only', 'admitted_at': runtime.now})
        a.catalog = a.with_proofs(a.catalog, [('host_admission', admission), ('join_ack', a.ack(a.hosts['host_c'].b64))])
        a.check_map(a.call('POST', '/import', self.body(a, '-'), host='host_c'), ('host_a', 'host_q', 'host_c'))

    def rotation_does_not_bootstrap_new_issuer(self, runtime):
        a = self.author(runtime)
        a.check_map(a.call('POST', '/import', self.body(a, self.authorization(a))),
                    ('host_a', 'host_q', 'host_b'), status=201)
        before = a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b'))
        roots = RootAuthor(a.oracle.vectors)
        rotated = roots.catalog(current=True, source=a.catalog)
        a.signers.update(roots.signers)
        next_root = roots.roots[1]
        new_admin = a.key('rotation/no-new-issuer')
        admission = a.signed_legacy('person_admission',
                                   {'epoch': 1, 'person_public_key': new_admin,
                                    'member': 'new-batch-admin', 'admitted_at': runtime.now}, next_root)
        delegation = {'network_id': a.network, 'epoch': 1, 'person_public_key': new_admin, 'delegated_at': runtime.now}
        delegation['signature'] = b64(a.signers[next_root].raw(
            lines('peerspan-admin-delegate-v1', a.network, 1, new_admin, runtime.now)))
        fields = {'host_public_key': a.hosts['host_c'].b64, 'revoked_at': runtime.now}
        unauthorized = a.signed_legacy('host_revocation', fields, new_admin, ssh=True)
        candidate = a.with_proofs(rotated, [('person_admission', admission), ('admin_delegation', delegation),
                                           ('host_revocation', unauthorized)])
        error(a.call('POST', '/' + a.network + '/statements', {'catalog': candidate}), 403, 'forbidden')
        need(a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b')) == before,
             'newly delegated issuer cannot authorize another fresh mutation or partially advance root/catalog')
        authorized = a.signed_legacy('host_revocation', fields, next_root)
        candidate = a.with_proofs(rotated, [('person_admission', admission), ('admin_delegation', delegation),
                                           ('host_revocation', authorized)])
        a.check_map(a.call('POST', '/' + a.network + '/statements', {'catalog': candidate}),
                    ('host_a', 'host_q', 'host_b'))

    def current_root_and_fresh_writers(self, runtime):
        a = self.author(runtime, rotated=True)
        for signer in (a.root, a.quinn):
            error(a.call('POST', '/import', self.body(a, self.authorization(a, signer=signer))), 400, 'invalid')
            self.absent(a)
        a.check_map(a.call('POST', '/import', self.body(a, self.authorization(a))), ('host_a', 'host_q', 'host_b'), status=201)
        # Exact historical root0 grants are still imported. A new issuance must
        # use current root1, even when the old signature is cryptographically valid.
        for kind, fields in (
                ('host_admission', {'epoch': 0, 'host_public_key': a.hosts['host_c'].b64, 'member': 'carmen', 'admitted_at': runtime.now}),
                ('host_revocation', {'host_public_key': a.hosts['host_c'].b64, 'revoked_at': runtime.now}),
                ('invite_revocation', {'invite_public_key': a.target_invite, 'revoked_at': runtime.now})):
            before = a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b'))
            old = a.signed_legacy(kind, fields, a.root)
            source = a.with_proofs({'format': 1, 'network_id': a.network, 'objects': []}, [(kind, old)])
            error(a.call('POST', '/' + a.network + '/statements', {'catalog': source}), 403, 'forbidden')
            need(a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b')) == before,
                 'retired-root fresh write changes no public state', kind)
        # A current-epoch root grant and exact host acknowledgment are usable.
        admitted = a.signed_legacy('host_admission', {'epoch': 1, 'host_public_key': a.hosts['host_c'].b64,
                                   'member': 'carmen', 'admitted_at': runtime.now}, a.tip)
        source = a.with_proofs({'format': 1, 'network_id': a.network, 'objects': []},
                              [('host_admission', admitted), ('join_ack', a.ack(a.hosts['host_c'].b64))])
        a.check_map(a.call('POST', '/' + a.network + '/statements', {'catalog': source}), ('host_a', 'host_q', 'host_b', 'host_c'))
        revoked = a.signed_legacy('host_revocation', {'host_public_key': a.hosts['host_c'].b64, 'revoked_at': runtime.now}, a.tip)
        source = a.with_proofs({'format': 1, 'network_id': a.network, 'objects': []}, [('host_revocation', revoked)])
        a.check_map(a.call('POST', '/' + a.network + '/statements', {'catalog': source}), ('host_a', 'host_q', 'host_b'))
        revoked_invite = a.signed_legacy('invite_revocation', {'invite_public_key': a.target_invite, 'revoked_at': runtime.now}, a.tip)
        source = a.with_proofs({'format': 1, 'network_id': a.network, 'objects': []}, [('invite_revocation', revoked_invite)])
        a.check_map(a.call('POST', '/' + a.network + '/statements', {'catalog': source}), ('host_a', 'host_q', 'host_b'))
        for signer, code in ((a.root, 'forbidden'), (a.tip, None)):
            removal = a.removal(a.quinn)
            a.oracle.resign('admin_removal_v2', removal, signer)
            source = a.with_proofs({'format': 1, 'network_id': a.network, 'objects': []}, [('admin_removal', removal)])
            response = a.call('POST', '/' + a.network + '/statements', {'catalog': source})
            if code:
                error(response, 403, code)
            else:
                a.check_map(response, ('host_a', 'host_q', 'host_b'))
        # A removed person keeps historical label evidence but cannot reserve
        # that label against a different freshly admitted invitation subject.
        admitted = a.signed_legacy('person_admission', {'epoch': 1, 'person_public_key': a.new_person,
                                   'member': 'reusable', 'admitted_at': runtime.now}, a.tip)
        removed = a.signed_legacy('person_removal', {'person_public_key': a.new_person, 'removed_at': runtime.now}, a.tip)
        for kind, value in (('person_admission', admitted), ('person_removal', removed)):
            source = a.with_proofs({'format': 1, 'network_id': a.network, 'objects': []}, [(kind, value)])
            a.check_map(a.call('POST', '/' + a.network + '/statements', {'catalog': source}), ('host_a', 'host_q', 'host_b'))
        invite, person = a.key('import/reusable-invite'), a.key('import/reusable-person')
        redemption = a.redemption('person', 'admit', style='legacy_root', invite=invite, person=person,
                                  label='reusable', joined=runtime.now, expires=shift(runtime.now, DAY))
        grant = redemption['person_invite']
        grant['invite_epoch'] = 1
        grant['signature'] = b64(a.signers[a.tip].raw(lines('peerspan-person-invite-v1', a.network, 1, invite,
                                                          'reusable', grant['invite_expires_at'])))
        empty = {'format': 1, 'network_id': a.network, 'objects': []}
        result = a.check_map(a.call('POST', '/' + a.network + '/invite-redemptions',
                            {'redemption': redemption, 'catalog': empty, 'address': '', 'candidates': [], 'join_ack': '-'}),
                            ('host_a', 'host_q', 'host_b'), status=201)
        need(any(entry['id'] == proof('invite_redemption', redemption)['id'] for entry in result['catalog']['objects']),
             'fresh root-authorized new person may reuse only a removed subject label')

    def person_label_conflicts(self, runtime):
        a = self.author(runtime, rotated=True)
        a.check_map(a.call('POST', '/import', self.body(a, self.authorization(a))), ('host_a', 'host_q', 'host_b'), status=201)
        def legacy(key, label):
            return a.signed_legacy('person_admission', {'epoch': 1, 'person_public_key': key,
                                   'member': label, 'admitted_at': runtime.now}, a.tip)
        def ordinary(key, label):
            return a.record('person-admit-v1', unsigned={'network_id': a.network, 'epoch': 1,
                            'person_public_key': key, 'member': label, 'admitted_at': runtime.now}, epoch=1)
        candidates = [
            [('person_admission', legacy(a.key('label-conflict/legacy'), 'Alice'))],
            [('person_record', ordinary(a.key('label-conflict/ordinary'), 'ALICE'))],
            [('person_admission', legacy(a.key('label-conflict/batch-legacy'), 'Twins')),
             ('person_record', ordinary(a.key('label-conflict/batch-ordinary'), 'tWINS'))],
        ]
        for entries in candidates:
            before = a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b'))
            catalog = a.with_proofs({'format': 1, 'network_id': a.network, 'objects': []}, entries)
            error(a.call('POST', '/' + a.network + '/statements', {'catalog': catalog}), 409, 'state_conflict')
            need(a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b')) == before,
                 'case-conflicting legacy/enveloped/batch admission cannot publish a partial grant')

    def same_pin_older_backup(self, runtime):
        vectors = {path.name: json.loads(path.read_bytes()) for path in (ROOT / 'conformance' / 'vectors').glob('*.json')}
        a = Author(vectors, runtime)
        a.epoch, a.tip = 0, a.root
        a.register()
        backup = runtime.root / 'complete-prefeature.backup'
        need(runtime.command('backup', str(backup)).returncode == 0, 'complete pre-feature backup succeeds')
        need(ok(a.call('POST', '/' + a.network + '/link-feature', a.feature_body()), 201) == {'feature_id': a.feature_id},
             'later feature activation creates history absent from old complete backup')
        current = a.check_map(a.call('GET', '/' + a.network + '/map'))
        runtime.stop()
        restored_state = runtime.root / 'older-state'
        restored = runtime.command('restore', str(backup), state=restored_state)
        need(restored.returncode == 0, 'complete older pre-feature backup remains restorable', restored.stderr)
        prior = Runtime(runtime.binary, runtime.root / 'repaired', initial=shift(START, 2 * DAY), state=restored_state, port=runtime.port)
        try:
            need(json.loads(prior.command('info').stdout)['public_key'] == a.descriptor['coordinator_public_key'], 'same-pin restore preserves original coordinator identity')
            a.runtime, a.catalog = prior, current['catalog']
            response = a.call('POST', '/import', self.body(a, '-'))
            error(response, 409, 'proof_required')
            need(response[2]['details']['required_ids'] == [a.feature_id], 'older backup cannot infer absent durable feature from host assertion')
            body = self.body(a, self.authorization(a))
            repaired = a.check_map(a.call('POST', '/import', body), status=201)
            need(any(entry['kind'] == 'feature' for entry in repaired['catalog']['objects']), 'fresh exact root intent repairs the original immutable feature')
            prior.advance(300)
            need(a.check_map(a.call('POST', '/import', body)) == repaired, 'same-pin repair retry preserves its stored map after authorization expiry')
        finally:
            self.requests += prior.requests
            prior.close()

    def moves_and_new_target(self, runtime):
        a = self.author(runtime)
        a.check_map(a.call('POST', '/import', self.body(a, self.authorization(a))), ('host_a', 'host_q', 'host_b'), status=201)
        destination = Runtime(runtime.binary, runtime.root / 'destination', initial=runtime.now)
        original_descriptor = copy.deepcopy(a.descriptor)
        target_key = json.loads(destination.command('info').stdout)['public_key']
        target_address = f'127.0.0.1:{destination.port}'
        def move(sequence, signer='root', **changes):
            value = {'network_id': a.network, 'sequence': sequence, 'address': target_address,
                     'public_key': target_key, 'moved_at': runtime.now, 'signer': signer}
            value.update(changes)
            msg = lines('peerspan-coordinator-move-v1', *(value[field] for field in
                        ('network_id', 'sequence', 'address', 'public_key', 'moved_at')))
            key = a.signers[a.tip if signer == 'root' else signer]
            value['signature'] = b64(key.raw(msg)) if signer == 'root' else key.sshsig(msg)
            return value
        empty = {'format': 1, 'network_id': a.network, 'objects': []}
        try:
            first = move(1)
            body = {'move': first, 'catalog': empty}
            original = a.check_map(a.call('POST', '/' + a.network + '/moves', body), ('host_a', 'host_q', 'host_b'))
            need(a.check_map(a.call('POST', '/' + a.network + '/moves', body), ('host_a', 'host_q', 'host_b')) == original, 'exact known move retry does not reissue')
            conflict = move(1, address='different.example:443')
            error(a.call('POST', '/' + a.network + '/moves', {'move': conflict, 'catalog': empty}), 409, 'state_conflict')
            need(a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b')) == original, 'conflicting move cannot partially change source state')
            legacy = runtime.call('POST', '/coord/v1/networks/' + a.network + '/moves', {'move': first}, key=a.hosts['host_a'])
            error(legacy, 426, 'upgrade_required')
            second = move(2, a.quinn)
            a.check_map(a.call('POST', '/' + a.network + '/moves', {'move': second, 'catalog': empty}), ('host_a', 'host_q', 'host_b'))
            third = move(3)
            source = a.with_proofs(empty, [('coordinator_move', third)])
            latest = a.check_map(a.call('POST', '/' + a.network + '/statements', {'catalog': source}), ('host_a', 'host_q', 'host_b'))
            need(any(entry['id'] == proof('coordinator_move', third)['id'] for entry in latest['catalog']['objects']), 'generic statement writer shares current move sequence gate')
            a.runtime, a.catalog = destination, latest['catalog']
            a.descriptor.update(coordinator_address=target_address, coordinator_public_key=target_key)
            failed = a.call('POST', '/import', self.body(a, '-'))
            error(failed, 409, 'proof_required')
            need(failed[2]['details']['required_ids'] == [a.feature_id], 'even signed current-root/admin moves cannot infer target durable feature')
            self.absent(a)
            imported = a.check_map(a.call('POST', '/import', self.body(a, self.authorization(a))), ('host_a', 'host_q', 'host_b'), status=201)
            need(any(entry['id'] == proof('coordinator_move', third)['id'] for entry in imported['catalog']['objects']), 'new target retains exact signed move and original feature history')
            a.runtime, a.descriptor = runtime, original_descriptor
            a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b'))
        finally:
            self.requests += destination.requests
            destination.close()

    def actual_successor_catalog(self, runtime):
        vectors = {path.name: json.loads(path.read_bytes()) for path in (ROOT / 'conformance' / 'vectors').glob('*.json')}
        a = Author(vectors, runtime)
        a.activate()
        activation = a.rebind(label='successors/old-pin/B')
        a.check_result(a.call('POST', '/' + a.network + '/link-operations', a.operation_body(activation), host='host_b'), activation)
        baseline = a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b'))
        original = copy.deepcopy(a.descriptor)
        original_port = runtime.port
        first_address = f'localhost:{original_port}'
        runtime.stop()
        first_reply = runtime.command('successor', '--address', first_address)
        need(first_reply.returncode == 0, 'actual same-key successor CLI succeeds', first_reply.stderr)
        first = json.loads(first_reply.stdout)
        check_successor_object(first['successor'], 1, original['coordinator_public_key'], first_address,
                               original['coordinator_public_key'], runtime.root)
        runtime.start()
        first_map = a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b'))
        first_entries = [entry for entry in first_map['catalog']['objects'] if entry['kind'] == 'coordinator_successor']
        need(len(first_entries) == 1 and json.loads(unb64(first_entries[0]['body_base64'])) == first['successor'],
             'same-key actual successor is present as one exact catalog proof')
        runtime.stop()
        latest_port = available_port()
        latest_address = f'127.0.0.1:{latest_port}'
        second_reply = runtime.command('successor', '--address', latest_address, '--new-key')
        need(second_reply.returncode == 0, 'actual second new-key successor CLI succeeds', second_reply.stderr)
        second = json.loads(second_reply.stdout)
        check_successor_object(second['successor'], 2, first['public_key'], latest_address, second['public_key'], runtime.root)
        def start_both():
            runtime.port = latest_port
            env = dict(os.environ, PEERSPAN_LINK_TEST_MODE='1', PEERSPAN_LINK_TEST_CLOCK_FILE=str(runtime.clock),
                       PEERSPAN_LINK_TEST_BARRIER_DIR=str(runtime.barriers))
            runtime.process = subprocess.Popen([runtime.binary, '--state', str(runtime.state), 'run', '--listen', latest_address,
                '--previous-listen', f'0=127.0.0.1:{original_port}'], env=env, stdout=runtime.logs, stderr=runtime.logs)
            deadline = time.monotonic() + 20
            for port in (original_port, latest_port):
                while time.monotonic() < deadline:
                    need(runtime.process.poll() is None, 'actual successor listeners stay alive')
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.02)
                else:
                    raise AssertionError('actual successor listener did not start')
        start_both()
        expected = None
        for restarted in (False, True):
            if restarted:
                runtime.stop()
                start_both()
            for port, key in ((original_port, original['coordinator_public_key']), (latest_port, second['public_key'])):
                runtime.port = port
                a.descriptor = dict(original, coordinator_address=f'127.0.0.1:{port}', coordinator_public_key=key)
                result = a.check_map(a.call('GET', '/' + a.network + '/map', fresh=True), ('host_a', 'host_q', 'host_b'))
                retained = {entry['id']: entry for entry in result['catalog']['objects']}
                need(all(retained.get(entry['id']) == entry for entry in baseline['catalog']['objects']),
                     'actual successor adoption preserves every exact old activation/feature proof from both listeners')
                entries = [entry for entry in result['catalog']['objects'] if entry['kind'] == 'coordinator_successor']
                need(len(entries) == 2 and first_entries[0] in entries and
                     sorted((json.loads(unb64(entry['body_base64'])) for entry in entries), key=lambda item: item['sequence']) ==
                     [first['successor'], second['successor']], 'both listeners serve the complete actual signed two-step chain')
                if expected is None:
                    expected = entries
                need(entries == expected, 'old/latest listeners and restart retain identical exact successor body bytes and PFs')

    def fresh_dependencies_require_current_authority(self, runtime):
        a = self.author(runtime, rotated=True)
        a.check_map(a.call('POST', '/import', self.body(a, self.authorization(a))), ('host_a', 'host_q', 'host_b'), status=201)
        restricted_host = a.key('fresh-dependencies/unrelated-host')
        fields = {'host_public_key': restricted_host, 'revoked_at': runtime.now}
        old = a.signed_legacy('host_revocation', fields, a.root)
        current = a.signed_legacy('host_revocation', fields, a.tip)
        # A correctly current-root-signed person invitation is otherwise valid.
        red = a.redemption('person', 'admit', style='legacy_root', person=a.key('fresh-dependencies/person'),
                          label='fresh-person', invite=a.key('fresh-dependencies/invite'),
                          expires=shift(runtime.now, DAY), joined=runtime.now)
        grant = red['person_invite']
        grant['invite_epoch'] = 1
        grant['signature'] = b64(a.signers[a.tip].raw(lines('peerspan-person-invite-v1', a.network, 1,
                                            grant['invite_public_key'], grant['member'], grant['invite_expires_at'])))
        def redemption_body(restriction):
            return {'redemption': red, 'catalog': a.with_proofs(a.catalog, [('host_revocation', restriction)]),
                    'address': '', 'candidates': [], 'join_ack': '-'}
        before = a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b'))
        error(a.call('POST', '/' + a.network + '/invite-redemptions', redemption_body(old)), 403, 'forbidden')
        need(a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b')) == before,
             'fresh redemption cannot smuggle a retired-root restriction or partially consume its invitation')
        a.check_map(a.call('POST', '/' + a.network + '/invite-redemptions', redemption_body(current)),
                    ('host_a', 'host_q', 'host_b'), status=201)
        # A separate old-root restriction isolates the link-operation entry gate.
        fields['host_public_key'] = a.key('fresh-dependencies/operation-unrelated-host')
        old = a.signed_legacy('host_revocation', fields, a.root)
        current = a.signed_legacy('host_revocation', fields, a.tip)
        roots = RootAuthor(a.oracle.vectors)
        template = dict(a.base, activation=roots.epoch_activation(a.base, 1))
        activation = a.rebind(template, label='fresh-dependencies/current-epoch-C', target='host_c')
        transcript = Transcript(a, dict(a.base, activation=activation))
        transcript.values['request'].update(created_at=runtime.now, expires_at=shift(runtime.now, 300))
        transcript.values['owner']['certificate'].update(issued_at=runtime.now, not_after=shift(runtime.now, 90 * DAY))
        transcript.sign_certificate()
        for role, field in (('owner', 'binding_record'), ('administrator', 'admission_record')):
            record = transcript.values[role][field]
            unsigned = payload(record)
            unsigned['bound_at' if role == 'owner' else 'admitted_at'] = runtime.now
            record['payload_base64'] = b64(wire(unsigned))
            transcript.sign_record(record, a.person, draft=role == 'owner')
        activation = transcript.finish()
        def operation_body(restriction):
            body = a.operation_body(activation)
            body['catalog'] = a.with_proofs(a.catalog, [('host_revocation', restriction)])
            return body
        before = a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b'))
        error(a.call('POST', '/' + a.network + '/link-operations', operation_body(old), host='host_c'), 403, 'forbidden')
        need(a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b')) == before,
             'fresh linking cannot smuggle a retired-root dependency or partially admit the target')
        error(a.call('GET', '/' + a.network + '/link-operations/' + activation['request']['request_id'], host='host_c'), 404, 'not_found')
        a.check_result(a.call('POST', '/' + a.network + '/link-operations', operation_body(current), host='host_c'), activation)
        a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b', 'host_c'))

    def first_feature_dependencies_require_current_authority(self, runtime):
        vectors = {path.name: json.loads(path.read_bytes()) for path in (ROOT / 'conformance' / 'vectors').glob('*.json')}
        a = Author(vectors, runtime)
        roots = RootAuthor(vectors)
        a.signers.update(roots.signers)
        a.register()
        empty = {'format': 1, 'network_id': a.network, 'objects': []}
        additions = [('rotation', roots.rotation(1, rotated_at=runtime.now))]
        for name, label in (('host_a', 'alice'), ('host_q', 'quinn')):
            host = a.hosts[name].b64
            attested = roots.attestation(host, label)
            attested['attested_at'] = runtime.now
            attested['signature'] = b64(a.signers[roots.roots[1]].raw(lines('peerspan-attest-v1', a.network, 1, host, label, runtime.now)))
            additions.append(('attestation', attested))
        a.catalog = a.with_proofs(empty, additions)
        def feature():
            value = copy.deepcopy(a.feature)
            value['proposal'].update(epoch=1, issued_at=runtime.now)
            a.oracle.resign('feature_proposal', value['proposal'], roots.roots[1])
            identity = semantic_id('feature_proposal', value['proposal'])
            for ack in value['acknowledgments']:
                ack['feature_id'] = identity
                a.oracle.resign('feature_ack', ack, ack['host_public_key'])
            return value, identity
        a.feature, a.feature_id = feature()
        person = a.key('first-feature/unrelated-person')
        invite = a.key('first-feature/unrelated-invite')
        old_person = a.signed_legacy('person_removal', {'person_public_key': person, 'removed_at': runtime.now}, a.root)
        old_invite = a.signed_legacy('invite_revocation', {'invite_public_key': invite, 'revoked_at': runtime.now}, a.root)
        def legacy_snapshot():
            value = ok(a.call('POST', '/' + a.network + '/sync',
                       {'address': '', 'candidates': [], 'linking_version': 1}), 200)
            need('format' not in value, 'feature restriction boundary starts with unactivated legacy map')
            # Sync legitimately updates this unsigned reachability timestamp.
            # Every signed object and every membership field remains compared.
            for member in value['members']:
                member.pop('updated_at')
            return value
        before = legacy_snapshot()
        with sqlite3.connect(runtime.state / 'coord.db') as db:
            initial_counts = [db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0]
                              for table in ('link_features', 'link_objects')]
        def unchanged():
            need(legacy_snapshot() == before,
                 'failed first-feature restriction injection changes no active pin, membership or public proof')
            with sqlite3.connect(runtime.state / 'coord.db') as db:
                need([db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0]
                      for table in ('link_features', 'link_objects')] == initial_counts,
                     'first-feature refusal persists no public proof or active feature index')
        source = a.with_proofs(a.catalog, [('person_removal', old_person)])
        error(a.call('POST', '/' + a.network + '/link-feature', {'feature': a.feature, 'catalog': source}), 403, 'forbidden')
        unchanged()
        # Storing an incomplete candidate does not convert its dependencies into
        # already durable historical public evidence at eventual first use.
        source = a.with_proofs(a.catalog, [('invite_revocation', old_invite)])
        need(ok(a.call('POST', '/' + a.network + '/link-feature/proposals',
                       {'proposal': a.feature['proposal'], 'catalog': source}), 201) == {'feature_id': a.feature_id},
             'pending proposal retains independently signed candidate dependencies')
        for ack in a.feature['acknowledgments']:
            host = next(name for name, key in a.hosts.items() if key.b64 == ack['host_public_key'])
            need(ok(a.call('POST', '/' + a.network + '/link-feature/acknowledgments',
                           {'acknowledgment': ack, 'catalog': a.catalog}, host=host), 201) == {'feature_id': a.feature_id},
                 'matching host acknowledgment still establishes no active feature')
        # Proposal/ack preparation legitimately retains its inactive candidate.
        # Compare the failed activation with that immediately preceding state.
        with sqlite3.connect(runtime.state / 'coord.db') as db:
            initial_counts = [db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0]
                              for table in ('link_features', 'link_objects')]
        error(a.call('POST', '/' + a.network + '/link-feature', a.feature_body()), 403, 'forbidden')
        unchanged()
        runtime.advance(1)
        a.feature, a.feature_id = feature()
        current_person = a.signed_legacy('person_removal', {'person_public_key': person, 'removed_at': runtime.now}, roots.roots[1])
        current_invite = a.signed_legacy('invite_revocation', {'invite_public_key': invite, 'revoked_at': runtime.now}, roots.roots[1])
        source = a.with_proofs(a.catalog, [('person_removal', current_person), ('invite_revocation', current_invite)])
        need(ok(a.call('POST', '/' + a.network + '/link-feature', {'feature': a.feature, 'catalog': source}), 201) ==
             {'feature_id': a.feature_id}, 'fresh current-root feature and equivalent current restrictions can activate')
        result = a.check_map(a.call('GET', '/' + a.network + '/map'))
        identities = {entry['id'] for entry in result['catalog']['objects']}
        need(proof('person_removal', old_person)['id'] not in identities and
             proof('invite_revocation', old_invite)['id'] not in identities,
             'unrelated inactive pending candidate cannot smuggle retired-root restrictions into a different active feature')

    @staticmethod
    def member_limit(runtime, limit):
        # Change only a public process option, preserving the exact committed DB.
        runtime.stop()
        env = dict(os.environ, PEERSPAN_LINK_TEST_MODE='1', PEERSPAN_LINK_TEST_CLOCK_FILE=str(runtime.clock),
                   PEERSPAN_LINK_TEST_BARRIER_DIR=str(runtime.barriers))
        runtime.process = subprocess.Popen([runtime.binary, '--state', str(runtime.state), 'run', '--listen',
                            f'127.0.0.1:{runtime.port}', '--max-members', str(limit)],
                            env=env, stdout=runtime.logs, stderr=runtime.logs)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            need(runtime.process.poll() is None, 'at-capacity coordinator remains alive')
            try:
                with socket.create_connection(('127.0.0.1', runtime.port), timeout=.1):
                    return
            except OSError:
                time.sleep(.02)
        raise AssertionError('at-capacity coordinator did not listen')

    @staticmethod
    def current_redemption(a, mode, label, invite, person=None, host=None):
        value = a.redemption(mode, 'admit' if mode == 'person' else 'none', style='legacy_root',
                             label=label, invite=invite, person=person,
                             host=a.hosts[host].b64 if host else None,
                             expires=shift(a.runtime.now, DAY), joined=a.runtime.now)
        for field, domain in (('host_invite', 'peerspan-invite-v1'), ('person_invite', 'peerspan-person-invite-v1')):
            grant = value[field]
            if grant == '-':
                continue
            fields = [a.network]
            if field == 'person_invite':
                grant['invite_epoch'] = a.epoch
                fields.append(a.epoch)
            fields.extend([grant['invite_public_key'], grant['member'], grant['invite_expires_at']])
            grant['signature'] = b64(a.signers[a.tip].raw(lines(domain, *fields)))
        return value

    def person_redemption_reconciles_capacity(self, runtime):
        a = self.author(runtime, rotated=True)
        a.check_map(a.call('POST', '/import', self.body(a, self.authorization(a))),
                    ('host_a', 'host_q', 'host_b'), status=201)
        self.member_limit(runtime, 3)
        before = a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b'))
        route = '/' + a.network + '/invite-redemptions'
        person = self.current_redemption(a, 'person', 'capacity-person', a.key('capacity/person-invite'),
                                         person=a.key('capacity/person'))
        replacement = self.current_redemption(a, 'host', 'replacement', a.key('capacity/host-invite'), host='host_c')
        def body(redemption, catalog):
            return {'redemption': redemption, 'catalog': catalog, 'address': '', 'candidates': [],
                    'join_ack': a.ack(a.hosts['host_c'].b64) if redemption['mode'] == 'host' else '-'}
        error(a.call('POST', route, body(replacement, a.catalog), host='host_c'), 409, 'quota_exceeded')
        fields = {'host_public_key': a.hosts['host_b'].b64, 'revoked_at': runtime.now}
        old = a.signed_legacy('host_revocation', fields, a.root)
        current = a.signed_legacy('host_revocation', fields, a.tip)
        error(a.call('POST', route, body(person, a.with_proofs(a.catalog, [('host_revocation', old)]))), 403, 'forbidden')
        need(a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b')) == before,
             'unauthorized person-only dependency neither frees registration capacity nor consumes its invitation')
        accepted = a.check_map(a.call('POST', route,
                             body(person, a.with_proofs(a.catalog, [('host_revocation', current)]))),
                             ('host_a', 'host_q'), status=201)
        need(all(entry in accepted['catalog']['objects'] for entry in before['catalog']['objects']),
             'person-only dependency reconciliation keeps every immutable old proof')
        a.catalog = accepted['catalog']
        a.check_map(a.call('POST', route, body(replacement, a.catalog), host='host_c'),
                    ('host_a', 'host_q', 'host_c'), status=201)
        # Both failed fresh uses must leave their exact invitation reusable.
        need(a.check_map(a.call('POST', route, body(person, a.catalog)), ('host_a', 'host_q')) == accepted,
             'completed person-only retry retains its original immutable map after replacement admission')

    def operation_reconciles_capacity(self, runtime):
        a = self.author(runtime, rotated=True)
        a.check_map(a.call('POST', '/import', self.body(a, self.authorization(a))),
                    ('host_a', 'host_q', 'host_b'), status=201)
        self.member_limit(runtime, 3)
        roots = RootAuthor(a.oracle.vectors)
        activation = a.rebind(dict(a.base, activation=roots.epoch_activation(a.base, 1)),
                              label='capacity/current-epoch-C', target='host_c')
        transcript = Transcript(a, dict(a.base, activation=activation))
        transcript.values['request'].update(created_at=runtime.now, expires_at=shift(runtime.now, 300))
        transcript.values['owner']['certificate'].update(issued_at=runtime.now, not_after=shift(runtime.now, 90 * DAY))
        transcript.sign_certificate()
        for role, field in (('owner', 'binding_record'), ('administrator', 'admission_record')):
            record = transcript.values[role][field]
            unsigned = payload(record)
            unsigned['bound_at' if role == 'owner' else 'admitted_at'] = runtime.now
            record['payload_base64'] = b64(wire(unsigned))
            transcript.sign_record(record, a.person, draft=role == 'owner')
        activation = transcript.finish()
        route = '/' + a.network + '/link-operations'
        body = a.operation_body(activation)
        error(a.call('POST', route, body, host='host_c'), 409, 'quota_exceeded')
        before = a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b'))
        fields = {'host_public_key': a.hosts['host_b'].b64, 'revoked_at': runtime.now}
        old = a.signed_legacy('host_revocation', fields, a.root)
        current = a.signed_legacy('host_revocation', fields, a.tip)
        body['catalog'] = a.with_proofs(a.catalog, [('host_revocation', old)])
        error(a.call('POST', route, body, host='host_c'), 403, 'forbidden')
        need(a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b')) == before,
             'unauthorized operation dependency cannot free an occupied slot or partly admit its target')
        error(a.call('GET', route + '/' + activation['request']['request_id'], host='host_c'), 404, 'not_found')
        body['catalog'] = a.with_proofs(a.catalog, [('host_revocation', current)])
        result = a.check_result(a.call('POST', route, body, host='host_c'), activation)
        a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_c'))
        need(a.check_result(a.call('POST', route, body, host='host_c'), activation, status=200) == result,
             'replacement operation retries retain one immutable result without duplicate registration')

    @staticmethod
    def extra_host(a, name):
        seed = hashlib.sha256(('fresh-catalog/' + name).encode()).digest()
        a.hosts[name] = Key(a.runtime.root, seed)
        a.signers[a.hosts[name].b64] = FixtureSigner(seed)

    @staticmethod
    def timed_activation(a, target, label, created):
        activation = a.rebind(label=label, target=target)
        transcript = Transcript(a, dict(a.base, activation=activation))
        device = a.key(label + '/device')
        transcript.values['request'].update(created_at=created, expires_at=shift(created, 300), device_public_key=device)
        request = transcript.values['request']
        identity = 'link_' + digest(lines('peerspan-link-request-id-v1', request['coordinator_public_key'],
                                request['host_public_key'], device, request['request_nonce']))
        for packet in transcript.activation.values():
            if packet != '-':
                packet['request_id'] = identity
        transcript.values['owner']['certificate'].update(issued_at=created, not_after=shift(created, 90 * DAY),
                                                        device_public_key=device, request_id=identity)
        transcript.sign_certificate()
        for role, field in (('owner', 'binding_record'), ('administrator', 'admission_record')):
            record = transcript.values[role][field]
            record['operation_id'] = identity
            unsigned = payload(record)
            unsigned['bound_at' if role == 'owner' else 'admitted_at'] = created
            record['payload_base64'] = b64(wire(unsigned))
            transcript.sign_record(record, a.person, draft=role == 'owner')
        return transcript.finish()

    def fresh_redemption_catalog_first_use(self, runtime):
        a = self.author(runtime)
        a.check_map(a.call('POST', '/import', self.body(a, self.authorization(a))),
                    ('host_a', 'host_q', 'host_b'), status=201)
        before = a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b'))
        expired = a.redemption('host', 'none', style='legacy_root', host=a.hosts['host_c'].b64,
                              label='backdated', invite=a.key('fresh-catalog/expired-invite'),
                              joined=shift(runtime.now, -7200), expires=shift(runtime.now, -3600))
        ack = a.ack(a.hosts['host_c'].b64)
        source = a.with_proofs(a.catalog, [('invite_redemption', expired), ('join_ack', ack)])
        direct = {'redemption': expired, 'catalog': a.catalog, 'address': '', 'candidates': [], 'join_ack': ack}
        error(a.call('POST', '/' + a.network + '/invite-redemptions', direct, host='host_c'), 410, 'expired')
        error(a.call('POST', '/' + a.network + '/statements', {'catalog': source}), 410, 'expired')
        need(a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b')) == before,
             'backdated expired redemption in fresh statements grants no member/proof or invite-consumption state')
        fresh = a.redemption('host', 'none', style='legacy_root', host=a.hosts['host_c'].b64,
                            label='backdated', invite=a.key('fresh-catalog/expired-invite'),
                            joined=runtime.now, expires=shift(runtime.now, DAY))
        source = a.with_proofs(a.catalog, [('invite_redemption', fresh), ('join_ack', ack)])
        a.check_map(a.call('POST', '/' + a.network + '/statements', {'catalog': source}),
                    ('host_a', 'host_q', 'host_b', 'host_c'))

    def fresh_redemption_dependency_first_use(self, runtime):
        a = self.author(runtime)
        self.extra_host(a, 'host_d')
        a.check_map(a.call('POST', '/import', self.body(a, self.authorization(a))),
                    ('host_a', 'host_q', 'host_b'), status=201)
        activation = self.timed_activation(a, 'host_c', 'fresh-catalog/operation-C', runtime.now)
        before = a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b'))
        expired = a.redemption('host', 'none', style='legacy_root', host=a.hosts['host_d'].b64,
                              label='dependency', invite=a.key('fresh-catalog/dependency-invite'),
                              joined=shift(runtime.now, -7200), expires=shift(runtime.now, -3600))
        body = a.operation_body(activation)
        body['catalog'] = a.with_proofs(a.catalog, [('invite_redemption', expired), ('join_ack', a.ack(a.hosts['host_d'].b64))])
        route = '/' + a.network + '/link-operations'
        error(a.call('POST', route, body, host='host_c'), 410, 'expired')
        error(a.call('GET', route + '/' + activation['request']['request_id'], host='host_c'), 404, 'not_found')
        need(a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b')) == before,
             'expired redemption dependency cannot be reconciled as admission during an otherwise valid new operation')
        fresh = a.redemption('host', 'none', style='legacy_root', host=a.hosts['host_d'].b64,
                            label='dependency', invite=a.key('fresh-catalog/dependency-invite'),
                            joined=runtime.now, expires=shift(runtime.now, DAY))
        body['catalog'] = a.with_proofs(a.catalog, [('invite_redemption', fresh), ('join_ack', a.ack(a.hosts['host_d'].b64))])
        a.check_result(a.call('POST', route, body, host='host_c'), activation)
        a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b', 'host_c', 'host_d'))

    def fresh_activation_catalog_first_use(self, runtime):
        a = self.author(runtime)
        self.extra_host(a, 'host_d')
        a.check_map(a.call('POST', '/import', self.body(a, self.authorization(a))),
                    ('host_a', 'host_q', 'host_b'), status=201)
        before = a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b'))
        expired = self.timed_activation(a, 'host_d', 'fresh-catalog/expired-operation-D', shift(runtime.now, -600))
        route = '/' + a.network + '/link-operations'
        error(a.call('POST', route, a.operation_body(expired), host='host_d'), 410, 'expired')
        source = a.with_proofs(a.catalog, [('activation', expired)])
        error(a.call('POST', '/' + a.network + '/statements', {'catalog': source}), 410, 'expired')
        activation = self.timed_activation(a, 'host_c', 'fresh-catalog/operation-C-with-D', runtime.now)
        body = a.operation_body(activation)
        body['catalog'] = source
        error(a.call('POST', route, body, host='host_c'), 410, 'expired')
        need(a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b')) == before,
             'expired new activation cannot bypass exact direct-route deadline through statements or operation dependencies')
        error(a.call('GET', route + '/' + activation['request']['request_id'], host='host_c'), 404, 'not_found')
        fresh = self.timed_activation(a, 'host_d', 'fresh-catalog/current-operation-D', runtime.now)
        body['catalog'] = a.with_proofs(a.catalog, [('activation', fresh)])
        a.check_result(a.call('POST', route, body, host='host_c'), activation)
        a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b', 'host_c', 'host_d'))

    def build(self):
        for name in ('bindings_and_retry', 'membership_and_sticky_state', 'repair_authenticates_prior_sender',
                     'withdrawn_activation_is_inert_provenance',
                     'rotation_does_not_bootstrap_new_issuer', 'current_root_and_fresh_writers', 'person_label_conflicts',
                     'same_pin_older_backup', 'moves_and_new_target', 'actual_successor_catalog',
                     'fresh_dependencies_require_current_authority', 'first_feature_dependencies_require_current_authority',
                     'person_redemption_reconciles_capacity', 'operation_reconciles_capacity',
                     'fresh_redemption_catalog_first_use', 'fresh_redemption_dependency_first_use',
                     'fresh_activation_catalog_first_use'):
            self.run(name, getattr(self, name))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--coordinator', required=True)
    parser.add_argument('--section', action='append')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='peerspan-link-imports-') as temporary:
        suite = Suite(args, Path(temporary))
        suite.build()
        print(f'{suite.sections} import sections passed; {suite.failures} failed; {suite.requests} authenticated requests.', flush=True)
        return int(bool(suite.failures))


if __name__ == '__main__':
    sys.exit(main())
