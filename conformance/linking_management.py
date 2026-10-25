#!/usr/bin/env python3
"""Independent active-link management and recovery runtime checks.

Only public contracts, independent signing helpers, public routes and documented
durable categories are used. An accepted historical receipt is never freshness.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import hashlib
import http.client
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import traceback
from types import SimpleNamespace

from launch_service import host_key
from linking_activations import Transcript, payload, proof, semantic_id
from linking_activations import shift
from linking_hosts import Ceremony, checked, full_chain, need
from linking_mailboxes import Runtime, ok
from linking_mailboxes import error
from linking_policy_state import legacy_group_message
from linking_readers import Author as ReaderOracle, FixtureSigner, b64, digest, lines, unb64, wire
from linking_readers import message
from peer_messaging import fixture_context, set_probe, wire as peer_wire
from persons import ssh_key, ssh_sign
from capabilities import Fixture, cap_rule, policy_lines_v2


def network(host, identity):
    return next(value for value in checked(host.call('GET', '/v1/networks')) if value['id'] == identity)


def pending_rotations(host, identity):
    with sqlite3.connect(host.state / 'host.db') as db:
        return [json.loads(row[0]) for row in db.execute(
            "SELECT record FROM network_statements WHERE network_id=? AND kind='pending_rotation'", (identity,))]


def rotation_event_count(host, identity):
    events = checked(host.call('GET', '/v1/activity?after=0&limit=1000'))
    return sum(value['kind'] == 'network.root_rotated' and value['subject_id'] == identity for value in events)


def pending_rotation_retry(c):
    full_chain(c)
    c.a.start()
    c.a.cli('network', 'sync', c.network, sock=None)
    root_group = {'network_id': c.network, 'name': 'rotation-root-group', 'version': 8,
                  'defined_at': c.runtime.now, 'members': [c.person_id]}
    with sqlite3.connect(c.a.state / 'host.db') as db:
        seed = bytes(db.execute('SELECT root_seed FROM networks WHERE id=?', (c.network,)).fetchone()[0])
    root = FixtureSigner(seed)
    root_group['signature'] = b64(root.raw(legacy_group_message(root_group)))
    directory = c.root / 'root-group-transport'
    directory.mkdir()
    tls = host_key(c.a, directory)
    addition = {'format': 1, 'network_id': c.network, 'objects': [proof('group', root_group)]}
    ok(c.runtime.call('POST', '/coord/v2/networks/' + c.network + '/statements', {'catalog': addition}, key=tls), 200)
    device_group = {'network_id': c.network, 'name': 'rotation-device-group', 'version': 7,
                    'defined_at': c.runtime.now, 'members': [c.person_id]}
    device = c.action(c.c, 'peerspan-group-v1', device_group)
    c.a.cli('network', 'sync', c.network, sock=None)
    before = network(c.a, c.network)
    retained = c.a.public_catalog(c.network)
    with sqlite3.connect(c.a.state / 'host.db') as db:
        feature_before = db.execute('SELECT record FROM link_features WHERE network_id=?', (c.network,)).fetchone()[0]
        water_before = db.execute('SELECT kind,subject,version,record_hash FROM link_highwater WHERE network_id=? ORDER BY kind,subject', (c.network,)).fetchall()
    providers = {host.state.name: checked(host.call('GET', '/v1/networks/' + c.network + '/link-signer')) for host in (c.b, c.c)}
    events = rotation_event_count(c.a, c.network)
    c.runtime.stop()
    failure = c.a.run('network', 'rotate-root', c.network, sock=None)
    need(failure.returncode != 0, 'unreachable rotation CLI reports failure instead of claiming acceptance', failure.stderr)
    pending = pending_rotations(c.a, c.network)
    need(len(pending) == 1, 'exactly one root transition is durable before coordinator submission')
    new_seed = unb64(pending[0]['root_seed'])
    next_root = b64(FixtureSigner(new_seed).public)
    need(next_root == pending[0]['rotation']['root_public_key'] and next_root != b64(root.public),
         'durable pending seed independently derives the exact signed proposed root')
    need(network(c.a, c.network)['root_epoch'] == before['root_epoch'] and
         rotation_event_count(c.a, c.network) == events, 'failed submission keeps old epoch and no applied-root event')
    c.a.stop()
    c.a.start()
    need(pending_rotations(c.a, c.network) == pending, 'restart preserves exact signed pending rotation and seed')
    c.runtime.start()
    synced = c.a.cli('network', 'sync', c.network, sock=None)
    need(synced['root_epoch'] == before['root_epoch'] + 1 and synced['last_sync_error'] is None,
         'ordinary active sync completes the original pending root transition before projection')
    with sqlite3.connect(c.a.state / 'host.db') as db:
        installed_seed = bytes(db.execute('SELECT root_seed FROM networks WHERE id=?', (c.network,)).fetchone()[0])
        feature_after = db.execute('SELECT record FROM link_features WHERE network_id=?', (c.network,)).fetchone()[0]
        water_after = db.execute('SELECT kind,subject,version,record_hash FROM link_highwater WHERE network_id=? ORDER BY kind,subject', (c.network,)).fetchall()
    need(installed_seed == new_seed and b64(FixtureSigner(installed_seed).public) == next_root,
         'current epoch and exact accepted new seed are installed atomically')
    need(not pending_rotations(c.a, c.network) and rotation_event_count(c.a, c.network) == events + 1,
         'pending transition clears with exactly one applied-root event')
    need(feature_after == feature_before, 'root transition retains the exact durable feature')
    after = c.a.public_catalog(c.network)
    need(all(entry in after['objects'] for entry in retained['objects']), 'rotation preserves every original signed proof byte')
    current_marks = {(kind, subject): (version, record_hash)
                     for kind, subject, version, record_hash in water_after}
    for kind, subject, old_version, old_hash in water_before:
        need((kind, subject) in current_marks, 'rotation retains every previously observed access subject')
        new_version, new_hash = current_marks[(kind, subject)]
        old_version = int.from_bytes(old_version, 'big') if isinstance(old_version, bytes) else old_version
        new_version = int.from_bytes(new_version, 'big') if isinstance(new_version, bytes) else new_version
        need(new_version >= old_version and (new_version > old_version or new_hash == old_hash),
             'rotation retains or advances each high-water mark without changing an equal-version selection')
    groups = checked(c.a.call('GET', '/v1/networks/' + c.network + '/groups'))
    renewed = next(value for value in groups if value['name'] == root_group['name'])
    need(renewed['version'] == 9, 'active root group renews at guarded next version after feature activation')
    selected = next(value for value in groups if value['name'] == device_group['name'])
    need(selected['version'] == 7 and selected['authorization_base64'] == device['record_base64'],
         'device-signed group is retained exactly instead of reissued as root authority')
    for host in (c.b, c.c):
        synced = host.cli('network', 'sync', c.network, sock=None)
        need(synced['root_epoch'] == before['root_epoch'] + 1 and synced['last_sync_error'] is None,
             'root renewal plan includes actual linked host memberships')
        need(checked(host.call('GET', '/v1/networks/' + c.network + '/link-signer')) == providers[host.state.name],
             'root rotation preserves selected original person/device provider')
        need(not host.key_file.exists(), 'root recovery never creates or copies an original key onto linked machines')
    c.a.cli('network', 'sync', c.network, sock=None)
    need(rotation_event_count(c.a, c.network) == events + 1 and not pending_rotations(c.a, c.network),
         'ordinary sync retry cannot duplicate root transition application')
    c.no_secrets()


def competing_rotation_retires_only_refused_pending(c):
    full_chain(c)
    c.a.start()
    c.a.cli('network', 'sync', c.network, sock=None)
    with sqlite3.connect(c.a.state / 'host.db') as db:
        original = FixtureSigner(bytes(db.execute('SELECT root_seed FROM networks WHERE id=?', (c.network,)).fetchone()[0]))
    epoch = network(c.a, c.network)['root_epoch'] + 1
    c.b.stop()
    c.c.stop()
    c.runtime.stop()
    failed = c.a.run('network', 'rotate-root', c.network, sock=None)
    need(failed.returncode != 0, 'unreachable coordinator preserves an unresolved root transition')
    pending = pending_rotations(c.a, c.network)
    need(len(pending) == 1, 'one exact pending transition exists before a competing accepted rotation')
    c.a.stop()
    competing = FixtureSigner(bytes([112]) * 32)
    current = b64(competing.public)
    need(current != pending[0]['rotation']['root_public_key'], 'independent competing root differs from rejected proposed seed')
    rotation = {'network_id': c.network, 'epoch': epoch, 'previous_root_public_key': b64(original.public),
                'root_public_key': current, 'rotated_at': c.runtime.now}
    rotation['signature'] = b64(original.raw(lines('peerspan-root-rotate-v1', *(rotation[field] for field in
                                      ('network_id', 'epoch', 'previous_root_public_key', 'root_public_key', 'rotated_at')))))
    admitted = {'network_id': c.network, 'epoch': epoch, 'person_public_key': c.person,
                'member': 'alice', 'admitted_at': c.runtime.now}
    admitted['signature'] = b64(competing.raw(lines('peerspan-person-admit-v1', c.network, epoch, c.person, 'alice', c.runtime.now)))
    delegated = {'network_id': c.network, 'epoch': epoch, 'person_public_key': c.person, 'delegated_at': c.runtime.now}
    delegated['signature'] = b64(competing.raw(lines('peerspan-admin-delegate-v1', c.network, epoch, c.person, c.runtime.now)))
    objects = [proof('rotation', rotation), proof('person_admission', admitted), proof('admin_delegation', delegated)]
    for host in (c.a, c.b, c.c):
        key = c.identity[host.state.name]['public_key']
        attested = {'network_id': c.network, 'epoch': epoch, 'host_public_key': key,
                    'member': 'alice', 'attested_at': c.runtime.now}
        attested['signature'] = b64(competing.raw(lines('peerspan-attest-v1', c.network, epoch, key, 'alice', c.runtime.now)))
        objects.append(proof('attestation', attested))
    c.runtime.start()
    directory = c.root / 'competing-rotation-transport'
    directory.mkdir()
    accepted = ok(c.runtime.call('POST', '/coord/v2/networks/' + c.network + '/statements',
                  {'catalog': {'format': 1, 'network_id': c.network, 'objects': sorted(objects, key=lambda entry: entry['id'])}},
                  key=host_key(c.a, directory)), 200)
    need(all(entry in accepted['catalog']['objects'] for entry in objects), 'actual coordinator accepts the independent current-root renewal batch')
    c.a.start()
    # The first explicit sync may report its definitive refusal. A subsequent
    # ordinary sync is a separate operation after that exact pending row retires.
    c.a.run('network', 'sync', c.network, sock=None)
    need(not pending_rotations(c.a, c.network), 'authenticated same-epoch fork refusal retires only the rejected pending transition')
    learned = c.a.cli('network', 'sync', c.network, sock=None)
    with sqlite3.connect(c.a.state / 'host.db') as db:
        seed = db.execute('SELECT root_seed FROM networks WHERE id=?', (c.network,)).fetchone()[0]
    need(learned['root_epoch'] == epoch and learned['last_sync_error'] is None and seed is None,
         'fresh sync learns the accepted competing root without installing the refused proposed seed or retaining the obsolete seed')
    need(proof('rotation', rotation) in c.a.public_catalog(c.network)['objects'], 'accepted competing rotation is retained exactly')
    c.no_secrets()


def import_preview_reclaims_only_safe_expired_rows(c):
    full_chain(c)
    c.a.start()
    c.a.cli('network', 'sync', c.network, sock=None)
    route = '/v1/networks/' + c.network + '/feature-import'
    targets, previews = [], []
    def intents():
        with sqlite3.connect(c.a.state / 'host.db') as db:
            return {subject: raw for subject, raw in db.execute(
                "SELECT subject,record FROM network_statements WHERE network_id=? AND kind='link_feature_import_intent'", (c.network,))}
    try:
        for index in range(9):
            target = Runtime(c.args.coordinator, c.root / ('preview-target-' + str(index)), initial=c.runtime.now)
            targets.append(target)
            info = json.loads(target.command('info').stdout)
            body = {'coordinator_address': f'127.0.0.1:{target.port}', 'coordinator_public_key': info['public_key'],
                    'import_id': '-', 'approve': False}
            if index == 8:
                refused = c.a.call('POST', route, body)
                error((refused[0], {}, refused[1]), 409, 'quota_exceeded')
            else:
                preview = checked(c.a.call('POST', route, body))
                need(preview['signing_requests'] == [] and not preview['committed'], 'preview quota stores no signature or submitted mutation')
                previews.append((body, preview['import_id']))
        need(len(intents()) == 8, 'eight explicit immutable preview intents fill the documented per-network quota')
        # A genuinely attempted request with an unavailable target remains an
        # unresolved submitted outcome, rather than an invented private row.
        targets[0].stop()
        first_body, first_id = previews[0]
        attempted = c.a.call('POST', route, dict(first_body, import_id=first_id, approve=True))
        need(isinstance(attempted[1], dict), 'uncertain target submission retains a structured local response')
        unknown = intents()[first_id]
        value = json.loads(unknown)
        need(value['approved'] and value['submitted'] and value['state'] != 'complete' and value['signature'] != '-',
             'actual unavailable-target submission persists its exact approved signed unknown outcome')
        deadline = json.loads(unb64(value['authorization_template_base64']))['expires_at']
        c.runtime.set_time(shift(deadline, 24 * 3600 + 1))
        info = json.loads(targets[8].command('info').stdout)
        fresh = checked(c.a.call('POST', route, {'coordinator_address': f'127.0.0.1:{targets[8].port}',
                        'coordinator_public_key': info['public_key'], 'import_id': '-', 'approve': False}))
        retained = intents()
        need(set(retained) == {first_id, fresh['import_id']} and retained[first_id] == unknown,
             'past deadline-plus24h only unsubmitted previews are reclaimed; unknown submitted authorization remains byte-for-byte unchanged')
        c.no_secrets()
    finally:
        for target in targets:
            target.close()


def recovery_receipt_preserves_later_proofs(c):
    full_chain(c)
    c.a.start()
    c.a.cli('network', 'sync', c.network, sock=None)
    provider = c.root / 'external-repair-root'
    provider.mkdir()
    private_key, _, public_key = ssh_key(provider, 'root')
    c.a.cli('network', 'rotate-root', c.network, '--to-ssh', '--root-key', str(private_key), sock=None)
    c.c.cli('network', 'sync', c.network, sock=None)
    target = Runtime(c.args.coordinator, c.root / 'recovery-target', initial=c.runtime.now)
    try:
        info = json.loads(target.command('info').stdout)
        address, key = f'127.0.0.1:{target.port}', info['public_key']
        route = '/v1/networks/' + c.network + '/feature-import'
        body = {'coordinator_address': address, 'coordinator_public_key': key, 'import_id': '-', 'approve': False}
        # The sibling learned external-root format only through independently
        # verified current-epoch evidence; it holds no root seed or SSH key.
        sibling_preview = checked(c.c.call('POST', route, body))
        sibling_approved = checked(c.c.call('POST', route, dict(body, import_id=sibling_preview['import_id'], approve=True)))
        need(sibling_approved['committed'] is False and len(sibling_approved['signing_requests']) == 1 and
             sibling_approved['signing_requests'][0]['signer_public_key'] == public_key and
             sibling_approved['signing_requests'][0]['signature_format'] == 'sshsig' and
             sibling_approved['signing_requests'][0]['object_type'] == 'feature_import',
             'remote external-root rotation preserves the exact sibling public SSH signing slot without granting its device root authority')
        before_pin = network(c.a, c.network)
        preview = checked(c.a.call('POST', route, body))
        need(set(preview) == {'import_id', 'review', 'signing_requests', 'committed'} and
             preview['signing_requests'] == [] and preview['committed'] is False,
             'root repair preview freezes public intent without signing, submitting or switching pin')
        identity = preview['import_id']
        approved = checked(c.a.call('POST', route, dict(body, import_id=identity, approve=True)))
        need(len(approved['signing_requests']) == 1 and approved['committed'] is False,
             'external-root approval exposes exactly one fixed dependency-ready signing slot')
        request = approved['signing_requests'][0]
        need(set(request) == {'object_type', 'message_base64', 'signer_public_key', 'signature_format'} and
             request['object_type'] == 'feature_import' and request['signer_public_key'] == public_key and
             request['signature_format'] == 'sshsig', 'repair uses reviewed current external root, never owner/device fallback')
        def intent():
            with sqlite3.connect(c.a.state / 'host.db') as db:
                row = db.execute("SELECT record FROM network_statements WHERE network_id=? AND kind='link_feature_import_intent' AND subject=?",
                                 (c.network, identity)).fetchone()
            need(row is not None, 'approved public recovery intent persists before signature/submission')
            return json.loads(row[0])
        frozen = intent()
        template = json.loads(unb64(frozen['authorization_template_base64']))
        expected_message = lines('peerspan-link-feature-import-v1', *(template[field] for field in
                ('network_id', 'network_name', 'epoch', 'feature_id', 'coordinator_address',
                 'coordinator_public_key', 'catalog_sha256', 'issued_at', 'expires_at')))
        need(request['message_base64'] == b64(expected_message) and template['signature'] == '-' and
             template['catalog_sha256'] == digest(unb64(frozen['catalog_base64'])) and
             identity == 'lfi_' + digest(lines('peerspan-link-feature-import-intent-v1', c.network,
                    address, key, template['catalog_sha256'], template['issued_at'])),
             'external repair signs only independently derived exact reviewed target and original snapshot bytes')
        c.a.stop()
        snapshot = c.root / 'pre-submit-host-snapshot'
        shutil.copytree(c.a.state, snapshot, ignore=shutil.ignore_patterns('admin.sock'))
        c.a.start()
        preimage = provider / 'message'
        preimage.write_bytes(expected_message)
        signed = subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(private_key), '-n', 'peerspan-person-v1', str(preimage)],
                                capture_output=True, timeout=10)
        need(signed.returncode == 0, 'external root signs only the fixed public recovery message', signed.stderr)
        armor = preimage.with_suffix('.sig').read_text().splitlines()
        signature = b64(unb64(''.join(line for line in armor if not line.startswith('-----'))))
        c.verify_signature(public_key, expected_message, signature)
        submitted = checked(c.a.call('POST', route + '/' + identity + '/signed',
                                      {'object_type': 'feature_import', 'signature': signature}))
        need(submitted['committed'] is True, 'actual new target commits the reviewed original immutable import outcome')
        original_receipt = intent()['result_map_base64']
        # Replay the documented exact submitted public intent beside the genuine
        # stopped pre-submit state to model a lost response. An older approved
        # but never-submitted snapshot must still satisfy fresh-write checks.
        c.a.stop()
        shutil.rmtree(c.a.state)
        shutil.copytree(snapshot, c.a.state)
        submitted_replay = dict(frozen, state='submitted', signature=signature,
                                submitted=True, result_map_base64='-')
        with sqlite3.connect(c.a.state / 'host.db') as db:
            changed = db.execute("UPDATE network_statements SET record=? WHERE network_id=? AND kind='link_feature_import_intent' AND subject=?",
                                 (wire(submitted_replay).decode(), c.network, identity)).rowcount
        need(changed == 1, 'replay only the exact documented public submitted intent after actual target commitment')
        c.a.start()
        need(intent() == submitted_replay, 'lost-response fixture keeps exact signed public request and target pins')
        policy = {'format': 2, 'network_id': c.network, 'person_public_key': c.person,
                  'version': 52, 'issued_at': c.runtime.now, 'valid_until': shift(c.runtime.now, 86400),
                  'rules': [], 'capability_rules': [], 'trusted_hosts': [], 'edits': []}
        later = c.action(c.c, 'peerspan-policy-v2', policy)
        c.a.cli('network', 'sync', c.network, sock=None)
        before = c.access_snapshot(c.a)
        need(later['proof_id'] in {entry['id'] for entry in c.a.public_catalog(c.network)['objects']},
             'restored local host independently learns a later valid proof before retry')
        repeated = checked(c.a.call('POST', route + '/' + identity + '/signed',
                                     {'object_type': 'feature_import', 'signature': signature}))
        need(repeated['committed'] is True and intent()['result_map_base64'] == original_receipt,
             'exact retry verifies and retains target original historical outcome despite later local evidence')
        need(c.access_snapshot(c.a) == before, 'historical recovery unions all newer local proofs, marks and reservations without rollback')
        after_pin = network(c.a, c.network)
        need(all(after_pin[field] == before_pin[field] for field in ('coordinator_address', 'coordinator_public_key')),
             'target import completion alone cannot switch the current independently pinned coordinator')
        need(not c.b.key_file.exists() and not c.c.key_file.exists(), 'root repair never copies private root/person keys onto linked hosts')
        c.no_secrets()
    finally:
        target.close()


def peer_sender_must_precede_incoming_grants(c):
    full_chain(c)
    c.a.start()
    c.a.cli('network', 'sync', c.network, sock=None)
    c.b.cli('network', 'sync', c.network, sock=None)
    path = '/peer/v1/networks/' + c.network + '/link-catalog'
    need(peer_wire(c.a, fixture_context(c.b), 'GET', path)[0] == 200,
         'positive current sender can fetch active public catalog before withdrawal')
    catalog = c.a.public_catalog(c.network)
    activations = [json.loads(unb64(entry['body_base64'])) for entry in catalog['objects'] if entry['kind'] == 'activation']
    target_key = checked(c.c.call('GET', '/v1/host'))['public_key']
    activation = next(value for value in activations if payload(value['request'])['host_public_key'] == target_key)
    records = [payload(activation['commit'])['binding_record'], payload(activation['administrator'])['admission_record']]
    checkpoint = {'format': 1, 'network_id': c.network, 'person_public_key': c.person,
                  'issuer_certificate_id': 'root', 'issued_at': c.runtime.now,
                  'records': sorted(semantic_id('person_record', record) for record in records)}
    directory = c.root / 'peer-withdrawal-root-provider'
    directory.mkdir()
    preimage = directory / 'checkpoint-message'
    preimage.write_bytes(message('checkpoint', checkpoint))
    signed = subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(c.a.key_file), '-n', 'peerspan-person-v1', str(preimage)],
                            capture_output=True, timeout=10)
    need(signed.returncode == 0, 'original person explicitly endorses exact child history before ancestor withdrawal', signed.stderr)
    checkpoint['signature'] = ''.join(line for line in preimage.with_suffix('.sig').read_text().splitlines()
                                     if not line.startswith('-----'))
    c.verify_signature(c.person, message('checkpoint', checkpoint), checkpoint['signature'])
    with sqlite3.connect(c.a.state / 'host.db') as db:
        seed = bytes(db.execute('SELECT root_seed FROM networks WHERE id=?', (c.network,)).fetchone()[0])
    root = FixtureSigner(seed)
    b_key = checked(c.b.call('GET', '/v1/host'))['public_key']
    revocation = {'network_id': c.network, 'host_public_key': b_key, 'revoked_at': c.runtime.now}
    revocation['signature'] = b64(root.raw(lines('peerspan-revoke-host-v1', c.network, b_key, c.runtime.now)))
    source = json.loads(wire(catalog))
    source['objects'] += [proof('checkpoint', checkpoint), proof('host_revocation', revocation)]
    source['objects'].sort(key=lambda value: value['id'])
    need(peer_wire(c.a, fixture_context(c.b), 'POST', path, body={'catalog': source})[0] == 200,
         'prior-current sender may replicate valid signed evidence that removes itself')
    members = checked(c.a.call('GET', '/v1/networks/' + c.network + '/members'))
    need(b_key not in {member['public_key'] for member in members}, 'self-withdrawal takes effect after incoming catalog verification')
    before = c.access_snapshot(c.a)
    for method, body in (('GET', None), ('POST', {'catalog': source})):
        try:
            status = peer_wire(c.a, fixture_context(c.b), method, path, body=body)[0]
            need(status == 403, 'known removed sender cannot use later active catalog requests', method, status)
        except OSError:
            # The existing inbound TLS known-host gate may reject before HTTP.
            pass
    implementation = 'go' if str(c.b.binary) == str(c.args.go) else 'rust'
    outsider = c.host('NeverAdmitted', implementation)
    outsider.start()
    key_context = fixture_context(outsider)
    outsider_signer = FixtureSigner(bytes.fromhex(key_context['seed_hex']))
    outsider_key = b64(outsider_signer.public)
    admission = {'network_id': c.network, 'epoch': 0, 'host_public_key': outsider_key,
                 'member': 'incoming-only', 'admitted_at': c.runtime.now}
    admission['signature'] = b64(root.raw(lines('peerspan-host-admit-v1', c.network, 0,
                                               outsider_key, 'incoming-only', c.runtime.now)))
    feature = next(json.loads(unb64(entry['body_base64'])) for entry in source['objects'] if entry['kind'] == 'feature')
    ack = {'format': 1, 'feature_id': semantic_id('feature_proposal', feature['proposal']), 'host_public_key': outsider_key}
    ack['signature'] = outsider_signer.sshsig(message('feature_ack', ack))
    candidate = json.loads(wire(source))
    candidate['objects'] += [proof('host_admission', admission), proof('join_ack', ack)]
    candidate['objects'].sort(key=lambda value: value['id'])
    try:
        status = peer_wire(c.a, key_context, 'POST', path, body={'catalog': candidate})[0]
        need(status == 403, 'incoming valid new grant cannot establish its own sender pre-admission', status)
    except OSError:
        pass
    need(peer_wire(c.a, fixture_context(c.c), 'GET', path)[0] == 200,
         'independent retained current member remains an authenticated positive transport control')
    need(c.access_snapshot(c.a) == before, 'removed-sender retries cannot mutate public evidence or access marks')
    c.no_secrets()


def withdrawal_keeps_exact_history(c):
    full_chain(c)
    c.a.start()
    c.a.cli('network', 'sync', c.network, sock=None)
    group = {'network_id': c.network, 'name': 'withdrawal-current-device', 'version': 7,
             'defined_at': c.runtime.now, 'members': [c.person_id]}
    signed_group = c.action(c.c, 'peerspan-group-v1', group)
    c.a.cli('network', 'sync', c.network, sock=None)
    original = c.a.public_catalog(c.network)
    needed = {'record:' + signed_group['record_id']}
    for entry in original['objects']:
        if entry['kind'] == 'activation':
            activation = json.loads(unb64(entry['body_base64']))
            if activation['administrator'] != '-':
                admission = payload(activation['administrator'])['admission_record']
                if admission.get('person_public_key') == c.person:
                    needed.add('record:' + semantic_id('person_record', admission))
    route = '/v1/networks/' + c.network
    before = c.access_snapshot(c.a)
    plan_route = route + '/admin-removal-plan?person=' + c.person_id + '&format=2'
    plan = checked(c.a.call('GET', plan_route))
    need(set(plan) == {'format', 'person_public_key', 'kept'} and plan['format'] == 2 and
         plan['person_public_key'] == c.person and plan['kept'] == sorted(set(plan['kept'])) and
         needed <= set(plan['kept']), 'format2 plan retains exact nested administrator grants and selected active group')
    need(c.access_snapshot(c.a) == before, 'format2 plan is read-only and signs nothing')
    for query in ('&format=2', '&unknown=1'):
        rejected = c.a.call('GET', plan_route + query)
        need(rejected[0] == 400 and c.access_snapshot(c.a) == before,
             'duplicate/unknown plan query rejects without persistent mutation')
    c.runtime.stop()
    result = checked(c.a.call('POST', route + '/admin-removals', {'person': c.person_id, 'revoke_admitted': False}), 201)
    need(result['kind'] == 'admin' and result['submitted'] is False,
         'format2 withdrawal applies locally while publication remains unknown')
    def removals():
        return [json.loads(unb64(entry['body_base64'])) for entry in c.a.public_catalog(c.network)['objects']
                if entry['kind'] == 'admin_removal']
    removal = next(value for value in removals() if value['person_public_key'] == c.person and not value['revoke_admitted'])
    need(removal['format'] == 2 and removal['kept'] == plan['kept'], 'root generation signs the exact reviewed retention plan')
    need(all(entry in c.a.public_catalog(c.network)['objects'] for entry in original['objects']),
         'local withdrawal preserves every original signed proof byte')
    c.a.stop()
    c.a.start()
    need(removal in removals(), 'unknown-publication restart preserves the immutable signed withdrawal')
    c.runtime.start()
    c.a.cli('network', 'sync', c.network, sock=None)
    checked(c.a.call('POST', route + '/admin-removals', {'person': c.person_id, 'revoke_admitted': False}), 201)
    need(removals() == [removal], 'generated plain retry reuses the original signed bytes and kept list')
    for host in (c.b, c.c):
        host.cli('network', 'sync', c.network, sock=None)
        people = checked(host.call('GET', route + '/persons'))
        person = next(value for value in people if value['public_key'] == c.person)
        need(not person['administrator'], 'plain withdrawal preserves admitted person and exact linked-host history')
        need(not host.key_file.exists(), 'withdrawal never generates an original key on a linked machine')
    need(not any(value['name'] == group['name'] for value in checked(c.c.call('GET', route + '/groups'))),
         'withdrawn administrator group is inactive despite exact retention')
    versions = checked(c.c.call('GET', route + '/link-access-versions'))
    need(next(value for value in versions['groups'] if value['name'] == group['name'])['version'] == 7,
         'inactive group maximum remains retained without lower-version resurrection')
    policy = {'format': 2, 'network_id': c.network, 'person_public_key': c.person, 'version': 71,
              'issued_at': c.runtime.now, 'valid_until': shift(c.runtime.now, 86400),
              'rules': [], 'capability_rules': [], 'trusted_hosts': [], 'edits': []}
    c.action(c.c, 'peerspan-policy-v2', policy)
    before = c.access_snapshot(c.c)
    denied = c.c.call('POST', route + '/link-actions',
                      {'kind': 'peerspan-group-v1', 'certificate_id': 'auto',
                       'payload_base64': b64(wire(dict(group, version=8, defined_at=c.runtime.now)))})
    error((denied[0], {}, denied[1]), 403, 'forbidden')
    need(c.access_snapshot(c.c) == before and 'record_base64' not in denied[1],
         'lost administrator role refuses before a new group signature while owner policy remains usable')
    exact = {'removal_base64': b64(wire(removal))}
    checked(c.a.call('POST', route + '/admin-removals', exact), 201)
    before = c.access_snapshot(c.a)
    for extra in ({'person': ''}, {'revoke_admitted': False}, {'removal': {}}):
        rejected = c.a.call('POST', route + '/admin-removals', dict(exact, **extra))
        need(rejected[0] == 400 and c.access_snapshot(c.a) == before,
             'explicit signed withdrawal is mutually exclusive even with empty/false legacy fields')
    escalated = checked(c.a.call('POST', route + '/admin-removals', {'person': c.person_id, 'revoke_admitted': True}), 201)
    need(escalated['submitted'] is True and any(value['revoke_admitted'] for value in removals()),
         'irreversible revoke-admitted escalation keeps the prior withdrawal and publishes its own exact record')
    c.no_secrets()


def selected_device_status_requires_policy_scope(c):
    c.complete(c.b, c.a)
    c.a.cli('allow', 'network', '--agent', '*', '--network', c.network, sock=None)
    c.b.cli('network', 'sync', c.network, sock=None)
    request_id = c.complete(c.b, c.a, mode='renew')
    original = c.assert_provider(c.b, request_id)
    request = payload(original['request'])
    with sqlite3.connect(c.b.state / 'host.db') as db:
        seed = bytes(db.execute('SELECT seed FROM link_device_keys WHERE public_key=?', (request['device_public_key'],)).fetchone()[0])
    device = FixtureSigner(seed)
    host = FixtureSigner(bytes.fromhex(fixture_context(c.b)['seed_hex']))
    need(b64(device.public) == request['device_public_key'] and b64(host.public) == request['host_public_key'],
         'only the actual fixture-owned target host/device keys sign the narrowed transcript')
    signing = c.root / 'narrow-scope-original-signatures'
    signing.mkdir()
    class OriginalSigner:
        def sshsig(self, msg, **options):
            need(not options, 'narrowed fixture uses the normal original-person signature format')
            return ssh_sign(msg.decode('utf-8').split('\n'), c.a.key_file, signing)
    class Oracle:
        resign = ReaderOracle.resign
    oracle = Oracle()
    oracle.signers = {c.person: OriginalSigner(), request['device_public_key']: device,
                      request['host_public_key']: host}
    transcript = Transcript(SimpleNamespace(oracle=oracle, signers=oracle.signers), {'activation': original})
    nonce = b64(hashlib.sha256(b'policy-scope-status-fixture' + unb64(request['request_nonce'])).digest())
    target_id = 'link_' + digest(lines('peerspan-link-request-id-v1', request['coordinator_public_key'],
                                     request['host_public_key'], request['device_public_key'], nonce))
    transcript.values['request']['request_nonce'] = nonce
    for packet in transcript.activation.values():
        if packet != '-':
            packet['request_id'] = target_id
    certificate = transcript.values['owner']['certificate']
    certificate.update(request_id=target_id, scopes=2)
    transcript.sign_certificate()
    narrowed = transcript.finish()
    selected = semantic_id('certificate', payload(narrowed['owner'])['certificate'])
    source = c.b.public_catalog(c.network)
    source['objects'].append(proof('activation', narrowed))
    source['objects'].sort(key=lambda entry: entry['id'])
    c.verify_transcript(narrowed, [original, narrowed])
    need(peer_wire(c.b, fixture_context(c.a), 'POST', '/peer/v1/networks/' + c.network + '/link-catalog',
                   body={'catalog': source})[0] == 200,
         'the narrowed complete public transcript passes the existing authenticated historical catalog verifier')
    c.b.stop()
    with sqlite3.connect(c.b.state / 'host.db') as db:
        row = db.execute('SELECT person_key,device_key,certificate_id FROM link_signers WHERE network_id=?', (c.network,)).fetchone()
        need(row[:2] == (c.person, request['device_public_key']), 'selected fixture still owns the exact same person/device')
        need(db.execute('UPDATE link_signers SET certificate_id=? WHERE network_id=? AND certificate_id=?',
                        (selected, c.network, row[2])).rowcount == 1,
             'the fixture changes only the documented exact selected certificate reference')
    c.b.start()
    provider = checked(c.b.call('GET', '/v1/networks/' + c.network + '/link-signer'))
    need(provider['certificate_id'] == selected and provider['scopes'] == 2 and
         provider['person_public_key'] == c.person and provider['device_public_key'] == request['device_public_key'] and
         not c.b.key_file.exists(), 'public provider independently verifies the exact activated owned scope2 selection')
    def retained():
        with sqlite3.connect(c.b.state / 'host.db') as db:
            return (c.access_snapshot(c.b),
                    db.execute('SELECT person_key,device_key,certificate_id FROM link_signers ORDER BY network_id').fetchall(),
                    db.execute('SELECT request_id,record FROM link_pending ORDER BY request_id').fetchall(),
                    [(key, digest(bytes(private))) for key, private in db.execute('SELECT public_key,seed FROM link_device_keys ORDER BY public_key')])
    before = retained()
    status = checked(c.b.call('GET', '/v1/status'))
    attention = [item for item in status['attention'] if item['subject'] == c.network]
    failure = next((item for item in attention if item['kind'] == 'person_device_signer_unavailable'), None)
    need(failure is not None and set(failure) == {'kind', 'subject', 'detail', 'command'} and
         failure['detail'].startswith("selected device cannot renew this person's access policy: forbidden: ") and
         failure['command'] == 'peerspan network sync ' + c.network and
         not any(item['kind'] == 'person_agent_unreachable' for item in attention) and
         'ssh-agent' not in json.dumps(attention).lower() and 'link --renew' not in failure['detail'] and retained() == before,
         'scope2 selection yields precise read-only device repair attention without original-agent fallback or mutation', attention)
    policy_route = '/v1/networks/' + c.network + '/policy?person=' + c.person_id
    policy = checked(c.b.call('GET', policy_route))
    expired_at = shift(provider['not_after'], 1)
    need(datetime.fromisoformat(policy['valid_until'].replace('Z', '+00:00')) <
         datetime.fromisoformat(expired_at.replace('Z', '+00:00')),
         'the independently observed original-person policy expires before the selected certificate boundary')
    versions_route = '/v1/networks/' + c.network + '/link-access-versions'
    maxima = checked(c.b.call('GET', versions_route))
    c.runtime.set_time(expired_at)
    need(c.b.call('GET', policy_route)[0] == 404,
         'expired access policy is absent from the active permission view')
    before = retained()
    status = checked(c.b.call('GET', '/v1/status'))
    attention = [item for item in status['attention'] if item['subject'] == c.network]
    failure = next((item for item in attention if item['kind'] == 'person_device_signer_unavailable'), None)
    need(next(item for item in status['networks'] if item['id'] == c.network)['policy'] is None and
         failure is not None and set(failure) == {'kind', 'subject', 'detail', 'command'} and
         failure['detail'].startswith("selected device cannot renew this person's access policy: authority_expired: ") and
         failure['command'] == 'peerspan network sync ' + c.network and
         not any(item['kind'] == 'person_agent_unreachable' for item in attention) and
         'ssh-agent' not in json.dumps(attention).lower() and
         checked(c.b.call('GET', versions_route)) == maxima and retained() == before,
         'inactive policy cannot hide expired selected-device repair attention or erase its exact retained maximum', attention)
    c.no_secrets()


def explicit_original_capability_claims_only_its_person(c):
    host = c.a
    keys = c.root / 'different-bound-person'
    keys.mkdir()
    other_key, _, other_public = ssh_key(keys, 'quinn')
    created = host.cli('network', 'create', 'other-bound-person', '--as', 'quinn',
                       '--person-key', str(other_key), '--coordinator', f'127.0.0.1:{c.runtime.port}',
                       '--coordinator-key', c.coordinator_key, sock=None)
    other = created['id']
    need(created['person']['key']['public_key'] == other_public and other_public != c.person,
         'the same actual host is independently bound to different original persons in two networks')
    from datetime import datetime, timezone
    c.runtime.set_time(max(c.runtime.now, shift(datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 1)))
    host.cli('network', 'enable-linking', '--network', other, sock=None)
    def both_active():
        with sqlite3.connect(host.state / 'host.db') as db:
            return all((row := db.execute('SELECT record FROM link_features WHERE network_id=?', (identity,)).fetchone())
                       and json.loads(row[0])['state'] == 'active' for identity in (c.network, other))
    c.until(both_active, 'both different-person networks durably activated')
    agent = host.cli('agent', 'register', '--name', 'explicit-key-source', '--owner', 'alice')
    workspace = c.root / 'explicit-key-workspace'
    workspace.mkdir()
    fixture = Fixture(c.root / 'explicit-key-fixture')
    server = {'name': 'fixture', 'transport': 'stdio', 'command': sys.executable,
              'args': fixture.args('explicit-person-claim'), 'env': {}, 'url': None, 'source': 'claude-code:user'}
    checked(host.call('PUT', '/v1/agents/' + agent['id'] + '/tool-servers',
                      {'workspace': str(workspace), 'servers': [server], 'values': {}}))
    def unrelated():
        with sqlite3.connect(host.state / 'host.db') as db:
            return (db.execute('SELECT proof_id,kind,body FROM link_objects WHERE network_id=? ORDER BY proof_id', (other,)).fetchall(),
                    db.execute('SELECT kind,subject,version,record_hash FROM link_highwater WHERE network_id=? ORDER BY kind,subject', (other,)).fetchall(),
                    sorted(db.execute('SELECT * FROM policy_edits WHERE network_id=?', (other,)).fetchall(), key=repr))
    before = unrelated()
    route = '/v1/networks/' + c.network
    current = host.call('GET', route + '/policy?person=' + c.person_id)
    version = current[1]['version'] if current[0] == 200 else 0
    result = host.run('capability', 'create', 'only-alice-claim', '--from', 'explicit-key-source/fixture',
                      '--operations', 'echo', '--person-key', str(host.key_file), sock=None)
    need(result.returncode == 0, 'explicit personA key claims matching networkA despite unrelated active personB network', result.stderr)
    policy = checked(host.call('GET', route + '/policy?person=' + c.person_id))
    host_id = checked(host.call('GET', '/v1/host'))['id']
    need(policy['person_public_key'] == c.person and policy['version'] == version + 1 and
         cap_rule(host_id, 'only-alice-claim', []) in policy['capability_rules'] and
         checked(host.call('GET', '/v1/capabilities/only-alice-claim'))['name'] == 'only-alice-claim',
         'capability commits with exactly the selected original person claim')
    c.verify_signature(c.person, '\n'.join(policy_lines_v2(policy)).encode(), policy['signature'])
    need(unrelated() == before, 'unrelated personB network receives no signature, claim, high-water or edit mutation')
    c.no_secrets()


def atomic_device_capability_claim(c):
    full_chain(c)
    host = c.c
    agent = host.cli('agent', 'register', '--name', 'linked-cap-source', '--owner', 'alice')
    workspace = c.root / 'capability-workspace'
    workspace.mkdir()
    fixture = Fixture(c.root / 'capability-fixture')
    definition = {'name': 'fixture', 'transport': 'stdio', 'command': sys.executable,
                  'args': fixture.args('linked-claim'), 'env': {}, 'url': None, 'source': 'claude-code:user'}
    checked(host.call('PUT', '/v1/agents/' + agent['id'] + '/tool-servers',
                      {'workspace': str(workspace), 'servers': [definition], 'values': {}}))
    route = '/v1/networks/' + c.network
    start = checked(host.call('GET', route + '/policy/edit'))
    need(set(start) == {'policy', 'version', 'seq'}, 'device claim starts from the exact current edit reservation')
    base = start['policy'] or {}
    host_id = checked(host.call('GET', '/v1/host'))['id']
    edits = {entry['host']: entry['seq'] for entry in base.get('edits', [])}
    edits[host_id] = start['seq']
    name = 'linked-atomic-claim'
    unsigned = {'format': 2, 'network_id': c.network, 'person_public_key': c.person,
                'version': start['version'] + 1, 'issued_at': c.runtime.now,
                'valid_until': shift(c.runtime.now, 86400), 'rules': base.get('rules', []),
                'capability_rules': base.get('capability_rules', []) + [cap_rule(host_id, name, [])],
                'trusted_hosts': base.get('trusted_hosts', []),
                'edits': [{'host': identity, 'seq': seq} for identity, seq in sorted(edits.items())]}
    intent = {'kind': 'policy_claim', 'certificate_id': 'auto',
              'payload_base64': b64(wire({'capability': name, 'policy_base64': b64(wire(unsigned))}))}
    before = c.access_snapshot(host)
    prepared = checked(host.call('POST', route + '/link-actions', intent))
    need(set(prepared) == {'record_id', 'proof_id', 'record_base64', 'catalog', 'committed'} and
         prepared['committed'] is False and c.access_snapshot(host) == before,
         'device claim preparation signs only the fixed intent without storing policy/edit/delivery state')
    raw = unb64(prepared['record_base64'])
    record = json.loads(raw)
    signer = checked(host.call('GET', route + '/link-signer'))
    need(record['kind'] == 'peerspan-policy-v2' and record['operation_id'] == '-' and
         record['payload_base64'] == b64(wire(unsigned)) and record['person_public_key'] == c.person and
         record['certificate_id'] == signer['certificate_id'] and
         prepared['record_id'] == semantic_id('person_record', record) and
         prepared['proof_id'] == proof('person_record', raw=raw)['id'],
         'prepared claim retains exact unsigned policy bytes, owned device path and independently derived IDs')
    c.verify_signature(signer['device_public_key'], message('person_record', record), record['signature'])
    body = {'name': name, 'source': {'agent': 'linked-cap-source', 'server': 'fixture'},
            'operations': ['echo'], 'resources': None, 'env_file': None, 'policies': [],
            'catalogs': [{'network_id': c.network, 'catalog': prepared['catalog']}]}
    capabilities = checked(host.call('GET', '/v1/capabilities'))
    for changed in (dict(body, operations=['not-an-operation']),
                    dict(body, catalogs=[]),
                    dict(body, catalogs=body['catalogs'] * 2)):
        rejected = host.call('POST', '/v1/capabilities', changed)
        need(rejected[0] >= 400 and c.access_snapshot(host) == before and
             checked(host.call('GET', '/v1/capabilities')) == capabilities,
             'invalid source or incomplete/duplicate claim set commits no capability, policy, marks or edit')
    created = checked(host.call('POST', '/v1/capabilities', body), 201)
    need(created['name'] == name, 'atomic create commits the capability with its exact device-signed claim')
    need(prepared['proof_id'] in {entry['id'] for entry in host.public_catalog(c.network)['objects']},
         'atomic claim stores the exact prepared public envelope')
    policy = checked(host.call('GET', route + '/policy?person=' + c.person_id))
    need(policy['version'] == unsigned['version'] and policy['authorization_base64'] == prepared['record_base64'] and
         cap_rule(host_id, name, []) in policy['capability_rules'], 'committed claim materializes unsigned view with exact envelope authority')
    before = c.access_snapshot(host)
    repeated = host.run('capability', 'create', name, '--from', 'linked-cap-source/fixture', '--operations', 'echo', sock=None)
    need(repeated.returncode == 0 and c.access_snapshot(host) == before,
         'identical CLI create preflight signs nothing and reserves no new edit', repeated.stderr)
    # A sibling's later policy is based on the empty pre-claim policy. The
    # daemon must reapply its already signed claim edit through its owned device,
    # without a CLI signature or copied original key.
    replacement = dict(unsigned, version=unsigned['version'] + 1, capability_rules=[], edits=[])
    c.action(c.b, 'peerspan-policy-v2', replacement)
    host.cli('network', 'sync', c.network, sock=None)
    def reapplied():
        value = checked(host.call('GET', route + '/policy?person=' + c.person_id))
        return value if value['version'] > replacement['version'] and cap_rule(host_id, name, []) in value['capability_rules'] else None
    merged = c.until(reapplied, 'automatic selected-device capability edit reapplication')
    signed = json.loads(unb64(merged['authorization_base64']))
    need(signed['certificate_id'] == signer['certificate_id'] and signed['person_public_key'] == c.person and
         signed['operation_id'] == '-' and merged['edits'] == unsigned['edits'] and
         merged['valid_until'] <= signer['not_after'],
         'automatic reapplication retains exact device/person and edit sequence while capping path expiry')
    c.verify_signature(signer['device_public_key'], message('person_record', signed), signed['signature'])
    need(not host.key_file.exists(), 'capability claims never generate or copy an original-person private key')
    c.no_secrets()


def automatic_device_policy_renewal(c):
    full_chain(c)
    # Stop every other signing provider so a sibling renewal cannot satisfy
    # this daemon's own selected-device renewal requirement.
    c.b.stop()
    host = c.c
    route = '/v1/networks/' + c.network
    signer = checked(host.call('GET', route + '/link-signer'))
    unsigned = {'format': 2, 'network_id': c.network, 'person_public_key': c.person, 'version': 17,
                'issued_at': shift(c.runtime.now, -3 * 86400), 'valid_until': shift(c.runtime.now, 3600),
                'rules': [], 'capability_rules': [], 'trusted_hosts': [], 'edits': []}
    c.action(host, 'peerspan-policy-v2', unsigned)
    def renewed():
        value = checked(host.call('GET', route + '/policy?person=' + c.person_id))
        return value if value['version'] > unsigned['version'] else None
    view = c.until(renewed, 'automatic daemon renewal without original-person key or CLI signing')
    record = json.loads(unb64(view['authorization_base64']))
    need(view['version'] == 18 and view['valid_until'] > unsigned['valid_until'] and
         view['valid_until'] <= signer['not_after'] and
         all(view[field] == unsigned[field] for field in ('rules', 'capability_rules', 'trusted_hosts', 'edits')),
         'automatic renewal increments once, retains all policy content and caps expiry at current device path')
    need(record['kind'] == 'peerspan-policy-v2' and record['operation_id'] == '-' and
         record['person_public_key'] == c.person and record['certificate_id'] == signer['certificate_id'],
         'daemon renewal uses its exact owned selected device and stable original person')
    c.verify_signature(signer['device_public_key'], message('person_record', record), record['signature'])
    need(not host.key_file.exists(), 'automatic renewal creates no fallback original-person key')
    c.no_secrets()


def unpublished_administrator_rechecks_role(c):
    # A separate external administrator exposes a fixed final packet-signing
    # slot after all received selection frames have already been processed.
    # The generic frame barrier also applies to received frame persistence.
    implementation = 'go' if str(c.b.binary) == str(c.args.go) else 'rust'
    admin = c.host('Quinn', implementation)
    admin.start()
    invitation = c.a.cli('network', 'invite', '--network', c.network, '--member', 'quinn', sock=None)
    c.codes.append(invitation['token'])
    joined = admin.cli('network', 'join', '--token', invitation['token'], sock=None)
    administrator_id = joined['person']['person_id']
    administrator_key = joined['person']['key']['public_key']
    # The remote join is complete; explicitly learn Quinn's admission before
    # the legacy local-person selector resolves the delegation target.
    c.a.cli('network', 'sync', c.network, sock=None)
    c.a.cli('network', 'delegate-admin', '--network', c.network, '--person', administrator_id, sock=None)
    c.a.cli('network', 'remove-admin', '--network', c.network, '--person', c.person_id, sock=None)
    admin.cli('network', 'sync', c.network, sock=None)
    created = c.request(c.b)
    identity = created['request_id']
    c.approval(c.a, created, signer='person_root')
    c.consent(c.b, created)
    need(c.a.pending(identity)['administrator_intent'] == '-', 'nonadministrator owner cannot approve an alternate admission')
    body = {'code': created['display_code'], 'network_id': c.network, 'expected_person_id': c.person_id,
            'expected_host_key': '-', 'expected_device_key': '-', 'signer': 'person_root', 'approve': False}
    c.runtime.advance(2)
    preview = checked(admin.call('POST', '/v1/link/admissions', body))
    body.update(expected_host_key=preview['review']['host_public_key'],
                expected_device_key=preview['review']['device_public_key'], approve=True)
    c.runtime.advance(2)
    approved = checked(admin.call('POST', '/v1/link/admissions', body))
    def signed_slot(value, expected):
        need(len(value['signing_requests']) == 1, 'one dependency-ready fixed administrator slot')
        slot = value['signing_requests'][0]
        need(slot['object_type'] == expected and slot['signer_public_key'] == administrator_key and
             slot['signature_format'] == 'sshsig', 'fixed original-administrator signing identity and slot')
        preimage = c.root / ('unpublished-' + expected)
        preimage.write_bytes(unb64(slot['message_base64']))
        result = subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(admin.key_file), '-n',
                                 'peerspan-person-v1', '-q', str(preimage)], capture_output=True, timeout=10)
        need(result.returncode == 0, 'independent original administrator signs only its approved fixed message', result.stderr)
        signature = ''.join(line for line in preimage.with_name(preimage.name + '.sig').read_text().splitlines()
                            if not line.startswith('-----'))
        return {'object_type': expected, 'signature': signature}
    first = signed_slot(approved, 'admission_authorization')
    c.runtime.advance(2)
    ready = checked(admin.call('POST', '/v1/link/requests/' + identity + '/signed', first))
    final_signature = signed_slot(ready, 'administrator_packet')
    need(admin.pending(identity)['selection_packet_base64'] != '-', 'selected request is already durably processed before arming frame fault')
    arm = admin.barriers / 'host.frame.after_commit.arm'
    entered = admin.barriers / 'host.frame.after_commit.entered'
    entered.unlink(missing_ok=True)
    arm.write_text('')
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(admin.call, 'POST', '/v1/link/requests/' + identity + '/signed', final_signature)
        deadline = time.monotonic() + 20
        while not entered.exists() and time.monotonic() < deadline:
            if future.done():
                checked(future.result())
            time.sleep(.01)
        need(entered.exists() and entered.read_text().strip() == identity,
             'administrator ciphertext commits at the documented pre-publication barrier')
        frozen = admin.pending(identity)
        unsent = [entry for entry in frozen['outbound_frames'] if entry['role'] == 'administrator']
        need(len(unsent) == 1 and not unsent[0]['published'] and unsent[0]['sequence'] == 0 and
             frozen['administrator_packet_base64'] != '-', 'one immutable complete administrator frame remains unpublished')
        with sqlite3.connect(admin.state / 'host.db') as db:
            frames = db.execute('SELECT role,writer_key,frame_id,record FROM link_frames WHERE request_id=? ORDER BY role,writer_key,frame_id',
                                (identity,)).fetchall()
        sealed = json.loads(unb64(json.loads(next(row[3] for row in frames if row[0] == 'administrator'))['frame_base64']))
        locator, frame_id = sealed['locator'], sealed['frame_id']
        admin.stop(crash=True)
        arm.unlink()
        try:
            future.result(timeout=5)
        except (OSError, http.client.HTTPException):
            pass
    route = '/v1/networks/' + c.network
    checked(c.a.call('POST', route + '/admin-removals', {'person': administrator_id, 'revoke_admitted': False}), 201)
    need(c.runtime.now < created['expires_at'], 'role-loss regression keeps the pending request before its exclusive deadline')
    replacement = c.args.rust if str(admin.binary) == str(c.args.go) else c.args.go
    admin.binary = admin.cli_binary = str(replacement)
    admin.start()
    c.runtime.advance(2)
    rejected = admin.call('POST', '/v1/link/requests/' + identity + '/resume', {})
    error((rejected[0], {}, rejected[1]), 403, 'forbidden')
    after = admin.pending(identity)
    need(after['administrator_intent'] == frozen['administrator_intent'] and
         after['administrator_packet_base64'] == frozen['administrator_packet_base64'] and
         next(entry for entry in after['outbound_frames'] if entry['frame_id'] == frame_id) == unsent[0],
         'role loss retains exact approved signed bytes and unpublished sequence without new consent/signature')
    with sqlite3.connect(admin.state / 'host.db') as db:
        need(db.execute('SELECT role,writer_key,frame_id,record FROM link_frames WHERE request_id=? ORDER BY role,writer_key,frame_id',
                        (identity,)).fetchall() == frames, 'cross-language failed replay never reseals or replaces a frame')
    response = ok(c.runtime.call('GET', '/coord/v2/link-mailboxes/' + locator + '?after=0'), 200)
    need(all(entry['frame']['frame_id'] != frame_id for entry in response['frames']),
         'actual coordinator has no administrator frame published after current role withdrawal')
    need(not c.b.key_file.exists() and not c.c.key_file.exists(), 'failed replay creates no original-person fallback key')
    c.no_secrets()


def documented_marker_repairs_older_coordinator(c):
    """Replay documented public outbox state; no post-sign fault claim."""
    full_chain(c)
    host = c.c
    backup = c.root / 'before-restriction.backup'
    saved = c.runtime.command('backup', str(backup))
    need(saved.returncode == 0, 'actual complete coordinator backup precedes restriction', saved.stderr)
    unrelated = b64(FixtureSigner(bytes([93]) * 32).public)
    signed = c.action(host, 'peerspan-revoke-host-v1',
                      {'network_id': c.network, 'host_public_key': unrelated, 'revoked_at': c.runtime.now})
    identity = signed['proof_id']
    retained = host.public_catalog(c.network)
    need(identity in {entry['id'] for entry in retained['objects']}, 'manual marker names an independently verified completed typed restriction')
    c.b.stop()
    host.stop()
    c.runtime.stop()
    restored = c.runtime.command('restore', '--replace', str(backup))
    need(restored.returncode == 0, 'genuine complete older coordinator backup restores', restored.stderr)
    marker = {'format': 1, 'proof_id': identity}
    with sqlite3.connect(host.state / 'host.db') as db:
        db.execute('INSERT INTO network_statements(network_id,kind,subject,record) VALUES (?,?,?,?)',
                   (c.network, 'pending_link_restriction', identity, wire(marker).decode()))
    c.runtime.start()
    host.start()
    current = host.cli('network', 'sync', c.network, sock=None)
    need(current['last_sync_error'] is None, 'ordinary sync repairs documented retained restriction before strict live-map application')
    with sqlite3.connect(host.state / 'host.db') as db:
        need(db.execute("SELECT subject,record FROM network_statements WHERE network_id=? AND kind='pending_link_restriction'",
                        (c.network,)).fetchall() == [], 'marker clears only after current live map acknowledges its exact PF')
    directory = c.root / 'marker-current-map-transport'
    directory.mkdir()
    remote = ok(c.runtime.call('GET', '/coord/v2/networks/' + c.network + '/map', key=host_key(host, directory)), 200)
    need(any(entry['id'] == identity and entry['body_base64'] == signed['record_base64'] for entry in remote['catalog']['objects']),
         'actual coordinator now retains the exact restored-away signed restriction')
    need(all(entry in host.public_catalog(c.network)['objects'] for entry in retained['objects']),
         'repair retains every prior public authority byte and stable selected provider')
    provider = checked(host.call('GET', '/v1/networks/' + c.network + '/link-signer'))
    pin = network(host, c.network)
    host.stop()
    missing = 'pf_' + '0' * 64
    need(missing not in {entry['id'] for entry in retained['objects']}, 'invalid marker control names a missing exact PF')
    for label, value in (('missing_pf', {'format': 1, 'proof_id': missing}),
                         ('invalid_shape', {'format': 1, 'proof_id': missing, 'extra': True})):
        implementation = 'go' if str(host.binary) == str(c.args.go) else 'rust'
        copy_host = c.host('Marker-' + label, implementation)
        shutil.copytree(host.state, copy_host.state, ignore=shutil.ignore_patterns('admin.sock'))
        with sqlite3.connect(copy_host.state / 'host.db') as db:
            db.execute('INSERT INTO network_statements(network_id,kind,subject,record) VALUES (?,?,?,?)',
                       (c.network, 'pending_link_restriction', missing, wire(value).decode()))
        before = c.access_snapshot(copy_host)
        startup_failed = False
        try:
            copy_host.start()
        except AssertionError:
            startup_failed = True
            need(copy_host.process.poll() is not None, 'only explicit invalid-outbox startup refusal can replace sync validation')
        if not startup_failed:
            response = copy_host.call('POST', '/v1/networks/' + c.network + '/sync')
            need(response[0] >= 400 or response[1].get('last_sync_error') is not None,
                 'missing or malformed marker fails closed instead of silently clearing repair state')
            after_pin = network(copy_host, c.network)
            need(all(after_pin[field] == pin[field] for field in ('coordinator_address', 'coordinator_public_key', 'root_epoch')),
                 'invalid local marker cannot change actual pin or current root')
            need(checked(copy_host.call('GET', '/v1/networks/' + c.network + '/link-signer')) == provider,
                 'marker refusal cannot replace the selected stable person/device provider')
        with sqlite3.connect(copy_host.state / 'host.db') as db:
            need(db.execute("SELECT record FROM network_statements WHERE network_id=? AND kind='pending_link_restriction' AND subject=?",
                            (c.network, missing)).fetchall() == [(wire(value).decode(),)],
                 'invalid or unresolved marker is retained exactly for repair')
        need(c.access_snapshot(copy_host) == before, 'invalid marker repair stores no partial proof/high-water/edit state')
        copy_host.stop()
        need(not copy_host.key_file.exists(), 'outbox repair never creates an original-person fallback key')
    c.no_secrets()


def missed_move_is_pulled_from_current_peer(c):
    full_chain(c)
    c.a.start()
    c.a.cli('network', 'sync', c.network, sock=None)
    policy = {'format': 2, 'network_id': c.network, 'person_public_key': c.person, 'version': 47,
              'issued_at': c.runtime.now, 'valid_until': shift(c.runtime.now, 86400),
              'rules': [], 'capability_rules': [], 'trusted_hosts': [], 'edits': []}
    c.action(c.c, 'peerspan-policy-v2', policy)
    c.a.cli('network', 'sync', c.network, sock=None)
    before = c.c.public_catalog(c.network)
    provider = checked(c.c.call('GET', '/v1/networks/' + c.network + '/link-signer'))
    initial = network(c.c, c.network)
    need(not any(entry['kind'] == 'coordinator_move' for entry in before['objects']), 'offline recipient starts without the later move')
    c.c.stop()
    target = Runtime(c.args.coordinator, c.root / 'missed-move-target', initial=c.runtime.now)
    try:
        info = json.loads(target.command('info').stdout)
        address, key = f'127.0.0.1:{target.port}', info['public_key']
        route = '/v1/networks/' + c.network + '/feature-import'
        body = {'coordinator_address': address, 'coordinator_public_key': key, 'import_id': '-', 'approve': False}
        preview = checked(c.a.call('POST', route, body))
        approved = checked(c.a.call('POST', route, dict(body, import_id=preview['import_id'], approve=True)))
        need(approved['committed'] is True, 'existing root explicitly prepares exact target LF before separate move consent')
        need(network(c.a, c.network)['coordinator_address'] == initial['coordinator_address'],
             'feature repair alone never follows or switches a coordinator pin')
        c.a.cli('network', 'move', '--network', c.network, '--coordinator', address, '--coordinator-key', key, sock=None)
        c.b.cli('network', 'sync', c.network, sock=None)
        need(network(c.b, c.network)['coordinator_address'] == address, 'independent reachable member verifies current-authorized move and live target')
        c.a.stop()
        c.runtime.stop()
        c.c.start()
        def followed():
            value = c.c.cli('network', 'sync', c.network, sock=None)
            return value if value['coordinator_address'] == address and value['coordinator_public_key'] == key and value['last_sync_error'] is None else None
        c.until(followed, 'current peer move pull after consecutive failed actual old-pin syncs')
        need(checked(c.c.call('GET', '/v1/networks/' + c.network + '/link-signer')) == provider,
             'peer-learned move preserves exact selected original person/device path')
        after = c.c.public_catalog(c.network)
        need(all(entry in after['objects'] for entry in before['objects']) and
             any(entry['kind'] == 'coordinator_move' for entry in after['objects']),
             'move pull retains old activations, exact feature and signed high-water evidence')
        versions = checked(c.c.call('GET', '/v1/networks/' + c.network + '/link-access-versions'))
        need(next(value for value in versions['policies'] if value['person_public_key'] == c.person)['version'] >= 47,
             'following transport proof never resets an existing access maximum')
        plan = checked(c.c.call('GET', '/v1/networks/' + c.network + '/move'))
        need(plan['move']['sequence'] == 1 and plan['next_sequence'] == 2 and
             plan['move']['address'] == address and plan['move']['public_key'] == key,
             'public plan retains the exact independently followed move and guarded next sequence')
        c.c.cli('network', 'sync', c.network, sock=None)
        need(checked(c.c.call('GET', '/v1/networks/' + c.network + '/move')) == plan,
             'missed-push recovery retry cannot create a new move or advance the applied sequence again')
        need(not c.b.key_file.exists() and not c.c.key_file.exists(), 'peer move recovery never copies original-person keys')
        c.no_secrets()
    finally:
        target.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--coordinator', required=True)
    parser.add_argument('--go', required=True)
    parser.add_argument('--rust', required=True)
    parser.add_argument('--probe')
    parser.add_argument('--section', action='append', choices=('rotation', 'rotation-refusal', 'import-previews', 'receipt', 'peer', 'withdrawal', 'claims', 'explicit-claims', 'status-scope', 'automatic', 'unpublished', 'marker', 'move'))
    parser.add_argument('--pair', action='append', choices=('go-go', 'go-rust', 'rust-go', 'rust-rust'))
    parser.add_argument('--work-dir', type=Path)
    args = parser.parse_args()
    if not args.section or any(section in args.section for section in ('peer', 'status-scope')):
        if not args.probe:
            parser.error('--probe is required for the authenticated peer gate')
        set_probe(args.probe)
    temporary = None
    if args.work_dir:
        args.work_dir.mkdir(parents=True, exist_ok=False)
        directory = args.work_dir
    else:
        temporary = tempfile.TemporaryDirectory(prefix='peerspan-link-management-')
        directory = Path(temporary.name)
    failures = 0
    try:
        for section in args.section or ('rotation', 'rotation-refusal', 'import-previews', 'receipt', 'peer', 'withdrawal', 'claims', 'automatic', 'unpublished', 'marker', 'move'):
            for pair in args.pair or ('go-go', 'go-rust', 'rust-go', 'rust-rust'):
                ceremony = None
                try:
                    creator, requester = pair.split('-')
                    ceremony = Ceremony(args, directory / (section + '-' + pair), creator, requester)
                    {'rotation': pending_rotation_retry, 'rotation-refusal': competing_rotation_retires_only_refused_pending,
                     'import-previews': import_preview_reclaims_only_safe_expired_rows, 'receipt': recovery_receipt_preserves_later_proofs,
                     'peer': peer_sender_must_precede_incoming_grants,
                     'withdrawal': withdrawal_keeps_exact_history,
                     'claims': atomic_device_capability_claim,
                     'explicit-claims': explicit_original_capability_claims_only_its_person,
                     'status-scope': selected_device_status_requires_policy_scope,
                     'automatic': automatic_device_policy_renewal,
                     'unpublished': unpublished_administrator_rechecks_role,
                     'marker': documented_marker_repairs_older_coordinator,
                     'move': missed_move_is_pulled_from_current_peer}[section](ceremony)
                    print('PASS ' + pair + ': active management ' + section, flush=True)
                except Exception:
                    failures += 1
                    traceback.print_exc()
                finally:
                    if ceremony:
                        ceremony.close()
    finally:
        if temporary:
            temporary.cleanup()
    return int(bool(failures))


if __name__ == '__main__':
    sys.exit(main())
