#!/usr/bin/env python3
"""Independent cold private-invitation feature adoption runtime checks.

Public contracts define the outer signed LF choice, exact inner grant bytes and
durable public LRI. Tokens/seeds are never printed or placed in evidence files.
"""

import argparse
import base64
import copy
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import traceback

from linking_hosts import Ceremony, checked, need
from linking_invite_features import binding_message
from linking_activations import payload, proof, semantic_id, shift
from linking_readers import FixtureSigner, b64, digest, lines, unb64, wire
from linking_readers import message
from launch_service import host_key
from persons import ssh_key


WRAPPER = {'format', 'network', 'token', 'mode', 'host_invite_base64', 'person_invite_base64', 'feature_binding', 'catalog'}
INTENT = {'format', 'network_base64', 'feature_id', 'feature_binding_base64', 'redemption_base64',
          'request_base64', 'submitted', 'result_map_base64'}


def decode(token, prefix=None):
    kind, encoded = token.split('.', 1)
    need(prefix is None or kind == prefix, 'exact private invitation version prefix')
    raw = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
    need(base64.urlsafe_b64encode(raw).decode().rstrip('=') == encoded, 'canonical unpadded private base64url')
    return kind, json.loads(raw)


def encode(wrapper):
    return 'peerspan-feature-invite-v1.' + base64.urlsafe_b64encode(wire(wrapper)).decode().rstrip('=')


def public_grant(value):
    return payload(value) if 'payload_base64' in value else value


def inspect(c, token, issuer, device=False):
    _, outer = decode(token, 'peerspan-feature-invite-v1')
    need(set(outer) == WRAPPER and outer['format'] == 1, 'strict fresh feature-choice wrapper')
    binding = outer['feature_binding']
    network = outer['network']
    need(binding['network_id'] == network['network_id'] == c.network and
         binding['coordinator_address'] == network['coordinator_address'] and
         binding['coordinator_public_key'] == network['coordinator_public_key'] and
         binding['genesis_root_public_key'] == network['genesis_root_public_key'] and
         binding['network_name'] == network['name'], 'signed feature choice pins the complete immutable descriptor')
    c.verify_signature(binding['signer_public_key'], binding_message(binding), binding['signature'])
    if device:
        signer = checked(issuer.call('GET', '/v1/networks/' + c.network + '/link-signer'))
        need(binding['issuer_kind'] == 'person' and binding['person_public_key'] == c.person and
             binding['certificate_id'] == signer['certificate_id'] and binding['signer_public_key'] == signer['device_public_key'],
             'device invitation preserves original person and exact live selected device authority')
    else:
        need(binding['issuer_kind'] == 'network_root' and binding['person_public_key'] == '-' and binding['certificate_id'] == '-',
             'root-held invitation uses typed current-root authority')
    _, inner = decode(outer['token'])
    seed = unb64(inner['invite_seed'])
    invite_key = b64(FixtureSigner(seed).public)
    for name in ('host', 'person'):
        encoded = outer[name + '_invite_base64']
        need(binding[name + '_invite_sha256'] == ('-' if encoded == '-' else digest(unb64(encoded))),
             'fresh binding covers exact retained public half bytes')
        if encoded != '-':
            grant = json.loads(unb64(encoded))
            value = public_grant(grant)
            need(value['invite_public_key'] == invite_key and value['invite_expires_at'] == binding['expires_at'],
                 'preserved private seed derives the exact public grant key and expiry')
            if 'host_invite' in inner:
                need(grant == inner[name + '_invite'], 'authorized inner public grant remains unchanged in feature wrapper')
            else:
                expected = {key: inner[key] for key in ('network_id', 'member', 'invite_public_key', 'invite_expires_at')}
                expected['signature'] = inner['invite_signature' if name == 'host' else 'person_invite_signature']
                if name == 'person':
                    expected['invite_epoch'] = inner['invite_epoch']
                need(grant == expected, 'legacy inner signature strings and fields remain exact')
    return outer, seed


def join(host, token, success, no_person=False, expected_code=None):
    try:
        result = host.run('network', 'join', '--token', token, *(['--no-person'] if no_person else []), sock=None)
    except subprocess.TimeoutExpired:
        raise AssertionError('private invitation join exceeded the existing 30-second CLI budget') from None
    need((result.returncode == 0) == success, 'private join outcome', result.returncode,
         result.stderr.replace(token, '[private invite]'))
    if expected_code:
        need(expected_code in result.stderr.lower().replace(' ', '_'),
             'private retry reports its exact authority repair category', result.stderr.replace(token, '[private invite]'))
    return json.loads(result.stdout) if result.stdout else None


def host_only_does_not_admit_a_person(c, issuer, implementation):
    target = c.host('Raw', implementation)
    c.identity[target.state.name] = target.start()
    token = issuer.cli('network', 'invite', '--network', c.network, '--member', 'raw-host-only', '--host-only', sock=None)['token']
    _, outer = decode(token, 'peerspan-feature-invite-v1')
    c.codes.extend((token, outer['token']))
    provider = c.root / 'raw-host-external-person'
    provider.mkdir()
    private_key, ssh_public, person = ssh_key(provider, 'raw-member')
    need(person != c.person and not target.key_file.exists(), 'raw person subject is independent and has no local private key')
    result = checked(target.call('POST', '/v1/networks/join', {'token': token, 'person_public_key': person}), 201)
    value = result['person']
    need(value['person_id'] == 'person_' + digest(unb64(person)) and value['admitted'] is False and
         value['bound'] is False and value['skipped'] and value['next'],
         'host-only invitation reports the explicit unadmitted person accurately with administrator-admission recovery')
    people = checked(target.call('GET', '/v1/networks/' + c.network + '/persons'))
    need(all(value['public_key'] != person for value in people) and not target.key_file.exists(),
         'unsigned requested person metadata grants no person admission, binding or replacement private key')
    admitted = issuer.cli('network', 'admit', '--network', c.network, '--person', ssh_public,
                          '--member', 'raw-host-only', sock=None)
    need(admitted['person_id'] == value['person_id'], 'current administrator separately admits only the exact requested original person')
    target.cli('network', 'sync', c.network, sock=None)
    bound = target.cli('network', 'bind', '--network', c.network, '--person-key', str(private_key), sock=None)
    need(bound['person_id'] == value['person_id'] and bound['host_id'] == c.identity[target.state.name]['id'] and
         not target.key_file.exists(),
         'explicit external original key recovers the first binding of a verified host-only member without importing a default person key')


def cold(c, device=False, late=False, unknown=False):
    # Pair labels always mean issuer implementation -> cold target
    # implementation. Ceremony.c uses the creator implementation, so it is
    # unsuitable as the cold target of a cross-language case.
    issuer, target = c.a, c.b
    if device:
        implementation = 'go' if str(c.a.binary) == str(c.args.go) else 'rust'
        issuer = c.host('InviteIssuer', implementation)
        c.identity[issuer.state.name] = issuer.start()
        c.complete(issuer, c.a)
        c.a.stop()
    c.runtime.advance(2 * 86400)
    flags = ['network', 'invite', '--network', c.network, '--member', 'cold-recipient']
    if not device:
        flags.append('--host-only')
    invitation = issuer.cli(*flags, sock=None)
    token = invitation['token']
    outer, seed = inspect(c, token, issuer, device)
    c.codes.extend([token, outer['token'], b64(seed)])
    need(not target.key_file.exists() and checked(target.call('GET', '/v1/networks')) == [], 'cold target starts with no prior feature/person/network')
    # An old private token cannot promote an unsigned old LF beyond the first
    # activation window. Neither malformed signed choice can create identity.
    for field, changed in (('feature_id', 'lf_' + '0' * 64), ('coordinator_public_key', c.person)):
        bad = copy.deepcopy(outer)
        bad['feature_binding'][field] = changed
        join(target, encode(bad), False, not device)
        need(not target.key_file.exists() and checked(target.call('GET', '/v1/networks')) == [],
             'invalid feature choice creates no replacement identity or partial membership')
    join(target, outer['token'], False, not device)
    prejoin = c.root / 'genuine-prejoin-state'
    if unknown:
        need(device and late, 'unknown-local repair isolates an expired delegated invitation')
        target.stop()
        shutil.copytree(target.state, prejoin, ignore=shutil.ignore_patterns('admin.sock'))
        target.start()
    joined = join(target, token, True, not device)
    need(joined['id'] == c.network, 'fresh signed choice permits cold adoption after original 24-hour feature window')
    with sqlite3.connect(target.state / 'host.db') as db:
        feature = json.loads(db.execute('SELECT record FROM link_features WHERE network_id=?', (c.network,)).fetchone()[0])
        rows = db.execute("SELECT subject,record FROM network_statements WHERE network_id=? AND kind='link_invite_redemption_intent'", (c.network,)).fetchall()
    need(feature['state'] == 'active' and len(rows) == 1, 'cold membership atomically retains one exact active feature and public LRI')
    identity, raw = rows[0]
    record = json.loads(raw)
    need(set(record) == INTENT and record['format'] == 1 and record['submitted'] is True and
         record['result_map_base64'] != '-', 'strict public-only completed immutable redemption intent')
    redemption = json.loads(unb64(record['redemption_base64']))
    request = json.loads(unb64(record['request_base64']))
    need(request['redemption'] == redemption and record['feature_id'] == outer['feature_binding']['feature_id'],
         'durable public request retains exact completed redemption and chosen feature')
    retained = json.loads(unb64(record['feature_binding_base64']))
    need(retained == {'binding': outer['feature_binding'], 'host_invite_base64': outer['host_invite_base64'],
                      'person_invite_base64': outer['person_invite_base64']}, 'LRI retains exact public binding seed without private token')
    invite = public_grant(json.loads(unb64(outer['host_invite_base64'])))['invite_public_key']
    need(identity == 'lri_' + digest(lines('peerspan-invite-redemption-intent-v1', c.network, redemption['mode'],
                   redemption['host_public_key'], redemption['person_public_key'], invite)), 'derive exact public LRI ID independently')
    public = [record, request, redemption, json.loads(unb64(record['result_map_base64'])), retained]
    need(token not in json.dumps(public) and outer['token'] not in json.dumps(public) and b64(seed) not in json.dumps(public),
         'durable redemption contains no private token or invitation seed')
    if device:
        need(target.key_file.exists() and os.stat(target.key_file).st_mode & 0o777 == 0o600,
             'new invited original identity persists privately for uncertain retry')
    else:
        need(not target.key_file.exists(), 'host-only cold join never fabricates a person')
    before = c.access_snapshot(target)
    before_identity = checked(target.call('GET', '/v1/host'))
    with sqlite3.connect(target.state / 'host.db') as db:
        binding_before = db.execute("SELECT subject,record FROM network_statements WHERE network_id=? AND kind='binding' ORDER BY subject",
                                    (c.network,)).fetchall()
        operations_before = db.execute('SELECT request_id,manifest_id,locally_applied FROM link_operations ORDER BY request_id').fetchall()
    repeated = join(target, token, True, not device)
    after = c.access_snapshot(target)
    old_ids, new_ids = {row[0] for row in before[0]}, {row[0] for row in after[0]}
    def mark_rows(rows):
        return [[*row[:2], b64(row[2]) if isinstance(row[2], bytes) else row[2], row[3]] for row in rows]
    with sqlite3.connect(target.state / 'host.db') as db:
        after_intents = [(identity, json.loads(raw)) for identity, raw in db.execute(
                "SELECT subject,record FROM network_statements WHERE network_id=? AND kind='link_invite_redemption_intent'", (c.network,))]
        binding_after = db.execute("SELECT subject,record FROM network_statements WHERE network_id=? AND kind='binding' ORDER BY subject",
                                   (c.network,)).fetchall()
        operations_after = db.execute('SELECT request_id,manifest_id,locally_applied FROM link_operations ORDER BY request_id').fetchall()
    diagnostic = {'added_proof_ids': sorted(new_ids - old_ids), 'removed_proof_ids': sorted(old_ids - new_ids),
                  'before_marks': mark_rows(before[1]), 'after_marks': mark_rows(after[1]),
                  'edit_reservations_unchanged': before[2] == after[2],
                  'original_intent_unchanged': after_intents == [(identity, record)],
                  'binding_unchanged': binding_after == binding_before}
    (c.root / 'cold-retry-public-diff.json').write_text(json.dumps(diagnostic, indent=2) + '\n')
    need(repeated['id'] == c.network and after_intents == [(identity, record)] and
         checked(target.call('GET', '/v1/host')) == before_identity and
         binding_after == binding_before and operations_after == operations_before,
         'exact committed invitation retry preserves original LRI, receipt, identity, binding and operations', diagnostic)
    need(set(before[0]) <= set(after[0]) and before[2] == after[2],
         'retry retains every old exact signed proof and edit reservation while verified sync may append newer evidence', diagnostic)
    after_marks = {(row[0], row[1]): row[2:] for row in after[1]}
    for kind, subject, version, _ in before[1]:
        actual = after_marks[(kind, subject)]
        old_version = int.from_bytes(version, 'big') if isinstance(version, bytes) else version
        current_version = int.from_bytes(actual[0], 'big') if isinstance(actual[0], bytes) else actual[0]
        need(current_version >= old_version,
             'fresh verified sync during exact retry cannot lower a retained maximum')
    if not device:
        implementation = 'go' if str(target.binary) == str(c.args.go) else 'rust'
        host_only_does_not_admit_a_person(c, issuer, implementation)
    if unknown:
        # The public contract permits replaying this exact submitted public
        # bookkeeping row beside the genuine pre-join DB to model loss of
        # local completion. The host/person private keys remain their own.
        person_key = target.key_file.read_bytes()
        target.stop()
        shutil.rmtree(target.state)
        shutil.copytree(prejoin, target.state)
        pending = dict(record, result_map_base64='-')
        with sqlite3.connect(target.state / 'host.db') as db:
            db.execute('INSERT INTO network_statements(network_id,kind,subject,record) VALUES (?,?,?,?)',
                       (c.network, 'link_invite_redemption_intent', identity, wire(pending).decode()))
        c.runtime.set_time(shift(outer['feature_binding']['expires_at'], 1))
        target.start()
        need(target.key_file.read_bytes() == person_key and checked(target.call('GET', '/v1/networks')) == [],
             'lost-completion fixture retains its chosen person and original host while no network is installed')
    if late:
        late_retry(c, issuer, target, token, outer, record, identity, device, unknown)
    c.no_secrets()


def late_retry(c, issuer, target, token, outer, record, identity, device, unknown=False):
    c.runtime.set_time(shift(outer['feature_binding']['expires_at'], 1))
    before = c.access_snapshot(target)
    original_host = checked(target.call('GET', '/v1/host'))
    def intent():
        with sqlite3.connect(target.state / 'host.db') as db:
            return [(subject, json.loads(raw)) for subject, raw in db.execute(
                "SELECT subject,record FROM network_statements WHERE network_id=? AND kind='link_invite_redemption_intent'", (c.network,))]
    if device:
        join(target, token, False, expected_code='proof_required')
        raw_request = {'token': token, 'person_public_key': json.loads(unb64(record['redemption_base64']))['person_public_key']}
        if not unknown:
            denied = target.call('POST', '/v1/networks/join', raw_request)
            need(denied[0] == 409 and denied[1]['code'] == 'proof_required',
                 'raw completed join independently refuses missing current retention without CLI preflight')
        current = intent()
        if unknown:
            need(len(current) == 1 and current[0][0] == identity and
                 {key: value for key, value in current[0][1].items() if key != 'result_map_base64'} ==
                 {key: value for key, value in record.items() if key != 'result_map_base64'} and
                 current[0][1]['result_map_base64'] in ('-', record['result_map_base64']),
                 'unresolved current retention never changes exact submitted LRI or its frozen commitment')
            need(checked(target.call('GET', '/v1/networks')) == [] and
                 c.access_snapshot(target) == before,
                 'unknown-local late outcome installs no partial network, feature, provider or public projection')
        else:
            need(current == [(identity, record)] and c.access_snapshot(target) == before,
                 'late delegated receipt without paired retention preserves exact LRI and all prior state')
        need(checked(target.call('GET', '/v1/host')) == original_host,
             'failed late retention repair preserves the exact stable host identity')
        records = [proof('invite_redemption', raw=unb64(record['redemption_base64']))['id']]
        for half in ('host_invite_base64', 'person_invite_base64'):
            if outer[half] != '-':
                grant = json.loads(unb64(outer[half]))
                need('payload_base64' in grant, 'delegated invitation halves retain exact ordinary authorization envelopes')
                records.append(semantic_id('person_record', grant))
        checkpoint = {'format': 1, 'network_id': c.network, 'person_public_key': c.person,
                      'issuer_certificate_id': 'root', 'issued_at': c.runtime.now, 'records': sorted(set(records))}
        preimage = c.a.home / 'late-invitation-retention-message'
        preimage.write_bytes(message('checkpoint', checkpoint))
        signed = subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(c.a.key_file), '-n', 'peerspan-person-v1', '-q', str(preimage)],
                                capture_output=True, timeout=10)
        need(signed.returncode == 0, 'unaffected original person endorses exact invitation ARs alongside completed redemption PF', signed.stderr)
        checkpoint['signature'] = ''.join(line for line in preimage.with_name(preimage.name + '.sig').read_text().splitlines()
                                          if not line.startswith('-----'))
        c.verify_signature(c.person, message('checkpoint', checkpoint), checkpoint['signature'])
        directory = c.root / 'late-retention-transport'
        directory.mkdir()
        catalog = {'format': 1, 'network_id': c.network, 'objects': [proof('checkpoint', checkpoint)]}
        posted = c.runtime.call('POST', '/coord/v2/networks/' + c.network + '/statements', {'catalog': catalog},
                                key=host_key(issuer, directory))
        need(posted[0] == 200, 'valid paired retention repairs delegated invitation history through actual coordinator', posted)
        if not unknown:
            target.cli('network', 'sync', c.network, sock=None)
            fixed = checked(target.call('POST', '/v1/networks/join', raw_request), 201)
            need(fixed['id'] == c.network and intent() == [(identity, record)],
                 'raw completed join returns its exact fixed result only after current paired retention is learned')
    repeated = join(target, token, True, not device)
    need(repeated['id'] == c.network and intent() == [(identity, record)] and
         checked(target.call('GET', '/v1/host')) == original_host,
         'late exact retry keeps its original signed request, outcome, receipt and stable identity')
    need(set(before[0]) <= set(c.access_snapshot(target)[0]), 'late retry retains every prior exact public proof')
    if unknown:
        need(any(value['id'] == c.network for value in checked(target.call('GET', '/v1/networks'))),
             'exact pinned repair evidence permits atomic first local application of the original committed outcome')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--coordinator', required=True)
    parser.add_argument('--go', required=True)
    parser.add_argument('--rust', required=True)
    parser.add_argument('--section', action='append', choices=('root', 'device', 'late-root', 'late-device', 'unknown-late-device'))
    parser.add_argument('--pair', action='append', choices=('go-go', 'go-rust', 'rust-go', 'rust-rust'))
    parser.add_argument('--work-dir', type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='peerspan-cold-invite-') as temporary:
        directory = args.work_dir or Path(temporary)
        if args.work_dir:
            directory.mkdir(parents=True, exist_ok=False)
        failures = 0
        for section in args.section or ('root', 'device', 'late-root', 'late-device', 'unknown-late-device'):
            for pair in args.pair or ('go-go', 'go-rust', 'rust-go', 'rust-rust'):
                ceremony = None
                try:
                    creator, requester = pair.split('-')
                    # Unix-domain socket paths have a small platform bound;
                    # retain full section labels in output, not nested paths.
                    folder = {'late-root': 'lr', 'late-device': 'ld',
                              'unknown-late-device': 'uld'}.get(section, section)
                    ceremony = Ceremony(args, directory / (folder + '-' + pair), creator, requester)
                    cold(ceremony, section.endswith('device'), 'late-' in section, section.startswith('unknown-'))
                    print('PASS ' + pair + ': cold ' + section + ' invitation exact feature choice and public LRI', flush=True)
                except Exception:
                    failures += 1
                    traceback.print_exc()
                finally:
                    if ceremony:
                        ceremony.close()
        return int(bool(failures))


if __name__ == '__main__':
    sys.exit(main())
