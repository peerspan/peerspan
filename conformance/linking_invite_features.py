#!/usr/bin/env python3
"""Independent signed invitation feature-choice checks.

Uses only the accepted feature-invitation contract, public vectors and the
independent Python signing oracle. Probe success verifies a fixed public binding,
never a private-token seed, admission, invitation consumption or durable adoption.
"""

import argparse
import copy
import json
from pathlib import Path
import sys

from linking_actions import NOW
from linking_activations import semantic_id, shift
from linking_paths import error
from linking_proof_selection import Case as SelectionCase, check_success
from linking_activations import proof
from linking_readers import b64, digest, lines, unb64, wire
from linking_roots import Author as RootAuthor
from linking_stored import ModeProbe


ROOT = Path(__file__).resolve().parents[1]
DAY = 86400
FIELDS = ('network_id', 'network_name', 'genesis_root_public_key', 'epoch', 'feature_id',
          'coordinator_address', 'coordinator_public_key', 'mode', 'host_invite_sha256',
          'person_invite_sha256', 'issuer_kind', 'person_public_key', 'certificate_id',
          'signer_public_key', 'issued_at', 'expires_at')


def binding_message(value):
    return lines('peerspan-link-invite-feature-v1', *(value[field] for field in FIELDS))


class Author(RootAuthor):
    def __init__(self, vectors):
        super().__init__(vectors)
        self.invite_cases = []
        self.serial = 0

    def binding(self, mode='member', issuer='network_root', context=None, expires=None,
                issued=NOW, epoch=0, root=None, ssh=False):
        context = context or self.root_context
        root = root or self.root
        self.serial += 1
        invite = self.key('feature-invite/' + str(self.serial))
        expires = expires or shift(issued, 3600)
        halves = {}
        for name, kind in (('host', 'invite-v1'), ('person', 'person-invite-v1')):
            if mode == ('person' if name == 'host' else 'host'):
                halves[name] = '-'
                continue
            grant = {'network_id': self.network, 'invite_public_key': invite,
                     'member': 'feature-recipient', 'invite_expires_at': expires}
            if name == 'person':
                grant['invite_epoch'] = epoch
            if issuer == 'person':
                grant = self.record(kind, context, grant, epoch=epoch)
            else:
                msg = lines('peerspan-person-invite-v1' if name == 'person' else 'peerspan-invite-v1',
                            self.network, *([epoch] if name == 'person' else []), invite, 'feature-recipient', expires)
                grant['signature'] = b64(self.signers[root].raw(msg))
            halves[name] = b64(wire(grant))
        descriptor = self.data['network']
        signer = self.signer(context) if issuer == 'person' else root
        value = {'format': 1, 'network_id': self.network, 'network_name': descriptor['name'],
                 'genesis_root_public_key': descriptor['genesis_root_public_key'], 'epoch': epoch,
                 'feature_id': self.data['feature_id'], 'coordinator_address': descriptor['coordinator_address'],
                 'coordinator_public_key': descriptor['coordinator_public_key'], 'mode': mode,
                 'host_invite_sha256': digest(unb64(halves['host'])) if halves['host'] != '-' else '-',
                 'person_invite_sha256': digest(unb64(halves['person'])) if halves['person'] != '-' else '-',
                 'issuer_kind': issuer, 'person_public_key': context['person'] if issuer == 'person' else '-',
                 'certificate_id': self.certificate_id(context) if issuer == 'person' else '-',
                 'signer_public_key': signer, 'issued_at': issued, 'expires_at': expires}
        self.sign(value, ssh)
        return value, halves, context

    def sign(self, binding, ssh=False, signer=None):
        key = self.signers[signer or binding['signer_public_key']]
        msg = binding_message(binding)
        binding['signature'] = (key.sshsig(msg) if ssh or binding['issuer_kind'] == 'person' else b64(key.raw(msg)))

    def request(self, binding, halves, context, intent=False, **changes):
        result = {'kind': 'invite_feature_intent' if intent else 'invite_feature',
                  'network_base64': b64(wire(self.data['network'])), 'catalog_base64': b64(wire(context['catalog'])),
                  'epoch': binding['epoch'], 'known_feature_id': self.data['feature_id'], 'now': context['now']}
        if intent:
            unsigned = {key: value for key, value in binding.items() if key != 'signature'}
            unsigned.update(host_invite_base64=halves['host'], person_invite_base64=halves['person'])
            result['unsigned_base64'] = b64(wire(unsigned))
        else:
            result.update(binding_base64=b64(wire(binding)), host_invite_base64=halves['host'],
                          person_invite_base64=halves['person'])
        result.update(changes)
        return result

    def success(self, binding, context):
        fields = ('feature_id', 'epoch', 'issuer_kind', 'person_public_key', 'certificate_id',
                  'signer_public_key', 'issued_at', 'expires_at')
        return {'ok': True, **{key: binding[key] for key in fields},
                'not_after': min(cert['not_after'] for cert in context['path'])
                             if binding['issuer_kind'] == 'person' and context['path'] else '-',
                'message_base64': b64(binding_message(binding))}

    def add(self, name, bundle, code=None, missing=(), intent=False, **changes):
        binding, halves, context = copy.deepcopy(bundle)
        request = self.request(binding, halves, context, intent, **changes)
        expected = error(code, missing) if code else self.success(binding, context)
        self.invite_cases.append((name, request, expected))
        return request

    def build(self):
        for mode in ('host', 'person', 'member'):
            for label, issuer, context in (('network_root', 'network_root', self.root_context),
                                           ('original_person', 'person', self.root_context),
                                           ('device', 'person', self.b)):
                bundle = self.binding(mode, issuer, context)
                self.add('forms/' + mode + '/' + label, bundle)
                self.add('intent/' + mode + '/' + label, bundle, intent=True)
        raw = self.binding()
        ssh = self.binding(ssh=True)
        self.add('root/sshsig', ssh)
        cold_context = copy.deepcopy(self.root_context)
        cold_context['now'] = shift(NOW, 2 * DAY)
        cold = self.binding(context=cold_context, issued=cold_context['now'])
        self.add('cold/late_existing_feature_signed_choice', cold, known_feature_id='-')
        self.add('cold/unsigned_intent_never_chooses_feature', raw, intent=True, code='upgrade_required', known_feature_id='-')
        for intent in (False, True):
            self.add('known_pin/mismatch/' + str(intent), raw, intent=intent,
                     known_feature_id='lf_' + '0' * 64, code='state_conflict')
        # Hashes bind exact public bytes, including valid JSON spelling aliases.
        alias = copy.deepcopy(raw)
        grant = unb64(alias[1]['host'])
        alias[1]['host'] = b64(grant + b' ')
        self.add('bytes/substituted_equivalent_half_fails_exact_hash', alias, code='invalid')
        alias[0]['host_invite_sha256'] = digest(unb64(alias[1]['host']))
        self.sign(alias[0])
        self.add('bytes/explicitly_bound_original_half_alias', alias)
        for field, changed in (('network_id', 'net_' + '0' * 64), ('network_name', 'other-network'),
                               ('genesis_root_public_key', self.quinn), ('coordinator_address', 'other.example:443'),
                               ('coordinator_public_key', self.quinn), ('signer_public_key', self.quinn),
                               ('person_public_key', self.person), ('certificate_id', 'root')):
            bad = copy.deepcopy(raw)
            bad[0][field] = changed
            self.sign(bad[0])
            self.add('binding/substituted_' + field, bad, code='invalid')
        bad = copy.deepcopy(raw)
        bad[0]['feature_id'] = 'lf_' + '0' * 64
        self.sign(bad[0])
        self.add('binding/substituted_feature', bad, code='state_conflict')
        bad = copy.deepcopy(raw)
        self.sign(bad[0], signer=self.quinn)
        self.add('signature/wrong_independent_key', bad, code='invalid')
        bad = copy.deepcopy(raw)
        bad[0]['signature'] = self.signers[self.root].sshsig(binding_message(bad[0]), namespace=b'wrong-context')
        self.add('signature/wrong_sshsig_namespace', bad, code='invalid')
        for field, value in (('mode', 'host'), ('host_invite_sha256', '-'), ('person_invite_sha256', '-')):
            bad = copy.deepcopy(raw)
            bad[0][field] = value
            self.sign(bad[0])
            self.add('halves/' + field, bad, code='invalid')
        other = self.binding()
        bad = copy.deepcopy(raw)
        bad[1]['person'] = other[1]['person']
        bad[0]['person_invite_sha256'] = digest(unb64(bad[1]['person']))
        self.sign(bad[0])
        self.add('halves/different_member_grant_key', bad, code='invalid')
        bad = copy.deepcopy(raw)
        bad[0]['expires_at'] = shift(bad[0]['expires_at'], 1)
        self.sign(bad[0])
        self.add('time/inner_expiry_mismatch', bad, code='invalid')
        self.add('time/exclusive_expiry', raw, now=raw[0]['expires_at'], code='expired')
        self.add('time/future_issued', raw, now=shift(raw[0]['issued_at'], -1), code='invalid')
        self.add('time/exact_30_days', self.binding(expires=shift(NOW, 30 * DAY)))
        self.add('time/over_30_days', self.binding(expires=shift(NOW, 30 * DAY + 1)), code='invalid')
        near = copy.deepcopy(self.b)
        near['now'] = shift(self.cert_b['not_after'], -3600)
        device = self.binding(issuer='person', context=near, issued=near['now'], expires=self.cert_b['not_after'])
        self.add('time/device_exact_path_expiry', device)
        self.add('time/device_expiry_above_path', self.binding(issuer='person', context=near, issued=near['now'],
                 expires=shift(self.cert_b['not_after'], 1)), code='forbidden')
        late = self.cert_b['not_after']
        context = copy.deepcopy(self.b)
        context['now'] = late
        self.add('authority/expired_device_not_revived_by_fresh_binding',
                 self.binding(issuer='person', context=context, issued=late, expires=shift(late, 3600)), code='authority_expired')
        withdrawn = copy.deepcopy(self.root_context)
        withdrawn['catalog'] = self.with_proofs(withdrawn['catalog'], [('admin_removal', self.removal(self.person))])
        self.add('authority/withdrawn_original_admin', self.binding(issuer='person', context=withdrawn), code='forbidden')
        self.add('authority/root_remains_independent_of_removed_admin', self.binding(context=withdrawn))
        revoked = copy.deepcopy(self.b)
        revoked['catalog'] = self.with_proofs(revoked['catalog'], [('device_revocation', self.revocation(self.cert_b))])
        self.add('authority/revoked_device', self.binding(issuer='person', context=revoked), code='device_revoked')
        invitation_key = json.loads(unb64(raw[1]['host']))['invite_public_key']
        restriction = self.signed_legacy('invite_revocation', {'invite_public_key': invitation_key, 'revoked_at': NOW})
        revoked_invite = copy.deepcopy(raw)
        revoked_invite[2]['catalog'] = self.with_proofs(revoked_invite[2]['catalog'], [('invite_revocation', restriction)])
        self.add('authority/revoked_invite_key', revoked_invite, code='forbidden')
        pending = copy.deepcopy(self.b)
        pending['catalog'] = self.without(pending['catalog'], lambda kind, obj: kind == 'activation')
        self.add('authority/missing_exact_issuer_activation', self.binding(issuer='person', context=pending),
                 code='proof_required', missing=[self.cert_b['request_id']])
        narrow = self.narrowed(1, 'invite-feature/no-admin-scope')
        self.add('authority/insufficient_device_scope', self.binding(issuer='person', context=narrow), code='forbidden')
        rotated = self.context(self.catalog(current=True))
        current = self.binding(context=rotated, epoch=1, root=self.roots[1])
        self.add('root/current_rotated_root', current)
        self.add('root/old_root_cannot_issue_binding', self.binding(context=rotated, epoch=1), code='invalid')
        # Strict shape checks are independent of whether a canonical message
        # could otherwise be reconstructed from the expected known fields.
        for label, changed in (('unknown', dict(raw[0], extra=True)), ('null', dict(raw[0], mode=None)),
                                ('fractional_time', dict(raw[0], issued_at=NOW.replace('Z', '.1Z'))),
                                ('noncanonical_key', dict(raw[0], signer_public_key=self.root.rstrip('='))),
                                ('format_bool', dict(raw[0], format=True))):
            request = self.add('strict/binding/' + label, raw, code='invalid')
            request['binding_base64'] = b64(wire(changed))
        for label, encoded in (('duplicate', wire(raw[0])[:-1] + b',"mode":"member"}'),
                                ('trailing', wire(raw[0]) + b'{}'), ('invalid_utf8', b'{"mode":"\xff"}')):
            request = self.add('strict/binding/' + label, raw, code='invalid')
            request['binding_base64'] = b64(encoded)
        request = self.add('strict/half_noncanonical_base64', raw, code='invalid')
        request['host_invite_base64'] = ' ' + raw[1]['host']
        request = self.add('strict/unsigned_signature_injection', raw, intent=True, code='invalid')
        unsigned = json.loads(unb64(request['unsigned_base64']))
        unsigned['signature'] = raw[0]['signature']
        request['unsigned_base64'] = b64(wire(unsigned))
        request = self.add('strict/outer_unknown', raw, code='invalid')
        request['seed'] = 'never-accepted'
        return self.invite_cases

    def selection_cases(self):
        cases = []
        def add(name, bundle, required=(), excluded=(), code=None):
            binding, halves, context = bundle
            seed = {'binding': binding, 'host_invite_base64': halves['host'], 'person_invite_base64': halves['person']}
            request = {'kind': 'proof_selection', 'network_base64': b64(wire(self.data['network'])),
                       'catalog_base64': b64(wire(context['catalog'])),
                       'seeds': [{'kind': 'invite_feature', 'body_base64': b64(wire(seed))}],
                       'epoch': binding['epoch'], 'known_feature_id': self.data['feature_id'], 'now': context['now']}
            cases.append(SelectionCase(name, request, context['catalog'], set(required), set(excluded), error(code) if code else None))
        def ids(catalog, kinds):
            return {entry['id'] for entry in catalog['objects'] if entry['kind'] in kinds}
        root = self.binding()
        add('selector/root_exact_feature', root, ids(root[2]['catalog'], {'feature'}))
        device = self.binding(issuer='person', context=self.b)
        required = ids(device[2]['catalog'], {'feature', 'activation', 'certificate'})
        add('selector/device_exact_activation_closure', device, required)
        large = copy.deepcopy(device)
        unrelated = []
        for version in range(1, 5):
            unsigned = dict(self.payloads['policy-v2'], person_public_key=self.quinn, version=version)
            record = self.record('policy-v2', self.root_person(self.quinn), unsigned)
            original = wire(unsigned)
            record['payload_base64'] = b64(original + b' ' * (240 * 1024 - len(original)))
            self.oracle.resign('person_record', record, self.quinn)
            unrelated.append(('person_record', record))
        large[2]['catalog'] = self.with_proofs(large[2]['catalog'], unrelated)
        assert len(wire(large[2]['catalog'])) > 1024 * 1024
        add('selector/unrelated_large_catalog_omitted', large, required,
            {proof(kind, value)['id'] for kind, value in unrelated})
        current = self.binding(context=self.context(self.catalog(current=True)), epoch=1, root=self.roots[1])
        add('selector/current_root_chain_exact_source_bytes', current, ids(current[2]['catalog'], {'feature', 'rotation'}))
        unsigned = copy.deepcopy(root)
        unsigned[0]['signature'] = '-'
        add('selector/unsigned_binding_is_not_a_public_seed', unsigned, code='invalid')
        return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go-probe')
    parser.add_argument('--rust-probe')
    parser.add_argument('--self-check', action='store_true')
    args = parser.parse_args()
    probes = [(label, path) for label, path in (('go', args.go_probe), ('rust', args.rust_probe)) if path]
    if not probes and not args.self_check:
        parser.error('supply a probe or --self-check')
    vectors = {path.name: json.loads(path.read_bytes()) for path in sorted((ROOT / 'conformance/vectors').glob('*.json'))}
    author = Author(vectors)
    signatures = author.oracle.fixture_self_check()
    cases = author.build()
    selection = author.selection_cases()
    print(f'Independent oracle: {signatures} fixture signatures reproduced; {len(cases)} invite-feature cases per mode.', flush=True)
    failures = 0
    for label, executable in probes:
        for stored in (False, True):
            probe = ModeProbe(label, executable, stored)
            try:
                for name, request, expected in cases:
                    actual = probe.exchange(request)
                    if actual != expected:
                        failures += 1
                        print(f'FAIL {label}/{"stored" if stored else "normal"} {name}: expected {expected!r}; got {actual!r}', file=sys.stderr, flush=True)
            finally:
                probe.close()
            print(f'{label}/{"stored" if stored else "normal"}: {len(cases)} invite-feature checks completed.', flush=True)
        probe = ModeProbe(label, executable, True)
        try:
            for case in selection:
                actual = probe.exchange(case.request)
                try:
                    if case.expected is not None:
                        assert actual == case.expected, actual
                    else:
                        check_success(case, actual)
                except AssertionError as exc:
                    failures += 1
                    print(f'FAIL {label}/stored {case.name}: {exc}', file=sys.stderr, flush=True)
        finally:
            probe.close()
        print(f'{label}/stored: {len(selection)} invite-feature proof-selection checks completed.', flush=True)
    return int(bool(failures))


if __name__ == '__main__':
    sys.exit(main())
