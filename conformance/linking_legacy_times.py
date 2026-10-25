#!/usr/bin/env python3
"""Independent legacy UTC nanosecond compatibility and strict new-time checks.

Only accepted public contracts/fixtures and independent signers define these
cases. Original signed timestamp strings are retained, never rounded/re-spelled.
This suite does not assert persistence, live writers or transport readiness.
"""

import argparse
import copy
import json
from pathlib import Path
import sys

from linking_actions import NOW
from linking_activations import Author as ActivationAuthor, payload, proof, shift, sort_catalog
from linking_features import Author as FeatureAuthor
from linking_history import legacy_message
from linking_paths import error
from linking_policy_state import Author as PolicyAuthor, legacy_group_message, legacy_policy_message
from linking_readers import b64, lines, message, unb64, wire
from linking_redemptions import Author as RedemptionAuthor
from linking_roots import Author as RootAuthor
from linking_stored import ModeProbe
from linking_transport_evidence import Author as TransportAuthor


ROOT = Path(__file__).resolve().parents[1]


def fraction(value, digits='123456789'):
    assert value.endswith('Z')
    return value[:-1] + '.' + digits + 'Z'


class Author(RootAuthor):
    def __init__(self, vectors):
        super().__init__(vectors)
        feature = next(json.loads(unb64(entry['body_base64'])) for entry in self.base['catalog']['objects'] if entry['kind'] == 'feature')
        self.issued = feature['proposal']['issued_at']

    def sign_legacy(self, kind, value):
        if kind in ('person_admission', 'host_admission', 'person_removal', 'host_revocation',
                    'invite_revocation', 'host_leave', 'host_unbinding'):
            msg = legacy_message(kind, value)
            signer = (value['host_public_key'] if kind == 'host_leave' else value['person_public_key']
                      if kind == 'host_unbinding' else self.roots.get(value.get('epoch', 0), self.root))
            value['signature'] = self.signers[signer].sshsig(msg) if kind == 'host_unbinding' else b64(self.signers[signer].raw(msg))
        elif kind == 'admin_delegation':
            msg = lines('peerspan-admin-delegate-v1', *(value[key] for key in ('network_id', 'epoch', 'person_public_key', 'delegated_at')))
            value['signature'] = b64(self.signers[self.roots[value['epoch']]].raw(msg))
        elif kind == 'host_binding':
            msg = lines('peerspan-host-bind-v1', *(value[key] for key in ('network_id', 'person_public_key', 'host_public_key', 'bound_at')))
            value['signature'] = self.signers[value['person_public_key']].sshsig(msg)
            value['host_signature'] = b64(self.signers[value['host_public_key']].raw(msg))
        else:
            raise AssertionError(kind)
        return value

    def fractional_base(self, digits='123456789'):
        catalog = copy.deepcopy(self.base['catalog'])
        for index, entry in enumerate(catalog['objects']):
            if entry['kind'] == 'feature':
                continue
            value = json.loads(unb64(entry['body_base64']))
            for field in list(value):
                if field.endswith('_at'):
                    value[field] = fraction(value[field], digits)
            catalog['objects'][index] = proof(entry['kind'], self.sign_legacy(entry['kind'], value))
        sort_catalog(catalog)
        return catalog

    def reader_invalid(self, name, kind, obj, signer, device='-'):
        self.add_request('strict/' + name, {'kind': kind, 'object_base64': b64(wire(obj)),
                         'signer_public_key': signer, 'device_public_key': device}, error('invalid'))

    def baselines_and_authority(self):
        for digits in ('0', '1', '12', '123', '1234', '12345', '123456', '1234567', '12345678', '123456789'):
            catalog = self.fractional_base(digits)
            self.add('legacy/full_bootstrap/' + digits, catalog)
        catalog = self.fractional_base()
        feature = next(json.loads(unb64(entry['body_base64'])) for entry in catalog['objects'] if entry['kind'] == 'feature')
        before_feature = self.without(catalog, lambda kind, obj: kind == 'feature')
        self.add_request('legacy/feature_first_with_fractional_bootstrap',
                         FeatureAuthor.request(self, feature, before_feature, now=NOW), FeatureAuthor.success(self, feature))
        self.add_request('legacy/full_first_activation_with_fractional_bootstrap',
                         ActivationAuthor.request(self, catalog=catalog), ActivationAuthor.success(self, self.base['activation']))
        rotation = self.rotation(1, rotated_at=fraction(NOW))
        self.add('legacy/rotation', self.with_proofs(catalog, [('rotation', rotation)]), self.stale_facts(), epoch=1)
        host_a, host_q = (self.data['keys'][name]['public_key'] for name in ('host_a', 'host_q'))
        attestation = self.attestation(host_a, epoch=0)
        attestation['attested_at'] = fraction(NOW)
        attestation['signature'] = b64(self.signers[self.root].raw(lines('peerspan-attest-v1', self.network, 0, host_a, 'alice', attestation['attested_at'])))
        self.add('legacy/attestation', self.with_proofs(catalog, [('attestation', attestation)]))
        removal = self.removal(self.quinn, version=1, removed_at=fraction(NOW))
        facts = self.base_facts.clone()
        facts.persons[self.quinn]['administrator'] = False
        self.add('legacy/format1_admin_removal', self.with_proofs(catalog, [('admin_removal', removal)]), facts)
        for kind, fields, facts in (
                ('person_removal', {'person_public_key': self.quinn, 'removed_at': fraction(NOW)},
                 self.base_facts.clone().person(self.quinn, 'quinn', admitted=False).bind(host_q, '-')),
                ('host_revocation', {'host_public_key': host_q, 'revoked_at': fraction(NOW)},
                 self.base_facts.clone().host(host_q, 'quinn', admitted=False).bind(host_q, '-')),
                ('host_leave', {'host_public_key': host_q, 'left_at': fraction(NOW)},
                 self.base_facts.clone().host(host_q, 'quinn', admitted=False).bind(host_q, '-')),
                ('host_unbinding', {'person_public_key': self.person, 'host_public_key': host_a, 'unbound_at': fraction(NOW)},
                 self.base_facts.clone().bind(host_a, '-')),
                ('invite_revocation', {'invite_public_key': self.target_invite, 'revoked_at': fraction(NOW)}, self.base_facts)):
            obj = self.sign_legacy(kind, dict(network_id=self.network, **fields))
            self.add('legacy/restriction/' + kind, self.with_proofs(catalog, [(kind, obj)]), facts)
        for kind, value in (('coordinator_move', TransportAuthor.move(self, moved_at=fraction(NOW))),
                            ('coordinator_successor', TransportAuthor.successor(self, signed_at=fraction(NOW)))):
            self.add('legacy/' + kind, self.with_proofs(catalog, [(kind, value)]))

    def memberships_and_redemptions(self):
        invite = self.key('legacy-times/invite')
        expires = fraction(shift(NOW, 86400))
        joined = fraction(shift(NOW, -60))
        for kind, subject_field, signature_field, domain, person in (
                ('host_membership', 'host_public_key', 'host_signature', 'peerspan-member-v1', False),
                ('person_membership', 'person_public_key', 'person_signature', 'peerspan-person-member-v1', True)):
            subject = self.person if person else self.data['keys']['host_a']['public_key']
            obj = {'network_id': self.network, 'member': 'alice', 'invite_public_key': invite,
                   'invite_expires_at': expires, 'joined_at': joined, subject_field: subject}
            if person:
                obj['invite_epoch'] = 0
            grant = lines('peerspan-person-invite-v1', self.network, 0, invite, 'alice', expires) if person else lines('peerspan-invite-v1', self.network, invite, 'alice', expires)
            obj['invite_signature'] = b64(self.signers[self.root].raw(grant))
            obj[signature_field] = b64(self.signers[invite].raw(lines(domain, self.network, invite, subject, joined)))
            catalog = self.without(self.base['catalog'], lambda name, value: name == ('person_admission' if person else 'host_admission') and value[subject_field] == subject)
            self.add('legacy/' + kind, self.with_proofs(catalog, [(kind, obj)]))
            # One nanosecond above expiry cannot be rounded into an equal second.
            obj['joined_at'] = fraction(shift(NOW, 86400), '123456790')
            obj[signature_field] = b64(self.signers[invite].raw(lines(domain, self.network, invite, subject, obj['joined_at'])))
            self.add('precision/' + kind + '/one_nanosecond_late', self.with_proofs(catalog, [(kind, obj)]), code='invalid')
        for mode, action in (('member', 'skip'), ('person', 'admit')):
            red = RedemptionAuthor.redemption(self, mode, action, style='legacy_root', host=self.target_host,
                    person=self.person if action == 'skip' else self.new_person, label='alice' if action == 'skip' else 'dana',
                    invite=self.key('legacy-times/redemption/' + mode), expires=fraction(NOW, '000000001'), joined=NOW)
            extra = [('invite_redemption', red)]
            facts = self.base_facts.clone()
            if mode == 'member':
                extra += [('join_ack', self.ack(self.target_host))]
                facts.host(self.target_host, 'alice')
            else:
                facts.person(self.new_person, 'dana')
            self.add('legacy/redemption_inline_invite/' + mode, self.with_proofs(self.base['catalog'], extra), facts)
            strict = copy.deepcopy(red)
            strict['joined_at'] = fraction(NOW)
            # Re-sign the member to isolate wrapper lexical rejection.
            key = strict['host_invite' if mode == 'member' else 'person_invite']['invite_public_key']
            domain = 'peerspan-member-v1' if mode == 'member' else 'peerspan-person-member-v1'
            field = 'host_member_signature' if mode == 'member' else 'person_member_signature'
            subject = strict['host_public_key' if mode == 'member' else 'person_public_key']
            strict[field] = b64(self.signers[key].raw(lines(domain, self.network, key, subject, strict['joined_at'])))
            self.add('strict/redemption_wrapper/' + mode, self.with_proofs(self.base['catalog'], [('invite_redemption', strict), *extra[1:]]), code='invalid')

    def access_and_malformed(self):
        for suffix in ('policy-v1', 'policy-v2', 'group-v1'):
            changes = {'defined_at': fraction(NOW)} if suffix == 'group-v1' else {
                'issued_at': fraction(shift(NOW, -86400), '000000001'), 'valid_until': fraction(NOW, '000000001')}
            candidate = PolicyAuthor.candidate(self, suffix, legacy=True, **changes)
            request = PolicyAuthor.request(self, [candidate])
            selected = PolicyAuthor.row(candidate)
            expected = {'ok': True, 'network_id': self.network, 'feature_id': self.data['feature_id'],
                        'policies': [] if suffix == 'group-v1' else [selected],
                        'groups': [selected] if suffix == 'group-v1' else []}
            self.add_request('legacy/access/' + suffix, request, expected)
        original = next(json.loads(unb64(entry['body_base64'])) for entry in self.base['catalog']['objects']
                        if entry['kind'] == 'person_admission' and json.loads(unb64(entry['body_base64']))['person_public_key'] == self.person)
        source = self.without(self.base['catalog'], lambda kind, value: kind == 'person_admission' and value['person_public_key'] == self.person)
        for label, timestamp in (('empty', NOW[:-1] + '.Z'), ('ten_digits', fraction(NOW, '1234567890')),
                                 ('offset', NOW[:-1] + '.1+00:00'), ('comma', NOW[:-1] + ',1Z'),
                                 ('space', NOW + ' '), ('calendar', '2026-02-30T12:02:00.1Z')):
            value = self.sign_legacy('person_admission', dict(original, admitted_at=timestamp))
            self.add('malformed/legacy/' + label, self.with_proofs(source, [('person_admission', value)]), code='invalid')
        value = self.sign_legacy('person_admission', dict(original, admitted_at=fraction(original['admitted_at'])))
        value['admitted_at'] = original['admitted_at']
        self.add('signature/rounding_signed_timestamp_is_not_allowed', self.with_proofs(source, [('person_admission', value)]), code='invalid')

    def strict_new_objects(self):
        for suffix, value in self.payloads.items():
            changed = copy.deepcopy(value)
            field = next(field for field in changed if field.endswith('_at') or field in ('valid_until', 'invite_expires_at'))
            changed[field] = fraction(changed[field])
            obj = self.record(suffix, unsigned=changed)
            self.reader_invalid('typed_payload/' + suffix, 'person_record', obj, self.person)
        cert = dict(self.cert_b, issued_at=fraction(self.cert_b['issued_at']))
        self.oracle.resign('certificate', cert, self.person)
        self.reader_invalid('certificate', 'certificate', cert, self.person)
        for kind, obj in (('checkpoint', self.checkpoint(['ar_' + 'a' * 64], issued_at=fraction(NOW))),
                          ('device_revocation', self.revocation(self.cert_b, revoked_at=fraction(NOW))),
                          ('admin_removal_v2', self.removal(self.quinn, removed_at=fraction(NOW)))):
            self.reader_invalid(kind, kind, obj, self.root if kind == 'admin_removal_v2' else self.person)
        feature = next(json.loads(unb64(entry['body_base64'])) for entry in self.base['catalog']['objects'] if entry['kind'] == 'feature')
        proposal = feature['proposal']
        proposal['issued_at'] = fraction(proposal['issued_at'])
        self.oracle.resign('feature_proposal', proposal, self.root)
        self.reader_invalid('feature_proposal', 'feature_proposal', proposal, self.root)

    def build(self):
        self.baselines_and_authority()
        self.memberships_and_redemptions()
        self.access_and_malformed()
        self.strict_new_objects()
        return self.cases


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
    fixed = author.oracle.fixture_self_check()
    cases = author.build()
    print(f'Independent oracle: {fixed} signatures reproduced; {len(cases)} legacy-time checks per mode.', flush=True)
    failures = 0
    for label, executable in probes:
        for stored in (False, True):
            probe = ModeProbe(label, executable, stored)
            try:
                for case in cases:
                    actual = probe.exchange(case.request)
                    if actual != case.expected:
                        failures += 1
                        print(f'FAIL {label} stored={stored} {case.name}: expected {case.expected}; received {actual}', file=sys.stderr)
            finally:
                probe.close()
            print(f'{label}: {len(cases)} legacy-time checks completed in ' + ('stored' if stored else 'normal') + ' mode.', flush=True)
    return int(bool(failures))


if __name__ == '__main__':
    sys.exit(main())
