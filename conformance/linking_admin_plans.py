#!/usr/bin/env python3
"""Independent exact administrator withdrawal retention-plan conformance.

The public host contract defines planning as a verified read with no signature,
withdrawal or current-authority claim. No implementation source is imported.
"""

import argparse
import copy
import json
from pathlib import Path
import sys

from linking_actions import NOW
from linking_activations import proof, semantic_id, sort_catalog
from linking_history import legacy_message
from linking_paths import error
from linking_policy_state import legacy_group_message
from linking_readers import b64, digest, lines, unb64, wire
from linking_redemptions import Author as RedemptionAuthor
from linking_roots import Author as RootAuthor
from linking_stored import ModeProbe


ROOT = Path(__file__).resolve().parents[1]


class Author(RootAuthor):
    redemption = RedemptionAuthor.redemption

    def __init__(self, vectors):
        super().__init__(vectors)
        self.plan_cases = []

    def add(self, name, source=None, tags=(), person=None, code=None, missing=(), now=NOW):
        request = {'kind': 'admin_removal_plan', 'network_base64': b64(wire(self.data['network'])),
                   'catalog_base64': b64(wire(source or self.base['catalog'])), 'epoch': 0,
                   'known_feature_id': self.data['feature_id'], 'now': now,
                   'person_public_key': person or self.person}
        expected = error(code, missing) if code else {'ok': True, 'kept': sorted(set(tags))}
        self.plan_cases.append((name, request, expected))
        return request

    @staticmethod
    def ar(value):
        return 'record:' + semantic_id('person_record', value)

    def group(self, name, version, signer):
        value = {'network_id': self.network, 'name': name, 'version': version,
                 'defined_at': NOW, 'members': ['person_' + digest(unb64(self.person))]}
        msg = legacy_group_message(value)
        value['signature'] = b64(self.signers[signer].raw(msg)) if signer == self.root else self.signers[signer].sshsig(msg)
        return value

    def build(self):
        nested_b = self.ar(self.record_b)
        nested_c = self.ar(self.records_c['admission'])
        self.add('baseline/no_administrator_issued_grants')
        self.add('activation/exact_nested_original_record', self.b['catalog'], [nested_b])
        self.add('activation/delegated_nested_original_records', self.c['catalog'], [nested_b, nested_c])
        unsigned = {'network_id': self.network, 'epoch': 0, 'person_public_key': self.key('plan/new-person'),
                    'member': 'new-person', 'admitted_at': NOW}
        ordinary = self.record('person-admit-v1', self.b, unsigned)
        source = self.with_proofs(self.b['catalog'], [('person_record', ordinary)])
        self.add('ordinary/exact_ar_with_activated_issuer', source, [nested_b, self.ar(ordinary)])
        for kind in ('policy-v2', 'host-bind-v1'):
            value = self.record(kind)
            self.add('ordinary/owner_scope_excluded/' + kind,
                     self.with_proofs(self.base['catalog'], [('person_record', value)]))
        host = self.key('plan/legacy-host')
        grants = [('host_admission', self.signed_legacy('host_admission',
                   {'epoch': 0, 'host_public_key': host, 'member': 'legacy-host', 'admitted_at': NOW}, self.person, True)),
                  ('person_admission', self.signed_legacy('person_admission',
                   {key: value for key, value in unsigned.items() if key != 'network_id'}, self.person, True))]
        tags = ['legacy:' + digest(legacy_message(kind, value)) for kind, value in grants]
        self.add('legacy/exact_signed_message_digests', self.with_proofs(self.base['catalog'],
                 [*grants, ('join_ack', self.ack(host))]), tags)
        first, second = self.group('planned-group', 1, self.person), self.group('planned-group', 2, self.person)
        self.add('group/highest_selected_active_only', self.with_proofs(self.base['catalog'], [('group', first), ('group', second)]),
                 ['legacy:' + digest(legacy_group_message(second))])
        high = self.group('planned-group', 3, self.quinn)
        removed = self.removal(self.quinn)
        self.add('group/inactive_higher_never_exposes_lower', self.with_proofs(self.base['catalog'],
                 [('group', first), ('group', high), ('admin_removal', removed)]))
        modern = self.record('group-v1')
        self.add('group/selected_person_authorization_ar', self.with_proofs(self.base['catalog'], [('person_record', modern)]), [self.ar(modern)])
        red = self.redemption('member', 'admit', host=self.key('plan/redemption-host'),
                              person=self.key('plan/redemption-person'), invite=self.key('plan/invite'), joined=NOW)
        tags = [self.ar(red['host_invite']), self.ar(red['person_invite']), 'redemption:' + proof('invite_redemption', red)['id']]
        red_source = self.with_proofs(self.base['catalog'], [('invite_redemption', red), ('join_ack', self.ack(red['host_public_key']))])
        self.add('redemption/exact_pair_and_both_real_invite_halves', red_source, tags)
        legacy = self.redemption('host', 'none', style='legacy_person', host=self.key('plan/legacy-redemption-host'),
                                 invite=self.key('plan/legacy-invite'), joined=NOW)
        grant = legacy['host_invite']
        msg = lines('peerspan-invite-v1', self.network, grant['invite_public_key'], grant['member'], grant['invite_expires_at'])
        self.add('redemption/legacy_admin_half_and_exact_pf', self.with_proofs(self.base['catalog'],
                 [('invite_redemption', legacy), ('join_ack', self.ack(legacy['host_public_key']))]),
                 ['legacy:' + digest(msg), 'redemption:' + proof('invite_redemption', legacy)['id']])
        expired = self.cert_b['not_after']
        self.add('history/incomplete_expired_issuer_fails_whole_source', source, code='proof_required',
                 missing=[semantic_id('person_record', ordinary)], now=expired)
        retained = self.checkpoint([semantic_id('person_record', ordinary)], issued_at=expired)
        self.add('history/exact_original_person_retention', self.with_proofs(source, [('checkpoint', retained)]),
                 [nested_b, self.ar(ordinary)], now=expired)
        excluded = self.record('person-admit-v1', unsigned=unsigned)
        self.add('history/withdrawn_excluded_grant_stays_excluded', self.with_proofs(self.base['catalog'],
                 [('person_record', excluded), ('admin_removal', self.removal(self.person))]))
        pending = self.with_proofs(self.base['catalog'], [('certificate', self.cert_b), ('person_record', ordinary)])
        self.add('history/pending_issuer_requires_exact_activation', pending, code='proof_required', missing=[self.cert_b['request_id']])
        aliases = copy.deepcopy(red_source)
        aliases['objects'].append(proof('invite_redemption', raw=json.dumps(red, indent=2).encode()))
        sort_catalog(aliases)
        alias_tag = 'redemption:' + aliases['objects'][next(index for index, entry in enumerate(aliases['objects'])
                         if entry['kind'] == 'invite_redemption' and json.loads(unb64(entry['body_base64'])) == red and
                            entry['id'] != proof('invite_redemption', red)['id'])]['id']
        self.add('bytes/each_exact_completed_redemption_alias', aliases, tags + [alias_tag])
        # A root key can also be an admitted person. Legacy root recognition has
        # precedence, while an explicit person envelope retains its named role.
        overlap = self.with_proofs(self.base['catalog'], [
            ('person_admission', self.admission('person_admission', self.root, 'root-person', epoch=0)),
            ('admin_delegation', self.role(self.root, epoch=0))])
        root_group = self.group('root-overlap', 1, self.root)
        person_group = self.record('group-v1', self.root_person(self.root, overlap),
                                  dict(self.payloads['group-v1'], name='person-overlap'))
        self.add('roles/legacy_root_precedence_explicit_person_distinction', self.with_proofs(overlap,
                 [('group', root_group), ('person_record', person_group)]), [self.ar(person_group)], person=self.root)
        forged = copy.deepcopy(self.cert_b)
        self.oracle.resign('certificate', forged, self.quinn)
        self.add('strict/forged_unused_source_object', self.with_proofs(self.base['catalog'], [('certificate', forged)]), code='invalid')
        request = self.add('strict/unknown_outer', code='invalid')
        request['revoke_admitted'] = False
        request = self.add('strict/null_person', code='invalid')
        request['person_public_key'] = None
        request = self.add('strict/noncanonical_person', code='invalid')
        request['person_public_key'] = self.person.rstrip('=')
        return self.plan_cases


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
    print(f'Independent oracle: {signatures} fixture signatures reproduced; {len(cases)} exact administrator-plan cases.', flush=True)
    failures = 0
    for label, path in probes:
        probe = ModeProbe(label, path, True)
        try:
            for name, request, expected in cases:
                actual = probe.exchange(request)
                if actual != expected:
                    failures += 1
                    print(f'FAIL {label} {name}: expected {expected!r}; got {actual!r}', file=sys.stderr, flush=True)
        finally:
            probe.close()
        print(f'{label}: {len(cases)} administrator-plan checks completed.', flush=True)
    return int(bool(failures))


if __name__ == '__main__':
    sys.exit(main())
