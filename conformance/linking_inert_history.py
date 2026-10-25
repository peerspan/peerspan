#!/usr/bin/env python3
"""Independent aggregate-provenance/current-authority separation checks.

Accepted history contracts and public signing helpers define these cases.
Independent current host admission/binding cannot activate a withdrawn complete
transcript's certificate or revive access through that certificate.
"""

import argparse
import copy
import json
from pathlib import Path
import sys

from linking_activations import Author as ActivationAuthor
from linking_paths import error
from linking_policy_state import Author as PolicyAuthor
from linking_readers import Probe, b64, unb64, wire
from linking_records import Facts

ROOT = Path(__file__).resolve().parents[1]


class Author(PolicyAuthor):
    def build(self):
        catalog = copy.deepcopy(self.c['catalog'])
        withdrawal = self.removal(self.person, revoke=True, removed_at=self.c['now'])
        additions = [('admin_removal', withdrawal)]
        for cert in (self.cert_b, self.cert_c):
            host = cert['host_public_key']
            admission = self.signed_legacy('host_admission', {'epoch': 0, 'host_public_key': host,
                                          'member': 'alice', 'admitted_at': self.c['now']}, self.root)
            binding = self.record('host-bind-v1', self.root_context,
                                  {'network_id': self.network, 'person_public_key': self.person,
                                   'host_public_key': host, 'bound_at': self.c['now']})
            ack = {'format': 1, 'feature_id': self.data['feature_id'], 'host_public_key': host}
            self.oracle.resign('feature_ack', ack, host)
            additions.extend((('host_admission', admission), ('person_record', binding), ('join_ack', ack)))
        catalog = self.with_proofs(catalog, additions)
        b_policy = self.candidate('policy-v2', self.b, version=77)
        c_group = self.candidate('group-v1', self.c, version=17)
        complete = self.with_proofs(catalog, [b_policy, c_group])
        context = self.context(complete, now=self.c['now'])
        expected = {'ok': True, 'network_id': self.network, 'feature_id': self.data['feature_id'],
                    'policies': [self.row(b_policy, active=False, code='forbidden')],
                    'groups': [self.row(c_group, active=False, code='forbidden')]}
        request = self.request(context=context)
        self.add_request('access/independent_readmission_does_not_activate_b', request, expected)
        c_policy = self.candidate('policy-v2', self.c, version=78)
        descendant = self.with_proofs(complete, [c_policy])
        self.add_request('access/descendant_remains_inactive', self.request(context=self.context(descendant)),
                         dict(expected, policies=[self.row(c_policy, active=False, code='forbidden')]))
        facts = Facts(self).person(self.person, 'alice', administrator=False)
        for cert in (self.cert_b, self.cert_c):
            facts.host(cert['host_public_key'], 'alice').bind(cert['host_public_key'], self.person)
        self.add_request('facts/complete_inert_certificates_never_enter_activated_set',
                         {'kind': 'catalog_facts', 'network_base64': b64(wire(self.data['network'])),
                          'catalog_base64': b64(wire(descendant)), 'epoch': 0,
                          'known_feature_id': self.data['feature_id'], 'now': self.c['now']}, facts.reply())
        for label, actor, version in (('b', self.b, 78), ('c', self.c, 79)):
            candidate = self.candidate('policy-v2', actor, version=version)[1]
            self.add_request('action/' + label + '/new_scope1_policy_forbidden',
                             {'kind': 'action_authorization', 'action_kind': 'person_record',
                              'network_base64': b64(wire(self.data['network'])), 'catalog_base64': b64(wire(complete)),
                              'action_base64': b64(wire(candidate)), 'epoch': 0,
                              'known_feature_id': self.data['feature_id'], 'person_public_key': self.person,
                              'certificate_id': self.certificate_id(actor), 'now': self.c['now']}, error('forbidden'))
        for label, fixture in (('b', self.base), ('c', self.c_source)):
            selected = self.request_activation(fixture, complete)
            self.add_request('selected/' + label + '/historical_activation_still_forbidden', selected, error('forbidden'))
        forged = copy.deepcopy(self.c_source['activation'])
        forged['owner']['authority_signature'] = b64(bytes(64))
        damaged = self.with_proofs(self.without(complete, lambda kind, obj: kind == 'activation' and
                    obj['request']['request_id'] == forged['request']['request_id']), [('activation', forged)])
        self.add_request('strict/withdrawal_never_hides_bad_original_signature',
                         self.request(context=self.context(damaged)), error('invalid'))
        missing = self.without(complete, lambda kind, obj: kind == 'activation' and
                               obj['request']['request_id'] == self.base['activation']['request']['request_id'])
        self.add_request('strict/complete_ancestor_provenance_required',
                         self.request(context=self.context(missing)),
                         error('proof_required', [self.base['activation']['request']['request_id']]))
        return self.cases

    def request_activation(self, fixture, catalog):
        return ActivationAuthor.request(self, fixture, catalog=catalog, verification='historical',
                                        known_feature_id=self.data['feature_id'], now=self.c['now'])


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
    print(f'Independent oracle: {fixed} fixture signatures reproduced; {len(cases)} inert-history checks.', flush=True)
    failures = 0
    for label, executable in probes:
        probe = Probe(label, executable, 60)
        try:
            for case in cases:
                actual = probe.exchange(case.request)
                if actual != case.expected:
                    failures += 1
                    print(f'FAIL {label} {case.name}: expected {str(case.expected)[:3000]}; received {str(actual)[:3000]}', file=sys.stderr)
        finally:
            probe.close()
        print(f'{label}: {len(cases)} inert-history checks completed.', flush=True)
    return int(bool(failures))


if __name__ == '__main__':
    sys.exit(main())
