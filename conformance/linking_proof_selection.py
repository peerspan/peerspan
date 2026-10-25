#!/usr/bin/env python3
"""Independent sufficient-proof selection checks from the public host contract.

Tests required/excluded IDs and exact retained source bytes. Conservative
alternatives/aliases are permitted. Seeds supply no facts and this suite claims
no current signing authorization or ceremony completion from selection success.
"""

import argparse
import copy
from dataclasses import dataclass
import json
from pathlib import Path
import sys

from linking_actions import NOW
from linking_activations import payload, proof, semantic_id, shift, sort_catalog
from linking_paths import error
from linking_readers import b64, unb64, wire
from linking_roots import Author as RootAuthor
from linking_stored import ModeProbe


ROOT = Path(__file__).resolve().parents[1]
KIB = 1024


@dataclass
class Case:
    name: str
    request: dict
    source: dict
    required: set
    excluded: set
    expected: dict = None
    alternatives: tuple = ()


class Author(RootAuthor):
    def __init__(self, vectors):
        super().__init__(vectors)
        self.selection_cases = []

    @staticmethod
    def ids(catalog, predicate):
        return {entry['id'] for entry in catalog['objects'] if predicate(entry['kind'], json.loads(unb64(entry['body_base64'])))}

    def select_case(self, name, source=None, seeds=None, required=(), excluded=(), code=None, missing=(), alternatives=(), **context):
        source = source or self.base['catalog']
        seeds = seeds if seeds is not None else [('certificate', self.cert_b)]
        request = {'kind': 'proof_selection', 'network_base64': b64(wire(self.data['network'])),
                   'catalog_base64': b64(wire(source)), 'seeds': [{'kind': kind, 'body_base64': b64(wire(body)) if isinstance(body, dict) else b64(body)} for kind, body in seeds],
                   'epoch': 0, 'known_feature_id': self.data['feature_id'], 'now': NOW}
        request.update(context)
        self.selection_cases.append(Case(name, request, source, set(required), set(excluded), error(code, missing) if code else None,
                                         tuple(set(group) for group in alternatives)))
        return request

    def build(self):
        base = self.base['catalog']
        feature = self.ids(base, lambda kind, obj: kind == 'feature')
        owner_evidence = self.ids(base, lambda kind, obj: kind in ('person_admission', 'admin_delegation') and obj.get('person_public_key') == self.person)
        mandatory = feature | owner_evidence
        self.select_case('pending/target_certificate_seed_confers_no_activation', required=mandatory)
        self.select_case('pending/signed_owner_with_binding_draft', seeds=[('packet', self.base['activation']['owner'])], required=mandatory)
        key = self.quinn
        unrelated = []
        for version in range(1, 5):
            value = copy.deepcopy(self.payloads['policy-v2'])
            value.update(person_public_key=key, version=version)
            record = self.record('policy-v2', self.root_person(key), value)
            raw = wire(value)
            record['payload_base64'] = b64(raw + b' ' * (240 * KIB - len(raw)))
            self.oracle.resign('person_record', record, key)
            unrelated.append(('person_record', record))
        large = self.with_proofs(base, unrelated)
        unrelated_ids = {proof(kind, value)['id'] for kind, value in unrelated}
        assert len(wire(large)) > 1024 * KIB
        self.select_case('size/unrelated_large_policies_omitted', large, required=mandatory, excluded=unrelated_ids)
        aliases = copy.deepcopy(base)
        original = next(entry for entry in aliases['objects'] if entry['id'] in owner_evidence)
        obj = json.loads(unb64(original['body_base64']))
        alias = proof(original['kind'], raw=json.dumps(obj, indent=2).encode())
        aliases['objects'].append(alias)
        sort_catalog(aliases)
        self.select_case('bytes/equivalent_source_alias_retained_exactly', aliases,
                         required=mandatory - {original['id']}, alternatives=[{original['id'], alias['id']}])
        # A live actor record references the original complete activation, not just its certificate.
        actor = self.record('host-unbind-v1', self.b)
        b_required = self.ids(self.b['catalog'], lambda kind, obj: kind in ('activation', 'certificate')) | mandatory
        self.select_case('dependencies/original_certificate_activation', self.b['catalog'], [('person_record', actor)], required=b_required)
        late = shift(self.cert_b['not_after'], 1)
        retained = self.checkpoint(self.ids_c.values(), issued_at=late)
        retained_source = self.with_proofs(self.c['catalog'], [('checkpoint', retained)])
        retained_ids = self.ids(retained_source, lambda kind, obj: kind in ('activation', 'certificate', 'checkpoint'))
        self.select_case('dependencies/expired_issuer_exact_retention', retained_source, [('certificate', self.cert_c)],
                         required=mandatory | retained_ids, now=late)
        # Exact renewal PF references resolve the original nested bytes, while
        # selection emits only the supplied enclosing top-level activations.
        nested_source = self.without(self.c['catalog'], lambda kind, obj: kind == 'person_record' and obj['operation_id'] != '-')
        nested_ids = {proof('person_record', record)['id'] for record in self.records_c.values()}
        assert not nested_ids.intersection(entry['id'] for entry in nested_source['objects'])
        renewal = self.renewal(self.c_source['activation'], nested_source, 'selection/nested-renewal', NOW)
        containers = self.ids(nested_source, lambda kind, obj: kind == 'activation')
        self.select_case('dependencies/renewal_exact_nested_pf_selects_enclosing_activation', nested_source,
                         [('packet', renewal['activation']['owner'])], required=mandatory | containers)
        pending = self.with_proofs(base, [('certificate', self.cert_b)])
        self.select_case('dependencies/missing_actor_activation', pending, [('person_record', actor)], code='proof_required', missing=[self.cert_b['request_id']])
        missing_id = 'ar_' + 'f' * 64
        cp = self.checkpoint([missing_id], issued_at=NOW)
        self.select_case('dependencies/missing_exact_checkpoint_record', seeds=[('checkpoint', cp)], code='proof_required', missing=[missing_id])
        # Current role withdrawal is retained byte-for-byte; unrelated kept IDs are not fetch seeds.
        admission = payload(self.base['activation']['administrator'])['admission_record']
        withdrawal = self.removal(self.person, kept=['record:' + semantic_id('person_record', admission), 'record:' + missing_id])
        withdrawn = self.with_proofs(self.b['catalog'], [('admin_removal', withdrawal)])
        self.select_case('restriction/withdrawal_complete_kept_list', withdrawn, [('person_record', actor)],
                         required=b_required | {proof('admin_removal', withdrawal)['id']})
        # Known restrictions survive selection even when the seed is pending/inert.
        host, device = self.key('selection/restricted-host'), self.key('selection/restricted-device')
        certificate = copy.deepcopy(self.cert_b)
        certificate.update(host_public_key=host, device_public_key=device)
        self.oracle.resign('certificate', certificate, self.person)
        unbinding = self.signed_legacy('host_unbinding', {'person_public_key': self.person, 'host_public_key': host, 'unbound_at': NOW}, self.person, ssh=True)
        revoked = self.signed_legacy('host_revocation', {'host_public_key': host, 'revoked_at': NOW})
        restricted = self.with_proofs(base, [('host_unbinding', unbinding), ('host_revocation', revoked)])
        self.select_case('restriction/pending_target_host_restrictions', restricted, [('certificate', certificate)],
                         required=mandatory | {proof('host_unbinding', unbinding)['id'], proof('host_revocation', revoked)['id']})
        dr = self.revocation(certificate)
        source = self.with_proofs(base, [('certificate', certificate), ('device_revocation', dr)])
        self.select_case('restriction/pending_device_revocation', source, [('certificate', certificate)],
                         required=mandatory | {proof('device_revocation', dr)['id'], proof('certificate', certificate)['id']})
        person_removed = self.signed_legacy('person_removal', {'person_public_key': self.person, 'removed_at': NOW})
        source = self.with_proofs(base, [('person_removal', person_removed)])
        self.select_case('restriction/person_removal_not_hidden', source, required=mandatory | {proof('person_removal', person_removed)['id']})
        invite = self.key('selection/revoked-invite')
        grant = self.record('invite-v1', unsigned=dict(self.payloads['invite-v1'], invite_public_key=invite))
        revoked_invite = self.signed_legacy('invite_revocation', {'invite_public_key': invite, 'revoked_at': NOW})
        source = self.with_proofs(base, [('invite_revocation', revoked_invite)])
        self.select_case('restriction/invite_key_not_hidden', source, [('person_record', grant)], required=mandatory | {proof('invite_revocation', revoked_invite)['id']})
        # Required exact checkpoint records, not optional aliases, make this closure >1MiB.
        bindings = []
        for index in range(4):
            value = copy.deepcopy(self.payloads['host-bind-v1'])
            value['host_public_key'] = self.key('selection/large-binding/' + str(index))
            record = self.record('host-bind-v1', unsigned=value)
            raw = wire(value)
            record['payload_base64'] = b64(raw + b' ' * (250 * KIB - len(raw)))
            self.oracle.resign('person_record', record, self.person)
            bindings.append(('person_record', record))
        checkpoint = self.checkpoint([semantic_id('person_record', record) for _, record in bindings], issued_at=NOW)
        self.select_case('size/exact_referenced_closure_too_large', self.with_proofs(base, bindings), [('checkpoint', checkpoint)], code='quota_exceeded')
        # Whole-source validation cannot hide a malformed unrelated late entry.
        malformed = copy.deepcopy(large)
        malformed['objects'].append(proof('certificate', raw=b'{}'))
        sort_catalog(malformed)
        self.select_case('source/malformed_unrelated_entry_fails_whole_result', malformed, code='invalid')
        root_seed = self.record('host-unbind-v1')
        pending = self.with_proofs(base, [('certificate', self.cert_b)])
        self.select_case('source/valid_pending_certificate_remains_inert', pending, [('certificate', self.cert_b)],
                         required=mandatory | {proof('certificate', self.cert_b)['id']})
        forged = copy.deepcopy(self.cert_b)
        self.oracle.resign('certificate', forged, self.quinn)
        self.select_case('source/forged_unused_certificate_fails_whole_result', self.with_proofs(base, [('certificate', forged)]),
                         [('person_record', root_seed)], code='invalid')
        unused_checkpoint = self.checkpoint(['ar_' + 'e' * 64], issued_at=NOW)
        self.select_case('source/valid_unused_checkpoint_confers_no_retention', self.with_proofs(base, [('checkpoint', unused_checkpoint)]),
                         [('person_record', root_seed)], required=mandatory)
        forged = copy.deepcopy(unused_checkpoint)
        self.oracle.resign('checkpoint', forged, self.quinn)
        self.select_case('source/forged_unused_checkpoint_fails_whole_result', self.with_proofs(base, [('checkpoint', forged)]),
                         [('person_record', root_seed)], code='invalid')
        final_binding = payload(self.base['activation']['commit'])['binding_record']
        self.select_case('source/complete_operation_record_requires_exact_activation',
                         self.with_proofs(base, [('person_record', final_binding)]), [('person_record', root_seed)],
                         code='proof_required', missing=[final_binding['operation_id']])
        rotated = self.catalog(current=True, epoch=2)
        seed = self.record('host-unbind-v1', epoch=2)
        required = self.ids(rotated, lambda kind, obj: kind in ('rotation', 'feature'))
        self.select_case('dependencies/full_root_chain_and_original_feature', rotated, [('person_record', seed)], required=required, epoch=2)
        raw = wire(self.cert_b)
        for label, length, code in (('inclusive', 512 * KIB, None), ('over', 512 * KIB + 1, 'invalid')):
            self.select_case('seed_bytes/' + label, seeds=[('certificate', raw + b' ' * (length - len(raw)))], required=mandatory, code=code)
        unsigned = dict(self.cert_b, signature='-')
        self.select_case('seed/unsigned_template_rejected', seeds=[('certificate', unsigned)], code='invalid')
        forged = copy.deepcopy(self.cert_b)
        self.oracle.resign('certificate', forged, self.quinn)
        self.select_case('seed/wrong_independent_signer', seeds=[('certificate', forged)], code='invalid')
        request = self.select_case('strict/empty_seeds', seeds=[], code='invalid')
        request = self.select_case('strict/unknown_outer', code='invalid')
        request['arbitrary_limit'] = 100000000
        request = self.select_case('strict/unknown_seed_field', code='invalid')
        request['seeds'][0]['approved'] = True
        return self.selection_cases


def check_success(case, reply):
    assert set(reply) == {'ok', 'catalog_base64'} and reply['ok'] is True, reply
    raw = unb64(reply['catalog_base64'])
    assert len(raw) <= 1024 * KIB, ('selected catalog bytes', len(raw))
    selected = json.loads(raw)
    assert set(selected) == {'format', 'network_id', 'objects'} and selected['format'] == 1 and selected['network_id'] == case.source['network_id']
    objects = selected['objects']
    assert len(objects) <= 4096
    ids = [entry['id'] for entry in objects]
    assert ids == sorted(set(ids))
    source = {entry['id']: entry for entry in case.source['objects']}
    for entry in objects:
        assert set(entry) == {'id', 'kind', 'body_base64'}
        assert proof(entry['kind'], raw=unb64(entry['body_base64']))['id'] == entry['id']
        assert entry == source[entry['id']], 'selected bytes must be an exact verified source entry; seeds are never inserted'
    assert case.required <= set(ids), ('missing required IDs', sorted(case.required - set(ids)))
    for alternatives in case.alternatives:
        assert alternatives.intersection(ids), ('missing all equivalent source alternatives', sorted(alternatives))
    assert not case.excluded.intersection(ids), ('unrelated IDs retained', sorted(case.excluded.intersection(ids)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go-probe')
    parser.add_argument('--rust-probe')
    parser.add_argument('--self-check', action='store_true')
    args = parser.parse_args()
    probes = [(label, path) for label, path in (('go', args.go_probe), ('rust', args.rust_probe)) if path]
    if not probes and not args.self_check:
        parser.error('supply a probe or --self-check')
    vectors = {path.name: json.loads(path.read_bytes()) for path in sorted((ROOT / 'conformance' / 'vectors').glob('*.json'))}
    author = Author(vectors)
    fixed = author.oracle.fixture_self_check()
    cases = author.build()
    print(f'Independent oracle: {fixed} signatures reproduced; {len(cases)} proof-selection checks.', flush=True)
    failures = 0
    for label, executable in probes:
        probe = ModeProbe(label, executable, True)
        try:
            for case in cases:
                actual = probe.exchange(case.request)
                try:
                    if case.expected is not None:
                        assert actual == case.expected, {'expected': case.expected, 'actual_keys': sorted(actual), 'actual_code': actual.get('code'), 'catalog_base64_bytes': len(actual.get('catalog_base64', ''))}
                    else:
                        check_success(case, actual)
                except Exception as exc:
                    failures += 1
                    print(f'FAIL {label} {case.name}: {exc}', file=sys.stderr, flush=True)
        finally:
            probe.close()
        print(f'{label}: {len(cases)} proof-selection checks completed.', flush=True)
    return int(bool(failures))


if __name__ == '__main__':
    sys.exit(main())
