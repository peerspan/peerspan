#!/usr/bin/env python3
"""Independent catalog transport-evidence checks; no pin-follow authority.

Derived solely from linking-coordinator-evidence-checks.md and accepted public
contracts/signers. Membership, role, feature and binding projection must remain
unchanged; storing a signed move/successor does not authorize following it.
"""

import argparse
import copy
import json
from pathlib import Path
import sys

from linking_actions import NOW
from linking_activations import proof, sort_catalog
from linking_readers import b64, lines, unb64, wire
from linking_roots import Author as RootAuthor
from linking_stored import ModeProbe


ROOT = Path(__file__).resolve().parents[1]


class Author(RootAuthor):
    def move(self, signing_key=None, ssh=False, **changes):
        value = dict(network_id=self.network, sequence=1, address='next.example:443',
                     public_key=self.other, moved_at=NOW, signer='root')
        value.update(changes)
        key = signing_key or (self.root if value['signer'] == 'root' else value['signer'])
        msg = lines('peerspan-coordinator-move-v1', *(value[field] for field in
                    ('network_id', 'sequence', 'address', 'public_key', 'moved_at')))
        value['signature'] = self.signers[key].sshsig(msg) if ssh else b64(self.signers[key].raw(msg))
        return value

    def successor(self, signer=None, **changes):
        value = dict(sequence=1, previous_public_key=self.other, address='successor.example:443',
                     public_key=self.key('transport/successor'), signed_at=NOW)
        value.update(changes)
        msg = lines('peerspan-coordinator-successor-v1', *(value[field] for field in
                    ('sequence', 'previous_public_key', 'address', 'public_key', 'signed_at')))
        value['signature'] = b64(self.signers[signer or value['previous_public_key']].raw(msg))
        return value

    def evidence(self, name, entries, source=None, facts=None, code=None, epoch=0):
        catalog = self.with_proofs(source or self.base['catalog'], [])
        existing = {entry['id'] for entry in catalog['objects']}
        for kind, value in entries:
            entry = proof(kind, value) if isinstance(value, dict) else proof(kind, raw=value)
            if entry['id'] not in existing:
                catalog['objects'].append(entry)
                existing.add(entry['id'])
        sort_catalog(catalog)
        self.add(name, catalog, facts, code=code, epoch=epoch, known_feature_id=self.data['feature_id'])

    def build(self):
        move, successor = self.move(), self.successor()
        for label, value in (('raw_root', move), ('ssh_root', self.move(ssh=True)),
                             ('named_admin', self.move(ssh=True, signer=self.quinn))):
            self.evidence('valid/move/' + label, [('coordinator_move', value)])
        self.evidence('valid/successor_independent_of_current_pin', [('coordinator_successor', successor)])
        self.evidence('valid/all_transport_is_projection_inert', [('coordinator_move', move), ('coordinator_successor', successor)])
        for label, key in (('old', self.root), ('tip', self.roots[1])):
            self.evidence('root_chain/' + label, [('coordinator_move', self.move(signing_key=key))],
                          self.catalog(current=True), epoch=1)
        removal = self.removal(self.quinn)
        facts = self.base_facts.clone()
        facts.persons[self.quinn]['administrator'] = False
        source = self.with_proofs(self.base['catalog'], [('admin_removal', removal)])
        self.evidence('history/withdrawn_admin_is_evidence_only',
                      [('coordinator_move', self.move(ssh=True, **{'signer': self.quinn}))], source, facts)
        missing = self.without(self.base['catalog'], lambda kind, value: kind == 'admin_delegation' and value['person_public_key'] == self.quinn)
        self.evidence('authority/missing_named_delegation', [('coordinator_move', self.move(ssh=True, **{'signer': self.quinn}))], missing, code='forbidden')
        self.evidence('authority/admin_signature_must_be_sshsig', [('coordinator_move', self.move(**{'signer': self.quinn}))], code='invalid')
        self.evidence('signature/root_wrong_key', [('coordinator_move', self.move(signing_key=self.person))], code='invalid')
        self.evidence('signature/named_admin_wrong_key', [('coordinator_move', self.move(signing_key=self.person, ssh=True, signer=self.quinn))], code='invalid')
        self.evidence('signature/successor_wrong_predecessor', [('coordinator_successor', self.successor(signer=self.person))], code='invalid')
        self.evidence('network/exact_catalog_network', [('coordinator_move', self.move(network_id='net_' + '0' * 64))], code='invalid')
        for kind, original, factory in (('coordinator_move', move, self.move), ('coordinator_successor', successor, self.successor)):
            for label, value in (('zero', 0), ('negative', -1), ('over_max', 2 ** 63), ('boolean', True), ('string', '1')):
                self.evidence('sequence/' + kind + '/' + label, [(kind, factory(sequence=value))], code='invalid')
            self.evidence('sequence/' + kind + '/max_int64', [(kind, factory(sequence=2 ** 63 - 1))])
            raw = wire(original)
            for label, invalid in (('fraction', raw.replace(b'"sequence":1', b'"sequence":1.0')),
                                   ('exponent', raw.replace(b'"sequence":1', b'"sequence":1e0')),
                                   ('duplicate', raw[:-1] + b',"sequence":1}'),
                                   ('unknown', raw[:-1] + b',"source_address":"old.example:443"}'),
                                   ('null', wire(dict(original, signature=None))),
                                   ('missing', wire({key: value for key, value in original.items() if key != 'signature'})),
                                   ('trailing', raw + b'{}'),
                                   ('invalid_utf8', raw[:-1] + b',"\xff":0}')):
                self.evidence('strict/' + kind + '/' + label, [(kind, invalid)], code='invalid')
            time_field = 'moved_at' if kind == 'coordinator_move' else 'signed_at'
            for label, fields in (('address', {'address': 'not an address'}),
                                  ('key_length', {'public_key': b64(b'x' * 31)}),
                                  ('key_point', {'public_key': b64(bytes(32))}),
                                  ('key_padding', {'public_key': original['public_key'].rstrip('=')})):
                self.evidence('encoding/' + kind + '/' + label, [(kind, factory(**fields))], code='invalid')
            self.evidence('encoding/' + kind + '/time_fraction', [(kind, factory(**{time_field: NOW.replace('Z', '.0Z')}))])
            self.evidence('alias/' + kind, [(kind, original), (kind, json.dumps(original, indent=2).encode())])
            self.evidence('conflict/' + kind, [(kind, original), (kind, factory(address='different.example:443'))], code='state_conflict')
            for label, address, code in (('opaque_underscore', 'coord_internal.example:443', None),
                                         ('bracketed_opaque_host', '[coord_internal]:443', None),
                                         ('leading_zero_port', 'next.example:0443', 'invalid'),
                                         ('signed_port', 'next.example:+443', 'invalid'),
                                         ('extra_bracket', '[coord_internal]suffix:443', 'invalid')):
                self.evidence('address/' + kind + '/' + label, [(kind, factory(address=address))], code=code)
        predecessor = self.key('transport/independent-predecessor')
        self.evidence('successor/same_sequence_different_predecessors',
                      [('coordinator_successor', successor), ('coordinator_successor', self.successor(previous_public_key=predecessor))])
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
    vectors = {path.name: json.loads(path.read_bytes()) for path in sorted((ROOT / 'conformance' / 'vectors').glob('*.json'))}
    author = Author(vectors)
    fixed = author.oracle.fixture_self_check()
    cases = author.build()
    print(f'Independent oracle: {fixed} signatures reproduced; {len(cases)} transport-evidence checks per mode.', flush=True)
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
            print(f'{label}: {len(cases)} transport-evidence checks completed in ' + ('stored' if stored else 'normal') + ' mode.', flush=True)
    return int(bool(failures))


if __name__ == '__main__':
    sys.exit(main())
