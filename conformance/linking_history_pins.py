#!/usr/bin/env python3
"""Independent historical-coordinator pin/complete-consent conformance.

Historical grant verification authenticates the full signed owner/admin/host
transcript, without asserting that an old coordinator was trusted or authorizing
a current pin switch. No implementation source is imported.
"""

import argparse
import copy
import json
from pathlib import Path
import sys

from linking_actions import Author as ActionAuthor, NOW
from linking_activations import Author as ActivationAuthor, Transcript, payload, semantic_id
from linking_paths import error
from linking_readers import Probe, b64, digest, message, unb64, wire
from linking_roots import Author as RootAuthor
from linking_stored import ModeProbe


ROOT = Path(__file__).resolve().parents[1]


class Author(RootAuthor):
    def changed(self, address=True, key=True):
        descriptor = copy.deepcopy(self.data['network'])
        if address:
            descriptor['coordinator_address'] = 'current.example:7443'
        if key:
            descriptor['coordinator_public_key'] = self.key('historical-pin/current-coordinator')
        return descriptor

    def activation_case(self, name, activation=None, descriptor=None, code=None, verification='historical'):
        activation = activation or self.base['activation']
        request = ActivationAuthor.request(self, activation=activation, network_base64=b64(wire(descriptor or self.changed())),
                                           verification=verification, now=NOW, known_feature_id=self.data['feature_id'])
        expected = error(code) if code else ActivationAuthor.success(self, activation)
        self.add_request(name, request, expected)

    def action_case(self, name, context=None, code=None, epoch=0):
        context = context or self.b
        record = self.record('host-unbind-v1', context, epoch=epoch)
        request = ActionAuthor.request(self, record, context, network_base64=b64(wire(self.changed())), epoch=epoch)
        expected = error(code) if code else ActionAuthor.success(self, record, context)
        self.add_request(name, request, expected)

    def forge_authority(self, role):
        activation = copy.deepcopy(self.base['activation'])
        device = payload(activation['request'])['device_public_key']
        ids = {}
        for current_role in ('request', 'owner', 'selection', 'administrator', 'commit'):
            packet = activation[current_role]
            value = payload(packet)
            if current_role == 'owner':
                value['request_packet_id'] = ids['request']
            elif current_role == 'selection':
                value['owner_offer_id'] = ids['owner']
            elif current_role == 'administrator':
                value.update(owner_offer_id=ids['owner'], selection_id=ids['selection'])
            elif current_role == 'commit':
                value.update(request_packet_id=ids['request'], owner_offer_id=ids['owner'],
                             selection_id=ids['selection'], administrator_offer_id=ids['administrator'])
            packet['payload_base64'] = b64(wire(value))
            signer = self.other if current_role == role else packet['writer_public_key']
            self.oracle.resign('packet', packet, signer, device if current_role in ('request', 'selection', 'commit') else '-')
            ids[current_role] = semantic_id('packet', packet)
        return activation

    def build(self):
        for label, descriptor in (('address', self.changed(key=False)), ('key', self.changed(address=False)), ('both', self.changed())):
            self.activation_case('historical/unchanged_old_' + label, descriptor=descriptor)
        self.activation_case('first/actual_pin_still_required', verification='first', code='invalid')
        self.action_case('current/path_resolves_complete_old_pin_activation')
        for field, value in (('name', 'different-network-name'),
                             ('network_id', 'net_' + digest(unb64(self.key('historical-pin/other-genesis')))),
                             ('genesis_root_public_key', self.key('historical-pin/other-genesis'))):
            descriptor = self.changed()
            descriptor[field] = value
            self.activation_case('identity/' + field, descriptor=descriptor, code='invalid')
        transcript = Transcript(self, self.base)
        transcript.values['owner']['network']['coordinator_address'] = 'not an address'
        self.activation_case('strict/malformed_original_descriptor', transcript.finish(), code='invalid')
        transcript = Transcript(self, self.base)
        transcript.values['request']['coordinator_address'] = self.changed()['coordinator_address']
        self.activation_case('consent/mixed_original_request_owner_pins', transcript.finish(), code='invalid')
        transcript = Transcript(self, self.base)
        self.activation_case('consent/substituted_locked_selection', transcript.finish({'commit': {'selection_id': 'lp_' + '0' * 64}}), code='invalid')
        for role in ('owner', 'administrator'):
            self.activation_case('consent/coordinator_cannot_forge_' + role, self.forge_authority(role), code='invalid')
        missing = copy.deepcopy(self.base['activation'])
        missing['administrator'] = '-'
        self.activation_case('consent/missing_administrator', missing, code='invalid')
        revoked = copy.deepcopy(self.b)
        revoked['catalog'] = self.with_proofs(revoked['catalog'], [('device_revocation', self.revocation(self.cert_b))])
        self.action_case('current/known_device_revocation_still_blocks', revoked, code='device_revoked')
        withdrawn = copy.deepcopy(self.b)
        withdrawn['catalog'] = self.with_proofs(withdrawn['catalog'], [('admin_removal', self.removal(self.person))])
        self.action_case('current/withdrawn_unkept_admission_still_blocks', withdrawn, code='forbidden')
        fixture = self.fixtures['network_root_admits']
        certificate = payload(fixture['activation']['owner'])['certificate']
        catalog = self.with_proofs(fixture['catalog'], [('activation', fixture['activation']), ('certificate', certificate)])
        context = self.context(self.catalog(current=True, source=catalog), [certificate])
        self.action_case('current/old_root_admission_still_needs_current_attestation', context, code='forbidden', epoch=1)
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
    print(f'Independent oracle: {fixed} signatures reproduced; {len(cases)} historical-pin checks per mode.', flush=True)
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
            print(f'{label}: {len(cases)} historical-pin checks completed in ' + ('stored' if stored else 'normal') + ' mode.', flush=True)
    return int(bool(failures))


if __name__ == '__main__':
    sys.exit(main())
