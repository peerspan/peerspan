#!/usr/bin/env python3
"""Independent signed coordinator feature/operation/map runtime checks.

Derived from the accepted coordinator and transaction contracts. Uses public
fixture keys and the independent signing oracle, real mTLS and documented crash
hooks; no host/coordinator implementation is imported. This is not host ceremony
or installed-bundle acceptance.
"""

import argparse
import base64
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import http.client

from launch_service import Key
from linking_activations import Transcript, payload, proof, semantic_id, shift
from linking_mailboxes import Runtime, Suite as MailboxSuite, BASE as MAILBOX_BASE, START, error, need, ok, source
from linking_readers import FixtureSigner, b64, digest, lines, message, unb64, wire
from linking_records import Author as RecordAuthor
from linking_redemptions import Author as RedemptionAuthor


ROOT = Path(__file__).resolve().parents[1]


class Author(RecordAuthor):
    invite = RedemptionAuthor.invite
    redemption = RedemptionAuthor.redemption

    def __init__(self, vectors, runtime):
        super().__init__(vectors)
        self.runtime = runtime
        self.hosts = {name: Key(runtime.root, unb64(value['seed_base64'])) for name, value in self.data['keys'].items()
                      if name.startswith('host_')}
        info = json.loads(runtime.command('info').stdout)
        self.descriptor = dict(self.data['network'], coordinator_address=f'127.0.0.1:{runtime.port}',
                               coordinator_public_key=info['public_key'])
        self.catalog = self.without(self.base['catalog'], lambda kind, obj: kind == 'feature')
        self.feature = next(json.loads(unb64(entry['body_base64'])) for entry in self.base['catalog']['objects'] if entry['kind'] == 'feature')
        self.feature_id = semantic_id('feature_proposal', self.feature['proposal'])
        self.serial = 0
        self.completed = {}

    def call(self, method, path='', body=None, host='host_a', **kwargs):
        return self.runtime.call(method, '/coord/v2/networks' + path, body, key=self.hosts[host], **kwargs)

    def membership(self, host, member):
        self.serial += 1
        invite = self.key('coordinator/invite/' + str(self.serial))
        expires, joined = '2026-11-20T12:00:00Z', START
        invitation = b64(self.signers[self.root].raw(lines('peerspan-invite-v1', self.network, invite, member, expires)))
        signature = b64(self.signers[invite].raw(lines('peerspan-member-v1', self.network, invite, self.hosts[host].b64, joined)))
        return {'network_id': self.network, 'member': member, 'invite_public_key': invite,
                'invite_expires_at': expires, 'invite_signature': invitation, 'host_public_key': self.hosts[host].b64,
                'joined_at': joined, 'host_signature': signature}

    def register(self):
        reply = self.call('POST', body={'name': self.descriptor['name'], 'root_public_key': self.root,
                          'membership': self.membership('host_a', 'alice'), 'address': '', 'candidates': [], 'linking_version': 1})
        value = ok(reply, 201)
        need('format' not in value, 'prefeature registration is the legacy map branch')
        reply = self.call('POST', '/' + self.network + '/members', {'membership': self.membership('host_q', 'quinn'),
                          'address': '', 'candidates': [], 'join_ack': '-', 'linking_version': 1}, host='host_q')
        need('format' not in ok(reply, 201), 'prefeature join remains legacy map')

    def complete_feature(self, issued=None, hosts=None):
        proposal = copy.deepcopy(self.feature['proposal'])
        if issued is not None:
            proposal['issued_at'] = issued
        if hosts is not None:
            proposal['host_public_keys'] = sorted(self.hosts[name].b64 for name in hosts)
        self.oracle.resign('feature_proposal', proposal, self.root)
        feature_id = semantic_id('feature_proposal', proposal)
        acknowledgments = []
        for host in proposal['host_public_keys']:
            ack = {'format': 1, 'feature_id': feature_id, 'host_public_key': host}
            self.oracle.resign('feature_ack', ack, host)
            acknowledgments.append(ack)
        return {'proposal': proposal, 'acknowledgments': acknowledgments}

    def feature_body(self):
        return {'feature': self.feature, 'catalog': self.catalog}

    def activate(self):
        self.register()
        proposal = {'proposal': self.feature['proposal'], 'catalog': self.catalog}
        need(ok(self.call('POST', '/' + self.network + '/link-feature/proposals', proposal), 201) == {'feature_id': self.feature_id}, 'prepare proposal ID')
        need(ok(self.call('POST', '/' + self.network + '/link-feature/proposals', proposal), 200) == {'feature_id': self.feature_id}, 'proposal retry')
        for ack in self.feature['acknowledgments']:
            host = next(name for name, key in self.hosts.items() if key.b64 == ack['host_public_key'])
            body = {'acknowledgment': ack, 'catalog': self.catalog}
            need(ok(self.call('POST', '/' + self.network + '/link-feature/acknowledgments', body, host=host), 201) == {'feature_id': self.feature_id}, 'host acknowledgment')
            need(ok(self.call('POST', '/' + self.network + '/link-feature/acknowledgments', body, host=host), 200) == {'feature_id': self.feature_id}, 'exact acknowledgment retry')
        need(ok(self.call('POST', '/' + self.network + '/link-feature', self.feature_body()), 201) == {'feature_id': self.feature_id}, 'first complete feature activation')

    def rebind(self, fixture=None, label='new', issuer=None, target='host_b'):
        template = copy.deepcopy(fixture or self.base)
        transcript = Transcript(self, template)
        request = transcript.values['request']
        target_key = self.hosts[target].b64
        device = self.data['keys']['device_c' if target == 'host_c' else 'device_b']['public_key']
        request.update(host_public_key=target_key, device_public_key=device)
        request.update(coordinator_address=self.descriptor['coordinator_address'], coordinator_public_key=self.descriptor['coordinator_public_key'],
                       request_nonce=b64(hashlib.sha256(label.encode()).digest()))
        request_id = 'link_' + digest(lines('peerspan-link-request-id-v1', request['coordinator_public_key'], request['host_public_key'],
                                          request['device_public_key'], request['request_nonce']))
        for role, packet in transcript.activation.items():
            if packet != '-':
                packet['request_id'] = request_id
                if role in ('request', 'selection', 'commit'):
                    packet['writer_public_key'] = target_key
        owner = transcript.values['owner']
        owner['network'] = copy.deepcopy(self.descriptor)
        owner['certificate'].update(request_id=request_id, host_public_key=target_key, device_public_key=device)
        if issuer:
            issuer_id = semantic_id('certificate', issuer)
            owner['certificate']['parent_id'] = issuer_id
            transcript.activation['owner']['certificate_id'] = issuer_id
        transcript.sign_certificate()
        for role, field in (('owner', 'binding_record'), ('administrator', 'admission_record')):
            if role not in transcript.values or transcript.values[role][field] == '-':
                continue
            record = transcript.values[role][field]
            record['operation_id'] = request_id
            unsigned = payload(record)
            unsigned['host_public_key'] = target_key
            record['payload_base64'] = b64(wire(unsigned))
            if issuer and 'certificate_id' in record:
                record['certificate_id'] = semantic_id('certificate', issuer)
                transcript.activation[role]['certificate_id'] = record['certificate_id']
            signer = transcript.activation[role]['writer_public_key']
            transcript.sign_record(record, signer, draft=role == 'owner')
        return transcript.finish()

    def operation_body(self, activation):
        return {'activation': activation, 'catalog': self.catalog, 'address': '', 'candidates': []}

    def check_map(self, reply, hosts=('host_a', 'host_q'), status=200):
        value = ok(reply, status)
        need(set(value) == {'format', 'network', 'catalog', 'members'} and value['format'] == 2, 'strict v2 map')
        need(value['network'] == self.descriptor, 'map descriptor authenticates served endpoint pin', value['network'], self.descriptor)
        catalog = value['catalog']
        need(set(catalog) == {'format', 'network_id', 'objects'} and catalog['format'] == 1 and catalog['network_id'] == self.network, 'map public catalog')
        ids = []
        kinds = {}
        for entry in catalog['objects']:
            need(set(entry) == {'id', 'kind', 'body_base64'}, 'strict public object entry')
            raw = unb64(entry['body_base64'])
            need(proof(entry['kind'], raw=raw)['id'] == entry['id'], 'derive map transport ID from exact body')
            json.loads(raw)
            ids.append(entry['id'])
            kinds.setdefault(entry['kind'], []).append(entry)
        need(ids == sorted(set(ids)), 'map catalog IDs sorted distinct')
        need(any(json.loads(unb64(entry['body_base64'])) == self.feature for entry in kinds.get('feature', [])), 'map includes exact durable feature')
        members = value['members']
        fields = {'host_id', 'host_public_key', 'membership_proof_id', 'binding_proof_id', 'join_proof_id', 'address', 'candidates', 'updated_at'}
        need(all(set(member) == fields for member in members), 'strict member rows')
        need([member['host_id'] for member in members] == sorted(member['host_id'] for member in members), 'members sorted by host ID')
        need({member['host_public_key'] for member in members} == {self.hosts[host].b64 for host in hosts}, 'only verified admitted hosts projected')
        for member in members:
            need(member['host_id'] == 'host_' + digest(unb64(member['host_public_key'])), 'host ID derived from exact key')
            need(member['membership_proof_id'].startswith('pf_'), 'membership signed proof reference')
            if member['host_public_key'] in self.feature['proposal']['host_public_keys']:
                need(member['join_proof_id'] == '-', 'exact feature roster may omit join proof')
            else:
                need(member['join_proof_id'].startswith('pf_'), 'later host needs feature acknowledgment proof')
            known = self.completed.get(member['host_public_key'], [])
            if known:
                new_grants = [activation for activation in known if activation['administrator'] != '-']
                admissions, bindings = [], []
                for activation in new_grants:
                    record = payload(activation['administrator'])['admission_record']
                    admissions.append(proof('person_record' if 'person_public_key' in record else 'root_record', record)['id'])
                    bindings.append(proof('person_record', payload(activation['commit'])['binding_record'])['id'])
                need(member['membership_proof_id'] == min(admissions), 'exact nested signed admission proof, independent of unsigned member rows')
                need(member['binding_proof_id'] == min(bindings), 'exact final host-consented binding proof')
                joins = [proof('activation', activation)['id'] for activation in known]
                need(member['join_proof_id'] == min(joins), 'lexicographically first exact complete feature acknowledgment proof')
                need(any(entry['id'] in joins for entry in kinds.get('activation', [])), 'map retains complete grant, not only a coordinator receipt')
        return value

    def check_result(self, reply, activation, status=201):
        result = ok(reply, status)
        need(set(result) == {'format', 'request_id', 'role', 'writer_public_key', 'person_public_key', 'certificate_id', 'payload_base64', 'host_signature', 'device_signature', 'authority_signature'}, 'strict result packet fields')
        need(result['format'] == 1 and result['person_public_key'] == '-' and result['certificate_id'] == 'coordinator' and result['host_signature'] == '-' and result['device_signature'] == '-', 'exact result signature roles')
        need(result['role'] == 'result' and result['request_id'] == activation['request']['request_id'], 'result packet metadata')
        need(result['writer_public_key'] == self.descriptor['coordinator_public_key'], 'result signer is pinned coordinator')
        # Verify server-generated Ed25519 independently through OpenSSL, not a host probe.
        public = self.runtime.root / 'result-public.der'
        signature = self.runtime.root / 'result.sig'
        preimage = self.runtime.root / 'result.msg'
        public.write_bytes(bytes.fromhex('302a300506032b6570032100') + unb64(result['writer_public_key']))
        signature.write_bytes(unb64(result['authority_signature']))
        preimage.write_bytes(message('packet', result))
        verified = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', str(public), '-keyform', 'DER',
                                   '-rawin', '-in', str(preimage), '-sigfile', str(signature)], capture_output=True, timeout=10)
        need(verified.returncode == 0, 'independent coordinator result signature')
        value = payload(result)
        need(set(value) == {'manifest_id', 'activation', 'catalog'}, 'public result payload contains no private fields')
        need(value['manifest_id'] == semantic_id('packet', activation['commit']) and value['activation'] == activation, 'exact activation and commit manifest retained')
        need(value['catalog']['network_id'] == self.network, 'result proof catalog pinned network')
        host = payload(activation['request'])['host_public_key']
        complete = self.completed.setdefault(host, [])
        if activation not in complete:
            complete.append(copy.deepcopy(activation))
        return result


class Suite(MailboxSuite):
    def author(self, runtime):
        vectors = {path.name: json.loads(path.read_bytes()) for path in sorted((ROOT / 'conformance' / 'vectors').glob('*.json'))}
        return Author(vectors, runtime)

    def feature_and_negotiation(self, runtime):
        a = self.author(runtime)
        a.activate()
        a.check_map(a.call('GET', '/' + a.network + '/map'))
        a.check_map(a.call('POST', '/' + a.network + '/sync', {'address': '', 'candidates': [], 'linking_version': 1}))
        legacy = runtime.call('POST', '/coord/v1/networks/' + a.network + '/sync', {'address': '', 'candidates': []}, key=a.hosts['host_a'])
        error(legacy, 426, 'upgrade_required')
        legacy = runtime.call('POST', '/coord/v1/networks/' + a.network + '/members',
                              {'membership': a.membership('host_c', 'alice'), 'address': '', 'candidates': []}, key=a.hosts['host_c'])
        error(legacy, 426, 'upgrade_required')
        missing = copy.deepcopy(a.feature_body())
        missing['feature']['acknowledgments'].pop()
        error(a.call('POST', '/' + a.network + '/link-feature', missing), 400, 'invalid')
        runtime.advance(86400)
        need(ok(a.call('POST', '/' + a.network + '/link-feature', a.feature_body()), 200) == {'feature_id': a.feature_id}, 'persisted feature retry after expiry')
        runtime.restart()
        a.check_map(a.call('GET', '/' + a.network + '/map'))
        distinct = copy.deepcopy(a.feature)
        distinct['proposal']['issued_at'] = runtime.now
        a.oracle.resign('feature_proposal', distinct['proposal'], a.root)
        fid = semantic_id('feature_proposal', distinct['proposal'])
        for ack in distinct['acknowledgments']:
            ack['feature_id'] = fid
            a.oracle.resign('feature_ack', ack, ack['host_public_key'])
        error(a.call('POST', '/' + a.network + '/link-feature', {'feature': distinct, 'catalog': a.catalog}), 409, 'state_conflict')

    def pending_bound_and_expiry(self, runtime):
        a = self.author(runtime)
        a.register()
        candidates = [a.complete_feature(issued=shift(START, -index)) for index in range(1, 10)]
        for feature in candidates[:8]:
            fid = semantic_id('feature_proposal', feature['proposal'])
            need(ok(a.call('POST', '/' + a.network + '/link-feature/proposals',
                          {'proposal': feature['proposal'], 'catalog': a.catalog}), 201) == {'feature_id': fid}, 'inclusive eight pending proposals')
        first = candidates[0]
        first_id = semantic_id('feature_proposal', first['proposal'])
        need(ok(a.call('POST', '/' + a.network + '/link-feature/proposals',
                      {'proposal': first['proposal'], 'catalog': a.catalog}), 200) == {'feature_id': first_id}, 'pending retry consumes no slot')
        error(a.call('POST', '/' + a.network + '/link-feature/proposals',
                     {'proposal': candidates[-1]['proposal'], 'catalog': a.catalog}), 409, 'quota_exceeded')
        listing = ok(a.call('GET', '/' + a.network + '/link-feature/proposals'), 200)
        need(set(listing) == {'proposals'}, 'strict proposal list envelope')
        expected = sorted(({'proposal': item['proposal'], 'acknowledgments': []} for item in candidates[:8]),
                          key=lambda item: semantic_id('feature_proposal', item['proposal']))
        need(listing['proposals'] == expected, 'pending proposals sorted and incomplete, never active facts')
        error(a.call('GET', '/' + a.network + '/link-feature/proposals', host='host_b'), 403, 'forbidden')
        ack = first['acknowledgments'][0]
        wrong = 'host_q' if ack['host_public_key'] == a.hosts['host_a'].b64 else 'host_a'
        error(a.call('POST', '/' + a.network + '/link-feature/acknowledgments', {'acknowledgment': ack, 'catalog': a.catalog}, host=wrong), 403, 'forbidden')
        runtime.advance(86400)
        error(a.call('POST', '/' + a.network + '/link-feature', {'feature': first, 'catalog': a.catalog}), 410, 'expired')
        fresh = a.complete_feature(issued=runtime.now)
        need(ok(a.call('POST', '/' + a.network + '/link-feature/proposals',
                      {'proposal': fresh['proposal'], 'catalog': a.catalog}), 201) == {'feature_id': semantic_id('feature_proposal', fresh['proposal'])},
             'expired inactive proposals release all eight slots')
        listing = ok(a.call('GET', '/' + a.network + '/link-feature/proposals'), 200)
        need(listing == {'proposals': [{'proposal': fresh['proposal'], 'acknowledgments': []}]}, 'expired inactive candidates discarded before fresh prepare')

    def roster_race(self, runtime):
        a = self.author(runtime)
        a.register()
        need(ok(a.call('POST', '/' + a.network + '/link-feature/proposals',
                      {'proposal': a.feature['proposal'], 'catalog': a.catalog}), 201) == {'feature_id': a.feature_id}, 'prepare original roster')
        ok(a.call('POST', '/' + a.network + '/members', {'membership': a.membership('host_c', 'alice'),
                  'address': '', 'candidates': [], 'join_ack': '-', 'linking_version': 1}, host='host_c'), 201)
        ack = next(ack for ack in a.feature['acknowledgments'] if ack['host_public_key'] == a.hosts['host_a'].b64)
        error(a.call('POST', '/' + a.network + '/link-feature/acknowledgments', {'acknowledgment': ack, 'catalog': a.catalog}), 409, 'state_conflict')
        error(a.call('POST', '/' + a.network + '/link-feature', a.feature_body()), 409, 'state_conflict')
        a.feature = a.complete_feature(issued=runtime.now, hosts=('host_a', 'host_q', 'host_c'))
        a.feature_id = semantic_id('feature_proposal', a.feature['proposal'])
        need(ok(a.call('POST', '/' + a.network + '/link-feature', a.feature_body()), 201) == {'feature_id': a.feature_id}, 'fresh root signature includes concurrent admitted host')
        a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_c'))

    def operations(self, runtime):
        a = self.author(runtime)
        a.activate()
        activation = a.rebind()
        body = a.operation_body(activation)
        error(a.call('POST', '/' + a.network + '/link-operations', body), 403, 'forbidden')
        result = a.check_result(a.call('POST', '/' + a.network + '/link-operations', body, host='host_b'), activation)
        need(a.check_result(a.call('POST', '/' + a.network + '/link-operations', body, host='host_b'), activation, 200) == result, 'committed exact operation retry')
        a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b'))
        request_id = activation['request']['request_id']
        for host in ('host_a', 'host_b'):
            need(ok(a.call('GET', '/' + a.network + '/link-operations/' + request_id, host=host), 200) == result, 'joining host/member retrieval exact result')
        error(a.call('GET', '/' + a.network + '/link-operations/' + request_id, host='host_c'), 403, 'forbidden')
        error(a.call('GET', '/' + a.network + '/link-operations/link_' + '0' * 64), 404, 'not_found')
        substituted = copy.deepcopy(body)
        transcript = Transcript(a, {'activation': activation})
        transcript.values['owner']['certificate']['scopes'] = 3
        transcript.sign_certificate()
        substituted['activation'] = transcript.finish()
        error(a.call('POST', '/' + a.network + '/link-operations', substituted, host='host_b'), 409, 'operation_conflict')
        runtime.advance(300)
        need(ok(a.call('POST', '/' + a.network + '/link-operations', body, host='host_b'), 200) == result, 'committed retry precedes expired first-operation checks')
        runtime.restart()
        need(ok(a.call('GET', '/' + a.network + '/link-operations/' + request_id, host='host_b'), 200) == result, 'durable exact result after restart')
        a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b'))

    def invite_redemptions(self, runtime):
        a = self.author(runtime)
        a.activate()
        host_b = a.hosts['host_b'].b64
        invite = a.key('runtime/first-redemption/invite')
        expiration = shift(runtime.now, 86400)
        admitting = a.redemption('member', 'admit', host=host_b, person=a.person, label='alice',
                                 invite=invite, expires=expiration, joined=runtime.now)
        ack = {'format': 1, 'feature_id': a.feature_id, 'host_public_key': host_b}
        a.oracle.resign('feature_ack', ack, host_b)
        def body(redemption, acknowledgment=ack):
            return {'redemption': redemption, 'catalog': a.catalog, 'address': '', 'candidates': [], 'join_ack': acknowledgment}
        route = '/' + a.network + '/invite-redemptions'
        error(a.call('POST', route, body(admitting), host='host_b'), 409, 'state_conflict')
        skip = a.redemption('member', 'skip', host=host_b, person=a.person, label='alice',
                            invite=invite, expires=expiration, joined=runtime.now)
        need(skip['host_invite'] == admitting['host_invite'], 'same unconsumed exact host invitation after failed admit')
        error(a.call('POST', route, body(skip)), 403, 'forbidden')
        accepted = a.call('POST', route, body(skip), host='host_b')
        projection = a.check_map(accepted, ('host_a', 'host_q', 'host_b'), status=201)
        member = next(row for row in projection['members'] if row['host_public_key'] == host_b)
        need(member['membership_proof_id'] == proof('invite_redemption', skip)['id'], 'completed redemption is exact membership proof')
        need(member['join_proof_id'] == proof('join_ack', ack)['id'] and member['binding_proof_id'] == '-', 'invite membership creates feature capability without person binding')
        # An exact completed retry precedes invite expiry and already-admitted checks.
        runtime.advance(86400)
        a.check_map(a.call('POST', route, body(skip), host='host_b'), ('host_a', 'host_q', 'host_b'))
        runtime.restart()
        a.check_map(a.call('POST', route, body(skip), host='host_b'), ('host_a', 'host_q', 'host_b'))
        pair = [semantic_id('person_record', skip['host_invite']), proof('invite_redemption', skip)['id']]
        a.catalog = a.with_proofs(a.catalog, [('checkpoint', a.checkpoint(pair, issued_at=runtime.now))])
        person = a.key('runtime/person-only/subject')
        person_only = a.redemption('person', 'admit', person=person, label='dana', joined=runtime.now,
                                   invite=a.key('runtime/person-only/invite'), expires=shift(runtime.now, 86400))
        person_body = body(person_only, '-')
        person_result = a.check_map(a.call('POST', route, person_body), ('host_a', 'host_q', 'host_b'), status=201)
        need(any(entry['id'] == proof('invite_redemption', person_only)['id'] for entry in person_result['catalog']['objects']), 'person-only redemption is public evidence with no transport admission')

    def invite_forms_and_single_use(self, runtime):
        a = self.author(runtime)
        a.activate()
        seed = hashlib.sha256(b'coordinator/new-host-D').digest()
        a.hosts['host_d'] = Key(runtime.root, seed)
        a.signers[a.hosts['host_d'].b64] = FixtureSigner(seed)
        route = '/' + a.network + '/invite-redemptions'
        admitted_hosts = ['host_a', 'host_q']
        host_only = None
        for mode, action, host, person, label in (
                ('member', 'admit', 'host_b', a.key('runtime/member/subject'), 'dana'),
                ('host', 'none', 'host_c', '-', 'erin'),
                ('person', 'admit', '-', a.key('runtime/person/subject'), 'frank'),
                ('member', 'skip', 'host_d', a.person, 'alice')):
            if host == 'host_d':
                # A different target under the consumed host-only grant must fail.
                invite_key = payload(host_only['host_invite'])['invite_public_key']
                reused = a.redemption('host', 'none', host=a.hosts[host].b64, invite=invite_key,
                                      label='erin', expires=shift(runtime.now, 86400), joined=runtime.now)
                need(reused['host_invite'] == host_only['host_invite'], 'exact consumed host half reused without other grant mutation')
                reused_ack = {'format': 1, 'feature_id': a.feature_id, 'host_public_key': a.hosts[host].b64}
                a.oracle.resign('feature_ack', reused_ack, a.hosts[host].b64)
                error(a.call('POST', route, {'redemption': reused, 'catalog': a.catalog, 'address': '', 'candidates': [],
                             'join_ack': reused_ack}, host=host), 409, 'state_conflict')
            redemption = a.redemption(mode, action, host=a.hosts[host].b64 if host != '-' else None,
                                      person=person, label=label, invite=a.key('runtime/form/' + mode + '/' + action),
                                      expires=shift(runtime.now, 86400), joined=runtime.now)
            ack = '-'
            caller = 'host_a' if host == '-' else host
            if host != '-':
                ack = {'format': 1, 'feature_id': a.feature_id, 'host_public_key': a.hosts[host].b64}
                a.oracle.resign('feature_ack', ack, a.hosts[host].b64)
                admitted_hosts.append(host)
            response = a.call('POST', route, {'redemption': redemption, 'catalog': a.catalog, 'address': '',
                              'candidates': [], 'join_ack': ack}, host=caller)
            projection = a.check_map(response, tuple(admitted_hosts), status=201)
            need(any(entry['id'] == proof('invite_redemption', redemption)['id'] for entry in projection['catalog']['objects']), 'exact completed public redemption retained for every form')
            if host != '-':
                member = next(row for row in projection['members'] if row['host_public_key'] == a.hosts[host].b64)
                need(member['membership_proof_id'] == proof('invite_redemption', redemption)['id'] and
                     member['join_proof_id'] == proof('join_ack', ack)['id'] and member['binding_proof_id'] == '-',
                     'all invite forms use exact signed evidence without creating binding')
            if mode == 'host':
                host_only = redemption

    def delegated_and_expired_renewal(self, runtime):
        a = self.author(runtime)
        a.activate()
        first = a.rebind(label='delegated/B')
        a.check_result(a.call('POST', '/' + a.network + '/link-operations', a.operation_body(first), host='host_b'), first)
        cert_b = payload(first['owner'])['certificate']
        runtime.advance(60)
        child = a.rebind(a.fixtures['delegated_b_links_c'], label='delegated/C', issuer=cert_b, target='host_c')
        a.check_result(a.call('POST', '/' + a.network + '/link-operations', a.operation_body(child), host='host_c'), child)
        snapshot = a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b', 'host_c'))
        late = shift(cert_b['not_after'], 1)
        runtime.set_time(late)
        retained_ids = [semantic_id('person_record', payload(child['commit'])['binding_record']),
                        semantic_id('person_record', payload(child['administrator'])['admission_record'])]
        checkpoint = a.checkpoint(retained_ids, issued_at=late)
        renewal_fixture = a.renewal(child, snapshot['catalog'], 'renew/C', late)
        renewed = a.rebind(renewal_fixture, label='renew/C/pinned', target='host_c')
        body = a.operation_body(renewed)
        # Before checkpoint publication exact historical authority is incomplete.
        failure = a.call('POST', '/' + a.network + '/link-operations', body, host='host_c')
        error(failure, 409, 'proof_required')
        need(failure[2]['details']['required_ids'] in ([retained_ids[0]], [retained_ids[1]]), 'exact affected expired historical record requested')
        body['catalog'] = a.with_proofs(a.catalog, [('checkpoint', checkpoint)])
        a.check_result(a.call('POST', '/' + a.network + '/link-operations', body, host='host_c'), renewed)
        a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b', 'host_c'))
        old_request, new_request = payload(child['request']), payload(renewed['request'])
        need((old_request['host_public_key'], old_request['device_public_key']) ==
             (new_request['host_public_key'], new_request['device_public_key']), 'expired renewal preserves exact host/device keys')
        need(payload(renewed['owner'])['person_public_key'] == payload(child['owner'])['person_public_key'], 'renewal preserves original person')

    def checkpoint_writer(self, runtime):
        a = self.author(runtime)
        a.activate()
        activation = a.rebind(label='checkpoint/B')
        a.check_result(a.call('POST', '/' + a.network + '/link-operations', a.operation_body(activation), host='host_b'), activation)
        before = a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b'))
        records = [semantic_id('person_record', payload(activation[role])[field])
                   for role, field in (('commit', 'binding_record'), ('administrator', 'admission_record'))]
        certificate = payload(activation['owner'])['certificate']
        # B's valid signature and full scopes cannot endorse its root issuer's records.
        self_endorsement = a.checkpoint(records, semantic_id('certificate', certificate),
                                       certificate['device_public_key'], issued_at=runtime.now)
        submitted = a.with_proofs(a.catalog, [('checkpoint', self_endorsement)])
        error(a.call('POST', '/' + a.network + '/statements', {'catalog': submitted}), 403, 'forbidden')
        need(a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b')) == before,
             'rejected checkpoint leaves the complete map unchanged')
        checkpoint = a.checkpoint(records, issued_at=runtime.now)
        submitted = a.with_proofs(a.catalog, [('checkpoint', checkpoint)])
        after = a.check_map(a.call('POST', '/' + a.network + '/statements', {'catalog': submitted}),
                            ('host_a', 'host_q', 'host_b'))
        need(any(entry['id'] == proof('checkpoint', checkpoint)['id'] for entry in after['catalog']['objects']),
             'original person checkpoint retains exact combined-scope records')

    def crash_and_restore(self, runtime):
        a = self.author(runtime)
        a.activate()
        outcomes = []
        for name, target in (('coord.finalize.before_commit', 'host_b'), ('coord.finalize.after_commit', 'host_c')):
            activation = a.rebind(label=name, target=target)
            request_id = activation['request']['request_id']
            body = a.operation_body(activation)
            arm = runtime.barriers / (name + '.arm')
            entered = runtime.barriers / (name + '.entered')
            arm.write_text('')
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(a.call, 'POST', '/' + a.network + '/link-operations', body, host=target)
                deadline = time.monotonic() + 15
                while not entered.exists() and time.monotonic() < deadline and not pending.done():
                    time.sleep(.01)
                need(entered.exists(), 'documented finalize barrier reached', name)
                need(entered.read_text().strip() == request_id, 'barrier stores only public request ID')
                runtime.stop(kill=True)
                arm.unlink()
                try:
                    pending.result(timeout=5)
                except (OSError, http.client.HTTPException):
                    pass
                runtime.start()
            retrieval = a.call('GET', '/' + a.network + '/link-operations/' + request_id)
            if name.endswith('before_commit'):
                error(retrieval, 404, 'not_found')
                a.check_map(a.call('GET', '/' + a.network + '/map'))
                result = a.check_result(a.call('POST', '/' + a.network + '/link-operations', body, host=target), activation)
            else:
                result = a.check_result(retrieval, activation, 200)
                need(a.check_result(a.call('POST', '/' + a.network + '/link-operations', body, host=target), activation, 200) == result,
                     'after-commit retry retains complete original outcome')
            outcomes.append((target, activation, result))
        a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b', 'host_c'))
        backup = runtime.root / 'operations.backup'
        need(runtime.command('backup', str(backup)).returncode == 0, 'operation backup succeeds')
        runtime.stop()
        restored_state = runtime.root / 'restored-state'
        need(runtime.command('restore', str(backup), state=restored_state).returncode == 0, 'operation restore succeeds')
        restored = Runtime(runtime.binary, runtime.root / 'restored', initial=runtime.now, state=restored_state, port=runtime.port)
        try:
            a.runtime = restored
            for target, activation, result in outcomes:
                request_id = activation['request']['request_id']
                need(ok(a.call('GET', '/' + a.network + '/link-operations/' + request_id, host=target), 200) == result,
                     'restored operation retains original signature and outcome')
                need(ok(a.call('POST', '/' + a.network + '/link-operations', a.operation_body(activation), host=target), 200) == result,
                     'restored committed operation retry remains immutable')
            a.check_map(a.call('GET', '/' + a.network + '/map'), ('host_a', 'host_q', 'host_b', 'host_c'))
        finally:
            self.requests += restored.requests
            restored.close()

    def strict_and_uncommitted(self, runtime):
        a = self.author(runtime)
        a.activate()
        activation = a.rebind(label='strict')
        body = a.operation_body(activation)
        for change in (dict(body, code='never-accepted'), dict(body, catalog=None), dict(body, candidates=None)):
            error(a.call('POST', '/' + a.network + '/link-operations', change, host='host_b'), 400, 'invalid')
        raw = wire(body)
        for invalid in (raw + b'{}', raw[:-1] + b',"address":""}', b'{"activation":"\xff"}'):
            error(a.call('POST', '/' + a.network + '/link-operations', invalid, host='host_b'), 400, 'invalid')
        incomplete = copy.deepcopy(activation)
        incomplete['commit'] = '-'
        error(a.call('POST', '/' + a.network + '/link-operations', a.operation_body(incomplete), host='host_b'), 400, 'invalid')
        draft = payload(activation['owner'])['binding_record']
        draft_catalog = a.with_proofs(a.catalog, [('person_record', draft)])
        error(a.call('POST', '/' + a.network + '/statements', {'catalog': draft_catalog}), 400, 'invalid')
        complete_record = payload(activation['commit'])['binding_record']
        missing_operation = a.with_proofs(a.catalog, [('person_record', complete_record)])
        failure = a.call('POST', '/' + a.network + '/statements', {'catalog': missing_operation})
        error(failure, 409, 'proof_required')
        need(failure[2]['details']['required_ids'] == [complete_record['operation_id']],
             'complete operation record requires its exact missing activation')
        before = a.check_map(a.call('GET', '/' + a.network + '/map'))
        certificate = payload(activation['owner'])['certificate']
        forged = copy.deepcopy(certificate)
        a.oracle.resign('certificate', forged, a.quinn)
        checkpoint = a.checkpoint(['ar_' + 'e' * 64], issued_at=runtime.now)
        a.oracle.resign('checkpoint', checkpoint, a.quinn)
        for kind, obj in (('certificate', forged), ('checkpoint', checkpoint)):
            rejected = a.with_proofs(a.catalog, [(kind, obj)])
            error(a.call('POST', '/' + a.network + '/statements', {'catalog': rejected}), 400, 'invalid')
            need(a.check_map(a.call('GET', '/' + a.network + '/map')) == before,
                 'forged unused object cannot mutate or poison public state', kind)
        pending = a.with_proofs(a.catalog, [('certificate', certificate)])
        a.check_map(a.call('POST', '/' + a.network + '/statements', {'catalog': pending}))
        a.check_map(a.call('GET', '/' + a.network + '/map'))
        runtime.advance(300)
        error(a.call('POST', '/' + a.network + '/link-operations', body, host='host_b'), 410, 'expired')
        error(a.call('GET', '/' + a.network + '/link-operations/' + activation['request']['request_id'], host='host_b'), 404, 'not_found')
        a.check_map(a.call('GET', '/' + a.network + '/map'))

    def build(self):
        for name in ('feature_and_negotiation', 'pending_bound_and_expiry', 'roster_race', 'operations', 'strict_and_uncommitted', 'invite_redemptions', 'invite_forms_and_single_use', 'delegated_and_expired_renewal', 'checkpoint_writer', 'crash_and_restore'):
            self.run(name, getattr(self, name))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--coordinator', required=True)
    parser.add_argument('--section', action='append')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='peerspan-link-coordinator-') as temporary:
        suite = Suite(args, Path(temporary))
        suite.build()
        print(f'{suite.sections} coordinator sections passed; {suite.failures} failed; {suite.requests} authenticated requests.', flush=True)
        return int(bool(suite.failures))


if __name__ == '__main__':
    sys.exit(main())
