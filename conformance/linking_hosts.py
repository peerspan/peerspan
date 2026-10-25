#!/usr/bin/env python3
"""Independent approved-link host runtime conformance.

Real Go/Rust hosts, public local/peer routes, exact public storage and external
OpenSSH/OpenSSL signatures. No implementation module or source is imported.
Installed service/up acceptance remains a separate gate.
"""

import argparse
import base64
import copy
from contextlib import nullcontext
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import time
import traceback

from host_service import SCHEMA_VERSION, LINKING_TABLES, UnixHTTPConnection, stop_all
from launch_onboarding import OnboardHost
from launch_service import host_key
from linking_activations import payload, proof, semantic_id, shift
from linking_mailboxes import Runtime, error, need
from linking_readers import b64, digest, lines, message, ssh_string, unb64, wire
from peer_messaging import fixture_context, request_id as peer_request_id, set_probe, wire as peer_wire
from persons import ssh_key


VIEW = {'request_id', 'mode', 'state', 'network_id', 'person_id', 'host_id',
        'device_fingerprint', 'expires_at', 'completed', 'attention', 'next'}
STAGES = ['request_created', 'owner_offered', 'owner_selected', 'administrator_offered',
          'commit_persisted', 'locally_applied']
APPROVAL = {'request', 'review', 'signing_requests'}
APPROVAL_REVIEW = {'network_id', 'person_id', 'host_public_key', 'device_public_key',
                   'scopes', 'not_after', 'signer_public_key', 'authority_warning'}
SELECT_REVIEW = {'owner_offer_id', 'network_id', 'person_id', 'person_public_key',
                 'host_public_key', 'device_public_key', 'certificate_id',
                 'issuer_certificate_id', 'scopes', 'not_after', 'signer_public_key', 'authority_warning'}
COMMIT_REVIEW = SELECT_REVIEW | {'selection_id', 'administrator_offer_id', 'admission_record_id',
                                'admission_record_base64', 'administrator_signer_public_key'}
PENDING = {'format', 'network_base64', 'expected_network_id', 'expected_person_public_key',
           'coordinator_address', 'coordinator_public_key', 'host_public_key', 'device_public_key',
           'request_nonce', 'request_packet_base64', 'owner_packet_base64', 'selection_packet_base64',
           'administrator_packet_base64', 'commit_packet_base64', 'result_packet_base64', 'catalog_base64',
           'owner_offer_id', 'selection_id', 'administrator_offer_id', 'manifest_id', 'after_sequence',
           'selection_approved', 'commit_approved', 'owner_intent', 'administrator_intent', 'outbound_frames'}


def checked(reply, status=200):
    need(reply[0] == status, 'local HTTP success', status, reply)
    return reply[1]


def public_view(value, display=False):
    need(isinstance(value, dict) and set(value) == VIEW | ({'display_code'} if display else set()),
         'strict public request view', value)
    need(all(isinstance(value[field], list) and all(isinstance(item, str) for item in value[field])
             for field in ('completed', 'attention', 'next')), 'public stage arrays contain only strings')
    stages = value['completed']
    need(stages == [stage for stage in STAGES if stage in stages], 'durable stage order without duplicates', stages)
    if value['mode'] == 'renew':
        need('administrator_offered' not in stages, 'renewal has no administrator stage')
    need(value['device_fingerprint'].startswith('SHA256:'), 'public device fingerprint')
    return value


class Host(OnboardHost):
    def __init__(self, binary, cli, state, home, runtime):
        self.runtime = runtime
        self.barriers = home / 'barriers'
        self.barriers.mkdir(parents=True, exist_ok=True)
        super().__init__(binary, cli, state, home)
        self.logs.close()
        self.logs = (home / 'daemon.log').open('ab+')

    def private_env(self):
        # The deterministic decision clock is explicitly configured for every
        # CLI process as well as its daemon. CLI calls do not arm crash hooks.
        env = super().private_env()
        env.update(PEERSPAN_LINK_TEST_MODE='1', PEERSPAN_LINK_TEST_CLOCK_FILE=str(self.runtime.clock))
        return env

    def call(self, method, path, body=None, raw=None):
        # Linking may await bounded coordinator round trips or the documented
        # 20-second durable crash barrier. The old generic 3-second client is
        # shorter than those operations. Protocol deadlines stay unchanged.
        connection = UnixHTTPConnection(self.state / 'admin.sock', timeout=30)
        try:
            encoded = raw if raw is not None else wire(body) if body is not None else None
            connection.request(method, path, encoded, {'Content-Type': 'application/json'})
            response = connection.getresponse()
            payload = response.read()
            try:
                value = json.loads(payload)
            except (ValueError, UnicodeDecodeError):
                diagnostic = {'method': method, 'path': path, 'status': response.status,
                              'content_type': response.getheader('Content-Type'),
                              'body_bytes': len(payload), 'body_sha256': digest(payload)}
                with (self.home / 'http-errors.jsonl').open('a') as output:
                    output.write(json.dumps(diagnostic, sort_keys=True) + '\n')
                raise AssertionError('local HTTP response is not JSON: ' + repr(diagnostic)) from None
            if response.status >= 400:
                # Retain public response diagnostics without request bodies,
                # which can carry a pairing code or private invitation token.
                with (self.home / 'http-errors.jsonl').open('a') as output:
                    output.write(json.dumps({'method': method, 'path': path, 'status': response.status,
                                             'headers': dict(response.getheaders()), 'body': value},
                                            sort_keys=True) + '\n')
            return response.status, value
        finally:
            connection.close()

    def daemon_env(self):
        env = super().daemon_env()
        env.pop('SSH_AUTH_SOCK', None)
        env.update(PEERSPAN_LINK_TEST_MODE='1', PEERSPAN_LINK_TEST_CLOCK_FILE=str(self.runtime.clock),
                   PEERSPAN_LINK_TEST_BARRIER_DIR=str(self.barriers))
        return env

    def pending(self, request_id):
        with sqlite3.connect(self.state / 'host.db') as db:
            row = db.execute('SELECT record FROM link_pending WHERE request_id=?', (request_id,)).fetchone()
        need(row is not None, 'pending state durably exists before use')
        raw = row[0].encode() if isinstance(row[0], str) else bytes(row[0])
        value = json.loads(raw)
        need(set(value) == PENDING and value['format'] == 1, 'shared strict pending record fields', sorted(value))
        need(raw == wire(value), 'new private rows use recursively sorted compact UTF-8')
        need(type(value['selection_approved']) is bool and type(value['commit_approved']) is bool,
             'consent booleans are explicit')
        return value

    def public_catalog(self, network):
        with sqlite3.connect(self.state / 'host.db') as db:
            rows = db.execute('SELECT proof_id,kind,body FROM link_objects WHERE network_id=? ORDER BY proof_id', (network,)).fetchall()
        entries = []
        for identity, kind, raw in rows:
            raw = raw.encode() if isinstance(raw, str) else bytes(raw)
            entry = proof(kind, raw=raw)
            need(entry['id'] == identity, 'public stored ID derives from original body bytes')
            entries.append(entry)
        return {'format': 1, 'network_id': network, 'objects': entries}

    def cli_input(self, args, stdin=''):
        env = dict(os.environ, **self.private_env())
        env.pop('SSH_AUTH_SOCK', None)
        return subprocess.run([str(self.cli_binary), '--state', str(self.state), *args], input=stdin,
                              capture_output=True, text=True, timeout=30, env=env)


class Ceremony:
    def __init__(self, args, directory, creator, requester):
        self.args, self.root = args, directory
        directory.mkdir(parents=True)
        self.runtime = Runtime(args.coordinator, directory / 'coordinator',
                               initial=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
        self.hosts = []
        self.codes = []
        self.a = self.host('A', creator)
        self.b = self.host('B', requester)
        self.c = self.host('C', creator)
        try:
            self.identity = {h.state.name: h.start() for h in self.hosts}
            info = json.loads(self.runtime.command('info').stdout)
            self.coordinator_key = info['public_key']
            created = self.a.cli('network', 'create', 'linked-team', '--as', 'alice',
                                 '--coordinator', f'127.0.0.1:{self.runtime.port}', '--coordinator-key', self.coordinator_key,
                                 sock=None)
            self.network = created['id']
            self.person = created['person']['key']['public_key']
            self.person_id = 'person_' + digest(unb64(self.person))
            # Legacy creation statements retain real UTC nanoseconds. Set the
            # injected whole-second decision clock after that completed setup,
            # so valid actual setup evidence is not from its fractional future.
            self.runtime.set_time(shift(datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 1))
            self.a.cli('network', 'enable-linking', '--network', self.network, sock=None)
            self.until(lambda: self.feature_active(), 'durably active feature')
        except Exception:
            self.close()
            raise

    def host(self, name, implementation):
        binary = getattr(self.args, implementation)
        value = Host(binary, binary, self.root / name, self.root / ('user-' + name), self.runtime)
        self.hosts.append(value)
        return value

    def close(self):
        try:
            stop_all(self.hosts)
        finally:
            self.runtime.close()

    def until(self, function, label, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = function()
            if value:
                return value
            self.runtime.advance(2)
            time.sleep(.05)
        raise AssertionError('timed out awaiting ' + label)

    def feature_active(self):
        with sqlite3.connect(self.a.state / 'host.db') as db:
            row = db.execute('SELECT record FROM link_features WHERE network_id=?', (self.network,)).fetchone()
        return row is not None and json.loads(row[0])['state'] == 'active'

    def request(self, host, mode='new'):
        value = checked(host.call('POST', '/v1/link/requests',
                        {'mode': mode, 'network_id': self.network, 'person_public_key': self.person,
                         'coordinator_address': f'127.0.0.1:{self.runtime.port}', 'coordinator_public_key': self.coordinator_key}), 201)
        public_view(value, display=True)
        self.codes.append(value['display_code'])
        stored = host.pending(value['request_id'])
        need(not stored['selection_approved'] and not stored['commit_approved'], 'creation grants no mutable-offer consent')
        packet = json.loads(unb64(stored['request_packet_base64']))
        request = payload(packet)
        need(packet['request_id'] == value['request_id'] == 'link_' + digest(lines('peerspan-link-request-id-v1',
             request['coordinator_public_key'], request['host_public_key'], request['device_public_key'], request['request_nonce'])),
             'derive exact public request ID independently')
        need(value['device_fingerprint'] == 'SHA256:' + b64(hashlib.sha256(unb64(request['device_public_key'])).digest()).rstrip('='),
             'fingerprint binds the new device key')
        return value

    def resume(self, host, request_id):
        self.runtime.advance(2)  # Every simulated participant shares this source IP's mailbox poll limit.
        value = checked(host.call('POST', '/v1/link/requests/' + request_id + '/resume', {}))
        if value['state'] in ('linked', 'cancelled', 'expired'):
            need('display_code' not in value, 'terminal resume never discloses code')
        return public_view(value, display='display_code' in value)

    def approval(self, approver, created, admission=False, signer='auto'):
        route = '/v1/link/admissions' if admission else '/v1/link/approvals'
        body = {'code': created['display_code'], 'network_id': self.network,
                'expected_person_id': self.person_id, 'expected_host_key': '-', 'expected_device_key': '-',
                'signer': signer, 'approve': False}
        self.runtime.advance(2)
        value = checked(approver.call('POST', route, body))
        need(set(value) == APPROVAL and set(value['review']) == APPROVAL_REVIEW, 'exact original approval review')
        review = value['review']
        need(review['person_id'] == self.person_id and review['network_id'] == self.network, 'stable identity shown before consent')
        need(isinstance(review['authority_warning'], str), 'authority warning is always public text or dash')
        need(value['signing_requests'] == [], 'preview never offers a signature or publishes an offer')
        body.update(expected_host_key=review['host_public_key'], expected_device_key=review['device_public_key'], approve=True)
        self.runtime.advance(2)
        value = checked(approver.call('POST', route, body))
        return self.sign_ready(approver, created, value)

    def sign_ready(self, approver, created, value):
        """Sign only already approved, dependency-ready fixed external slots."""
        for _ in range(8):
            need(set(value) == APPROVAL and set(value['review']) == APPROVAL_REVIEW, 'strict approval continuation')
            requests = value['signing_requests']
            if not requests:
                return value
            need(approver.key_file.exists(), 'delegated device approval requires no original-person key or external signatures')
            request = requests[0]
            need(set(request) == {'object_type', 'message_base64', 'signer_public_key', 'signature_format'}, 'typed signing request')
            original_public = b64(base64.b64decode(approver.key_file.with_suffix('.pub').read_text().split()[1])[-32:])
            need(request['signature_format'] == 'sshsig' and request['signer_public_key'] == original_public,
                 'external original-person message remains pinned to the actual local provider')
            msg = self.root / 'external-signing-message'
            msg.write_bytes(unb64(request['message_base64']))
            signature = msg.with_name(msg.name + '.sig')
            signature.unlink(missing_ok=True)
            signed = subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(approver.key_file), '-n', 'peerspan-person-v1', '-q', str(msg)],
                                    capture_output=True, timeout=10)
            need(signed.returncode == 0, 'external provider signs exact requested bytes', signed.stderr)
            blob = ''.join(line for line in signature.read_text().splitlines() if not line.startswith('-----'))
            self.runtime.advance(2)
            value = checked(approver.call('POST', '/v1/link/requests/' + created['request_id'] + '/signed',
                                         {'object_type': request['object_type'], 'signature': blob}))
        raise AssertionError('typed signature dependency sequence did not finish')

    def same_review_administrator(self, approver, created):
        """Advance the exact owner/admin consent without granting new consent."""
        request_id = created['request_id']
        def advance():
            self.resume(approver, request_id)
            value = checked(approver.call('GET', '/v1/link/requests/' + request_id + '/approval'))
            need(set(value) == APPROVAL and set(value['review']) == APPROVAL_REVIEW,
                 'already-approved read exposes only the exact public approval response')
            if value['signing_requests']:
                # The daemon has no original key. While this external slot waits,
                # repeated GET cannot create another template or advance consent.
                before = approver.pending(request_id)
                need(checked(approver.call('GET', '/v1/link/requests/' + request_id + '/approval')) == value and
                     approver.pending(request_id) == before, 'GET approval is read-only while waiting for the external signer')
            self.sign_ready(approver, created, value)
            return approver.pending(request_id)['administrator_packet_base64'] != '-'
        self.until(advance, 'same-reviewed exact owner administrator offer')

    def consent(self, host, created, commit=False):
        request_id = created['request_id']
        route = '/v1/link/requests/' + request_id + ('/commit' if commit else '/selection')
        body = {'owner_offer_id': '-', 'network_id': self.network, 'person_public_key': self.person,
                'host_public_key': '-', 'device_public_key': '-', 'approve': False}
        if commit:
            body.update(selection_id='-', administrator_offer_id='-')
        def preview():
            self.runtime.advance(2)
            status, value = host.call('POST', route, body)
            if status == 409 and value.get('code') == 'proof_required':
                self.resume(host, request_id)
                return None
            checked((status, value))
            return value
        value = self.until(preview, 'final review' if commit else 'owner selection review')
        need(set(value) == {'request', 'review'}, 'selection/commit strict response')
        review = value['review']
        need(set(review) == (COMMIT_REVIEW if commit else SELECT_REVIEW), 'selection/commit exact review fields', sorted(review))
        need(review['person_public_key'] == self.person and review['person_id'] == self.person_id, 'review binds original stable person')
        need(isinstance(review['authority_warning'], str), 'selection authority warning is public text')
        for field in ('owner_offer_id', 'network_id', 'person_public_key', 'host_public_key', 'device_public_key'):
            body[field] = review[field]
        if commit:
            for field in ('selection_id', 'administrator_offer_id'):
                body[field] = review[field]
        before = host.pending(request_id)
        need(not before['commit_approved'], 'preview and resume cannot imply final consent')
        body['approve'] = True
        self.runtime.advance(2)
        value = checked(host.call('POST', route, body))
        need(set(value) == {'request', 'review'} and value['review'] == review, 'consent cannot choose another offer or change reviewed fields')
        after = host.pending(request_id)
        need(after['selection_approved'] and (after['commit_approved'] if commit else not after['commit_approved']),
             'separate durable requester consent stages')
        return value

    def complete(self, requester, approver, mode='new'):
        created = self.request(requester, mode)
        self.approval(approver, created, signer='person_root' if approver is self.a else 'auto')
        self.consent(requester, created)
        if mode == 'new':
            if approver is self.a:
                self.runtime.advance(2)
                conflict = approver.call('POST', '/v1/link/admissions',
                    {'code': created['display_code'], 'network_id': self.network, 'expected_person_id': self.person_id,
                     'expected_host_key': '-', 'expected_device_key': '-', 'signer': 'network_root', 'approve': False})
                error((conflict[0], {}, conflict[1]), 409, 'state_conflict')
            self.same_review_administrator(approver, created)
        self.consent(requester, created, commit=True)
        request_id = created['request_id']
        final = self.until(lambda: (view if (view := self.resume(requester, request_id))['state'] == 'linked' else None), 'atomic locally applied link')
        need(final['completed'] == [stage for stage in STAGES if mode != 'renew' or stage != 'administrator_offered'], 'all durable stages before linked')
        need(final['person_id'] == self.person_id and final['network_id'] == self.network, 'link retains original identity')
        self.assert_provider(requester, request_id)
        return request_id

    def assert_provider(self, host, request_id):
        need(not host.key_file.exists(), 'linked machine has no copied/generated original-person private key')
        with sqlite3.connect(host.state / 'host.db') as db:
            row = db.execute('SELECT person_key,device_key,certificate_id FROM link_signers WHERE network_id=?', (self.network,)).fetchone()
            need(row is not None and row[0] == self.person and row[1] != self.person, 'network-scoped provider preserves original identity')
            keys = db.execute('SELECT public_key,length(seed) FROM link_device_keys').fetchall()
            need(keys and all(key != self.person and length == 32 for key, length in keys), 'only separate device seeds stored')
            operations = db.execute('SELECT manifest_id,locally_applied FROM link_operations WHERE request_id=?', (request_id,)).fetchall()
            need(len(operations) == 1 and operations[0][1] == 1, 'one complete locally-applied operation')
            need(db.execute('SELECT secret FROM link_pending WHERE request_id=?', (request_id,)).fetchall() == [(None,)] and
                 db.execute('SELECT COUNT(*) FROM link_frames WHERE request_id=?', (request_id,)).fetchone()[0] == 0,
                 'completed public pending record is retained with live secret/ciphertext atomically erased')
        catalog = host.public_catalog(self.network)
        activations = [json.loads(unb64(entry['body_base64'])) for entry in catalog['objects'] if entry['kind'] == 'activation']
        activation = next(value for value in activations if value['request']['request_id'] == request_id)
        need(semantic_id('packet', activation['commit']) == operations[0][0], 'local manifest derives from exact signed commit')
        certificate = payload(activation['owner'])['certificate']
        need(semantic_id('certificate', certificate) == row[2] and certificate['device_public_key'] == row[1], 'selected exact activated certificate')
        discovered = checked(host.call('GET', '/v1/networks/' + self.network + '/link-signer'))
        need(set(discovered) == {'network_id', 'person_public_key', 'device_public_key', 'certificate_id', 'scopes', 'not_after'} and
             discovered == {'network_id': self.network, 'person_public_key': self.person, 'device_public_key': row[1],
                            'certificate_id': row[2], 'scopes': certificate['scopes'], 'not_after': certificate['not_after']},
             'read-only signer discovery resolves the exact usable local provider and stable person')
        events = checked(host.call('GET', '/v1/activity?after=0&limit=1000'))
        need(sum(event['kind'] == 'network.link_applied' and event['subject_id'] == request_id for event in events) == 1,
             'exactly one link application event shares the atomic local transaction')
        self.verify_transcript(activation, activations)
        return activation

    def verify_signature(self, key, msg, encoded):
        """Use independent OpenSSH/OpenSSL against the exact retained message."""
        raw = unb64(encoded)
        directory = self.root / 'signature-verification'
        directory.mkdir(exist_ok=True)
        preimage, signature = directory / 'message', directory / 'signature'
        preimage.write_bytes(msg)
        if raw.startswith(b'SSHSIG'):
            signature.write_text('-----BEGIN SSH SIGNATURE-----\n' + '\n'.join(textwrap.wrap(encoded, 76)) + '\n-----END SSH SIGNATURE-----\n')
            allowed = directory / 'allowed'
            allowed.write_text('person ssh-ed25519 ' + b64(ssh_string(b'ssh-ed25519') + ssh_string(unb64(key))) + '\n')
            command = ['ssh-keygen', '-Y', 'verify', '-f', str(allowed), '-I', 'person',
                       '-n', 'peerspan-person-v1', '-s', str(signature)]
        else:
            need(len(raw) == 64, 'raw Ed25519 signature has exactly 64 bytes')
            signature.write_bytes(raw)
            public = directory / 'public.der'
            public.write_bytes(bytes.fromhex('302a300506032b6570032100') + unb64(key))
            command = ['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', str(public), '-keyform', 'DER',
                       '-rawin', '-in', str(preimage), '-sigfile', str(signature)]
        verified = subprocess.run(command, input=msg, capture_output=True, timeout=10)
        need(verified.returncode == 0, 'independent exact-message signature verification', verified.stderr)

    def verify_transcript(self, activation, all_activations):
        certificates = {semantic_id('certificate', certificate): certificate
                        for other in all_activations for certificate in [payload(other['owner'])['certificate']]}
        request = payload(activation['request'])
        certificate = payload(activation['owner'])['certificate']
        need(certificate['host_public_key'] == request['host_public_key'] and
             certificate['device_public_key'] == request['device_public_key'] and certificate['person_public_key'] == self.person,
             'certificate binds exact requested host, device and original person')
        parent = certificate['parent_id']
        issuer = self.person if parent == 'root' else certificates[parent]['device_public_key']
        self.verify_signature(issuer, message('certificate', certificate), certificate['signature'])
        for role, packet in activation.items():
            if packet == '-':
                continue
            need(packet['role'] == role and packet['request_id'] == activation['request']['request_id'], 'packet role/request association')
            msg = message('packet', packet)
            if role in ('request', 'selection', 'commit'):
                need(packet['writer_public_key'] == request['host_public_key'], 'requester packet exact host writer')
                self.verify_signature(request['host_public_key'], msg, packet['host_signature'])
                self.verify_signature(request['device_public_key'], msg, packet['device_signature'])
            else:
                selected = packet['certificate_id']
                expected = (payload(activation['owner'])['network']['genesis_root_public_key'] if selected == 'network_root'
                            else packet['person_public_key'] if selected == 'root' else certificates[selected]['device_public_key'])
                need(packet['writer_public_key'] == expected, 'authority packet independently pinned signer')
                self.verify_signature(expected, msg, packet['authority_signature'])
        for role, field in (('owner', 'binding_record'), ('administrator', 'admission_record'), ('commit', 'binding_record')):
            if activation[role] == '-':
                continue
            record = payload(activation[role])[field]
            if record == '-':
                continue
            kind = 'person_record' if 'person_public_key' in record else 'root_record'
            selected = record.get('certificate_id', 'network_root')
            expected = (payload(activation['owner'])['network']['genesis_root_public_key'] if selected == 'network_root'
                        else record['person_public_key'] if selected == 'root' else certificates[selected]['device_public_key'])
            need(record['operation_id'] == activation['request']['request_id'], 'operation records cannot become ordinary grants')
            self.verify_signature(expected, message(kind, record), record['signature'])
            if role == 'commit':
                self.verify_signature(request['host_public_key'], lines('peerspan-binding-consent-v1', digest(message(kind, record))),
                                      record['host_signature'])

    def no_secrets(self):
        for host in self.hosts:
            listing = checked(host.call('GET', '/v1/link/requests')) if host.process and host.process.poll() is None else []
            need(isinstance(listing, list) and [item['request_id'] for item in listing] == sorted(item['request_id'] for item in listing),
                 'normal request collection is a sorted bare array')
            for item in listing:
                public_view(item)
                public_view(checked(host.call('GET', '/v1/link/requests/' + item['request_id'])))
            public = json.dumps(listing)
            if host.process and host.process.poll() is None:
                public += json.dumps(checked(host.call('GET', '/v1/status')))
                public += json.dumps(checked(host.call('GET', '/v1/activity?after=0&limit=1000')))
            logs = os.pread(host.logs.fileno(), os.fstat(host.logs.fileno()).st_size, 0)
            for code in self.codes:
                need(code.encode() not in logs and code not in public, 'logs/status/activity never disclose display code')

    def action(self, host, kind, unsigned):
        raw = wire(unsigned)
        response = checked(host.call('POST', '/v1/networks/' + self.network + '/link-actions',
                                     {'kind': kind, 'payload_base64': b64(raw), 'certificate_id': 'auto'}))
        need(set(response) == {'record_id', 'proof_id', 'record_base64', 'catalog', 'committed'}, 'strict typed action result')
        need(response['committed'] is True, 'published ordinary action applies locally before success')
        record_raw = unb64(response['record_base64'])
        record = json.loads(record_raw)
        need(record['payload_base64'] == b64(raw) and record['operation_id'] == '-', 'typed operation signs the exact supplied ordinary payload')
        need(response['record_id'] == semantic_id('person_record', record) and
             response['proof_id'] == proof('person_record', raw=record_raw)['id'], 'independent exact action identifiers')
        with sqlite3.connect(host.state / 'host.db') as db:
            signer = db.execute('SELECT device_key,certificate_id FROM link_signers WHERE network_id=?', (self.network,)).fetchone()
        need(record['certificate_id'] == signer[1] and record['person_public_key'] == self.person, 'typed signer remains selected original person/device')
        self.verify_signature(signer[0], message('person_record', record), record['signature'])
        return response

    def access_snapshot(self, host):
        with sqlite3.connect(host.state / 'host.db') as db:
            return (db.execute('SELECT proof_id,kind,body FROM link_objects WHERE network_id=? ORDER BY proof_id', (self.network,)).fetchall(),
                    db.execute('SELECT kind,subject,version,record_hash FROM link_highwater WHERE network_id=? ORDER BY kind,subject', (self.network,)).fetchall(),
                    sorted(db.execute('SELECT * FROM policy_edits').fetchall(), key=repr))


def full_chain(c):
    first = c.complete(c.b, c.a)
    c.a.stop()
    child = c.complete(c.c, c.b)
    b = c.assert_provider(c.b, first)
    nested = c.assert_provider(c.c, child)
    need(payload(nested['owner'])['certificate']['parent_id'] == semantic_id('certificate', payload(b['owner'])['certificate']),
         'B approves C with its exact device while original-person machine is offline')
    c.no_secrets()


def renewal_retries_and_reachability(c):
    old = next(value for value in checked(c.c.call('GET', '/v1/link/requests')) if value['mode'] == 'new')
    original_id = old['request_id']
    stored = c.c.pending(original_id)
    activation = json.loads(unb64(stored['result_packet_base64']))
    activation = payload(activation)['activation']
    target = payload(activation['request'])
    body = {'owner_offer_id': stored['owner_offer_id'], 'selection_id': stored['selection_id'],
            'administrator_offer_id': stored['administrator_offer_id'], 'network_id': c.network,
            'person_public_key': c.person, 'host_public_key': target['host_public_key'],
            'device_public_key': target['device_public_key'], 'approve': True}
    route = '/v1/link/requests/' + original_id + '/commit'
    original_outcome = checked(c.c.call('POST', route, body))
    original_certificate = semantic_id('certificate', payload(activation['owner'])['certificate'])
    for host in (c.b, c.c):
        synced = host.cli('network', 'sync', c.network, sock=None)
        need(synced['last_sync_error'] is None, 'explicit current sync establishes the positive peer-hint precondition')
    before_members = c.c.cli('network', 'members', c.network, sock=None)
    b_host = c.identity[c.b.state.name]['id']
    b_address = next(member['address'] for member in before_members if member['host_id'] == b_host)
    need(b_address == c.b.address, 'positive peer reachability hint exists before renewal')
    renewed_id = c.complete(c.c, c.b, mode='renew')
    current = c.assert_provider(c.c, renewed_id)
    certificate = payload(current['owner'])['certificate']
    need((certificate['host_public_key'], certificate['device_public_key']) ==
         (target['host_public_key'], target['device_public_key']) and
         semantic_id('certificate', certificate) != original_certificate,
         'renewal preserves exact host/device keys while selecting its new certificate')
    after_members = c.c.cli('network', 'members', c.network, sock=None)
    need(next(member['address'] for member in after_members if member['host_id'] == b_host) == b_address,
         'first renewal apply retains the existing verified peer reachability hint')
    def snapshot():
        members = checked(c.c.call('GET', '/v1/networks/' + c.network + '/members'))
        public_members = [(member['host_id'], member['address'], member['public_key'], member['member'],
                           member.get('person_id'), member.get('person_member')) for member in members]
        with sqlite3.connect(c.c.state / 'host.db') as db:
            return (db.execute('SELECT person_key,device_key,certificate_id FROM link_signers WHERE network_id=?', (c.network,)).fetchall(),
                    public_members,
                    db.execute('SELECT request_id,manifest_id,locally_applied FROM link_operations ORDER BY request_id').fetchall(),
                    c.access_snapshot(c.c))
    before = snapshot()
    need(checked(c.c.call('POST', route, body)) == original_outcome,
         'old exact committed retry returns its original public outcome after a newer renewal')
    need(snapshot() == before, 'old committed retry cannot roll back newer provider, membership or public authority')
    for field, changed in (('owner_offer_id', 'lp_' + '0' * 64), ('selection_id', 'lp_' + '0' * 64),
                            ('administrator_offer_id', 'lp_' + '0' * 64), ('network_id', 'net_' + '0' * 64),
                            ('person_public_key', c.coordinator_key), ('host_public_key', c.person),
                            ('device_public_key', c.person)):
        rejected = c.c.call('POST', route, dict(body, **{field: changed}))
        error((rejected[0], {}, rejected[1]), 409, 'operation_conflict')
        need(snapshot() == before, 'changed retry pin/reference cannot mutate committed state', field)
    c.no_secrets()


def separate_roles(c):
    implementation = 'go' if str(c.b.binary) == str(c.args.go) else 'rust'
    quinn = c.host('Quinn', implementation)
    quinn.start()
    invitation = c.a.cli('network', 'invite', '--network', c.network, '--member', 'quinn', sock=None)
    joined = quinn.cli('network', 'join', '--token', invitation['token'], sock=None)
    quinn_id = joined['person']['person_id']
    # Resolve the remote admission through an explicit ordinary sync before
    # the legacy local-person delegation selector runs.
    c.a.cli('network', 'sync', c.network, sock=None)
    c.a.cli('network', 'delegate-admin', '--network', c.network, '--person', quinn_id, sock=None)
    # Keep current root material external to the owner/provider. Alice cannot
    # silently supply the independent administrator signature after rotation.
    provider = c.root / 'external-root-provider'
    provider.mkdir()
    root_key, _, _ = ssh_key(provider, 'network-root')
    c.a.cli('network', 'rotate-root', c.network, '--to-ssh', '--root-key', str(root_key), sock=None)
    c.a.cli('network', 'remove-admin', '--network', c.network, '--person', c.person_id, '--root-key', str(root_key), sock=None)
    quinn.cli('network', 'sync', c.network, sock=None)
    c.a.cli('network', 'sync', c.network, sock=None)

    def link(requester, owner):
        created = c.request(requester)
        c.approval(owner, created, signer='person_root' if owner is c.a else 'auto')
        c.consent(requester, created)
        if owner is c.b:
            denied = owner.call('POST', '/v1/link/admissions',
                               {'code': created['display_code'], 'network_id': c.network, 'expected_person_id': c.person_id,
                                'expected_host_key': '-', 'expected_device_key': '-', 'signer': 'auto', 'approve': False})
            error((denied[0], {}, denied[1]), 403, 'forbidden')
        approved = c.approval(quinn, created, admission=True, signer='person_root')
        need(approved['review']['person_id'] == c.person_id and approved['review']['signer_public_key'] != c.person,
             'administrator review separately pins owner Alice and actual signer Quinn')
        c.consent(requester, created, commit=True)
        request_id = created['request_id']
        c.until(lambda: (view if (view := c.resume(requester, request_id))['state'] == 'linked' else None), 'separately admitted host')
        activation = c.assert_provider(requester, request_id)
        admin = payload(activation['administrator'])['admission_record']
        need(admin['person_public_key'] == approved['review']['signer_public_key'] and admin['person_public_key'] != c.person,
             'exact selected admission uses the independent administrator identity')
    link(c.b, c.a)
    c.a.stop()
    link(c.c, c.b)
    c.no_secrets()


def approval_network_pin(c):
    other = c.a.cli('network', 'create', 'linked-other', '--as', 'alice',
                    '--coordinator', f'127.0.0.1:{c.runtime.port}', '--coordinator-key', c.coordinator_key, sock=None)
    need(other['id'] != c.network and other['person']['key']['public_key'] == c.person,
         'two actual networks share the same local person and actual coordinator without sharing network identity')
    completed_setup = shift(datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 1)
    c.runtime.set_time(max(c.runtime.now, completed_setup))
    c.a.cli('network', 'enable-linking', '--network', other['id'], sock=None)
    created = c.request(c.b)
    identity = created['request_id']
    body = {'code': created['display_code'], 'network_id': other['id'], 'expected_person_id': c.person_id,
            'expected_host_key': '-', 'expected_device_key': '-', 'signer': 'person_root', 'approve': False}
    def local_rows():
        with sqlite3.connect(c.a.state / 'host.db') as db:
            return db.execute('SELECT record FROM link_pending WHERE request_id=?', (identity,)).fetchall()
    for cached in (False, True):
        if cached:
            c.approval(c.a, created, signer='person_root')
        before = [json.loads(row[0]) for row in local_rows()]
        public_before = (c.a.public_catalog(c.network), c.a.public_catalog(other['id']))
        c.runtime.advance(2)
        refused = c.a.call('POST', '/v1/link/approvals', body)
        error((refused[0], {}, refused[1]), 400, 'invalid')
        after = [json.loads(row[0]) for row in local_rows()]
        if cached:
            fields = ('owner_intent', 'administrator_intent', 'owner_packet_base64', 'administrator_packet_base64',
                      'selection_packet_base64', 'commit_packet_base64', 'selection_approved', 'commit_approved')
            need(len(before) == len(after) == 1 and all(after[0][field] == before[0][field] for field in fields) and
                 {frame['frame_id'] for frame in after[0]['outbound_frames']} ==
                 {frame['frame_id'] for frame in before[0]['outbound_frames']},
                 'cached wrong-network preview preserves every exact approved intent/template/packet and creates no outbound frame')
        else:
            need(all(value['owner_intent'] == value['administrator_intent'] == '-' and
                     value['owner_packet_base64'] == value['administrator_packet_base64'] == '-' and
                     not value['outbound_frames'] for value in after),
                 'uncached wrong-network preview may retain verified transport but grants no approval, signature or outbound publication')
        need((c.a.public_catalog(c.network), c.a.public_catalog(other['id'])) == public_before,
             'invalid actual-network pin changes no public authority in either network')
    need(not c.b.pending(identity)['selection_approved'] and not c.b.pending(identity)['commit_approved'],
         'invalid cross-network approval cannot confer requester selection or final consent')
    c.no_secrets()


def root_admission_without_owner_role(c):
    c.a.cli('network', 'remove-admin', '--network', c.network, '--person', c.person_id, sock=None)
    created = c.request(c.b)
    c.approval(c.a, created, signer='person_root')
    need(c.a.pending(created['request_id'])['administrator_intent'] == '-',
         'owner without current administrator role cannot preapprove a root/alternate fallback')
    c.consent(c.b, created)
    c.resume(c.a, created['request_id'])
    need(c.a.pending(created['request_id'])['administrator_packet_base64'] == '-',
         'owner-only resume never publishes an unreviewed network-root admission')
    c.approval(c.a, created, admission=True, signer='network_root')
    c.consent(c.b, created, commit=True)
    c.until(lambda: (view if (view := c.resume(c.b, created['request_id']))['state'] == 'linked' else None), 'explicit root-only admission')
    activation = c.assert_provider(c.b, created['request_id'])
    packet = activation['administrator']
    need(packet['certificate_id'] == 'network_root' and packet['person_public_key'] == '-' and
         'person_public_key' not in payload(packet)['admission_record'],
         'independent explicit network-root administration uses its exact root companion')
    c.no_secrets()


def cancellation_and_terminal_retention(c):
    first = c.request(c.b)
    request_id = first['request_id']
    before = c.b.pending(request_id)
    denied = c.b.call('GET', '/v1/link/requests/' + request_id + '/approval')
    error((denied[0], {}, denied[1]), 409, 'state_conflict')
    need(c.b.pending(request_id) == before, 'unapproved requester GET grants no consent or signing slot')
    def cancelled(created):
        identity = created['request_id']
        value = public_view(checked(c.b.call('POST', '/v1/link/requests/' + identity + '/cancel', {})))
        need(value['state'] == 'cancelled' and not c.b.pending(identity)['commit_approved'],
             'pre-final-consent cancellation retires a request without final authorization')
        with sqlite3.connect(c.b.state / 'host.db') as db:
            need(db.execute('SELECT secret FROM link_pending WHERE request_id=?', (identity,)).fetchall() == [(None,)] and
                 db.execute('SELECT COUNT(*) FROM link_frames WHERE request_id=?', (identity,)).fetchone()[0] == 0,
                 'cancel immediately retires code secret and ciphertext while keeping the public tombstone')
        terminal = c.resume(c.b, identity)
        need(terminal['state'] == 'cancelled' and 'display_code' not in terminal, 'terminal resume does not revive or disclose cancelled code')
    cancelled(first)
    second = c.request(c.b)
    after = c.b.pending(second['request_id'])
    need(second['request_id'] != request_id and after['request_nonce'] != before['request_nonce'] and
         (after['host_public_key'], after['device_public_key']) == (before['host_public_key'], before['device_public_key']),
         'fresh request after cancellation preserves machine/device keys and creates a fresh immutable nonce/ID')
    c.approval(c.a, second, signer='person_root')
    stopped = public_view(checked(c.a.call('POST', '/v1/link/requests/' + second['request_id'] + '/cancel', {})))
    need(stopped['state'] == 'offer_sent', 'stopping an approver reports the already sent offer, not withdrawal')
    c.consent(c.b, second)
    cancelled(second)
    signer = c.b.call('GET', '/v1/networks/' + c.network + '/link-signer')
    need(signer[0] == 404, 'cancelled pending certificates never become a selected live provider')
    c.runtime.set_time(shift(second['expires_at'], 86400 - 1))
    value = public_view(checked(c.b.call('GET', '/v1/link/requests/' + second['request_id'])))
    need(value['state'] == 'cancelled', 'public cancellation tombstone survives through deadline plus24hours')
    need(not c.b.key_file.exists(), 'cancellation and expiry never generate a replacement original-person key')
    c.no_secrets()


def checkpoint_provider(c):
    full_chain(c)
    implementation = 'go' if str(c.b.binary) == str(c.args.go) else 'rust'
    d = c.host('D', implementation)
    c.identity[d.state.name] = d.start()
    request_id = c.complete(d, c.c)
    activation = c.assert_provider(d, request_id)
    child_id = next(item['request_id'] for item in checked(c.c.call('GET', '/v1/link/requests')) if item['mode'] == 'new')
    child = c.assert_provider(c.c, child_id)
    def retained_records(value):
        return sorted(semantic_id('person_record', payload(value[role])[field])
                      for role, field in (('commit', 'binding_record'), ('administrator', 'admission_record')))
    records = retained_records(activation)
    child_records = retained_records(child)
    c.b.cli('network', 'sync', c.network, sock=None)
    signer = checked(c.b.call('GET', '/v1/networks/' + c.network + '/link-signer'))
    unsigned = {'format': 1, 'network_id': c.network, 'person_public_key': c.person,
                'issuer_certificate_id': signer['certificate_id'], 'issued_at': c.runtime.now, 'records': records}
    route = '/v1/networks/' + c.network + '/link-actions'
    body = {'kind': 'checkpoint', 'payload_base64': b64(wire(unsigned)), 'certificate_id': 'auto'}
    response = checked(c.b.call('POST', route, body))
    need(set(response) == {'record_id', 'proof_id', 'record_base64', 'catalog', 'committed'} and
         response['record_id'] == '-' and response['committed'] is True,
         'typed checkpoint uses no invented semantic ID and commits the exact public proof')
    raw = unb64(response['record_base64'])
    signed = json.loads(raw)
    need(set(signed) == set(unsigned) | {'signature'} and all(signed[key] == value for key, value in unsigned.items()) and
         response['proof_id'] == proof('checkpoint', raw=raw)['id'], 'checkpoint retains exact unsigned intent and transport PF')
    c.verify_signature(signer['device_public_key'], message('checkpoint', signed), signed['signature'])
    def refused(host, value, status, code, required=None):
        before = c.access_snapshot(host)
        rejected = host.call('POST', route, {'kind': 'checkpoint', 'payload_base64': b64(wire(value)), 'certificate_id': 'auto'})
        error((rejected[0], {}, rejected[1]), status, code)
        if required is not None:
            need(rejected[1]['details']['required_ids'] == required, 'checkpoint intent names the exact missing retained record')
        need(c.access_snapshot(host) == before and 'record_base64' not in rejected[1],
             'checkpoint intent refusal exposes no signature and mutates no signed public authority')
    refused(c.b, dict(unsigned, records=child_records), 403, 'forbidden')
    d.cli('network', 'sync', c.network, sock=None)
    d_signer = checked(d.call('GET', '/v1/networks/' + c.network + '/link-signer'))
    refused(d, dict(unsigned, issuer_certificate_id=d_signer['certificate_id'], records=child_records), 403, 'forbidden')
    refused(c.b, dict(unsigned, person_public_key=c.coordinator_key), 400, 'invalid')
    unknown = 'ar_' + '0' * 64
    refused(c.b, dict(unsigned, records=[unknown]), 409, 'proof_required', [unknown])
    # Supply independently signed original-person retention before testing actor
    # expiry, so unrelated missing C/D history cannot mask the expired provider.
    c.runtime.set_time(shift(signer['not_after'], 1))
    root_cp = dict(unsigned, issuer_certificate_id='root', issued_at=c.runtime.now,
                   records=sorted(set(records + child_records)))
    message_file = c.a.home / 'root-checkpoint-message'
    message_file.write_bytes(message('checkpoint', root_cp))
    signed_file = message_file.with_name(message_file.name + '.sig')
    signed_file.unlink(missing_ok=True)
    signed_result = subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(c.a.key_file), '-n', 'peerspan-person-v1', '-q', str(message_file)],
                                   capture_output=True, timeout=10)
    need(signed_result.returncode == 0, 'original-person machine signs the exact public retention checkpoint', signed_result.stderr)
    root_cp['signature'] = ''.join(line for line in signed_file.read_text().splitlines() if not line.startswith('-----'))
    c.verify_signature(c.person, message('checkpoint', root_cp), root_cp['signature'])
    catalog = {'format': 1, 'network_id': c.network, 'objects': [proof('checkpoint', root_cp)]}
    tls_directory = c.a.home / 'checkpoint-transport'
    tls_directory.mkdir(mode=0o700)
    posted = c.runtime.call('POST', '/coord/v2/networks/' + c.network + '/statements', {'catalog': catalog},
                            key=host_key(c.a, tls_directory))
    need(posted[0] == 200, 'unaffected original person repairs exact retained C/D history', posted)
    c.b.cli('network', 'sync', c.network, sock=None)
    refused(c.b, dict(unsigned, issued_at=c.runtime.now), 403, 'authority_expired')
    need(not c.b.key_file.exists(), 'expired checkpoint provider retains the original person without creating its key')
    c.no_secrets()


def full_u64_management(c):
    host = c.c
    agent = host.cli('agent', 'register', '--name', 'high-u64-citation', '--owner', 'alice')
    policy = {'format': 2, 'network_id': c.network, 'person_public_key': c.person,
              'version': 1, 'issued_at': shift(c.runtime.now, -3600), 'valid_until': shift(c.runtime.now, 86400),
              'rules': [{'agent': '*', 'principals': ['network'], 'actions': ['message.append'],
                         'max_message_bytes': 65536, 'allow_disconnected': False}],
              'capability_rules': [], 'trusted_hosts': [], 'edits': []}
    group = {'network_id': c.network, 'name': 'linking-high-u64', 'version': 1,
             'defined_at': c.runtime.now, 'members': [c.person_id]}
    for version in (2 ** 63, 2 ** 64 - 1):
        policy['version'], group['version'] = version, version
        if version == 2 ** 64 - 1:
            policy['issued_at'] = shift(c.runtime.now, -86400)
            policy['valid_until'] = shift(c.runtime.now, 30)
        signed_policy = c.action(host, 'peerspan-policy-v2', policy)
        signed_group = c.action(host, 'peerspan-group-v1', group)
        view = checked(host.call('GET', '/v1/networks/' + c.network + '/policy?person=' + c.person_id))
        need(set(view) == set(policy) | {'signature', 'expires_soon', 'authorization_base64'} and view['signature'] == '-',
             'enveloped policy view has only verified payload, expiry flag and exact authorization')
        need(view['version'] == version and view['authorization_base64'] == signed_policy['record_base64'], 'policy view preserves full u64 and original signed envelope')
        groups = checked(host.call('GET', '/v1/networks/' + c.network + '/groups'))
        selected = next(value for value in groups if value['name'] == group['name'])
        need(set(selected) == {'name', 'version', 'members', 'signer', 'authorization_base64'} and
             selected['version'] == version and selected['members'] == [c.person_id] and
             selected['authorization_base64'] == signed_group['record_base64'], 'unsigned group view preserves exact selected envelope and full u64')
        with sqlite3.connect(host.state / 'host.db') as db:
            rows = db.execute('SELECT version,typeof(version) FROM link_highwater WHERE network_id=?', (c.network,)).fetchall()
        encoded = version.to_bytes(8, 'big')
        need(sum(value == encoded and storage == 'blob' for value, storage in rows) >= 2,
             'high-half policy and group versions use exact big-endian SQLite BLOB, never numeric coercion')
        c.b.cli('network', 'sync', c.network, sock=None)
        # Owner CLI sends between these siblings correctly prefer `self`.
        # Explicit policy is separately valid on the public peer wire, so use
        # the actual authenticated probe to isolate u64 citation decoding.
        sent = {'request_id': peer_request_id(), 'target_agent_id': agent['id'],
                'deadline': shift(c.runtime.now, 20), 'content': 'exact-u64-citation-' + str(version),
                'policy': {'person_id': c.person_id, 'version': version}}
        response = peer_wire(host, fixture_context(c.b), 'POST', '/peer/v1/messages', body=sent)
        need(response[0] == 200, 'actual peer accepts full unsigned version policy citation', response)
        received = next(value['request'] for value in host.cli('message', 'list', sock=None)
                        if value['request']['request_id'] == sent['request_id'])
        need(received['policy'] == {'person_id': c.person_id, 'version': version},
             'receiver accepts and retains exact high-half/max citation without signed narrowing')
        if version == 2 ** 63:
            # Exercise the same CLI generation paths positively before the max
            # refusal, so an unrelated missing-provider error cannot pass it.
            allowed = host.run('allow', 'network', '--agent', '*', '--network', c.network, sock=None)
            need(allowed.returncode == 0, 'linked device CLI advances a high-half policy without an original-person key', allowed.stderr)
            grouped = host.run('network', 'group', 'set', '--network', c.network, '--group', group['name'], '--person', c.person_id, sock=None)
            need(grouped.returncode == 0, 'linked administrator CLI advances a high-half group', grouped.stderr)
            updated = checked(host.call('GET', '/v1/networks/' + c.network + '/policy?person=' + c.person_id))
            groups = checked(host.call('GET', '/v1/networks/' + c.network + '/groups'))
            need(updated['version'] == version + 1 and next(value['version'] for value in groups if value['name'] == group['name']) == version + 1,
                 'CLI increments the full high-half value exactly once')
            for field in policy:
                policy[field] = copy.deepcopy(updated[field])
            need(not host.key_file.exists(), 'positive high-half CLI updates use only the linked device provider')
    before = c.access_snapshot(host)
    # The same device seed and exact catalog/high-water rows survive an actual
    # daemon/CLI implementation switch, with no original-person key available.
    host.stop()
    replacement = c.args.rust if str(host.binary) == str(c.args.go) else c.args.go
    host.binary = host.cli_binary = str(replacement)
    host.start()
    need(c.access_snapshot(host) == before, 'cross-language reopen preserves exact high-half/max version storage and public bytes')
    policy_after = checked(host.call('GET', '/v1/networks/' + c.network + '/policy?person=' + c.person_id))
    need(policy_after['version'] == 2 ** 64 - 1, 'cross-language materialization keeps max-u64 policy')
    selected_id = checked(host.call('GET', '/v1/networks/' + c.network + '/link-signer'))['certificate_id']
    activations = [json.loads(unb64(entry['body_base64'])) for entry in host.public_catalog(c.network)['objects']
                   if entry['kind'] == 'activation']
    selected_activation = next(value for value in activations if semantic_id('certificate', payload(value['owner'])['certificate']) == selected_id)
    c.assert_provider(host, selected_activation['request']['request_id'])
    for command in (('allow', 'network', '--agent', '*', '--network', c.network),
                    ('network', 'group', 'set', '--network', c.network, '--group', group['name'], '--person', c.person_id)):
        refused = host.run(*command, sock=None)
        need(refused.returncode != 0, 'CLI refuses version progression from max-u64 before signing or mutation')
        need('access version exhausted' in refused.stderr, 'max-version refusal reports the pinned exhaustion category', refused.stderr)
        need(c.access_snapshot(host) == before, 'max-version refusal leaves exact public records, marks and edit reservations unchanged')
        need(not host.key_file.exists(), 'max-version failure cannot generate a replacement person')
    metadata_route = '/v1/networks/' + c.network + '/link-access-versions'
    versions = checked(host.call('GET', metadata_route))
    signed = json.loads(unb64(signed_policy['record_base64']))
    group_signed = json.loads(unb64(signed_group['record_base64']))
    need(set(versions) == {'policies', 'groups'} and
         versions['policies'] == sorted(versions['policies'], key=lambda value: value['person_public_key']) and
         versions['groups'] == sorted(versions['groups'], key=lambda value: value['name']),
         'read-only access version metadata has exact sorted arrays')
    need({'person_public_key': c.person, 'version': 2 ** 64 - 1,
          'message_hash': digest(message('person_record', signed))} in versions['policies'] and
         {'name': group['name'], 'version': 2 ** 64 - 1,
          'message_hash': digest(message('person_record', group_signed))} in versions['groups'],
         'metadata exposes max-u64 with independently derived exact signed-message hashes')
    c.runtime.advance(31)
    c.runtime.stop()
    try:
        need(checked(host.call('GET', metadata_route)) == versions,
             'offline metadata retains an expired highest policy without falling back to lower access')
        inactive_before = c.access_snapshot(host)
        for command in (('allow', 'network', '--agent', '*', '--network', c.network),
                        ('network', 'group', 'set', '--network', c.network, '--group', group['name'], '--person', c.person_id)):
            refused = host.run(*command, sock=None)
            need(refused.returncode != 0 and 'access version exhausted' in refused.stderr,
                 'offline generation uses retained maxima even when the selected highest policy is inactive', refused.stderr)
            need(c.access_snapshot(host) == inactive_before,
                 'inactive-max refusal occurs before edit reservation, signature or public mutation')
    finally:
        c.runtime.start()


def typed_guards(c):
    host = c.c
    before = c.access_snapshot(host)
    with sqlite3.connect(host.state / 'host.db') as db:
        device, certificate = db.execute('SELECT device_key,certificate_id FROM link_signers WHERE network_id=?', (c.network,)).fetchone()
    revocation = {'format': 1, 'network_id': c.network, 'person_public_key': c.person,
                  'target_device_public_key': device, 'target_certificate_id': certificate,
                  'issuer_certificate_id': certificate, 'revoked_at': c.runtime.now}
    route = '/v1/networks/' + c.network + '/link-actions'
    response = host.call('POST', route, {'kind': 'device_revocation', 'payload_base64': b64(wire(revocation)), 'certificate_id': certificate})
    error((response[0], {}, response[1]), 403, 'authority_would_be_invalidated')
    for body in ({'kind': 'raw', 'payload_base64': b64(b'please sign arbitrary bytes'), 'certificate_id': 'auto'},
                 {'kind': 'peerspan-policy-v2', 'payload_base64': None, 'certificate_id': 'auto'},
                 {'kind': 'peerspan-policy-v2', 'payload_base64': b64(b'{}'), 'certificate_id': 'auto', 'signature': 'injected'},
                 {'kind': 'device_revocation', 'payload_base64': b64(wire(dict(revocation, signature='injected'))), 'certificate_id': certificate}):
        response = host.call('POST', route, body)
        error((response[0], {}, response[1]), 400, 'invalid')
    need(c.access_snapshot(host) == before, 'invalid/raw/self-invalidating actions publish and apply no new records')
    for path in ('/v1/link/requests', '/v1/link/approvals', '/v1/networks/' + c.network + '/link-actions'):
        status, _ = peer_wire(host, fixture_context(c.b), 'POST', path, body={})
        need(status == 404, 'private linking routes are absent from the peer router', path, status)


def canonical_highwater_copies(c):
    """Actual SQLite storage encodings must fail closed in both readers."""
    original = c.c
    original.stop()
    c.runtime.stop()
    before = c.access_snapshot(original)
    with sqlite3.connect(original.state / 'host.db') as db:
        subject = db.execute('SELECT kind,subject FROM link_highwater WHERE network_id=? ORDER BY kind,subject LIMIT 1',
                             (c.network,)).fetchone()
        providers = db.execute('SELECT person_key,device_key,certificate_id FROM link_signers WHERE network_id=?',
                               (c.network,)).fetchall()
    need(subject is not None, 'canonical-storage corruption gate has a positive learned high-water row')
    malformed = [('zero_integer', 0), ('negative_integer', -1), ('real', 1.5), ('text', 'not-a-u64'),
                 ('short_blob', b'\x80' * 7), ('long_blob', b'\x80' * 9), ('low_half_blob', b'\x7f' + b'\xff' * 7)]
    try:
        for implementation in ('go', 'rust'):
            for label, value in [('valid_control', None), *malformed]:
                root = c.root / ('highwater-' + implementation + '-' + label)
                state = root / 'state'
                root.mkdir()
                shutil.copytree(original.state, state, ignore=shutil.ignore_patterns('admin.sock'))
                if value is not None:
                    with sqlite3.connect(state / 'host.db') as db:
                        db.execute('UPDATE link_highwater SET version=? WHERE network_id=? AND kind=? AND subject=?',
                                   (value, c.network, *subject))
                copy_host = Host(getattr(c.args, implementation), getattr(c.args, implementation), state, root / 'user', c.runtime)
                try:
                    startup_failed = False
                    try:
                        copy_host.start()
                    except AssertionError:
                        startup_failed = True
                        need(value is not None and copy_host.process.poll() is not None,
                             'only explicit corrupt-state refusal may replace an HTTP validation response')
                    if not startup_failed:
                        status, body = copy_host.call('GET', '/v1/networks/' + c.network + '/link-access-versions')
                        need((status == 200) == (value is None), 'storage decoder never coerces, drops or resets malformed retained version',
                             implementation, label, status)
                        if value is None:
                            need(any(row['version'] == 2 ** 64 - 1 for row in body['policies']),
                                 'same copied state and environment positively materialize the retained maximum')
                    with sqlite3.connect(state / 'host.db') as db:
                        if value is not None:
                            retained = db.execute('SELECT version FROM link_highwater WHERE network_id=? AND kind=? AND subject=?',
                                                  (c.network, *subject)).fetchall()
                            need(retained and all(row[0] == value for row in retained),
                                 'malformed-row refusal never silently repairs, resets or deletes its version')
                        need(db.execute('SELECT person_key,device_key,certificate_id FROM link_signers WHERE network_id=?',
                                        (c.network,)).fetchall() == providers,
                             'bad retained mark cannot select a replacement identity or signer')
                    need(copy_host.public_catalog(c.network) == original.public_catalog(c.network),
                         'canonical-storage refusal changes no exact signed public evidence')
                    need(not copy_host.key_file.exists(), 'malformed high-water cannot generate an original-person fallback key')
                finally:
                    copy_host.stop()
                    copy_host.logs.close()
        need(c.access_snapshot(original) == before, 'disposable corrupt-state checks preserve the exact original installed state')
    finally:
        c.runtime.start()
        original.start()


def finish_existing(c, created):
    request_id = created['request_id']
    pending = c.b.pending(request_id)
    if pending['owner_packet_base64'] == '-' and not pending['selection_approved']:
        c.approval(c.a, created, signer='person_root')
    if not c.b.pending(request_id)['selection_approved']:
        c.consent(c.b, created)
    if c.b.pending(request_id)['administrator_packet_base64'] == '-':
        c.same_review_administrator(c.a, created)
    if not c.b.pending(request_id)['commit_approved']:
        c.consent(c.b, created, commit=True)
    c.until(lambda: (view if (view := c.resume(c.b, request_id))['state'] == 'linked' else None), 'recovered atomic result')
    return c.assert_provider(c.b, request_id)


def cli_ceremony(c, cli):
    for host in c.hosts:
        host.cli_binary = str(cli)
    flags = ['--network', c.network, '--expect-person', c.person, '--coordinator',
             f'127.0.0.1:{c.runtime.port}', '--coordinator-key', c.coordinator_key]
    result = c.b.cli_input(['link', *flags])
    need(result.returncode != 0, 'noninteractive incomplete request creation exits nonzero')
    created = public_view(json.loads(result.stdout), display=True)
    c.codes.append(created['display_code'])
    request_id = created['request_id']
    preview = c.a.cli_input(['link', 'approve', '--network', c.network, '--person', c.person_id, '--code-stdin'], created['display_code'] + '\n')
    value = json.loads(preview.stdout)
    need(set(value) == APPROVAL and set(value['review']) == APPROVAL_REVIEW and value['signing_requests'] == [], 'CLI approval preview is strict JSON and signs nothing')
    review = value['review']
    pins = ['--network', c.network, '--person', c.person_id, '--expect-host-key', review['host_public_key'],
            '--expect-device-key', review['device_public_key'], '--code-stdin', '--approve']
    c.runtime.advance(2)
    approved = c.a.cli_input(['link', 'approve', *pins], created['display_code'] + '\n')
    need(set(json.loads(approved.stdout)) == APPROVAL, 'CLI drives only typed external signing requests')
    def review_for(commit=False):
        route = '/v1/link/requests/' + request_id + ('/commit' if commit else '/selection')
        body = {'owner_offer_id': '-', 'network_id': c.network, 'person_public_key': c.person,
                'host_public_key': '-', 'device_public_key': '-', 'approve': False}
        if commit:
            body.update(selection_id='-', administrator_offer_id='-')
        status, value = c.b.call('POST', route, body)
        if status == 409 and value.get('code') == 'proof_required':
            c.resume(c.b, request_id)
            return None
        return checked((status, value))['review']
    selection = c.until(review_for, 'CLI owner offer delivery')
    selected = c.b.cli_input(['link', 'select', request_id, '--owner-offer', selection['owner_offer_id'], '--network', c.network,
                             '--expect-person', c.person, '--expect-host-key', selection['host_public_key'],
                             '--expect-device-key', selection['device_public_key'], '--approve'])
    need(set(json.loads(selected.stdout)) == {'request', 'review'}, 'CLI selection preserves the exact reviewed pins')
    c.runtime.advance(2)
    admitted = c.a.cli_input(['link', 'resume', request_id])
    resumed = json.loads(admitted.stdout)
    public_view(resumed, display='display_code' in resumed)
    final = c.until(lambda: review_for(True), 'CLI administrator delivery')
    commit_flags = ['--owner-offer', final['owner_offer_id'], '--selection', final['selection_id'],
                    '--administrator-offer', final['administrator_offer_id'], '--network', c.network,
                    '--expect-person', c.person, '--expect-host-key', selection['host_public_key'],
                    '--expect-device-key', selection['device_public_key']]
    preview = c.b.cli_input(['link', 'commit', request_id, *commit_flags])
    need(set(json.loads(preview.stdout)) == {'request', 'review'} and not c.b.pending(request_id)['commit_approved'],
         'CLI final preview cannot grant final commit consent')
    c.runtime.advance(2)
    committed = c.b.cli_input(['link', 'commit', request_id, *commit_flags, '--approve'])
    need(set(json.loads(committed.stdout)) == {'request', 'review'}, 'CLI final commit uses strict pinned response')
    c.until(lambda: (view if (view := c.resume(c.b, request_id))['state'] == 'linked' else None), 'CLI locally applied result')
    c.assert_provider(c.b, request_id)
    c.no_secrets()


def recovery(c, barrier_name, replacement):
    host = c.b
    created = None
    if barrier_name not in ('host.request.after_commit', 'host.frame.after_commit'):
        created = c.request(host)
        c.approval(c.a, created, signer='person_root')
        if barrier_name != 'host.selection.after_commit':
            c.consent(host, created)
            c.same_review_administrator(c.a, created)
    operation = ((lambda: c.request(host)) if created is None else
                 (lambda: c.consent(host, created, commit=barrier_name != 'host.selection.after_commit')))
    arm = host.barriers / (barrier_name + '.arm')
    entered = host.barriers / (barrier_name + '.entered')
    arm.write_text('')
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(operation)
        deadline = time.monotonic() + 20
        while not entered.exists() and time.monotonic() < deadline:
            if future.done():
                # A route may return finalizing while a durable worker advances.
                future.result()
            time.sleep(.01)
        need(entered.exists(), 'documented durable host barrier reached', barrier_name)
        request_id = entered.read_text().strip()
        need(request_id.startswith('link_') and len(request_id) == 69, 'barrier stores only a public request ID')
        before = host.pending(request_id)
        with sqlite3.connect(host.state / 'host.db') as db:
            frames = db.execute('SELECT role,writer_key,frame_id,record FROM link_frames WHERE request_id=? ORDER BY role,writer_key,frame_id', (request_id,)).fetchall()
            keys = db.execute('SELECT public_key,length(seed) FROM link_device_keys ORDER BY public_key').fetchall()
            applied = db.execute('SELECT locally_applied FROM link_operations WHERE request_id=?', (request_id,)).fetchall()
        if barrier_name == 'host.result.after_commit':
            need(applied == [(1,)], 'result barrier follows atomic locally-applied operation')
        elif barrier_name == 'host.finalize.after_commit':
            need(not applied and before['commit_approved'] and before['commit_packet_base64'] != '-',
                 'finalize barrier precedes submission and retains exact signed consent')
        host.stop(crash=True)
        arm.unlink()
        try:
            future.result(timeout=5)
        except (OSError, http.client.HTTPException):
            pass
    host.binary = host.cli_binary = str(replacement)
    host.start()
    after = host.pending(request_id)
    for field in ('request_packet_base64', 'request_nonce', 'host_public_key', 'device_public_key',
                  'owner_packet_base64', 'selection_packet_base64', 'commit_packet_base64',
                  'selection_approved', 'commit_approved'):
        if before[field] != '-':
            need(after[field] == before[field], 'cross-language crash recovery preserves exact durable field', barrier_name, field)
    with sqlite3.connect(host.state / 'host.db') as db:
        need(db.execute('SELECT public_key,length(seed) FROM link_device_keys ORDER BY public_key').fetchall() == keys,
             'restart creates no replacement device/person key')
        current = {(role, writer, identity): raw for role, writer, identity, raw in
                   db.execute('SELECT role,writer_key,frame_id,record FROM link_frames WHERE request_id=?', (request_id,))}
    if after['result_packet_base64'] == '-':
        for role, writer, identity, raw in frames:
            need(current.get((role, writer, identity)) == raw, 'unknown publish outcome never reseals an existing frame tuple')
    resumed = c.resume(host, request_id)
    if resumed['state'] != 'linked':
        need('display_code' in resumed, 'explicit still-pending resume returns original resumable code')
        if created is None:
            created = resumed
            c.codes.append(resumed['display_code'])
        else:
            need(resumed['display_code'] == created['display_code'], 'cross-language restart retains the exact private pairing code')
        activation = finish_existing(c, created)
    else:
        activation = c.assert_provider(host, request_id)
    manifest = semantic_id('packet', activation['commit'])
    for _ in range(2):
        need(c.resume(host, request_id)['state'] == 'linked', 'terminal exact resume returns the durable linked outcome')
    with sqlite3.connect(host.state / 'host.db') as db:
        need(db.execute('SELECT manifest_id,locally_applied FROM link_operations WHERE request_id=?', (request_id,)).fetchall() == [(manifest, 1)],
             'repeated recovery has exactly one immutable local application')
    c.no_secrets()


def refuses_state(binary, state, env):
    process = subprocess.Popen([str(binary), '--state', str(state), 'run'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    try:
        process.communicate(timeout=5)
        need(process.returncode != 0, 'unsupported or failed migration refuses state before running')
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise AssertionError('binary opened unsupported or inconsistent state')


def migration(args, directory, implementation):
    directory.mkdir(parents=True)
    runtime = Runtime(args.coordinator, directory / 'coordinator')
    baseline = getattr(args, 'baseline_' + implementation)
    current = getattr(args, implementation)
    host = Host(baseline, baseline, directory / 'host', directory / 'user', runtime)
    try:
        original = host.start()
        agent = host.cli('agent', 'register', '--name', 'preserved-agent', '--owner', 'alice')
        host.stop()
        with sqlite3.connect(host.state / 'host.db') as db:
            need(db.execute('PRAGMA user_version').fetchone()[0] == 18, 'unmodified historical artifact creates schema18')
            broken = directory / 'failed-migration'
            broken.mkdir(mode=0o700)
            with sqlite3.connect(broken / 'host.db') as target:
                db.backup(target)
                target.execute('CREATE TABLE link_features (preexisting_marker TEXT NOT NULL)')
                target.execute("INSERT INTO link_features VALUES ('preserve-on-rollback')")
        (broken / 'host.db').chmod(0o600)
        refuses_state(current, broken, host.daemon_env())
        with sqlite3.connect(broken / 'host.db') as db:
            need(db.execute('PRAGMA user_version').fetchone()[0] == 18 and
                 db.execute('SELECT preexisting_marker FROM link_features').fetchall() == [('preserve-on-rollback',)],
                 'failed schema19 migration rolls back exact prior state')
        host.binary = host.cli_binary = str(current)
        upgraded = host.start()
        need(upgraded['id'] == original['id'] and upgraded['public_key'] == original['public_key'], 'migration preserves exact host identity')
        agents = checked(host.call('GET', '/v1/agents'))
        need(any(value['id'] == agent['id'] and value['name'] == agent['name'] for value in agents), 'migration preserves existing agent metadata')
        with sqlite3.connect(host.state / 'host.db') as db:
            need(db.execute('PRAGMA user_version').fetchone()[0] == SCHEMA_VERSION == 19, 'current schema19')
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            need(set(LINKING_TABLES) <= tables, 'all exact eight schema19 table categories')
        host.stop()
        refuses_state(baseline, host.state, host.daemon_env())
        with sqlite3.connect(host.state / 'host.db') as db:
            db.execute('PRAGMA user_version=20')
        refuses_state(current, host.state, host.daemon_env())
        with sqlite3.connect(host.state / 'host.db') as db:
            need(db.execute('PRAGMA user_version').fetchone()[0] == 20, 'unsupported future schema is untouched')
    finally:
        host.stop()
        host.logs.close()
        runtime.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--coordinator', required=True)
    parser.add_argument('--go', required=True)
    parser.add_argument('--rust', required=True)
    parser.add_argument('--probe')
    parser.add_argument('--work-dir', type=Path, help='retain public fixture databases and logs for explicit failure diagnosis')
    parser.add_argument('--baseline-go', default='/tmp/peerspan-schema18-go-host')
    parser.add_argument('--baseline-rust', default='/tmp/peerspan-schema18-rust-host')
    parser.add_argument('--section', action='append', choices=('migration', 'http-core', 'renewals', 'access', 'highwater', 'chain', 'roles', 'approval-pins', 'root-admin', 'cancellations', 'providers', 'cli', 'recovery'))
    parser.add_argument('--pair', action='append', choices=('go-go', 'go-rust', 'rust-go', 'rust-rust'))
    parser.add_argument('--recovery-initial', action='append', choices=('go', 'rust'),
                        help='select an existing recovery direction for a separate runtime lock slot')
    parser.add_argument('--barrier', action='append', choices=('host.request.after_commit', 'host.frame.after_commit',
                        'host.selection.after_commit', 'host.finalize.after_commit', 'host.result.after_commit'),
                        help='select an existing recovery barrier without changing its assertions')
    args = parser.parse_args()
    if (not args.section or any(section in args.section for section in ('chain', 'access', 'highwater'))) and not args.probe:
        parser.error('--probe is required for the complete chain/provider/peer checks')
    if args.probe:
        set_probe(args.probe)
    failures = 0
    if args.work_dir:
        args.work_dir.mkdir(parents=True, exist_ok=False)
        print('Retaining diagnostic fixtures: ' + str(args.work_dir), flush=True)
    workspace = nullcontext(str(args.work_dir)) if args.work_dir else tempfile.TemporaryDirectory(prefix='peerspan-link-hosts-')
    with workspace as temporary:
        for implementation in ('go', 'rust') if not args.section or 'migration' in args.section else ():
            try:
                migration(args, Path(temporary) / ('migration-' + implementation), implementation)
                print('PASS ' + implementation + ': schema18 migration, exact rollback and old/future refusal', flush=True)
            except Exception:
                failures += 1
                traceback.print_exc()
        for pair in (args.pair or ('go-go', 'go-rust', 'rust-go', 'rust-rust')) if not args.section or any(section in args.section for section in ('chain', 'http-core', 'renewals', 'access', 'highwater')) else ():
            creator, requester = pair.split('-')
            ceremony = None
            try:
                ceremony = Ceremony(args, Path(temporary) / pair, creator, requester)
                full_chain(ceremony)
                if not args.section or 'chain' in args.section or 'renewals' in args.section:
                    renewal_retries_and_reachability(ceremony)
                if not args.section or 'chain' in args.section or 'access' in args.section or 'highwater' in args.section:
                    full_u64_management(ceremony)
                if not args.section or 'chain' in args.section or 'highwater' in args.section:
                    canonical_highwater_copies(ceremony)
                if not args.section or 'chain' in args.section:
                    typed_guards(ceremony)
                print('PASS ' + pair + ': complete original-person A to B to C device chain', flush=True)
            except Exception:
                failures += 1
                print('FAIL ' + pair, file=sys.stderr, flush=True)
                traceback.print_exc()
            finally:
                if ceremony:
                    ceremony.close()
        for pair in (args.pair or ('go-go', 'go-rust', 'rust-go', 'rust-rust')) if not args.section or 'roles' in args.section else ():
            ceremony = None
            try:
                creator, requester = pair.split('-')
                ceremony = Ceremony(args, Path(temporary) / ('roles-' + pair), creator, requester)
                separate_roles(ceremony)
                print('PASS ' + pair + ': nonadministrator owner and independent administrator remain distinct', flush=True)
            except Exception:
                failures += 1
                traceback.print_exc()
            finally:
                if ceremony:
                    ceremony.close()
        for section, function in (('approval-pins', approval_network_pin),
                                  ('root-admin', root_admission_without_owner_role),
                                  ('cancellations', cancellation_and_terminal_retention),
                                  ('providers', checkpoint_provider)):
            if args.section and section not in args.section:
                continue
            for pair in args.pair or ('go-go', 'go-rust', 'rust-go', 'rust-rust'):
                ceremony = None
                try:
                    creator, requester = pair.split('-')
                    ceremony = Ceremony(args, Path(temporary) / (section + '-' + pair), creator, requester)
                    function(ceremony)
                    print('PASS ' + pair + ': ' + section, flush=True)
                except Exception:
                    failures += 1
                    traceback.print_exc()
                finally:
                    if ceremony:
                        ceremony.close()
        for initial, replacement in (('go', 'rust'), ('rust', 'go')) if not args.section or 'recovery' in args.section else ():
            if args.recovery_initial and initial not in args.recovery_initial:
                continue
            for barrier in ('host.request.after_commit', 'host.frame.after_commit', 'host.selection.after_commit',
                            'host.finalize.after_commit', 'host.result.after_commit'):
                if args.barrier and barrier not in args.barrier:
                    continue
                ceremony = None
                try:
                    ceremony = Ceremony(args, Path(temporary) / (initial + '-' + replacement + '-' + barrier), initial, initial)
                    recovery(ceremony, barrier, getattr(args, replacement))
                    print(f'PASS {initial} to {replacement}: {barrier} exact cross-language recovery', flush=True)
                except Exception:
                    failures += 1
                    traceback.print_exc()
                finally:
                    if ceremony:
                        ceremony.close()
        for pair in (args.pair or ('go-go', 'go-rust', 'rust-go', 'rust-rust')) if not args.section or 'cli' in args.section else ():
            ceremony = None
            try:
                cli, daemon = pair.split('-')
                ceremony = Ceremony(args, Path(temporary) / ('cli-' + pair), daemon, daemon)
                cli_ceremony(ceremony, getattr(args, cli))
                print(f'PASS {cli} CLI/{daemon} daemon: exact noninteractive consent and hidden code stdin', flush=True)
            except Exception:
                failures += 1
                traceback.print_exc()
            finally:
                if ceremony:
                    ceremony.close()
    return int(bool(failures))


if __name__ == '__main__':
    sys.exit(main())
