#!/usr/bin/env python3
"""Installed two-fixture participant acceptance, final contract section 3.

Authoring boundary: public contracts, AGENTS.md, and independently authored
conformance sources only. Never imports an eager slim suite or production code.
Install/verification is outside each strict 120-second live-suite subprocess.
HOME stays unchanged. Each host has private XDG configuration and explicit state.

Example (root executes after independent author commits):
  python3 conformance/installed_participants.py --archive RELEASE.tar.gz \
    --sha256 ARCHIVE_SHA256 --probe BUILD/peerspan-peer-probe --suite all

An already installed release can instead use --prefix DIR --host-sha256 SHA.
--work-dir must be a new directory; it retains private logs and first failures.
Public output contains fixed outcomes/counts and hashes, never private payloads.
Existing negative conformance suites remain required separate final-head gates.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback

# Safe shared transport/assertion helpers only; no Suite is constructed here.
sys.path.insert(0, str(Path(__file__).resolve().parent / 'slim'))
from harness import Failure, Result, UnixHTTPConnection, check, rfc3339, wait_for
import installed_participant_support as g

PROJECT = '/v1/onboarding/project-flows'
INVITATIONS = '/v1/onboarding/invitation-flows'
JOINS = '/v1/onboarding/join-flows'
ACCESS = '/v1/onboarding/access-consent'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def private_dir(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def private_json(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as connection:
        connection.bind(('127.0.0.1', 0))
        return connection.getsockname()[1]


class InstalledHost:
    """Real installed daemon, preserving HOME and isolating normal person keys."""
    def __init__(self, suite, name):
        self.suite, self.name = suite, name
        self.root = private_dir(suite.work / name)
        self.config = private_dir(self.root / 'xdg-config')
        self.home = self.root  # fixture compatibility; never assigned to HOME
        self.state = private_dir(self.root / 'host-state')
        self.original = self.config / 'peerspan/person_ed25519'
        self.peer_port = free_port(socket.SOCK_DGRAM)
        self.bootstrap_port = free_port(socket.SOCK_STREAM)
        self.log = self.root / 'daemon.log'
        self.process = None
        self.extra_args, self.extra_env = [], {}
        self.id = self.public_key = None

    @property
    def env(self):
        environment = {key: os.environ[key] for key in ('PATH', 'HOME', 'LANG') if key in os.environ}
        environment.update(XDG_CONFIG_HOME=str(self.config),
                           XDG_STATE_HOME=str(private_dir(self.root / 'xdg-state')),
                           XDG_RUNTIME_DIR=str(private_dir(self.root / 'xdg-runtime')))
        # No inherited SSH agent, test clocks, coordinator, model, or key override.
        environment.update(self.extra_env)
        check(environment.get('HOME') == os.environ.get('HOME'), 'fixture changed HOME')
        return environment

    @property
    def peer_address(self):
        return '127.0.0.1:' + str(self.peer_port)

    def now(self):
        return datetime.now(timezone.utc)

    def start(self):
        check(self.process is None, 'fixture daemon already running')
        descriptor = os.open(self.log, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(descriptor, 'ab') as log:
            self.process = subprocess.Popen([str(self.suite.host_bin), '--state', str(self.state),
                'run', '--peer-listen', self.peer_address, '--bootstrap-listen',
                '127.0.0.1:' + str(self.bootstrap_port), *map(str, self.extra_args),
                '--person-key-file', str(self.root / 'absent-daemon-original')],
                cwd=self.root, stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=self.env)
        def alive():
            check(self.process.poll() is None, 'installed daemon exited during startup')
            try:
                status, value = self.api('GET', '/v1/host', timeout=1)
                return value if status == 200 else None
            except OSError:
                return None
        value = wait_for(alive, timeout=15, interval=.1, message='installed private owner socket')
        self.id, self.public_key = value['id'], value['public_key']
        return self

    def stop(self):
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=1)
        self.process = None

    def api(self, method, path, body=None, timeout=5):
        connection = UnixHTTPConnection(str(self.state / 'admin.sock'), timeout=timeout)
        try:
            raw = None if body is None else g.compact(body)
            connection.request(method, path, body=raw,
                headers={} if raw is None else {'Content-Type': 'application/json'})
            response = connection.getresponse()
            value = response.read(2 * 1024 * 1024 + 1)
            check(len(value) <= 2 * 1024 * 1024, 'owner response exceeds public guided limit')
            return response.status, json.loads(value) if value else None
        finally:
            connection.close()

    def cli(self, *args, input=None, timeout=5):
        result = subprocess.run([str(self.suite.host_bin), '--state', str(self.state), *map(str, args)],
            cwd=self.root, env=self.env, input=(input or '').encode(), capture_output=True, timeout=timeout)
        return Result(list(map(str, args)), result.returncode, result.stdout.decode(errors='replace'),
                      result.stderr.decode(errors='replace'))


class InstalledSuite:
    def __init__(self, prefix, probe, work):
        self.host_bin = prefix / 'bin/peerspan-host'
        self.probe_bin, self.work = probe, work
        self.hosts = []
        self.stage = 'startup'

    def host(self, name, start=False):
        host = InstalledHost(self, name)
        self.hosts.append(host)
        return host.start() if start else host

    def close(self):
        for host in reversed(self.hosts):
            host.stop()


def step(label):
    g.suite.stage = label


def cli_json(host, words, body, timeout=5):
    result = host.cli(*words, '--stdin', input=g.compact(body).decode(), timeout=timeout)
    g.public(result.stdout + result.stderr, *g.shared.get('secrets', []))
    check(result.code == 0 and type(result.json) is dict, 'installed guided CLI action failed')
    return result.json


def create_network(host, label):
    result = host.cli('network', 'create', label, '--as', 'Existing person', timeout=30)
    check(result.code == 0 and type(result.json) is dict, 'installed ordinary network creation failed')
    network = result.json
    check(network['mode'] == 'decentralized' and network['authority']['state'] == 'usable'
          and network['provider']['kind'] == 'device' and network['provider']['scopes'] == 15,
          'creator lacks actual current device15 authority')
    return network


def immutable(value, key, domain, state):
    record = value[key]
    check(record['state'] == state and record['review_id'] == g.digest(domain, record['review']),
          'guided receipt state/digest mismatch')
    return record


def receipt_core(record):
    return record['review_id'], record['review']


def invitation(host, parent, network, person, member, previous=None):
    body = dict(context=g.context(parent), network_id=network['id'], member=member,
                expected_person_public_key=person)
    if previous is not None:
        body['replace_flow_id'] = previous['flow_id']
    prepared = g.api(host, 'POST', INVITATIONS, body, expected=201)
    check(prepared['state'] == 'review' and prepared['invitation'] is None
          and prepared['review_id'] == g.digest('peerspan-invitation-review-v1', prepared['review']),
          'guided invitation preparation lacks exact unapproved review')
    check(prepared['review']['network'] == {k: network[k] for k in ('id', 'name', 'context_id', 'genesis_root_public_key')}
          and prepared['review']['expected_person_public_key'] == person
          and prepared['review']['member'] == member
          and prepared['review']['transport']['helpers'] == [], 'invitation changed exact network/person/transport')
    decision = dict(context=g.context(parent), review_id=prepared['review_id'], decision='approve')
    issued = g.api(host, 'POST', INVITATIONS + '/' + prepared['flow_id'] + '/decision', decision)
    check(issued['state'] == 'issued' and issued['review'] == prepared['review'], 'invitation approval changed terms')
    status, handoff = host.api('POST', INVITATIONS + '/' + prepared['flow_id'] + '/handoff',
        dict(context=g.context(parent), review_id=prepared['review_id']))
    check(status == 200 and handoff['invitation'].startswith('psi2-')
          and handoff['invitation_id'] == issued['invitation']['invitation_id'], 'private authentic invitation handoff failed')
    g.shared['secrets'].append(handoff['invitation'])
    return issued, handoff['invitation']


def request(host, parent, network, code, person):
    preview = g.api(host, 'POST', '/v1/onboarding/invitation-preview',
                    dict(context=g.context(parent), invitation=code))
    check(preview['review_id'] == g.digest('peerspan-invitation-preview-v1', preview['review'])
          and preview['review']['invitation']['expected_person_public_key'] == person
          and preview['review']['invitation']['automatic_return'] is True,
          'recipient private preview lost signature/pin/automatic-return terms')
    before = g.get(host, '/v2/link/requests')
    prepared = g.api(host, 'POST', JOINS,
        dict(context=g.context(parent), invitation=code, person_public_key=person), expected=201)
    check(prepared['state'] == 'review' and prepared['outcome'] is None
          and prepared['review_id'] == g.digest('peerspan-join-review-v1', prepared['review'])
          and prepared['review']['invitation_review_id'] == preview['review_id']
          and g.get(host, '/v2/link/requests') == before, 'unapproved recipient review created a request')
    approved = g.api(host, 'POST', JOINS + '/' + prepared['flow_id'] + '/decision',
        dict(context=g.context(parent), review_id=prepared['review_id'], decision='approve', invitation=code), timeout=30)
    check(approved['state'] == 'requested' and approved['review'] == prepared['review']
          and approved['outcome']['network_id'] == network['id']
          and approved['outcome']['context_id'] == network['context_id']
          and approved['outcome']['person_public_key'] == person, 'exact recipient publication failed')
    return approved


def returned(host, requester, rid, network):
    def received():
        value = next((v for v in g.get(host, '/v2/link/requests') if v['request_id'] == rid), None)
        if value is None:
            return None
        sent = g.saved_request_frame(requester, rid, requester.public_key)
        return value if sent is not None and g.saved_request_frame(host, rid, requester.public_key) == sent else None
    value = wait_for(received, timeout=15, interval=.1, message='genuine automatic return')
    check(value['role'] == 'approver' and value['network_id'] == network['id']
          and value['context_id'] == network['context_id'] and value['owner_offer_id'] == '-',
          'automatic return changed destination or bypassed actual person decision')
    return value


def checkpoint(f, field, state, seconds=15):
    def observed():
        value = g.link_view(f['b'], f['rid'])
        return value if value[field] != '-' and value['state'] == state else None
    return wait_for(observed, timeout=seconds, interval=.1, message='guided retained checkpoint')


def verify_statement(envelope, label):
    sid = g.statement_id(envelope)
    check(envelope['signatures'], 'retained statement has no declared signatures')
    for index, signature in enumerate(envelope['signatures']):
        check(signature['signature'] != '-', 'retained applied statement lacks a required signature')
        message = '\n'.join(('peerspan-decentralized-signature-v1', sid, signature['role'], signature['public_key'])).encode()
        g.verify_signature(signature['format'], signature['public_key'], signature['signature'],
                           message, label + '-' + str(index))
    return sid, json.loads(base64.b64decode(envelope['payload_base64'], validate=True))


def teammate_application(f, host, completed, review):
    """Verify genuine retained transcript and finite P/H/B/D, without writes."""
    operation = g.operation(host, f['rid'])
    check(operation is not None and operation['locally_applied'] == 1, 'participant lacks actual retained operation')
    record = operation['record']
    activation_bytes = base64.b64decode(record['activation_base64'], validate=True)
    activation = json.loads(activation_bytes)
    commit = activation['commit']
    commit_body = json.loads(base64.b64decode(commit['payload_base64'], validate=True))
    manifest_bytes = base64.b64decode(commit_body['manifest_base64'], validate=True)
    manifest = json.loads(manifest_bytes)
    mid = 'dm_' + hashlib.sha256(b'peerspan-decentralized-manifest-v1\n' + hashlib.sha256(manifest_bytes).hexdigest().encode()).hexdigest()
    aid = 'da_' + hashlib.sha256('\n'.join(('peerspan-decentralized-activation-v1', f['network']['context_id'],
        f['rid'], mid, g.packet_id(commit))).encode()).hexdigest()
    check(mid == operation['manifest_id'] == completed['completion']['manifest_id']
          and aid == operation['activation_id'] == completed['completion']['activation_id'], 'actual manifest/activation identity mismatch')
    for key in ('request_packet_id', 'owner_offer_id', 'selection_id', 'administrator_offer_id', 'owner_finalization_id',
                'root_state_id', 'person_lease_id', 'host_lease_id', 'binding_lease_id', 'device_lease_id'):
        check(manifest[key] == review[key], 'retained application substituted reviewed authority dependency')
    for role, ref in (('request', 'request_packet_id'), ('owner', 'owner_offer_id'), ('selection', 'selection_id'),
                      ('administrator', 'administrator_offer_id'), ('owner_finalization', 'owner_finalization_id'), ('commit', None)):
        packet = activation[role]
        check(packet['request_id'] == f['rid'] and packet['role'] == role
              and (ref is None or g.packet_id(packet) == review[ref]), 'retained typed packet identity mismatch')
        message = g.packet_message(packet)
        g.ed25519(packet['writer_host_public_key'], packet['host_signature'], message, host.name + '-' + role + '-host')
        if role in ('request', 'selection', 'commit'):
            check(packet['writer_host_public_key'] == f['b'].public_key
                  and packet['signer_public_key'] == review['device_public_key'], 'requester packet changed owned host/device')
            g.ed25519(review['device_public_key'], packet['device_signature'], message, host.name + '-' + role + '-device')
        else:
            expected = f['network']['root_public_key'] if role == 'administrator' else f['person']
            check(packet['signer_public_key'] == expected, 'packet changed explicitly authorized original/root signer')
            g.verify_signature(packet['authority_signature_format'], expected, packet['authority_signature'], message,
                               host.name + '-' + role + '-authority')
    catalog = json.loads(base64.b64decode(record['catalog_base64'], validate=True))
    by_id, proof_ids = {}, set()
    for item in catalog['objects']:
        raw = base64.b64decode(item['body_base64'], validate=True)
        pid = 'dp_' + hashlib.sha256(('peerspan-decentralized-proof-v1\n' + item['kind'] + '\n' + hashlib.sha256(raw).hexdigest()).encode()).hexdigest()
        check(item['id'] == pid, 'retained authority proof does not bind exact bytes')
        proof_ids.add(pid)
        envelope = json.loads(raw)
        if type(envelope) is dict and {'kind', 'context_id', 'payload_base64', 'signatures'} <= set(envelope):
            by_id[g.statement_id(envelope)] = envelope
    check(set(manifest['proof_ids']) <= proof_ids, 'applied manifest lacks complete retained proof closure')
    for kind, field in (('person_lease', 'person_lease_id'), ('host_lease', 'host_lease_id'),
                        ('binding_lease', 'binding_lease_id'), ('device_lease', 'device_lease_id')):
        envelope = by_id[review[field]]
        sid, body = verify_statement(envelope, host.name + '-' + kind)
        check(sid == review[field] and envelope['kind'] == kind
              and envelope['context_id'] == f['network']['context_id'], 'applied typed authority identity mismatch')
        if kind in ('binding_lease', 'device_lease'):
            subject = body['subject']
            check(body['operation_id'] == f['rid'] and body['not_after'] == review['not_after']
                  and subject['person_public_key'] == f['person'] and subject['host_public_key'] == f['b'].public_key
                  and subject['scopes'] == (2 if kind == 'binding_lease' else 7)
                  and subject['device_public_key'] == ('-' if kind == 'binding_lease' else review['device_public_key']),
                  'actual signed B/D widened reviewed finite powers/identity/lifetime')
    outcome = json.loads(base64.b64decode(record['outcome_packet_base64'], validate=True))
    body = json.loads(base64.b64decode(outcome['payload_base64'], validate=True))
    check(outcome['role'] == 'outcome' and outcome['writer_host_public_key'] == host.public_key
          and body['activation_id'] == aid and body['manifest_id'] == mid
          and body['activation_sha256'] == hashlib.sha256(activation_bytes).hexdigest()
          and body['applied_at'] == record['applied_at'], 'retained outcome lacks actual matching application')
    g.ed25519(host.public_key, outcome['host_signature'], g.packet_message(outcome), host.name + '-outcome')
    pending, secret = g.pending(host, f['rid'])
    check(pending['terminal'] == 'applied' and secret is None, 'actual application did not retire pairing secret')
    members = g.get(host, '/v2/networks/' + f['network']['id'] + '/members')['members']
    target = [m for m in members if m['host_public_key'] == f['b'].public_key]
    check(len(members) == 2 and len(target) == 1 and target[0]['person_public_key'] == f['person']
          and all(target[0][key] == review[key] for key in ('host_lease_id', 'binding_lease_id', 'device_lease_id', 'not_after')),
          'current member differs from actual reviewed application')
    people = g.get(host, '/v2/networks/' + f['network']['id'] + '/persons')['persons']
    check(len(people) == 2 and len([p for p in people if p['person_public_key'] == f['person']
          and p['person_lease_id'] == review['person_lease_id']]) == 1, 'actual admitted person changed reviewed P')
    if host is f['b']:
        provider = g.get(host, '/v2/networks/' + f['network']['id'])['provider']
        check(provider['kind'] == 'device' and provider['scopes'] == 7 and provider['lease_id'] == review['device_lease_id'],
              'new person lacks actual finite device7 provider')


def peer(host, target, method, path, body=None):
    args = [str(g.suite.probe_bin), '--state', str(host.state), '--address', target.counted_peer.address,
            '--alpn', 'peerspan-peer/1', '--method', method, '--path', path]
    if body is not None:
        args.append('--body-stdin')
    result = subprocess.run(args, input=None if body is None else g.compact(body),
                            env=host.env, cwd=host.root, capture_output=True, timeout=15)
    check(result.returncode == 0, 'genuine authenticated public peer transport failed')
    value = json.loads(result.stdout)
    check(type(value) is dict and type(value.get('status')) is int, 'public peer response malformed')
    return value['status'], value.get('body')


def message_enforcement(f, policy, accepted):
    """Bypass sender policy filtering; exercise the real receiver every time."""
    rid = 'request_' + os.urandom(16).hex()
    body = dict(request_id=rid, target_agent_id=f['owner_parent']['review']['agent']['id'],
                deadline=rfc3339(datetime.now(timezone.utc) + timedelta(minutes=2)),
                content='private-installed-fixture-' + os.urandom(16).hex(), policy=policy)
    before = g.get(f['a'], '/v1/messages?limit=1000')
    status, response = peer(f['b'], f['a'], 'POST', '/peer/v1/messages', body)
    messages = g.get(f['a'], '/v1/messages?limit=1000')
    if accepted:
        check(status == 200 and response['request_id'] == rid
              and response['sender_host_id'] == f['b'].id and response['receiver_host_id'] == f['a'].id
              and response['target_agent_id'] == body['target_agent_id']
              and len(messages) == len(before) + 1
              and any(v['request'] == body and v['receipt'] == response for v in messages),
              'receiver failed actual permitted append/retained receipt')
    else:
        check(status == 403 and type(response) is dict and response.get('code') == 'forbidden'
              and messages == before, 'receiver failed actual fresh-message permission denial')


def signed_policy(host, network, person):
    import urllib.parse
    value = g.get(host, '/v2/networks/' + network + '/policy/' + urllib.parse.quote(person, safe=''))
    envelope = json.loads(base64.b64decode(value['statement_base64'], validate=True))
    sid, payload = verify_statement(envelope, 'actual-receiver-policy')
    check(sid == value['statement_id'], 'current policy identity mismatch')
    return payload, json.loads(base64.b64decode(payload['body_base64'], validate=True))


def access_and_enforcement(f):
    step('membership_denied_then_guided_access_then_owner_withdrawal')
    a, b, net = f['a'], f['b'], f['network']['id']
    owner = g.ssh_public_base64(a.original)
    payload, _body = signed_policy(a, net, owner)
    person_id = 'person_' + hashlib.sha256(base64.b64decode(owner, validate=True)).hexdigest()
    citation = dict(person_id=person_id, version=payload['sequence'])
    message_enforcement(f, citation, False)
    key = dict(context=g.context(f['owner_parent']), network_id=net, person_public_key=f['person'])
    inspected = g.api(a, 'POST', '/v1/onboarding/access-inspection', key)
    check(inspected['review_id'] == g.digest('peerspan-project-access-inspection-v1', inspected['review']),
          'access inspection digest mismatch')
    prepared = g.api(a, 'POST', ACCESS + '/prepare', {**key, 'inspection_review_id': inspected['review_id']})
    access = immutable(prepared, 'access', 'peerspan-project-access-consent-v1', 'review')
    check(access['review']['inspection'] == inspected['review'], 'access preparation changed current exact inspection')
    data = {**key, 'access_id': access['access_id'], 'access_review_id': access['review_id']}
    approved = g.api(a, 'POST', ACCESS + '/approve', data)
    check(approved['access']['state'] == 'approved' and receipt_core(approved['access']) == receipt_core(access)
          and approved['access']['access_id'] == access['access_id'], 'access approval changed exact receipt')
    signed = g.api(a, 'POST', ACCESS + '/sign', {**data, 'decision': 'sign_project_agent_access'}, timeout=95)
    check(signed['signing']['state'] == 'signed' and signed['signing']['signature_count'] == 1
          and signed['signing']['policy_application'] == 'not_verified', 'policy signature overclaimed application')
    applied = g.api(a, 'POST', ACCESS + '/apply', {**data, 'decision': 'apply_project_agent_access'}, timeout=95)
    check(applied['application']['state'] == 'locally_applied'
          and all(applied['application'][k] == 'not_verified' for k in ('peer_delivery', 'connection_readiness')),
          'guided exact signed policy was not actually applied')
    payload, body = signed_policy(a, net, owner)
    rules = [r for r in body['rules'] if r['agent'] == f['owner_parent']['review']['agent']['name']]
    principal = 'person:person_' + hashlib.sha256(base64.b64decode(f['person'], validate=True)).hexdigest()
    check(any(principal in r['principals'] and r['actions'] == ['message.append', 'task.submit']
              and r['max_message_bytes'] == 65536 and r['max_artifact_bytes'] == 0 for r in rules),
          'applied policy lacks exact reviewed narrow person/agent profile')
    citation = dict(person_id=person_id, version=payload['sequence'])
    message_enforcement(f, citation, True)
    withdrawn = a.cli('deny', principal, '--agent', f['owner_parent']['review']['agent']['name'], '--network', net, timeout=20)
    check(withdrawn.code == 0 and withdrawn.json['removed'] == 1, 'explicit owner withdrawal failed')
    # Deliberately cite the previously granted version: receiver must enforce
    # its own newest policy even if the sender has not learned the withdrawal.
    message_enforcement(f, citation, False)
    check(g.get(a, '/v1/grants') == [] and g.get(b, '/v1/grants') == [], 'permission check used a manual grant')


def evidence_observations(f):
    key = dict(context=g.context(f['owner_parent']), network_id=f['network']['id'], person_public_key=f['person'])
    ready = g.api(f['a'], 'POST', '/v1/onboarding/readiness', key)
    evidence = ready['readiness']
    check(evidence['adapter_connections'] == [] and all(evidence[k] == 'not_verified'
        for k in ('peer_reachability', 'model_receipt', 'connection_readiness')), 'host membership/enforcement inferred adapter/model readiness')
    observed = g.api(f['a'], 'POST', '/v1/onboarding/reachability', {**key, 'peer_host_id': f['b'].id}, timeout=15)
    result = observed['reachability']
    check(result['peer_host_id'] == f['b'].id and result['peer_host_public_key'] == f['b'].public_key
          and result['result'] == 'authenticated_response' and 200 <= result['http_status'] <= 599
          and all(result[k] == 'not_verified' for k in ('incoming_delivery', 'model_receipt', 'connection_readiness')),
          'explicit outbound peer observation overclaimed agent/model receipt')


def teammate():
    f = g.shared
    step('distinct_people_and_attached_projects')
    a, b = g.host('inviter'), g.host('teammate')
    f.update(a=a, b=b, secrets=[])
    net = create_network(a, 'Installed teammate network')
    pa, pb = g.project(a, 'inviter'), g.project(b, 'teammate')
    created = cli_json(b, ('onboarding', 'join', 'create-identity'),
                       dict(context=g.context(pb), decision='create_new_identity'), timeout=15)
    person = created['identity']['public_key']
    check(created['identity']['sources'] == ['generated'] and person == g.ssh_public_base64(b.original)
          and person != g.ssh_public_base64(a.original) and a.id != b.id, 'fixtures are not two genuine distinct people/hosts')
    originals = {h.name: (sha(h.original), stat.S_IMODE(h.original.stat().st_mode)) for h in (a, b)}
    check(all(mode == 0o600 for _digest, mode in originals.values()), 'original key permissions are not private')
    f.update(network=net, person=person, owner_parent=pa, parent=pb)
    step('pinned_guided_invitation_recipient_review_and_automatic_return')
    first, code = invitation(a, pa, net, person, 'New teammate')
    flow = request(b, pb, net, code, person)
    f.update(flow=flow, rid=flow['outcome']['request_id'])
    returned(a, b, f['rid'], net)

    step('second_invitation_same_endpoint_distinct_request_and_destination')
    second_net = create_network(a, 'Second invitation destination')
    second, second_code = invitation(a, pa, second_net, person, 'Other destination', previous=first)
    second_parent = g.project(b, 'second-destination')
    second_flow = request(b, second_parent, second_net, second_code, person)
    second_rid = second_flow['outcome']['request_id']
    returned(a, b, second_rid, second_net)
    check(first['invitation']['invitation_id'] != second['invitation']['invitation_id'] and second_rid != f['rid']
          and first['review']['transport']['bootstrap_addresses'] == second['review']['transport']['bootstrap_addresses']
          and g.link_view(a, f['rid'])['network_id'] == net['id']
          and g.link_view(a, second_rid)['network_id'] == second_net['id'], 'shared endpoint conflated invitation/request/destination')

    step('exact_original_owner_consent_and_signing')
    base = JOINS + '/' + flow['flow_id']
    body = dict(context=g.context(pb), join_review_id=flow['review_id'])
    prepared = g.api(b, 'POST', base + '/owner/prepare', body)
    owner = immutable(prepared, 'owner', 'peerspan-onboarding-original-owner-review-v1', 'review')
    check(owner['review']['scopes'] == 7 and owner['review']['person_public_key'] == person
          and owner['review']['effects']['auto_select_single_offer_after_signature'] is True
          and owner['review']['effects']['approve_network_administrator'] is False, 'original owner review crossed consent boundaries')
    approved = g.api(b, 'POST', base + '/owner/approve', {**body, 'owner_review_id': owner['review_id']})
    check(approved['owner']['state'] == 'approved' and receipt_core(approved['owner']) == receipt_core(owner), 'original approval changed exact terms')
    signed = cli_json(b, ('onboarding', 'join', 'owner', 'sign'),
        dict(flow_id=flow['flow_id'], **body, owner_review_id=owner['review_id'], decision='sign_original_owner_offer'), timeout=45)
    check(signed['original_signature']['state'] == 'recorded', 'exact original offer signature not retained')
    selected = checkpoint(f, 'selection_id', 'needs_administrator')
    check(selected['selection_approved'] and not selected['commit_approved'] and g.get(b, '/v2/networks') == [],
          'owner/authorized single-offer selection bypassed administrator/requester consent')

    step('incoming_proof_checkpoint_and_exact_administrator_consent')
    incoming_body = dict(context=g.context(pa), request_id=f['rid'])
    progressed = g.api(a, 'POST', '/v1/onboarding/incoming-progress', incoming_body)
    check(progressed['next_action'] == 'review_administrator_consent'
          and progressed['request']['owner_offer_id'] == selected['owner_offer_id']
          and progressed['request']['selection_id'] == selected['selection_id'], 'incoming proof checkpoint changed selected offer')
    inspected = g.api(a, 'POST', '/v1/onboarding/admission-inspection', incoming_body)
    check(inspected['review_id'] == g.digest('peerspan-admission-inspection-v1', inspected['review']),
          'incoming administrator inspection digest mismatch')
    prepared = g.api(a, 'POST', '/v1/onboarding/admission-consent/prepare', incoming_body)
    admission = immutable(prepared, 'admission', 'peerspan-onboarding-original-admission-review-v1', 'review')
    check(admission['review']['person_public_key'] == person and admission['review']['scopes'] == 7
          and admission['review']['owner_offer_id'] == selected['owner_offer_id']
          and admission['review']['selection_id'] == selected['selection_id'], 'administrator review changed exact selected person/powers')
    approved = g.api(a, 'POST', '/v1/onboarding/admission-consent/approve',
        {**incoming_body, 'admission_review_id': admission['review_id']})
    check(approved['admission']['state'] == 'approved' and receipt_core(approved['admission']) == receipt_core(admission),
          'administrator approval changed immutable exact review')
    checkpoint(f, 'administrator_offer_id', 'needs_owner_finalization')

    step('original_finalization_then_separate_requester_commit_completion')
    final_body = {**body, 'owner_review_id': owner['review_id']}
    final = g.api(b, 'POST', base + '/owner/finalization/inspect', final_body)
    check(final['review_id'] == g.digest('peerspan-original-finalization-inspection-v1', final['review'])
          and final['review']['scopes'] == 7 and final['review']['binding_scopes'] == 2,
          'original finalization inspection changed finite powers')
    finalized = cli_json(b, ('onboarding', 'join', 'owner', 'finalization', 'sign'),
        dict(flow_id=flow['flow_id'], **final_body, finalization_review_id=final['review_id'],
             decision='sign_original_finalization'), timeout=95)
    check(finalized['original_finalization']['state'] == 'recorded', 'original F not actually retained')
    checkpoint(f, 'owner_finalization_id', 'needs_commit')
    prepared = g.api(b, 'POST', base + '/commit/prepare', body)
    commit = immutable(prepared, 'commit', 'peerspan-requester-commit-review-v1', 'review')
    approved = g.api(b, 'POST', base + '/commit/approve', {**body, 'commit_review_id': commit['review_id']})
    check(approved['commit']['state'] == 'approved' and receipt_core(approved['commit']) == receipt_core(commit), 'requester approval changed exact review')
    completed = g.api(b, 'POST', base + '/commit/complete',
        {**body, 'commit_review_id': commit['review_id'], 'decision': 'complete_requester_commit'}, timeout=95)
    check(completed['completion']['state'] == 'locally_applied' and completed['request']['state'] == 'linked'
          and completed['commit'] == approved['commit'] and all(completed['completion'][k] == 'not_verified'
              for k in ('participant_delivery', 'agent_access', 'connection_readiness')), 'completion lacked actual application or overclaimed access')
    g.checkpoint(f, lambda values: all(status == 200 and v['state'] == 'linked' for status, v in values.values()),
                 seconds=25, message='both participants actual local application')
    for host in (a, b):
        teammate_application(f, host, completed, commit['review'])
        check(len(g.rows(host, 'SELECT activation_id FROM dec_operations WHERE request_id=?', (f['rid'],))) == 1,
              'teammate duplicated actual local application')
    check(len(g.intent_rows(b, f['rid'], 'owner')) == len(g.intent_rows(b, f['rid'], 'requester_commit')) == 1
          and len(g.intent_rows(a, f['rid'], 'administrator')) == 1,
          'teammate duplicated original, administrator or requester intent')
    access_and_enforcement(f)
    evidence_observations(f)
    check({h.name: (sha(h.original), stat.S_IMODE(h.original.stat().st_mode)) for h in (a, b)} == originals,
          'distinct people original key/hash/mode changed or moved')

    step('unavailable_first_contact_private_manual_fallback')
    third_net = create_network(a, 'Unavailable destination')
    _third, unavailable_code = invitation(a, pa, third_net, person, 'Unavailable teammate', previous=second)
    before = {v['request_id'] for v in g.get(b, '/v2/link/requests')}
    a.stop()
    # This separate diagnostic invokes the documented public join entry point,
    # never imports a reply code or drives an approval. The real unavailable
    # endpoint must produce its own private psl2 fallback in at most one30s pass.
    result = b.cli('join', '--invite-stdin', '--person-key', b.original,
                   input=unavailable_code + '\n', timeout=40)
    check(result.code in (0, 1) and type(result.json) is dict, 'unavailable join failed without public pending outcome')
    fallback = result.json.get('display_code')
    check(type(fallback) is str and fallback.startswith('psl2-'), 'unavailable endpoint failed specified private manual fallback')
    g.shared['secrets'].append(fallback)
    new = [v for v in g.get(b, '/v2/link/requests') if v['request_id'] not in before]
    check(len(new) == 1 and new[0]['network_id'] == third_net['id'] and new[0]['state'] == 'pending'
          and new[0]['completed'] == ['request_created'] and new[0]['owner_offer_id'] == '-'
          and not new[0]['selection_approved'] and not new[0]['commit_approved'],
          'manual fallback claimed connectivity, selected an owner or duplicated the request')
    # It must stay private to the explicit failed-return result.
    g.public(g.get(b, '/v2/link/requests'), fallback, unavailable_code)
    return dict(host_fixtures=2, physical_machines=0, distinct_people=2, invitations_same_endpoint=2,
                distinct_destinations=2, automatic_returns=2, main_applications=2,
                receiver_denials=2, receiver_appends=1, guided_access_grants=1, explicit_withdrawals=1,
                unavailable_manual_fallback=True, adapter_connection=False, incoming_acknowledgment=False,
                receiver_message_receipt=True, outbound_peer_observation=True, model_receipt=False)


def machine():
    step('machine_guided_automatic_return_owner_consent_and_automatic_F')
    g.machine_setup()
    step('machine_one_lost_completion_and_lookup_recovery')
    g.machine_complete()
    step('machine_retained_finite_authority_and_separate_readiness')
    g.machine_current()
    evidence_observations(g.shared)
    return dict(host_fixtures=2, physical_machines=0, distinct_people=1, distinct_host_keys=True,
                distinct_device_keys=True, copied_original_keys=0, finite_device_scopes=7,
                binding_scopes=2, automatic_returns=1, completion_invocations=1, lost_completion_recovered=True,
                main_applications=2, new_agent_grants=0, adapter_connection=False,
                incoming_acknowledgment=False, outbound_peer_observation=True, model_receipt=False)


def worker(args):
    suite = InstalledSuite(args.prefix, args.probe, args.work_dir)
    g.suite, g.shared = suite, {'secrets': []}
    started = time.monotonic()
    try:
        outcome = teammate() if args.suite == 'teammate' else machine()
        suite.close()
        check(time.monotonic() - started <= 120, 'installed live-flow suite exceeded 120 seconds')
        private_json(args.work_dir / 'outcome.json', dict(passed=True, suite=args.suite, evidence=outcome,
                     seconds=round(time.monotonic() - started, 3)))
        return 0
    except BaseException as error:
        with (args.work_dir / 'failure.private.txt').open('w') as stream:
            traceback.print_exc(file=stream)
        private_json(args.work_dir / 'outcome.json', dict(passed=False, suite=args.suite, stage=suite.stage,
                     failure_type=type(error).__name__, seconds=round(time.monotonic() - started, 3)))
        return 1
    finally:
        suite.close()


def install(args, work):
    if args.archive is not None:
        check(args.sha256 is not None and sha(args.archive) == args.sha256.lower(), 'real archive checksum mismatch')
        check(hasattr(tarfile, 'data_filter'), 'safe archive extraction requires supported tarfile data_filter')
        extraction = private_dir(work / 'extraction')
        with tarfile.open(args.archive, 'r:gz') as archive:
            members = archive.getmembers()
            roots = set()
            for member in members:
                path = PurePosixPath(member.name)
                check(path.parts and not path.is_absolute() and '..' not in path.parts, 'unsafe archive path')
                roots.add(path.parts[0])
                if member.issym() or member.islnk():
                    target = PurePosixPath(member.linkname)
                    linked = target if member.islnk() else path.parent / target
                    normalized = PurePosixPath(posixpath.normpath(str(linked)))
                    check(not target.is_absolute() and normalized.parts and normalized.parts[0] == path.parts[0], 'unsafe archive link')
            check(len(roots) == 1, 'release archive must have one named root')
            archive.extractall(extraction, members=members, filter='data')
        prefix = work / 'relocated installed prefix with spaces'
        (extraction / roots.pop()).rename(prefix)
    else:
        prefix = args.prefix
        check(prefix is not None and args.host_sha256 is not None, 'installed prefix requires expected host SHA256')
        check(sha(prefix / 'bin/peerspan-host') == args.host_sha256.lower(), 'installed host checksum mismatch')
    binary = prefix / 'bin/peerspan-host'
    check(binary.is_file() and os.access(binary, os.X_OK), 'installed executable is absent')
    metadata = json.loads((prefix / 'RELEASE.json').read_text())
    check(metadata['implementation'] == 'rust' and metadata['os'] == 'linux', 'expected actual Rust Linux release artifact')
    # Only release metadata and executable hashes are read; no runtime .mjs,
    # native cache formats, implementation source or packaging script is read.
    return prefix, {'host_sha256': sha(binary), 'probe_sha256': sha(args.probe),
                    'archive_sha256': sha(args.archive) if args.archive else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--archive', type=Path)
    source.add_argument('--prefix', type=Path)
    parser.add_argument('--sha256')
    parser.add_argument('--host-sha256')
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--suite', choices=('all', 'teammate', 'machine'), default='all')
    parser.add_argument('--work-dir', type=Path)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.probe = args.probe.resolve()
    if args.prefix:
        args.prefix = args.prefix.resolve()
    if args.archive:
        args.archive = args.archive.resolve()
    os.umask(0o077)
    if args.worker:
        check(args.suite != 'all' and args.work_dir is not None and args.prefix is not None, 'invalid private worker invocation')
        return worker(args)
    if args.work_dir:
        args.work_dir = args.work_dir.resolve()
        args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    else:
        args.work_dir = Path(tempfile.mkdtemp(prefix='peerspan-installed-participants-'))
    prefix, artifacts = install(args, args.work_dir)
    sources = {path.name: sha(path) for path in (Path(__file__), Path(g.__file__),
                Path(__file__).parent / 'slim/harness.py', Path(__file__).parent / 'slim/counted_peer.py')}
    receipts, all_passed = [], True
    for name in ('teammate', 'machine') if args.suite == 'all' else (args.suite,):
        scenario = private_dir(args.work_dir / name)
        command = [sys.executable, str(Path(__file__).resolve()), '--worker', '--prefix', str(prefix),
                   '--probe', str(args.probe), '--suite', name, '--work-dir', str(scenario)]
        logpath = scenario / 'suite.private.log'
        began = time.monotonic()
        with logpath.open('wb') as log:
            process = subprocess.Popen(command, stdout=log, stderr=log, start_new_session=True)
            timed_out = False
            try:
                code = process.wait(timeout=120)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
                code = 1
        if timed_out:
            result = dict(passed=False, suite=name, stage='suite_deadline', failure_type='TimeoutExpired', seconds=120)
        elif (scenario / 'outcome.json').exists():
            result = json.loads((scenario / 'outcome.json').read_text())
        else:
            result = dict(passed=False, suite=name, stage='worker_exit', failure_type='WorkerExit',
                          seconds=round(time.monotonic() - began, 3))
        result['passed'] = bool(result['passed'] and code == 0 and not timed_out)
        result['suite_log_sha256'] = sha(logpath)
        result['daemon_log_sha256'] = sorted(sha(p) for p in scenario.glob('*/daemon.log'))
        if (scenario / 'failure.private.txt').exists():
            result['failure_log_sha256'] = sha(scenario / 'failure.private.txt')
        receipts.append(result)
        print('installed_participants_public=' + json.dumps({**result, **artifacts, 'source_sha256': sources,
            'complete_final_acceptance': False,
            'required_separate_gates': ['unchanged_negative_suites', 'native_terminal', 'upgrade', 'actual_model_receipt']},
            sort_keys=True), flush=True)
        all_passed &= result['passed']
    private_json(args.work_dir / 'receipt.json', dict(artifacts=artifacts, source_sha256=sources, suites=receipts,
        required_separate_gates=['unchanged_negative_suites', 'native_terminal', 'upgrade', 'actual_model_receipt'],
        topology='two isolated host fixtures on one machine; direct loopback TCP/UDP; no helpers/coordinator'))
    return 0 if all_passed else 1


if __name__ == '__main__':
    sys.exit(main())
