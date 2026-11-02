#!/usr/bin/env python3
"""Manual installed D1 cross-host qualification, authored from public contracts.

No implementation imports, database access, key transfer, peer proxies or tunnels.
SSH carries owner-local orchestration only. The actual installed daemons exchange
protocol/application traffic through their advertised public listeners. This is
host/protocol evidence; native terminal, adapter and model receipt remain separate.

Use the private fleet manifest described by --help. Each scenario has a strict
120s process deadline, excluding archive installation. All control JSON and host
logs remain private. Only fixed outcomes, counts and hashes enter receipt.json.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time
import traceback
import urllib.parse

# These independently authored modules construct no Suite or product on import.
import installed_participants as i
from installed_participants import g, check, Result, rfc3339

# Public Python source is sent in argv; private owner JSON is exclusively stdin.
# This worker has no generic shell/SQL/file-read operation. Original-key metadata
# is computed on its owning machine; the private bytes never leave that machine.
OWNER_WORKER = r'''
import base64, hashlib, http.client, json, os, pathlib, signal, socket, stat, subprocess, sys, time, traceback
class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.unix_path)
def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()
def write(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write('\n')
def run():
    os.umask(0o077)
    payload = json.load(sys.stdin)
    root = pathlib.Path(payload['root'])
    prefix = pathlib.Path(payload['prefix'])
    assert root.is_absolute() and prefix.is_absolute()
    state = root / 'host-state'
    config = root / 'xdg-config'
    binary = prefix / 'bin/peerspan-host'
    env = {key: os.environ[key] for key in ('PATH', 'HOME', 'LANG') if key in os.environ}
    env.update(XDG_CONFIG_HOME=str(config), XDG_STATE_HOME=str(root/'xdg-state'), XDG_RUNTIME_DIR=str(root/'xdg-runtime'))
    action = payload['action']
    if action == 'prepare':
        assert not root.exists(), 'scenario root already exists'
        root.mkdir(mode=0o700, parents=True)
        for directory in ('host-state', 'xdg-config', 'xdg-state', 'xdg-runtime', 'private-project'):
            (root/directory).mkdir(mode=0o700)
        actual = digest(binary)
        assert actual == payload['host_sha256'], 'installed host hash mismatch'
        write(root/'transport.json', payload['transport'])
        write(root/'deployment.private.json', {key:payload[key] for key in ('root','prefix','peer_port','bootstrap_port','transport','host_sha256')})
        return {'host_sha256':actual, 'machine_id_sha256':hashlib.sha256(pathlib.Path('/etc/machine-id').read_bytes()).hexdigest()}
    assert root.is_dir()
    if action == 'start':
        assert not (root/'daemon.pid.json').exists(), 'already started'
        args = [str(binary), '--state', str(state), 'run', '--peer-listen', '0.0.0.0:'+str(payload['peer_port']),
                '--bootstrap-listen', '0.0.0.0:'+str(payload['bootstrap_port']), '--transport-config', str(root/'transport.json'),
                '--person-key-file', str(root/'absent-daemon-original')]
        descriptor = os.open(root/'daemon.log', os.O_WRONLY|os.O_CREAT|os.O_APPEND, 0o600)
        with os.fdopen(descriptor, 'ab') as log:
            child = subprocess.Popen(args, cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        token = pathlib.Path('/proc/'+str(child.pid)+'/stat').read_text().split()[21]
        write(root/'daemon.pid.json', {'pid':child.pid,'start_token':token,'state':str(state),'argv':args})
        return {'started':True}
    if action == 'stop':
        path = root/'daemon.pid.json'
        if not path.exists(): return {'stopped':True}
        saved = json.loads(path.read_text())
        proc = pathlib.Path('/proc/'+str(saved['pid']))
        if proc.exists():
            assert (proc/'stat').read_text().split()[21] == saved['start_token'], 'pid reused'
            argv = (proc/'cmdline').read_bytes().split(b'\0')
            assert str(state).encode() in argv and str(binary).encode() == argv[0], 'not owned fixture'
            os.kill(saved['pid'], signal.SIGTERM)
            until = time.monotonic()+3
            while proc.exists() and time.monotonic()<until:
                if (proc/'stat').read_text().split()[2] == 'Z': break
                time.sleep(.05)
            if proc.exists() and (proc/'stat').read_text().split()[2] != 'Z':
                assert (proc/'stat').read_text().split()[21] == saved['start_token']
                os.kill(saved['pid'], signal.SIGKILL)
        return {'stopped':True}
    if action == 'identity':
        key = config/'peerspan/person_ed25519'
        if not key.exists(): return {'exists':False}
        result = subprocess.run(['ssh-keygen','-y','-f',str(key)], capture_output=True, timeout=5)
        assert result.returncode == 0
        blob = base64.b64decode(result.stdout.split()[1],validate=True)
        n = int.from_bytes(blob[:4],'big')
        assert blob[4:4+n] == b'ssh-ed25519'
        public = blob[8+n:]
        assert len(public) == 32
        return {'exists':True,'mode':stat.S_IMODE(key.stat().st_mode),'sha256':digest(key),'public_key':base64.b64encode(public).decode()}
    timeout = payload.get('timeout',5)
    assert 0 < timeout <= 95
    if action == 'api':
        connection = UnixHTTP('localhost',timeout=timeout)
        connection.unix_path = str(state/'admin.sock')
        raw = None if payload['body'] is None else json.dumps(payload['body'],ensure_ascii=False,separators=(',',':')).encode()
        try:
            connection.request(payload['method'],payload['path'],body=raw,headers={} if raw is None else {'Content-Type':'application/json'})
            response = connection.getresponse()
            body = response.read(20*1024*1024+1)
            assert len(body) <= 20*1024*1024
            return {'status':response.status,'body':json.loads(body) if body else None}
        finally: connection.close()
    if action == 'cli':
        result = subprocess.run([str(binary),'--state',str(state),*payload['args']],input=payload.get('input','').encode(),
                                cwd=root,env=env,capture_output=True,timeout=timeout)
        return {'code':result.returncode,'stdout':result.stdout.decode(errors='replace'),'stderr':result.stderr.decode(errors='replace')}
    raise AssertionError('unknown owner operation')
try:
    print(json.dumps({'ok':True,'value':run()},ensure_ascii=False,separators=(',',':')))
except BaseException:
    print(json.dumps({'ok':False,'traceback':traceback.format_exc()},separators=(',',':')))
    sys.exit(1)
'''


def private_json(path, value):
    i.private_json(path, value)


class Controller:
    def __init__(self, fleet, work, scenario, port_base):
        self.fleet, self.work, self.stage = fleet, work, 'deployment'
        self.deadline = time.monotonic() + 120
        self.hosts = [Endpoint(self, side, scenario, port_base + offset)
                      for side, offset in (('left', 0), ('right', 2))]
        self.sequence = 0

    def control(self, host, action, timeout=5, **body):
        remaining = self.deadline-time.monotonic()
        check(remaining > 0 or action == 'stop', 'ceremony deadline exceeded')
        request = dict(root=str(host.root), prefix=host.metadata['prefix'], action=action, timeout=timeout, **body)
        command = [sys.executable, '-c', OWNER_WORKER]
        if host.metadata.get('ssh'):
            command = ['ssh', *self.fleet.get('ssh_options', []), host.metadata['ssh'],
                       'python3 -c ' + shlex.quote(OWNER_WORKER)]
        self.sequence += 1
        stem = self.work / ('%04d-%s-%s.private' % (self.sequence, host.name, action))
        private_json(stem.with_suffix('.request.json'), request)
        # A few seconds beyond the product bound allows private SSH delivery.
        # The outer 120s process deadline still covers the entire ceremony.
        result = subprocess.run(command, input=g.compact(request), capture_output=True,
                                timeout=min(timeout+10, max(1,remaining)) if action != 'stop' else 10)
        private_json(stem.with_suffix('.response.json'), dict(returncode=result.returncode,
                     stdout=result.stdout.decode(errors='replace'), stderr=result.stderr.decode(errors='replace')))
        check(result.returncode == 0, 'private owner worker failed')
        value = json.loads(result.stdout)
        check(value.get('ok') is True, 'private owner worker rejected operation')
        return value['value']

    def wait(self, predicate, seconds, label):
        until = min(self.deadline, time.monotonic()+seconds)
        while time.monotonic() < until:
            value = predicate()
            if value:
                return value
            time.sleep(.1)
        check(False, label)

    def close(self):
        for host in reversed(self.hosts):
            if host.prepared:
                try:
                    self.control(host, 'stop')
                except BaseException:
                    with (self.work / (host.name+'-cleanup.private.txt')).open('w') as stream:
                        traceback.print_exc(file=stream)


class Endpoint:
    def __init__(self, controller, side, scenario, port):
        self.suite, self.name = controller, side
        self.metadata = controller.fleet[side]
        self.root = Path(self.metadata['root']) / scenario
        self.state = self.root/'host-state'
        self.peer_port, self.bootstrap_port = port, port+1
        self.id = self.public_key = None
        self.prepared = False

    @property
    def peer_address(self):
        return self.metadata['address']+':'+str(self.peer_port)

    def start(self):
        transport = dict(format=1, advertise_bootstrap=[self.metadata['address']+':'+str(self.bootstrap_port)],
                         advertise_quic=[self.peer_address], rendezvous=[], relays=[], publish_contacts=False)
        observation = self.suite.control(self, 'prepare', host_sha256=self.metadata['host_sha256'],
            peer_port=self.peer_port, bootstrap_port=self.bootstrap_port, transport=transport)
        self.prepared = True
        check(observation['machine_id_sha256'] == self.metadata['machine_id_sha256'], 'machine identity metadata mismatch')
        self.suite.control(self,'start',peer_port=self.peer_port,bootstrap_port=self.bootstrap_port)
        def ready():
            try:
                status, value = self.api('GET','/v1/host',timeout=1)
                return value if status == 200 else None
            except (OSError, AssertionError):
                return None
        value = self.suite.wait(ready,15,'private owner socket startup')
        self.id, self.public_key = value['id'], value['public_key']
        check(self.identity() == {'exists':False},'fresh fixture has an original key')
        return self

    def identity(self):
        return self.suite.control(self,'identity')

    def api(self, method, path, body=None, timeout=5):
        value = self.suite.control(self,'api',method=method,path=path,body=body,timeout=timeout)
        return value['status'], value['body']

    def cli(self, *args, input=None, timeout=5):
        value = self.suite.control(self,'cli',args=list(map(str,args)),input=input or '',timeout=timeout)
        return Result(args,value['code'],value['stdout'],value['stderr'])


def stage(label):
    g.suite.stage = label


def view(host, rid):
    return g.get(host,'/v2/link/requests/'+rid)


def checkpoint(f, field, state, seconds=20):
    def observed():
        value = view(f['b'],f['rid'])
        return value if value[field] != '-' and value['state'] == state else None
    return g.suite.wait(observed,seconds,'required guided checkpoint')


def immutable(record, original):
    check(record['review_id'] == original['review_id'] and record['review'] == original['review'],
          'approval replaced exact reviewed terms')


def setup(kind):
    stage('fresh_hosts_and_projects')
    a,b = [host.start() for host in g.suite.hosts]
    check(a.id != b.id and a.public_key != b.public_key,'hosts share identity')
    net = i.create_network(a,'Real direct '+kind)
    pa,pb = g.project(a,'left-'+kind),g.project(b,'right-'+kind)
    original = a.identity()
    check(original['exists'] and original['mode'] == 0o600,'creator original lacks private normal storage')
    if kind == 'teammate':
        created = i.cli_json(b,('onboarding','join','create-identity'),
                            dict(context=g.context(pb),decision='create_new_identity'),timeout=15)
        right_original = b.identity()
        person = created['identity']['public_key']
        check(created['identity']['sources'] == ['generated'] and right_original['public_key'] == person
              and right_original['mode'] == 0o600 and person != original['public_key'],'distinct-person local identity prerequisite')
        member = 'New remote teammate'
    else:
        right_original = {'exists':False}
        person = original['public_key']
        people = g.get(a,'/v2/networks/'+net['id']+'/persons')['persons']
        matching = [p for p in people if p['person_public_key'] == person]
        check(len(matching) == 1,'existing person ambiguous')
        member = matching[0]['member']
    f = dict(a=a,b=b,network=net,person=person,owner_parent=pa,parent=pb,
             originals=[original,right_original],secrets=[])
    if kind == 'machine':
        f['policy_before'] = g.get(a,'/v2/networks/'+net['id']+'/policy/'+urllib.parse.quote(person,safe=''))
    g.shared = f
    stage('invitation_review_request_and_real_return')
    _issued,code = i.invitation(a,pa,net,person,member)
    flow = i.request(b,pb,net,code,person)
    f.update(flow=flow,rid=flow['outcome']['request_id'])
    def returned():
        return next((v for v in g.get(a,'/v2/link/requests') if v['request_id'] == f['rid']),None)
    incoming = g.suite.wait(returned,20,'genuine public automatic request return')
    check(incoming['role'] == 'approver' and incoming['state'] == 'pending'
          and incoming['network_id'] == net['id'] and incoming['context_id'] == net['context_id']
          and incoming['host_public_key'] == b.public_key and incoming['person_public_key'] == person
          and incoming['owner_offer_id'] == '-','returned request changed pin or bypassed owner')
    return f


def machine(f):
    a,b,net = f['a'],f['b'],f['network']
    stage('existing_person_owner_inspection_and_consent')
    body = dict(context=g.context(f['owner_parent']),request_id=f['rid'])
    inspected = g.api(a,'POST','/v1/onboarding/machine-owner-inspection',body)
    review = inspected['review']
    check(inspected['review_id'] == g.digest('peerspan-machine-owner-inspection-v1',review)
          and review['provider'] == net['provider'] and review['provider']['host_public_key'] == a.public_key
          and review['scopes'] == 7 and review['host_admission'] == 'owner_may_fold'
          and review['host_public_key'] == b.public_key and review['person_public_key'] == f['person'],
          'existing owner inspection changed authority/pins/powers')
    prepared = g.api(a,'POST',g.MACHINE+'/prepare',{**body,'inspection_review_id':inspected['review_id']})
    consent = i.immutable(prepared,'consent','peerspan-machine-owner-consent-v1','review')
    action = {**body,'consent_id':consent['consent_id'],'consent_review_id':consent['review_id']}
    approved = g.api(a,'POST',g.MACHINE+'/approve',action)
    immutable(approved['consent'],consent)
    check(approved['consent']['state'] == 'approved','owner consent not approved')
    signing = g.api(a,'POST',g.MACHINE+'/signing',action)
    if signing['signing']['state'] != 'signed':
        check(signing['signing']['can_sign'] is True,'approved owner work cannot sign')
        signing = g.api(a,'POST',g.MACHINE+'/sign',{**action,'decision':'sign_machine_owner_offer'},timeout=95)
    check(signing['signing']['state'] == 'signed','existing owner signature not retained')
    current = checkpoint(f,'owner_finalization_id','needs_commit',30)
    check(current['administrator_offer_id'] == '-' and current['selection_approved']
          and not current['commit_approved'] and g.get(b,'/v2/networks') == [],'automatic F bypassed requester consent')
    stage('machine_requester_inspection_consent_and_one_completion')
    endpoint = i.JOINS+'/'+f['flow']['flow_id']+'/machine-commit'
    key = dict(context=g.context(f['parent']),join_review_id=f['flow']['review_id'])
    inspected = g.api(b,'POST',endpoint+'/inspect',key)
    review = inspected['review']
    check(inspected['review_id'] == g.digest('peerspan-machine-requester-inspection-v1',review)
          and review['scopes'] == 7 and review['binding_scopes'] == 2
          and review['owner_provider'] == net['provider'],'requester inspection changed finite provider authority')
    prepared = g.api(b,'POST',endpoint+'/prepare',{**key,'inspection_review_id':inspected['review_id']})
    consent = i.immutable(prepared,'consent','peerspan-machine-requester-consent-v1','review')
    action = {**key,'consent_review_id':consent['review_id']}
    approved = g.api(b,'POST',endpoint+'/approve',action)
    immutable(approved['consent'],consent)
    check(approved['consent']['state'] == 'approved','machine requester consent not approved')
    completed = g.api(b,'POST',endpoint+'/complete',{**action,'decision':'complete_machine_requester_commit'},timeout=95)
    check(completed['consent'] == approved['consent'],'completion changed immutable requester receipt')
    return completed,review


def teammate(f):
    a,b,flow,person = f['a'],f['b'],f['flow'],f['person']
    endpoint = i.JOINS+'/'+flow['flow_id']
    key = dict(context=g.context(f['parent']),join_review_id=flow['review_id'])
    stage('new_original_owner_consent_and_local_signature')
    prepared = g.api(b,'POST',endpoint+'/owner/prepare',key)
    owner = i.immutable(prepared,'owner','peerspan-onboarding-original-owner-review-v1','review')
    check(owner['review']['scopes'] == 7 and owner['review']['person_public_key'] == person
          and owner['review']['effects']['auto_select_single_offer_after_signature'] is True
          and owner['review']['effects']['approve_network_administrator'] is False,'owner review crossed consent boundaries')
    approved = g.api(b,'POST',endpoint+'/owner/approve',{**key,'owner_review_id':owner['review_id']})
    immutable(approved['owner'],owner)
    check(approved['owner']['state'] == 'approved','original owner approval missing')
    signed = i.cli_json(b,('onboarding','join','owner','sign'),dict(flow_id=flow['flow_id'],**key,
        owner_review_id=owner['review_id'],decision='sign_original_owner_offer'),timeout=45)
    check(signed['original_signature']['state'] == 'recorded','original offer not recorded')
    selected = checkpoint(f,'selection_id','needs_administrator')
    check(selected['selection_approved'] and not selected['commit_approved'] and g.get(b,'/v2/networks') == [],
          'original/selection bypassed administrator/requester')
    stage('incoming_selected_proof_and_administrator_consent')
    incoming = dict(context=g.context(f['owner_parent']),request_id=f['rid'])
    progressed = g.api(a,'POST','/v1/onboarding/incoming-progress',incoming)
    check(progressed['next_action'] == 'review_administrator_consent'
          and progressed['request']['owner_offer_id'] == selected['owner_offer_id']
          and progressed['request']['selection_id'] == selected['selection_id'],'incoming progress changed selected proof')
    inspected = g.api(a,'POST','/v1/onboarding/admission-inspection',incoming)
    check(inspected['review_id'] == g.digest('peerspan-admission-inspection-v1',inspected['review']),'admission inspection digest')
    prepared = g.api(a,'POST','/v1/onboarding/admission-consent/prepare',incoming)
    admission = i.immutable(prepared,'admission','peerspan-onboarding-original-admission-review-v1','review')
    check(admission['review']['person_public_key'] == person and admission['review']['scopes'] == 7
          and admission['review']['owner_offer_id'] == selected['owner_offer_id']
          and admission['review']['selection_id'] == selected['selection_id'],'administrator changed selected pins/powers')
    approved = g.api(a,'POST','/v1/onboarding/admission-consent/approve',{**incoming,'admission_review_id':admission['review_id']})
    immutable(approved['admission'],admission)
    check(approved['admission']['state'] == 'approved','administrator approval missing')
    checkpoint(f,'administrator_offer_id','needs_owner_finalization')
    stage('new_original_finalization_and_requester_commit')
    final_body = {**key,'owner_review_id':owner['review_id']}
    final = g.api(b,'POST',endpoint+'/owner/finalization/inspect',final_body)
    check(final['review_id'] == g.digest('peerspan-original-finalization-inspection-v1',final['review'])
          and final['review']['scopes'] == 7 and final['review']['binding_scopes'] == 2,'finalization widened finite powers')
    signed = i.cli_json(b,('onboarding','join','owner','finalization','sign'),dict(flow_id=flow['flow_id'],**final_body,
        finalization_review_id=final['review_id'],decision='sign_original_finalization'),timeout=95)
    check(signed['original_finalization']['state'] == 'recorded','original finalization not recorded')
    checkpoint(f,'owner_finalization_id','needs_commit')
    prepared = g.api(b,'POST',endpoint+'/commit/prepare',key)
    commit = i.immutable(prepared,'commit','peerspan-requester-commit-review-v1','review')
    action = {**key,'commit_review_id':commit['review_id']}
    approved = g.api(b,'POST',endpoint+'/commit/approve',action)
    immutable(approved['commit'],commit)
    check(approved['commit']['state'] == 'approved','requester approval missing')
    completed = g.api(b,'POST',endpoint+'/commit/complete',{**action,'decision':'complete_requester_commit'},timeout=95)
    check(completed['commit'] == approved['commit'],'completion changed immutable requester commit')
    return completed,commit['review']


def proof(f, host, completed, review, kind):
    """Verify public catalog bytes/signatures, never a database or private secret."""
    catalog = g.get(host,'/v2/networks/'+f['network']['id']+'/catalog')['catalog']
    proofs, statements, activations = set(),{},[]
    for item in catalog['objects']:
        raw = base64.b64decode(item['body_base64'],validate=True)
        pid = 'dp_'+hashlib.sha256(('peerspan-decentralized-proof-v1\n'+item['kind']+'\n'+hashlib.sha256(raw).hexdigest()).encode()).hexdigest()
        check(item['id'] == pid,'public proof does not bind exact bytes')
        proofs.add(pid)
        value = json.loads(raw)
        if item['kind'] == 'activation' and value['request']['request_id'] == f['rid']:
            activations.append(value)
        elif isinstance(value,dict) and {'kind','context_id','payload_base64','signatures'} <= set(value):
            statements[g.statement_id(value)] = value
    check(len(activations) == 1,'public catalog lacks unique actual activation')
    activation = activations[0]
    commit = activation['commit']
    manifest_raw = base64.b64decode(json.loads(base64.b64decode(commit['payload_base64']))['manifest_base64'],validate=True)
    manifest = json.loads(manifest_raw)
    mid = 'dm_'+hashlib.sha256(b'peerspan-decentralized-manifest-v1\n'+hashlib.sha256(manifest_raw).hexdigest().encode()).hexdigest()
    aid = 'da_'+hashlib.sha256('\n'.join(('peerspan-decentralized-activation-v1',f['network']['context_id'],f['rid'],mid,g.packet_id(commit))).encode()).hexdigest()
    check(mid == completed['completion']['manifest_id'] and aid == completed['completion']['activation_id']
          and set(manifest['proof_ids']) <= proofs,'activation/manifest identity or proof closure mismatch')
    check(all(manifest[key] == review[key] for key in ('root_state_id','person_lease_id','host_lease_id','binding_lease_id','device_lease_id')),
          'manifest changed exact reviewed authority dependencies')
    refs = dict(request='request_packet_id',owner='owner_offer_id',selection='selection_id',administrator='administrator_offer_id',owner_finalization='owner_finalization_id')
    for role in ('request','owner','selection','administrator','owner_finalization','commit'):
        packet = activation[role]
        if role == 'administrator' and kind == 'machine':
            check(packet == '-' and manifest['administrator_offer_id'] == '-','folded activation invented administrator')
            continue
        # Wire9.2: the signed request is unbound; its invitation pins are in
        # the request payload. Later stage packets bind the selected context.
        expected_context = '-' if role == 'request' else f['network']['context_id']
        check(packet['role'] == role and packet['request_id'] == f['rid'] and packet['context_id'] == expected_context,
              'typed activation packet changed operation pins')
        if role == 'request':
            check(packet['person_public_key'] == packet['issuer_id'] == '-',
                  'unbound request packet carries selected owner authority')
        message = g.packet_message(packet)
        if role in refs:
            check(g.packet_id(packet) == manifest[refs[role]] == review[refs[role]],'packet differs from exact approved reference')
        g.ed25519(packet['writer_host_public_key'],packet['host_signature'],message,host.name+'-'+role+'-host')
        if role in ('request','selection','commit'):
            check(packet['writer_host_public_key'] == f['b'].public_key and packet['signer_public_key'] == review['device_public_key'],
                  'requester packet changed owned host/device')
            g.ed25519(packet['signer_public_key'],packet['device_signature'],message,host.name+'-'+role+'-device')
        else:
            expected = (f['network']['root_public_key'] if role == 'administrator' else
                        f['network']['provider']['device_public_key'] if kind == 'machine' else f['person'])
            check(packet['signer_public_key'] == expected,'authority packet changed expressly selected signer')
            g.verify_signature(packet['authority_signature_format'],expected,packet['authority_signature'],message,host.name+'-'+role+'-authority')
    for typed,field in (('person_lease','person_lease_id'),('host_lease','host_lease_id'),('binding_lease','binding_lease_id'),('device_lease','device_lease_id')):
        envelope = statements[manifest[field]]
        sid,body = i.verify_statement(envelope,host.name+'-'+typed)
        check(sid == manifest[field] == review[field] and envelope['kind'] == typed,'signed lease differs from reviewed authority')
        if typed in ('binding_lease','device_lease'):
            subject = body['subject']
            check(body['operation_id'] == f['rid'] and body['not_after'] == review['not_after']
                  and subject['person_public_key'] == f['person'] and subject['host_public_key'] == f['b'].public_key
                  and subject['scopes'] == (2 if typed == 'binding_lease' else 7)
                  and subject['device_public_key'] == ('-' if typed == 'binding_lease' else review['device_public_key']),
                  'signed authority widened finite reviewed powers')
    members = g.get(host,'/v2/networks/'+f['network']['id']+'/members')['members']
    target = [m for m in members if m['host_public_key'] == f['b'].public_key]
    check(len(members) == 2 and len(target) == 1 and target[0]['person_public_key'] == f['person']
          and all(target[0][key] == review[key] for key in ('host_lease_id','binding_lease_id','device_lease_id','not_after')),
          'actual current member differs from signed reviewed application')
    current = view(host,f['rid'])
    check(current['state'] == 'linked' and current['manifest_id'] == mid and current['activation_id'] == aid,
          'actual public local application differs from completion')
    if host is f['b']:
        provider = g.get(host,'/v2/networks/'+f['network']['id'])['provider']
        check(provider['kind'] == 'device' and provider['scopes'] == 7 and provider['lease_id'] == review['device_lease_id'],
              'new computer lacks finite device7 provider')


def receiver_message(f, citation, accepted):
    a,b = f['a'],f['b']
    rid = 'request_'+os.urandom(16).hex()
    message = dict(request_id=rid,target_agent_id=f['owner_parent']['review']['agent']['id'],
        deadline=rfc3339(datetime.now(timezone.utc)+timedelta(minutes=2)),
        content='Private real-machine qualification '+os.urandom(16).hex(),policy=citation)
    before = g.get(a,'/v1/messages?limit=1000')
    # Explicit public owner send carries the exact policy citation. The result
    # must prove an authenticated receiver attempt, including on denial.
    status,outbound = b.api('POST','/v1/outbound',dict(peer_host_id=a.id,**message),timeout=15)
    check(status in (200,201,202) and outbound['attempts'] > 0 and outbound['request'] == message,
          'owner send lacks actual immutable network attempt')
    after = g.get(a,'/v1/messages?limit=1000')
    if accepted:
        receipt = outbound['receipt']
        check(outbound['state'] == 'accepted' and isinstance(receipt,dict) and receipt['request_id'] == rid
              and receipt['sender_host_id'] == b.id and receipt['receiver_host_id'] == a.id
              and receipt['target_agent_id'] == message['target_agent_id'] and len(after) == len(before)+1
              and any(v['request'] == message and v['receipt'] == receipt for v in after),
              'receiver lacks actual permitted append and matching receipt')
    else:
        check(outbound['state'] == 'rejected' and outbound['receipt'] is None
              and outbound['error']['code'] == 'forbidden' and after == before,
              'receiver lacks actual forbidden rejection or retained work changed')


def finish(f,completed,review,kind):
    a,b,net = f['a'],f['b'],f['network']['id']
    stage('actual_both_host_application_and_signed_public_proof')
    check(completed['completion']['state'] == 'locally_applied' and completed['request']['state'] == 'linked'
          and all(completed['completion'][key] == 'not_verified' for key in ('participant_delivery','agent_access','connection_readiness')),
          'completion overclaimed readiness or lacks actual application')
    def both():
        values = [view(host,f['rid']) for host in (a,b)]
        return values if all(v['state'] == 'linked' for v in values) else None
    g.suite.wait(both,25,'both actual host applications')
    expected_end = g.parse_time(view(b,f['rid'])['created_at'])+timedelta(days=7)
    if kind == 'machine':
        expected_end = min(expected_end,g.parse_time(f['network']['provider']['not_after']))
    check(g.parse_time(review['not_after']) == expected_end,'finite authority restarted or widened seven-day bound')
    for host in (a,b):
        proof(f,host,completed,review,kind)
        people = g.get(host,'/v2/networks/'+net+'/persons')['persons']
        check(len(people) == (1 if kind == 'machine' else 2),'current person count differs from ceremony')
    # Direct peer pins configure transport only. They neither grant authority
    # nor relay bytes; both endpoints were independently created and verified.
    for host,target in ((a,b),(b,a)):
        g.api(host,'POST','/v1/peers',dict(id=target.id,public_key=target.public_key,address=target.peer_address))
    if kind == 'teammate':
        stage('membership_receiver_denial_guided_access_and_withdrawal')
        owner = f['originals'][0]['public_key']
        payload,_ = i.signed_policy(a,net,owner)
        person_id = 'person_'+hashlib.sha256(base64.b64decode(owner)).hexdigest()
        citation = dict(person_id=person_id,version=payload['sequence'])
        receiver_message(f,citation,False)
        key = dict(context=g.context(f['owner_parent']),network_id=net,person_public_key=f['person'])
        inspected = g.api(a,'POST','/v1/onboarding/access-inspection',key)
        check(inspected['review_id'] == g.digest('peerspan-project-access-inspection-v1',inspected['review']),'access inspection digest')
        prepared = g.api(a,'POST',i.ACCESS+'/prepare',{**key,'inspection_review_id':inspected['review_id']})
        access = i.immutable(prepared,'access','peerspan-project-access-consent-v1','review')
        check(access['review']['inspection'] == inspected['review'],'access review changed inspection')
        action = {**key,'access_id':access['access_id'],'access_review_id':access['review_id']}
        approved = g.api(a,'POST',i.ACCESS+'/approve',action)
        immutable(approved['access'],access)
        check(approved['access']['state'] == 'approved','access consent not approved')
        signed = g.api(a,'POST',i.ACCESS+'/sign',{**action,'decision':'sign_project_agent_access'},timeout=95)
        check(signed['signing']['state'] == 'signed' and signed['signing']['signature_count'] == 1
              and signed['signing']['policy_application'] == 'not_verified','access signing overclaimed application')
        applied = g.api(a,'POST',i.ACCESS+'/apply',{**action,'decision':'apply_project_agent_access'},timeout=95)
        check(applied['application']['state'] == 'locally_applied' and all(applied['application'][k] == 'not_verified'
              for k in ('peer_delivery','connection_readiness')),'access apply overclaimed readiness')
        payload,policy = i.signed_policy(a,net,owner)
        principal = 'person:person_'+hashlib.sha256(base64.b64decode(f['person'])).hexdigest()
        rules = [r for r in policy['rules'] if r['agent'] == f['owner_parent']['review']['agent']['name']]
        check(any(principal in r['principals'] and r['actions'] == ['message.append','task.submit']
                  and r['max_message_bytes'] == 65536 and r['max_artifact_bytes'] == 0 for r in rules),'access policy widened exact narrow grant')
        citation = dict(person_id=person_id,version=payload['sequence'])
        receiver_message(f,citation,True)
        result = a.cli('deny',principal,'--agent',f['owner_parent']['review']['agent']['name'],'--network',net,timeout=20)
        check(result.code == 0 and result.json['removed'] == 1,'explicit owner withdrawal failed')
        receiver_message(f,citation,False) # deliberately stale sender policy
    stage('key_custody_and_readiness_separation')
    check([a.identity(),b.identity()] == f['originals'],'original key metadata changed or copied')
    if kind == 'machine':
        check(g.get(a,'/v2/networks/'+net+'/policy/'+urllib.parse.quote(f['person'],safe='')) == f['policy_before'],
              'same-person linking changed owner agent policy')
    check(g.get(a,'/v1/grants') == [] and g.get(b,'/v1/grants') == [],'fixture used manual grants')
    key = dict(context=g.context(f['owner_parent']),network_id=net,person_public_key=f['person'])
    readiness = g.api(a,'POST','/v1/onboarding/readiness',key)['readiness']
    check(readiness['adapter_connections'] == [] and all(readiness[k] == 'not_verified'
          for k in ('peer_reachability','model_receipt','connection_readiness')),'protocol inferred adapter/model readiness')
    return dict(actual_host_applications=2,finite_device_scopes=7,binding_scopes=2,original_key_transfers=0,
        receiver_denials=2 if kind == 'teammate' else 0,receiver_appends=1 if kind == 'teammate' else 0,
        guided_access_grants=1 if kind == 'teammate' else 0,explicit_withdrawals=1 if kind == 'teammate' else 0,
        signed_public_proof_verified=True,immutable_requester_approval=True,adapter_connection=False,model_receipt=False)


def scenario(args,fleet):
    os.umask(0o077)
    controller = Controller(fleet,args.work_dir,args.scenario,args.port_base)
    g.suite,g.shared = controller,{'secrets':[]}
    started = time.monotonic()
    outcome = dict(scenario=args.scenario,passed=False,stage='deployment')
    try:
        f = setup(args.scenario)
        completed,review = machine(f) if args.scenario == 'machine' else teammate(f)
        evidence = finish(f,completed,review,args.scenario)
        check(time.monotonic() < controller.deadline,'ceremony deadline exceeded')
        outcome.update(passed=True,stage='complete',evidence=evidence)
        return 0
    except BaseException:
        outcome['stage'] = controller.stage
        with (args.work_dir/'failure.private.txt').open('w') as stream:
            traceback.print_exc(file=stream)
        return 1
    finally:
        controller.close()
        outcome['seconds'] = round(time.monotonic()-started,3)
        private_json(args.work_dir/'outcome.json',outcome)


def main():
    parser = argparse.ArgumentParser(description=__doc__,epilog='Fleet JSON: root, archive_sha256, left/right={prefix,root,address,ssh(null for local),host_sha256,machine_id_sha256}; optional ssh_options string array. The roots must be dedicated, and <root>/machine and <root>/teammate must not already exist. The driver edits no firewall, service, HOME or global configuration.')
    parser.add_argument('--fleet',type=Path,required=True)
    parser.add_argument('--work-dir',type=Path,required=True)
    parser.add_argument('--port-base',type=int,default=27440)
    parser.add_argument('--scenario',choices=('machine','teammate'),help=argparse.SUPPRESS)
    args = parser.parse_args()
    fleet = json.loads(args.fleet.read_text())
    check(args.fleet.is_absolute() and args.work_dir.is_absolute(),'explicit absolute fleet/work roots required')
    check(1024 <= args.port_base <= 65528,'invalid dedicated port range')
    check(fleet['left']['machine_id_sha256'] != fleet['right']['machine_id_sha256'],'fleet does not identify separate machines')
    check(fleet['left']['address'] != fleet['right']['address'],'D1 needs distinct public endpoints')
    check(fleet['left']['host_sha256'] == fleet['right']['host_sha256'],'installed binaries differ')
    for key in ('archive_sha256',):
        check(len(fleet[key]) == 64 and all(c in '0123456789abcdef' for c in fleet[key]),'invalid provenance hash')
    for side in ('left','right'):
        endpoint = fleet[side]
        check(Path(endpoint['root']).is_absolute() and Path(endpoint['prefix']).is_absolute(),'explicit endpoint roots required')
        check(endpoint.get('archive_sha256',fleet['archive_sha256']) == fleet['archive_sha256'],'endpoint archive provenance differs')
    if args.scenario:
        return scenario(args,fleet)
    os.umask(0o077)
    check(not args.work_dir.exists(),'work directory must be new')
    i.private_dir(args.work_dir)
    outcomes = []
    for offset,kind in ((0,'machine'),(4,'teammate')):
        work = i.private_dir(args.work_dir/kind)
        command = [sys.executable,str(Path(__file__).resolve()),'--fleet',str(args.fleet),'--work-dir',str(work),
                   '--port-base',str(args.port_base+offset),'--scenario',kind]
        descriptor = os.open(work/'controller.private.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(descriptor,'wb') as log:
            child = subprocess.Popen(command,stdout=log,stderr=log,start_new_session=True)
            try:
                code = child.wait(timeout=120)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid,signal.SIGKILL)
                child.wait(timeout=3)
                cleanup = Controller(fleet,work,kind,args.port_base+offset)
                for host in cleanup.hosts:
                    host.prepared = True
                cleanup.close()
                code = 124
        path = work/'outcome.json'
        outcome = json.loads(path.read_text()) if path.exists() else dict(scenario=kind,passed=False,stage='deadline' if code == 124 else 'controller')
        # Only this driver's fixed category/boolean/count outcomes are published.
        outcomes.append(outcome)
    evidence_indexes = {}
    for kind in ('machine','teammate'):
        work = args.work_dir/kind
        logs = sorted([*work.glob('*.request.json'),*work.glob('*.response.json')])
        logs += [p for p in (work/'controller.private.log',work/'failure.private.txt',work/'outcome.json') if p.exists()]
        index = {p.name:i.sha(p) for p in logs}
        private_json(work/'evidence-index.private.json',index)
        evidence_indexes[kind] = i.sha(work/'evidence-index.private.json')
    sources = {name:i.sha(Path(__file__).parent/name) for name in
               ('real_network_participants.py','installed_participants.py','installed_participant_support.py','slim/harness.py','slim/counted_peer.py')}
    receipt = dict(format=1,qualification='D1',separate_machines=True,independent_public_endpoints=True,
        bare_metal_physical_machines=False,nat_qualification=False,relay_qualification=False,
        native_terminal_receipt=False,model_receipt=False,ssh_control_only=True,
        archive_sha256=fleet['archive_sha256'],host_sha256=fleet['left']['host_sha256'],source_sha256=sources,
        private_control_evidence_index_sha256=evidence_indexes,
        scenarios=outcomes,passed=all(o['passed'] for o in outcomes))
    private_json(args.work_dir/'receipt.json',receipt)
    print(json.dumps(receipt,sort_keys=True))
    return 0 if receipt['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
