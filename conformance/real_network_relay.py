#!/usr/bin/env python3
"""Manual installed R1/R2 protocol qualification on two real public machines.

Root provisions both helpers and scopes direct-peer UDP drops/captures. R1 runs
with helper1 active/helper2 stopped; both pins are configured. Each ceremony and
each work phase has its own120s process bound. Successful R1 keeps only its owned
hosts running and saves private public-proof checkpoints. Root verifies captures,
starts helper2/stops helper1, then supplies the explicit phase gate for R2.

SSH carries owner-local control JSON only. No manual peer pins, coordinator,
original-key transfer, database access, helper authority, clock/lease extension,
firewall change or NAT claim. Native/model evidence is separate. Helper tokens
stay in protected files on each client; this driver never reads their contents.
Public relay-path observations do not replace root's packet/firewall evidence.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import traceback
import urllib.parse

import real_network_participants as r
from real_network_participants import g, i, check, rfc3339

# Extend only the independent owner worker's fixture preflight, not the product.
# Credentials are stat-checked locally, never read or transported by this driver.
TOKEN_CHECK = """    if action == 'prepare':
        for item in payload['transport']['rendezvous'] + payload['transport']['relays']:
            if item['token_file'] == '-':
                continue
            credential = pathlib.Path(item['token_file'])
            assert credential.is_absolute()
            info = credential.lstat()
            assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0, 'unprotected helper credential file'
"""
check(r.OWNER_WORKER.count("    action = payload['action']\n")==1,'independent worker shape changed')
r.OWNER_WORKER = r.OWNER_WORKER.replace("    action = payload['action']\n", "    action = payload['action']\n"+TOKEN_CHECK)


def helper_pins(fleet,credentials=True):
    keys = ('address','public_key','token_file') if credentials else ('address','public_key')
    return sorted(({key:h[key] for key in keys} for h in fleet['helpers']),key=lambda h:(h['address'],h['public_key']))


class RelayEndpoint(r.Endpoint):
    def start(self):
        transport = dict(format=1,advertise_bootstrap=[self.metadata['address']+':'+str(self.bootstrap_port)],
            advertise_quic=[self.peer_address],rendezvous=helper_pins(self.suite.fleet),
            relays=helper_pins(self.suite.fleet),publish_contacts=False)
        observed = self.suite.control(self,'prepare',host_sha256=self.metadata['host_sha256'],
            peer_port=self.peer_port,bootstrap_port=self.bootstrap_port,transport=transport)
        self.prepared = True
        check(observed['machine_id_sha256']==self.metadata['machine_id_sha256'],'machine identity metadata mismatch')
        self.suite.control(self,'start',peer_port=self.peer_port,bootstrap_port=self.bootstrap_port)
        def ready():
            try:
                status,value = self.api('GET','/v1/host',timeout=1)
                return value if status==200 else None
            except (OSError,AssertionError):
                return None
        value = self.suite.wait(ready,15,'private owner socket startup')
        self.id,self.public_key = value['id'],value['public_key']
        check(self.identity()=={'exists':False},'fresh relay fixture acquired an original key')
        return self


class RelayController(r.Controller):
    def __init__(self,fleet,work,kind,port_base):
        self.fleet,self.work,self.stage = fleet,work,'deployment'
        self.deadline = time.monotonic()+120
        self.hosts = [RelayEndpoint(self,side,'relay-'+kind,port_base+offset)
                      for side,offset in (('left',0),('right',2))]
        self.sequence = 0
        self.transport_unavailable = False


def project(host,kind):
    data = dict(project_root=str(host.root/'private-project'),native_session_id='private-relay-'+kind+'-'+host.name,
                integration='claude-code',agent=dict(kind='new',name='rn109-'+host.name,owner='Relay fixture owner'))
    value = g.api(host,'POST',i.PROJECT,data,expected=201)
    check(value['state']=='review' and value['review_id']==g.digest('peerspan-project-review-v1',value['review']),
          'exact addressable project review missing')
    approved = g.api(host,'POST',i.PROJECT+'/'+value['flow_id']+'/decision',
        {**{key:data[key] for key in ('project_root','native_session_id','integration')},'review_id':value['review_id'],'decision':'approve'})
    check(approved['state']=='attached' and approved['review']==value['review'],'project decision changed reviewed terms')
    return approved


def invitation(host,parent,network,person,member):
    data = dict(context=g.context(parent),network_id=network['id'],member=member,expected_person_public_key=person)
    proposed = g.api(host,'POST',i.INVITATIONS,data,expected=201)
    review = proposed['review']
    pins = helper_pins(g.suite.fleet,credentials=False)
    check(proposed['state']=='review' and proposed['invitation'] is None
          and proposed['review_id']==g.digest('peerspan-invitation-review-v1',review)
          and review['network']=={key:network[key] for key in ('id','name','context_id','genesis_root_public_key')}
          and review['expected_person_public_key']==person and review['member']==member
          and review['transport']['helpers']==pins and review['transport']['relays']==pins,
          'invitation changed exact network/person/explicit helper pins')
    key = dict(context=g.context(parent),review_id=proposed['review_id'])
    issued = g.api(host,'POST',i.INVITATIONS+'/'+proposed['flow_id']+'/decision',{**key,'decision':'approve'})
    check(issued['state']=='issued' and issued['review']==review,'invitation approval changed terms')
    status,private = host.api('POST',i.INVITATIONS+'/'+proposed['flow_id']+'/handoff',key)
    check(status==200 and private['invitation'].startswith('psi2-') and private['invitation_id']==issued['invitation']['invitation_id'],
          'authentic private invitation handoff missing')
    g.shared['secrets'].append(private['invitation'])
    return private['invitation']


def setup(kind):
    r.stage('fresh_hosts_addressable_projects_and_reviewed_helpers')
    a,b = [h.start() for h in g.suite.hosts]
    check(a.public_key!=b.public_key and a.id!=b.id,'hosts share identity')
    net = i.create_network(a,'Real relay '+kind)
    pa,pb = project(a,kind),project(b,kind)
    original = a.identity()
    check(original['exists'] and original['mode']==0o600,'creator original storage is not private')
    if kind=='teammate':
        created = i.cli_json(b,('onboarding','join','create-identity'),
            dict(context=g.context(pb),decision='create_new_identity'),timeout=15)
        recipient = b.identity()
        person = created['identity']['public_key']
        check(created['identity']['sources']==['generated'] and recipient['public_key']==person
              and recipient['mode']==0o600 and person!=original['public_key'],'distinct original identities not genuinely local')
        member = 'Relay teammate'
    else:
        recipient,person = {'exists':False},original['public_key']
        people = g.get(a,'/v2/networks/'+net['id']+'/persons')['persons']
        matches = [p for p in people if p['person_public_key']==person]
        check(len(matches)==1,'existing person ambiguous')
        member = matches[0]['member']
    f = dict(a=a,b=b,network=net,person=person,owner_parent=pa,parent=pb,originals=[original,recipient],secrets=[])
    g.shared = f
    if kind=='machine':
        f['policy_before'] = g.get(a,'/v2/networks/'+net['id']+'/policy/'+urllib.parse.quote(person,safe=''))
    code = invitation(a,pa,net,person,member)
    flow = i.request(b,pb,net,code,person)
    f.update(flow=flow,rid=flow['outcome']['request_id'])
    def returned():
        return next((v for v in g.get(a,'/v2/link/requests') if v['request_id']==f['rid']),None)
    incoming = g.suite.wait(returned,20,'genuine pinned automatic return')
    check(incoming['role']=='approver' and incoming['state']=='pending' and incoming['network_id']==net['id']
          and incoming['context_id']==net['context_id'] and incoming['host_public_key']==b.public_key
          and incoming['person_public_key']==person and incoming['owner_offer_id']=='-','automatic return changed consent/pins')
    return f


def verify(f,completed,review,kind):
    a,b,net = f['a'],f['b'],f['network']['id']
    check(completed['completion']['state']=='locally_applied' and completed['request']['state']=='linked'
          and all(completed['completion'][k]=='not_verified' for k in ('participant_delivery','agent_access','connection_readiness')),
          'completion overclaimed readiness or lacks application')
    g.suite.wait(lambda:all(r.view(h,f['rid'])['state']=='linked' for h in (a,b)),25,'both actual host applications')
    end = g.parse_time(r.view(b,f['rid'])['created_at'])+timedelta(days=7)
    if kind=='machine':
        end = min(end,g.parse_time(f['network']['provider']['not_after']))
    check(g.parse_time(review['not_after'])==end,'finite reviewed authority widened or restarted')
    for host in (a,b):
        r.proof(f,host,completed,review,kind)
        check(g.get(host,'/v1/peers')==[],'relay qualification acquired manual transport pins')
        people = g.get(host,'/v2/networks/'+net+'/persons')['persons']
        check(len(people)==(1 if kind=='machine' else 2),'ceremony changed person count')
    check([a.identity(),b.identity()]==f['originals'],'original key custody changed')
    if kind=='machine':
        check(g.get(a,'/v2/networks/'+net+'/policy/'+urllib.parse.quote(f['person'],safe=''))==f['policy_before'],
              'same-person ceremony changed access policy')


def save_checkpoint(path,f,completed,review):
    value = {key:f[key] for key in ('network','person','owner_parent','parent','originals','flow','rid')}
    if 'policy_before' in f:
        value['policy_before'] = f['policy_before']
    value.update(completed=completed,authority_review=review,
                 hosts={h.name:dict(id=h.id,public_key=h.public_key) for h in (f['a'],f['b'])})
    r.private_json(path,value)


def attach(path):
    value = json.loads(path.read_text())
    for host in g.suite.hosts:
        status,actual = host.api('GET','/v1/host')
        expected = value['hosts'][host.name]
        check(status==200 and all(actual[key]==expected[key] for key in ('id','public_key')),'retained host identity changed')
        host.id,host.public_key = actual['id'],actual['public_key']
        host.prepared = True
    f = {key:value[key] for key in ('network','person','owner_parent','parent','originals','flow','rid')}
    if 'policy_before' in value:
        f['policy_before'] = value['policy_before']
    f.update(a=g.suite.hosts[0],b=g.suite.hosts[1],secrets=[])
    g.shared = f
    return f,value['completed'],value['authority_review']


def normalized(request):
    # Public outbound projections use null for an absent grant; peer retained
    # requests may omit absent authorization alternatives. All actual values stay exact.
    return {key:value for key,value in request.items() if key not in ('grant_id','policy','self') or value is not None}


def receiver_messages(host):
    return g.get(host,'/v1/messages?limit=1000')


def assert_append(sender,receiver,outbound,before,content):
    check(outbound['state']=='accepted' and outbound['peer_host_id']==receiver.id and outbound['attempts']>0,
          'normal send lacks actual accepted authenticated attempt')
    receipt,request = outbound['receipt'],outbound['request']
    check(isinstance(receipt,dict) and receipt['sender_host_id']==sender.id and receipt['receiver_host_id']==receiver.id
          and receipt['request_id']==request['request_id'] and receipt['target_agent_id']==request['target_agent_id']
          and request['content']==content,'accepted send receipt/request pins mismatch')
    after = receiver_messages(receiver)
    check(len(after)==len(before)+1 and any(v['receipt']==receipt and normalized(v['request'])==normalized(request) for v in after),
          'actual receiver lacks exact retained append/receipt')


def relay_path(host,target):
    value = g.get(host,'/v1/peers/'+target.id+'/path')
    check(value['host_id']==target.id and value['path']=='relay' and value['endpoint'] is None,
          'actual path is not reported as relay')


def settled(sender,receiver,outbound):
    if outbound['state']!='unknown':
        return outbound
    # Observe only the original durable request and its documented automatic
    # retry schedule. This never submits another command or extends a deadline.
    g.suite.transport_unavailable = True
    rid = outbound['request']['request_id']
    def observed():
        current = g.get(sender,'/v1/outbound/'+receiver.id+'/'+rid)
        check(current['request']==outbound['request'],'automatic recovery changed the original request')
        return current if current['state']!='unknown' else None
    result = g.suite.wait(observed,35,'same persisted request automatic relay delivery')
    g.suite.transport_unavailable = False
    return result


def addressed(f,sender,receiver,parent,kind):
    r.stage('normal_directory_and_addressed_cli_over_reported_relay')
    directory = g.api(sender,'POST','/v1/directory/refresh?network='+f['network']['id'],{},timeout=15)
    agent = parent['review']['agent']
    if any(v['host_id']==receiver.id and v['state'] in ('error','pending') for v in directory['hosts']):
        g.suite.transport_unavailable = True
    matches = [v for v in directory['agents'] if v['host_id']==receiver.id and v['agent_id']==agent['id']]
    check(len(matches)==1 and any(v['kind']==('self' if kind=='machine' else 'policy') for v in matches[0]['authorizations']),
          'normal directory lacks exact target authorization')
    content = 'Private relay qualification '+os.urandom(16).hex()
    before = receiver_messages(receiver)
    result = sender.cli('send',receiver.id+'/'+agent['name'],content,'--network',f['network']['id'],
        '--deadline',rfc3339(datetime.now(timezone.utc)+timedelta(minutes=2)),timeout=30)
    check(result.code==0 and isinstance(result.json,dict),'normal addressed CLI failed')
    outbound = result.json
    check(outbound['request']['target_agent_id']==agent['id'],'address resolved to another agent')
    outbound = settled(sender,receiver,outbound)
    assert_append(sender,receiver,outbound,before,content)
    g.suite.transport_unavailable = False
    relay_path(sender,receiver)
    return outbound['request']['request_id']


def raw_denial(f):
    """No explicit policy/self input; receiver applies its current owner policy."""
    r.stage('actual_receiver_rejection_without_address_prefilter')
    a,b = f['a'],f['b']
    body = dict(peer_host_id=a.id,target_agent_id=f['owner_parent']['review']['agent']['id'],
        request_id='request_'+os.urandom(16).hex(),content='Private relay refusal '+os.urandom(16).hex(),
        deadline=rfc3339(datetime.now(timezone.utc)+timedelta(minutes=2)))
    before = receiver_messages(a)
    status,value = b.api('POST','/v1/outbound',body,timeout=15)
    check(status==200 and isinstance(value,dict),'raw owner send did not return a durable outcome')
    value = settled(b,a,value)
    check(value['state']=='rejected' and value['attempts']>0
          and value['receipt'] is None and value['peer_host_id']==a.id,'owner send lacks actual authenticated receiver rejection')
    request = value['request']
    check(all(request[key]==body[key] for key in ('target_agent_id','request_id','content','deadline'))
          and request.get('grant_id') is None and request.get('self') is None,'raw owner send substituted request/citation kind')
    policy,_ = i.signed_policy(a,f['network']['id'],f['originals'][0]['public_key'])
    owner_id = 'person_'+hashlib.sha256(base64.b64decode(f['originals'][0]['public_key'])).hexdigest()
    citation = request.get('policy')
    check(isinstance(citation,dict) and citation['person_id']==owner_id and type(citation['version']) is int
          and 0<citation['version']<=policy['sequence'],'raw send did not cite the actual receiver owner policy')
    check(receiver_messages(a)==before,'refused fresh work changed receiver history')
    relay_path(b,a)
    # The nullable durable error has no promised structured HTTP status/code.
    return dict(authenticated_rejection=True,exact_peer_status_verified=False,receiving_work_unchanged=True)


def grant_access(f):
    a,net = f['a'],f['network']['id']
    r.stage('exact_guided_narrow_agent_access')
    key = dict(context=g.context(f['owner_parent']),network_id=net,person_public_key=f['person'])
    inspected = g.api(a,'POST','/v1/onboarding/access-inspection',key)
    check(inspected['review_id']==g.digest('peerspan-project-access-inspection-v1',inspected['review']),'access inspection digest')
    prepared = g.api(a,'POST',i.ACCESS+'/prepare',{**key,'inspection_review_id':inspected['review_id']})
    access = i.immutable(prepared,'access','peerspan-project-access-consent-v1','review')
    check(access['review']['inspection']==inspected['review'],'access consent substituted inspection')
    data = {**key,'access_id':access['access_id'],'access_review_id':access['review_id']}
    approved = g.api(a,'POST',i.ACCESS+'/approve',data)
    r.immutable(approved['access'],access)
    check(approved['access']['state']=='approved','exact access approval missing')
    signed = g.api(a,'POST',i.ACCESS+'/sign',{**data,'decision':'sign_project_agent_access'},timeout=95)
    check(signed['signing']['state']=='signed' and signed['signing']['signature_count']==1
          and signed['signing']['policy_application']=='not_verified','access signature overclaimed application')
    applied = g.api(a,'POST',i.ACCESS+'/apply',{**data,'decision':'apply_project_agent_access'},timeout=95)
    check(applied['application']['state']=='locally_applied' and all(applied['application'][k]=='not_verified'
          for k in ('peer_delivery','connection_readiness')),'access application overclaimed delivery')
    _payload,policy = i.signed_policy(a,net,f['originals'][0]['public_key'])
    principal = 'person:person_'+hashlib.sha256(base64.b64decode(f['person'])).hexdigest()
    rules = [v for v in policy['rules'] if v['agent']==f['owner_parent']['review']['agent']['name']]
    check(any(principal in v['principals'] and v['actions']==['message.append','task.submit']
          and v['max_message_bytes']==65536 and v['max_artifact_bytes']==0 for v in rules),'policy differs from narrow reviewed agent profile')
    return principal


def authority_snapshot(f):
    values = {}
    for host in (f['a'],f['b']):
        base = '/v2/networks/'+f['network']['id']
        request = r.view(host,f['rid'])
        values[host.name] = dict(provider=g.get(host,base)['provider'],members=g.get(host,base+'/members'),
            persons=g.get(host,base+'/persons'),request={key:request[key]
                for key in ('request_id','manifest_id','activation_id','state')})
    return values


def receiver_policy(f):
    return g.get(f['a'],'/v2/networks/'+f['network']['id']+'/policy/'+urllib.parse.quote(f['originals'][0]['public_key'],safe=''))


def work(f,kind,replacement):
    check(all(g.get(h,'/v1/peers')==[] and g.get(h,'/v1/grants')==[] for h in (f['a'],f['b'])),
          'relay fixture has manual peers or grants')
    if kind=='machine':
        addressed(f,f['b'],f['a'],f['owner_parent'],kind)
        addressed(f,f['a'],f['b'],f['parent'],kind)
        counts = dict(addressed_appends=2,receiver_rejections=0,guided_grants=0,withdrawals=0)
    elif replacement:
        raw_denial(f)
        counts = dict(addressed_appends=0,receiver_rejections=1,guided_grants=0,withdrawals=0)
    else:
        raw_denial(f)
        principal = grant_access(f)
        addressed(f,f['b'],f['a'],f['owner_parent'],kind)
        r.stage('explicit_owner_policy_withdrawal')
        denied = f['a'].cli('deny',principal,'--agent',f['owner_parent']['review']['agent']['name'],
                            '--network',f['network']['id'],timeout=20)
        check(denied.code==0 and denied.json['removed']==1,'exact owner policy withdrawal missing')
        raw_denial(f)
        counts = dict(addressed_appends=1,receiver_rejections=2,guided_grants=1,withdrawals=1)
    check([f['a'].identity(),f['b'].identity()]==f['originals'],'work changed original-key custody')
    check(all(g.get(h,'/v1/peers')==[] and g.get(h,'/v1/grants')==[] for h in (f['a'],f['b'])),
          'work introduced manual transport pins/grants')
    return dict(**counts,relay_path_reported=True,manual_transport_pins=0,normal_directory_routing=kind=='machine' or not replacement,
        actual_receiver_append_verified=kind=='machine' or not replacement,exact_peer_rejection_status_verified=False,
        adapter_connection=False,native_terminal_receipt=False,model_receipt=False)


def phase_worker(args,fleet):
    os.umask(0o077)
    controller = RelayController(fleet,args.phase_work,args.scenario,args.port_base)
    g.suite,g.shared = controller,{'secrets':[]}
    started = time.monotonic()
    outcome = dict(phase=args.worker,scenario=args.scenario,passed=False,stage='deployment',transport_unavailable=False)
    retain = False
    checkpoint = args.work_dir/(args.scenario+'-checkpoint.private.json')
    try:
        if args.worker=='ceremony':
            f = setup(args.scenario)
            completed,review = r.machine(f) if args.scenario=='machine' else r.teammate(f)
            verify(f,completed,review,args.scenario)
            save_checkpoint(checkpoint,f,completed,review)
            evidence = dict(actual_host_applications=2,signed_public_proof_verified=True,immutable_requester_approval=True,
                finite_device_scopes=7,binding_scopes=2,original_key_transfers=0,manual_transport_pins=0,
                agent_access=False,adapter_connection=False,model_receipt=False)
        else:
            f,completed,review = attach(checkpoint)
            verify(f,completed,review,args.scenario)
            before = authority_snapshot(f)
            if args.worker=='replacement':
                expected = json.loads((args.work_dir/(args.scenario+'-authority.private.json')).read_text())
                check(before==expected['authority'] and receiver_policy(f)==expected['receiver_policy'],
                      'operator replacement changed existing authority or withdrawn policy')
            evidence = work(f,args.scenario,args.worker=='replacement')
            check(authority_snapshot(f)==before,'relay work changed existing authority')
            verify(f,completed,review,args.scenario)
            if args.worker=='work':
                r.private_json(args.work_dir/(args.scenario+'-authority.private.json'),
                               dict(authority=before,receiver_policy=receiver_policy(f)))
            else:
                check(receiver_policy(f)==expected['receiver_policy'],'replacement work changed existing access policy')
        check(time.monotonic()<controller.deadline,'phase exceeded120s')
        outcome.update(passed=True,stage='complete',evidence=evidence)
        retain = args.worker!='replacement'
        return 0
    except BaseException:
        outcome.update(stage=controller.stage,transport_unavailable=controller.transport_unavailable)
        with (args.phase_work/'failure.private.txt').open('w') as stream:
            traceback.print_exc(file=stream)
        return 1
    finally:
        if not retain:
            controller.close()
        outcome['seconds'] = round(time.monotonic()-started,3)
        r.private_json(args.phase_work/'outcome.json',outcome)


def execute(args,kind,phase,offset):
    directory = i.private_dir(args.work_dir/(kind+'-'+phase))
    command = [sys.executable,str(Path(__file__).resolve()),'--fleet',str(args.fleet),'--work-dir',str(args.work_dir),
               '--port-base',str(args.port_base+offset),'--phase',args.phase,'--worker',phase,
               '--scenario',kind,'--phase-work',str(directory)]
    descriptor = os.open(directory/'controller.private.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,'wb') as log:
        child = subprocess.Popen(command,stdout=log,stderr=log,start_new_session=True)
        try:
            code = child.wait(timeout=120)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid,signal.SIGKILL)
            child.wait(timeout=3)
            cleanup = RelayController(json.loads(args.fleet.read_text()),directory,kind,args.port_base+offset)
            for host in cleanup.hosts:
                host.prepared = True
            cleanup.close()
            code = 124
    path = directory/'outcome.json'
    value = json.loads(path.read_text()) if path.exists() else dict(phase=phase,scenario=kind,passed=False,
        stage='deadline' if code==124 else 'controller',transport_unavailable=False)
    if code!=0:
        value['passed'] = False
    logs = sorted([*directory.glob('*.request.json'),*directory.glob('*.response.json')])
    logs += [p for p in (directory/'controller.private.log',directory/'failure.private.txt',path) if p.exists()]
    r.private_json(directory/'evidence-index.private.json',{p.name:i.sha(p) for p in logs})
    value['private_control_evidence_index_sha256'] = i.sha(directory/'evidence-index.private.json')
    return value


def valid_hash(value):
    return isinstance(value,str) and len(value)==64 and all(c in '0123456789abcdef' for c in value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fleet',type=Path,required=True)
    parser.add_argument('--work-dir',type=Path,required=True)
    parser.add_argument('--port-base',type=int,default=27540)
    parser.add_argument('--phase',choices=('r1','r2'),required=True)
    parser.add_argument('--phase-gate',type=Path)
    parser.add_argument('--worker',choices=('ceremony','work','replacement'),help=argparse.SUPPRESS)
    parser.add_argument('--scenario',choices=('machine','teammate'),help=argparse.SUPPRESS)
    parser.add_argument('--phase-work',type=Path,help=argparse.SUPPRESS)
    args = parser.parse_args()
    fleet = json.loads(args.fleet.read_text())
    check(args.fleet.is_absolute() and args.work_dir.is_absolute(),'explicit absolute fleet/work paths required')
    check(1024<=args.port_base<=65528,'invalid dedicated port range')
    check(len(fleet['helpers'])==2,'R1/R2 needs two explicitly configured independent helpers')
    check(len({h['public_key'] for h in fleet['helpers']})==2 and len({h['address'] for h in fleet['helpers']})==2,
          'optional helpers do not have distinct operator identities/endpoints')
    check(valid_hash(fleet['archive_sha256']) and fleet['left']['host_sha256']==fleet['right']['host_sha256']
          and valid_hash(fleet['left']['host_sha256']),'installed release provenance differs')
    check(fleet['left']['machine_id_sha256']!=fleet['right']['machine_id_sha256'],'fleet is not separate machines')
    check(fleet['left']['address']!=fleet['right']['address'],'fleet public endpoints are not distinct')
    for side in ('left','right'):
        check(Path(fleet[side]['root']).is_absolute() and Path(fleet[side]['prefix']).is_absolute(),
              'explicit absolute endpoint roots required')
    for helper in fleet['helpers']:
        check(helper['token_file']=='-' or Path(helper['token_file']).is_absolute(),'helper credential must be an explicit protected local path')
        check(valid_hash(helper['operator']['sha256']),'helper binary provenance hash missing')
    if args.worker:
        check((args.phase=='r2')==(args.worker=='replacement'),'internal phase/worker mismatch')
        return phase_worker(args,fleet)
    os.umask(0o077)
    gate_hash = None
    if args.phase=='r1':
        check(not args.work_dir.exists(),'R1 work directory must be new')
        i.private_dir(args.work_dir)
    else:
        check(args.phase_gate is not None and args.phase_gate.is_absolute(),'R2 requires explicit root phase gate')
        previous = args.work_dir/'r1-receipt.json'
        gate = json.loads(args.phase_gate.read_text())
        check(set(gate)=={'format','r1_receipt_sha256','primary_r1_transport_observed','direct_peer_udp_blocked',
            'primary_stopped','replacement_started','private_capture_index_sha256'} and gate['format']==1
            and gate['r1_receipt_sha256']==i.sha(previous) and json.loads(previous.read_text())['passed'] is True
            and json.loads(previous.read_text())['fleet_sha256']==i.sha(args.fleet)
            and json.loads(previous.read_text())['port_base']==args.port_base
            and all(gate[k] is True for k in ('primary_r1_transport_observed','direct_peer_udp_blocked','primary_stopped','replacement_started'))
            and valid_hash(gate['private_capture_index_sha256']),'R2 operator/capture prerequisites are unverified')
        gate_hash = i.sha(args.phase_gate)
    results = []
    failed = False
    for kind,offset in (('machine',0),('teammate',4)):
        if failed:
            for phase in (('ceremony','work') if args.phase=='r1' else ('replacement',)):
                results.append(dict(phase=phase,scenario=kind,passed=False,stage='not_run_after_first_failure',transport_unavailable=False))
            continue
        if args.phase=='r1':
            ceremony = execute(args,kind,'ceremony',offset)
            results.append(ceremony)
            if ceremony['passed']:
                result = execute(args,kind,'work',offset)
                results.append(result)
                failed = not result['passed']
            else:
                results.append(dict(phase='work',scenario=kind,passed=False,stage='ceremony_prerequisite_failed',transport_unavailable=False))
                failed = True
        else:
            result = execute(args,kind,'replacement',offset)
            results.append(result)
            failed = not result['passed']
    if args.phase=='r2' or not all(v['passed'] for v in results):
        for kind,offset in (('machine',0),('teammate',4)):
            cleanup = RelayController(fleet,i.private_dir(args.work_dir/(kind+'-cleanup')),kind,args.port_base+offset)
            for host in cleanup.hosts:
                host.prepared = True
            cleanup.close()
    sources = {name:i.sha(Path(__file__).parent/name) for name in ('real_network_relay.py','real_network_participants.py',
        'installed_participants.py','installed_participant_support.py','slim/harness.py','slim/counted_peer.py')}
    receipt = dict(format=1,qualification=args.phase+'_protocol_relay_path_observation',passed=all(v['passed'] for v in results),
        separate_machines=True,manual_transport_pins=0,helper_count=2,root_capture_qualification=False,
        requires_operator_capture_confirmation=True,nat_qualification=False,native_terminal_receipt=False,model_receipt=False,
        ssh_control_only=True,original_key_transfers=0,archive_sha256=fleet['archive_sha256'],host_sha256=fleet['left']['host_sha256'],
        fleet_sha256=i.sha(args.fleet),
        helper_sha256=[h['operator']['sha256'] for h in fleet['helpers']],source_sha256=sources,
        helper_public_key_sha256=[hashlib.sha256(base64.b64decode(h['public_key'],validate=True)).hexdigest() for h in fleet['helpers']],
        port_base=args.port_base,
        phase_gate_sha256=gate_hash,results=results,retained_owned_hosts=args.phase=='r1' and all(v['passed'] for v in results))
    r.private_json(args.work_dir/(args.phase+'-receipt.json'),receipt)
    print(json.dumps(receipt,sort_keys=True))
    return 0 if receipt['passed'] else 1


if __name__=='__main__':
    raise SystemExit(main())
