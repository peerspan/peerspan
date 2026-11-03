#!/usr/bin/env python3
"""Manual installed managed-cloud N1 protocol/work observation.

Root provisions the actual NAT gateway, private right VM, SSH jump, one pinned
external helper and captures. SSH carries private owner-local control only.
Run fresh machine/teammate ceremonies, then separate 120s work phases on their
proof-verified checkpoints. No manual peers, original-key transfer, database
access, repeated approvals/signing/work, route/firewall changes or model/restart cases.
Only the documented incoming-progress refusal permits one scoped re-observation.
Direct and relay delivery are valid. Path diagnostics establish no readiness or
NAT traversal; root must qualify actual traffic and translation separately.

Usage: --fleet PRIVATE_JSON --work-dir NEW_ABSOLUTE_DIR --port-base 27640
Fleet fields: archive_sha256, ssh_options (argv list), left/right objects with
ssh (null locally), address, prefix, root, host_sha256, machine_id_sha256 (raw
/etc/machine-id bytes), and exactly one helpers entry with address, public_key,
token_file and operator.sha256. Roots and credential paths are explicit/private.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import traceback
import unicodedata

import real_network_relay as q
from real_network_relay import r, g, i, check, rfc3339

# Extend only the independent worker with hashes of its fixed owned daemon log.
# The inherited helper-token preflight stats credentials without reading them.
LOG_HASHES = """    if action == 'log_hashes':
        path = root/'daemon.log'
        if not path.exists():
            return {'daemon_log_sha256':None}
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0
        return {'daemon_log_sha256':digest(path)}
    if action == 'stop' and not root.exists():
        return {'stopped':True}
"""
check(r.OWNER_WORKER.count("    action = payload['action']\n")==1,'independent worker shape changed')
r.OWNER_WORKER = r.OWNER_WORKER.replace("    action = payload['action']\n", "    action = payload['action']\n"+LOG_HASHES)

STAGES = frozenset(('deployment','fresh_hosts_addressable_projects_and_reviewed_helpers',
    'existing_person_owner_inspection_and_consent','machine_requester_inspection_consent_and_one_completion',
    'new_original_owner_consent_and_local_signature','incoming_selected_proof_and_administrator_consent',
    'new_original_finalization_and_requester_commit','normal_directory_and_addressed_cli',
    'actual_receiver_rejection_without_address_prefilter','exact_guided_narrow_agent_access',
    'explicit_owner_policy_withdrawal','path_diagnostics','complete','cleanup','deadline','controller',
    'evidence','ceremony_prerequisite_failed','not_run_after_first_failure','other'))
LOG_NAME = re.compile(r'[0-9]{4}-(?:left|right)-(?:prepare|start|stop|identity|api|cli|log_hashes)\.(?:request|response)\.json')
SOURCES = ('real_network_nat.py','real_network_relay.py','real_network_participants.py',
           'installed_participants.py','installed_participant_support.py','slim/harness.py','slim/counted_peer.py')
PROGRESS = '/v1/onboarding/incoming-progress'
REQUEST_PINS = ('request_id','mode','network_id','context_id','migration_proposal_id','person_public_key',
                'host_public_key','device_public_key','request_packet_id','created_at','expires_at')
LATER_IDS = ('administrator_offer_id','owner_finalization_id','manifest_id','activation_id','outcome_id')
NETWORK_PINS = ('id','name','mode','context_id','genesis_root_public_key','root_state_id','root_public_key','root_epoch','provider')


def progress_counts():
    # Dispatches, received non200 responses, and attempted public revalidations.
    return dict(attempts=0,refusals=0,revalidations=0)


def valid_hash(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None


def absolute(value):
    return type(value) is str and Path(value).is_absolute() and '..' not in Path(value).parts and not any(char in value for char in '\0\r\n')


def unique(pairs):
    result = {}
    for key,value in pairs:
        check(key not in result,'duplicate private configuration field')
        result[key] = value
    return result


def validate_fleet(fleet):
    check(type(fleet) is dict and valid_hash(fleet.get('archive_sha256')),'invalid archive provenance')
    check(type(fleet.get('helpers')) is list and len(fleet['helpers'])==1,'N1 requires one explicitly pinned helper')
    for side in ('left','right'):
        endpoint = fleet.get(side)
        check(type(endpoint) is dict and all(absolute(endpoint.get(key)) for key in ('root','prefix'))
              and endpoint['root'] not in ('/','/root','/tmp') and endpoint['root']!=endpoint['prefix'],
              'invalid dedicated endpoint roots')
        check(valid_hash(endpoint.get('host_sha256')) and valid_hash(endpoint.get('machine_id_sha256'))
              and endpoint.get('archive_sha256',fleet['archive_sha256'])==fleet['archive_sha256'],
              'invalid installed endpoint provenance')
        address = ipaddress.IPv4Address(endpoint['address'])
        check(str(address)==endpoint['address'],'noncanonical actual listener address')
        if side=='left':
            check(address.is_global and endpoint.get('ssh') is None,'left must be the local public workspace')
        else:
            check(any(address in ipaddress.IPv4Network(network) for network in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
                  and type(endpoint.get('ssh')) is str and re.fullmatch(r'[a-z_][a-z0-9_-]*@'+re.escape(str(address)),endpoint['ssh']) is not None,
                  'right must use its actual private IPv4 and owner SSH target')
    check(fleet['left']['host_sha256']==fleet['right']['host_sha256']
          and fleet['left']['machine_id_sha256']!=fleet['right']['machine_id_sha256'],'release or deployment identity mismatch')
    helper = fleet['helpers'][0]
    check(type(helper) is dict and absolute(helper.get('token_file'))
          and type(helper.get('operator')) is dict and valid_hash(helper['operator'].get('sha256')),
          'helper requires protected local credentials and binary provenance')
    address,port = helper['address'].rsplit(':',1)
    check(ipaddress.IPv4Address(address).is_global and str(ipaddress.IPv4Address(address))==address
          and re.fullmatch('[1-9][0-9]{0,4}',port) is not None and 0<int(port)<=65535,
          'helper must be outside the private VPCs at an explicit public endpoint')
    public = base64.b64decode(helper['public_key'],validate=True)
    check(len(public)==32 and base64.b64encode(public).decode()==helper['public_key'],'invalid canonical helper key pin')
    options = fleet.get('ssh_options',[])
    check(type(options) is list and len(options)<=64 and all(type(value) is str and 0<len(value)<=4096
          and not any(char in value for char in '\0\r\n') for value in options),'invalid private SSH options')
    check(not any(value.startswith(('-L','-R','-D','-W')) or any(word in value.lower()
          for word in ('localforward','remoteforward','dynamicforward','proxycommand')) for value in options),
          'SSH options must carry management only')
    normalized = [value.removeprefix('-o').lower() for value in options]
    check('batchmode=yes' in normalized and 'stricthostkeychecking=yes' in normalized,'SSH must use existing pinned noninteractive authentication')
    check('-J' in options or any(value.startswith('proxyjump=') for value in normalized),'private VM requires explicit management ProxyJump')
    # Clear forwarding inherited from SSH configuration; ProxyJump remains the
    # explicit management connection, never a peer data carrier.
    return {**fleet,'ssh_options':['-o','ClearAllForwardings=yes',*options]}


class N1Controller(r.Controller):
    def __init__(self,fleet,work,kind,port_base):
        self.fleet,self.work,self.stage = fleet,work,'deployment'
        self.deadline = time.monotonic()+120
        self.hosts = [q.RelayEndpoint(self,side,'n1-'+kind,port_base+offset) for side,offset in (('left',0),('right',2))]
        self.sequence,self.transport_unavailable = 0,False
        self.daemon_logs = {}
        self.progress = progress_counts()

    def log_hashes(self):
        for host in self.hosts:
            if host.prepared:
                value = self.control(host,'log_hashes')
                check(set(value)=={'daemon_log_sha256'} and (value['daemon_log_sha256'] is None
                      or valid_hash(value['daemon_log_sha256'])),'invalid owned daemon log hash')
                if value['daemon_log_sha256'] is not None:
                    self.daemon_logs[host.name] = value['daemon_log_sha256']

    def close(self):
        complete = True
        for host in reversed(self.hosts):
            if host.prepared:
                try:
                    check(self.control(host,'stop')=={'stopped':True},'owned fixture stop was not confirmed')
                except BaseException:
                    complete = False
                    with (self.work/(host.name+'-cleanup.private.txt')).open('w') as output:
                        traceback.print_exc(file=output)
        return complete


def invitation(host,parent,network,person,member):
    """Review the actual listener hints as well as the sole helper's two pins."""
    data = dict(context=g.context(parent),network_id=network['id'],member=member,expected_person_public_key=person)
    proposed = g.api(host,'POST',i.INVITATIONS,data,expected=201)
    review = proposed['review']
    pins = q.helper_pins(g.suite.fleet,credentials=False)
    transport = dict(bootstrap_addresses=[host.metadata['address']+':'+str(host.bootstrap_port)],
                     quic_addresses=[host.peer_address],helpers=pins,relays=pins)
    check(proposed['state']=='review' and proposed['invitation'] is None
          and proposed['review_id']==g.digest('peerspan-invitation-review-v1',review)
          and review['network']=={key:network[key] for key in ('id','name','context_id','genesis_root_public_key')}
          and review['expected_person_public_key']==person and review['member']==member
          and review['transport']==transport,'invitation changed exact terms, actual listener hints or helper pins')
    key = dict(context=g.context(parent),review_id=proposed['review_id'])
    issued = g.api(host,'POST',i.INVITATIONS+'/'+proposed['flow_id']+'/decision',{**key,'decision':'approve'})
    check(issued['state']=='issued' and issued['review']==review,'invitation approval changed terms')
    status,private = host.api('POST',i.INVITATIONS+'/'+proposed['flow_id']+'/handoff',key)
    check(status==200 and private['invitation'].startswith('psi2-')
          and private['invitation_id']==issued['invitation']['invitation_id'],'authentic private invitation handoff missing')
    g.shared['secrets'].append(private['invitation'])
    return private['invitation']


def verify(f,completed,review,kind):
    q.verify(f,completed,review,kind)
    branch,field = ('machine-commit','consent') if kind=='machine' else ('commit','commit')
    current = g.api(f['b'],'POST',i.JOINS+'/'+f['flow']['flow_id']+'/'+branch+'/lookup',
                    dict(context=g.context(f['parent']),join_review_id=f['flow']['review_id']))
    check(current[field]==completed[field],'retained exact requester consent changed')


def progress_snapshot(f):
    """Existing public reads only; no prepare, import, resume or private state."""
    a,b = f['a'],f['b']
    result = dict(hosts={},projects={},requests={})
    for host,parent,role in ((a,f['owner_parent'],'approver'),(b,f['parent'],'requester')):
        identity = g.get(host,'/v1/host')
        check(type(identity) is dict and set(identity)=={'id','public_key','created_at'}
              and identity['id']==host.id and identity['public_key']==host.public_key,'progress host identity changed')
        result['hosts'][host.name] = identity
        context = {key:parent['review'][key] for key in ('project_root','native_session_id','integration')}
        current = g.api(host,'POST',i.PROJECT+'/lookup',context)
        check(type(current) is dict and set(current)=={'version','host_id','context','flow','agents'}
              and type(current['version']) is int and current['version']==1 and current['host_id']==host.id
              and current['context']==context and type(current['agents']) is list,'invalid current project lookup')
        flow = current['flow']
        check(type(flow) is dict and set(flow)==set(parent) and flow['state']=='attached'
              and flow==parent and flow['review_id']==g.digest('peerspan-project-review-v1',flow['review']),
              'latest attached project changed')
        matches = [value for value in current['agents'] if type(value) is dict and value.get('id')==parent['review']['agent']['id']]
        check(len(matches)==1 and set(matches[0])=={'id','name','owner','capabilities','created_at'}
              and {key:matches[0][key] for key in ('id','name','owner','capabilities')}==parent['review']['agent'],
              'attached agent metadata changed')
        result['projects'][host.name] = dict(flow=flow,agent=matches[0])
        request = g.link_view(host,f['rid'])
        check(request['role']==role and request['mode']=='new' and request['migration_proposal_id']=='-'
              and request['request_id']==f['rid'] and request['network_id']==f['network']['id']
              and request['context_id']==f['network']['context_id'] and request['person_public_key']==f['person']
              and request['host_public_key']==b.public_key and request['commit_approved'] is False
              and all(request[key]=='-' for key in LATER_IDS),'progress request is outside the original eligible scope')
        check(request['state'] in (('pending','needs_selection','needs_administrator') if role=='approver' else ('needs_administrator',))
              and request['selection_approved'] is (role=='requester'),'progress request stage or local consent changed')
        for key in ('created_at','expires_at'):
            check(type(request[key]) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ',request[key]) is not None,
                  'noncanonical original request time')
        check(g.parse_time(request['expires_at'])==g.parse_time(request['created_at'])+timedelta(seconds=3600)
              and datetime.now(timezone.utc)<g.parse_time(request['expires_at']),'original request expired or changed lifetime')
        result['requests'][host.name] = request
    ar,br = result['requests']['left'],result['requests']['right']
    check(all(ar[key]==br[key] for key in REQUEST_PINS) and br['owner_offer_id']!='-' and br['selection_id']!='-',
          'participant request or selected proof pins disagree')
    check(all(ar[key] in ('-',br[key]) for key in ('owner_offer_id','selection_id'))
          and (ar['selection_id']=='-' or ar['owner_offer_id']==br['owner_offer_id']),'administrator retained another selected prefix')
    network = g.get(a,'/v2/networks/'+f['network']['id'])
    check(type(network) is dict and set(network)==set(f['network'])
          and network['root_state_id']!='-' and network['root_public_key']!='-'
          and all(network[key]==f['network'][key] for key in NETWORK_PINS),'original network descriptor/root/provider changed')
    result['network'] = {key:network[key] for key in NETWORK_PINS}
    people = g.get(a,'/v2/networks/'+f['network']['id']+'/persons')
    check(type(people) is dict and set(people)=={'context_id','persons'} and people['context_id']==f['network']['context_id']
          and type(people['persons']) is list and all(type(value) is dict and value.get('person_public_key')!=f['person']
          for value in people['persons']),'target person already adopted or malformed person observation')
    result['persons'] = people
    context = g.context(f['parent'])
    joined = g.api(b,'POST',i.JOINS+'/lookup',dict(context=context))
    check(type(joined) is dict and set(joined)=={'version','host_id','context','flow'}
          and type(joined['version']) is int and joined['version']==1 and joined['host_id']==b.id
          and joined['context']==context and joined['flow']==f['flow'] and joined['flow']['state']=='requested',
          'requester join flow or immutable outcome changed')
    result['join'] = joined
    owner = g.api(b,'POST',i.JOINS+'/'+f['flow']['flow_id']+'/owner/lookup',
                  dict(context=context,join_review_id=f['flow']['review_id']))
    check(type(owner) is dict and set(owner)=={'version','host_id','flow_id','join_review_id','context','observed_at','request','owner'}
          and type(owner['version']) is int and owner['version']==1 and owner['host_id']==b.id and owner['flow_id']==f['flow']['flow_id']
          and owner['join_review_id']==f['flow']['review_id'] and owner['context']==context
          and type(owner['request']) is dict and set(owner['request'])==g.LINK
          and all(owner['request'][key]==br[key] for key in
                  (*REQUEST_PINS,'role','state','owner_offer_id','selection_id','selection_approved','commit_approved',*LATER_IDS)),
          'requester owner lookup changed scope')
    receipt = i.immutable(owner,'owner','peerspan-onboarding-original-owner-review-v1','approved')
    review = receipt['review']
    check(set(receipt)=={'review_id','review','state','next_action'}
          and review['kind']=='approve_new_original_owner' and type(review['version']) is int and review['version']==1 and review['host_id']==b.id
          and review['context']==context and review['flow_id']==f['flow']['flow_id']
          and review['join_review_id']==f['flow']['review_id'] and review['request_id']==f['rid']
          and review['network']=={key:f['network'][key] for key in ('id','name','context_id','genesis_root_public_key')}
          and all(review[key]==br[key] for key in ('person_public_key','host_public_key','device_public_key'))
          and review['member']==f['flow']['review']['invitation']['invitation']['member']
          and review['proposed_owner_offer_id']==br['owner_offer_id'] and review['scopes']==7
          and g.parse_time(review['not_after'])==g.parse_time(br['created_at'])+timedelta(days=7),
          'approved original owner terms changed')
    result['owner'] = receipt
    consent = g.api(a,'POST','/v1/onboarding/admission-consent/lookup',
                    dict(context=g.context(f['owner_parent']),request_id=f['rid']))
    check(type(consent) is dict and set(consent)=={'version','host_id','context','observed_at','request','admission'}
          and type(consent['version']) is int and consent['version']==1 and consent['host_id']==a.id
          and consent['context']==g.context(f['owner_parent']) and type(consent['request']) is dict
          and set(consent['request'])==g.LINK and consent['admission'] is None
          and all(consent['request'][key]==ar[key] for key in REQUEST_PINS)
          and all(consent['request'][key]=='-' for key in LATER_IDS)
          and consent['request']['selection_approved'] is False and consent['request']['commit_approved'] is False,
          'administrator consent appeared or changed request scope')
    check(consent['request']['role']=='approver' and consent['request']['state'] in ('pending','needs_selection','needs_administrator')
          and all(consent['request'][key] in ('-',br[key]) and (ar[key]=='-' or consent['request'][key]==ar[key])
                  for key in ('owner_offer_id','selection_id')),'administrator prefix changed during observation')
    result['requests']['left'] = consent['request']
    return result


def same_progress_scope(before,after):
    for key in ('hosts','projects','network','persons','join','owner'):
        check(after[key]==before[key],'public progress revalidation changed frozen scope')
    for side in ('left','right'):
        old,new = before['requests'][side],after['requests'][side]
        check(all(old[key]==new[key] for key in REQUEST_PINS),'public progress revalidation changed immutable request')
        for key in ('owner_offer_id','selection_id'):
            expected = before['requests']['right'][key]
            check(new[key]==expected if side=='right' or old[key]!='-' else new[key] in ('-',expected),
                  'public progress revalidation replaced or regressed selected prefix')


def install_progress_observation(f):
    """Wrap exactly one original teammate call; its success assertions remain."""
    original = f['a'].api
    def exact_success(value,baseline,incoming):
        check(type(value) is dict and set(value)=={'version','host_id','context','observed_at','request','next_action'}
              and type(value['version']) is int and value['version']==1 and value['host_id']==f['a'].id
              and value['context']==incoming['context'] and type(value['observed_at']) is str
              and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ',value['observed_at']) is not None
              and type(value['request']) is dict and set(value['request'])==g.LINK,'malformed progress success')
        request,expected = value['request'],baseline['requests']['right']
        check(value['next_action']=='review_administrator_consent' and request['role']=='approver'
              and request['state']=='needs_administrator' and request['selection_approved'] is False
              and request['commit_approved'] is False and all(request[key]=='-' for key in LATER_IDS)
              and all(request[key]==expected[key] for key in (*REQUEST_PINS,'owner_offer_id','selection_id')),
              'progress success changed frozen selected proof')
    def observed(method,path,body=None,timeout=5):
        if method!='POST' or path!=PROGRESS:
            return original(method,path,body,timeout=timeout)
        counts = g.suite.progress
        incoming = dict(context=g.context(f['owner_parent']),request_id=f['rid'])
        check(body==incoming and timeout==5 and counts==progress_counts(),'unexpected or repeated progress sequence')
        baseline = progress_snapshot(f)
        r.private_json(g.suite.work/'incoming-progress-baseline.private.json',baseline)
        counts['attempts'] = 1
        status,value = original('POST',PROGRESS,incoming,timeout=5)
        g.public(value,*g.shared.get('secrets',[]))
        if status==200:
            exact_success(value,baseline,incoming)
            return status,value
        counts['refusals'] = 1
        if not (status==409 and type(value) is dict and value.get('code')=='review_changed'
                and type(value.get('error')) is str and 0<len(value['error'])<=4096
                and not any(unicodedata.category(char).startswith('C') for char in value['error'])
                and set(value)=={'code','error'}):
            return status,value  # The unchanged caller rejects every other status.
        counts['revalidations'] = 1
        current = progress_snapshot(f)
        r.private_json(g.suite.work/'incoming-progress-revalidation.private.json',current)
        same_progress_scope(baseline,current)
        counts['attempts'] = 2
        status,value = original('POST',PROGRESS,incoming,timeout=5)
        g.public(value,*g.shared.get('secrets',[]))
        if status!=200:
            counts['refusals'] = 2
        else:
            exact_success(value,baseline,incoming)
        return status,value
    f['a'].api = observed


def paths(f):
    r.stage('path_diagnostics')
    result = []
    for host,target in ((f['a'],f['b']),(f['b'],f['a'])):
        status,value = host.api('GET','/v1/peers/'+target.id+'/path')
        check(status in (200,404),'path diagnostic returned an unsupported status')
        if status==200:
            check(type(value) is dict and value.get('host_id')==target.id and value.get('path') in ('direct','relay','none'),
                  'path diagnostic has an unsupported shape')
            check(value['path']=='direct' or value.get('endpoint') is None,'nondirect diagnostic exposed a direct endpoint')
        result.append(dict(observer=host.name,target=target.name,http_status=status,
            path=value['path'] if status==200 else 'unavailable',
            endpoint_present=status==200 and value.get('endpoint') is not None,diagnostic_only=True))
    return result


def settled(sender,receiver,outbound):
    if outbound['state']!='unknown':
        return outbound
    g.suite.transport_unavailable = True
    request = outbound['request']
    def observed():
        current = g.get(sender,'/v1/outbound/'+receiver.id+'/'+request['request_id'])
        check(current['request']==request,'automatic delivery changed the original durable request')
        return current if current['state']!='unknown' else None
    result = g.suite.wait(observed,35,'same durable request ordinary automatic delivery')
    g.suite.transport_unavailable = False
    return result


def addressed(f,sender,receiver,parent,kind):
    r.stage('normal_directory_and_addressed_cli')
    directory = g.api(sender,'POST','/v1/directory/refresh?network='+f['network']['id'],{},timeout=15)
    agent = parent['review']['agent']
    matches = [value for value in directory['agents'] if value['host_id']==receiver.id and value['agent_id']==agent['id']]
    check(len(matches)==1 and any(value['kind']==('self' if kind=='machine' else 'policy') for value in matches[0]['authorizations']),
          'normal directory lacks the exact target authorization')
    content = 'Private N1 qualification '+os.urandom(16).hex()
    before = q.receiver_messages(receiver)
    result = sender.cli('send',receiver.id+'/'+agent['name'],content,'--network',f['network']['id'],
        '--deadline',rfc3339(datetime.now(timezone.utc)+timedelta(minutes=2)),timeout=30)
    check(result.code==0 and type(result.json) is dict,'normal addressed CLI failed')
    outbound = settled(sender,receiver,result.json)
    check(outbound['request']['target_agent_id']==agent['id'],'address resolved to another agent')
    q.assert_append(sender,receiver,outbound,before,content)


def denial(f):
    r.stage('actual_receiver_rejection_without_address_prefilter')
    a,b = f['a'],f['b']
    body = dict(peer_host_id=a.id,target_agent_id=f['owner_parent']['review']['agent']['id'],
        request_id='request_'+os.urandom(16).hex(),content='Private N1 refusal '+os.urandom(16).hex(),
        deadline=rfc3339(datetime.now(timezone.utc)+timedelta(minutes=2)))
    before = q.receiver_messages(a)
    status,value = b.api('POST','/v1/outbound',body,timeout=15)
    check(status==200 and type(value) is dict,'raw owner send lacks a durable outcome')
    value = settled(b,a,value)
    check(value['state']=='rejected' and value['attempts']>0 and value['receipt'] is None
          and value['peer_host_id']==a.id,'receiver rejection lacks an actual authenticated attempt')
    request = value['request']
    check(all(request[key]==body[key] for key in ('target_agent_id','request_id','content','deadline'))
          and request.get('grant_id') is None and request.get('self') is None,'raw owner send changed request or citation kind')
    policy,_ = i.signed_policy(a,f['network']['id'],f['originals'][0]['public_key'])
    owner = 'person_'+hashlib.sha256(base64.b64decode(f['originals'][0]['public_key'])).hexdigest()
    citation = request.get('policy')
    check(type(citation) is dict and citation['person_id']==owner and type(citation['version']) is int
          and 0<citation['version']<=policy['sequence'],'raw send lacks the actual receiver owner-policy citation')
    check(q.receiver_messages(a)==before,'refused fresh work changed receiver history')


def ceremony_evidence():
    return dict(actual_host_applications=2,signed_public_proof_verified=True,immutable_requester_approval=True,
        finite_device_scopes=7,binding_scopes=2,original_key_transfers=0,manual_transport_pins=0,
        agent_access=False,adapter_connection=False,native_terminal_receipt=False,model_receipt=False)


def work(f,kind):
    check(all(g.get(host,'/v1/peers')==[] and g.get(host,'/v1/grants')==[] for host in (f['a'],f['b'])),
          'N1 fixture has manual peers or grants')
    if kind=='machine':
        addressed(f,f['b'],f['a'],f['owner_parent'],kind)
        addressed(f,f['a'],f['b'],f['parent'],kind)
    else:
        denial(f)
        principal = q.grant_access(f)
        addressed(f,f['b'],f['a'],f['owner_parent'],kind)
        r.stage('explicit_owner_policy_withdrawal')
        result = f['a'].cli('deny',principal,'--agent',f['owner_parent']['review']['agent']['name'],
                            '--network',f['network']['id'],timeout=20)
        check(result.code==0 and result.json['removed']==1,'exact scoped owner withdrawal failed')
        denial(f)
    check(all(g.get(host,'/v1/peers')==[] and g.get(host,'/v1/grants')==[] for host in (f['a'],f['b'])),
          'N1 work introduced manual peer or grant configuration')
    return dict(addressed_appends=2 if kind=='machine' else 1,receiver_rejections=0 if kind=='machine' else 2,
        guided_grants=0 if kind=='machine' else 1,withdrawals=0 if kind=='machine' else 1,
        normal_directory_routing=True,actual_receiver_append_verified=True,
        receiver_enforcement_checked=kind=='teammate',exact_peer_rejection_status_verified=False,
        manual_transport_pins=0,original_key_custody_verified=True,requester_consent_unchanged=True,
        native_terminal_receipt=False,model_receipt=False,paths=paths(f))


def phase_worker(args,fleet):
    controller = N1Controller(fleet,args.phase_work,args.scenario,args.port_base)
    g.suite,g.shared = controller,{'secrets':[]}
    started,retain,closed = time.monotonic(),False,False
    outcome = dict(phase=args.worker,scenario=args.scenario,passed=False,stage='deployment',transport_unavailable=False)
    checkpoint = args.work_dir/(args.scenario+'-checkpoint.private.json')
    try:
        if args.worker=='ceremony':
            # Reuse the independent setup with this N1 invitation review hook.
            # Existing driver sources and all ceremony operations stay intact.
            q.invitation = invitation
            f = q.setup(args.scenario)
            if args.scenario=='teammate':
                install_progress_observation(f)
            completed,review = r.machine(f) if args.scenario=='machine' else r.teammate(f)
            verify(f,completed,review,args.scenario)
            q.save_checkpoint(checkpoint,f,completed,review)
            evidence = ceremony_evidence()
        else:
            # The completed ceremony retained both owned daemons, including a
            # host whose identity lookup might fail during this work phase.
            for host in controller.hosts:
                host.prepared = True
            f,completed,review = q.attach(checkpoint)
            verify(f,completed,review,args.scenario)
            before = q.authority_snapshot(f)
            evidence = work(f,args.scenario)
            check(q.authority_snapshot(f)==before,'work changed existing membership or authority')
            verify(f,completed,review,args.scenario)
        if args.worker=='ceremony':
            controller.log_hashes()
        check(time.monotonic()<controller.deadline,'phase exceeded120s')
        outcome.update(passed=True,stage='complete',evidence=evidence)
        retain = args.worker=='ceremony'
    except BaseException:
        outcome.update(stage=controller.stage,transport_unavailable=controller.transport_unavailable)
        with (args.phase_work/'failure.private.txt').open('w') as output:
            traceback.print_exc(file=output)
    finally:
        if not retain:
            closed = controller.close()
            if not closed:
                outcome.update(passed=False,stage='cleanup')
            try:
                controller.log_hashes()
            except BaseException:
                outcome.update(passed=False,stage='evidence' if closed else 'cleanup')
                with (args.phase_work/'log-hash-failure.private.txt').open('w') as output:
                    traceback.print_exc(file=output)
        outcome.update(seconds=round(time.monotonic()-started,3),daemon_log_sha256=controller.daemon_logs,
                       retained_for_work=retain,cleanup_confirmed=closed,progress=controller.progress)
        r.private_json(args.phase_work/'outcome.private.json',outcome)
    return 0 if outcome['passed'] else 1


def clean_outcome(value,kind,phase,code):
    """Closed public projection; no subprocess/error/endpoint text is accepted."""
    check(type(value) is dict,'invalid private phase outcome')
    result = dict(phase=phase,scenario=kind,passed=value.get('passed') is True and code==0,
        stage=value.get('stage') if value.get('stage') in STAGES else 'other',
        transport_unavailable=value.get('transport_unavailable') is True,
        retained_for_work=value.get('retained_for_work') is True,cleanup_confirmed=value.get('cleanup_confirmed') is True)
    seconds = value.get('seconds')
    result['seconds'] = seconds if type(seconds) in (int,float) and 0<=seconds<=120 else None
    logs = value.get('daemon_log_sha256',{})
    result['daemon_log_sha256'] = {side:logs[side] for side in ('left','right') if type(logs) is dict and valid_hash(logs.get(side))}
    counts = value.get('progress',progress_counts())
    check(type(counts) is dict and set(counts)==set(progress_counts())
          and all(type(counts[key]) is int and 0<=counts[key]<=bound for key,bound in
                  (('attempts',2),('refusals',2),('revalidations',1)))
          and (counts['attempts'],counts['refusals'],counts['revalidations']) in
              ((0,0,0),(1,0,0),(1,1,0),(1,1,1),(2,1,1),(2,2,1)),'invalid closed progress counts')
    result['progress'] = counts
    if result['passed']:
        check((kind=='teammate' and phase=='ceremony' and counts in
               (dict(attempts=1,refusals=0,revalidations=0),dict(attempts=2,refusals=1,revalidations=1)))
              or ((kind!='teammate' or phase!='ceremony') and counts==progress_counts()),'invalid successful progress counts')
        check(result['stage']=='complete' and result['seconds'] is not None
              and set(result['daemon_log_sha256'])=={'left','right'}
              and result['retained_for_work']==(phase=='ceremony')
              and result['cleanup_confirmed']==(phase=='work'),'incomplete successful phase evidence')
        evidence = value.get('evidence')
        if phase=='ceremony':
            expected = ceremony_evidence()
            check(type(evidence) is dict and set(evidence)==set(expected)
                  and all(type(evidence[key]) is type(item) and evidence[key]==item for key,item in expected.items()),
                  'invalid ceremony evidence projection')
            result['evidence'] = ceremony_evidence()
        else:
            expected = dict(addressed_appends=2 if kind=='machine' else 1,receiver_rejections=0 if kind=='machine' else 2,
                guided_grants=0 if kind=='machine' else 1,withdrawals=0 if kind=='machine' else 1,
                normal_directory_routing=True,actual_receiver_append_verified=True,receiver_enforcement_checked=kind=='teammate',
                exact_peer_rejection_status_verified=False,manual_transport_pins=0,original_key_custody_verified=True,
                requester_consent_unchanged=True,native_terminal_receipt=False,model_receipt=False)
            check(type(evidence) is dict and set(evidence)==set(expected)|{'paths'}
                  and all(type(evidence[key]) is type(value) and evidence[key]==value for key,value in expected.items()),
                  'invalid work evidence projection')
            observed = evidence['paths']
            check(type(observed) is list and len(observed)==2,'missing participant path diagnostics')
            for item,(side,target) in zip(observed,(('left','right'),('right','left'))):
                check(type(item) is dict and set(item)=={'observer','target','http_status','path','endpoint_present','diagnostic_only'}
                      and item['observer']==side and item['target']==target and type(item['http_status']) is int
                      and item['http_status'] in (200,404) and item['path'] in ('direct','relay','none','unavailable')
                      and type(item['endpoint_present']) is bool and item['diagnostic_only'] is True,'invalid closed path observation')
                check((item['http_status']==200 and item['path']!='unavailable'
                       and (item['path']=='direct' or not item['endpoint_present']))
                      or (item['http_status']==404 and item['path']=='unavailable' and not item['endpoint_present']),
                      'inconsistent closed path observation')
            result['evidence'] = {**expected,'paths':observed}
    return result


def evidence_index(directory):
    """Hash fixed private control/log filenames only, never state or credentials."""
    logs = [file for file in directory.iterdir() if LOG_NAME.fullmatch(file.name)]
    logs += [file for name in ('controller.private.log','failure.private.txt','outcome.private.json',
                              'left-cleanup.private.txt','right-cleanup.private.txt','log-hash-failure.private.txt',
                              'incoming-progress-baseline.private.json','incoming-progress-revalidation.private.json')
             if (file:=directory/name).exists()]
    check(all(file.is_file() and not file.is_symlink() for file in logs),'private evidence log is not a regular file')
    index = directory/'evidence-index.private.json'
    r.private_json(index,{file.name:i.sha(file) for file in sorted(logs)})
    return i.sha(index)


def execute(args,kind,phase,offset):
    directory = i.private_dir(args.work_dir/(kind+'-'+phase))
    command = [sys.executable,str(Path(__file__).resolve()),'--fleet',str(args.fleet),'--work-dir',str(args.work_dir),
        '--port-base',str(args.port_base+offset),'--worker',phase,'--scenario',kind,'--phase-work',str(directory)]
    descriptor = os.open(directory/'controller.private.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,'wb') as output:
        child = subprocess.Popen(command,stdout=output,stderr=output,start_new_session=True)
        try:
            code = child.wait(timeout=120)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid,signal.SIGKILL); child.wait(timeout=3)
            code = 124
        except BaseException:
            if child.poll() is None:
                os.killpg(child.pid,signal.SIGKILL)
            child.wait(timeout=3)
            raise
    path = directory/'outcome.private.json'
    try:
        value = json.loads(path.read_text()) if path.exists() else dict(passed=False,stage='deadline' if code==124 else 'controller')
        result = clean_outcome(value,kind,phase,code)
    except (AssertionError,TypeError,KeyError,ValueError):
        result = dict(phase=phase,scenario=kind,passed=False,stage='evidence')
    result['private_log_index_sha256'] = evidence_index(directory)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fleet',type=Path,required=True)
    parser.add_argument('--work-dir',type=Path,required=True)
    parser.add_argument('--port-base',type=int,default=27640)
    parser.add_argument('--worker',choices=('ceremony','work'),help=argparse.SUPPRESS)
    parser.add_argument('--scenario',choices=('machine','teammate'),help=argparse.SUPPRESS)
    parser.add_argument('--phase-work',type=Path,help=argparse.SUPPRESS)
    args = parser.parse_args()
    os.umask(0o077)
    check(args.fleet.is_absolute() and args.work_dir.is_absolute() and 1024<=args.port_base<=65528,
          'explicit private fleet/work paths and dedicated ports required')
    info = args.fleet.lstat()
    check(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_mode & 0o077==0
          and info.st_size<=262144,'unprotected private fleet configuration')
    fleet = validate_fleet(json.loads(args.fleet.read_text(),object_pairs_hook=unique))
    if args.worker:
        check(args.scenario is not None and args.phase_work is not None and args.phase_work.is_absolute(), 'invalid internal phase')
        return phase_worker(args,fleet)
    check(not args.work_dir.exists(),'N1 work directory must be new')
    i.private_dir(args.work_dir)
    r.private_json(args.work_dir/'run.private.json',dict(fleet_sha256=i.sha(args.fleet),port_base=args.port_base))
    results,touched,cleanup_logs = [],[],{}
    failed = False
    cleanup = True
    try:
        for kind,offset in (('machine',0),('teammate',4)):
            if failed:
                results.extend(dict(phase=phase,scenario=kind,passed=False,stage='not_run_after_first_failure') for phase in ('ceremony','work'))
                continue
            touched.append((kind,offset))
            ceremony = execute(args,kind,'ceremony',offset); results.append(ceremony)
            if ceremony['passed']:
                result = execute(args,kind,'work',offset); results.append(result)
                failed = not result['passed']
            else:
                results.append(dict(phase='work',scenario=kind,passed=False,stage='ceremony_prerequisite_failed'))
                failed = True
    except Exception:
        failed = True
        with (args.work_dir/'failure.private.txt').open('w') as output:
            traceback.print_exc(file=output)
    finally:
        # Fallback cleanup covers a killed phase or missing outcome. A phase
        # which already confirmed its exact owned PIDs stopped is not repeated.
        for kind,offset in touched:
            actual = [value for value in results if value['scenario']==kind and 'cleanup_confirmed' in value]
            if actual and actual[-1]['cleanup_confirmed']:
                continue
            directory = i.private_dir(args.work_dir/(kind+'-cleanup'))
            controller = N1Controller(fleet,directory,kind,args.port_base+offset)
            for host in controller.hosts:
                host.prepared = True
            cleanup = controller.close() and cleanup
            cleanup_logs[kind] = evidence_index(directory)
    for kind,_offset in (('machine',0),('teammate',4)):
        for phase in ('ceremony','work'):
            if not any(value['scenario']==kind and value['phase']==phase for value in results):
                results.append(dict(phase=phase,scenario=kind,passed=False,stage='not_run_after_first_failure'))
    receipt = dict(format=1,qualification='n1_managed_cloud_protocol_observation',passed=not failed and cleanup,
        topology_class='managed_cloud_one_nat',helper_count=1,
        separate_machine_metadata_verified=any(value['phase']=='ceremony' and value['passed'] for value in results),
        archive_sha256=fleet['archive_sha256'],host_sha256=fleet['left']['host_sha256'],fleet_sha256=i.sha(args.fleet),
        run_configuration_sha256=i.sha(args.work_dir/'run.private.json'),helper_sha256=fleet['helpers'][0]['operator']['sha256'],
        helper_public_key_sha256=hashlib.sha256(base64.b64decode(fleet['helpers'][0]['public_key'])).hexdigest(),
        source_sha256={name:i.sha(Path(__file__).parent/name) for name in SOURCES},
        owner_worker_sha256=hashlib.sha256(r.OWNER_WORKER.encode()).hexdigest(),results=results,cleanup_confirmed=cleanup,
        daemon_log_hashes_are_phase_snapshots=True,
        cleanup_private_log_index_sha256=cleanup_logs,
        controller_failure_log_sha256=i.sha(args.work_dir/'failure.private.txt') if (args.work_dir/'failure.private.txt').exists() else None,
        manual_peer_configuration_operations=0,ssh_control_only=True,root_topology_capture_confirmation_required=True,
        nat_translation_verified_by_driver=False,direct_traversal_verified_by_driver=False,
        two_independent_nats=False,changed_attachment=False,native_terminal_receipt=False,model_receipt=False,
        daemon_restart=False,task_artifact_qualification=False)
    r.private_json(args.work_dir/'receipt.json',receipt)
    print(json.dumps(receipt,sort_keys=True))
    return 0 if receipt['passed'] else 1


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except Exception:
        print(json.dumps(dict(format=1,qualification='n1_managed_cloud_protocol_observation',passed=False,stage='controller_or_configuration_failure'),sort_keys=True))
        raise SystemExit(1)
