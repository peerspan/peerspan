#!/usr/bin/env python3
"""Immediate machine consent from genuine automatic return (guided42).

Independent public-contract regression. Both hosts explicitly advertise counted
bootstrap refusal proxies, counted QUIC endpoints, no relays and one fresh
independent resource helper. Each refusal proxy targets an owned bound but
non-listening socket until cleanup; the actual daemon bootstrap listener is
used only for pinned public certificate discovery. QUIC serves no mailboxes.
Before join approval,
that helper holds every original link_ mailbox GET before any response bytes;
the distinct invitation-ID return mailbox and genuine B publication pass.
It preserves exact opaque frame bytes and owns only its transport key. Public
certificate discovery anchors mTLS; no participant private file is read.
The held request must have both A's actual TLS host key and its known daemon
PID/socket provenance. Only owned B is SIGSTOPped with kernel acknowledgment;
SIGCONT runs unconditionally before all gates release. Accepted A-side and
helper streams park at acknowledged boundaries. Atomic empty/closed snapshots
are drained; new connections and every original TCP/UDP counter stay counted,
with all helper connections/encrypted bytes added. One original-frame absence
observation immediately precedes exact owner inspection/preparation. No SQL
polling, fabricated request, key copying, clock change or transport retry.

The prior opaque connection gate allowed a real original frame to arrive in CI.
Preserve that first failure; neither filter nor relabel the stored frame. This
prearmed resource-route discriminator removes that fixture timing assumption.

Fixture/status/continuation failures remain ordinary FAIL. The exact final
required prepare200 assertion is a normal gate. Release the hold before any
owner approval, then complete the same ceremony if preparation200.
Root executes committed source; the author performs static checks only.
"""
from __future__ import annotations

import base64
import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import json
import os
from pathlib import Path
import select
import signal
import socket
import socketserver
import sys
import threading
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import installed_participants as i
import real_network_participants as r
from installed_participants import g, check
from harness import Suite
from counted_peer import CountedUDP
from resource_mailbox_gate import ResourceMailboxGate

suite = Suite('machine_return_prepare',__doc__)
suite.work.chmod(0o700)
suite.stage = 'fixture'
g.suite,g.shared = suite,{'secrets':[]}
shared = {}
deadline = suite.started+120


def expired(_number,_frame):
    print('FAIL machine_return_prepare: hard120s deadline exceeded',flush=True)
    for value in suite.hosts:
        if value.process is not None and value.process.poll() is None:
            value.process.kill()
    os._exit(1)


signal.signal(signal.SIGALRM,expired)
signal.setitimer(signal.ITIMER_REAL,max(.001,deadline-time.monotonic()))


def wait(predicate,seconds,label):
    until = min(deadline,time.monotonic()+seconds)
    while time.monotonic()<until:
        value = predicate()
        if value:
            return value
        time.sleep(.02)
    check(False,label)


suite.wait = wait


def socket_owner(client,server,pids):
    """Linux OS metadata only; no key, database or product inspection."""
    def encoded(value):
        return socket.inet_aton(value[0])[::-1].hex().upper()+':'+format(value[1],'04X')
    local,remote = encoded(client),encoded(server)
    inodes = {line.split()[9] for line in Path('/proc/net/tcp').read_text().splitlines()[1:]
              if line.split()[1:4]==[local,remote,'01']}
    owners = []
    for pid in pids:
        try:
            descriptors = list(Path('/proc',str(pid),'fd').iterdir())
        except OSError:
            continue
        for descriptor in descriptors:
            try:
                target = os.readlink(descriptor)
            except OSError:
                continue
            if target.startswith('socket:[') and target.endswith(']') and target[8:-1] in inodes:
                owners.append(pid)
                break
    return owners[0] if len(owners)==1 else None


def stop_requester(value):
    check(value.process is not None and value.process.poll() is None,'owned requester is not running')
    pid = value.process.pid
    command = Path('/proc',str(pid),'cmdline').read_bytes().split(b'\0')
    check(str(value.state).encode() in command and command[0]==str(suite.host_bin).encode(),'requester PID ownership changed')
    value.fixture_pid_token = Path('/proc',str(pid),'stat').read_text().split()[21]
    value.fixture_stop_requested = True
    os.kill(pid,signal.SIGSTOP)
    ready,result = threading.Event(),[]
    def acknowledged():
        try:
            result.append(os.waitid(os.P_PID,pid,os.WSTOPPED|os.WNOWAIT))
        except OSError:
            result.append(None)
        finally:
            ready.set()
    threading.Thread(target=acknowledged,daemon=True).start()
    check(ready.wait(min(1,max(0,deadline-time.monotonic()))),'requester stop acknowledgment exceeded bound')
    state = Path('/proc',str(pid),'stat').read_text().split()
    check(result[0] is not None and result[0].si_pid==pid and result[0].si_code==os.CLD_STOPPED
          and result[0].si_status==signal.SIGSTOP and state[2] in ('T','t')
          and state[21]==value.fixture_pid_token,'owned requester did not enter verified stopped state')


def resume_requester(value):
    if getattr(value,'fixture_stop_requested',False):
        pid = value.process.pid
        check(Path('/proc',str(pid),'stat').read_text().split()[21]==value.fixture_pid_token,'requester PID changed before resume')
        os.kill(pid,signal.SIGCONT)
        value.fixture_stop_requested = False


class FirstFetchGate:
    """Count opaque bytes; hold a complete ClientHello before server bytes."""
    def __init__(self,target,held=False,forbidden_ports=()):
        self.target = target
        self.lock = threading.Lock()
        self.condition = threading.Condition(self.lock)
        self.released,self.closed = threading.Event(),threading.Event()
        self.connections = self.sent = self.returned = 0
        self.live = {}
        self.verified_owners = {}
        self.accepted = {}
        self.established = {}
        self.pid_roles = None
        self.provenance_errors = 0
        self.park_targets,self.parked = set(),set()
        self.last_barrier = None
        self.sockets = set()
        if not held:
            self.released.set()
        outer = self
        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                upstream = None
                with outer.lock:
                    outer.connections += 1
                    generation = outer.connections
                    outer.sockets.add(self.request)
                    outer.accepted[generation] = self.request
                try:
                    if not outer.forward_barrier(generation):
                        return
                    owner_role = owner = None
                    with outer.lock:
                        roles = dict(outer.pid_roles) if outer.pid_roles is not None else None
                    if roles is not None:
                        owner = socket_owner(self.request.getpeername(),self.request.getsockname(),roles)
                        owner_role = roles.get(owner)
                        if owner_role not in ('existing','requester'):
                            with outer.lock:
                                outer.provenance_errors += 1
                            return
                    prefix = b''
                    if not outer.released.is_set() and (roles is None or owner_role=='existing'):
                        self.request.settimeout(.1)
                        limit = time.monotonic()+1
                        def receive(count):
                            result = bytearray()
                            while len(result)<count and time.monotonic()<limit and not outer.closed.is_set():
                                try:
                                    value = self.request.recv(count-len(result))
                                except socket.timeout:
                                    continue
                                if not value:
                                    return None
                                with outer.lock:
                                    outer.sent += len(value)
                                result.extend(value)
                            return bytes(result) if len(result)==count else None
                        header = receive(5)
                        if header is None or header[0]!=22 or header[1]!=3:
                            return
                        count = int.from_bytes(header[3:5],'big')
                        if not 4<=count<=65535:
                            return
                        hello = receive(count)
                        if hello is None or hello[0]!=1 or int.from_bytes(hello[1:4],'big')+4>len(hello):
                            return
                        prefix = header+hello
                        self.request.setblocking(False)
                        with outer.lock:
                            outer.live[generation] = self.request
                            outer.verified_owners[generation] = owner
                        while not outer.released.wait(.01):
                            if outer.closed.is_set():
                                return
                            readable,_,_ = select.select([self.request],[],[],0)
                            if readable:
                                return # EOF or extra bytes is not a live quiet hold.
                        with outer.lock:
                            outer.live.pop(generation,None)
                    self.request.settimeout(None)
                    upstream = socket.create_connection(outer.target,timeout=5)
                    upstream.settimeout(None)
                    with outer.lock:
                        outer.sockets.add(upstream)
                        outer.established[generation] = (self.request,upstream)
                    if not outer.forward_barrier(generation):
                        return
                    if prefix:
                        upstream.sendall(prefix)
                    while not outer.closed.is_set():
                        if not outer.forward_barrier(generation):
                            return
                        readable,_,_ = select.select([self.request,upstream],[],[],.02)
                        for stream in readable:
                            with outer.lock:
                                if generation in outer.park_targets:
                                    break
                                data = stream.recv(65536)
                                if not data:
                                    return
                                if stream is self.request:
                                    outer.sent += len(data)
                                else:
                                    outer.returned += len(data)
                            (upstream if stream is self.request else self.request).sendall(data)
                except OSError:
                    pass
                finally:
                    with outer.lock:
                        outer.live.pop(generation,None)
                        outer.verified_owners.pop(generation,None)
                        outer.accepted.pop(generation,None)
                        outer.established.pop(generation,None)
                        outer.parked.discard(generation)
                        outer.condition.notify_all()
                        outer.sockets.discard(self.request)
                        if upstream:
                            outer.sockets.discard(upstream)
                    if upstream:
                        upstream.close()
        self.server = Server(('127.0.0.1',0),Handler)
        while self.server.server_address[1] in (target[1],*forbidden_ports):
            self.server.server_close()
            self.server = Server(('127.0.0.1',0),Handler)
        self.address = '127.0.0.1:'+str(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':.02},daemon=True)
        self.thread.start()

    def counts(self):
        with self.lock:
            return self.connections,self.sent,self.returned

    def forward_barrier(self,generation):
        with self.condition:
            while generation in self.park_targets and not self.closed.is_set():
                self.parked.add(generation)
                self.condition.notify_all()
                self.condition.wait()
            self.parked.discard(generation)
            return not self.closed.is_set()

    def park_accepted(self,timeout=1):
        # Freeze the existing set once. Later connections remain fully live and
        # counted, so unrelated retries cannot be hidden by the barrier.
        until = min(deadline,time.monotonic()+timeout)
        with self.condition:
            check(not self.park_targets,'accepted transport was already parked')
            self.park_targets = set(self.accepted)
            snapshot_counts = self.connections,self.sent,self.returned
            while (self.park_targets & self.accepted.keys())-self.parked:
                remaining = until-time.monotonic()
                check(remaining>0,'accepted relay-thread barrier unavailable')
                self.condition.wait(remaining)
            held = tuple(sorted(self.park_targets & self.parked))
            self.last_barrier = dict(snapshot_streams=len(self.park_targets),parked_streams=len(held),
                drained_streams=len(self.park_targets-self.accepted.keys()),snapshot_counts=list(snapshot_counts),
                acknowledged_counts=[self.connections,self.sent,self.returned])
            check(self.last_barrier['snapshot_streams']==self.last_barrier['parked_streams']+self.last_barrier['drained_streams'],
                  'snapshot stream is neither parked nor actually drained')
        check(set(held)<=set(self.live_parked_generations()),'still-accepted stream lacks a live acknowledged hold')
        return held

    def live_parked_generations(self):
        with self.lock:
            current = [(generation,self.established.get(generation,(self.accepted[generation],)))
                       for generation in self.parked if generation in self.accepted]
        result = []
        for generation,streams in current:
            live = True
            for stream in streams:
                try:
                    if stream.recv(1,socket.MSG_PEEK|socket.MSG_DONTWAIT)==b'':
                        live = False
                except BlockingIOError:
                    pass
                except OSError:
                    live = False
            if live:
                result.append(generation)
        return result

    def release_accepted(self):
        with self.condition:
            self.park_targets.clear()
            self.condition.notify_all()

    def live_generations(self):
        with self.lock:
            current = list(self.live.items())
        result = []
        for generation,stream in current:
            try:
                stream.recv(1,socket.MSG_PEEK|socket.MSG_DONTWAIT)
            except BlockingIOError:
                result.append(generation)
            except OSError:
                pass
        return result

    def fetch_owner(self,generation):
        with self.lock:
            return self.verified_owners.get(generation)

    def release(self):
        self.released.set()

    def close(self):
        self.closed.set()
        self.release()
        self.release_accepted()
        with self.lock:
            streams = list(self.sockets)
        for stream in streams:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=1)


def host(name,helper):
    value = i.InstalledHost(suite,name)
    suite.hosts.append(value)
    value.refusal_reservation = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    value.refusal_reservation.bind(('127.0.0.1',0))
    while value.refusal_reservation.getsockname()[1]==value.bootstrap_port:
        value.refusal_reservation.close()
        value.refusal_reservation = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        value.refusal_reservation.bind(('127.0.0.1',0))
    # Never listen or release this owned refusal target while a host is live.
    value.relay = FirstFetchGate(value.refusal_reservation.getsockname(),forbidden_ports=(value.bootstrap_port,))
    value.counted_peer = CountedUDP(('127.0.0.1',value.peer_port))
    config = value.root/'transport.json'
    config.write_bytes(g.compact(dict(format=1,advertise_bootstrap=[value.relay.address],advertise_quic=[value.counted_peer.address],
                                     rendezvous=[helper.pin()],relays=[],publish_contacts=False)))
    config.chmod(0o600)
    value.extra_args = ['--transport-config',str(config)]
    return value.start()


def invitation(a,parent,network,person,member,helper):
    body = dict(context=g.context(parent),network_id=network['id'],member=member,expected_person_public_key=person)
    prepared = g.api(a,'POST',i.INVITATIONS,body,expected=201)
    review = prepared['review']
    expected_transport = dict(bootstrap_addresses=[a.relay.address],quic_addresses=[a.counted_peer.address],relays=[],
                              helpers=[dict(address=helper.address,public_key=helper.public_key)])
    check(prepared['state']=='review' and prepared['invitation'] is None
          and prepared['review_id']==g.digest('peerspan-invitation-review-v1',review)
          and review['network']=={key:network[key] for key in ('id','name','context_id','genesis_root_public_key')}
          and review['expected_person_public_key']==person and review['member']==member
          and review['transport']==expected_transport,'sole-resource guided invitation changed exact terms')
    issued = g.api(a,'POST',i.INVITATIONS+'/'+prepared['flow_id']+'/decision',
                   dict(context=g.context(parent),review_id=prepared['review_id'],decision='approve'))
    check(issued['state']=='issued' and issued['review']==review,'guided invitation approval changed terms')
    status,handoff = a.api('POST',i.INVITATIONS+'/'+prepared['flow_id']+'/handoff',
                          dict(context=g.context(parent),review_id=prepared['review_id']))
    check(status==200 and handoff['invitation'].startswith('psi2-')
          and handoff['invitation_id']==issued['invitation']['invitation_id'],'private genuine invitation handoff failed')
    code = handoff['invitation']
    g.shared['secrets'].append(code)
    # Independently verify the exact signed carrier hints before requester approval.
    encoded = code[5:]
    outer = json.loads(base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)))
    raw_payload = base64.b64decode(outer['payload_base64'],validate=True)
    payload = json.loads(raw_payload)
    check(outer['context_id']==network['context_id'] and outer['inviter_host_public_key']==a.public_key
          and payload['helpers']==expected_transport['helpers'] and payload['contacts'],
          'signed invitation lacks the exact sole helper and refusing contact')
    message = '\n'.join(['peerspan-decentralized-contact-invitation-v1',network['context_id'],a.public_key,
                         hashlib.sha256(raw_payload).hexdigest()]).encode()
    g.ed25519(a.public_key,outer['signature'],message,'resource-invitation')
    for index,contact in enumerate(payload['contacts']):
        raw_hints = base64.b64decode(contact['payload_base64'],validate=True)
        check(contact['context_id']==network['context_id'] and contact['host_public_key']==a.public_key
              and json.loads(raw_hints)=={name:expected_transport[name] for name in ('bootstrap_addresses','quic_addresses','relays')},
              'signed invitation acquired an alternate direct resource endpoint')
        message = '\n'.join(['peerspan-decentralized-contact-v1',contact['context_id'],a.public_key,
                             str(contact['sequence']),contact['issued_at'],contact['expires_at'],
                             hashlib.sha256(raw_hints).hexdigest()]).encode()
        g.ed25519(a.public_key,contact['signature'],message,'resource-contact-'+str(index))
    return code


def traffic(f):
    return g.traffic(f)+(f['helper'].counts(),)


def continue_ceremony(f,prepared):
    a,b = f['a'],f['b']
    consent = prepared['consent']
    body = dict(context=g.context(f['owner_parent']),request_id=f['rid'],
                consent_id=consent['consent_id'],consent_review_id=consent['review_id'])
    approved = g.api(a,'POST',g.MACHINE+'/approve',body)
    r.immutable(approved['consent'],consent)
    check(approved['consent']['state']=='approved','exact owner approval missing')
    signing = g.api(a,'POST',g.MACHINE+'/signing',body)
    if signing['signing']['state']!='signed':
        check(signing['signing']['can_sign'] is True,'approved owned device cannot sign')
        signing = g.api(a,'POST',g.MACHINE+'/sign',{**body,'decision':'sign_machine_owner_offer'},timeout=95)
    check(signing['signing']['state']=='signed','exact owner signatures missing')
    current = r.checkpoint(f,'owner_finalization_id','needs_commit',30)
    check(current['administrator_offer_id']=='-' and not current['commit_approved']
          and current['selection_approved'] and g.get(b,'/v2/networks')==[],
          'automatic folded finalization bypassed requester consent')
    endpoint = i.JOINS+'/'+f['flow']['flow_id']+'/machine-commit'
    key = dict(context=g.context(f['parent']),join_review_id=f['flow']['review_id'])
    inspected = g.api(b,'POST',endpoint+'/inspect',key)
    review = inspected['review']
    check(inspected['review_id']==g.digest('peerspan-machine-requester-inspection-v1',review)
          and review['scopes']==7 and review['binding_scopes']==2 and review['owner_provider']==f['provider'],
          'requester inspection substituted finite selected authority')
    prepared = g.api(b,'POST',endpoint+'/prepare',{**key,'inspection_review_id':inspected['review_id']})
    requester = i.immutable(prepared,'consent','peerspan-machine-requester-consent-v1','review')
    action = {**key,'consent_review_id':requester['review_id']}
    approved = g.api(b,'POST',endpoint+'/approve',action)
    r.immutable(approved['consent'],requester)
    check(approved['consent']['state']=='approved','requester consent not approved')
    completed = g.api(b,'POST',endpoint+'/complete',{**action,'decision':'complete_machine_requester_commit'},timeout=95)
    check(completed['consent']==approved['consent'] and completed['completion']['state']=='locally_applied'
          and all(completed['completion'][k]=='not_verified' for k in ('participant_delivery','agent_access','connection_readiness')),
          'completion changed approval or overclaimed readiness')
    wait(lambda:all(r.view(h,f['rid'])['state']=='linked' for h in (a,b)),25,'both actual applications')
    check(g.parse_time(review['not_after'])==min(g.parse_time(current['created_at'])+timedelta(days=7),
          g.parse_time(f['provider']['not_after'])),'finite powers deadline widened')
    for h in (a,b):
        r.proof(f,h,completed,review,'machine')
    check(not b.original.exists() and i.sha(a.original)==f['original'],'original key copied or changed')


@suite.case('genuine_return_live_fetch_hold_unsigned_prepare_and_continuation','guided42 retained request/capability')
def _():
    a=b=helper=None
    try:
        helper = ResourceMailboxGate(suite.work/'resource-helper',deadline,socket_owner,g.ed25519)
        a,b = host('existing',helper),host('requester',helper)
        helper.configure((a,b))
        check(a.public_key!=b.public_key and not a.original.exists() and not b.original.exists(),'fresh distinct host prerequisite')
        net = i.create_network(a,'Immediate returned request')
        pa,pb = g.project(a,'existing-return'),g.project(b,'requester-return')
        person = g.ssh_public_base64(a.original)
        people = g.get(a,'/v2/networks/'+net['id']+'/persons')['persons']
        member = [p for p in people if p['person_public_key']==person]
        check(len(member)==1,'existing person ambiguous')
        f = dict(a=a,b=b,helper=helper,network=net,person=person,provider=net['provider'],owner_parent=pa,parent=pb,
                 original=i.sha(a.original),secrets=[])
        g.shared = f
        code = invitation(a,pa,net,person,member[0]['member'],helper)
        preview = g.api(b,'POST','/v1/onboarding/invitation-preview',dict(context=g.context(pb),invitation=code))
        check(preview['review_id']==g.digest('peerspan-invitation-preview-v1',preview['review'])
              and preview['review']['invitation']['automatic_return'] is True
              and preview['review']['helpers']==[dict(address=helper.address,public_key=helper.public_key)]
              and preview['review']['contacts']
              and all(contact['bootstrap_addresses']==[a.relay.address]
                      and contact['quic_addresses']==[a.counted_peer.address] and contact['relays']==[]
                      for contact in preview['review']['contacts']), 'authentic exclusive-resource automatic-return preview missing')
        flow = g.api(b,'POST',i.JOINS,dict(context=g.context(pb),invitation=code,person_public_key=person),expected=201)
        check(flow['state']=='review' and flow['outcome'] is None and flow['review_id']==g.digest('peerspan-join-review-v1',flow['review'])
              and flow['review']['invitation_review_id']==preview['review_id'],'unapproved join review changed')
        check(g.get(a,'/v2/link/requests')==g.get(b,'/v2/link/requests')==[],'unapproved request appeared')
        decision = dict(context=g.context(pb),review_id=flow['review_id'],decision='approve',invitation=code)
        with ThreadPoolExecutor(max_workers=1) as executor:
            publication = executor.submit(g.api,b,'POST',i.JOINS+'/'+flow['flow_id']+'/decision',decision,timeout=30)
            try:
                incoming = wait(lambda:next(iter(g.get(a,'/v2/link/requests')),None),15,'genuine automatic incoming return')
                f.update(flow=flow,rid=incoming['request_id'])
                check(incoming['role']=='approver' and incoming['mode']=='new' and incoming['state']=='pending'
                      and incoming['network_id']==net['id'] and incoming['context_id']==net['context_id']
                      and incoming['person_public_key']==person and incoming['host_public_key']==b.public_key
                      and incoming['owner_offer_id']=='-' and not incoming['commit_approved'],'returned request changed pins/consent')
                generation = wait(lambda:next(iter(helper.live_holds(f['rid'],a.process.pid,a.public_key)),None),
                                  5,'live authenticated owner original-resource GET hold')
                check(helper.stored_request(f['rid'],b.public_key)==1 and helper.errors==0,
                      'resource helper lacks genuine original publication or transport authentication')
                stop_requester(b)
                existing_hold = a.relay.park_accepted()
                helper_hold = helper.park_accepted()
                pending,capability = g.pending(a,f['rid'])
                packet = json.loads(base64.b64decode(pending['request_packet_base64'],validate=True))
                check(capability is not None and packet['role']=='request' and packet['context_id']=='-'
                      and packet['request_id']==f['rid'] and packet['writer_host_public_key']==b.public_key
                      and packet['signer_public_key']==incoming['device_public_key']
                      and g.packet_id(packet)==incoming['request_packet_id'],'retained authenticated request/capability mismatch')
                check(pending['carrier_endpoints']==[dict(kind='helper',address=helper.address,public_key=helper.public_key),
                      dict(kind='participant',address=b.relay.address,public_key=b.public_key)],
                      'returned request acquired an alternate original-frame carrier')
                g.ed25519(b.public_key,packet['host_signature'],g.packet_message(packet),'returned-host')
                g.ed25519(packet['signer_public_key'],packet['device_signature'],g.packet_message(packet),'returned-device')
                # Exactly one absence observation. No SQL wait or protocol write.
                original_frame = g.rows(a,"SELECT frame_id FROM dec_frames WHERE request_id=? AND role='request' AND writer_key=?",(f['rid'],b.public_key))
                precondition_fetch_live = generation in helper.live_holds(f['rid'],a.process.pid,a.public_key)
                precondition_return_live = set(a.relay.live_parked_generations())
                precondition_helper_live = set(helper.live_parked_generations())
                print('machine_return_prepare_precondition_public='+json.dumps(dict(
                    original_frame_count=len(original_frame),original_frame_absent=original_frame==[],
                    same_fetch_generation_live=precondition_fetch_live,
                    expected_return_streams=len(existing_hold),
                    live_expected_return_streams=len(set(existing_hold)&precondition_return_live),
                    all_return_streams_live=set(existing_hold)<=precondition_return_live,
                    fetch_owner_still_proven=precondition_fetch_live,
                    provenance_errors=helper.errors,requester_stop_verified=True,
                    helper_original_frames=helper.stored_request(f['rid'],b.public_key),
                    helper_expected_streams=len(helper_hold),helper_live_streams=len(set(helper_hold)&precondition_helper_live),
                    helper_stream_barrier=helper.last_barrier,
                    existing_stream_barrier=a.relay.last_barrier,measured_owner_calls_started=False),sort_keys=True),flush=True)
                check(original_frame==[] and precondition_fetch_live and set(existing_hold)<=precondition_return_live
                      and set(helper_hold)<=precondition_helper_live and helper.errors==0,
                      'original frame or live transport barrier unavailable')
                before_traffic = traffic(f)
                began = time.monotonic()
                body = dict(context=g.context(pa),request_id=f['rid'])
                inspected = g.api(a,'POST','/v1/onboarding/machine-owner-inspection',body,timeout=5)
                review = inspected['review']
                check(inspected['review_id']==g.digest('peerspan-machine-owner-inspection-v1',review)
                      and review['provider']==net['provider'] and review['scopes']==7 and review['host_admission']=='owner_may_fold'
                      and all(review[k]==incoming[k] for k in ('request_id','request_packet_id','person_public_key','host_public_key','device_public_key')),
                      'exact existing-owner inspection changed reviewed authority')
                f['owner_inspection'] = dict(review_id=inspected['review_id'],review=review)
                status,prepared = a.api('POST',g.MACHINE+'/prepare',{**body,'inspection_review_id':inspected['review_id']},timeout=5)
                elapsed = time.monotonic()-began
                after_traffic = traffic(f)
                same_held_generation = generation in helper.live_holds(f['rid'],a.process.pid,a.public_key)
                same_existing_hold = set(existing_hold)<=set(a.relay.live_parked_generations())
                same_helper_hold = set(helper_hold)<=set(helper.live_parked_generations())
                fetch_owner_proven = same_held_generation and helper.errors==0
                observed_code = prepared.get('code') if isinstance(prepared,dict) else None
                print('machine_return_prepare_boundary_public='+json.dumps(dict(
                    prepare_status=status if type(status) is int and 100<=status<=599 else None,
                    prepare_code=observed_code if observed_code in {'invalid','not_found','review_changed','review_expired',
                        'machine_owner_consent_unavailable'} else ('none' if observed_code is None else 'other'),
                    seconds=round(elapsed,3),same_held_generation=same_held_generation,same_existing_hold=same_existing_hold,
                    same_helper_hold=same_helper_hold,fetch_owner_proven=fetch_owner_proven,requester_stopped=True,
                    helper_stream_barrier=helper.last_barrier,
                    existing_stream_barrier=a.relay.last_barrier,
                    captured_review_receipt=status==200 and isinstance(prepared,dict)
                        and isinstance(prepared.get('consent'),dict) and prepared['consent'].get('state')=='review',
                    traffic={name:dict(before=list(before_traffic[index]),after=list(after_traffic[index]))
                        for index,name in enumerate(('existing_tcp','existing_udp','requester_tcp','requester_udp','helper_tcp'))}),
                    sort_keys=True),flush=True)
                check(elapsed<=5 and after_traffic==before_traffic and same_held_generation and same_existing_hold
                      and same_helper_hold and fetch_owner_proven,
                      'immediate inspect/prepare exceeded5s or performed counted network IO')
                check(status==200 or (status==409 and isinstance(prepared,dict) and prepared.get('code')=='machine_owner_consent_unavailable'),
                      'unexpected preparation status/category')
                if status==200:
                    receipt = g.owner_consent(f,prepared,'review')
                    owner = g.load_intent(a,receipt['review']['intent_id'])['record']
                    check(not owner['approved'] and owner['approved_at']=='-' and owner['signatures']==[]
                          and prepared['request']['owner_offer_id']=='-' and not prepared['request']['commit_approved'],
                          'preparation approved or signed authority')
                else:
                    check(g.intent_rows(a,f['rid'],'owner')==[] and g.rows(a,"SELECT intent_id FROM dec_intents WHERE kind='machine_owner_review'")==[],
                          'failed preparation left partial owner consent')
                shared['prepare_status'] = status
                print('machine_return_prepare_public='+json.dumps(dict(live_authenticated_original_get=True,original_frame_absent=True,
                    inspect_status=200,prepare_status=status,prepare_code='none' if status==200 else 'machine_owner_consent_unavailable',
                    counted_io_unchanged=True,owner_approved=False,owner_signed=False,seconds=round(elapsed,3)),sort_keys=True),flush=True)
            finally:
                try:
                    resume_requester(b)
                finally:
                    a.relay.release_accepted()
                    helper.release_accepted()
                    helper.release()
            if status==200:
                check(g.get(b,'/v2/networks')==[],'unsigned preparation adopted requester authority')
            published = publication.result(timeout=35)
            check(published['state']=='requested' and published['review']==flow['review']
                  and published['outcome']['request_id']==f['rid'],'original publication changed after released hold')
            f['flow'] = published
        if status==200:
            continue_ceremony(f,prepared)
        check(time.monotonic()<deadline,'suite exceeded120s')
    finally:
        if helper is not None:
            print('machine_return_prepare_resource_public='+json.dumps(helper.summary(),sort_keys=True),flush=True)
            helper.close()
        for h in (b,a):
            if h is not None:
                h.relay.close()
                h.counted_peer.close()
                h.stop()
                h.refusal_reservation.close()


@suite.case('immediate_exact_prepare_requires_no_original_frame','guided42 retained request/capability')
def _():
    check(shared.get('prepare_status')==200,'exact inspectable returned request preparation must return200')


suite.finish()
