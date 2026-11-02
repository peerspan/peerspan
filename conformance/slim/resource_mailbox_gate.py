"""Independent resource-only carrier for the guided42 transport fixture.

Only public mailbox HTTP and opaque participant-created frames are handled.
The gate is armed at construction, before any requester approval. It never
decrypts a frame and owns only its fresh TLS transport key. Public certificates
discovered from the two fixture hosts are the only client trust anchors.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import select
import socket
import socketserver
import ssl
import subprocess
import threading
import time
from datetime import datetime, timezone

from harness import check, parse_time


TLS_LIBRARIES = frozenset({'SSL','X509','ASN1','PEM'})
TLS_REASONS = frozenset({'CERTIFICATE_VERIFY_FAILED','TLSV1_ALERT_UNKNOWN_CA',
    'TLSV1_ALERT_DECRYPT_ERROR','SSLV3_ALERT_BAD_CERTIFICATE','SSLV3_ALERT_CERTIFICATE_UNKNOWN',
    'TLSV13_ALERT_CERTIFICATE_REQUIRED','UNSUPPORTED_PROTOCOL','WRONG_VERSION_NUMBER',
    'NO_SHARED_CIPHER','NO_APPLICATION_PROTOCOL','TLSV1_ALERT_NO_APPLICATION_PROTOCOL',
    'PEER_DID_NOT_RETURN_A_CERTIFICATE','CERTIFICATE_REQUIRED','TLSV1_ALERT_PROTOCOL_VERSION',
    'SSLV3_ALERT_HANDSHAKE_FAILURE','TLSV1_ALERT_INTERNAL_ERROR','UNEXPECTED_EOF_WHILE_READING',
    'DECRYPTION_FAILED_OR_BAD_RECORD_MAC','BAD_SIGNATURE','TLSV1_ALERT_BAD_RECORD_MAC'})
MAILBOX_CHECKS = {message:'_'.join(message.removeprefix('resource fixture ').split()) for message in (
    'resource fixture duplicate JSON field','resource fixture malformed JSON field','resource fixture missing frame',
    'resource fixture invalid frame envelope','resource fixture frame bound','resource fixture header bound',
    'resource fixture invalid header','resource fixture invalid HTTP framing','resource fixture request body bound',
    'resource fixture request pipelining','resource fixture missing exact capability','resource fixture unsupported route',
    'resource fixture invalid mailbox creation','resource fixture invalid mailbox window','resource fixture invalid original window',
    'resource fixture mailbox quota','resource fixture conflicting mailbox creation','resource fixture wrong capability or expired mailbox',
    'resource fixture invalid append','resource fixture conflicting frame','resource fixture frame quota',
    'resource fixture GET body','resource fixture invalid method','resource fixture response bound')}


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def exact(pairs):
    result = {}
    for key, value in pairs:
        check(key not in result, 'resource fixture duplicate JSON field')
        result[key] = value
    return result


def frame_slice(body):
    """Retain the exact outer frame JSON slice, including its original order."""
    text = body.decode('utf-8')
    decoder = json.JSONDecoder(object_pairs_hook=exact)
    position = text.index('{')+1
    while True:
        while text[position].isspace() or text[position]==',':
            position += 1
        key, position = decoder.raw_decode(text, position)
        while text[position].isspace():
            position += 1
        check(text[position]==':', 'resource fixture malformed JSON field')
        position += 1
        while text[position].isspace():
            position += 1
        start = position
        _value, position = decoder.raw_decode(text, position)
        if key=='frame':
            return text[start:position].encode('utf-8')
        while text[position].isspace():
            position += 1
        check(text[position]!='}', 'resource fixture missing frame')


def public_key(certificate):
    pem = ssl.DER_cert_to_PEM_cert(certificate).encode()
    public = subprocess.run(['openssl','x509','-pubkey','-noout'], input=pem,
                            capture_output=True, timeout=5, check=True).stdout
    der = subprocess.run(['openssl','pkey','-pubin','-outform','DER'], input=public,
                         capture_output=True, timeout=5, check=True).stdout
    check(len(der)==44 and der[:12]==bytes.fromhex('302a300506032b6570032100'),
          'resource fixture certificate is not Ed25519')
    return base64.b64encode(der[12:]).decode()


class TLSStream:
    """MemoryBIO keeps every encrypted socket byte in the helper counters."""
    def __init__(self, helper, generation, raw):
        self.helper,self.generation,self.raw = helper,generation,raw
        self.incoming,self.outgoing = ssl.MemoryBIO(),ssl.MemoryBIO()
        self.tls = helper.context.wrap_bio(self.incoming,self.outgoing,server_side=True)
        self.until = min(helper.deadline,time.monotonic()+30)

    def network(self, data=None):
        while True:
            with self.helper.condition:
                self.helper.checkpoint(self.generation)
                if self.helper.closed.is_set() or time.monotonic()>=self.until:
                    raise OSError('resource fixture closed')
                try:
                    if data is None:
                        value = self.raw.recv(65536)
                        self.helper.received += len(value)
                        if not value:
                            raise EOFError
                        return value
                    count = self.raw.send(data)
                    self.helper.sent += count
                    if not count:
                        raise EOFError
                    return count
                except BlockingIOError:
                    pass
            select.select([self.raw] if data is None else [], [] if data is None else [self.raw], [], .02)

    def flush(self):
        while self.outgoing.pending:
            data = self.outgoing.read()
            while data:
                data = data[self.network(data):]

    def perform(self, operation):
        while True:
            try:
                result = operation()
                self.flush()
                return result
            except ssl.SSLWantReadError:
                self.flush()
                self.incoming.write(self.network())
            except ssl.SSLWantWriteError:
                self.flush()

    def handshake(self):
        self.perform(self.tls.do_handshake)

    def recv(self, count):
        value = self.perform(lambda:self.tls.read(count))
        if not value:
            raise EOFError
        return value

    def sendall(self, data):
        while data:
            data = data[self.perform(lambda:self.tls.write(data)):]


class ResourceMailboxGate:
    def __init__(self, work, deadline, socket_owner, verify_signature):
        self.work,self.deadline = work,deadline
        self.socket_owner,self.verify_signature = socket_owner,verify_signature
        work.mkdir(mode=0o700)
        self.key,self.cert = work/'helper-key.pem',work/'helper-cert.pem'
        subprocess.run(['openssl','req','-x509','-newkey','ed25519','-nodes','-subj','/CN=resource-fixture',
                        '-days','1','-keyout',str(self.key),'-out',str(self.cert)],
                       capture_output=True, timeout=5, check=True)
        self.key.chmod(0o600)
        self.public_key = public_key(ssl.PEM_cert_to_DER_cert(self.cert.read_text()))
        self.condition = threading.Condition(threading.RLock())
        self.closed,self.released = threading.Event(),threading.Event()
        self.connections=self.received=self.sent=self.errors=0
        self.failures = {name:0 for name in ('socket_provenance','tls_handshake','tls_host_key','mailbox_request')}
        self.tls_errors,self.verify_codes,self.mailbox_checks,self.mailbox_clauses = {},{},{},{}
        self.diagnostic_errors = 0
        self.clients,self.held,self.boxes = {},{},{}
        self.park_targets,self.parked = set(),set()
        self.last_barrier = None
        outer = self

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

            def get_request(self):
                raw,address = super().get_request()
                raw.setblocking(False)
                with outer.condition:
                    outer.connections += 1
                    generation = outer.connections
                    outer.clients[generation] = dict(raw=raw,tuple=(address,raw.getsockname()),pid=None,key=None)
                return (raw,generation),address

            def shutdown_request(self, request):
                super().shutdown_request(request[0])

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                raw,generation = self.request
                phase = 'socket_provenance'
                try:
                    client = outer.clients[generation]
                    pid = outer.socket_owner(*client['tuple'],outer.host_keys)
                    check(pid in outer.host_keys, 'resource fixture client lacks owned socket provenance')
                    with outer.condition:
                        client['pid'] = pid
                    phase = 'tls_handshake'
                    stream = TLSStream(outer,generation,raw)
                    stream.handshake()
                    check(stream.tls.selected_alpn_protocol()=='peerspan-bootstrap/1', 'resource fixture wrong ALPN')
                    phase = 'tls_host_key'
                    key = public_key(stream.tls.getpeercert(binary_form=True))
                    check(key==outer.host_keys[pid], 'resource fixture client TLS host key mismatch')
                    with outer.condition:
                        client['key'] = key
                    phase = 'mailbox_request'
                    outer.handle(stream,generation,key)
                except (EOFError,ConnectionError,ssl.SSLEOFError):
                    pass
                except Exception as error:
                    with outer.condition:
                        if not outer.closed.is_set():
                            outer.errors += 1
                            outer.failures[phase] += 1
                            try:
                                outer.observe_failure(phase,error)
                            except Exception:
                                outer.diagnostic_errors += 1
                finally:
                    with outer.condition:
                        outer.clients.pop(generation,None)
                        outer.held.pop(generation,None)
                        outer.parked.discard(generation)
                        outer.condition.notify_all()

        self.server = Server(('127.0.0.1',0),Handler)
        self.address = '127.0.0.1:'+str(self.server.server_address[1])
        self.thread = None

    def configure(self, hosts):
        """Public TLS discovery only; no participant key or state file access."""
        self.host_keys = {host.process.pid:host.public_key for host in hosts}
        discovery = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        discovery.check_hostname,discovery.verify_mode = False,ssl.CERT_NONE
        discovery.minimum_version = ssl.TLSVersion.TLSv1_3
        discovery.load_cert_chain(str(self.cert),str(self.key))
        discovery.set_alpn_protocols(['peerspan-bootstrap/1'])
        anchors = []
        for host in hosts:
            with socket.create_connection(('127.0.0.1',host.bootstrap_port),timeout=5) as raw:
                with discovery.wrap_socket(raw,server_hostname='peerspan') as stream:
                    certificate = stream.getpeercert(binary_form=True)
                    check(stream.selected_alpn_protocol()=='peerspan-bootstrap/1'
                          and public_key(certificate)==host.public_key, 'public host certificate discovery pin mismatch')
                    anchors.append(ssl.DER_cert_to_PEM_cert(certificate))
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.context.num_tickets = 0
        self.context.load_cert_chain(str(self.cert),str(self.key))
        self.context.load_verify_locations(cadata='\n'.join(anchors))
        self.context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.set_alpn_protocols(['peerspan-bootstrap/1'])
        self.thread = threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':.02},daemon=True)
        self.thread.start()

    def pin(self):
        return dict(address=self.address,public_key=self.public_key,token_file='-')

    def counts(self):
        with self.condition:
            return self.connections,self.received,self.sent

    def summary(self):
        with self.condition:
            return dict(connections=self.connections,received_bytes=self.received,sent_bytes=self.sent,
                failures=dict(self.failures),tls_errors=dict(self.tls_errors),tls_verify_codes=dict(self.verify_codes),
                mailbox_checks=dict(self.mailbox_checks),mailbox_clauses=dict(self.mailbox_clauses),
                diagnostic_errors=self.diagnostic_errors,mailboxes=len(self.boxes),
                original_mailboxes=sum(box['request_id'].startswith('link_') for box in self.boxes.values()),
                return_mailboxes=sum(box['request_id'].startswith('di_') for box in self.boxes.values()),
                held_original_gets=len(self.held),gate_released=self.released.is_set())

    def observe_failure(self, phase, error):
        """Receive-only: closed categories from the already-caught exception/locals."""
        def increment(histogram, category):
            histogram[category] = histogram.get(category,0)+1
        if phase=='tls_handshake':
            library,reason = getattr(error,'library',None),getattr(error,'reason',None)
            library = library if library in TLS_LIBRARIES else ('none' if library is None else 'other')
            reason = reason if reason in TLS_REASONS else ('none' if reason is None else 'other')
            increment(self.tls_errors,library+'/'+reason)
            code = getattr(error,'verify_code',None)
            increment(self.verify_codes,str(code) if type(code) is int and 0<=code<=9999
                      else ('none' if code is None else 'other'))
        if phase!='mailbox_request':
            return
        message = error.args[0] if error.args and type(error.args[0]) is str else None
        category = MAILBOX_CHECKS.get(message)
        if category is None:
            if type(message) is str and message.startswith('independent public Ed25519 verification failed: resource-'):
                category = 'frame_signature'
            else:
                category = next((name for kind,name in ((json.JSONDecodeError,'json_decode'),
                    (UnicodeError,'unicode_decode'),(KeyError,'key_error'),(TypeError,'type_error'),
                    (ValueError,'value_error'),(subprocess.SubprocessError,'subprocess_error')) if isinstance(error,kind)), 'other')
        increment(self.mailbox_checks,category)
        # Inspect only locals already captured at the failing original check.
        # No new parsing, time sample, IO, request or assertion is dispatched.
        local = {}
        trace = error.__traceback__
        while trace is not None:
            if trace.tb_frame.f_code in (ResourceMailboxGate.handle.__code__,ResourceMailboxGate.validate_frame.__code__):
                local = trace.tb_frame.f_locals
            trace = trace.tb_next
        value,frame,box = local.get('value'),local.get('frame'),local.get('box')
        clauses = {}
        if category=='invalid_mailbox_creation':
            shape = isinstance(value,dict) and set(value)==set('format request_id locator read_cap_hash created_at expires_at frame'.split())
            clauses = dict(create_method=local.get('method')=='POST',create_object_shape=shape)
            if shape:
                clauses.update(create_format=type(value['format']) is int and value['format']==1,
                    create_request_id=type(value['request_id']) is str and re.fullmatch('(?:link|di)_[0-9a-f]{64}',value['request_id']) is not None,
                    create_locator=type(value['locator']) is str and re.fullmatch('[0-9a-f]{64}',value['locator']) is not None,
                    create_capability_hash=value['read_cap_hash']==local.get('cap_hash'),
                    create_first_role=isinstance(value['frame'],dict) and value['frame'].get('role')=='request')
        elif category=='invalid_frame_envelope':
            shape = isinstance(frame,dict) and set(frame)==set('format request_id locator role writer_host_public_key frame_id created_at expires_at ciphertext_base64 signature'.split())
            clauses = dict(frame_object_shape=shape)
            if shape:
                clauses.update(frame_format=type(frame['format']) is int and frame['format']==1,
                    frame_writer=frame['writer_host_public_key']==local.get('key'),
                    frame_role=frame['role'] in {'request','owner','selection','administrator','owner_finalization','commit','outcome','proofs'},
                    frame_id=type(frame['frame_id']) is str and re.fullmatch('[0-9a-f]{64}',frame['frame_id']) is not None,
                    frame_mailbox_tuple=isinstance(box,dict) and all(frame[name]==box.get(name) for name in ('request_id','locator','created_at','expires_at')))
        elif category in {'invalid_mailbox_window','invalid_original_window'}:
            created,expires,now = local.get('created'),local.get('expires'),local.get('now')
            if all(isinstance(item,datetime) for item in (created,expires,now)):
                clauses = dict(window_future=created.timestamp()<=now.timestamp()+30,window_unexpired=now<expires,
                    window_bounds=60<=(expires-created).total_seconds()<=86400,
                    window_original_lifetime=(expires-created).total_seconds()==300)
        elif category=='conflicting_mailbox_creation':
            prior = local.get('prior')
            if isinstance(prior,dict) and isinstance(value,dict):
                clauses = dict(retry_live=not prior.get('deleted',True),
                    retry_terms=prior.get('creation')=={name:value.get(name) for name in prior.get('creation',{})},
                    retry_first_frame=prior.get('first')==local.get('raw'))
        for clause,passed in clauses.items():
            if not passed:
                increment(self.mailbox_clauses,clause)

    def checkpoint(self, generation):
        while generation in self.park_targets and not self.closed.is_set():
            self.parked.add(generation)
            self.condition.notify_all()
            self.condition.wait()
        self.parked.discard(generation)

    def park_accepted(self, timeout=1):
        until = min(self.deadline,time.monotonic()+timeout)
        with self.condition:
            check(not self.park_targets, 'resource fixture transport already parked')
            self.park_targets = set(self.clients)
            before = self.counts()
            while (self.park_targets & self.clients.keys())-self.parked:
                remaining = until-time.monotonic()
                check(remaining>0, 'resource fixture accepted-stream barrier unavailable')
                self.condition.wait(remaining)
            live = tuple(sorted(self.park_targets & self.parked))
            self.last_barrier = dict(snapshot_streams=len(self.park_targets),parked_streams=len(live),
                drained_streams=len(self.park_targets-self.clients.keys()),snapshot_counts=list(before),
                acknowledged_counts=list(self.counts()))
            check(self.last_barrier['snapshot_streams']==self.last_barrier['parked_streams']+self.last_barrier['drained_streams'],
                  'resource fixture stream neither parked nor drained')
        check(set(live)<=set(self.live_parked_generations()), 'resource fixture parked stream is not live')
        return live

    def live_parked_generations(self):
        with self.condition:
            return [generation for generation in self.parked if generation in self.clients and self.live(generation)]

    def live(self, generation):
        if generation not in self.clients:
            return False
        try:
            return self.clients[generation]['raw'].recv(1,socket.MSG_PEEK|socket.MSG_DONTWAIT)!=b''
        except BlockingIOError:
            return True
        except OSError:
            return False

    def live_holds(self, request_id, pid, key):
        with self.condition:
            return [generation for generation,rid in self.held.items()
                    if rid==request_id and generation in self.clients
                    and self.clients[generation]['pid']==pid and self.clients[generation]['key']==key
                    and self.socket_owner(*self.clients[generation]['tuple'],self.host_keys)==pid
                    and self.live(generation)]

    def stored_request(self, request_id, writer):
        with self.condition:
            return sum(frame['role']=='request' and frame['writer_host_public_key']==writer
                       for box in self.boxes.values() if box['request_id']==request_id
                       for frame,_raw in box['frames'].values())

    def release_accepted(self):
        with self.condition:
            self.park_targets.clear()
            self.condition.notify_all()

    def release(self):
        self.released.set()
        with self.condition:
            self.condition.notify_all()

    def close(self):
        self.closed.set()
        self.release_accepted()
        self.release()
        with self.condition:
            streams = [client['raw'] for client in self.clients.values()]
        for raw in streams:
            try:
                raw.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if self.thread is not None:
            self.server.shutdown()
            self.thread.join(timeout=1)
        self.server.server_close()

    def validate_frame(self, frame, raw, key, box):
        check(isinstance(frame,dict) and set(frame)==set('format request_id locator role writer_host_public_key frame_id created_at expires_at ciphertext_base64 signature'.split())
              and type(frame['format']) is int and frame['format']==1 and frame['writer_host_public_key']==key
              and frame['role'] in {'request','owner','selection','administrator','owner_finalization','commit','outcome','proofs'}
              and re.fullmatch('[0-9a-f]{64}',frame['frame_id']) is not None
              and all(frame[name]==box[name] for name in ('request_id','locator','created_at','expires_at')),
              'resource fixture invalid frame envelope')
        ciphertext = base64.b64decode(frame['ciphertext_base64'],validate=True)
        check(16<=len(ciphertext)<=8*1024*1024 and len(raw)<=8*1024*1024, 'resource fixture frame bound')
        ad = '\n'.join(['peerspan-decentralized-frame-v1',frame['request_id'],frame['locator'],frame['role'],key,
                        frame['frame_id'],frame['created_at'],frame['expires_at']])
        message = ('peerspan-decentralized-frame-envelope-v1\n'+ad+'\n'+digest(ciphertext)).encode()
        self.verify_signature(key,frame['signature'],message,'resource-'+frame['frame_id'])

    def handle(self, stream, generation, key):
        data = bytearray()
        while b'\r\n\r\n' not in data:
            check(len(data)<16384, 'resource fixture header bound')
            data.extend(stream.recv(4096))
        head,body = bytes(data).split(b'\r\n\r\n',1)
        lines = head.decode('ascii').split('\r\n')
        method,path,version = lines[0].split(' ')
        headers = {}
        for line in lines[1:]:
            name,separator,value = line.partition(':')
            name = name.lower()
            check(separator and name not in headers, 'resource fixture invalid header')
            headers[name] = value.strip()
        check(version=='HTTP/1.1' and len(lines)<=65 and 'transfer-encoding' not in headers,
              'resource fixture invalid HTTP framing')
        length = headers.get('content-length','0')
        check(re.fullmatch('0|[1-9][0-9]*',length) is not None and int(length)<=8*1024*1024,
              'resource fixture request body bound')
        while len(body)<int(length):
            body += stream.recv(min(65536,int(length)-len(body)))
        check(len(body)==int(length), 'resource fixture request pipelining')
        auth = headers.get('authorization','')
        check(re.fullmatch('Bearer [0-9a-f]{64}',auth) is not None, 'resource fixture missing exact capability')
        cap_hash = digest(auth[7:].encode())
        matched = re.fullmatch('/bootstrap/v1/mailboxes(?:/([0-9a-f]{64})(/frames)?)?',path)
        check(matched is not None, 'resource fixture unsupported route')
        locator,append = matched.groups()
        value = json.loads(body,object_pairs_hook=exact) if body else None
        status,payload = 200,None
        with self.condition:
            if locator is None:
                check(method=='POST' and isinstance(value,dict) and set(value)==set('format request_id locator read_cap_hash created_at expires_at frame'.split())
                      and type(value['format']) is int and value['format']==1
                      and re.fullmatch('(?:link|di)_[0-9a-f]{64}',value['request_id']) is not None
                      and re.fullmatch('[0-9a-f]{64}',value['locator']) is not None
                      and value['read_cap_hash']==cap_hash and value['frame']['role']=='request',
                      'resource fixture invalid mailbox creation')
                created,expires = parse_time(value['created_at']),parse_time(value['expires_at'])
                now = datetime.now(timezone.utc)
                check(created.timestamp()<=now.timestamp()+30 and now<expires
                      and 60<=(expires-created).total_seconds()<=86400, 'resource fixture invalid mailbox window')
                if value['request_id'].startswith('link_'):
                    check((expires-created).total_seconds()==300, 'resource fixture invalid original window')
                raw = frame_slice(body)
                self.validate_frame(value['frame'],raw,key,value)
                locator = value['locator']
                prior = self.boxes.get(locator)
                if prior is None:
                    check(len(self.boxes)<16, 'resource fixture mailbox quota')
                    self.boxes[locator] = {**{name:value[name] for name in ('request_id','locator','read_cap_hash','created_at','expires_at')},
                        'creation':{name:value[name] for name in ('format','request_id','locator','read_cap_hash','created_at','expires_at')},
                        'first':raw,'frames':{value['frame']['frame_id']:(value['frame'],raw)},'deleted':False}
                    status = 201
                else:
                    check(not prior['deleted'] and prior['creation']=={name:value[name] for name in prior['creation']}
                          and prior['first']==raw, 'resource fixture conflicting mailbox creation')
                payload = compact(dict(request_id=value['request_id'],locator=locator))
            else:
                box = self.boxes.get(locator)
                if box is None or box['deleted']:
                    status,payload = 404,compact(dict(code='not_found',error='not found',required_ids=[]))
                else:
                    check(box['read_cap_hash']==cap_hash and datetime.now(timezone.utc)<parse_time(box['expires_at']),
                          'resource fixture wrong capability or expired mailbox')
                    if append:
                        check(method=='POST' and isinstance(value,dict) and set(value)=={'frame'}, 'resource fixture invalid append')
                        raw = frame_slice(body)
                        frame = value['frame']
                        self.validate_frame(frame,raw,key,box)
                        prior = box['frames'].get(frame['frame_id'])
                        check(prior is None or prior[1]==raw, 'resource fixture conflicting frame')
                        check(prior is not None or len(box['frames'])<64, 'resource fixture frame quota')
                        box['frames'][frame['frame_id']] = frame,raw
                        payload = compact(dict(frame_id=frame['frame_id']))
                    elif method=='GET':
                        check(not body, 'resource fixture GET body')
                        if box['request_id'].startswith('link_') and not self.released.is_set():
                            self.held[generation] = box['request_id']
                            self.condition.notify_all()
                            while not self.released.is_set() and not self.closed.is_set():
                                self.checkpoint(generation)
                                self.condition.wait(.02)
                            self.held.pop(generation,None)
                        frames = sorted(box['frames'].values(),key=lambda item:tuple(item[0][name] for name in ('role','writer_host_public_key','frame_id')))
                        prefix = compact({name:box[name] for name in ('request_id','created_at','expires_at')})
                        payload = b'{"format":1,'+prefix[1:-1]+b',"frames":['+b','.join(raw for _frame,raw in frames)+b']}'
                    else:
                        check(method=='DELETE' and not body, 'resource fixture invalid method')
                        box['frames'].clear()
                        box['deleted'] = True
                        status,payload = 204,b''
        check(payload is not None and len(payload)<=48*1024*1024, 'resource fixture response bound')
        stream.sendall(('HTTP/1.1 '+str(status)+' Resource\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: '
                        +str(len(payload))+'\r\n\r\n').encode()+payload)
