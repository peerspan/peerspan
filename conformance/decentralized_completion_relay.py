#!/usr/bin/env python3
"""Independent PR125 completed-resume controls through observable relay4 fixtures.

The two operators implement only public opaque relay wire. Actual participant
keys remain in their original daemon stores. The operators save PUBLIC TLS
certificates and forwarding observations, never QUIC plaintext. Production
helper conformance, malicious outcome parsing, client wrong-server-pin, NAT,
first application, pressure and installed behavior are separate scopes.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import threading
import time

from decentralized_complete_link import table_rows
from decentralized_completion_transport import CompletionTransport
from decentralized_fixtures import FixtureKeys,lines,raw_json,sha,unb64
from decentralized_helper import ClientIdentity,RelayClient
from decentralized_requester import VIEW
from decentralized_storage import CheckFailure,UnixHTTP,require
from decentralized_vectors import strict_output


PIN="8e39ffe568e5d0dcd888903875d1b740a9a50169"
CASES=["go_completed_resume_uses_original_optional_relay",
       "rust_completed_resume_uses_original_optional_relay",
       "go_completed_resume_uses_replacement_with_original_helper_gone",
       "rust_completed_resume_uses_replacement_with_original_helper_gone",
       "helper_outage_preserves_both_linked_results_with_transport_attention",
       "relay_path_does_not_make_outsider_an_operation_participant"]


class Operator:
    def __init__(self,root,keys,label,public_keys):
        self.root=root/label;self.root.mkdir(mode=0o700)
        self.identity=ClientIdentity(keys,"observable-"+label)
        self.observations=self.root/"observations.jsonl"
        self.certificates=self.root/"public-certificates";self.certificates.mkdir(mode=0o700)
        self.configuration=self.root/"operator.json"
        self.configuration.write_bytes(raw_json({"key_file":str(self.identity.pem),
            "certificate_file":str(self.identity.cert),"public_keys":public_keys,
            "observations":str(self.observations),"certificate_directory":str(self.certificates)}))
        self.configuration.chmod(0o600);self.process=None

    def start(self):
        self.stderr=(self.root/"operator.stderr").open("wb")
        self.process=subprocess.Popen(["/usr/bin/node",str(Path(__file__).with_name("decentralized_observable_relay.js")),
            str(self.configuration)],stdout=subprocess.PIPE,stderr=self.stderr,start_new_session=True)
        require(select.select([self.process.stdout],[],[],5)[0],"owned reference relay did not announce its listener")
        self.metadata=strict_output(self.process.stdout.readline())
        require(set(self.metadata)=={"address","public_key"} and self.metadata["public_key"]==self.identity.public,
            "owned reference relay announced another identity")
        (self.root/"public-info.json").write_bytes(raw_json(self.metadata))

    def events(self):
        if not self.observations.exists():return []
        data=self.observations.read_bytes()
        # appendFileSync emits one complete newline-terminated event at a time.
        return [strict_output(line) for line in data.split(b"\n")[:-1] if line]

    def registered(self,public_keys):
        expected={sha(unb64(key)) for key in public_keys};deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            require(self.process.poll() is None,"owned reference relay exited before registrations")
            events=self.events()
            if {e["host"] for e in events if e["kind"]=="auth_ok"}>=expected:return
            time.sleep(.025)
        raise CheckFailure("actual participant TLS registrations were not observed within10s")

    def stop(self):
        if self.process is None:return
        process,self.process=self.process,None
        if process.poll() is None:os.killpg(process.pid,signal.SIGTERM)
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5)
            raise CheckFailure("owned reference relay did not stop within5s")
        finally:self.stderr.close()
        require(process.returncode==0,"owned reference relay failed; see operator stderr")


class OutsiderBridge:
    """Owned UDP<->opaque relay wire bridge; no actual daemon key is loaded."""
    def __init__(self,operator,identity,target):
        self.client=RelayClient(operator,identity);self.client.auth()
        self.target=bytes.fromhex(sha(unb64(target)));self.stop_event=threading.Event()
        self.udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.udp.bind(("127.0.0.1",0));self.udp.settimeout(.1)
        self.address="127.0.0.1:"+str(self.udp.getsockname()[1]);self.remote=None;self.failure=None
        self.client.stream.settimeout(.1)
        self.thread=threading.Thread(target=self.pump,daemon=True);self.thread.start()

    def pump(self):
        # Read complete relay records without discarding a partial record on a
        # short poll timeout; TLS may split a header/body across arbitrary reads.
        pending=bytearray()
        try:
            while not self.stop_event.is_set():
                ready=select.select([self.udp,self.client.stream],[],[],.1)[0]
                if self.udp in ready:
                    data,remote=self.udp.recvfrom(1501)
                    require(1<=len(data)<=1500,"owned raw client's UDP datagram exceeds relay wire bound")
                    self.remote=remote;self.client.send(1,self.target+data)
                if self.client.stream not in ready and not self.client.stream.pending():continue
                try:data=self.client.stream.recv(8192)
                except TimeoutError:continue
                require(data,"owned relay bridge closed unexpectedly");pending.extend(data)
                while len(pending)>=3:
                    kind,length=pending[0],int.from_bytes(pending[1:3],"big")
                    require(length<=1532,"owned relay bridge received an oversized frame")
                    if len(pending)<3+length:break
                    body=bytes(pending[3:3+length]);del pending[:3+length]
                    if kind==2:
                        require(body[:32]==self.target and len(body)>32,"relay bridge source does not match its pinned target")
                        if self.remote is not None:self.udp.sendto(body[32:],self.remote)
                    else:require(kind in (3,4),"owned relay bridge received an unexpected direction/type")
        except BaseException as error:
            if not self.stop_event.is_set():self.failure=error

    def close(self):
        self.stop_event.set();self.client.close();self.udp.close()
        self.thread.join(timeout=2)
        require(not self.thread.is_alive(),"owned relay bridge thread did not stop")
        if self.failure is not None:raise self.failure


class CompletionRelay(CompletionTransport):
    def __init__(self,args,keys):
        super().__init__(args,keys)
        self.outsider=ClientIdentity(keys,"completion-relay-outsider")
        self.public_keys={label:strict_output(unb64(r[2]["outcome_packet_base64"]))["writer_host_public_key"]
            for label,r in self.operations.items()}
        self.operators=[Operator(args.work_dir,keys,name,list(self.public_keys.values())+[self.outsider.public])
            for name in ("helper-one","helper-two")]
        if args.after_go_get_dir:
            original=strict_output((args.after_go_get_dir/"wire"/"relay-outsider-001.stdout").read_bytes())
            metadata=strict_output((args.after_go_get_dir/"wire"/"relay-outsider-001.meta.json").read_bytes())
            observed=[strict_output(line) for line in (args.after_go_get_dir/"helper-two"/"observations.jsonl").read_bytes().splitlines()]
            require(original["status"]==403 and original["body"]["code"]=="forbidden" and metadata["exit"]==0 and
                metadata["target"]=="owner" and metadata["method"]=="GET" and metadata["path"]==self.path and
                any(event["kind"]=="actual_tls_host" and event["public_key"]==self.outsider.public for event in observed),
                "retained already evaluated Go GET does not match this exact operation/actual outsider key")
            self.trace.append({"prior_go_outsider_get403_not_repeated":True,
                "original_immediate_post_refusal_remains_unresolved_client_close_precondition":True,
                "continuation_is_authorization_isolation_after_real_route_lifetime_not_cleanup_fix_evidence":True})
        self.blocked=[];self.old_endpoints=set();self.old_quic_endpoints=set();self.configurations={};self.local_responses=0
        for label,s in self.hosts.items():
            for record, in table_rows(s.host,"dec_pending","record"):
                p=strict_output(record.encode())
                self.old_endpoints|={e["address"] for e in p["carrier_endpoints"] if e["kind"]=="participant"}
            for record, in table_rows(s.host,"dec_contacts","record"):
                for encoded in strict_output(record.encode())["contacts_base64"]:
                    contact=strict_output(unb64(encoded));payload=strict_output(unb64(contact["payload_base64"]))
                    self.old_endpoints.update(payload["bootstrap_addresses"])
                    self.old_quic_endpoints.update(payload["quic_addresses"])
            configuration=s.root/"transport.json";self.configurations[label]=configuration
        self.old_quic_endpoints.update(self.old_endpoints)
        for label,s in self.hosts.items():
            # Reserve the old public hints later; select different actual
            # listeners now so they cannot accidentally make an old hint live.
            for _ in range(8):
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                    sock.bind(("127.0.0.1",0));address="127.0.0.1:"+str(sock.getsockname()[1])
                if address not in self.old_quic_endpoints and address not in self.addresses.values():break
            else:raise CheckFailure("owned actual peer listener repeatedly collided with old retained hints")
            self.addresses[label]=address
            # The actual new peer listeners stay unadvertised. Dead explicit
            # hints are transport configuration only, not rewritten history.
            s.host.run_arguments=["--peer-listen",address,"--transport-config",str(self.configurations[label])]
        self.retired_transport={}
        self.before={label:self.immutable(label) for label in self.hosts}

    def immutable(self,label):
        result=self.snapshot(label);s=self.hosts[label]
        result["operations"]=sha(raw_json(table_rows(s.host,"dec_operations","*")))
        pending=[];caps={}
        for request,record,secret,cap in table_rows(s.host,"dec_pending","request_id,record,secret,terminal_read_cap"):
            p=strict_output(record.encode());require(secret is None,"historical relay fixture still has a private pairing secret")
            require(cap is None or len(cap)==32,"terminal read capability has another private wire length")
            if cap is not None:caps[request]=sha(cap)
            for field in ("carrier_endpoints","outbound"):p.pop(field,None)
            pending.append([request,p])
        frames={(request,sha(record.encode())) for request,record in table_rows(s.host,"dec_frames","request_id,record")}
        if label not in self.retired_transport:
            self.retired_transport[label]=(caps,frames)
            self.trace.append({"participant":label,"pairing_secret_is_null":True,
                "preexisting_terminal_read_cap_count":len(caps),"preexisting_sealed_frame_count":len(frames),
                "existing_transport_bytes_may_retire_but_never_be_created_or_changed":True})
        else:
            old_caps,old_frames=self.retired_transport[label]
            require(all(old_caps.get(request)==digest for request,digest in caps.items()) and frames<=old_frames,
                "completion resume recreated a terminal capability or resealed/new mailbox ciphertext after pairing-secret retirement")
        result["pending_pins"]=sha(raw_json(pending));return result

    def unchanged(self):
        require({label:self.immutable(label) for label in self.hosts}==self.before,
            "completed relay resume changed authority/guard/provider/signatures/consent/outcome or revived a secret/frame")

    def reserve_dead(self,address,kind):
        host,port=address.rsplit(":",1)
        require(host=="127.0.0.1","this bounded fixture requires retained loopback endpoint hints")
        sock=socket.socket(socket.AF_INET,kind)
        # A just-stopped retained daemon can leave TIME_WAIT connections on its
        # old listener port. Reuse permits binding that bounded dead endpoint,
        # never a live listener; the socket stays bound without listening.
        if kind==socket.SOCK_STREAM:sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        sock.bind((host,int(port)))
        self.blocked.append(sock);return address

    def new_dead(self,kind):
        for _ in range(8):
            sock=socket.socket(socket.AF_INET,kind);sock.bind(("127.0.0.1",0));self.blocked.append(sock)
            address="127.0.0.1:"+str(sock.getsockname()[1])
            if kind!=socket.SOCK_DGRAM or address not in self.addresses.values():return address
        raise CheckFailure("owned dead hints repeatedly collided with reserved future actual peer listeners")

    def configure(self,operator):
        for s in self.hosts.values():s.host.stop()
        for label,s in self.hosts.items():
            value={"format":1,"advertise_bootstrap":[self.dead_tcp],"advertise_quic":[self.dead_udp],
                "rendezvous":[],"relays":[dict(operator.metadata,token_file="-")],"publish_contacts":False}
            self.configurations[label].write_bytes(raw_json(value));self.configurations[label].chmod(0o600)
            s.host.start();s.identity=s.host.api("GET","/v1/host")
            require(s.identity["public_key"]==self.public_keys[label],"host restart replaced its actual participant key")
            self.verify_raw_history(label)
        operator.registered(self.public_keys.values());self.unchanged()

    def verify_raw_history(self,label):
        record=self.operations[label][2];packet=strict_output(unb64(record["outcome_packet_base64"]))
        from decentralized_complete_link import packet_message
        self.hosts[label].verify_raw(self.public_keys[label],packet_message(packet),packet["host_signature"])
        p=strict_output(unb64(packet["payload_base64"]))
        require(p["request_id"]==self.request_id and p["activation_sha256"]==sha(unb64(record["activation_base64"])) and
            p["applied_at"]==record["applied_at"],"retained actual participant outcome does not bind its immutable operation")

    def local(self,label,method,path,body=None):
        client=UnixHTTP(self.hosts[label].host.state/"admin.sock",timeout=35)
        began=time.monotonic()
        try:
            client.request(method,path,body=None if body is None else raw_json(body),
                headers={} if body is None else {"Content-Type":"application/json"})
            response=client.getresponse();raw=response.read(32*1024*1024+1);elapsed=time.monotonic()-began
            self.local_responses+=1;p=self.args.work_dir/("local-%03d"%self.local_responses)
            p.with_suffix(".json").write_bytes(raw);p.with_suffix(".json").chmod(0o600)
            p.with_suffix(".meta.json").write_bytes(raw_json({"label":label,"method":method,"path":path,
                "status":response.status,"seconds":round(elapsed,3),"body_sha256":sha(raw)}))
            require(response.status==200 and len(raw)<=32*1024*1024,"historical local completion response did not return bounded200")
            value=strict_output(raw);require(set(value)==VIEW and value["state"]=="linked" and
                value["request_id"]==self.request_id and value["activation_id"]==self.operations[label][3] and
                value["manifest_id"]==self.operations[label][4],"historical relay action changed its flat linked result or exposed a code")
            # One second covers local request setup/capture overhead; this is
            # not a change to the transport's single overall30s contract bound.
            require(elapsed<=31,"explicit completed resume exceeded the overall30s transport bound plus local capture overhead")
            return value
        finally:client.close()

    def resume(self,label,operator):
        route="/v2/link/requests/"+self.request_id
        before=self.local(label,"GET",route);start=len(operator.events())
        value=self.local(label,"POST",route+"/resume",{})
        require({k:v for k,v in value.items() if k not in ("attention","next")}==
            {k:v for k,v in before.items() if k not in ("attention","next")},"completion delivery changed immutable historical LINK_VIEW fields")
        require(not (set(value["attention"])-set(before["attention"])),
            "reachable participant completion returned new transport attention; see exact local response")
        source=sha(unb64(self.public_keys[label]));other="requester" if label=="owner" else "owner"
        target=sha(unb64(self.public_keys[other]));events=operator.events()[start:]
        forwards={(e["source"],e["destination"]) for e in events if e["kind"]=="forward"}
        require((source,target) in forwards and (target,source) in forwards,
            "explicit completed resume did not observe bidirectional actual-host relay datagrams")
        # A retained delivery reporting failure cannot be treated as observed
        # successful completion merely because encrypted packets were forwarded.
        for key,record in table_rows(self.hosts[label].host,"dec_outbox","target_key,record"):
            record=strict_output(record.encode())
            if key==self.public_keys[other] and record["kind"]=="activation":
                require(record["last_error_code"]=="-","completion delivery retained a transport/participant error")
        self.unchanged();self.trace.append({"sender":label,"operator":operator.root.name,
            "exact_participant_key":self.public_keys[other],"forwarded_event_first_sequence":events[0]["sequence"] if events else None,
            "forwarded_event_last_sequence":events[-1]["sequence"] if events else None,
            "linked_response_without_new_transport_attention":True,
            "inner_http_is_encrypted_not_passively_observed":True,"no_malformed_remote_outcome_coverage_claim":True})

    def outage(self):
        self.operators[1].stop()
        for label in self.hosts:
            before=self.local(label,"GET","/v2/link/requests/"+self.request_id)
            after=self.local(label,"POST","/v2/link/requests/"+self.request_id+"/resume",{})
            require(after["attention"],"all unavailable paths returned linked without actual transport attention")
            require({k:v for k,v in before.items() if k not in ("attention","next")}==
                {k:v for k,v in after.items() if k not in ("attention","next")},"helper outage rolled back a local completed result")
            self.unchanged()

    def outsider_case(self):
        # This runs before the outage test so helper-two is still alive. An
        # outer fixture identity and its inner raw client use the SAME owned
        # key; helper source assertions alone never substitute a participant.
        for target in self.hosts:
            bridge=OutsiderBridge(self.operators[1],self.outsider,self.public_keys[target])
            try:
                for method,path,body in (("GET",self.path,None),("POST","/bootstrap/v1/activations",self.complete_body(target))):
                    if target=="owner" and method=="GET" and self.args.after_go_get_dir:continue
                    if method=="POST" and self.args.isolate_route_expiry:
                        # The earlier raw client did not expose an observed
                        # graceful QUIC-close acknowledgment. Isolate this
                        # authorization check AFTER the existing maximum30s
                        # provisional-route lifetime using real time only.
                        print("ISOLATE "+target+" POST after real30s route lifetime",flush=True)
                        began=time.monotonic();time.sleep(30.05)
                        self.trace.append({"outsider_target":target,"before_fresh_post_real_wait_seconds":round(time.monotonic()-began,3),
                            "authority_clock_not_changed":self.now,"no_immediate_route_cleanup_or_fix_claim":True})
                        self.unchanged()
                    argv=[str(self.args.probe),"--address",bridge.address,"--alpn","peerspan-completion/1",
                        "--seed-hex",sha(lines("peerspan-independent-dec-fixture-only-v1","completion-relay-outsider")),
                        "--method",method,"--path",path]
                    if body is not None:argv.append("--body-stdin")
                    result=subprocess.run(argv,input=None if body is None else raw_json(body),capture_output=True,timeout=40)
                    self.wire_count+=1;p=self.receipts/("relay-outsider-%03d"%self.wire_count)
                    for suffix,data in (("stdout",result.stdout),("stderr",result.stderr)):
                        file=p.with_suffix("."+suffix);file.write_bytes(data);file.chmod(0o600)
                    p.with_suffix(".meta.json").write_bytes(raw_json({"target":target,"method":method,"path":path,
                        "exit":result.returncode,"raw_probe_does_not_check_server_pin":True,
                        "request_sha256":None if body is None else sha(raw_json(body))}))
                    require(result.returncode==0,"relay outsider raw request did not obtain a protocol response")
                    value=strict_output(result.stdout)
                    require(set(value)=={"status","body"} and value["status"]==403 and type(value["body"]) is dict and
                        value["body"].get("code")=="forbidden" and "outcome" not in value["body"],
                        "relay outsider gained participant disclosure/application or wrong denial")
            finally:bridge.close()
            self.unchanged()

    def run(self):
        for address in sorted(self.old_endpoints):self.reserve_dead(address,socket.SOCK_STREAM)
        for address in sorted(self.old_quic_endpoints):self.reserve_dead(address,socket.SOCK_DGRAM)
        self.dead_tcp=self.new_dead(socket.SOCK_STREAM);self.dead_udp=self.new_dead(socket.SOCK_DGRAM)
        self.trace.append({"retained_direct_tcp_hints_reserved_without_listeners":sorted(self.old_endpoints),
            "retained_contact_quic_hints_reserved_without_receivers":sorted(self.old_quic_endpoints),
            "new_advertised_dead_tcp":self.dead_tcp,"new_advertised_dead_udp":self.dead_udp,
            "new_actual_quic_listener_hints_not_advertised":dict(self.addresses),"guard_respecting_decision_time":self.now})
        one,two=self.operators
        positives={"relay/"+name for name in CASES[:4]}
        if positives<=self.prior_passed:
            self.trace.append({"four_passed_host_client_original_and_replacement_relay_controls_skipped":True})
            two.start();self.configure(two)
        else:
            one.start();self.configure(one)
            for label,index in (("owner",0),("requester",1)):
                self.case("relay",CASES[index],lambda label=label:self.resume(label,one))
            for s in self.hosts.values():s.host.stop()
            one.stop();two.start();self.configure(two)
            for label,index in (("owner",2),("requester",3)):
                self.case("relay",CASES[index],lambda label=label:self.resume(label,two))
        self.case("relay",CASES[5],self.outsider_case)
        self.case("relay",CASES[4],self.outage)

    def close(self):
        errors=[]
        for s in reversed(list(self.hosts.values())):
            try:s.host.stop()
            except BaseException as error:errors.append(error)
        for operator in self.operators:
            try:operator.stop()
            except BaseException as error:errors.append(error)
        for sock in self.blocked:sock.close()
        if errors:raise errors[0]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--list-cases",action="store_true")
    p.add_argument("--prior-results",type=Path,action="append",default=[],help="Skip actual already passing case names; preserve their separate attribution")
    p.add_argument("--after-go-get-dir",type=Path,help="Verify and skip the exact prior Go outsider GET403 substep")
    p.add_argument("--isolate-route-expiry",action="store_true",help="Use real30s old-route expiration before fresh same-key outsider POST; no immediate cleanup claim")
    for name in ("owner","requester","probe","retained-dir","work-dir","results"):p.add_argument("--"+name,type=Path)
    args=p.parse_args()
    if args.list_cases:print(json.dumps({"contract_pin":PIN,"cases":CASES,"product_execution":False},indent=2));return 0
    for name in ("owner","requester","probe","retained_dir","work_dir","results"):
        if getattr(args,name) is None:p.error("all paths required")
        setattr(args,name,getattr(args,name).resolve())
    if args.after_go_get_dir:
        args.after_go_get_dir=args.after_go_get_dir.resolve()
        if not args.prior_results or not args.isolate_route_expiry:p.error("Go GET continuation requires prior passing results and explicit route-expiry isolation")
    args.work_dir.mkdir(mode=0o700,parents=True,exist_ok=False)
    keys=FixtureKeys();suite=None;failure=detail=None;began=time.monotonic()
    try:suite=CompletionRelay(args,keys);suite.run()
    except BaseException as error:
        failure=type(error).__name__;detail=str(error) if isinstance(error,CheckFailure) else "fixture/transport failure"
    finally:
        if suite is not None:
            try:suite.close()
            except BaseException as error:failure=failure or type(error).__name__
        keys.close()
    support=("decentralized_observable_relay.js","decentralized_completion_transport.py","decentralized_helper.py",
        "decentralized_complete_link.py","decentralized_fixtures.py","decentralized_runtime.py",
        "decentralized_storage.py","decentralized_owner_preview.py","decentralized_vectors.py","decentralized_requester.py")
    result={"contract_pin":PIN,"implementation_source_read":False,"suite_sha256":sha(Path(__file__).read_bytes()),
        "support_sha256":{name:sha(Path(__file__).with_name(name).read_bytes()) for name in support},
        "artifacts":{name:{"path":str(getattr(args,name)),"sha256":sha(getattr(args,name).read_bytes())} for name in ("owner","requester","probe")},
        "retained_dir":str(args.retained_dir),"rows":[] if suite is None else suite.rows,"trace":[] if suite is None else suite.trace,
        "prior_results":[{"path":str(path.resolve()),"sha256":sha(path.read_bytes())} for path in args.prior_results],
        "failure":failure,"detail":detail,"seconds":round(time.monotonic()-began,3),
        "scope":"actual completed host-client resume through two independently instrumented relay4 operators under controlled direct unavailability; not production helper wire, malicious ACK, wrong-server-pin, NAT, pressure, installed or first-application coverage",
        "passed":failure is None and suite is not None and len(suite.rows)+len(suite.prior_passed)==6 and all(row["passed"] for row in suite.rows)}
    args.results.parent.mkdir(parents=True,exist_ok=True);args.results.write_text(json.dumps(result,indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__=="__main__":raise SystemExit(main())
