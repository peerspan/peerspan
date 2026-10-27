#!/usr/bin/env python3
"""Independent completion-only QUIC history/router controls (merged PR122).

Reuse an already applied stopped actual pair. The raw public wire client uses
each actual host's state in place and asserts NO outbound server-pin, relay,
NAT or first-application property. These eight controls cover only the isolated
server ALPN dispatcher and immutable participant history/retry after expiry.
"""
from __future__ import annotations

import argparse
from datetime import datetime,timedelta
import json
from pathlib import Path
import socket
import subprocess
import time

from decentralized_complete_link import packet_message,table_rows
from decentralized_fixtures import FixtureKeys,b64,lines,raw_json,sha,unb64
from decentralized_owner_preview import authority_rows
from decentralized_runtime import CreationSuite
from decentralized_storage import CheckFailure,require
from decentralized_vectors import strict_output


PIN="088bdea41a80834fad8f111bd9bbdbdf9709e8e4"
ALPN="peerspan-completion/1"
CASES=["historical_exact_participant_get_after_original_deadlines",
       "exact_complete_post_retry_preserves_original_outcome_and_authority",
       "nonparticipant_cannot_read_or_post_other_participants_operation",
       "completion_router_and_normal_unknown_key_policy_remain_isolated"]


class CompletionTransport:
    def __init__(self,args,keys):
        self.args,self.keys=args,keys
        self.rows,self.trace,self.hosts,self.addresses=[],[],{},{}
        self.prior_passed=set()
        for path in args.prior_results:
            self.prior_passed|={row["name"] for row in strict_output(path.read_bytes())["rows"] if row["passed"]}
        self.wire_count=0
        self.receipts=args.work_dir/"wire";self.receipts.mkdir(mode=0o700)
        self.operations={};anchors=[]
        for label,binary in (("owner",args.owner),("requester",args.requester)):
            root=args.work_dir/label;root.mkdir(mode=0o700)
            s=CreationSuite(binary,root,keys);s.host.state=args.retained_dir/label/"state";self.hosts[label]=s
            require(not (s.host.state/"admin.sock").exists(),"retained actual pair is not stopped")
            rows=table_rows(s.host,"dec_operations","request_id,record,locally_applied,activation_id,manifest_id")
            require(len(rows)==1 and rows[0][2]==1,"completion fixture lacks one actual applied participant outcome")
            identifier,encoded,_,activation_id,manifest_id=rows[0];r=strict_output(encoded.encode())
            require(set(r)=={"format","activation_base64","catalog_base64","outcome_packet_base64","applied_at"} and r["format"]==1,
                "retained operation has another record shape")
            self.operations[label]=(identifier,encoded,r,activation_id,manifest_id)
            activation=strict_output(unb64(r["activation_base64"]))
            payload=strict_output(unb64(activation["request"]["payload_base64"]))
            anchors.append(datetime.fromisoformat(payload["expires_at"].replace("Z","+00:00"))+timedelta(seconds=1))
            for entry in strict_output(unb64(r["catalog_base64"]))["objects"]:
                if entry["kind"]=="activation":continue
                body=strict_output(unb64(entry["body_base64"]));p=strict_output(unb64(body["payload_base64"]))
                if "not_after" in p:anchors.append(datetime.fromisoformat(p["not_after"].replace("Z","+00:00"))+timedelta(seconds=1))
            for record, in table_rows(s.host,"dec_clock","record"):
                anchors.append(datetime.fromisoformat(strict_output(record.encode())["largest_local_time"].replace("Z","+00:00")))
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as reserved:
                reserved.bind(("127.0.0.1",0));address="127.0.0.1:"+str(reserved.getsockname()[1])
            self.addresses[label]=address
            s.host.run_arguments=["--peer-listen",address,"--advertise",address]
        require(self.operations["owner"][0]==self.operations["requester"][0] and
            self.operations["owner"][3:]==self.operations["requester"][3:],
            "retained actual participants applied different operations")
        self.now=max(anchors).strftime("%Y-%m-%dT%H:%M:%SZ")
        for label,s in self.hosts.items():
            clock=s.root/"authority-clock";clock.write_text(self.now);clock.chmod(0o600)
            s.host.environment.update(PEERSPAN_DEC_TEST_MODE="1",PEERSPAN_DEC_TEST_CLOCK_FILE=str(clock))
        self.request_id=self.operations["owner"][0]
        self.path="/bootstrap/v1/operations/"+self.request_id

    def complete_body(self,label):
        # Each local result retains its own exact verified carrier/proof aliases;
        # matching operation IDs do not impose a cross-host preferred alias.
        record=self.operations[label][2]
        return {"activation":strict_output(unb64(record["activation_base64"])),
            "catalog":strict_output(unb64(record["catalog_base64"]))}

    def snapshot(self,label):
        s=self.hosts[label]
        return {"authority_sha256":authority_rows(s),"clock_sha256":sha(raw_json(table_rows(s.host,"dec_clock","*"))),
            "intents_sha256":sha(raw_json([[r[0],r[1],None if r[2] is None else sha(r[2])]
                for r in table_rows(s.host,"dec_intents","intent_id,record,secret")]))}

    def wire(self,target,sender,method,path,body=None,alpn=ALPN):
        args=[str(self.args.probe),"--address",self.addresses[target],"--alpn",alpn,"--method",method,"--path",path]
        if sender is None:
            args += ["--seed-hex",sha(lines("peerspan-independent-dec-fixture-only-v1","completion-outsider"))]
        else:args += ["--state",str(self.hosts[sender].host.state)]
        data=None if body is None else raw_json(body)
        if data is not None:args.append("--body-stdin")
        r=subprocess.run(args,input=data,capture_output=True,env=self.hosts[target].host.environment,timeout=40)
        self.wire_count+=1;p=self.receipts/f"{self.wire_count:03}"
        for suffix,raw in (("stdout",r.stdout),("stderr",r.stderr)):
            file=p.with_suffix("."+suffix);file.write_bytes(raw);file.chmod(0o600)
        value=None if r.returncode else strict_output(r.stdout)
        if value is not None:require(set(value)=={"status","body"} and type(value["status"]) is int,"raw client wrapper differs")
        p.with_suffix(".meta.json").write_bytes(raw_json({"target":target,"sender":sender or "fixture-outsider",
            "alpn":alpn,"method":method,"path":path,"exit":r.returncode,"request_sha256":None if data is None else sha(data),
            "raw_client_does_not_check_server_pin":True}))
        return value,r

    def history(self,label,value):
        require(value is not None and value["status"]==200,"participant completion did not return200")
        body=value["body"];r=self.operations[label][2]
        require(set(body)=={"outcome","activation","catalog"} and
            body["outcome"]==strict_output(unb64(r["outcome_packet_base64"])) and
            body["activation"]==strict_output(unb64(r["activation_base64"])) and
            body["catalog"]==strict_output(unb64(r["catalog_base64"])),"historical completion rewrote exact signed outcome/proof bodies")
        packet=body["outcome"];payload=strict_output(unb64(packet["payload_base64"]))
        require(packet["writer_host_public_key"]==self.hosts[label].identity["public_key"] and
            payload["request_id"]==self.request_id and payload["activation_sha256"]==sha(unb64(r["activation_base64"])) and
            payload["applied_at"]==r["applied_at"],"outcome changed its participant/application pins")
        self.hosts[label].verify_raw(packet["writer_host_public_key"],packet_message(packet),packet["host_signature"])
        rows=table_rows(self.hosts[label].host,"dec_operations","record"," WHERE request_id=?",(self.request_id,))
        require(rows==[(self.operations[label][1],)],"historical transport changed the stored exact local outcome")

    def case(self,label,name,function):
        if label+"/"+name in self.prior_passed:return
        began=time.monotonic()
        try:function()
        except BaseException as e:
            self.rows.append({"name":label+"/"+name,"passed":False,"error_type":type(e).__name__,
                "detail":str(e) if isinstance(e,CheckFailure) else "fixture/transport failure"});print("FAIL "+label+"/"+name,flush=True);raise
        self.rows.append({"name":label+"/"+name,"passed":True,"seconds":round(time.monotonic()-began,3)})
        print("PASS "+label+"/"+name,flush=True)

    def run(self):
        for label,s in self.hosts.items():
            s.host.start();s.identity=s.host.api("GET","/v1/host")
        for label in ("owner","requester"):
            sender="requester" if label=="owner" else "owner"
            def get():
                before=self.snapshot(label);value,_=self.wire(label,sender,"GET",self.path);self.history(label,value)
                require(self.snapshot(label)==before,"historical GET changed authority/guard/selected provider/intent")
            self.case(label,CASES[0],get)
            def post():
                before=self.snapshot(label);value,_=self.wire(label,sender,"POST","/bootstrap/v1/activations",self.complete_body(label));self.history(label,value)
                require(self.snapshot(label)==before,"exact completion POST retry reapplied authority/advanced guard/signed another intent")
            self.case(label,CASES[1],post)
            def outsider():
                before=self.snapshot(label)
                for method,path,body in (("GET",self.path,None),("POST","/bootstrap/v1/activations",self.complete_body(label))):
                    value,_=self.wire(label,None,method,path,body)
                    require(value is not None and value["status"]==403 and type(value["body"]) is dict and
                        value["body"].get("code")=="forbidden" and "outcome" not in value["body"],"nonparticipant completion disclosed or applied an operation")
                require(self.snapshot(label)==before,"nonparticipant attempt changed authority/private selection")
            self.case(label,CASES[2],outsider)
            def isolation():
                before=self.snapshot(label)
                for method,path,status,code in (("GET","/v1/host",404,"not_found"),
                    ("POST",self.path,405,None),("GET",self.path+"/",404,"not_found")):
                    value,_=self.wire(label,None,method,path)
                    require(value is not None and value["status"]==status and type(value["body"]) is dict and
                        (code is None or value["body"].get("code")==code) and "outcome" not in value["body"],
                        "completion ALPN exposed another router or accepted a method/path alias")
                for alpn in ("peerspan-peer/1","peerspan-state-repair/1"):
                    value,r=self.wire(label,None,"GET","/v1/host",alpn=alpn)
                    require(value is None and r.returncode!=0 and not r.stdout,"completion possession opened an unknown-key normal/repair application response")
                require(self.snapshot(label)==before,"isolated routing attempt changed authority/guard/provider")
            self.case(label,CASES[3],isolation)
        self.trace.append({"decision_time_after_original_finite_deadlines":self.now,"original_operation_ids":{label:v[0] for label,v in self.operations.items()},
            "actual_daemon_keys_stayed_in_place":True,"no_outbound_server_pin_relay_nat_or_first_apply_claim":True,
            "raw_status_body_client_does_not_observe_allow_header_or_before_stream_phase":True})


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--list-cases",action="store_true")
    p.add_argument("--prior-results",type=Path,action="append",default=[],help="Skip individual passing cases from preserved actual receipts")
    for n in ("owner","requester","probe","retained-dir","work-dir","results"):p.add_argument("--"+n,type=Path)
    args=p.parse_args()
    if args.list_cases:print(json.dumps({"contract_pin":PIN,"cases":[label+"/"+name for label in ("owner","requester") for name in CASES],"product_execution":False},indent=2));return 0
    if any(getattr(args,n) is None for n in ("owner","requester","probe","retained_dir","work_dir","results")):p.error("all path arguments required")
    for n in ("owner","requester","probe","retained_dir","work_dir","results"):setattr(args,n,getattr(args,n).resolve())
    args.work_dir.mkdir(mode=0o700,parents=True,exist_ok=False)
    keys=FixtureKeys();suite=CompletionTransport(args,keys);failure=detail=None;began=time.monotonic()
    try:suite.run()
    except BaseException as e:failure,detail=type(e).__name__,str(e) if isinstance(e,CheckFailure) else "fixture/transport failure"
    finally:
        for s in reversed(list(suite.hosts.values())):
            try:s.host.stop()
            except BaseException as e:failure=failure or type(e).__name__;suite.rows.append({"name":"cleanup","passed":False,"error_type":type(e).__name__})
        keys.close()
    support=("decentralized_complete_link.py","decentralized_fixtures.py","decentralized_owner_preview.py","decentralized_runtime.py",
        "decentralized_storage.py","decentralized_vectors.py","decentralized_requester.py","decentralized_helper.py","decentralized_direct_carrier.py")
    result={"contract_pin":PIN,"implementation_source_read":False,"suite_sha256":sha(Path(__file__).read_bytes()),
        "support_sha256":{n:sha(Path(__file__).with_name(n).read_bytes()) for n in support},
        "artifacts":{n:{"path":str(getattr(args,n)),"sha256":sha(getattr(args,n).read_bytes())} for n in ("owner","requester","probe")},
        "rows":suite.rows,"trace":suite.trace,"failure":failure,"detail":detail,"seconds":round(time.monotonic()-began,3),
        "prior_results":[{"path":str(path.resolve()),"sha256":sha(path.read_bytes())} for path in args.prior_results],
        "scope":"server completion-only QUIC historical participant GET/POST retry and isolation, no client pin, first application, relay, NAT, installed or milestone claim",
        "passed":failure is None and len(suite.rows)+len(suite.prior_passed)==8 and all(r["passed"] for r in suite.rows)}
    args.results.parent.mkdir(parents=True,exist_ok=True);args.results.write_text(json.dumps(result,indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__=="__main__":raise SystemExit(main())
