#!/usr/bin/env python3
"""Independent preproposal migration identity acceptance (public pin PR121).

One bounded legacy fixture constructs a bound original owner, its actually
linked selected-device host and an independent unbound host. Only public old
CLI/API operations and our own external SSH signer are used. New-mode identity
tests never sign, prepare a proposal, fence, select a provider or adopt. Actual
daemon keys stay in their original owned directories throughout.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
from types import SimpleNamespace

from decentralized_complete_link import table_rows
from decentralized_fixtures import FixtureKeys, b64, raw_json, sha, unb64
from decentralized_runtime import CreationSuite
from decentralized_storage import CheckFailure, require, all_database_snapshots
from decentralized_vectors import strict_output


PIN="bc48acf903a00c545a898b24f175884940fdfc06"
ROSTER=set("host_public_key member person_public_key device_public_key scopes".split())
VIEW=set("network_id proposal_id context_id state source_catalog_sha256 source_state_sha256 prepared_catalog_sha256 root_state_id local_acknowledgment_id root_commit_id missing_host_keys required_proof_ids approved fenced expires_at".split())
REVIEW=set("stage network_id proposal_id legacy_root_public_key legacy_epoch new_context_id roster source_catalog_sha256 source_state_sha256 prepared_catalog_sha256 authority_warning".split())
INTENT=set("format operation_id approved approved_at review_base64 provider root_state_id person_public_key host_public_key device_public_key scopes not_after created_at expires_at templates signatures completed terminal result_base64".split())


def moment(s):return datetime.fromisoformat(s.strip().replace("Z","+00:00"))
def stamp(d):return d.strftime("%Y-%m-%dT%H:%M:%SZ")


class LegacyFixture:
    def __init__(self,args,keys):
        self.args,self.keys,self.root=args,keys,args.work_dir
        self.clock=self.root/"legacy-clock";self.now=datetime.now(timezone.utc).replace(microsecond=0)
        self.clock.write_text(stamp(self.now));self.clock.chmod(0o600)
        self.hosts={}
        for label in ("owner","selected","unbound"):
            root=self.root/label;root.mkdir(mode=0o700)
            s=CreationSuite(args.baseline,root,keys);s.host.environment.update(
                PEERSPAN_LINK_TEST_MODE="1",PEERSPAN_LINK_TEST_CLOCK_FILE=str(self.clock))
            s.host.environment["PATH"]="/usr/bin:/bin"
            self.hosts[label]=s
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1",0));self.address="127.0.0.1:"+str(reserved.getsockname()[1])
        self.coord_root=self.root/"coordinator";self.coord_root.mkdir(mode=0o700)
        self.coord_log=(self.coord_root/"daemon.log").open("ab")
        self.coordinator=None
        self.person_file=self.root/"fixture-original-ed25519"
        result=subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","","-f",str(self.person_file)],capture_output=True,timeout=10)
        require(result.returncode==0,"fixture original SSH key generation failed")

    def tick(self,seconds=2):
        self.now+=timedelta(seconds=seconds);self.clock.write_text(stamp(self.now))

    def api(self,label,method,path,body=None,status=200):
        self.tick();return self.hosts[label].api(method,path,body,status=status)[0]

    def until(self,function,label):
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            value=function()
            if value:return value
            time.sleep(.05)
        raise CheckFailure("bounded legacy setup did not reach "+label)

    def sign(self,value,request_id):
        for _ in range(8):
            slots=value["signing_requests"]
            if not slots:return value
            slot=slots[0]
            require(set(slot)=={"object_type","message_base64","signer_public_key","signature_format"} and
                slot["signer_public_key"]==self.person and slot["signature_format"]=="sshsig" and
                slot["object_type"] in {"certificate","binding_authorization","owner_packet","admission_authorization","administrator_packet"},
                "legacy fixture requested an unrelated original-person signature")
            msg=self.root/"original-signing-message";msg.write_bytes(unb64(slot["message_base64"]))
            sig=msg.with_name(msg.name+".sig");sig.unlink(missing_ok=True)
            result=subprocess.run(["ssh-keygen","-Y","sign","-f",str(self.person_file),"-n","peerspan-person-v1","-q",str(msg)],
                capture_output=True,timeout=10)
            require(result.returncode==0,"fixture original SSH signing failed")
            encoded="".join(line for line in sig.read_text().splitlines() if not line.startswith("-----"))
            value=self.api("owner","POST","/v1/link/requests/"+request_id+"/signed",{"object_type":slot["object_type"],"signature":encoded})
        raise CheckFailure("legacy setup exceeded8 typed signature batches")

    def consent(self,created,commit=False):
        route="/v1/link/requests/"+created["request_id"]+("/commit" if commit else "/selection")
        body={"owner_offer_id":"-","network_id":self.network,"person_public_key":self.person,
            "host_public_key":"-","device_public_key":"-","approve":False}
        if commit:body.update(selection_id="-",administrator_offer_id="-")
        def preview():
            self.tick()
            # Preserve every actual response, including a legitimate pending
            # proof response. No transparent retry changes an expected error.
            from decentralized_storage import UnixHTTP
            c=UnixHTTP(self.hosts["selected"].host.state/"admin.sock",timeout=30)
            try:
                c.request("POST",route,raw_json(body),{"Content-Type":"application/json"});response=c.getresponse();raw=response.read()
                value=strict_output(raw)
                self.hosts["selected"].response_count+=1
                p=self.hosts["selected"].responses/f"{self.hosts['selected'].response_count:03}.json";p.write_bytes(raw);p.chmod(0o600)
                if response.status==409 and value.get("code")=="proof_required":
                    self.api("selected","POST","/v1/link/requests/"+created["request_id"]+"/resume",{})
                    return None
                require(response.status==200,"legacy consent preview failed; status="+str(response.status))
                return value
            finally:c.close()
        value=self.until(preview,"final review" if commit else "selection review");review=value["review"]
        for field in ("owner_offer_id","network_id","person_public_key","host_public_key","device_public_key"):
            body[field]=review[field]
        if commit:
            for field in ("selection_id","administrator_offer_id"):body[field]=review[field]
        body["approve"]=True
        return self.api("selected","POST",route,body)

    def build(self):
        env=dict(self.hosts["owner"].host.environment)
        self.coordinator=subprocess.Popen([str(self.args.coordinator),"--state",str(self.coord_root/"state"),"run","--listen",self.address],
            env=env,stdout=self.coord_log,stderr=subprocess.STDOUT,start_new_session=True)
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            require(self.coordinator.poll() is None,"legacy fixture coordinator exited at startup")
            try:
                with socket.create_connection(("127.0.0.1",int(self.address.rsplit(":",1)[1])),timeout=.1):break
            except OSError:time.sleep(.02)
        else:raise CheckFailure("legacy fixture coordinator readiness exceeded20s")
        info=subprocess.run([str(self.args.coordinator),"--state",str(self.coord_root/"state"),"info"],capture_output=True,timeout=20)
        require(info.returncode==0,"legacy coordinator public info failed")
        self.coordinator_key=strict_output(info.stdout)["public_key"]
        for instance in self.hosts.values():
            instance.host.start();instance.identity=instance.host.api("GET","/v1/host")
        a=self.hosts["owner"]
        created=a.host.cli("network","create","Independent migration identity","--as","Fixture original owner",
            "--person-key",str(self.person_file),"--coordinator",self.address,"--coordinator-key",self.coordinator_key)
        self.network,self.person=created["id"],created["person"]["key"]["public_key"]
        # Cover real legacy creation fractional timestamps with its documented
        # whole-second fixture clock; no expiry/deadline is enlarged.
        self.now=max(self.now,datetime.now(timezone.utc).replace(microsecond=0)+timedelta(seconds=1));self.tick()
        a.host.cli("network","enable-linking","--network",self.network)
        body={"mode":"new","network_id":self.network,"person_public_key":self.person,
            "coordinator_address":self.address,"coordinator_public_key":self.coordinator_key}
        request=self.api("selected","POST","/v1/link/requests",body,status=201)
        identifier=request["request_id"]
        approval={"code":request["display_code"],"network_id":self.network,"expected_person_id":"person_"+sha(unb64(self.person)),
            "expected_host_key":"-","expected_device_key":"-","signer":"person_root","approve":False}
        review=self.api("owner","POST","/v1/link/approvals",approval)["review"]
        approval.update(expected_host_key=review["host_public_key"],expected_device_key=review["device_public_key"],approve=True)
        self.sign(self.api("owner","POST","/v1/link/approvals",approval),identifier)
        self.consent(request)
        def administrator():
            self.api("owner","POST","/v1/link/requests/"+identifier+"/resume",{})
            value=self.api("owner","GET","/v1/link/requests/"+identifier+"/approval")
            self.sign(value,identifier)
            rows=table_rows(a.host,"link_pending","record"," WHERE request_id=?",(identifier,))
            return rows and strict_output(rows[0][0].encode())["administrator_packet_base64"]!="-"
        self.until(administrator,"approved legacy administrator packet")
        self.consent(request,commit=True)
        linked=self.until(lambda: (v if (v:=self.api("selected","POST","/v1/link/requests/"+identifier+"/resume",{}))["state"]=="linked" else None),
            "actually linked selected-device baseline")
        signer=self.api("selected","GET","/v1/networks/"+self.network+"/link-signer")
        require(signer["person_public_key"]==self.person and signer["device_public_key"]!=self.person and signer["scopes"]>0,
            "legacy fixture did not establish a real separate selected device")
        unbound=self.hosts["unbound"].host.cli("network","create","Independent host only","--as","Fixture unbound host", "--no-person",
            "--coordinator",self.address,"--coordinator-key",self.coordinator_key)
        self.tick()
        self.specs=[{"label":"owner","network_id":self.network,"member":"Fixture original owner","person_public_key":self.person,
            "host_public_key":a.identity["public_key"],"device_public_key":"-","scopes":7},
            {"label":"selected","network_id":self.network,"member":"Fixture original owner","person_public_key":self.person,
             "host_public_key":self.hosts["selected"].identity["public_key"],"device_public_key":signer["device_public_key"],"scopes":signer["scopes"]},
            {"label":"unbound","network_id":unbound["id"],"member":"Fixture unbound host","person_public_key":"-",
             "host_public_key":self.hosts["unbound"].identity["public_key"],"device_public_key":"-","scopes":0}]
        (self.root/"legacy-public-baseline.json").write_bytes(raw_json({"specs":self.specs,"selected_signer":signer,
            "actually_linked_request_view":linked,"old_host_sha256":sha(self.args.baseline.read_bytes()),
            "old_coordinator_sha256":sha(self.args.coordinator.read_bytes()),"decision_time":stamp(self.now)}))
        return self.specs

    def stop(self):
        errors=[]
        for instance in reversed(list(self.hosts.values())):
            try:instance.host.stop()
            except BaseException as error:errors.append(error)
        if self.coordinator:
            process,self.coordinator=self.coordinator,None
            if process.poll() is None:
                require(os.getpgid(process.pid)==process.pid,"fixture coordinator PGID changed")
                os.killpg(process.pid,signal.SIGTERM)
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5);errors.append(CheckFailure("fixture coordinator shutdown exceeded10s"))
        self.coord_log.close()
        if errors:raise errors[0]


class IdentitySuite:
    def __init__(self,args,keys,baseline):
        self.args,self.keys,self.baseline=args,keys,baseline
        self.rows=[];self.trace=[];self.hosts=[]

    def same_except_rows(self,left,right,excluded):
        def kept(value):
            return {"databases":{name:{**database,"tables":{
                table:({**record,"rows":[]} if table in excluded else record)
                for table,record in database["tables"].items()}}
                for name,database in value["databases"].items()}}
        return kept(left)==kept(right)

    def same_except_clock(self,left,right):
        return self.same_except_rows(left,right,{"dec_clock"})

    def clock_rows(self,value):
        return {name:database["tables"]["dec_clock"] for name,database in value["databases"].items()
            if "dec_clock" in database["tables"]}

    def intent(self,instance):
        rows=table_rows(instance.host,"dec_intents","intent_id,network_id,context_id,record,secret"," WHERE kind='migration_identity'")
        require(len(rows)==1,"identity approval did not leave exactly one migration_identity intent")
        identifier,network,context,encoded,secret=rows[0];record=strict_output(encoded.encode())
        require(set(record)==INTENT and record["format"]==1 and record["approved"] is True and record["completed"] is True and
            record["templates"]==record["signatures"]==[] and record["terminal"]==record["operation_id"]==record["root_state_id"]==
            record["result_base64"]==record["not_after"]==context=="-","identity intent became a signing/applying/proposal intent")
        return identifier,network,record,None if secret is None else sha(secret),secret

    def shape(self,value,spec,approved=False):
        require(set(value)=={"migration","identity","review","signing_requests"} and value["signing_requests"]==[],
            "identity response exposes signing work or wrong fields")
        m,i,r=value["migration"],value["identity"],value["review"]
        require(set(m)==VIEW and set(i)==ROSTER and set(r)==REVIEW,"identity/migration/review exact fields differ")
        require(m["network_id"]==spec["network_id"] and m["state"]=="needs_approvals" and m["approved"] is False and m["fenced"] is False and
            m["missing_host_keys"]==m["required_proof_ids"]==[] and all(m[k]=="-" for k in
            ("proposal_id","context_id","source_catalog_sha256","source_state_sha256","prepared_catalog_sha256","root_state_id",
             "local_acknowledgment_id","root_commit_id","expires_at")),"identity approval fabricated proposal participation/fence/context")
        for k in ("host_public_key","member","person_public_key","scopes"):
            require(i[k]==spec[k],"identity changed actual baseline "+k)
        if spec["label"]!="owner" or not approved:
            require(i["device_public_key"]==spec["device_public_key"],"identity preview/reused device changed stable key")
        else:require(len(unb64(i["device_public_key"]))==32 and i["device_public_key"]!=i["person_public_key"],"approved identity lacks separate actual device")
        require(r["stage"]=="identity" and r["network_id"]==spec["network_id"] and
            r["proposal_id"]==r["new_context_id"]==r["prepared_catalog_sha256"]=="-" and
            i in r["roster"],"identity review changed stage/proposal or omits its exact own tuple")

    def run_one(self,spec):
        old=self.baseline.hosts[spec["label"]]
        root=self.args.work_dir/("new-"+spec["label"]);root.mkdir(mode=0o700)
        instance=CreationSuite(self.args.host,root,self.keys);instance.host.state=old.host.state
        self.hosts.append(instance)
        clock=root/"authority-clock";base=self.baseline.now+timedelta(seconds=1);clock.write_text(stamp(base));clock.chmod(0o600)
        instance.host.environment.update(PEERSPAN_DEC_TEST_MODE="1",PEERSPAN_DEC_TEST_CLOCK_FILE=str(clock))
        instance.host.start();require(instance.host.api("GET","/v1/host")["public_key"]==spec["host_public_key"],"upgrade replaced actual host key")
        route="/v2/networks/"+spec["network_id"]+"/migration/identity"
        before=all_database_snapshots(instance.host.state)
        (root/"before-database-hashes.json").write_bytes(raw_json(before))
        def preview():
            self.preview=instance.api("POST",route,{"scopes":spec["scopes"],"approve":False})[0]
            self.shape(self.preview,spec)
            require(all_database_snapshots(instance.host.state)==before and not table_rows(instance.host,"dec_intents","intent_id"," WHERE kind='migration_identity'"),
                "preview generated/persisted an intent/key/guard/authority")
        self.case(spec["label"],"preview_is_nonsigning_and_writes_nothing",preview)
        def approve():
            self.approved=instance.api("POST",route,{"scopes":spec["scopes"],"approve":True})[0];self.shape(self.approved,spec,True)
            self.fixed=self.intent(instance);identifier,network,r,seed_hash,secret=self.fixed
            require(network==spec["network_id"] and r["provider"]=={"kind":"host","signer_public_key":spec["host_public_key"],
                "signature_format":"ed25519","lease_id":"-"} and strict_output(unb64(r["review_base64"]))==self.approved["review"],
                "identity private selector/review differs from exact nonsigning owned host")
            require(all(r[k]==self.approved["identity"][k] for k in ("person_public_key","host_public_key","device_public_key","scopes")) and
                moment(r["expires_at"])-moment(r["created_at"])==timedelta(seconds=300),"identity intent tuple/window differs")
            if spec["label"]=="owner":
                require(type(secret) is bytes and len(secret)==32,"new device does not have one exact32-byte pending seed")
                result=subprocess.run(["openssl","pkey","-inform","DER","-pubout","-outform","DER"],
                    input=bytes.fromhex("302e020100300506032b657004220420")+secret,capture_output=True,timeout=10)
                require(result.returncode==0 and b64(result.stdout[-32:])==r["device_public_key"],"pending device seed does not match approved actual key")
            else:require(secret is None,"existing-device/unbound identity copied or generated a seed")
            after=all_database_snapshots(instance.host.state)
            intent_databases=[name for name,database in before["databases"].items() if "dec_intents" in database["tables"]]
            require(len(intent_databases)==1,"runtime state lacks exactly one observed normative intent table")
            database=intent_databases[0]
            old_intents=before["databases"][database]["tables"]["dec_intents"]["rows"]
            new_intents=after["databases"][database]["tables"]["dec_intents"]["rows"]
            require(len(new_intents)==len(old_intents)+1 and set(old_intents)<=set(new_intents),
                "identity approval modified another intent or invented additional approval work")
            require(self.same_except_rows(before,after,{"dec_intents","dec_clock"}),
                "identity approval mutated another database/table/DDL/version")
            self.fixed_rows=after
            (root/"approved-database-hashes.json").write_bytes(raw_json(after))
            self.trace.append({"fixture":spec["label"],"intent_id":identifier,"pending_seed_sha256":seed_hash,
                "approved_identity":self.approved["identity"],"all_other_table_rows_unchanged":True})
        self.case(spec["label"],"approval_fixes_only_one_exact_tuple_and_pending_key",approve)
        def repeat():
            for restart in (False,True):
                if restart:
                    clock.write_text(stamp(base+timedelta(seconds=301)));instance.host.stop();instance.host.start()
                value=instance.api("POST",route,{"scopes":spec["scopes"],"approve":True})[0]
                require(value==self.approved and self.intent(instance)[:4]==self.fixed[:4],
                    "identity retry/restart/300s boundary changed tuple/review/approved_at/key")
            after=all_database_snapshots(instance.host.state)
            require(self.same_except_clock(after,self.fixed_rows),"identity exact retry/restart changed durable rows")
            (root/"retried-database-hashes.json").write_bytes(raw_json(after))
            self.trace.append({"fixture":spec["label"],"retry_clock_metadata_before":self.clock_rows(self.fixed_rows),
                "retry_clock_metadata_after":self.clock_rows(after),"original_approved_at_preserved":True})
        self.case(spec["label"],"retry_restart_after300_preserve_tuple_key_and_approval",repeat)
        def changed():
            scopes=1 if spec["scopes"]!=1 else 3
            value=instance.api("POST",route,{"scopes":scopes,"approve":True},status=409)[0]
            require(value["code"]=="operation_conflict" and self.intent(instance)[:4]==self.fixed[:4] and
                self.same_except_clock(all_database_snapshots(instance.host.state),self.fixed_rows),"changed contribution replaced the key/review or mutated authority")
        self.case(spec["label"],"changed_scopes_conflict_without_replacement",changed)
        instance.host.stop()

    def case(self,label,name,function):
        began=time.monotonic()
        try:function()
        except BaseException as e:
            self.rows.append({"name":label+"/"+name,"passed":False,"error_type":type(e).__name__,
                "detail":str(e) if isinstance(e,CheckFailure) else "fixture/transport failure"});print("FAIL "+label+"/"+name,flush=True);raise
        self.rows.append({"name":label+"/"+name,"passed":True,"seconds":round(time.monotonic()-began,3)});print("PASS "+label+"/"+name,flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for n in ("host","baseline","coordinator","work-dir","results"):parser.add_argument("--"+n,type=Path,required=True)
    parser.add_argument("--retained-fixture-dir",type=Path,
        help="Reuse an explicitly retained stopped actual legacy fixture; never regenerate/copy its host keys")
    args=parser.parse_args()
    for n in ("host","baseline","coordinator","work_dir","results"):setattr(args,n,getattr(args,n).resolve())
    args.work_dir.mkdir(mode=0o700,parents=True,exist_ok=False)
    keys=FixtureKeys();legacy=None;failure=detail=None;began=time.monotonic()
    retained=None
    if args.retained_fixture_dir is not None:
        args.retained_fixture_dir=args.retained_fixture_dir.resolve()
        path=args.retained_fixture_dir/"legacy-public-baseline.json"
        retained=strict_output(path.read_bytes())
        require(retained["old_host_sha256"]==sha(args.baseline.read_bytes()) and
            retained["old_coordinator_sha256"]==sha(args.coordinator.read_bytes()),"retained fixture baseline artifacts differ")
        legacy=SimpleNamespace(now=moment(retained["decision_time"]),coordinator=None,
            hosts={spec["label"]:SimpleNamespace(host=SimpleNamespace(state=args.retained_fixture_dir/spec["label"]/"state"))
                for spec in retained["specs"]})
    else:legacy=LegacyFixture(args,keys)
    suite=IdentitySuite(args,keys,legacy)
    try:
        if retained is None:specs=legacy.build();legacy.stop()
        else:specs=retained["specs"]
        for spec in specs:suite.run_one(spec)
    except BaseException as e:failure,detail=type(e).__name__,str(e) if isinstance(e,CheckFailure) else "fixture/transport failure"
    finally:
        for instance in reversed(suite.hosts):
            try:instance.host.stop()
            except BaseException as e:failure=failure or type(e).__name__;suite.rows.append({"name":"cleanup","passed":False,"error_type":type(e).__name__})
        if legacy.coordinator:
            try:legacy.stop()
            except BaseException as e:failure=failure or type(e).__name__
        keys.close()
    support=("decentralized_complete_link.py","decentralized_fixtures.py","decentralized_runtime.py","decentralized_storage.py",
        "decentralized_vectors.py","decentralized_requester.py","decentralized_owner_preview.py","decentralized_helper.py","decentralized_direct_carrier.py")
    result={"contract_pin":PIN,"implementation_source_read":False,"suite_sha256":sha(Path(__file__).read_bytes()),
        "support_sha256":{n:sha(Path(__file__).with_name(n).read_bytes()) for n in support},
        "artifacts":{n:{"path":str(getattr(args,n)),"sha256":sha(getattr(args,n).read_bytes())} for n in ("host","baseline","coordinator")},
        "rows":suite.rows,"trace":suite.trace,"failure":failure,"detail":detail,"seconds":round(time.monotonic()-began,3),
        "retained_fixture_dir":str(args.retained_fixture_dir) if retained is not None else None,
        "retained_baseline_sha256":sha((args.retained_fixture_dir/"legacy-public-baseline.json").read_bytes()) if retained is not None else None,
        "scope":"preproposal identity only; one bounded actual legacy fixture is setup, no new proposal/staging/ack/fence/adoption/signing/provider or installed claim",
        "passed":failure is None and len(suite.rows)==12 and all(r["passed"] for r in suite.rows)}
    args.results.parent.mkdir(parents=True,exist_ok=True);args.results.write_text(json.dumps(result,indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__=="__main__":raise SystemExit(main())
