#!/usr/bin/env python3
"""Independent PR123 root-retention preview/native runtime controls.

Fresh local original-provider creation is uncounted fixture setup. No actual
daemon key is copied/read by this suite. The one stopped-owned-state fault
removes only an exact public dec_objects policy body, retaining every private
admission/head/maximum; no internal schema is inferred. Root-fork signing is
covered separately by the frozen all_head_retention_signing pure group.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pty
import signal
import sqlite3
import subprocess
import time
from types import SimpleNamespace

from decentralized_complete_link import statement_id, table_rows
from decentralized_fixtures import FixtureKeys, b64, lines, raw_json, sha, unb64
from decentralized_runtime import CreationSuite
from decentralized_storage import CheckFailure, all_database_snapshots, require
from decentralized_vectors import strict_output


PIN = "434fd0da243dd9dae41cc5c80240b2a0057fd816"
CASES = [
    "preview_exact_finite_contributions_is_read_only",
    "native_default_carries_full_reviewed_eligible_union",
    "native_explicit_host_subset_is_exact_without_inferred_children",
    "api_incomplete_binding_closure_refuses_before_new_key_or_intent",
    "api_valid_host_preview_fixes_one_exact_pending_root_without_signing",
    "missing_policy_body_is_explicit_proof_gap_without_erasing_maximum",
    "native_default_blocks_unknown_eligibility_without_silent_omission",
    "native_explicit_empty_can_rotate_despite_unrelated_finite_proof_gap",
]


class RootRetention:
    def __init__(self, args, keys):
        self.args,self.keys=args,keys
        self.rows,self.trace,self.hosts=[],[],[]
        self.now=datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

    def retained_default(self):
        old=self.args.continue_default_dir or self.args.continue_unapproved_default_dir
        root=self.args.work_dir/"default";root.mkdir(mode=0o700)
        s=CreationSuite(self.args.host,root,self.keys);s.host.state=old/"state";self.hosts.append(s)
        require(not (s.host.state/"admin.sock").exists(),"retained default fixture is not stopped")
        preview=before=None
        for meta in sorted((old/"public-responses").glob("*.meta.json")):
            m=strict_output(meta.read_bytes());path=meta.with_name(meta.name.replace(".meta.json",".json"))
            value=strict_output(path.read_bytes())
            if m["method"]=="GET" and m["path"].endswith("/root-retention"):preview=value
            if m["method"]=="GET" and value.get("root_epoch")==0 and "provider" in value:before=value
        require(preview is not None and before is not None,"retained default fixture lacks exact original preview/network capture")
        self.now=(old/"clock").read_text()
        clock=root/"clock";clock.write_text(self.now);clock.chmod(0o600)
        s.host.environment.update(PEERSPAN_DEC_TEST_MODE="1",PEERSPAN_DEC_TEST_CLOCK_FILE=str(clock))
        s.network=before;s.context_id=before["context_id"];s.route="/v2/networks/"+before["id"]
        self.eligible=sorted({i for row in preview["candidates"] for i in row["required_retained_ids"]})
        s.host.start();s.identity=s.host.api("GET","/v1/host")
        require(s.identity["public_key"]==before["host_public_key"],"retained default host identity changed")
        if self.args.continue_unapproved_default_dir:
            rows=table_rows(s.host,"dec_intents","record"," WHERE kind='root_transition'")
            require(len(rows)==1,"unapproved continuation lacks its one fixed pending root")
            intent=strict_output(rows[0][0].encode())
            templates=[strict_output(unb64(t["template_base64"])) for t in intent["templates"] if t["object_type"]=="root_state"]
            require(len(templates)==1 and not intent["approved"],"unapproved continuation lost its original sole unsigned root template")
            self.pending_root_public_key=strict_output(unb64(templates[0]["payload_base64"]))["root_public_key"]
        self.trace.append({"continued_default_already_rotated_state":str(old/"state") if self.args.continue_default_dir else None,
            "continued_exact_unapproved_pending_root_state":str(old/"state") if self.args.continue_unapproved_default_dir else None,
            "prior_readonly_preview_not_repeated":True,"native_rotation_not_executed_again":bool(self.args.continue_default_dir),
            "fixture_correction":"explicit one-yes terminal approval for the same fixed pending root" if self.args.continue_unapproved_default_dir else
                "public provider root_state_id follows accepted current root; stable selection/other provider fields remain exact"})
        return s

    def fixture(self,label):
        root=self.args.work_dir/label;root.mkdir(mode=0o700)
        s=CreationSuite(self.args.host,root,self.keys);self.hosts.append(s)
        clock=root/"clock";clock.write_text(self.now);clock.chmod(0o600)
        s.host.environment.update(PEERSPAN_DEC_TEST_MODE="1",PEERSPAN_DEC_TEST_CLOCK_FILE=str(clock))
        s.name="Independent retention "+label
        s.host.start();s.identity=s.host.api("GET","/v1/host")
        s.preview=s.api("POST","/v2/networks",{"name":s.name,"member":s.member,
            "person_public_key":self.keys.public("alice"),"approve":False})[0]
        s.creation_shape(s.preview,False)
        route="/v2/network-creations/"+s.preview["creation_id"]
        ready=s.api("POST",route+"/approve",{"context_id":s.context_id,
            "root_state_id":s.preview["review"]["root_state_id"],"person_public_key":self.keys.public("alice"),
            "host_public_key":s.identity["public_key"],"approve":True})[0]
        for _ in range(8):
            if ready["committed"]:break
            slots=ready["signing_requests"];require(0<len(slots)<=16,"fixture creation has no bounded original signing batch")
            ready=s.api("POST",route+"/signed",{"intent_id":slots[0]["intent_id"],
                "signatures":[s.slot_signature(slot) for slot in slots]})[0]
        require(ready["committed"] is True,"bounded fresh creation fixture did not complete")
        s.network=ready["network"];s.route="/v2/networks/"+s.network["id"]
        s.objects=s.verify_catalog()
        s.catalog=s.api("GET",s.route+"/catalog")[0]["catalog"]
        s.proofs={}
        for entry in s.catalog["objects"]:
            body=strict_output(unb64(entry["body_base64"]))
            s.proofs[statement_id(body)]=entry
        require(set(s.objects)=={"root_state","admin_lease","person_lease","host_lease","binding_lease","policy"},
            "retention fixture created a different ordinary finite graph")
        self.trace.append({"uncounted_fresh_fixture":label,"host_public_key":s.identity["public_key"],
            "network_id":s.network["id"],"context_id":s.context_id,"no_actual_daemon_key_copy":True})
        return s

    def preview(self,s):
        before=all_database_snapshots(s.host.state)
        value=s.api("GET",s.route+"/root-retention")[0]
        require(set(value)=={"network_id","context_id","decision_time","root_head_ids","catalog","candidates","excluded"}
            and value["network_id"]==s.network["id"] and value["context_id"]==s.context_id and value["decision_time"]==self.now,
            "root-retention preview changed its exact context/snapshot shape/time")
        require(value["root_head_ids"]==[s.network["root_state_id"]],"preview omitted or chose another current root")
        for rows,fields in ((value["candidates"],{"statement_id","kind","required_retained_ids","effective_scopes","effective_not_after"}),
                            (value["excluded"],{"statement_id","code","required_ids"})):
            require([r["statement_id"] for r in rows]==sorted({r["statement_id"] for r in rows}),"preview rows not sorted unique")
            for row in rows:
                require(set(row)==fields,"preview row fields differ")
                field="required_retained_ids" if "kind" in row else "required_ids"
                require(row[field]==sorted(set(row[field])),"preview required IDs not sorted unique")
        require(all_database_snapshots(s.host.state)==before,"read-only retention preview changed any DB/guard/provider/key rows")
        return value

    def expected_initial(self,s):
        expected=[]
        for kind,(identifier,payload) in s.objects.items():
            if kind=="root_state":continue
            required={identifier}|{parent["id"] for parent in payload["parents"]}
            expected.append({"statement_id":identifier,"kind":kind,"required_retained_ids":sorted(required),
                "effective_scopes":{"admin_lease":8,"binding_lease":2}.get(kind,0),
                "effective_not_after":payload["not_after"]})
        return sorted(expected,key=lambda row:row["statement_id"])

    def latest_root(self,s):
        network=s.api("GET",s.route)[0]
        catalog=s.api("GET",s.route+"/catalog")[0]["catalog"]
        for entry in catalog["objects"]:
            if entry["kind"]!="root_state":continue
            body=strict_output(unb64(entry["body_base64"]))
            if statement_id(body)==network["root_state_id"]:
                return network,strict_output(unb64(body["payload_base64"]))
        raise CheckFailure("current root view has no exact retained public root proof")

    def native(self,s,*flags,success=True):
        # Public CLI review must receive actual consent. No root --approve
        # flag is contracted; one yes on an actual terminal supplies approval.
        # Refusal controls receive no approval and remain noninteractive.
        master=slave=None
        if success:master,slave=pty.openpty()
        process=subprocess.Popen([str(self.args.host),"--state",str(s.host.state),"network","rotate-root",s.network["id"],*flags],
            env=s.host.environment,stdin=slave if success else subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        if slave is not None:os.close(slave)
        timed_out=False
        try:
            if master is not None:os.write(master,b"yes\n")
            stdout,stderr=process.communicate(timeout=40)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid,signal.SIGKILL);stdout,stderr=process.communicate(timeout=5);timed_out=True
        finally:
            if master is not None:os.close(master)
        result=SimpleNamespace(returncode=process.returncode,stdout=stdout,stderr=stderr)
        number=len(list(s.root.glob("native-*.meta.json")))+1
        for suffix,raw in (("stdout",result.stdout),("stderr",result.stderr)):
            path=s.root/("native-"+str(number)+"."+suffix);path.write_bytes(raw);path.chmod(0o600)
        (s.root/("native-"+str(number)+".meta.json")).write_bytes(raw_json({"arguments":list(flags),"exit":result.returncode,
            "stdout_sha256":sha(result.stdout),"stderr_sha256":sha(result.stderr),
            "actual_terminal_approval":success,"input_sha256":sha(b"yes\n") if success else None,"timed_out":timed_out}))
        require(not timed_out,"native root review did not finish after one explicit terminal approval; see captured receipt")
        require((result.returncode==0)==success,"native root retention command had unexpected success/refusal")
        return result

    def root_request(self,s,retained):
        return {"new_root_public_key":"-","new_root_signature_format":"ed25519","signature_format":"ed25519",
            "retained_statement_ids":retained,"approve":False}

    def case(self,name,function):
        started=time.monotonic()
        try:function()
        except BaseException as e:
            self.rows.append({"name":name,"passed":False,"error_type":type(e).__name__,
                "detail":str(e) if isinstance(e,CheckFailure) else "fixture/transport failure"})
            print("FAIL "+name,flush=True);raise
        self.rows.append({"name":name,"passed":True,"seconds":round(time.monotonic()-started,3)})
        print("PASS "+name,flush=True)

    def run(self):
        continuing=self.args.continue_default_dir is not None or self.args.continue_unapproved_default_dir is not None
        s=self.retained_default() if continuing else self.fixture("default")
        def current():
            value=self.preview(s)
            require(value["catalog"]==s.catalog and value["candidates"]==self.expected_initial(s) and value["excluded"]==[],
                "preview changed exact retained proofs, finite authority closure, powers or deadlines")
            self.eligible=sorted({i for row in value["candidates"] for i in row["required_retained_ids"]})
        if not continuing:self.case(CASES[0],current)
        def default():
            before=s.network if continuing else s.api("GET",s.route)[0]
            if self.args.continue_default_dir is None:self.native(s)
            after,payload=self.latest_root(s)
            stable=lambda provider:{k:v for k,v in provider.items() if k!="root_state_id"}
            require(payload["epoch"]==1 and payload["predecessors"]==[before["root_state_id"]] and
                payload["retained_statement_ids"]==self.eligible and stable(after["provider"])==stable(before["provider"]) and
                after["provider"]["root_state_id"]==after["root_state_id"] and
                after["provider_state"]==before["provider_state"],"native default silently dropped a finite grant or changed selected provider")
            if self.args.continue_unapproved_default_dir:
                require(payload["root_public_key"]==self.pending_root_public_key,"terminal approval replaced the original pending root key")
        self.case(CASES[1],default);s.host.stop()
        s=self.fixture("subset");host=s.objects["host_lease"][0]
        def subset():
            self.native(s,"--retain",host)
            _,payload=self.latest_root(s)
            require(payload["retained_statement_ids"]==[host],"explicit native subset inferred other grants/children")
        self.case(CASES[2],subset);s.host.stop()
        s=self.fixture("api");binding=s.objects["binding_lease"][0];host=s.objects["host_lease"][0]
        def bad_closure():
            before=all_database_snapshots(s.host.state)
            value=s.api("POST",s.route+"/root-transitions",self.root_request(s,[binding]),status=403)[0]
            s.error(value,"forbidden")
            after=all_database_snapshots(s.host.state)
            def without_clock(v):
                return {name:{**db,"tables":{k:({**row,"rows":[]} if k=="dec_clock" else row)
                    for k,row in db["tables"].items()}} for name,db in v["databases"].items()}
            require(without_clock(before)==without_clock(after),"ineligible retention generated an intent/key or changed authority")
        self.case(CASES[3],bad_closure)
        def fixed_preview():
            network=s.api("GET",s.route)[0]
            value=s.api("POST",s.route+"/root-transitions",self.root_request(s,[host]))[0]
            require(set(value)=={"action_id","review","signing_requests","statement_base64","proof_id","catalog","committed","delivery"}
                and value["committed"] is False and value["signing_requests"]==[] and
                value["statement_base64"]==value["proof_id"]==value["catalog"]=="-","unapproved root preview signed/published")
            rows=table_rows(s.host,"dec_intents","intent_id,record,secret"," WHERE kind='root_transition'")
            require(len(rows)==1 and isinstance(rows[0][2],bytes) and len(rows[0][2])==32,
                "valid preview did not fix exactly one protected pending root")
            hashes=sha(raw_json([[row[0],row[1],sha(row[2])] for row in rows]))
            require(s.api("POST",s.route+"/root-transitions",self.root_request(s,[host]))[0]==value and
                s.api("GET",s.route)[0]==network,"root preview retry replaced exact pending review or applied state")
            retry=table_rows(s.host,"dec_intents","intent_id,record,secret"," WHERE kind='root_transition'")
            require(sha(raw_json([[row[0],row[1],sha(row[2])] for row in retry]))==hashes,
                "root preview regenerated an intent/key/template")
        self.case(CASES[4],fixed_preview);s.host.stop()
        s=self.fixture("proof-gap")
        policy=s.objects["policy"][0];entry=s.proofs[policy];proof=entry["id"]
        before_versions=s.api("GET",s.route+"/access-versions")[0]
        s.host.stop()
        candidates=[]
        for path in s.host.state.iterdir():
            if not path.is_file() or path.is_symlink():continue
            with path.open("rb") as stream:header=stream.read(16)
            if header!=b"SQLite format 3\x00":continue
            with sqlite3.connect(path) as c:
                if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='dec_objects'").fetchone():candidates.append(path)
        require(len(candidates)==1,"owned fault fixture lacks one observed normative dec_objects table")
        with sqlite3.connect(candidates[0]) as c:
            original=c.execute("SELECT body FROM dec_objects WHERE network_id=? AND context_id=? AND proof_id=?",
                (s.network["id"],s.context_id,proof)).fetchall()
            require(len(original)==1 and original[0][0]==unb64(entry["body_base64"]),"fault target is not exact fixture-created public policy")
            require(c.execute("DELETE FROM dec_objects WHERE network_id=? AND context_id=? AND proof_id=?",
                (s.network["id"],s.context_id,proof)).rowcount==1,"fault removed other than one exact public proof")
        self.trace.append({"stopped_owned_public_proof_fault":{"removed_proof_id":proof,"statement_id":policy,
            "body_sha256":sha(original[0][0]),"all_private_admissions_heads_maxima_keys_left_untouched":True}})
        s.host.start()
        def gap():
            value=self.preview(s)
            excluded=next((row for row in value["excluded"] if row["statement_id"]==policy),None)
            require(excluded is not None and excluded["code"]=="proof_required" and
                bool(excluded["required_ids"]) and set(excluded["required_ids"])<={policy,proof} and
                not any(row["statement_id"]==policy for row in value["candidates"]),
                "missing selected policy was hidden or treated as known ineligible")
            require(s.api("GET",s.route+"/access-versions")[0]==before_versions,"missing body erased its retained exact maximum/head")
        self.case(CASES[5],gap)
        def blocked():
            before=all_database_snapshots(s.host.state)
            self.native(s,success=False)
            require(all_database_snapshots(s.host.state)==before,"native full-set default signed/generated/changed state despite unknown eligibility")
        self.case(CASES[6],blocked)
        def empty():
            previous=s.api("GET",s.route)[0]
            self.native(s,"--retain-none")
            after,payload=self.latest_root(s)
            require(after["root_epoch"]==1 and payload["predecessors"]==[previous["root_state_id"]] and
                payload["retained_statement_ids"]==[] and s.api("GET",s.route+"/access-versions")[0]==before_versions,
                "explicit empty selection could not rotate or erased unrelated retained maxima")
        self.case(CASES[7],empty);s.host.stop()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--list-cases",action="store_true")
    p.add_argument("--continue-default-dir",type=Path,help="Validate already committed failed default postconditions; skip passed preview and another rotation")
    p.add_argument("--continue-unapproved-default-dir",type=Path,help="Continue same exact pending root with actual terminal approval; skip passed preview")
    for name in ("host","work-dir","results"):p.add_argument("--"+name,type=Path)
    args=p.parse_args()
    if args.continue_default_dir and args.continue_unapproved_default_dir:p.error("committed and unapproved continuations differ")
    if args.list_cases:print(json.dumps({"contract_pin":PIN,"cases":CASES,"product_execution":False},indent=2));return 0
    if any(getattr(args,name) is None for name in ("host","work_dir","results")):p.error("--host, --work-dir and --results are required")
    for name in ("host","work_dir","results"):setattr(args,name,getattr(args,name).resolve())
    if args.continue_default_dir:args.continue_default_dir=args.continue_default_dir.resolve()
    if args.continue_unapproved_default_dir:args.continue_unapproved_default_dir=args.continue_unapproved_default_dir.resolve()
    args.work_dir.mkdir(mode=0o700,parents=True,exist_ok=False)
    keys=FixtureKeys();suite=RootRetention(args,keys);failure=detail=None;began=time.monotonic()
    try:suite.run()
    except BaseException as e:failure,detail=type(e).__name__,str(e) if isinstance(e,CheckFailure) else "fixture/transport failure"
    finally:
        for s in reversed(suite.hosts):
            try:s.host.stop()
            except BaseException as e:failure=failure or type(e).__name__;suite.rows.append({"name":"cleanup","passed":False,"error_type":type(e).__name__})
        keys.close()
    support=("decentralized_complete_link.py","decentralized_fixtures.py","decentralized_runtime.py","decentralized_storage.py",
        "decentralized_vectors.py","decentralized_requester.py","decentralized_owner_preview.py","decentralized_helper.py","decentralized_direct_carrier.py")
    result={"contract_pin":PIN,"implementation_source_read":False,"suite_sha256":sha(Path(__file__).read_bytes()),
        "support_sha256":{n:sha(Path(__file__).with_name(n).read_bytes()) for n in support},
        "host":{"path":str(args.host),"sha256":sha(args.host.read_bytes())},"planned_cases":CASES,
        "rows":suite.rows,"trace":suite.trace,"failure":failure,"detail":detail,"seconds":round(time.monotonic()-began,3),
        "continued_default_dir":str(args.continue_default_dir) if args.continue_default_dir else None,
        "continued_unapproved_default_dir":str(args.continue_unapproved_default_dir) if args.continue_unapproved_default_dir else None,
        "scope":"fresh current-root preview/native/typed preparation only; pure all-head fork signing separate; no helper/NAT/installed/migration or overall launch claim",
        "passed":failure is None and len(suite.rows)==len(CASES)-(1 if args.continue_default_dir or args.continue_unapproved_default_dir else 0) and all(r["passed"] for r in suite.rows)}
    args.results.parent.mkdir(parents=True,exist_ok=True);args.results.write_text(json.dumps(result,indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__=="__main__":raise SystemExit(main())
