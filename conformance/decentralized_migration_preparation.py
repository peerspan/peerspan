#!/usr/bin/env python3
"""Independent public PR124 migration proposal/export/import/request controls.

Continue the original fixture-owned actual legacy A/B stores after identity
approval. Never rebuild their keys, copy daemon seeds, extract source evidence
from guessed columns, start the old coordinator or claim all-host adoption.
Source evidence comes ONLY from the documented owner-local export route.
Unbound H, ACK/fence, commit and whole adoption are separate later controls.
"""
from __future__ import annotations

import argparse
from datetime import datetime,timezone
import json
from pathlib import Path
import socket
import time

from decentralized_complete_link import packet_message,statement_id,table_rows
from decentralized_fixtures import FixtureKeys,b64,lines,raw_json,sha,unb64
from decentralized_migration_identity import INTENT,REVIEW,ROSTER,VIEW,moment,stamp
from decentralized_owner_preview import authority_rows
from decentralized_requester import VIEW as LINK_FIELDS
from decentralized_runtime import CreationSuite,SLOT_FIELDS
from decentralized_storage import CheckFailure,UnixHTTP,all_database_snapshots,require
from decentralized_vectors import strict_output


PIN="f43a6aba15cda44a553b90643e5e5772b7e596e9"
EVIDENCE=set("proposal source_catalog_base64 source_state_base64 catalog acknowledgments commit".split())
CASES=["before_proposal_export_is_absent_and_prepare_preview_grants_no_authority",
       "approved_root_proposal_exports_exact_source_initial_root_and_shared_person",
       "exact_source_import_and_separate_participation_review_do_not_adopt_or_fence",
       "staged_request_preserves_approved_existing_device_and_cannot_adopt_ordinary_context"]


class Preparation:
    def __init__(self,args,keys):
        self.args,self.keys=args,keys;self.rows=[];self.trace=[];self.hosts={};self.responses=0
        baseline=strict_output((args.retained_dir/"legacy-public-baseline.json").read_bytes())
        self.specs={r["label"]:r for r in baseline["specs"] if r["label"] in ("owner","selected")}
        require(set(self.specs)=={"owner","selected"},"retained public fixture lacks its original owned pair")
        self.network=self.specs["owner"]["network_id"];self.person=self.specs["owner"]["person_public_key"]
        require(self.specs["selected"]["network_id"]==self.network and self.specs["selected"]["person_public_key"]==self.person,
            "bounded migration fixture is not one actual same-person legacy pair")
        continuation=args.after_source_import_dir or args.continue_preview_dir
        anchors=[] if continuation else [datetime.now(timezone.utc).replace(microsecond=0)]
        self.identities={};self.identity_hashes={}
        for label,binary in (("owner",args.owner),("selected",args.selected)):
            root=args.work_dir/label;root.mkdir(mode=0o700);s=CreationSuite(binary,root,keys)
            s.host.state=args.retained_dir/label/"state";self.hosts[label]=s
            require(not (s.host.state/"admin.sock").exists(),"retained migration participant is not stopped")
            rows=table_rows(s.host,"dec_intents","intent_id,record,secret"," WHERE kind='migration_identity'")
            require(len(rows)==1,"retained participant lacks its one actual approved identity contribution")
            identifier,encoded,secret=rows[0];record=strict_output(encoded.encode())
            require(set(record)==INTENT and record["approved"] and record["completed"] and record["terminal"]=="-",
                "retained migration identity is not the original approved unresolved tuple")
            self.identities[label]={field:record[field] for field in ("host_public_key","person_public_key","device_public_key","scopes")}
            self.identities[label]["member"]=self.specs[label]["member"]
            require(set(self.identities[label])==ROSTER and all(self.identities[label][k]==self.specs[label][k]
                for k in ("host_public_key","person_public_key","scopes")),"retained contribution changed baseline ownership/profile")
            if label=="selected":require(self.identities[label]["device_public_key"]==self.specs[label]["device_public_key"],
                "preparation replaced the actual selected legacy device")
            self.identity_hashes[label]=sha(raw_json([identifier,encoded,None if secret is None else sha(secret)]))
            for clock, in table_rows(s.host,"dec_clock","record"):
                anchors.append(moment(strict_output(clock.encode())["largest_local_time"]))
            with socket.socket() as sock:
                sock.bind(("127.0.0.1",0));address="127.0.0.1:"+str(sock.getsockname()[1])
            s.host.run_arguments=["--bootstrap-listen",address]
        self.roster=sorted(self.identities.values(),key=lambda row:row["host_public_key"])
        if continuation:
            self.now=(continuation/"owner"/"authority-clock").read_text().strip()
            require(all(moment(self.now)>=anchor for anchor in anchors),"retained proposal continuation would rewind the actual guarded decision clock")
            require((continuation/"selected"/"authority-clock").read_text().strip()==self.now,
                "retained preparation participants had different fixed original decision times")
            if args.continue_preview_dir:
                self.original_preview=strict_output((continuation/"response-003.json").read_bytes())
                self.original_intents=table_rows(self.hosts["owner"].host,"dec_intents","intent_id,record,secret"," WHERE kind='migration'")
                require(self.original_intents and not self.original_preview["migration"]["approved"],
                    "retained first unapproved preview/pending intent is absent or already changed")
            else:
                self.evidence=strict_output((continuation/"response-003.json").read_bytes())
                imported=strict_output((continuation/"response-006.json").read_bytes());self.wrapper(imported)
                require(not imported["migration"]["approved"] and not imported["migration"]["fenced"] and
                    not imported["signing_requests"],"retained original successful import no longer describes unapproved evidence")
                self.verify_evidence(self.evidence)
                self.trace.append({"two_passed_test_functions_skipped":True,
                    "passed_source_hash_mismatch_and_unapproved_import_substeps_not_repeated":True,
                    "same_original_proposal_and_signed_evidence_reused":self.proposal_id,
                    "source_evidence_response_sha256":sha((continuation/"response-003.json").read_bytes())})
        else:self.now=stamp(max(anchors))
        for label,s in self.hosts.items():
            clock=s.root/"authority-clock";clock.write_text(self.now);clock.chmod(0o600)
            s.host.environment.update(PEERSPAN_DEC_TEST_MODE="1",PEERSPAN_DEC_TEST_CLOCK_FILE=str(clock))
        self.route="/v2/networks/"+self.network+"/migration"
        self.legacy_authority={label:authority_rows(s) for label,s in self.hosts.items()}

    def api(self,label,method,path,body=None,status=200):
        s=self.hosts[label];client=UnixHTTP(s.host.state/"admin.sock",timeout=35)
        try:
            client.request(method,path,body=None if body is None else raw_json(body),
                headers={} if body is None else {"Content-Type":"application/json"})
            response=client.getresponse();raw=response.read(32*1024*1024+1);self.responses+=1
            prefix=self.args.work_dir/("response-%03d"%self.responses)
            prefix.with_suffix(".json").write_bytes(raw);prefix.with_suffix(".json").chmod(0o600)
            prefix.with_suffix(".meta.json").write_bytes(raw_json({"participant":label,"method":method,"path":path,
                "status":response.status,"body_sha256":sha(raw),"request_sha256":None if body is None else sha(raw_json(body))}))
            statuses=status if isinstance(status,tuple) else (status,)
            require(len(raw)<=32*1024*1024 and response.status in statuses,
                "migration public API returned an unexpected status/body bound; see exact protected response")
            return strict_output(raw)
        finally:client.close()

    def wrapper(self,value):
        require(set(value)=={"migration","review","signing_requests"} and set(value["migration"])==VIEW and
            set(value["review"])==REVIEW,"migration wrapper/view/review exact fields differ")
        require(value["migration"]["network_id"]==self.network and value["review"]["network_id"]==self.network,
            "migration review changed the actual legacy network")

    def pending_only(self):
        for label,s in self.hosts.items():
            require(authority_rows(s)==self.legacy_authority[label],"incomplete migration installed active authority/provider/outcome")
            rows=table_rows(s.host,"dec_intents","intent_id,record,secret"," WHERE kind='migration_identity'")
            require(len(rows)==1 and sha(raw_json([rows[0][0],rows[0][1],None if rows[0][2] is None else sha(rows[0][2])]))==self.identity_hashes[label],
                "proposal/review/request replaced or copied its original approved identity intent/key")
            for encoded, in table_rows(s.host,"dec_migrations","record"):
                record=strict_output(encoded.encode())
                require(not record["fenced"] and record["local_acknowledgment_base64"]==record["commit_base64"]==record["migration_base64"]=="-",
                    "preparation manufactured acknowledgment/fence/root commit/adoption")

    def export(self,label,allow_pending=False):
        before=all_database_snapshots(self.hosts[label].host.state)
        value=self.api(label,"GET",self.route+"/evidence",status=(200,404) if allow_pending else 200)
        require((set(value)==EVIDENCE or (allow_pending and value.get("code")=="not_found")) and
            all_database_snapshots(self.hosts[label].host.state)==before,
            "public evidence export changed durable state or its exact carrier shape")
        return value

    def verify_statement(self,body,kind,context):
        require(set(body)=={"format","kind","context_id","payload_base64","signatures"} and
            body["format"]==1 and body["kind"]==kind and body["context_id"]==context,"exported prepared statement framing differs")
        identifier=statement_id(body)
        for signature in body["signatures"]:
            require(signature["format"]=="ed25519" and signature["signature"]!="-","root preparation exported a partial/non-owned signature")
            message=lines("peerspan-decentralized-signature-v1",identifier,signature["role"],signature["public_key"])
            self.hosts["owner"].verify_raw(signature["public_key"],message,signature["signature"])
        return identifier,strict_output(unb64(body["payload_base64"]))

    def verify_evidence(self,value):
        proposal=value["proposal"];descriptor=strict_output(unb64(proposal["payload_base64"]))["new_descriptor"]
        require(set(descriptor)=={"format","protocol","network_id","name","genesis_root_public_key"} and
            descriptor["format"]==1 and descriptor["protocol"]=="peerspan-decentralized-v1" and descriptor["network_id"]==self.network and
            "net_"+sha(unb64(descriptor["genesis_root_public_key"]))==self.network,"proposal rewrote the stable genesis/network descriptor")
        context="ctx_"+sha(lines("peerspan-decentralized-context-v1",descriptor["protocol"],self.network,descriptor["name"],descriptor["genesis_root_public_key"]))
        proposal_id,p=self.verify_statement(proposal,"migration_proposal",context)
        legacy_descriptor=strict_output(unb64(p["legacy_descriptor_base64"]))
        require(all(legacy_descriptor[field]==descriptor[field] for field in ("network_id","name","genesis_root_public_key")),
            "migration descriptor changed the signed original name/genesis/network")
        require(p["roster"]==self.roster and p["source_catalog_sha256"]==sha(unb64(value["source_catalog_base64"])) and
            p["source_state_sha256"]==sha(unb64(value["source_state_base64"])) and len(unb64(p["proposal_nonce"]))==32 and
            (moment(p["expires_at"])-moment(p["issued_at"])).total_seconds()==86400,
            "proposal changed exact approved roster/source hash/nonce/window")
        require(proposal["signatures"]==[{"role":"issuer","public_key":p["legacy_root_public_key"],"format":"ed25519",
            "signature":proposal["signatures"][0]["signature"]}],"migration proposal did not use its sole actual owned legacy-root role")
        require(p["legacy_epoch"]==0 and p["legacy_root_public_key"]==descriptor["genesis_root_public_key"],
            "fresh retained legacy fixture's current root no longer matches its original known genesis")
        state=strict_output(unb64(value["source_state_base64"]))
        require(state["network_id"]==self.network and {row["host_public_key"] for row in self.roster}<=set(state["known_admitted_hosts"]),
            "endorsed source snapshot omitted an actual admitted participant")
        catalog=value["catalog"];require(type(catalog) is dict and set(catalog)=={"format","context_id","objects"} and
            catalog["format"]==1 and catalog["context_id"]==context,"prepared public catalog context/schema differs")
        persons=[];roots=[]
        for entry in catalog["objects"]:
            raw=unb64(entry["body_base64"]);body=strict_output(raw)
            require(entry["id"]=="dp_"+sha(lines("peerspan-decentralized-proof-v1",entry["kind"],sha(raw))),"prepared proof ID does not preserve exact supplied bytes")
            if entry["kind"] in ("person_lease","root_state"):
                identifier,payload=self.verify_statement(body,entry["kind"],context)
                (persons if entry["kind"]=="person_lease" else roots).append((identifier,payload))
        require(len(roots)==len(persons)==1 and roots[0][1]["migration_proposal_id"]==proposal_id and
            roots[0][1]["root_public_key"]==p["legacy_root_public_key"] and roots[0][1]["predecessors"]==[] and
            persons[0][1]["operation_id"]=="-" and persons[0][1]["root_state_id"]==roots[0][0] and
            persons[0][1]["subject"]["person_public_key"]==self.person,"preparation forked the shared person or invented an ordinary migrated root")
        require(value["acknowledgments"]==[] and value["commit"]=="-","root preparation already claims acknowledgment/commit")
        self.proposal_id,self.context,self.root_id=proposal_id,context,roots[0][0]
        self.proposal_payload=p

    def case(self,name,function):
        began=time.monotonic()
        try:function()
        except BaseException as error:
            self.rows.append({"name":name,"passed":False,"error_type":type(error).__name__,
                "detail":str(error) if isinstance(error,CheckFailure) else "fixture/transport failure"});raise
        self.rows.append({"name":name,"passed":True,"seconds":round(time.monotonic()-began,3)})
        print("PASS "+name,flush=True)

    def run(self):
        for label,s in self.hosts.items():
            s.host.start();s.identity=s.host.api("GET","/v1/host")
            require(s.identity["public_key"]==self.specs[label]["host_public_key"],"migration opening replaced an actual daemon host key")
        def preview():
            if not self.args.continue_preview_dir:
                for label,s in self.hosts.items():
                    before=all_database_snapshots(s.host.state)
                    missing=self.api(label,"GET",self.route+"/evidence",status=404)
                    require(missing.get("code")=="not_found" and all_database_snapshots(s.host.state)==before,
                        "preproposal export fabricated source/evidence or changed state")
            self.prepare_body={"roster":self.roster,"signature_format":"ed25519","approve":False}
            value=self.api("owner","POST",self.route+"/prepare",self.prepare_body);self.wrapper(value)
            require(value["signing_requests"]==[] and not value["migration"]["approved"] and not value["migration"]["fenced"],
                "proposal preview signed or approved migration work")
            if self.args.continue_preview_dir:
                require({key:value[key] for key in ("migration","review")}==
                    {key:self.original_preview[key] for key in ("migration","review")} and
                    table_rows(self.hosts["owner"].host,"dec_intents","intent_id,record,secret"," WHERE kind='migration'")==self.original_intents,
                    "correction-only preview regenerated/changed its original nonce/template/intent/key/review")
                self.trace.append({"previously_passed_preproposal_404_and_readpurity_substeps_skipped":True,
                    "same_original_unapproved_proposal_id":self.original_preview["migration"]["proposal_id"],
                    "original_clock_nonce_templates_keys_and_review_preserved":True})
            self.pending_only()
        if not self.args.after_source_import_dir:self.case(CASES[0],preview)
        def approved():
            value=self.api("owner","POST",self.route+"/prepare",dict(self.prepare_body,approve=True));self.wrapper(value)
            for _ in range(8):
                # Approved dependency-ready slots may be visible before the
                # following durable signature phase. Validate their exact
                # typed raw-root messages; resume lets the actual owning
                # daemon advance them without exporting its key to this test.
                for slot in value["signing_requests"]:
                    require(set(slot)==SLOT_FIELDS and slot["object_type"] in ("migration_proposal","root_state","person_lease") and
                        slot["role"]=="issuer" and slot["format"]=="ed25519" and
                        slot["public_key"]==value["review"]["legacy_root_public_key"],"approved preparation exposed an unrelated signing role/key")
                    template=strict_output(unb64(slot["template_base64"]));identifier=statement_id(template)
                    require(template["kind"]==slot["object_type"] and template["context_id"]==value["review"]["new_context_id"] and
                        slot["object_id"]==identifier and unb64(slot["message_base64"])==
                        lines("peerspan-decentralized-signature-v1",identifier,"issuer",slot["public_key"]),
                        "approved root slot changed its exact template/context/role message")
                candidate=self.export("owner",allow_pending=True)
                if (set(candidate)==EVIDENCE and type(candidate["catalog"]) is dict and
                    {entry["kind"] for entry in candidate["catalog"]["objects"]}>={"root_state","person_lease"}):
                    self.evidence=candidate;break
                value=self.api("owner","POST",self.route+"/resume",{});self.wrapper(value)
            else:raise CheckFailure("approved owned-root preparation did not expose its bounded complete initial proof set")
            self.verify_evidence(self.evidence)
            before=all_database_snapshots(self.hosts["owner"].host.state)
            require(self.export("owner")==self.evidence and all_database_snapshots(self.hosts["owner"].host.state)==before,
                "same original-source export regenerated nonce/proofs/state")
            self.pending_only();self.trace.append({"proposal_id":self.proposal_id,"context_id":self.context,
                "exact_source_catalog_sha256":sha(unb64(self.evidence["source_catalog_base64"])),
                "exact_source_state_sha256":sha(unb64(self.evidence["source_state_base64"])),
                "actual_selected_legacy_nominal_scopes":self.identities["selected"]["scopes"],
                "one_shared_ordinary_person_head":True,"coordinator_started":False,"actual_keys_stayed_in_place":True})
        if not self.args.after_source_import_dir:self.case(CASES[1],approved)
        def imported():
            if not self.args.after_source_import_dir:
                s=self.hosts["selected"];before=all_database_snapshots(s.host.state)
                wrong=dict(self.evidence,source_catalog_base64=b64(unb64(self.evidence["source_catalog_base64"])+b"\n"))
                denied=self.api("selected","POST",self.route+"/evidence",wrong,status=400)
                require(denied.get("code")=="invalid" and all_database_snapshots(s.host.state)==before,
                    "unapproved source hash mismatch changed preparation or was accepted")
                value=self.api("selected","POST",self.route+"/evidence",self.evidence);self.wrapper(value)
                require(not value["migration"]["approved"] and not value["migration"]["fenced"] and not value["signing_requests"],
                    "public evidence supplied local participation/acknowledgment consent")
            value=self.api("selected","POST",self.route+"/review",{"proposal_id":self.proposal_id,"approve":False});self.wrapper(value)
            require(not value["migration"]["approved"],"default-no participation review supplied approval")
            self.pending_only()
            value=self.api("selected","POST",self.route+"/review",{"proposal_id":self.proposal_id,"approve":True});self.wrapper(value)
            require(value["migration"]["approved"] and not value["migration"]["fenced"] and not value["signing_requests"],
                "separate participation review created acknowledgment/signature/fence")
            require(self.export("selected")==self.evidence,"review/import changed exact source/prepared proof bytes")
            self.pending_only()
        self.case(CASES[2],imported)
        def request():
            value=self.api("selected","POST",self.route+"/link",{"proposal_id":self.proposal_id},status=201)
            require(set(value)==LINK_FIELDS|{"display_code"} and value["mode"]=="new" and value["migration_proposal_id"]==self.proposal_id and
                value["host_public_key"]==self.identities["selected"]["host_public_key"] and
                value["device_public_key"]==self.identities["selected"]["device_public_key"] and not value["selection_approved"] and
                not value["commit_approved"] and value["activation_id"]==value["outcome_id"]=="-",
                "staged new request changed the actual old device or supplied consent/adoption")
            rows=table_rows(self.hosts["selected"].host,"dec_pending","record"," WHERE request_id=?",(value["request_id"],))
            require(len(rows)==1,"staged request was not retained exactly once")
            packet=strict_output(unb64(strict_output(rows[0][0].encode())["request_packet_base64"]));payload=strict_output(unb64(packet["payload_base64"]))
            require(payload["mode"]=="new" and payload["migration_proposal_id"]==self.proposal_id and
                payload["expected_network_id"]==self.network and payload["expected_context_id"]==self.context and
                payload["expected_person_public_key"]==self.person,"signed staged request did not bind the approved exact migration/context/owner")
            for key,field in ((self.specs["selected"]["host_public_key"],"host_signature"),
                              (self.specs["selected"]["device_public_key"],"device_signature")):
                self.hosts["selected"].verify_raw(key,packet_message(packet),packet[field])
            require(self.api("selected","POST",self.route+"/link",{"proposal_id":self.proposal_id},status=200)==value,
                "exact staged request retry regenerated identity/window/code/bytes")
            self.pending_only();self.trace.append({"staged_request_id":value["request_id"],"request_packet_sha256":sha(unb64(strict_output(rows[0][0].encode())["request_packet_base64"])),
                "source_selected_device_and_roster_nominal_profile_preserved":True,
                "no_new_device_lease_issued_by_this_request_control":True,"no_new_context_provider_or_outcome":True})
        self.case(CASES[3],request)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--list-cases",action="store_true")
    parser.add_argument("--continue-preview-dir",type=Path,help="Retry only failed unsigned-preview visibility on exact pending work; skip prior404/purity substeps")
    parser.add_argument("--after-source-import-dir",type=Path,help="Only failed participation review plus unevaluated staged request; exact already imported source reused")
    for name in ("owner","selected","retained-dir","work-dir","results"):parser.add_argument("--"+name,type=Path)
    args=parser.parse_args()
    if args.continue_preview_dir and args.after_source_import_dir:parser.error("unapproved-preview and imported-source continuations differ")
    if args.list_cases:print(json.dumps({"contract_pin":PIN,"cases":CASES,"product_execution":False},indent=2));return 0
    for name in ("owner","selected","retained_dir","work_dir","results"):
        if getattr(args,name) is None:parser.error("all paths required")
        setattr(args,name,getattr(args,name).resolve())
    if args.continue_preview_dir:args.continue_preview_dir=args.continue_preview_dir.resolve()
    if args.after_source_import_dir:args.after_source_import_dir=args.after_source_import_dir.resolve()
    args.work_dir.mkdir(mode=0o700,parents=True,exist_ok=False)
    keys=FixtureKeys();suite=None;failure=detail=None;began=time.monotonic()
    try:suite=Preparation(args,keys);suite.run()
    except BaseException as error:failure,detail=type(error).__name__,str(error) if isinstance(error,CheckFailure) else "fixture/transport failure"
    finally:
        if suite is not None:
            for s in reversed(list(suite.hosts.values())):
                try:s.host.stop()
                except BaseException as error:failure=failure or type(error).__name__
        keys.close()
    support=("decentralized_complete_link.py","decentralized_migration_identity.py","decentralized_fixtures.py",
        "decentralized_owner_preview.py","decentralized_requester.py","decentralized_runtime.py","decentralized_storage.py","decentralized_vectors.py")
    result={"contract_pin":PIN,"implementation_source_read":False,"suite_sha256":sha(Path(__file__).read_bytes()),
        "support_sha256":{name:sha(Path(__file__).with_name(name).read_bytes()) for name in support},
        "artifacts":{name:{"path":str(getattr(args,name)),"sha256":sha(getattr(args,name).read_bytes())} for name in ("owner","selected")},
        "retained_dir":str(args.retained_dir),"rows":[] if suite is None else suite.rows,"trace":[] if suite is None else suite.trace,
        "continued_preview_dir":str(args.continue_preview_dir) if args.continue_preview_dir else None,
        "after_source_import_dir":str(args.after_source_import_dir) if args.after_source_import_dir else None,
        "failure":failure,"detail":detail,"seconds":round(time.monotonic()-began,3),
        "scope":"original actual legacy owned pair: proposal/source export/import/separate participation review and exact staged request only; no completed seven-stage preparation, unbound H, ACK/fence/commit/adoption/native/installed claim",
        "passed":failure is None and suite is not None and len(suite.rows)==(2 if args.after_source_import_dir else len(CASES)) and all(row["passed"] for row in suite.rows)}
    args.results.parent.mkdir(parents=True,exist_ok=True);args.results.write_text(json.dumps(result,indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__=="__main__":raise SystemExit(main())
