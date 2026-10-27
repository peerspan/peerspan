#!/usr/bin/env python3
"""Only a failed finalization/commit and its unevaluated full-link dependents.

Reuse the SAME stopped actual pair after its administrator case passed. Keep
the original clock, identities, request, reviewed packets and all private state
in place. A fully signed failed commit retries its exact existing approval body
and preserves every signed pin. The exact existing CompleteLink functions supply
the oracle; no passed-case repeat, replacement consent, key copy or source read.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import time

from decentralized_complete_link import CompleteLink, packet_message, statement_id, table_rows
from decentralized_fixtures import FixtureKeys, b64, lines, raw_json, sha, unb64
from decentralized_requester import Requester
from decentralized_runtime import CreationSuite
from decentralized_storage import CheckFailure, all_database_snapshots, require
from decentralized_vectors import strict_output


class FinalizationContinuation(CompleteLink):
    def __init__(self,owner_binary,requester_binary,retained,root,keys,after_finalization=False,after_commit_preview=False):
        self.root,self.keys,self.retained=root,keys,retained
        self.after_commit_preview=after_commit_preview
        self.after_finalization=after_finalization or after_commit_preview
        for label in ("owner","requester"):(root/label).mkdir(mode=0o700)
        self.owner=CreationSuite(owner_binary,root/"owner",keys)
        self.requester=Requester(requester_binary,root/"requester",keys)
        self.rows,self.trace,self.signatures,self.fixed_slots=self.owner.rows,[],{},{}
        self.endpoints={}
        self.original_clock=(retained/"requester"/"clock").read_bytes()
        self.requester.clock=retained/"requester"/"clock"
        self.requester.base=datetime.fromisoformat(self.original_clock.decode().replace("Z","+00:00"))
        for label,instance in (("owner",self.owner),("requester",self.requester)):
            instance.host.state=retained/label/"state"
            require(not (instance.host.state/"admin.sock").exists(),"retained actual fixture is not stopped")
            instance.host.environment.update(PEERSPAN_DEC_TEST_MODE="1",PEERSPAN_DEC_TEST_CLOCK_FILE=str(self.requester.clock))
        original_case=self.owner.case
        def remaining(name,function):
            if name=="complete_link/explicit_admin_grant_remains_pending_without_final_consent":return
            if self.after_finalization and name=="complete_link/explicit_owner_finalization_cannot_commit_for_requester":return
            if self.after_commit_preview and name=="complete_link/final_preview_and_wrong_target_never_grant_consent":return
            if self.after_commit_preview and name=="complete_link/explicit_final_consent_atomically_adopts_exact_owned_device":
                original=function
                def function():
                    try:return original()
                    finally:self.require_same_signed_commit()
            return original_case(name,function)
        self.owner.case=remaining

    def signed_commit(self):
        """Hash only normative immutable pins; terminal/result may advance on apply."""
        b=self.requester
        pending=strict_output(table_rows(b.host,"dec_pending","record"," WHERE request_id=?",(self.request["request_id"],))[0][0].encode())
        fields=("mode","migration_proposal_id","expected_network_id","expected_context_id","expected_person_public_key",
            "contact_invitation_base64","descriptor_base64","host_public_key","device_public_key","request_nonce",
            "request_packet_base64","owner_packet_base64","selection_packet_base64","administrator_packet_base64",
            "owner_finalization_packet_base64","commit_packet_base64","owner_offer_id","selection_id",
            "administrator_offer_id","owner_finalization_id","manifest_id","activation_id","selection_approved",
            "commit_approved","owner_intent_id","administrator_intent_id","selection_intent_id","commit_intent_id")
        rows=table_rows(b.host,"dec_intents","intent_id,network_id,context_id,kind,record",
            " WHERE intent_id=?",(pending["commit_intent_id"],))
        require(len(rows)==1 and rows[0][3]=="requester_commit","signed pending commit lost its exact typed intent")
        intent=strict_output(rows[0][4].encode())
        require(intent["approved"] is True and intent["completed"] is True and intent["operation_id"]==self.request["request_id"] and
            intent["provider"]["kind"]=="requester" and intent["provider"]["signer_public_key"]==pending["device_public_key"],
            "retry does not retain the fully approved, signed requester commit")
        immutable={key:value for key,value in intent.items() if key not in {"terminal","result_base64"}}
        return {"pending":{field:pending[field] for field in fields},"intent_tuple":list(rows[0][:4]),"intent":immutable,
            "all_requester_intent_ids":sorted(row[0] for row in table_rows(b.host,"dec_intents","intent_id"))}

    def require_same_signed_commit(self):
        require(self.signed_commit()==self.signed_commit_before,"retry replaced consent, provider, key, fixed template, signature or complete packet")

    def setup(self):
        a,b=self.owner,self.requester
        rows=table_rows(b.host,"dec_pending","request_id,record,secret")
        require(len(rows)==1 and type(rows[0][2]) is bytes and len(rows[0][2])==16,
            "retained requester does not have the original unresolved pairing secret")
        identifier,encoded,secret=rows[0];pending=strict_output(encoded.encode())
        require(pending["terminal"]=="-" and pending["selection_approved"] is True and
            pending["commit_approved"] is self.after_commit_preview and pending["administrator_packet_base64"]!="-",
            "retained pair is not the exact original unresolved consent stage")
        if self.after_commit_preview:
            require(pending["commit_packet_base64"]!="-" and pending["manifest_id"].startswith("dm_") and
                pending["activation_id"].startswith("da_"),"four-only continuation lacks the already signed complete commit")
        else:
            require(pending["commit_packet_base64"]==pending["activation_id"]=="-","retained pair already signed a final commit")
        self.request=strict_output((self.retained/"requester"/"public-responses"/"001.json").read_bytes())
        require(self.request["request_id"]==identifier,"retained original created response does not name the pending request")
        self.request_route="/v2/link/requests/"+identifier
        if self.after_commit_preview:self.signed_commit_before=self.signed_commit()
        descriptor=strict_output(unb64(pending["descriptor_base64"]))
        b.world.descriptor=descriptor
        b.world.context_id=pending["expected_context_id"]
        b.identity={"public_key":pending["host_public_key"]}
        _,original_secret=b.decode_request(self.request)
        require(original_secret==secret,"same retained request/code now names another private pairing secret")
        packets={role:strict_output(unb64(pending[field])) for role,field in
            (("owner","owner_packet_base64"),("administrator","administrator_packet_base64"),("request","request_packet_base64"))}
        if self.after_finalization:
            require(pending["owner_finalization_packet_base64"]!="-","five-only continuation lacks the already-observed finalization")
            packets["owner_finalization"]=strict_output(unb64(pending["owner_finalization_packet_base64"]))
        owner_payload=strict_output(unb64(packets["owner"]["payload_base64"]))
        self.terms={"scopes":owner_payload["scopes"],"not_after":owner_payload["not_after"]}
        for role in ("owner","administrator")+(("owner_finalization",) if self.after_finalization else ()):
            packet=packets[role];message=packet_message(packet)
            require(packet["signer_public_key"]==self.keys.public("alice") and packet["authority_signature_format"]=="sshsig",
                "retained approved packet changed the fixture-owned original authority")
            signature=b64(self.keys.sshsig("alice",message))
            require(signature==packet["authority_signature"],"retained authority packet differs from independently reproducible original signature")
            self.signatures[("dpk_"+sha(message),"authority")]=signature
        entries=list(strict_output(unb64(pending["catalog_base64"]))["objects"])
        if self.after_finalization:
            payload=strict_output(unb64(packets["owner_finalization"]["payload_base64"]))
            for field in ("binding_lease","device_lease"):
                if type(payload[field]) is dict:entries.append({"kind":payload[field]["kind"],"body_base64":b64(raw_json(payload[field]))})
        for entry in entries:
            if entry["kind"]=="activation":continue
            statement=strict_output(unb64(entry["body_base64"]));ds=statement_id(statement)
            for signature in statement["signatures"]:
                if signature["format"]!="sshsig":continue
                require(signature["public_key"]==self.keys.public("alice"),"retained catalog changed its original signer")
                message=lines("peerspan-decentralized-signature-v1",ds,signature["role"],signature["public_key"])
                expected=b64(self.keys.sshsig("alice",message))
                require(expected==signature["signature"],"retained catalog signature is not the exact fixture-owned original")
                self.signatures[(ds,signature["role"])]=expected
        for label,packet in (("owner",packets["owner"]),("requester",packets["request"])):
            public=packet["writer_host_public_key"]
            endpoints=[e for e in pending["carrier_endpoints"] if e["kind"]=="participant" and e["public_key"]==public]
            require(len(endpoints)==1,"original pinned actual participant endpoint is not unique")
            self.endpoints[label]={k:endpoints[0][k] for k in ("address","public_key")}
            instance=a if label=="owner" else b
            instance.identity={"public_key":public}
            instance.host.run_arguments=["--bootstrap-listen",endpoints[0]["address"]]
        require(not table_rows(a.host,"dec_operations","request_id"," WHERE request_id=?",(identifier,)) and
            not table_rows(b.host,"dec_operations","request_id"," WHERE request_id=?",(identifier,)),
            "a participant already applied before the failed finalization preview")
        (self.root/"before-state-hashes.json").write_bytes(raw_json({label:all_database_snapshots(instance.host.state)
            for label,instance in (("owner",a),("requester",b))}))
        for label,instance in (("owner",a),("requester",b)):
            expected=instance.identity["public_key"]
            instance.host.start();instance.identity=instance.host.api("GET","/v1/host")
            require(instance.identity["public_key"]==expected,"continuation replaced actual participant identity")
        self.network=a.api("GET","/v2/networks/"+descriptor["network_id"])[0]
        a.member=self.network["member"]
        require(self.network["context_id"]==b.world.context_id,"retained source context changed on reopen")
        if self.after_finalization:
            self.commit_terms={"network_id":self.network["id"],"context_id":self.network["context_id"],
                "person_public_key":self.keys.public("alice"),"host_public_key":self.request["host_public_key"],
                "device_public_key":self.request["device_public_key"],
                **{field:pending[field] for field in ("owner_offer_id","selection_id","administrator_offer_id","owner_finalization_id")}}
        if self.after_commit_preview:
            original_request=(self.retained/"failed-commit-approval-request.public.json").read_bytes()
            exact=strict_output(original_request)
            require(exact==dict(self.commit_terms,approve=True),"retry differs from the original failed exact approval body")
            self.commit_terms={key:value for key,value in exact.items() if key!="approve"}
            self.require_same_signed_commit()
            self.trace.append({"skipped_already_passed_commit_preview_and_wrong_target":True,
                "retry_existing_signed_commit_without_new_consent_or_signatures":True,
                "original_failed_approval_request_sha256":sha(original_request),
                "signed_commit_immutable_pins_sha256":sha(raw_json(self.signed_commit_before))})
        self.trace.append({"continued_original_failed_finalization":identifier,"skipped_already_passed_administrator":True,
            "same_original_clock":self.original_clock.decode(),"no_actual_daemon_key_copy":True,
            "pairing_secret_sha256":sha(secret),"owner_offer_id":pending["owner_offer_id"],
            "selection_id":pending["selection_id"],"administrator_offer_id":pending["administrator_offer_id"]})
        if self.after_finalization:self.trace.append({"skipped_already_passed_finalization":pending["owner_finalization_id"]})
        time.sleep(2.05)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("owner","requester","retained-dir","work-dir","results"):p.add_argument("--"+name,type=Path,required=True)
    stage=p.add_mutually_exclusive_group()
    stage.add_argument("--after-finalization",action="store_true",help="Skip actual passed F; run only failed commit-preview plus four dependents")
    stage.add_argument("--after-commit-preview",action="store_true",help="Skip passed preview/F/admin; retry existing signed commit and three unevaluated dependents")
    args=p.parse_args();args.work_dir.mkdir(mode=0o700,parents=True,exist_ok=False)
    keys=FixtureKeys();suite=FinalizationContinuation(args.owner.resolve(),args.requester.resolve(),args.retained_dir.resolve(),args.work_dir.resolve(),keys,args.after_finalization,args.after_commit_preview)
    failure=detail=None;began=time.monotonic()
    try:
        suite.run()
        require((suite.retained/"requester"/"clock").read_bytes()==suite.original_clock,"continuation changed the original fixed authority clock")
    except BaseException as e:failure,detail=type(e).__name__,str(e) if isinstance(e,CheckFailure) else "fixture/transport failure"
    finally:
        for instance in (suite.requester,suite.owner):
            try:
                instance.host.stop()
                logs=instance.host.log_path.read_bytes() if instance.host.log_path.exists() else b""
                require(not any(v and v in logs for v in suite.requester.sensitive),"host log exposed original code/secret")
            except BaseException as e:failure=failure or type(e).__name__;suite.rows.append({"name":"cleanup","passed":False,"error_type":type(e).__name__})
        keys.close()
    support=("decentralized_complete_link.py","decentralized_owner_preview.py","decentralized_direct_carrier.py","decentralized_fixtures.py",
        "decentralized_helper.py","decentralized_storage.py","decentralized_requester.py","decentralized_runtime.py","decentralized_vectors.py")
    result={"implementation_source_read":False,"contract_pin":"7c5a483aa01d87a5d3715bc8fef902f4839ba214",
        "additional_contract_pins":{"durable_review_signature_frame":"0ea487eba4134b851c87816b7d54776f7b8bee31"},
        "suite_sha256":sha(Path(__file__).read_bytes()),"support_sha256":{n:sha(Path(__file__).with_name(n).read_bytes()) for n in support},
        "artifacts":{n:{"path":str(getattr(args,n).resolve()),"sha256":sha(getattr(args,n).read_bytes())} for n in ("owner","requester")},
        "retained_dir":str(args.retained_dir.resolve()),"rows":suite.rows,"trace":suite.trace,"failure":failure,"detail":detail,
        "seconds":round(time.monotonic()-began,3),"scope":("same fully signed failed commit exact retry plus three unevaluated dependents; passed preview/F/admin skipped" if args.after_commit_preview else
            "unchanged failed commit-preview plus four unevaluated dependents; passed F/admin skipped" if args.after_finalization else
            "unchanged failed finalization plus five unevaluated dependents")+" on SAME actual pair; no copied daemon key, crash/relay/installed claim",
        "passed":failure is None and len(suite.rows)==(4 if args.after_commit_preview else 5 if args.after_finalization else 6) and all(r["passed"] for r in suite.rows)}
    args.results.parent.mkdir(parents=True,exist_ok=True);args.results.write_text(json.dumps(result,indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__=="__main__":raise SystemExit(main())
