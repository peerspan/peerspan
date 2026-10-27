#!/usr/bin/env python3
"""Independent current-self-withdrawal carrier and permanently banned repair.

Create a fresh actual admitted pair through our existing public-consent fixture
as uncounted setup. Stop B before A locally revokes A's own host, then stop A
before restarting B. The raw probe uses A's actual state in place: no background
delivery race, copied daemon key, fabricated remote prior or authority marker.
These three new controls exclude expired-member and partial-container repair.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import subprocess
import textwrap
import time
from datetime import datetime

from decentralized_complete_link import CompleteLink, packet_message, statement_id, table_rows
from decentralized_fixtures import FixtureKeys, b64, lines, raw_json, sha, ssh_string, unb64
from decentralized_peer import PEER, REPAIR, PeerReplication
from decentralized_storage import CheckFailure, all_database_snapshots, require
from decentralized_vectors import strict_output


CASES = ["current_member_can_carry_own_permanent_host_withdrawal",
         "known_host_ban_denies_normal_and_repair_without_disclosure",
         "restart_retains_ban_and_denied_reads_do_not_mutate_authority"]


class KnownBan(PeerReplication):
    def __init__(self,args,keys):
        self.args,self.keys,self.root = args,keys,args.work_dir
        self.rows,self.trace,self.prior_passed,self.wire_count = [],[],set(),0
        self.flow = CompleteLink(args.owner,args.requester,self.root,keys)
        self.hosts = {"owner":self.flow.owner,"requester":self.flow.requester}
        self.addresses = {}
        self.receipts = self.root/"wire"; self.receipts.mkdir(mode=0o700)
        for label,instance in self.hosts.items():
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as reserved:
                reserved.bind(("127.0.0.1",0)); address="127.0.0.1:"+str(reserved.getsockname()[1])
            self.addresses[label]=address
            config=instance.root/"transport.json"
            config.write_bytes(raw_json({"format":1,"advertise_bootstrap":[self.flow.endpoints[label]["address"]],
                "advertise_quic":[address],"rendezvous":[],"relays":[],"publish_contacts":False}));config.chmod(0o600)
            instance.host.run_arguments += ["--peer-listen",address,"--advertise",address,"--transport-config",str(config)]

    def retained_setup(self):
        """Verify an already applied setup after its local HTTP client timed out."""
        retained=self.args.retained_dir
        clock=retained/"requester"/"clock";self.original_clock=clock.read_bytes()
        self.flow.requester.clock=clock
        self.flow.requester.base=datetime.fromisoformat(self.original_clock.decode().replace("Z","+00:00"))
        for label,s in self.hosts.items():
            s.host.state=retained/label/"state"
            require(not (s.host.state/"admin.sock").exists(),"retained applied setup is not stopped")
            s.host.environment.update(PEERSPAN_DEC_TEST_MODE="1",PEERSPAN_DEC_TEST_CLOCK_FILE=str(clock))
        rows=table_rows(self.hosts["requester"].host,"dec_pending","request_id,record,secret")
        require(len(rows)==1 and rows[0][2] is None,"retained setup did not retire the requester pairing secret")
        identifier,encoded,_=rows[0];pending=strict_output(encoded.encode())
        require(pending["terminal"]=="applied" and pending["selection_approved"] is True and pending["commit_approved"] is True,
            "retained requester was not actually applied under both existing consents")
        descriptor=strict_output(unb64(pending["descriptor_base64"]))
        self.flow.request={"request_id":identifier,"host_public_key":pending["host_public_key"],"device_public_key":pending["device_public_key"]}
        self.flow.request_route="/v2/link/requests/"+identifier
        before={label:all_database_snapshots(s.host.state) for label,s in self.hosts.items()}
        (self.root/"retained-applied-setup-before-hashes.json").write_bytes(raw_json(before))
        for s in self.hosts.values():s.host.start();s.identity=s.host.api("GET","/v1/host")
        self.flow.network=self.hosts["owner"].api("GET","/v2/networks/"+descriptor["network_id"])[0]

        def remember_original(object_id,role,message,public,signature):
            require(public==self.keys.public("alice"),"retained original signer changed")
            allowed=self.keys.directory/"ban-allowed-signers"
            allowed.write_text("fixture ssh-ed25519 "+b64(ssh_string(b"ssh-ed25519")+ssh_string(unb64(public)))+"\n")
            sig=self.keys.directory/"ban-retained.sig"
            sig.write_text("-----BEGIN SSH SIGNATURE-----\n"+"\n".join(textwrap.wrap(signature,70))+"\n-----END SSH SIGNATURE-----\n")
            checked=subprocess.run(["ssh-keygen","-Y","verify","-f",str(allowed),"-I","fixture","-n","peerspan-person-v1","-s",str(sig)],
                input=message,capture_output=True,timeout=10)
            require(checked.returncode==0,"retained original typed signature does not independently verify")
            self.flow.signatures[(object_id,role)]=signature

        manifests={};operations={}
        for label,s in self.hosts.items():
            row=self.flow.operation(s);operations[label]=sha(raw_json(row))
            record=strict_output(row[5].encode());activation=strict_output(unb64(record["activation_base64"]))
            for role in ("owner","administrator","owner_finalization"):
                packet=activation[role];message=packet_message(packet)
                remember_original("dpk_"+sha(message),"authority",message,packet["signer_public_key"],packet["authority_signature"])
            for entry in strict_output(unb64(record["catalog_base64"]))["objects"]:
                if entry["kind"]=="activation":continue
                statement=strict_output(unb64(entry["body_base64"]));identifier_ds=statement_id(statement)
                for signature in statement["signatures"]:
                    if signature["format"]=="sshsig":
                        message=lines("peerspan-decentralized-signature-v1",identifier_ds,signature["role"],signature["public_key"])
                        remember_original(identifier_ds,signature["role"],message,signature["public_key"],signature["signature"])
            manifests[label]=self.flow.verify_complete(row,s.identity["public_key"])
        require(manifests["owner"]==manifests["requester"],"retained participants completed different manifests")
        provider=self.hosts["requester"].api("GET","/v2/networks/"+descriptor["network_id"]+"/provider")[0]
        network=self.hosts["requester"].api("GET","/v2/networks/"+descriptor["network_id"])[0]
        require(provider["kind"]=="device" and provider["device_public_key"]==pending["device_public_key"] and
            provider["lease_id"]==manifests["requester"]["device_lease_id"] and network["provider_state"]["state"]=="available" and
            network["authority"]["state"]=="usable","retained setup lost its selected usable owned device")
        self.trace.append({"uncounted_retained_actual_applied_setup":{"directory":str(retained),"request_id":identifier,
            "operation_hashes":operations,"complete_signatures_manifest_and_host_outcomes_verified":True,
            "selected_owned_device_and_secret_retirement_verified":True,"original_clock":self.original_clock.decode(),
            "no_preparation_consent_or_signature_repeated":True}})

    def prepare(self):
        # These public APIs are the necessary fresh fixture constructor, not a
        # repeat receipt for the earlier seven-case launch/phase suite.
        setup_steps=[]
        if self.args.retained_dir:self.retained_setup()
        else:
            original = self.flow.owner.case
            def uncounted(name,function):
                if name in {"complete_link/either_restart_and_exact_retry_preserve_original_local_outcomes",
                            "complete_link/bootstrap_router_and_participant_outcome_auth_remain_isolated"}:
                    return
                result=function();setup_steps.append(name);return result
            self.flow.owner.case=uncounted
            try:self.flow.run()
            finally:self.flow.owner.case=original
        self.network,self.context=self.flow.network["id"],self.flow.network["context_id"]
        self.route="/peer/v2/networks/"+self.network
        self.repair_route="/repair/v1/networks/"+self.network+"/catalog"
        self.trace.append({"uncounted_fresh_public_admission_setup":setup_steps,
            "actual_host_public_keys":{k:v.identity["public_key"] for k,v in self.hosts.items()},
            "original_operation_hashes":{k:self.operation_hash(k) for k in self.hosts},
            "no_actual_daemon_key_copy":True})
        (self.root/"fresh-before-ban-state-hashes.json").write_bytes(raw_json(
            {k:all_database_snapshots(v.host.state) for k,v in self.hosts.items()}))
        # Freeze B's independently current prior before the ban exists.
        self.hosts["requester"].host.stop()
        a=self.hosts["owner"]
        payload={"root_state_id":self.flow.network["root_state_id"],"issuer":{"kind":"root","person_public_key":"-"},
            "parents":[],"issued_at":self.flow.requester.clock.read_text(),
            "target":{"statement_id":"-","person_public_key":"-","host_public_key":a.identity["public_key"],"device_public_key":"-"},
            "kept_statement_ids":[],"ratifies":"-"}
        value,_=a.api("POST","/v2/networks/"+self.network+"/actions",{"kind":"host_revoke","provider_id":"network_root",
            "signature_format":"ed25519","payload_base64":b64(raw_json(payload)),"approve":True})
        require(set(value)=={"action_id","review","signing_requests","statement_base64","proof_id","catalog","committed","delivery"}
            and value["committed"] is True and value["signing_requests"]==[],"explicit local root host revocation did not commit")
        body=unb64(value["statement_base64"]);statement=strict_output(body)
        self.ban_id=statement_id(statement)
        require(statement["kind"]=="host_revoke" and statement["context_id"]==self.context and
            strict_output(unb64(statement["payload_base64"]))==payload,"root action changed exact self-ban target or authority")
        network,_=a.api("GET","/v2/networks/"+self.network)
        signatures=statement["signatures"]
        require(len(signatures)==1 and signatures[0]["role"]=="issuer" and signatures[0]["format"]=="ed25519" and
            signatures[0]["public_key"]==network["root_public_key"],"self-ban has wrong current root signer/role")
        a.verify_raw(signatures[0]["public_key"],lines("peerspan-decentralized-signature-v1",self.ban_id,"issuer",signatures[0]["public_key"]),
            signatures[0]["signature"])
        require(value["proof_id"]=="dp_"+sha(lines("peerspan-decentralized-proof-v1","host_revoke",sha(body))),"self-ban proof hash differs")
        self.proof_id=value["proof_id"]
        self.candidate=a.api("GET","/v2/networks/"+self.network+"/catalog")[0]
        self.catalog(self.candidate)
        a.host.stop()
        # A has no process that could deliver an outbox before our exact POST.
        self.hosts["requester"].host.start()
        require(not table_rows(self.hosts["requester"].host,"dec_restrictions","restriction_id"," WHERE restriction_id=?",(self.ban_id,)),
                "receiver already learned the ban before isolated explicit carrier")

    def ban_present(self):
        require(len(table_rows(self.hosts["requester"].host,"dec_restrictions","restriction_id"," WHERE restriction_id=?",(self.ban_id,)))==1,
            "exact current-root permanent host ban was not admitted or did not persist")

    def denied(self,alpn):
        path=self.route+"/catalog" if alpn==PEER else self.repair_route
        status,value,result=self.wire("requester","owner","GET",path,alpn=alpn)
        if alpn==PEER and status is None:
            require(result.returncode!=0 and not result.stdout,"banned normal caller received response data")
        else:
            require(status==403 and type(value) is dict and value.get("code")=="forbidden" and "catalog" not in value,
                "known banned host did not receive403/no catalog on isolated repair router")

    def run(self):
        self.prepare()
        def carry():
            # Prior-current route control immediately before the exact ban POST.
            self.catalog(self.success("requester","owner","GET",self.route+"/catalog"))
            value=self.success("requester","owner","POST",self.route+"/catalog",self.candidate)
            proofs=self.catalog(value)[1]
            require(self.proof_id in proofs,"own-withdrawal response omitted exact signed ban proof")
            self.ban_present()
        self.case("requester",CASES[0],carry)
        def deny():
            before=self.authority("requester")
            self.denied(PEER);self.denied(REPAIR);self.ban_present()
            require(self.authority("requester")==before,"denied banned-host reads changed authority/clock/provider")
        self.case("requester",CASES[1],deny)
        def restart():
            before=self.authority("requester");operation=self.operation_hash("requester")
            b=self.hosts["requester"];identity=b.identity["public_key"]
            b.host.stop();b.host.start()
            require(b.host.api("GET","/v1/host")["public_key"]==identity,"receiver restart replaced actual host identity")
            self.ban_present();self.denied(REPAIR)
            require(self.authority("requester")==before and self.operation_hash("requester")==operation,
                "restart or banned repair read lost restriction/heads/maxima/guard/selection/outcome")
        self.case("requester",CASES[2],restart)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("owner","requester","probe","work-dir","results"):parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--retained-dir",type=Path,help="Verify SAME already applied setup after an unanswered local response; no preparation or consent repeat")
    args=parser.parse_args()
    for name in ("owner","requester","probe","work_dir","results"):setattr(args,name,getattr(args,name).resolve())
    args.work_dir.mkdir(mode=0o700,parents=True,exist_ok=False)
    keys=FixtureKeys();suite=KnownBan(args,keys);failure=detail=None;began=time.monotonic()
    try:
        suite.run()
        if args.retained_dir:require((args.retained_dir/"requester"/"clock").read_bytes()==suite.original_clock,"continuation rewrote the original decision clock")
    except BaseException as error:failure,detail=type(error).__name__,str(error) if isinstance(error,CheckFailure) else "fixture/transport failure"
    finally:
        for instance in reversed(list(suite.hosts.values())):
            try:instance.host.stop()
            except BaseException as error:
                failure=failure or type(error).__name__;suite.rows.append({"name":"cleanup","passed":False,"error_type":type(error).__name__})
        keys.close()
    support=("decentralized_peer.py","decentralized_complete_link.py","decentralized_fixtures.py","decentralized_owner_preview.py",
        "decentralized_runtime.py","decentralized_storage.py","decentralized_vectors.py",
        "decentralized_requester.py","decentralized_helper.py","decentralized_direct_carrier.py")
    result={"contract_pin":"dada7fcedc4a215f79a78e08f2bedfa14e374931","implementation_source_read":False,
        "suite_sha256":sha(Path(__file__).read_bytes()),"support_sha256":{n:sha(Path(__file__).with_name(n).read_bytes()) for n in support},
        "artifacts":{n:{"path":str(getattr(args,n)),"sha256":sha(getattr(args,n).read_bytes())} for n in ("owner","requester","probe")},
        "planned_cases":CASES,"rows":suite.rows,"trace":suite.trace,"failure":failure,"detail":detail,"seconds":round(time.monotonic()-began,3),
        "scope":"new actual-current self-withdrawal carrier and known permanently banned-host normal/repair gates; fresh admission is uncounted setup; no expired/partial-container/data/installed claim",
        "passed":failure is None and len(suite.rows)==3 and all(r["passed"] for r in suite.rows)}
    args.results.parent.mkdir(parents=True,exist_ok=True);args.results.write_text(json.dumps(result,indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__=="__main__":raise SystemExit(main())
