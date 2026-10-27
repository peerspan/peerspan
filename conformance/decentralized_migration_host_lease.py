#!/usr/bin/env python3
"""Independent PR126 unbound host-membership handoff, public contracts only.

Reuse the originally approved unbound U fixture in place. The actual daemon
owns its legacy root and host keys; the suite never exports/copies them and
never generates a person/device. Root preparation and host consent are separate.
No evidence carrier, ACK/fence/commit/adoption or full migration is exercised.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import time

from decentralized_complete_link import statement_id, table_rows
from decentralized_fixtures import FixtureKeys, b64, lines, raw_json, sha, unb64
from decentralized_migration_identity import INTENT, ROSTER, VIEW, moment, stamp
from decentralized_migration_preparation import Preparation
from decentralized_owner_preview import authority_rows
from decentralized_runtime import CreationSuite, SLOT_FIELDS
from decentralized_storage import CheckFailure, all_database_snapshots, require
from decentralized_vectors import strict_output


PIN = "d6c6f45ebbb1e6198ae61b9ca99594a913c4b00a"
HREVIEW = set("stage network_id proposal_id host_public_key member root_state_id host_lease_id issued_at not_before not_after authority_warning".split())
CASES = [
    "unbound_root_fixes_issuer_before_exposing_exact_pending_host_template",
    "unbound_host_membership_preview_is_pure_and_supplies_no_consent",
    "unbound_explicit_host_consent_fixes_exact_body_across_retry_restart_and300",
    "changed_exact_host_template_conflicts_without_resigning_or_authority",
]


class HostLease:
    def __init__(self, args, keys):
        self.args, self.keys = args, keys
        self.rows, self.trace = [], []
        baseline = strict_output((args.fixture_dir/"legacy-public-baseline.json").read_bytes())
        specs = [row for row in baseline["specs"] if row["label"]=="unbound"]
        require(len(specs)==1 and specs[0]["person_public_key"]==specs[0]["device_public_key"]=="-" and specs[0]["scopes"]==0,
                "fixture is not the original actual unbound host")
        self.spec = specs[0]
        self.network = self.spec["network_id"]
        self.target = CreationSuite(args.host, args.work_dir/"target", keys)
        self.target.host.state = args.fixture_dir/"unbound"/"state"
        require(not (self.target.host.state/"admin.sock").exists(), "original unbound fixture is not stopped")
        self.target.host.environment["PATH"] = "/usr/bin:/bin"
        identities = table_rows(self.target.host, "dec_intents", "intent_id,record,secret", " WHERE kind='migration_identity'")
        require(len(identities)==1, "unbound fixture lacks its one original approved identity")
        identifier, encoded, secret = identities[0]
        identity = strict_output(encoded.encode())
        require(set(identity)==INTENT and identity["approved"] and identity["completed"] and identity["terminal"]=="-" and
                secret is None and all(identity[k]==self.spec[k] for k in ("person_public_key","host_public_key","device_public_key","scopes")),
                "unbound identity/host-only consent changed or contains a device seed")
        self.identity = identities
        self.roster = [{key:self.spec[key] for key in ROSTER}]
        anchors = [] if args.after_partial_dir else [datetime.now(timezone.utc).replace(microsecond=0)]
        for encoded_clock, in table_rows(self.target.host, "dec_clock", "record"):
            anchors.append(moment(strict_output(encoded_clock.encode())["largest_local_time"]))
        if args.after_partial_dir:
            self.now=moment((args.after_partial_dir/"authority-clock").read_text())
            require(all(self.now>=anchor for anchor in anchors),"same-state H continuation would rewind the guarded clock")
        else:self.now = max(anchors)
        self.clock = args.work_dir/"authority-clock"
        self.clock.write_text(stamp(self.now)); self.clock.chmod(0o600)
        self.target.host.environment.update(PEERSPAN_DEC_TEST_MODE="1",PEERSPAN_DEC_TEST_CLOCK_FILE=str(self.clock))
        self.route = "/v2/networks/"+self.spec["network_id"]+"/migration"

    def call(self, method, suffix, body=None, status=200):
        return self.target.api(method, self.route+suffix, body, status=status)[0]

    def no_authority(self):
        require(authority_rows(self.target)==self.authority_before, "inert H preparation changed live authority/provider/outcome")
        require(table_rows(self.target.host,"dec_intents","intent_id,record,secret"," WHERE kind='migration_identity'")==self.identity,
                "H preparation changed the original host-only approved identity")
        for encoded, in table_rows(self.target.host,"dec_migrations","record"):
            record=strict_output(encoded.encode())
            require(not record["fenced"] and record["local_acknowledgment_base64"]==record["commit_base64"]==record["migration_base64"]=="-",
                    "H consent manufactured ACK/fence/root commit/adoption")

    def parse_h(self, raw, *, complete):
        statement = strict_output(raw)
        require(set(statement)=={"format","kind","context_id","payload_base64","signatures"} and
                statement["format"]==1 and statement["kind"]=="host_lease" and statement["context_id"]==self.context,
                "host handoff is not the exact typed proposed host lease")
        payload = strict_output(unb64(statement["payload_base64"]))
        require(set(payload)==set("root_state_id operation_id sequence predecessors resolves retained_statement_ids subject issuer parents issued_at not_before not_after".split()) and
                payload["operation_id"]==self.proposal and payload["root_state_id"]==self.root_id and
                payload["sequence"]==1 and payload["predecessors"]==payload["resolves"]==payload["retained_statement_ids"]==[] and
                payload["parents"]==[] and payload["issuer"]=={"kind":"root","person_public_key":"-"} and
                payload["subject"]=={"member":self.spec["member"],"person_public_key":"-","host_public_key":self.spec["host_public_key"],"device_public_key":"-","scopes":0},
                "unbound H changed proposal/root/roster/roles/ordinary finite shape")
        require(moment(self.proposal_window[0])<=moment(payload["issued_at"])<=moment(self.proposal_window[1]) and
                moment(payload["not_before"])<=self.now<moment(payload["not_after"]) and
                timedelta(0)<moment(payload["not_after"])-moment(payload["issued_at"])<=timedelta(days=7),
                "unbound H is outside its fixed proposal/current finite interval")
        signatures=statement["signatures"]
        require([entry["role"] for entry in signatures]==["host","issuer"] and
                signatures[0]["public_key"]==self.spec["host_public_key"] and signatures[1]["public_key"]==self.root_key and
                all(set(entry)=={"role","public_key","format","signature"} and entry["format"]=="ed25519" for entry in signatures),
                "H signature roles/keys/formats differ from exact host and root")
        identifier=statement_id(statement)
        for entry in signatures:
            if entry["role"]=="host" and not complete:
                require(entry["signature"]=="-", "root preparation supplied target host consent")
            else:
                require(entry["signature"]!="-", "complete H is missing its actual signature")
                self.target.verify_raw(entry["public_key"],lines("peerspan-decentralized-signature-v1",identifier,entry["role"],entry["public_key"]),entry["signature"])
        return statement,payload,identifier

    def response(self, value, *, complete):
        require(set(value)=={"migration","host_lease_base64","review","signing_requests"} and
                set(value["migration"])==VIEW and set(value["review"])==HREVIEW and value["signing_requests"]==[],
                "host-only review changed shape or exposes the owned host as an external signer")
        raw=unb64(value["host_lease_base64"])
        _,payload,identifier=self.parse_h(raw,complete=complete)
        review=value["review"]
        require(review["stage"]=="host_membership" and review["network_id"]==self.spec["network_id"] and
                review["proposal_id"]==self.proposal and review["host_public_key"]==self.spec["host_public_key"] and
                review["member"]==self.spec["member"] and review["root_state_id"]==self.root_id and review["host_lease_id"]==identifier and
                all(review[key]==payload[key] for key in ("issued_at","not_before","not_after")) and
                isinstance(review["authority_warning"],str) and bool(review["authority_warning"]),
                "host membership review does not disclose its exact fixed public terms")
        return raw

    def case(self, name, function):
        began=time.monotonic()
        try:function()
        except BaseException as error:
            self.rows.append({"name":name,"passed":False,"error_type":type(error).__name__,
                "detail":str(error) if isinstance(error,CheckFailure) else "fixture/transport failure"});raise
        self.rows.append({"name":name,"passed":True,"seconds":round(time.monotonic()-began,3)})
        print("PASS "+name,flush=True)

    def fixed_host_intent(self):
        found=[]
        for identifier,encoded,secret in table_rows(self.target.host,"dec_intents","intent_id,record,secret"," WHERE kind='migration'"):
            record=strict_output(encoded.encode())
            if record["provider"]["kind"]!="host" or len(record["templates"])!=1 or record["templates"][0]["object_type"]!="host_lease":continue
            require(secret is None and record["approved"] and record["completed"] and record["terminal"]=="-" and
                    record["operation_id"]==self.proposal and record["root_state_id"]==self.root_id and
                    record["host_public_key"]==self.spec["host_public_key"] and record["person_public_key"]==record["device_public_key"]=="-" and
                    record["scopes"]==0 and record["provider"]=={"kind":"host","signer_public_key":self.spec["host_public_key"],"signature_format":"ed25519","lease_id":"-"} and
                    record["templates"][0]["template_base64"]==b64(self.partial) and
                    len(record["signatures"])==1 and record["signatures"][0]["role"]=="host",
                    "host-only H intent has another selector/template, missing approval/signature or copied private seed")
            found.append((identifier,record))
        require(len(found)==1,"completed H does not have exactly one original approved host-only intent")
        return found[0]

    def load_proposal_window(self):
        proposals=[]
        for record, in table_rows(self.target.host,"dec_intents","record"," WHERE kind='migration'"):
            intent=strict_output(record.encode())
            for template in intent["templates"]:
                if template["object_type"]=="migration_proposal":proposals.append(strict_output(unb64(template["template_base64"])))
        require(len(proposals)==1,"root handoff lacks its one durably approved proposal template")
        payload=strict_output(unb64(proposals[0]["payload_base64"]))
        self.proposal_window=(payload["issued_at"],payload["expires_at"])

    def run(self):
        self.target.host.start();self.target.identity=self.target.host.api("GET","/v1/host")
        require(self.target.identity["public_key"]==self.spec["host_public_key"],"migration opening replaced actual U host key")
        self.authority_before=authority_rows(self.target)
        def partial():
            before=self.call("GET","")
            require(before["proposal_id"]=="-" and not before["approved"] and not before["fenced"], "U already has a different migration proposal")
            body={"roster":self.roster,"signature_format":"ed25519","approve":True}
            value=self.call("POST","/prepare",body)
            # The actual root is owned by this fixture. Resume signs ONLY its
            # approved root roles; target-host consent needs the separate route.
            for _ in range(12):
                Preparation.wrapper(self,value)
                self.proposal=value["migration"]["proposal_id"];self.context=value["review"]["new_context_id"]
                self.root_key=value["review"]["legacy_root_public_key"];self.root_id=value["migration"]["root_state_id"]
                slots=value["signing_requests"]
                for slot in slots:
                    require(set(slot)==SLOT_FIELDS,"ready migration signing request shape differs")
                host_slots=[slot for slot in slots if slot["object_type"]=="host_lease" and slot["role"]=="host"]
                if host_slots:
                    require(len(host_slots)==1 and len(slots)==1 and host_slots[0]["public_key"]==self.spec["host_public_key"] and
                            host_slots[0]["format"]=="ed25519","root handoff offered an unrelated/ambiguous host signature")
                    slot=host_slots[0];self.partial=unb64(slot["template_base64"])
                    # Read only the already approved typed proposal template,
                    # never a key/source extraction or a guessed storage field.
                    self.load_proposal_window()
                    self.parse_h(self.partial,complete=False)
                    require(slot["message_base64"]==b64(lines("peerspan-decentralized-signature-v1",statement_id(strict_output(self.partial)),"host",self.spec["host_public_key"])),
                            "ready host signing request does not bind the exact partial H")
                    (self.args.work_dir/"public-partial-host-lease.json").write_bytes(self.partial)
                    self.no_authority();return
                require(all(slot["role"]=="issuer" and slot["public_key"]==self.root_key and slot["format"]=="ed25519" for slot in slots),
                        "unbound root preparation requested an owner/device/unrelated signer")
                value=self.call("POST","/resume",{})
            raise CheckFailure("root preparation did not expose its pending host template within12 fixed dependency steps")
        if self.args.after_partial_dir:
            original=strict_output((self.args.after_partial_dir/"target/public-responses/002.json").read_bytes())
            current=self.call("GET","")
            require(all(current[k]==original["migration"][k] for k in ("network_id","proposal_id","context_id","root_state_id","source_catalog_sha256","source_state_sha256")),
                    "same-state H continuation changed the already signed proposal/source/root")
            self.proposal=current["proposal_id"];self.context=current["context_id"];self.root_id=current["root_state_id"]
            self.root_key=original["review"]["legacy_root_public_key"]
            self.partial=(self.args.after_partial_dir/"public-partial-host-lease.json").read_bytes()
            self.load_proposal_window();self.parse_h(self.partial,complete=False)
            self.trace.append({"passed_root_handoff_function_skipped":True,"same_partial_sha256":sha(self.partial),
                "same_original_proposal_root_source_and_clock":True})
        else:self.case(CASES[0],partial)
        participation=self.call("GET","")
        if not participation["approved"]:
            for approve in (False,True):
                reviewed=self.call("POST","/review",{"proposal_id":self.proposal,"approve":approve})
                Preparation.wrapper(self,reviewed)
                require(reviewed["review"]["stage"]=="participation" and reviewed["migration"]["approved"] is approve,
                        "required own participation review did not preserve its separate approval")
            self.trace.append({"uncounted_required_own_participation_preview_and_approval":True,
                "root_proposal_approval_was_not_host_participation_consent":True})
        self.no_authority()
        body={"proposal_id":self.proposal,"host_lease_base64":b64(self.partial),"approve":False}
        def preview():
            for encoded, in table_rows(self.target.host,"dec_intents","record"," WHERE kind='migration'"):
                intent=strict_output(encoded.encode())
                host_slots={template["slot_id"] for template in intent["templates"] if template["object_type"]=="host_lease"}
                require(not any(signature["slot_id"] in host_slots and signature["role"]=="host" for signature in intent["signatures"]),
                        "root/participation approval supplied the separate target host signature")
            before=all_database_snapshots(self.target.host.state)
            value=self.call("POST","/host-lease",body)
            require(self.response(value,complete=False)==self.partial and all_database_snapshots(self.target.host.state)==before,
                    "host preview changed template, generated consent/key/intent or advanced the guard")
            self.no_authority()
        self.case(CASES[1],preview)
        def approve():
            value=self.call("POST","/host-lease",{**body,"approve":True})
            for _ in range(12):
                raw=unb64(value["host_lease_base64"])
                parsed=strict_output(raw)
                if parsed["signatures"][0]["signature"]!="-":break
                self.response(value,complete=False)
                self.call("POST","/resume",{})
                value=self.call("POST","/host-lease",body)
            self.complete=self.response(value,complete=True)
            first=strict_output(self.partial);second=strict_output(self.complete)
            require(first["payload_base64"]==second["payload_base64"] and first["signatures"][1]==second["signatures"][1] and
                    statement_id(first)==statement_id(second),"host consent rewrote the root issuer bytes/payload/statement")
            self.fixed_intent=self.fixed_host_intent()
            for restart in (False,True):
                if restart:
                    self.now+=timedelta(seconds=301);self.clock.write_text(stamp(self.now));self.target.host.stop();self.target.host.start()
                value=self.call("POST","/host-lease",{**body,"approve":True})
                require(self.response(value,complete=True)==self.complete and
                        self.fixed_host_intent()==self.fixed_intent,
                        "completed H retry/restart/300s changed the body, intent, approval or signatures")
            self.no_authority()
            self.trace.append({"proposal_id":self.proposal,"root_state_id":self.root_id,"host_lease_id":statement_id(second),
                "partial_sha256":sha(self.partial),"complete_sha256":sha(self.complete),"same_actual_host_only":True,
                "no_person_device_ack_fence_or_adoption":True})
        self.case(CASES[2],approve)
        def conflict():
            # A different envelope spelling is a different exact approved H
            # template; valid existing signatures still bind the same DS.
            alias=json.dumps(strict_output(self.partial),indent=2).encode()+b"\n"
            require(alias!=self.partial,"fixture failed to change exact template bytes")
            before=all_database_snapshots(self.target.host.state)
            value=self.call("POST","/host-lease",{**body,"host_lease_base64":b64(alias),"approve":True},status=409)
            after=all_database_snapshots(self.target.host.state)
            def without_clock(snapshot):
                value=copy.deepcopy(snapshot)
                for database in value["databases"].values():
                    if "dec_clock" in database["tables"]:database["tables"]["dec_clock"]["rows"]=[]
                return value
            require(value["code"]=="operation_conflict" and without_clock(after)==without_clock(before) and self.fixed_host_intent()==self.fixed_intent,
                    "changed approved H template did not refuse without writes/resigning")
            self.trace.append({"conflict_clock_before":{name:db["tables"].get("dec_clock") for name,db in before["databases"].items()},
                "conflict_clock_after":{name:db["tables"].get("dec_clock") for name,db in after["databases"].items()},
                "only_documented_clock_metadata_may_advance":True})
            self.no_authority()
        self.case(CASES[3],conflict)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("host","fixture-dir","work-dir","results"):parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--after-partial-dir",type=Path,help="Reuse the already passed root handoff and exact partial H; only three remaining controls, no root/template/key/clock reset")
    args=parser.parse_args()
    for name in ("host","fixture_dir","work_dir","results"):setattr(args,name,getattr(args,name).resolve())
    args.work_dir.mkdir(mode=0o700,parents=True,exist_ok=False)
    keys=FixtureKeys();suite=HostLease(args,keys);failure=detail=None;began=time.monotonic()
    try:suite.run()
    except BaseException as error:failure=type(error).__name__;detail=str(error) if isinstance(error,CheckFailure) else "fixture/transport failure"
    finally:
        try:suite.target.host.stop()
        except BaseException as error:failure=failure or type(error).__name__;suite.rows.append({"name":"cleanup","passed":False,"error_type":type(error).__name__})
        keys.close()
    receipt={"contract_pin":PIN,"implementation_source_read":False,"suite_sha256":sha(Path(__file__).read_bytes()),
        "artifact":{"path":str(args.host),"sha256":sha(args.host.read_bytes())},"fixture_dir":str(args.fixture_dir),
        "rows":suite.rows,"trace":suite.trace,"failure":failure,"detail":detail,"seconds":round(time.monotonic()-began,3),
        "after_partial_dir":None if args.after_partial_dir is None else str(args.after_partial_dir.resolve()),
        "scope":"PR126 actual unbound H handoff only; no evidence carrier, ACK/fence/root commit/adoption/full migration or native/installed claim",
        "passed":failure is None and len(suite.rows)==(3 if args.after_partial_dir else 4) and all(row["passed"] for row in suite.rows)}
    args.results.parent.mkdir(parents=True,exist_ok=True);args.results.write_text(json.dumps(receipt,indent=2)+"\n")
    return 0 if receipt["passed"] else 1


if __name__=="__main__":raise SystemExit(main())
