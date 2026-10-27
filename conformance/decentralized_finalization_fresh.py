#!/usr/bin/env python3
"""Fresh F+five controls after an immutable old carrier window elapsed.

The original stopped pair is observed only for generic preservation hashes.
Fresh minimal local creation/owner/selection/administrator setup is uncounted.
The already-passed administrator TEST FUNCTION is never executed. The exact
existing F and five dependent CompleteLink test functions remain unchanged.
No old clock, TTL, key, request or partial-publication route is rewritten.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import time

from decentralized_complete_link import CompleteLink
from decentralized_fixtures import FixtureKeys,raw_json,sha
from decentralized_requester import VIEW
from decentralized_storage import CheckFailure,all_database_snapshots,require


ADMIN="complete_link/explicit_admin_grant_remains_pending_without_final_consent"


class FreshFinalization(CompleteLink):
    def __init__(self,owner,requester,root,keys,original):
        super().__init__(owner,requester,root,keys)
        self.original=original
        self.original_clock=(original/"requester"/"clock").read_bytes()
        self.original_hashes=self.retained_hashes()
        counted=self.owner.case
        def remaining(name,function):
            if name==ADMIN:
                self.minimal_administrator_setup()
                return
            return counted(name,function)
        self.owner.case=remaining

    def retained_hashes(self):
        return {label:all_database_snapshots(self.original/label/"state") for label in ("owner","requester")}

    def minimal_administrator_setup(self):
        a,b=self.owner,self.requester
        state=self.pending()
        terms={key:self.terms[key] for key in ("code","network_id","person_public_key","provider_id","signature_format",
            "expected_host_public_key","expected_device_public_key")}
        terms.update(owner_offer_id=state["owner_offer_id"],selection_id=state["selection_id"],approve=True)
        ready=a.api("POST","/v2/link/admissions",terms)[0]
        self.wrapper(ready,"administrator")
        self.finish(ready,"administrator","administrator_packet_base64")
        time.sleep(2.05)
        view=b.api("POST",self.request_route+"/resume",{})[0]
        require(set(view)==VIEW|{"display_code"} and view["administrator_offer_id"].startswith("dpk_") and
            view["selection_approved"] is True and view["commit_approved"] is False and
            view["activation_id"]==view["outcome_id"]=="-" and b.api("GET","/v2/networks")[0]==[],
            "fresh prerequisite did not reach the same pending administrator boundary")
        self.trace.append({"uncounted_minimal_administrator_precondition":{"request_id":self.request["request_id"],
            "administrator_offer_id":view["administrator_offer_id"],"original_administrator_test_function_skipped":True,
            "fresh_prerequisites_do_not_claim_old_pair_identity_preservation":True}})


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ("owner","requester","original-retained-dir","work-dir","results"):p.add_argument("--"+n,type=Path,required=True)
    args=p.parse_args()
    for n in ("owner","requester","original_retained_dir","work_dir","results"):setattr(args,n,getattr(args,n).resolve())
    args.work_dir.mkdir(mode=0o700,parents=True,exist_ok=False)
    keys=FixtureKeys();suite=FreshFinalization(args.owner,args.requester,args.work_dir,keys,args.original_retained_dir)
    failure=detail=None;began=time.monotonic()
    try:
        suite.run()
        require(suite.retained_hashes()==suite.original_hashes and
            (suite.original/"requester"/"clock").read_bytes()==suite.original_clock,
            "fresh fixture touched the original pair or clock")
        (args.work_dir/"original-pair-preservation-hashes.json").write_bytes(raw_json(suite.original_hashes))
    except BaseException as e:failure,detail=type(e).__name__,str(e) if isinstance(e,CheckFailure) else "fixture/transport failure"
    finally:
        for s in (suite.requester,suite.owner):
            try:
                s.host.stop()
                logs=s.host.log_path.read_bytes() if s.host.log_path.exists() else b""
                require(not any(v and v in logs for v in suite.requester.sensitive),"host log exposed private pairing code/secret")
            except BaseException as e:failure=failure or type(e).__name__;suite.rows.append({"name":"cleanup","passed":False,"error_type":type(e).__name__})
        keys.close()
    support=("decentralized_complete_link.py","decentralized_owner_preview.py","decentralized_direct_carrier.py","decentralized_fixtures.py",
        "decentralized_helper.py","decentralized_storage.py","decentralized_requester.py","decentralized_runtime.py","decentralized_vectors.py")
    result={"contract_pin":"7c5a483aa01d87a5d3715bc8fef902f4839ba214","implementation_source_read":False,
        "suite_sha256":sha(Path(__file__).read_bytes()),"support_sha256":{n:sha(Path(__file__).with_name(n).read_bytes()) for n in support},
        "artifacts":{n:{"path":str(getattr(args,n)),"sha256":sha(getattr(args,n).read_bytes())} for n in ("owner","requester")},
        "original_retained_dir":str(args.original_retained_dir),"rows":suite.rows,"trace":suite.trace,"failure":failure,"detail":detail,
        "seconds":round(time.monotonic()-began,3),"scope":"still-failed F plus five unevaluated functional controls on NEW minimal fixture after original carrier expiry; prior administrator test skipped, original pair/clock preserved; no TTL/crash/relay/installed claim",
        "passed":failure is None and len(suite.rows)==6 and all(r["passed"] for r in suite.rows)}
    args.results.parent.mkdir(parents=True,exist_ok=True);args.results.write_text(json.dumps(result,indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__=="__main__":raise SystemExit(main())
