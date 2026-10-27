#!/usr/bin/env python3
"""A configured transport key without admitted H cannot use proof repair.

Use an already applied stopped pair and the documented owner-local peer add
CLI. The outsider key is independently fixture-owned and was never enrolled;
manual transport configuration is the only operation that introduces it. The
raw client observes zero application data, not the server's pre-stream phase.
No prior completion/expired-member positive is repeated.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import subprocess
import time

from decentralized_completion_transport import CompletionTransport, PIN
from decentralized_fixtures import FixtureKeys, raw_json, sha, unb64
from decentralized_storage import CheckFailure, require


CASE="manual_transport_pin_without_admitted_host_receives_no_repair_application_data"


class ManualPinRepair(CompletionTransport):
    def run(self):
        public=self.keys.public("completion-outsider")
        host_id="host_"+sha(unb64(public))
        for label,s in self.hosts.items():
            s.host.start();s.identity=s.host.api("GET","/v1/host")
            require(public!=s.identity["public_key"],"fixture outsider is an actual admitted participant")
        for label,s in self.hosts.items():
            # Pin a real, independently owned public key through the existing
            # public CLI. No direct legacy-table write or daemon key copying.
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as reserved:
                reserved.bind(("127.0.0.1",0));address="127.0.0.1:"+str(reserved.getsockname()[1])
            members=s.api("GET","/v2/networks/"+self.network_id(label)+"/members")[0]
            require(all(member["host_public_key"]!=public for member in members["members"]),
                "outsider already has public member authority before manual configuration")
            argv=[str(s.host.binary),"--state",str(s.host.state),"peer","add","--id",host_id,
                "--public-key",public,"--address",address]
            result=subprocess.run(argv,capture_output=True,env=s.host.environment,timeout=10)
            for suffix,raw in (("stdout",result.stdout),("stderr",result.stderr)):
                path=self.args.work_dir/(label+"-manual-peer."+suffix);path.write_bytes(raw);path.chmod(0o600)
            require(result.returncode==0,"documented manual peer configuration did not persist successfully")
            self.trace.append({"uncounted_manual_transport_pin_setup":{"target":label,"host_id":host_id,
                "public_key":public,"configured_address":address,"only_fixture_introduction_of_key":True,
                "no_enrollment_host_grant_or_admission_marker_supplied":True}})
            def deny():
                before=self.snapshot(label)
                value,wire=self.wire(label,None,"GET","/repair/v1/networks/"+self.network_id(label)+"/catalog",
                    alpn="peerspan-state-repair/1")
                require(value is None and wire.returncode!=0 and wire.stdout==b"",
                    "manual-known key without admitted H received a repair application response")
                require(self.snapshot(label)==before,"denied manual-only repair changed authority/guard/provider/intent")
            self.case(label,CASE,deny)
        self.trace.append({"actual_daemon_keys_stayed_in_place":True,"raw_client_observes_only_zero_application_data":True,
            "no_pre_stream_server_phase_or_outbound_server_pin_claim":True})

    def network_id(self,label):
        from decentralized_vectors import strict_output
        record=self.operations[label][2]
        catalog=strict_output(unb64(record["catalog_base64"]))
        # The public operation catalog fixes context; the signed initial request
        # fixes the exact network independently of current membership rendering.
        activation=strict_output(unb64(record["activation_base64"]))
        payload=strict_output(unb64(activation["request"]["payload_base64"]))
        require(catalog["context_id"]==activation["context_id"] and payload["expected_network_id"].startswith("net_"),
            "retained signed request does not fix a concrete network")
        return payload["expected_network_id"]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("owner","requester","probe","retained-dir","work-dir","results"):p.add_argument("--"+name,type=Path,required=True)
    args=p.parse_args()
    for name in ("owner","requester","probe","retained_dir","work_dir","results"):setattr(args,name,getattr(args,name).resolve())
    args.prior_results=[];args.work_dir.mkdir(mode=0o700,parents=True,exist_ok=False)
    keys=FixtureKeys();suite=ManualPinRepair(args,keys);began=time.monotonic();failure=detail=None
    try:suite.run()
    except BaseException as error:failure,detail=type(error).__name__,str(error) if isinstance(error,CheckFailure) else "fixture/transport failure"
    finally:
        for s in reversed(list(suite.hosts.values())):
            try:s.host.stop()
            except BaseException as error:failure=failure or type(error).__name__;suite.rows.append({"name":"cleanup","passed":False,"error_type":type(error).__name__})
        keys.close()
    support=("decentralized_completion_transport.py","decentralized_complete_link.py","decentralized_fixtures.py",
        "decentralized_owner_preview.py","decentralized_runtime.py","decentralized_storage.py","decentralized_vectors.py",
        "decentralized_requester.py","decentralized_helper.py","decentralized_direct_carrier.py")
    result={"contract_pin":PIN,"implementation_source_read":False,"suite_sha256":sha(Path(__file__).read_bytes()),
        "support_sha256":{name:sha(Path(__file__).with_name(name).read_bytes()) for name in support},
        "artifacts":{name:{"path":str(getattr(args,name)),"sha256":sha(getattr(args,name).read_bytes())} for name in ("owner","requester","probe")},
        "rows":suite.rows,"trace":suite.trace,"failure":failure,"detail":detail,"seconds":round(time.monotonic()-began,3),
        "scope":"new manual transport pin without prior admitted H denies exact repair catalog with zero application data; no before-stream, normal-manual-policy, server-pin, relay/NAT/installed claim",
        "passed":failure is None and len(suite.rows)==2 and all(row["passed"] for row in suite.rows)}
    args.results.parent.mkdir(parents=True,exist_ok=True);args.results.write_text(json.dumps(result,indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__=="__main__":raise SystemExit(main())
