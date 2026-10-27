#!/usr/bin/env python3
"""Independent native local create and same-person two-consent direct linking.

Six new CLI controls, public contracts only. Actual daemon keys stay in place;
the original SSH key exists only in A's fixture directory. No coordinator or
helper is configured. These foreground daemons do not establish installed/up,
adapter, task, relay or NAT readiness.
"""
from __future__ import annotations

import argparse
from datetime import datetime,timedelta,timezone
import json
import os
from pathlib import Path
import pty
import signal
import socket
import subprocess
import time
from types import SimpleNamespace

from decentralized_complete_link import table_rows
from decentralized_fixtures import FixtureKeys,b64,raw_json,sha,unb64
from decentralized_owner_preview import authority_rows
from decentralized_requester import VIEW
from decentralized_runtime import CreationSuite,NETWORK_FIELDS
from decentralized_storage import CheckFailure,all_database_snapshots,require
from decentralized_vectors import strict_output


PIN="b491b6a35935f9320a15d90f69ee6aba43cd96ef"
CASES=["native_local_create_has_original_provider_without_device_or_coordinator",
       "native_same_person_request_and_status_preserve_one_pending_identity",
       "native_private_owner_review_and_approval_reach_actual_direct_requester",
       "blank_owner_selection_declines_and_restart_preserves_pending_identity",
       "explicit_selection_native_admin_and_finalization_do_not_supply_final_consent",
       "blank_final_decline_then_explicit_native_commit_selects_owned_device_and_normal_peer"]


class NativeLink:
    def __init__(self,args,keys):
        self.args,self.keys=args,keys;self.rows,self.trace=[],[];self.calls=0
        self.a=CreationSuite(args.host,args.work_dir/"owner",keys)
        self.b=CreationSuite(args.host,args.work_dir/"requester",keys)
        self.hosts={"owner":self.a,"requester":self.b};self.sensitive=[];self.addresses={}
        self.guide=None
        self.key=(args.retained_dir/"owner" if args.retained_dir else self.a.root)/"original-ed25519"
        if not args.retained_dir:
            made=subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","","-f",str(self.key)],capture_output=True,timeout=10)
            require(made.returncode==0,"fixture original key generation failed")
        blob=unb64(self.key.with_suffix(".pub").read_text().split()[1]);pos=0
        def field():
            nonlocal pos
            length=int.from_bytes(blob[pos:pos+4],"big");pos+=4;value=blob[pos:pos+length];pos+=length;return value
        require(field()==b"ssh-ed25519","fixture public key is not Ed25519")
        public=field();require(len(public)==32 and pos==len(blob),"fixture SSH public key framing differs")
        self.person=b64(public)
        for label,s in self.hosts.items():
            if args.retained_dir:
                s.host.state=args.retained_dir/label/"state"
                require(not (s.host.state/"admin.sock").exists(),"native continuation actual fixture is not stopped")
            s.host.environment["PATH"]="/usr/bin:/bin"
            with socket.socket() as reserved:
                reserved.bind(("127.0.0.1",0));tcp="127.0.0.1:"+str(reserved.getsockname()[1])
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as reserved:
                reserved.bind(("127.0.0.1",0));udp="127.0.0.1:"+str(reserved.getsockname()[1])
            if args.retained_dir:
                selected_id=getattr(args,"retained_request_id",None)
                rows=table_rows(SimpleNamespace(state=args.retained_dir/"requester"/"state"),"dec_pending","record",
                    " WHERE request_id=?" if selected_id else "",(selected_id,) if selected_id else ())
                require(len(rows)==1,"native continuation lacks the original one pending request")
                pending=strict_output(rows[0][0].encode())
                public=pending["host_public_key"] if label=="requester" else (strict_output(unb64(pending["owner_packet_base64"]))["writer_host_public_key"]
                    if pending["owner_packet_base64"]!="-" else None)
                public=getattr(args,"retained_participant_keys",{}).get(label,public)
                endpoints=[v for v in pending["carrier_endpoints"] if v["kind"]=="participant" and v["public_key"]==public]
                if public is not None:
                    require(len(endpoints)==1,"native continuation lost the original pinned participant listener")
                    tcp=endpoints[0]["address"]
            self.addresses[label]=udp
            s.host.run_arguments=["--bootstrap-listen",tcp,"--peer-listen",udp,"--advertise",udp]
            if label=="owner":s.host.run_arguments += ["--person-key-file",str(self.key)]

    def cli(self,s,*args,input=b"",tty=False,success=None):
        binary=self.args.history_cli if self.args.history_cli and s is self.a else self.args.host
        argv=[str(binary),"--state",str(s.host.state),*args]
        master=slave=None
        if tty:master,slave=pty.openpty()
        process=subprocess.Popen(argv,stdin=slave if tty else subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            env=s.host.environment,start_new_session=True)
        if slave is not None:os.close(slave)
        timed_out=False
        # Native resume may include the runtime contract's one bounded 30s
        # publication attempt; the CLI reader bound must exceed it.
        try:
            if tty:
                os.write(master,input);stdout,stderr=process.communicate(timeout=40)
            else:stdout,stderr=process.communicate(input=input,timeout=40)
        except subprocess.TimeoutExpired:
            if process.poll() is None:os.killpg(process.pid,signal.SIGKILL)
            stdout,stderr=process.communicate(timeout=5);timed_out=True
        except BaseException:
            if process.poll() is None:os.killpg(process.pid,signal.SIGKILL)
            process.wait(timeout=5);raise
        finally:
            if master is not None:os.close(master)
        self.calls+=1;p=self.args.work_dir/f"cli-{self.calls:03}"
        for suffix,data in (("stdout",stdout),("stderr",stderr)):
            path=p.with_suffix("."+suffix);path.write_bytes(data);path.chmod(0o600)
        p.with_suffix(".meta.json").write_bytes(raw_json({"arguments":list(args),"exit":process.returncode,
            "stdin_sha256":sha(input),"stdout_sha256":sha(stdout),"stderr_sha256":sha(stderr),"tty_stdin":tty,"timed_out":timed_out}))
        if timed_out:raise subprocess.TimeoutExpired(argv,40,output=stdout,stderr=stderr)
        if success is not None:require((process.returncode==0) is success,"native command returned unexpected success/incomplete outcome; see CLI receipt")
        require(stdout.strip(),"native command omitted JSON stdout")
        value=strict_output(stdout)
        return value,stderr,process.returncode

    def start_guide(self):
        """Keep B's terminal open while the owner operates a separate terminal."""
        require(self.guide is None,"another native requester guide is already active")
        self.calls+=1;p=self.args.work_dir/f"guide-{self.calls:03}"
        master,slave=pty.openpty();out=p.with_suffix(".stdout");err=p.with_suffix(".stderr")
        stdout=out.open("wb");stderr=err.open("wb");out.chmod(0o600);err.chmod(0o600)
        process=subprocess.Popen([str(self.args.host),"--state",str(self.b.host.state),"link","resume",self.request["request_id"]],
            stdin=slave,stdout=stdout,stderr=stderr,env=self.b.host.environment,start_new_session=True)
        os.close(slave);self.guide=(process,master,stdout,stderr,out,err)

    def guide_prompt(self,text):
        require(self.guide is not None,"native guide is not running")
        process,_,_,_,_,err=self.guide;deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            if text in err.read_bytes():return
            require(process.poll() is None,"native guide exited before the expected separate consent prompt; see protected guide output")
            time.sleep(.02)
        raise CheckFailure("native guide did not reach its expected separate consent prompt within10s")

    def guide_send(self,data):
        os.write(self.guide[1],data)

    def finish_guide(self):
        process,master,stdout,stderr,out,err=self.guide
        process.wait(timeout=30);stdout.close();stderr.close();os.close(master);self.guide=None
        require(process.returncode!=0,"blank final decline reported completed native linking")
        value=strict_output(out.read_bytes());self.view(value,code="display_code" in value)
        return value

    def stop_guide(self):
        if self.guide is None:return
        process,master,stdout,stderr,_,_=self.guide
        if process.poll() is None:os.killpg(process.pid,signal.SIGKILL)
        process.wait(timeout=5);stdout.close();stderr.close();os.close(master);self.guide=None

    def view(self,value,code=False):
        require(type(value) is dict and set(value)==VIEW|({"display_code"} if code else set()),"native CLI leaked wrapper or changed flat LINK_VIEW")
        if hasattr(self,"request"):
            require(all(value[k]==self.request[k] for k in ("request_id","host_public_key","device_public_key","network_id","person_public_key")),
                "native continuation replaced request/person/host/device pins")
        return value

    def pending(self):
        rows=table_rows(self.b.host,"dec_pending","request_id,record,secret")
        require(len(rows)==1,"native retry created or lost a pending request")
        return rows[0][0],strict_output(rows[0][1].encode()),rows[0][2]

    def consent_snapshot(self):
        identifier,pending,secret=self.pending()
        return {"request_id":identifier,"packet_ids":{k:pending[k] for k in ("owner_offer_id","selection_id","administrator_offer_id","owner_finalization_id","manifest_id","activation_id")},
            "selection_approved":pending["selection_approved"],"commit_approved":pending["commit_approved"],
            "secret_sha256":None if secret is None else sha(secret),"host":pending["host_public_key"],"device":pending["device_public_key"]}

    def resume(self,input=b"\n",success=False):
        value,prompt,_=self.cli(self.b,"link","resume",self.request["request_id"],input=input,tty=True,success=success)
        self.view(value,code="display_code" in value)
        return value,prompt

    def no_adoption(self):
        require(self.b.api("GET","/v2/networks")[0]==[] and not table_rows(self.b.host,"dec_signers","network_id") and
            not table_rows(self.b.host,"dec_operations","request_id"),"pending native link supplied provider/network/outcome")

    def owner_arguments(self):
        return ["link","approve","--network",self.network["id"],"--person",self.person,
            "--expect-host-key",self.request["host_public_key"],"--expect-device-key",self.request["device_public_key"],
            "--person-key",str(self.key),"--scopes","7","--not-after",(datetime.now(timezone.utc)+timedelta(hours=1)).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),"--code-stdin"]

    def minimum_fresh_request(self):
        """Necessary NEW input after an immutable old request window elapsed."""
        self.cli(self.a,"network","create","Independent native remaining","--as","Native Alice","--person-key-file",str(self.key),success=True)
        values=self.a.api("GET","/v2/networks")[0];require(len(values)==1,"fresh native prerequisite lacks one context")
        self.network=values[0]
        self.request,_,_=self.cli(self.b,"link","--network",self.network["id"],"--expect-person",self.person,success=False)
        self.view(self.request,code=True);self.code=self.request["display_code"];self.sensitive.append(self.code.encode())
        require(not self.pending()[1]["selection_approved"] and not self.pending()[1]["commit_approved"],"fresh native prerequisite supplied requester consent")

    def minimum_fresh_prefix(self):
        """Necessary NEW fixture input, never call any four passed test functions."""
        self.minimum_fresh_request()
        self.cli(self.a,*self.owner_arguments(),"--approve",input=(self.code+"\n").encode(),success=False)
        time.sleep(2.05)  # Let any successful initial empty read's real2s cache expire.
        self.trace.append({"uncounted_minimum_new_native_setup":["native create","native same-person request","native explicit owner approval"],
            "passed_test_function_count_skipped":3 if self.args.fresh_after_owner_from else 4,
            "original_expired_fixture_not_rewritten":str(self.args.fresh_after_owner_from or self.args.fresh_remaining_from)})

    def old_fixture_hashes(self):
        old=self.args.fresh_remaining_from or self.args.fresh_after_pending_from or self.args.fresh_after_owner_from
        return {"databases":{label:all_database_snapshots(old/label/"state") for label in ("owner","requester")},
            "files":{str(p.relative_to(old)):sha(p.read_bytes()) for label in ("owner","requester")
                for base in (old/label/"state",old/label/"home") for p in sorted(base.rglob("*")) if p.is_file() and not p.is_symlink()},
            "fixture_original_key_sha256":sha((old/"owner"/"original-ed25519").read_bytes())}

    def run(self):
        if self.args.fresh_remaining_from or self.args.fresh_after_pending_from or self.args.fresh_after_owner_from:self.old_before=self.old_fixture_hashes()
        for s in self.hosts.values():s.host.start();s.identity=s.host.api("GET","/v1/host")
        def create():
            self.cli(self.a,"network","create","Independent native direct","--as","Native Alice","--person-key-file",str(self.key),success=True)
            networks=self.a.api("GET","/v2/networks")[0]
            require(len(networks)==1 and set(networks[0])==NETWORK_FIELDS,"native create did not establish one new-mode view")
            self.network=networks[0];provider=self.a.api("GET","/v2/networks/"+self.network["id"]+"/provider")[0]
            require(self.network["mode"]=="decentralized" and self.network["person_public_key"]==self.person and
                self.network["authority"]["state"]=="usable" and provider["kind"]=="original_person" and
                provider["device_public_key"]=="-" and provider["person_public_key"]==self.person,"native creator did not keep original provider")
            catalog=self.a.api("GET","/v2/networks/"+self.network["id"]+"/catalog")[0]["catalog"]
            require(not any(v["kind"] in {"device_lease","activation"} for v in catalog["objects"]),"native creation invented creator device consent")
        if self.args.fresh_remaining_from or self.args.fresh_after_owner_from:self.minimum_fresh_prefix()
        elif self.args.fresh_after_pending_from:
            self.minimum_fresh_request()
            self.trace.append({"uncounted_minimum_new_native_setup":["native create","native same-person request"],
                "two_passed_test_functions_not_executed":True,"original_expired_fixture_not_rewritten":str(self.args.fresh_after_pending_from)})
        elif self.args.retained_dir:
            original=strict_output((self.args.retained_dir/"cli-001.stdout").read_bytes())
            self.network=self.a.api("GET","/v2/networks/"+original["id"])[0]
            require(self.network["id"]==original["id"] and self.network["context_id"]==original["context_id"] and
                self.network["host_public_key"]==self.a.identity["public_key"],"native continuation replaced the already-created context")
            self.trace.append({"passed_native_create_skipped":True,"original_pending_state_reused":str(self.args.retained_dir),
                "no_new_request_key_code_or_deadline":True})
        else:self.a.case(CASES[0],create)
        if self.args.after_owner or self.args.after_selection or self.args.after_applied:
            self.request=strict_output((self.args.retained_dir/"cli-002.stdout").read_bytes())
            self.code=self.request["display_code"];self.sensitive.append(self.code.encode())
            pending=self.pending()[1]
            if self.args.after_owner:
                require(pending["owner_offer_id"].startswith("dpk_") and pending["owner_packet_base64"]!="-" and
                    not pending["selection_approved"] and not pending["commit_approved"],"three-only continuation lost exact owner evidence or gained consent")
                self.trace.append({"three_passed_test_functions_skipped":True,"exact_durable_owner_packet_sha256":sha(unb64(pending["owner_packet_base64"])),
                    "no_request_owner_signature_or_consent_repeated":True})
            else:require(pending["selection_approved"] is True and pending["commit_approved"] is self.args.after_applied,
                    "two-only continuation lacks the already fixed selection consent")
        def request():
            if self.args.retained_dir:value=strict_output((self.args.retained_dir/"cli-002.stdout").read_bytes())
            else:value,_,_=self.cli(self.b,"link","--network",self.network["id"],"--expect-person",self.person,success=False)
            self.view(value,code=True);require(value["mode"]=="new" and value["person_public_key"]==self.person and
                value["host_public_key"]==self.b.identity["public_key"] and value["completed"]==["request_created"],"native link changed same-person target")
            self.request=value;self.code=value["display_code"];self.sensitive.append(self.code.encode())
            identifier,pending,secret=self.pending();require(identifier==value["request_id"] and type(secret) is bytes and len(secret)==16,
                "native link did not retain exact private request secret")
            require(pending["host_public_key"]==value["host_public_key"] and pending["device_public_key"]==value["device_public_key"] and
                not pending["selection_approved"] and not pending["commit_approved"],"retained native pending tuple/consent differs from its request")
            before=self.consent_snapshot()
            if self.args.retained_dir:
                status=strict_output((self.args.retained_dir/"cli-003.stdout").read_bytes())
                status_meta=strict_output((self.args.retained_dir/"cli-003.meta.json").read_bytes())
                require(status_meta["exit"]!=0 and not status_meta["timed_out"],"retained pending native status did not report incomplete/nonzero")
                self.trace.append({"original_pending_status_validated_without_repeating_request":True,
                    "original_status_stdout_sha256":sha((self.args.retained_dir/"cli-003.stdout").read_bytes()),
                    "discarded_oracle":"requiring exit0 for pending status despite runtime section6 incomplete/nonzero"})
            else:status,_,_=self.cli(self.b,"link","status",identifier,success=False)
            self.view(status)
            require(self.consent_snapshot()==before,"native status replaced pending identity or consent")
            self.no_adoption()
        if not (self.args.after_owner or self.args.after_selection or self.args.after_applied or self.args.fresh_remaining_from or self.args.fresh_after_pending_from or self.args.fresh_after_owner_from):self.a.case(CASES[1],request)
        def owner():
            self.owner_args=self.owner_arguments()
            before=authority_rows(self.b)
            preview,_,_=self.cli(self.a,*self.owner_args,input=(self.code+"\n").encode(),success=False)
            self.view(preview);require(not table_rows(self.a.host,"dec_pending","request_id" ) or
                all(strict_output(r[0].encode())["owner_packet_base64"]=="-" for r in table_rows(self.a.host,"dec_pending","record")),
                "native default-no owner preview signed a packet")
            approved,_,_=self.cli(self.a,*self.owner_args,"--approve",input=(self.code+"\n").encode(),success=False)
            self.view(approved);time.sleep(2.05)
            require(authority_rows(self.b)==before,"owner approval admitted requester authority")
        if not (self.args.after_owner or self.args.after_selection or self.args.after_applied or self.args.fresh_remaining_from or self.args.fresh_after_owner_from):self.a.case(CASES[2],owner)
        def decline():
            before=self.consent_snapshot();value,prompt=self.resume()
            require(b"Select this exact owner offer?" in prompt and not value["selection_approved"] and not value["commit_approved"],
                "native blank selection did not preserve separate default-no consent")
            after=self.consent_snapshot();require(after["request_id"]==before["request_id"] and after["host"]==before["host"] and
                after["device"]==before["device"] and after["secret_sha256"]==before["secret_sha256"],"selection decline replaced pending key/secret")
            self.b.host.stop();self.b.host.start()
            value,_=self.resume();require(not value["selection_approved"] and self.consent_snapshot()==after,"restart/blank retry changed pending selection")
            self.no_adoption()
        if not (self.args.after_selection or self.args.after_applied or self.args.fresh_remaining_from):self.a.case(CASES[3],decline)
        def prefix():
            selected=self.pending()[1]["selection_approved"]
            self.start_guide()
            if not selected:
                self.guide_prompt(b"Select this exact owner offer?");self.guide_send(b"yes\n")
                deadline=time.monotonic()+10
                while (not self.pending()[1]["selection_approved"] or self.pending()[1]["selection_packet_base64"]=="-") and time.monotonic()<deadline:time.sleep(.02)
            value=self.pending()[1]
            require(value["selection_approved"] and value["selection_packet_base64"]!="-" and not value["commit_approved"],"explicit selection supplied final consent or lacks its completed packet")
            time.sleep(2.05)  # Existing real-time successful-poll reuse, never DEC clock or TTL extension.
            value={**value,"host_public_key":self.request["host_public_key"],"device_public_key":self.request["device_public_key"]}
            self.no_adoption();self.selected=value
            if self.args.after_local_finalization:
                rows=table_rows(self.a.host,"dec_pending","request_id,record")
                require(len(rows)==1 and rows[0][0]==self.request["request_id"],"retained local F belongs to another request")
                fixed_finalization=strict_output(rows[0][1].encode())
                require(fixed_finalization["owner_finalization_id"].startswith("dpk_") and
                    fixed_finalization["owner_finalization_packet_base64"]!="-","same-state continuation lacks its already durable complete F")
                fixed_intents=[(i,strict_output(r.encode()),secret) for i,r,secret in table_rows(self.a.host,"dec_intents","intent_id,record,secret")]
                value=self.a.api("GET","/v2/link/requests/"+self.request["request_id"])[0];self.view(value)
                self.trace.append({"retained_selection_and_administrator_not_repeated":True,
                    "existing_local_finalization_id":fixed_finalization["owner_finalization_id"],
                    "existing_local_finalization_packet_sha256":sha(unb64(fixed_finalization["owner_finalization_packet_base64"]))})
            else:
                admit=["link","admit","--network",self.network["id"],"--person",self.person,"--person-key",str(self.key),
                    "--expect-host-key",value["host_public_key"],"--expect-device-key",value["device_public_key"],
                    "--owner-offer",value["owner_offer_id"],"--selection",value["selection_id"],"--code-stdin","--approve"]
                self.cli(self.a,*admit,input=(self.code+"\n").encode(),success=False);time.sleep(2.05)
                value,_,_=self.cli(self.a,"link","status",self.request["request_id"],success=False);self.view(value)
            require(value["administrator_offer_id"].startswith("dpk_") and not self.pending()[1]["commit_approved"],"native administrator evidence did not remain pending")
            final=["link","finalize",self.request["request_id"],"--network",self.network["id"],"--context",self.network["context_id"],
                "--expect-person",self.person,"--expect-host-key",value["host_public_key"],"--expect-device-key",value["device_public_key"],
                "--owner-offer",value["owner_offer_id"],"--selection",value["selection_id"],"--administrator-offer",value["administrator_offer_id"],
                "--person-key",str(self.key),"--approve"]
            self.cli(self.a,*final,success=False);time.sleep(2.05)
            if self.args.after_local_finalization:
                current=strict_output(table_rows(self.a.host,"dec_pending","record")[0][0].encode())
                require(all(current[k]==fixed_finalization[k] for k in ("owner_finalization_id","owner_finalization_packet_base64")) and
                    [(i,strict_output(r.encode()),secret) for i,r,secret in table_rows(self.a.host,"dec_intents","intent_id,record,secret")]==fixed_intents,
                    "native failed-F recovery replaced its approved intent, templates, signatures or exact packet")
            self.guide_prompt(b"Commit this exact machine link?")
            require(self.pending()[1]["owner_finalization_id"].startswith("dpk_") and not self.pending()[1]["commit_approved"],
                "native finalization or waiting guide supplied requester final consent")
            self.no_adoption()
        if not self.args.after_applied:self.a.case(CASES[4],prefix)
        def final():
            if self.args.after_applied:
                declined=strict_output((self.args.retained_dir/"guide-004.stdout").read_bytes())
                require(declined["selection_approved"] and not declined["commit_approved"] and declined["activation_id"]=="-",
                    "retained actual blank-final-decline receipt changed")
                value=strict_output((self.args.retained_dir/"cli-008.stdout").read_bytes());self.view(value)
                before=self.consent_snapshot()
                require(before["secret_sha256"] is None and before["commit_approved"],"retained native final consent was not actually applied")
                authority_before={label:authority_rows(s) for label,s in self.hosts.items()}
                operation_before={label:table_rows(s.host,"dec_operations","request_id,record,activation_id,manifest_id,locally_applied") for label,s in self.hosts.items()}
                self.trace.append({"five_passed_test_functions_skipped":True,"blank_decline_and_final_yes_not_repeated":True,
                    "retained_prior_final_cli_output_sha256":sha((self.args.retained_dir/"cli-008.stdout").read_bytes())})
            else:
                self.guide_send(b"\n");value=self.finish_guide();require(value["owner_finalization_id"].startswith("dpk_") and
                    value["selection_approved"] and not value["commit_approved"],"native final default-no was skipped")
                self.no_adoption();before=self.consent_snapshot()
                value,_=self.resume(b"yes\n",success=True)
            require(value["state"]=="linked" and value["commit_approved"] and value["selection_approved"],"native explicit commit did not link")
            _,pending,secret=self.pending();require(secret is None and pending["terminal"]=="applied" and
                pending["device_public_key"]==before["device"],"native apply did not retire secret or preserved device")
            provider=self.b.api("GET","/v2/networks/"+self.network["id"]+"/provider")[0]
            require(provider["kind"]=="device" and provider["device_public_key"]==self.request["device_public_key"] and provider["scopes"]==7,
                "native apply selected another signer or scope")
            # B's completed local result is not a global commit receipt. Let
            # the actual other participant explicitly recover/apply before
            # requiring its current normal-peer membership gate to admit B.
            for _ in range(4):
                remote,_,_=self.cli(self.a,"link","resume",self.request["request_id"])
                self.view(remote)
                if remote["state"]=="linked":break
                time.sleep(2.05)
            require(remote["state"]=="linked","native other-participant resume did not actually apply the complete operation")
            if self.args.after_applied:
                require({label:authority_rows(s) for label,s in self.hosts.items()}==authority_before and
                    {label:table_rows(s.host,"dec_operations","request_id,record,activation_id,manifest_id,locally_applied") for label,s in self.hosts.items()}==operation_before,
                    "native historical resume changed applied authority/selection/outcomes")
            argv=[str(self.args.probe),"--state",str(self.b.host.state),"--address",self.addresses["owner"],"--alpn","peerspan-peer/1",
                "--method","GET","--path","/peer/v2/networks/"+self.network["id"]+"/catalog"]
            result=subprocess.run(argv,capture_output=True,env=self.b.host.environment,timeout=40)
            require(result.returncode==0 and strict_output(result.stdout)["status"]==200,"new native admission did not permit ordinary direct catalog transport")
            require(not (Path(self.b.host.environment["XDG_CONFIG_HOME"])/"peerspan/person_ed25519").exists(),"same-person native link generated an original private key")
            self.trace.append({"request_id":self.request["request_id"],"activation_id":value["activation_id"],"manifest_id":value["manifest_id"],
                "actual_direct_normal_catalog_observed":True,"raw_probe_does_not_establish_client_server_pin":True,
                "no_coordinator_or_helper_started":True,"original_key_stayed_only_on_owner":True})
        self.a.case(CASES[5],final)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("host","probe","work-dir","results"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--retained-dir",type=Path,help="Validate already performed request/status and continue same pending fixture; skip passed creation")
    p.add_argument("--after-owner",action="store_true",help="Continue only failed blank-selection and two unevaluated controls from exact durably retained owner evidence; three passed controls skipped")
    p.add_argument("--after-selection",action="store_true",help="Continue only failed native admin/F and final controls after durable selection; four passed controls skipped")
    p.add_argument("--after-local-finalization",action="store_true",help="With --after-selection, skip retained administrator work and resume the already durable exact local F before its requester observation")
    p.add_argument("--fresh-remaining-from",type=Path,help="NEW minimum prerequisites for still-failed admin/F and unevaluated final case; preserve old expired fixture read-only")
    p.add_argument("--fresh-after-pending-from",type=Path,help="NEW minimum create/request prerequisites for four remaining controls after original pending request expiry; two passed functions skipped")
    p.add_argument("--fresh-after-owner-from",type=Path,help="NEW minimum create/request/owner prerequisites for three remaining controls after exact owner-bearing request expiry; three passed functions skipped")
    p.add_argument("--after-applied",action="store_true",help="Only failed A native history plus unexecuted direct peer observation; no final consent repeat")
    p.add_argument("--history-cli",type=Path,help="Correction-only A CLI; original daemon and B binaries stay unchanged")
    args=p.parse_args()
    if args.after_owner and (args.retained_dir is None or args.after_selection or args.after_applied):p.error("owner three-only continuation requires its own retained fixture")
    if args.after_selection and args.retained_dir is None:p.error("--after-selection requires --retained-dir")
    if args.after_local_finalization and not args.after_selection:p.error("local F continuation requires --after-selection")
    if args.after_applied and args.retained_dir is None:p.error("--after-applied requires --retained-dir")
    if args.after_applied and args.after_selection:p.error("applied and selection continuations differ")
    if args.history_cli and not args.after_applied:p.error("--history-cli is scoped to --after-applied")
    if args.fresh_remaining_from and args.retained_dir:p.error("fresh and retained continuations are distinct")
    if args.fresh_after_pending_from and (args.retained_dir or args.fresh_remaining_from or args.after_owner or args.after_selection or args.after_applied):p.error("fresh four-only continuation is distinct")
    if args.fresh_after_owner_from and (args.retained_dir or args.fresh_remaining_from or args.fresh_after_pending_from or args.after_owner or args.after_selection or args.after_applied):p.error("fresh three-only continuation is distinct")
    for name in ("host","probe","work_dir","results"):setattr(args,name,getattr(args,name).resolve())
    args.work_dir.mkdir(mode=0o700,parents=True,exist_ok=False)
    for label in ("owner","requester"):(args.work_dir/label).mkdir(mode=0o700)
    keys=FixtureKeys();suite=NativeLink(args,keys);failure=detail=None;began=time.monotonic()
    try:
        suite.run()
    except BaseException as e:failure,detail=type(e).__name__,str(e) if isinstance(e,CheckFailure) else "fixture/transport failure"
    finally:
        suite.stop_guide()
        for s in (suite.b,suite.a):
            try:
                s.host.stop();logs=s.host.log_path.read_bytes() if s.host.log_path.exists() else b""
                require(not any(secret in logs for secret in suite.sensitive),"daemon log exposed the private native pairing code")
            except BaseException as e:failure=failure or type(e).__name__;suite.a.rows.append({"name":"cleanup","passed":False,"error_type":type(e).__name__})
        if args.fresh_remaining_from or args.fresh_after_pending_from or args.fresh_after_owner_from:
            try:
                require(suite.old_fixture_hashes()==suite.old_before,"fresh minimum setup changed the original expired state/key files")
                (args.work_dir/"old-fixture-preservation-hashes.json").write_bytes(raw_json(suite.old_before))
            except BaseException as e:failure=failure or type(e).__name__;suite.a.rows.append({"name":"original_fixture_preservation","passed":False,"error_type":type(e).__name__})
        keys.close()
    support=("decentralized_complete_link.py","decentralized_fixtures.py","decentralized_owner_preview.py",
        "decentralized_requester.py","decentralized_runtime.py","decentralized_storage.py","decentralized_vectors.py")
    result={"contract_pin":PIN,"implementation_source_read":False,"suite_sha256":sha(Path(__file__).read_bytes()),
        "support_sha256":{name:sha(Path(__file__).with_name(name).read_bytes()) for name in support},
        "artifacts":{name:{"path":str(getattr(args,name).resolve()),"sha256":sha(getattr(args,name).read_bytes())} for name in ("host","probe","history_cli") if getattr(args,name) is not None},
        "planned_cases":CASES,"rows":suite.a.rows,"trace":suite.trace,"failure":failure,"detail":detail,"seconds":round(time.monotonic()-began,3),
        "retained_dir":None if args.retained_dir is None else str(args.retained_dir.resolve()),
        "scope":"foreground native create/link/two-consent/direct-peer controls on the attributed host artifact; same-state continuation skips passed creation and no request repetition; no API7 repeat, service/up/installed, adapter, task, relay or NAT claim",
        "fresh_remaining_from":None if args.fresh_remaining_from is None else str(args.fresh_remaining_from.resolve()),
        "fresh_after_pending_from":None if args.fresh_after_pending_from is None else str(args.fresh_after_pending_from.resolve()),
        "fresh_after_owner_from":None if args.fresh_after_owner_from is None else str(args.fresh_after_owner_from.resolve()),
        "after_owner":args.after_owner,
        "after_local_finalization":args.after_local_finalization,
        "passed":failure is None and len(suite.a.rows)==(1 if args.after_applied else 2 if args.after_selection or args.fresh_remaining_from else 3 if args.after_owner or args.fresh_after_owner_from else 4 if args.fresh_after_pending_from else 5 if args.retained_dir else 6) and all(row["passed"] for row in suite.a.rows)}
    args.results.parent.mkdir(parents=True,exist_ok=True);args.results.write_text(json.dumps(result,indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__=="__main__":raise SystemExit(main())
