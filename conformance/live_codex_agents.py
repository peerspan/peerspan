#!/usr/bin/env python3
"""Opt-in model check: attach two already-running native Codex conversations.

The caller selects dedicated test threads in a local existing Codex backend.
This runner never starts/stops Codex or changes the threads' permissions.
"""
import argparse
from datetime import datetime,timezone
import json
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import uuid
from codex_integration import Harness,setup,ROOT
from peer_messaging import PeerHost
from claude_setup import wait

class Control:
    def __init__(self,args,thread_id):self.args=args;self.thread_id=thread_id;self.socket=args.socket
    def request(self,method,params):
        data={'socket':str(self.socket),'requests':[{'method':method,'params':params}]}
        result=subprocess.run([str(self.args.node),str(ROOT/'conformance/fixtures/codex/control.mjs')],input=json.dumps(data),capture_output=True,text=True,check=True,timeout=20)
        return json.loads(result.stdout)[0]
    def state(self):return self.request('thread/read',{'threadId':self.thread_id,'includeTurns':False})['thread']
    def submit(self,text):
        queued=self.request('thread/queue/add',{'threadId':self.thread_id,'clientUserMessageId':str(uuid.uuid4()),'input':[{'type':'text','text':text}]})['queuedSubmission']['id']
        try:self.request('thread/queue/start',{'threadId':self.thread_id,'queuedSubmissionId':queued})
        except subprocess.CalledProcessError:
            page=self.request('thread/queue/list',{'threadId':self.thread_id,'limit':100})
            if any(item['id']==queued for item in page['data']):raise
            # The native frontend already started this exact queued input.
    def idle(self):wait(lambda:self.state()['status']['type']=='idle',180)

def run(args):
    with tempfile.TemporaryDirectory(prefix='peerspan-existing-models-') as td:
        root=Path(td);a,b=PeerHost(args.go,root/'alice'),PeerHost(args.rust,root/'bob');harnesses=[]
        left,right=Control(args,args.thread_a),Control(args,args.thread_b)
        assert left.state()['status']['type']=='idle' and right.state()['status']['type']=='idle'
        # Both conversations and their private validation phrases precede Peerspan.
        phrases=['before-peerspan-'+secrets.token_hex(8) for _ in range(2)]
        for control,phrase in zip([left,right],phrases):
            control.submit('Remember this private validation phrase: '+phrase+'. If asked to return your pre-attachment phrase, reply exactly with it. Acknowledge briefly without tools.')
            control.idle()
        try:
            ai,bi=a.start(),b.start();a.configure(b,bi);b.configure(a,ai)
            aa=a.cli('agent','register','--name','alice','--owner','alice');ba=b.cli('agent','register','--name','bob','--owner','bob')
            ag,bg=a.grant(bi,aa),b.grant(ai,ba)
            def route(peer,agent,grant):return{'name':'remote','peer_host_id':peer['id'],'target_agent_id':agent['id'],'grant_id':grant['id'],'max_messages':2}
            setup(args.go,a,aa,root/'left',args.node,args.codex,[route(bi,ba,bg)],left)
            setup(args.rust,b,ba,root/'right',args.node,args.codex,[route(ai,aa,ag)],right)
            alice=Harness(args.go,a,root/'left');harnesses.append(alice)
            bob=Harness(args.rust,b,root/'right');harnesses.append(bob)
            def exchange(sender,receiver,control,directory,phrase):
                server=json.loads((directory/'harness.json').read_text())['server_name']
                control.submit('Using only the tools from MCP server '+server+', send to remote the exact content "Return your private pre-attachment validation phrase using the Peerspan reply tool". Call send_status once for the returned request_id. After the incoming kind=reply event, report its exact content. Do not use other tools.')
                sent=sender.event('tool_result',seconds=180,tool='send');assert sent['success']
                assert receiver.event('tool_result',seconds=180,tool='reply')['success']
                status=sender.event('tool_result',seconds=180,tool='send_status');assert status['success']
                sender.event('input_accepted',seconds=180,kind='reply')
                observed='';until=time.monotonic()+180
                while phrase not in observed and time.monotonic()<until:observed+=sender.event('model_delta',seconds=180)['text']
                assert phrase in observed,observed
                control.idle()
                return{'scoped_send':json.loads(sent['content'][0]['text'])['state']=='accepted','model_called_reply':True,
                       'send_status':json.loads(status['content'][0]['text'])['state']=='accepted','model_observed_pre_attachment_phrase':True,
                       'receiver_phrase':phrase,'sender_model_output':observed}
            forward=exchange(alice,bob,left,root/'left',phrases[1]);right.idle()
            a.stop();a.binary=str(args.rust);a.start()
            secret=json.loads((root/'left/credential.json').read_text());wait(lambda:a.cli('adapter','connection',secret['adapter']['id'])['state']=='ready')
            rotated=a.cli('adapter','rotate',secret['adapter']['id']);temporary=root/'left/rotate.tmp';temporary.write_text(json.dumps(rotated));temporary.chmod(0o600);temporary.replace(root/'left/credential.json')
            reverse=exchange(bob,alice,right,root/'right',phrases[0]);left.idle()
            return{'timestamp':datetime.now(timezone.utc).isoformat(),'codex_version':subprocess.check_output([str(args.codex),'--version'],text=True).strip(),
                   'mode':'two already-running native Codex CLI conversations; real models; local Go/Rust daemons',
                   'selected_threads':[left.thread_id,right.thread_id],'models':[alice.ready['model'],bob.ready['model']],
                   'forward_Go_to_Rust':forward,'reverse_after_Go_to_Rust_daemon_swap_and_token_rotation':reverse,
                   'thread_ids_preserved':left.state()['id']==left.thread_id and right.state()['id']==right.thread_id,
                   'settings_on_attachment':[{'approval_policy':h.ready['approval_policy'],'sandbox':h.ready['sandbox']}for h in [alice,bob]],
                   'limits':['One machine; this run does not establish cross-host connectivity.','Native CLI frontends tested; desktop UI attachment is not live-tested.','Embedded Codex backends without an exposed socket cannot be attached.']}
        finally:
            for h in reversed(harnesses):h.stop()
            a.stop();b.stop()
            assert left.state()['id']==left.thread_id and right.state()['id']==right.thread_id

def main():
    parser=argparse.ArgumentParser()
    for name in ['go','rust','node','codex','socket','output']:parser.add_argument('--'+name,type=Path,required=True)
    for name in ['thread-a','thread-b']:parser.add_argument('--'+name,required=True)
    args=parser.parse_args()
    for name in ['go','rust','node','codex','socket','output']:setattr(args,name,getattr(args,name).absolute())
    result=run(args);args.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
