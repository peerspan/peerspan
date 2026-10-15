#!/usr/bin/env python3
"""Pre-existing HTTP backend fixtures + real plugin/sidecar over real daemons."""
import argparse
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import tempfile
import threading
from claude_setup import invoke,snapshot,wait
from codex_integration import Harness,ROOT
from peer_messaging import PeerHost,timestamp

class Backend(Harness):
    def __init__(self,node,directory):
        directory.mkdir();self.directory=directory;self.bindings=directory/'bindings'
        self.events=[];self.queue=queue.Queue();self.logs=tempfile.TemporaryFile();self.count=0
        self.process=subprocess.Popen([str(node),str(ROOT/'conformance/fixtures/opencode/backend.mjs'),str(directory),str(self.bindings),str(ROOT/'integrations/opencode/plugin.mjs')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.logs,text=True)
        self.reader=threading.Thread(target=self.read,daemon=True);self.reader.start();self.ready=self.event('ready');self.server=self.ready['server'];self.session_id=self.ready['session_id']
    def control(self,op,**values):
        self.count+=1;self.process.stdin.write(json.dumps({'id':self.count,'op':op,**values})+'\n');self.process.stdin.flush()
        result=self.event('control',id=self.count);assert not result.get('error'),result;return result.get('result')
    def input(self,text):return self.control('input',text=text)

def setup(client,host,agent,directory,node,routes,backend):
    path=directory.parent/(directory.name+'-routes.json');path.write_text(json.dumps(routes))
    return invoke(client,host,'setup','--harness','opencode','--integrations',str(ROOT/'integrations'),'--runner',str(node),
                  '--option','server='+backend.server,'--option','session='+backend.session_id,'--option','directory='+str(backend.directory),
                  '--option','bindings='+str(backend.bindings),'--directory',str(directory),'--agent',agent['id'],'--expires-at',timestamp(900),'--routes',str(path))

def check(client,receiver_binary,replacement,node,label):
    with tempfile.TemporaryDirectory(prefix='peerspan-opencode-') as td:
        root=Path(td);a,b=PeerHost(client,root/'a'),PeerHost(receiver_binary,root/'b');harnesses=[];paused=None
        try:
            ai,bi=a.start(),b.start();a.configure(b,bi);b.configure(a,ai)
            aa=a.cli('agent','register','--name','alice','--owner','alice');ba=b.cli('agent','register','--name','bob','--owner','bob')
            ag,bg=a.grant(bi,aa),b.grant(ai,ba)
            def route(peer,agent,grant):return{'name':'remote','peer_host_id':peer['id'],'target_agent_id':agent['id'],'grant_id':grant['id'],'max_messages':2}
            alpha=Backend(node,root/'alpha');beta=Backend(node,root/'beta');harnesses.extend([alpha,beta]);before=alpha.control('inspect')['session']
            left,right=root/'left',root/'right';setup(client,a,aa,left,node,[route(bi,ba,bg)],alpha);setup(client,b,ba,right,node,[route(ai,aa,ag)],beta)
            alice=Harness(replacement,a,left);bob=Harness(client,b,right);harnesses.extend([alice,bob]);alice.verified();bob.verified()
            assert alpha.control('inspect')['session']==before
            assert alpha.control('wrong-session')['blocked'];assert alpha.control('deny')['blocked']
            alpha.input('destinations');destinations=alice.event('tool_result',tool='list_destinations');assert json.loads(destinations['content'][0]['text'])[0]['messages_remaining']==2
            beta.control('busy',value=True);alpha.input('send first');out=json.loads(alice.event('tool_result',tool='send')['content'][0]['text']);assert out['state']=='accepted'
            bob.event('input_accepted',kind='message');beta.control('busy',value=False);assert bob.event('tool_result',tool='reply')['success'];alpha.event('model_output',text='fixture reply: first')
            alpha.input('status '+out['request_id']);assert alice.event('tool_result',tool='send_status')['success']
            secret=json.loads((left/'credential.json').read_text());aid=secret['adapter']['id'];wait(lambda:a.cli('adapter','connection',aid)['state']=='ready')
            os.kill(alice.process.pid,signal.SIGSTOP);os.waitpid(alice.process.pid,os.WUNTRACED);paused=alice
            prior=snapshot(a);report=invoke(client,a,'doctor','--directory',str(left));assert snapshot(a)==prior;assert report['message_consumption']=='unverified';assert report['adapter_ready']
            os.kill(alice.process.pid,signal.SIGCONT);paused=None
            a.stop();a.binary=str(replacement);a.start();wait(lambda:a.cli('adapter','connection',aid)['state']=='ready')
            rotated=a.cli('adapter','rotate',aid);temporary=left/'rotate.tmp';temporary.write_text(json.dumps(rotated));temporary.chmod(0o600);temporary.replace(left/'credential.json')
            beta.input('send reverse');assert bob.event('tool_result',tool='send')['success'];assert alice.event('tool_result',tool='reply')['success'];beta.event('model_output',text='fixture reply: reverse')
            alpha.input('send second');assert alice.event('tool_result',tool='send')['success'];assert bob.event('tool_result',tool='reply')['success'];alpha.event('model_output',text='fixture reply: second')
            alpha.input('send exhausted');assert not alice.event('tool_result',tool='send')['success']
            alpha.control('drop');direct=b.submit(ai,aa,ag,'uncertain submission');assert direct['state']=='accepted';alice.event('error');alice.process.wait(timeout=15)
            assert alpha.control('inspect')['session']==before;assert not (alpha.bindings/(alpha.session_id+'.json')).exists()
        finally:
            if paused:os.kill(paused.process.pid,signal.SIGCONT)
            for h in reversed(harnesses):h.stop()
            a.stop();b.stop()
    print(label+': existing OpenCode session, plugin fencing/native permissions, exchange, read-only doctor, rotation/restart, budgets and uncertain handoff passed',flush=True)

def main():
    parser=argparse.ArgumentParser()
    for name in ['go','rust','node']:parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();go,rust,node=args.go.resolve(),args.rust.resolve(),args.node.resolve()
    for client,receiver,replacement,label in [(go,go,rust,'Go/Go'),(go,rust,rust,'Go/Rust'),(rust,go,go,'Rust/Go'),(rust,rust,go,'Rust/Rust')]:check(client,receiver,replacement,node,label)
if __name__=='__main__':main()
