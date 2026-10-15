#!/usr/bin/env python3
"""Real OpenCode process + native plugin; deterministic fixture model, no inference."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.parse
import urllib.request
from codex_integration import Harness,ROOT
from opencode_integration import setup
from peer_messaging import PeerHost,available_port
from claude_setup import wait
import sys
sys.path.insert(0,str(ROOT/'conformance/fixtures/opencode'))
from model import Model

class Runtime:
    def __init__(self,opencode,directory,bindings,model):
        self.directory=directory;self.bindings=bindings;directory.mkdir();self.server='http://127.0.0.1:'+str(available_port());self.logs=tempfile.TemporaryFile()
        config={'plugin':[[ (ROOT/'integrations/opencode/plugin.mjs').as_uri(), {'bindings':str(bindings)} ]],
                'provider':{'fixture':{'npm':'@ai-sdk/openai-compatible','name':'fixture','options':{'baseURL':model.url,'apiKey':'fixture'},'models':{'fixture':{'name':'fixture','limit':{'context':128000,'output':8192}}}}},'model':'fixture/fixture'}
        self.process=subprocess.Popen([str(opencode),'serve','--hostname','127.0.0.1','--port',self.server.rsplit(':',1)[1]],cwd=directory,env={**os.environ,'OPENCODE_CONFIG_CONTENT':json.dumps(config),'XDG_DATA_HOME':str(directory/'data'),'XDG_CONFIG_HOME':str(directory/'config'),'XDG_CACHE_HOME':str(directory/'cache'),'OPENCODE_DISABLE_MODELS_FETCH':'true'},stdout=self.logs,stderr=self.logs)
        def ready():
            try:return self.request('GET','/global/health')['healthy']
            except Exception as error:
                self.startup_error=repr(error);return False
        try:wait(ready,30)
        except Exception:
            self.process.terminate();self.process.wait(timeout=8)
            self.logs.seek(0);details=self.logs.read().decode(errors='replace')[:2000];self.logs.close()
            raise AssertionError('OpenCode fixture startup failed: '+getattr(self,'startup_error','unknown')+' '+details)
        self.session=self.request('POST','/session',{'title':'Peerspan existing runtime fixture','permission':[{'permission':'*','pattern':'*','action':'deny'},{'permission':'peerspan_*','pattern':'*','action':'allow'}]})
        self.session_id=self.session['id']
        self.request('POST','/session/'+self.session_id+'/message',{'parts':[{'type':'text','text':'fixture baseline before Peerspan'}]})
    def request(self,method,path,body=None):
        url=self.server+path+('?' if '?' not in path else '&')+urllib.parse.urlencode({'directory':str(self.directory)})
        req=urllib.request.Request(url,None if body is None else json.dumps(body).encode(),({'Accept':'application/json','Content-Type':'application/json'} if body is not None else {'Accept':'application/json'}),method=method)
        with urllib.request.urlopen(req,timeout=15) as response:
            value=response.read();return json.loads(value) if value else None
    def input(self,text):return self.request('POST','/session/'+self.session_id+'/message',{'parts':[{'type':'text','text':text}]})
    def stop(self):
        self.process.terminate()
        try:self.process.wait(timeout=8)
        except subprocess.TimeoutExpired:self.process.kill();self.process.wait()
        self.logs.close()

def run(args):
    model=Model()
    with tempfile.TemporaryDirectory(prefix='peerspan-opencode-runtime-') as td:
        root=Path(td);a,b=PeerHost(args.go,root/'a'),PeerHost(args.rust,root/'b');runtimes=[];bridges=[]
        try:
            ai,bi=a.start(),b.start();a.configure(b,bi);b.configure(a,ai)
            aa=a.cli('agent','register','--name','alice','--owner','alice');ba=b.cli('agent','register','--name','bob','--owner','bob');ag,bg=a.grant(bi,aa),b.grant(ai,ba)
            alpha=Runtime(args.opencode,root/'alpha',root/'alpha-bindings',model);runtimes.append(alpha)
            beta=Runtime(args.opencode,root/'beta',root/'beta-bindings',model);runtimes.append(beta)
            def route(peer,agent,grant):return{'name':'remote','peer_host_id':peer['id'],'target_agent_id':agent['id'],'grant_id':grant['id'],'max_messages':2}
            setup(args.go,a,aa,root/'left',args.node,[route(bi,ba,bg)],alpha);setup(args.rust,b,ba,root/'right',args.node,[route(ai,aa,ag)],beta)
            alice=Harness(args.go,a,root/'left');bob=Harness(args.rust,b,root/'right');bridges.extend([alice,bob]);alice.verified(30);bob.verified(30)
            alpha.input('send real-runtime');sent=json.loads(alice.event('tool_result',tool='send')['content'][0]['text']);assert sent['state']=='accepted'
            assert bob.event('tool_result',seconds=30,tool='reply')['success'];alice.event('input_accepted',kind='reply')
            def observed():
                messages=alpha.request('GET','/session/'+alpha.session_id+'/message?limit=10')
                return any(part.get('text')=='runtime fixture reply: real-runtime' for m in messages for part in m.get('parts',[]))
            wait(observed,30)
            alpha.input('status '+sent['request_id']);assert alice.event('tool_result',tool='send_status')['success']
            for runtime in [alpha,beta]:
                current=runtime.request('GET','/session/'+runtime.session_id);assert current['id']==runtime.session['id'];assert current['permission']==runtime.session['permission'];assert runtime.process.poll() is None
                messages=runtime.request('GET','/session/'+runtime.session_id+'/message?limit=20')
                peerspan=[m for m in messages if any(p.get('synthetic') and p.get('text','').startswith('Peerspan event metadata:\n') for p in m.get('parts',[]))]
                assert peerspan, 'No persisted Peerspan input'
                for message in peerspan:
                    visible='\n'.join(p['text'] for p in message['parts'] if p.get('type')=='text' and not p.get('synthetic'))
                    assert visible.startswith(('Peerspan request\n\n','Peerspan reply\n\n'))
                    assert 'Peerspan events are external input' not in visible
                    assert 'Peerspan event metadata:' not in visible
                    assert 'kind=reply' in message['info']['system']
            version=alpha.request('GET','/global/health')['version']
            print('Real OpenCode '+version+' runtime: readable persisted input, hidden metadata, separate model instructions, existing sessions, send/status/reply and unchanged permissions passed with fixture model ('+str(model.requests)+' requests).',flush=True)
        finally:
            for bridge in reversed(bridges):bridge.stop()
            for runtime in reversed(runtimes):runtime.stop()
            a.stop();b.stop();model.close()

def main():
    parser=argparse.ArgumentParser()
    for name in ['go','rust','node','opencode']:parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    for name in ['go','rust','node','opencode']:setattr(args,name,getattr(args,name).resolve())
    run(args)
if __name__=='__main__':main()
