#!/usr/bin/env python3
"""Real Capsule daemons + real Codex bridge; explicit app-server fixture, no model."""
import argparse
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import tempfile
import threading
import time
from claude_setup import invoke, snapshot, wait
from peer_messaging import PeerHost, timestamp

ROOT = Path(__file__).resolve().parents[1]

class Harness:
    def __init__(self, client, host, directory, prompt=None):
        self.events = []
        self.queue = queue.Queue()
        self.logs = tempfile.TemporaryFile()
        args = [str(client), 'session', 'start', '--directory', str(directory), '--workspace', str(directory.parent), '--', '--json']
        if prompt: args += ['--prompt', prompt]
        self.process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.logs, text=True)
        self.reader = threading.Thread(target=self.read, daemon=True); self.reader.start()
        try: self.ready = self.event('ready')
        except BaseException: self.stop(); raise
    def read(self):
        try:
            for line in self.process.stdout: self.queue.put(json.loads(line))
        finally: self.queue.put(None)
    def event(self, event_type, seconds=15, **keys):
        deadline = time.monotonic() + seconds
        while True:
            for event in self.events:
                if event.get('type') == event_type and all(event.get(k) == v for k,v in keys.items()):
                    self.events.remove(event); return event
            remaining = deadline-time.monotonic()
            assert remaining > 0, ('harness event timed out', event_type, keys, self.events)
            event = self.queue.get(timeout=remaining)
            assert event is not None, ('harness exited', self.process.poll(), self.events)
            self.events.append(event)
    def verified(self, seconds=15):
        # Live delivery readiness: the fixture model answered the hello event.
        result = self.event('tool_result', seconds, tool='capsule_ready'); assert result['success'], result
    def input(self, text):
        self.process.stdin.write(text+'\n'); self.process.stdin.flush()
    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try: self.process.wait(timeout=8)
            except subprocess.TimeoutExpired: self.process.kill(); self.process.wait()
        self.process.stdin.close(); self.process.stdout.close(); self.logs.close()

class Backend(Harness):
    def __init__(self,node,directory):
        self.events=[];self.queue=queue.Queue();self.logs=tempfile.TemporaryFile();self.count=0
        self.socket=directory/'codex.sock';self.thread_id='00000000-0000-4000-8000-000000000001'
        self.process=subprocess.Popen([str(node),str(ROOT/'conformance/fixtures/codex/backend.mjs'),str(self.socket),self.thread_id],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.logs,text=True)
        self.reader=threading.Thread(target=self.read,daemon=True);self.reader.start();self.ready=self.event('ready')
    def control(self,op,**values):
        self.count+=1;self.process.stdin.write(json.dumps({'op':op,'id':self.count,**values})+'\n');self.process.stdin.flush()
        result=self.event('control',id=self.count);assert not result.get('error'),result;return result
    def input(self,text):return self.control('input',text=text)

def setup(client,host,agent,directory,node,codex,routes,backend):
    path=directory.parent/(directory.name+'-routes.json');path.write_text(json.dumps(routes))
    return invoke(client,host,'setup','--harness','codex','--integrations',str(ROOT/'integrations'),
        '--runner',str(node),'--option','executable='+str(codex),'--option','thread='+backend.thread_id,
        '--option','socket='+str(backend.socket),'--directory',str(directory),'--agent',agent['id'],
        '--expires-at',timestamp(900),'--routes',str(path))

def check(client, source_binary, receiver_binary, replacement, node, label):
    codex = ROOT/'conformance/fixtures/codex/codex.py'
    with tempfile.TemporaryDirectory(prefix='capsule-codex-') as td:
        root = Path(td); source = PeerHost(source_binary,root/'source'); receiver = PeerHost(receiver_binary,root/'receiver')
        harnesses=[]; paused=None
        try:
            a,b=source.start(),receiver.start(); source.configure(receiver,b); receiver.configure(source,a)
            mine=source.cli('agent','register','--name','alice','--owner','alice')
            target=receiver.cli('agent','register','--name','bob','--owner','bob')
            inbound=receiver.grant(a,target); reverse=source.grant(b,mine)
            def route(peer,agent,grant): return {'name':'remote','peer_host_id':peer['id'],'target_agent_id':agent['id'],'grant_id':grant['id'],'max_messages':2}
            left,right=root/'left',root/'right'
            (root/'alice-backend').mkdir();(root/'bob-backend').mkdir()
            alice_backend=Backend(node,root/'alice-backend');bob_backend=Backend(node,root/'bob-backend');harnesses.extend([alice_backend,bob_backend])
            setup(client,source,mine,left,node,codex,[route(b,target,inbound)],alice_backend)
            setup(client,receiver,target,right,node,codex,[route(a,mine,reverse)],bob_backend)
            # Other native CLI can launch the profile unchanged.
            alice=Harness(replacement,source,left); harnesses.append(alice)
            bob=Harness(client,receiver,right); harnesses.append(bob)
            alice.verified(); bob.verified()
            before=json.loads((left/'credential.json').read_text()); original=before['adapter']
            wait(lambda: source.cli('adapter','connection',original['id'])['state']=='ready')
            alice_backend.input('destinations'); destinations=alice.event('tool_result',tool='list_destinations'); assert destinations['success']
            assert json.loads(destinations['content'][0]['text'])[0]['messages_remaining']==2
            alice_backend.input('invalid'); assert alice.event('tool_result',tool='send')['success'] is False
            assert alice_backend.control('wrong-thread')['result']['isError']
            bob_backend.control('busy',value=True)
            alice_backend.input('send first')
            out=json.loads(alice.event('tool_result',tool='send')['content'][0]['text']); assert out['state']=='accepted'
            bob.event('input_accepted',kind='message')
            assert bob_backend.control('inspect')['thread']['status']['type']=='active'
            bob_backend.control('busy',value=False)
            assert bob.event('tool_result',tool='reply')['success']
            assert alice.event('model_delta')['text']=='fixture reply: first'
            alice_backend.input('status '+out['request_id']); status=json.loads(alice.event('tool_result',tool='send_status')['content'][0]['text']); assert status['state']=='accepted'
            # Read-only doctor must not alter durable state or acquire a lease.
            os.kill(alice.process.pid,signal.SIGSTOP); os.waitpid(alice.process.pid,os.WUNTRACED); paused=alice
            prior=snapshot(source); report=invoke(client,source,'doctor','--directory',str(left)); assert snapshot(source)==prior
            assert report['message_consumption']=='unverified'
            os.kill(alice.process.pid,signal.SIGCONT); paused=None
            # The original process instance recovers through a daemon language swap.
            source.stop(); source.binary=str(replacement); source.start()
            wait(lambda: source.cli('adapter','connection',original['id'])['state']=='ready')
            assert json.loads((left/'credential.json').read_text())['adapter']['session_id']==original['session_id']
            rotated=source.cli('adapter','rotate',original['id'])
            temporary=left/'rotate.tmp'; temporary.write_text(json.dumps(rotated)); temporary.chmod(0o600); temporary.replace(left/'credential.json')
            bob_backend.input('send reverse'); assert bob.event('tool_result',tool='send')['success']
            assert alice.event('tool_result',tool='reply')['success']; assert bob.event('model_delta')['text']=='fixture reply: reverse'
            alice_backend.input('send second'); assert alice.event('tool_result',tool='send')['success']; assert bob.event('tool_result',tool='reply')['success']; alice.event('model_delta')
            alice_backend.input('send exhausted'); denied=alice.event('tool_result',tool='send'); assert not denied['success']
            # Lost queue acknowledgement leaves the host claim unknown, without
            # recreating input or killing/replacing the existing Codex backend.
            alice_backend.control('drop')
            direct=receiver.submit(a,mine,reverse,'uncertain queue acceptance')
            assert direct['state']=='accepted'
            alice.event('error')
            alice.process.wait(timeout=15)
            assert alice_backend.control('inspect')['thread']['id']==alice_backend.thread_id
            receiver.cli('grant','revoke',inbound['id'])
            source.cli('adapter','revoke',original['id'])
            # No model claim: fixtures validate transport, fencing and scopes only.
        finally:
            if paused: os.kill(paused.process.pid,signal.SIGCONT)
            for harness in reversed(harnesses): harness.stop()
            source.stop(); receiver.stop()
    print(label+': Codex setup, tools, existing-thread queueing, replies, doctor, recovery and budgets passed',flush=True)

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--go',type=Path,required=True); parser.add_argument('--rust',type=Path,required=True); parser.add_argument('--node',type=Path,required=True)
    args=parser.parse_args(); go,rust,node=args.go.resolve(),args.rust.resolve(),args.node.resolve()
    for client,receiver,label,replacement in [(go,go,'Go/Go',rust),(go,rust,'Go/Rust',rust),(rust,go,'Rust/Go',go),(rust,rust,'Rust/Rust',go)]:
        check(client,client,receiver,replacement,node,label)
if __name__=='__main__': main()
