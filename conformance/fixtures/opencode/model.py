"""Deterministic OpenAI-compatible model fixture for the real OpenCode runtime."""
import http.server
import json
import threading
import uuid

class Model:
    def __init__(self):
        owner=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*_args):pass
            def do_POST(self):
                body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                messages=body.get('messages',[])
                def content(message):
                    value=message.get('content','')
                    return value if isinstance(value,str) else '\n'.join(p.get('text','') for p in value or [] if isinstance(p,dict))
                last_user=next((content(m) for m in reversed(messages) if m['role']=='user'),'')
                tool=None;args=None;text='fixture ready'
                if messages and messages[-1]['role']=='tool':text='fixture tool completed'
                elif 'External Capsule event:\n' in last_user:
                    event=json.JSONDecoder().raw_decode(last_user.split('External Capsule event:\n',1)[1])[0]
                    if event['meta']['kind']=='message':tool='capsule_reply';args={'delivery_id':event['meta']['delivery_id'],'content':'runtime fixture reply: '+event['content']}
                    else:text=event['content']
                elif last_user.startswith('send '):tool='capsule_send';args={'destination':'remote','content':last_user[5:]}
                elif last_user.startswith('status '):tool='capsule_send_status';args={'request_id':last_user[7:].strip()}
                owner.requests+=1
                self.send_response(200);self.send_header('Content-Type','text/event-stream');self.end_headers()
                delta={'role':'assistant'}
                if tool:delta['tool_calls']=[{'index':0,'id':'call_'+uuid.uuid4().hex,'type':'function','function':{'name':tool,'arguments':json.dumps(args)}}]
                else:delta['content']=text
                def chunk(delta,finish):return {'id':'fixture','object':'chat.completion.chunk','created':1,'model':'fixture','choices':[{'index':0,'delta':delta,'finish_reason':finish}]}
                for value in [chunk(delta,None),chunk({},'tool_calls' if tool else 'stop')]:self.wfile.write(('data: '+json.dumps(value)+'\n\n').encode())
                self.wfile.write(b'data: [DONE]\n\n');self.wfile.flush()
        self.requests=0
        self.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.url='http://127.0.0.1:'+str(self.server.server_port)+'/v1'
    def close(self):self.server.shutdown();self.server.server_close();self.thread.join()
