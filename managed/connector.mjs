import {execFile} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {isAbsolute,resolve} from 'node:path';
import {promisify} from 'node:util';
const execute=promisify(execFile);
export const identifier=(kind,value)=>new RegExp('^'+kind+'_[a-f0-9]{'+(kind==='host'?64:32)+'}$').test(value||'');
export async function workerState(file){
 const text=await readFile(file,'utf8');if(text.length>65536)throw Error('Worker state too large');
 const w=JSON.parse(text);
 for(const kind of ['host','agent','adapter','session'])if(!identifier(kind,w[kind+'_id']))throw Error('Invalid worker identity');
 if(typeof w.host_dir!=='string'||!isAbsolute(w.host_dir))throw Error('Worker host directory must be absolute');
 return w;
}
export class PeerConnector{
 constructor(binary=process.env.PEERSPAN_BIN||'peerspan'){this.binary=binary;}
 async call(state,args,{status=false}={}){
  const argv=[...(state?['--state',state]:[]),'--json',...args];let stdout;
  try{({stdout}=await execute(this.binary,argv,{encoding:'utf8',timeout:15000,maxBuffer:4*1024*1024,windowsHide:true}));}
  catch(e){
   if(status&&e.code===1&&e.stdout){stdout=e.stdout;}
   else {const err=Error(e.code==='ENOENT'?'Peerspan executable is unavailable':'Peerspan command failed');err.notFound=e.code===1&&/^error: host daemon: not found\s*$/.test(e.stderr||'');throw err;}
  }
  try{return JSON.parse(stdout);}catch{throw Error('Peerspan returned invalid JSON');}
 }
 async readiness(connection){
  const checkedAt=new Date().toISOString();
  try{
   const w=await workerState(connection.workerState);
   if(w.host_id!==connection.hostId||w.agent_id!==connection.agentId||resolve(w.host_dir)!==connection.hostDir)return {ready:false,reason:'Worker identity changed; reconnect explicitly',checkedAt};
   const [s,a]=await Promise.all([this.call(w.host_dir,['status'],{status:true}),this.call(w.host_dir,['adapter','connection',w.adapter_id])]);
   const ready=typeof s.service?.active==='boolean'&&s.host_id===w.host_id&&Array.isArray(s.attention)&&Array.isArray(s.agents)&&s.agents.some(x=>x.id===w.agent_id&&x.sessions?.some(t=>t.id===w.session_id&&t.adapter_id===w.adapter_id&&t.connection==='ready'))&&a.adapter_id===w.adapter_id&&a.session_id===w.session_id&&a.state==='ready'&&a.channel==='verified'&&!!a.channel_verified_at;
   return {ready,reason:ready?(s.service.active?'Verified channel':'Verified channel; user service is inactive'):'Waiting for a verified worker channel',checkedAt};
  }catch{return {ready:false,reason:'Worker connection unavailable',checkedAt};}
 }
 inspect(run){return this.call(run.submission.senderState,['task','inspect','--peer',run.submission.peer,run.taskId]);}
 async output(run,status){
  if(!Number.isInteger(status.last_event)||status.last_event<1)throw Error('Final task event is unavailable');
  const events=await this.call(run.submission.senderState,['task','events','--peer',run.submission.peer,run.taskId,'--after',String(status.last_event-1)]);
  const final=Array.isArray(events)&&events.find(e=>e.sequence===status.last_event&&e.kind===status.state&&e.state===status.state&&typeof e.output==='string'&&e.output.length);
  if(!final)throw Error('Waiting for final task output');
  return final.output.slice(0,262144);
 }
 submit(run){const p=run.submission;return this.call(p.senderState,['task','submit','--peer',p.peer,'--agent',p.agent,'--task',run.taskId,'--input',p.input,'--deadline',p.deadline]);}
}
