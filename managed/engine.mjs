import {randomBytes,randomUUID} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {PeerConnector} from './connector.mjs';
const stamp=()=>new Date().toISOString();
const active=new Set(['submitting','queued','running']);
const terminal=new Set(['succeeded','failed','rejected','expired','cancelled']);
const target=c=>JSON.stringify([c.senderState||'',c.hostId,c.agentId]);
const count=v=>Array.isArray(v)?v.length:Number.isFinite(v)?v:0;
export class Engine{
 constructor(store,connector=new PeerConnector()){this.store=store;this.connector=connector;this.chain=Promise.resolve();this.ready=new Map();this.lastTickAt=null;this.error=null;}
 serial(fn){const next=this.chain.then(fn);this.chain=next.catch(()=>{});return next;}
 async create(body){
  const keys=['name','connectionId','instructions','intervalMinutes','maxRunsPerDay','acceptanceMinutes','enabled'];
  if(!body||Array.isArray(body)||Object.keys(body).some(k=>!keys.includes(k)))throw Error('Unexpected workflow fields');
  for(const [k,max] of [['name',100],['instructions',12000]])if(typeof body[k]!=='string'||!body[k].trim()||body[k].length>max)throw Error('Invalid '+k);
  for(const [k,min,max] of [['intervalMinutes',1,10080],['maxRunsPerDay',1,1000],['acceptanceMinutes',1,1440]])if(!Number.isInteger(body[k])||body[k]<min||body[k]>max)throw Error('Invalid '+k);
  if(body.enabled!==undefined&&typeof body.enabled!=='boolean')throw Error('Invalid enabled flag');
  if(typeof body.connectionId!=='string'||!await this.store.get('connection',body.connectionId))throw Error('Unknown worker connection');
  const workflow={...body,id:randomUUID(),name:body.name.trim(),enabled:body.enabled??false,nextRunAt:stamp(),failureStreak:0,blockedReason:null,createdAt:stamp()};
  return this.store.put('workflow',workflow);
 }
 async action(id,action){
  const w=await this.store.get('workflow',id);if(!w){const e=Error('Workflow not found');e.status=404;throw e;}
  if(action==='pause'){w.enabled=false;w.blockedReason='Paused by operator';}
  else if(action==='resume'){w.enabled=true;w.failureStreak=0;w.blockedReason=null;w.nextRunAt=stamp();}
  else if(action==='run'){w.nextRunAt=stamp();}
  else throw Error('Unknown action');
  return this.store.put('workflow',w);
 }
 async reconcile(run){
  if(run.retryAt&&Date.parse(run.retryAt)>Date.now())return;
  try{
   let remote;
   try{remote=await this.connector.inspect(run);}
   catch(e){
    if(!e.notFound||run.state!=='submitting')throw e;
    remote=await this.connector.submit(run);
   }
   const state=remote.status?.state||(remote.submit_state==='rejected'?'rejected':remote.submit_state==='accepted'?'queued':null);
   if(!state||!active.has(state)&&!terminal.has(state))throw Error('Remote task state is unresolved');
   if(state==='succeeded'||state==='failed')run.output=await this.connector.output(run,remote.status);
   run.state=state;run.error=null;run.retryAt=null;run.updatedAt=stamp();
   if(terminal.has(state)){
    run.finishedAt=stamp();
    const w=await this.store.get('workflow',run.workflowId);
    w.failureStreak=state==='succeeded'?0:w.failureStreak+1;
    w.nextRunAt=new Date(Date.now()+Math.max(w.intervalMinutes*60000,state==='succeeded'?0:60000)).toISOString();
    if(w.failureStreak>=3){w.enabled=false;w.blockedReason='Paused after three consecutive failures';}
    await this.store.batch([['run',run],['workflow',w]]);
   }else await this.store.put('run',run);
  }catch{
   run.error='Delivery or status uncertain; retaining this task identity';run.updatedAt=stamp();
   run.retryAt=new Date(Date.now()+Math.max(1000,Number(process.env.MANAGED_TICK_MS)||10000)).toISOString();
   await this.store.put('run',run);
  }
 }
 async tick(){
  const runs=await this.store.list('run');
  for(const run of runs.filter(r=>active.has(r.state)))await this.reconcile(run);
  const connections=await this.store.list('connection');
  for(const c of connections)this.ready.set(c.id,await this.connector.readiness(c));
  const latest=await this.store.list('run');const used=new Set(latest.filter(r=>active.has(r.state)).map(r=>r.target));
  for(const w of (await this.store.list('workflow')).reverse()){
   const c=connections.find(x=>x.id===w.connectionId);let reason=null;
   if(!w.enabled)reason=w.blockedReason||'Paused';
   else if(latest.some(r=>r.workflowId===w.id&&active.has(r.state)))reason='Assignment in progress';
   else if(latest.filter(r=>r.workflowId===w.id&&r.createdAt.slice(0,10)===stamp().slice(0,10)).length>=w.maxRunsPerDay)reason='Daily dispatch limit reached';
   else if(!c||!this.ready.get(c.id)?.ready)reason=this.ready.get(c?.id)?.reason||'Worker unavailable';
   else if(used.has(target(c)))reason='Worker is assigned to another managed workflow';
   else if(Date.parse(w.nextRunAt)>Date.now())reason='Waiting for next scheduled run';
   if(reason){if(w.blockedReason!==reason){w.blockedReason=reason;await this.store.put('workflow',w);}continue;}
   const taskId='task_'+randomBytes(16).toString('hex');
   const run={id:randomUUID(),workflowId:w.id,taskId,state:'submitting',target:target(c),createdAt:stamp(),updatedAt:stamp(),output:null,error:null,retryAt:null,
    submission:{peer:c.hostId,agent:c.agentId,senderState:c.senderState||null,input:w.instructions,deadline:new Date(Date.now()+w.acceptanceMinutes*60000).toISOString()}};
   // Persist before every external effect. A crash can replay only these bytes.
   w.blockedReason='Assignment in progress';
   await this.store.batch([['run',run],['workflow',w]]);used.add(run.target);latest.push(run);
   await this.reconcile(run);
  }
  this.lastTickAt=stamp();this.error=null;
 }
 async observations(){
  const result=[];
  for(const source of await this.store.list('observation')){
   try{
    const read=async name=>{const text=await readFile(join(source.directory,name),'utf8');if(text.length>2*1024*1024)throw Error('Too large');return JSON.parse(text);};
    const [config,s]=await Promise.all([read('config.json'),read('state.json')]);
    if(typeof config.enabled!=='boolean'||typeof s.phase!=='string'||!Number.isFinite(Date.parse(s.lastTickAt)))throw Error('Invalid observation');
    const t=s.task,b=s.lastBatch;const stale=Date.now()-Date.parse(s.lastTickAt)>180000;
    result.push({id:source.id,name:source.name,available:true,enabled:config.enabled,cycle:s.cycle??0,phase:s.phase,lastTickAt:s.lastTickAt,error:s.error?'Source controller reports an error':stale?'Source heartbeat is older than three minutes':null,
     task:t?{id:t.id,key:t.key,state:t.status||t.state||null,lane:t.lane||null}:null,
     lastBatch:b?{key:b.key,status:b.status,articlesAdded:count(b.articlesAdded),dossiersAdded:count(b.dossiersAdded)}:null});
   }catch{result.push({id:source.id,name:source.name,available:false,enabled:false,cycle:0,phase:'unavailable',lastTickAt:null,error:'Observation source is unavailable',task:null,lastBatch:null});}
  }return result;
 }
 async snapshot(){
  const [connections,workflows,runs,observed]=await Promise.all([this.store.list('connection'),this.store.list('workflow'),this.store.list('run'),this.observations()]);
  return {connections:connections.map(c=>({id:c.id,name:c.name,hostId:c.hostId,agentId:c.agentId,readiness:this.ready.get(c.id)||{ready:false,reason:'Checking connection',checkedAt:null}})),workflows,
   runs:runs.slice(0,100).map(({submission,target,...r})=>r),observed,
   meta:{name:'Peerspan Managed',version:'0.1.0',mode:'Local operator preview',lastTickAt:this.lastTickAt,error:this.error,modelCostAvailable:false,modelCost:'Unavailable; model usage is billed by your provider',cloudProvisioning:false}};
 }
}
