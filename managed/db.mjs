import {Worker} from 'node:worker_threads';
import {mkdir,chmod,readFile,writeFile} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {homedir} from 'node:os';
import {randomBytes} from 'node:crypto';
export const defaultState=()=>join(homedir(),'.local/state/peerspan-managed');
export async function prepareState(directory){
 const path=resolve(directory);await mkdir(path,{recursive:true,mode:0o700});await chmod(path,0o700);
 const tokenFile=join(path,'access-token');
 try{await writeFile(tokenFile,randomBytes(32).toString('hex')+'\n',{flag:'wx',mode:0o600});}catch(e){if(e.code!=='EEXIST')throw e;}
 const token=(await readFile(tokenFile,'utf8')).trim();if(!/^[a-f0-9]{64}$/.test(token))throw Error('Invalid private access token');
 await chmod(tokenFile,0o600);return {path,token};
}
export async function openStore(path){
 const worker=new Worker(new URL('./db-worker.mjs',import.meta.url),{workerData:{file:join(path,'managed.sqlite')}});
 const pending=new Map();let counter=0,closed=false;
 await new Promise((resolve,reject)=>{worker.once('message',resolve);worker.once('error',reject);});
 worker.on('message',m=>{const p=pending.get(m.id);if(!p)return;pending.delete(m.id);m.error?p.reject(Error(m.error)):p.resolve(m.value);});
 worker.on('error',e=>{for(const p of pending.values())p.reject(e);pending.clear();});
 worker.on('exit',()=>{for(const p of pending.values())p.reject(Error('Storage worker stopped'));pending.clear();});
 await chmod(join(path,'managed.sqlite'),0o600);
 const request=(op,...args)=>new Promise((resolve,reject)=>{if(closed)return reject(Error('Storage closed'));const id=++counter;pending.set(id,{resolve,reject});worker.postMessage({id,op,args});});
 return {get:(kind,id)=>request('get',kind,id),list:kind=>request('list',kind),put:(kind,record)=>request('put',kind,record),batch:rows=>request('batch',rows),close:async()=>{await request('close');closed=true;await worker.terminate();}};
}
