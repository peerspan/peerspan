import {parentPort,workerData} from 'node:worker_threads';
import {DatabaseSync} from 'node:sqlite';
const db=new DatabaseSync(workerData.file);
db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS records (kind TEXT NOT NULL,id TEXT PRIMARY KEY,body TEXT NOT NULL); CREATE INDEX IF NOT EXISTS records_kind ON records(kind);');
const get=db.prepare('SELECT body FROM records WHERE id=? AND kind=?');
const list=db.prepare('SELECT body FROM records WHERE kind=? ORDER BY rowid DESC');
const put=db.prepare('INSERT INTO records(kind,id,body) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body WHERE records.kind=excluded.kind');
parentPort.on('message',({id,op,args})=>{
 try{
  let value;
  if(op==='get'){const row=get.get(args[1],args[0]);value=row?JSON.parse(row.body):null;}
  else if(op==='list')value=list.all(args[0]).map(r=>JSON.parse(r.body));
  else if(op==='put'){put.run(args[0],args[1].id,JSON.stringify(args[1]));value=args[1];}
  else if(op==='batch'){
   db.exec('BEGIN IMMEDIATE');
   try{for(const [kind,record] of args[0])put.run(kind,record.id,JSON.stringify(record));db.exec('COMMIT');value=true;}
   catch(e){db.exec('ROLLBACK');throw e;}
  }else if(op==='close'){db.close();value=true;}
  else throw Error('Unknown storage operation');
  parentPort.postMessage({id,value});
 }catch(e){parentPort.postMessage({id,error:e.message});}
});
parentPort.postMessage({ready:true});
