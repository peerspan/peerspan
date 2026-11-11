#!/usr/bin/env node
import {join,resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
import {defaultState,prepareState,openStore} from './db.mjs';
import {workerState} from './connector.mjs';
import {Engine} from './engine.mjs';
import {startServer} from './server.mjs';
process.umask(0o077);
const help=`Peerspan Managed — persistent agent operations

node managed/cli.mjs serve [--state DIR] [--port 4310]
node managed/cli.mjs token [--state DIR]
node managed/cli.mjs connect --name NAME --worker-state FILE [--sender-state DIR] [--state DIR]
node managed/cli.mjs observe --name NAME --directory DIR [--state DIR]
node managed/cli.mjs status [--state DIR]

Connect existing Peerspan workers. This preview does not launch model sessions.
Read managed/README.md for setup, limits, and the supervised service recipe.`;
function lock(path){
 if(process.platform!=='linux'||typeof process.execve!=='function')throw Error('Run the controller in Linux or WSL with Node 24');
 const marker=path+':'+process.pid;
 if(process.env.PEERSPAN_MANAGED_LOCKED===marker){delete process.env.PEERSPAN_MANAGED_LOCKED;return;}
 // Same PID, no orphan wrapper. Kernel releases the lock even after SIGKILL.
 // Unlike PID-file deletion this is atomic during simultaneous crash recovery.
 process.execve('/usr/bin/flock',['flock','--nonblock','--conflict-exit-code','73','--no-fork',join(path,'runner.lock'),process.execPath,...process.argv.slice(1)],{...process.env,PEERSPAN_MANAGED_LOCKED:marker});
}
async function main(){
 const [command,...args]=process.argv.slice(2);if(!command||command==='--help'){console.log(help);return;}
 const allowed={serve:['state','port'],token:['state'],connect:['state','name','worker-state','sender-state'],observe:['state','name','directory'],status:['state']}[command];
 if(!allowed)throw Error('Unknown command; use --help');
 const opts={};for(let i=0;i<args.length;i+=2){const key=args[i].slice(2);if(!args[i].startsWith('--')||!allowed.includes(key)||!args[i+1]||Object.hasOwn(opts,key))throw Error('Invalid command option');opts[key]=args[i+1];}
 const {path,token}=await prepareState(opts.state||defaultState());
 if(command==='token'){console.log(token);return;}
 if(command==='serve')lock(path);
 const store=await openStore(path);const engine=new Engine(store);
 try{
  if(command==='connect'){
   if(!opts.name?.trim()||opts.name.length>100||!opts['worker-state'])throw Error('Name and worker-state are required');
   const file=resolve(opts['worker-state']);const w=await workerState(file);
   const connection={id:randomUUID(),name:opts.name.trim(),workerState:file,hostDir:resolve(w.host_dir),hostId:w.host_id,agentId:w.agent_id,senderState:opts['sender-state']?resolve(opts['sender-state']):null};
   await store.put('connection',connection);console.log(JSON.stringify({id:connection.id,name:connection.name}));
  }else if(command==='observe'){
   if(!opts.name?.trim()||opts.name.length>100||!opts.directory)throw Error('Name and directory are required');
   const source={id:randomUUID(),name:opts.name.trim(),directory:resolve(opts.directory)};await store.put('observation',source);console.log(JSON.stringify({id:source.id,name:source.name}));
  }else if(command==='status'){console.log(JSON.stringify(await engine.snapshot(),null,2));}
  else if(command==='serve'){
   const port=Number(opts.port||4310);if(!Number.isInteger(port)||port<1024||port>65535)throw Error('Port must be an integer from 1024 to 65535');
   const interval=Number(process.env.MANAGED_TICK_MS||10000);if(!Number.isFinite(interval)||interval<100)throw Error('Invalid polling interval');
   const server=await startServer({engine,token,port});let timer,stopping=false;
   const tick=async()=>{try{await engine.serial(()=>engine.tick());}catch{engine.error='Controller check failed; inspect local service logs';}finally{if(!stopping)timer=setTimeout(tick,interval);}};
   void tick();console.log(`Peerspan Managed ready at http://localhost:${port}\nUse the token command to sign in. No model sessions are started automatically.`);
   await new Promise(resolve=>{
    const stop=()=>{if(stopping)return;stopping=true;clearTimeout(timer);server.closeAllConnections();server.close(()=>resolve());};
    process.once('SIGTERM',stop);process.once('SIGINT',stop);
   });
   await engine.chain;
  }
 }finally{await store.close();}
}
main().catch(error=>{console.error(error.message);process.exitCode=1;});
