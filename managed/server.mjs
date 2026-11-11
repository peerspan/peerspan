import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {randomBytes,timingSafeEqual} from 'node:crypto';
const eq=(a,b)=>typeof a==='string'&&Buffer.byteLength(a)===Buffer.byteLength(b)&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
export async function startServer({engine,token,port}){
 const sessions=new Map();
 const assets=new Map(await Promise.all([['/','index.html','text/html'],['/app.js','app.js','text/javascript'],['/style.css','style.css','text/css']].map(async([route,file,type])=>[route,{type,body:await readFile(new URL('./public/'+file,import.meta.url))}])));
 const server=createServer(async(req,res)=>{
  const json=(status,data)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(data));};
  for(const [k,v] of Object.entries({'Cache-Control':'no-store','X-Robots-Tag':'noindex, nofollow','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"}))res.setHeader(k,v);
  if(![`127.0.0.1:${port}`,`localhost:${port}`].includes(req.headers.host))return json(403,{error:'Host is not allowed'});
  const origin='http://'+req.headers.host;
  const path=new URL(req.url,origin).pathname;
  const mutation=!['GET','HEAD'].includes(req.method);
  if(req.headers.origin&&req.headers.origin!==origin)return json(403,{error:'Origin is not allowed'});
  const bearer=req.headers.authorization?.startsWith('Bearer ')&&eq(req.headers.authorization.slice(7),token);
  const cookie=req.headers.cookie?.split(';').map(v=>v.trim()).find(v=>v.startsWith('managed_session='))?.slice(16);
  const authenticated=bearer||!!cookie&&(sessions.get(cookie)||0)>Date.now();
  if(path==='/health'&&req.method==='GET')return json(200,{ok:true});
  if(mutation&&!bearer&&req.headers.origin!==origin)return json(403,{error:'Same-origin request required'});
  if(path.startsWith('/api/')&&path!=='/api/login'&&!authenticated)return json(401,{error:'Sign in to your local console'});
  const body=async()=>{
   let size=0;const chunks=[];
   for await(const chunk of req){size+=chunk.length;if(size>65536){const e=Error('Request is too large');e.status=413;throw e;}chunks.push(chunk);}
   const data=JSON.parse(Buffer.concat(chunks).toString()||'{}');
   if(!data||typeof data!=='object'||Array.isArray(data))throw Error('Expected a JSON object');return data;
  };
  try{
   if(path==='/api/login'&&req.method==='POST'){
    const data=await body();if(Object.keys(data).some(k=>k!=='token'))return json(400,{error:'Unexpected login fields'});
    if(!eq(data.token,token))return json(401,{error:'Invalid access token'});
    for(const [key,expiry] of sessions)if(expiry<Date.now())sessions.delete(key);
    const session=randomBytes(32).toString('hex');sessions.set(session,Date.now()+43200000);
    res.setHeader('Set-Cookie',`managed_session=${session}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200`);return json(200,{ok:true});
   }
   if(path==='/api/logout'&&req.method==='POST'){
    if(Object.keys(await body()).length)throw Error('Unexpected fields');if(cookie)sessions.delete(cookie);
    res.setHeader('Set-Cookie','managed_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');return json(200,{ok:true});
   }
   if(path==='/api/snapshot'&&req.method==='GET')return json(200,await engine.snapshot());
   if(path==='/api/workflows'&&req.method==='POST'){
    const data=await body();return json(201,await engine.serial(()=>engine.create(data)));
   }
   const action=path.match(/^\/api\/workflows\/([a-f0-9-]+)\/(pause|resume|run)$/);
   if(action&&req.method==='POST'){
    if(Object.keys(await body()).length)throw Error('Unexpected action fields');
    return json(200,await engine.serial(()=>engine.action(action[1],action[2])));
   }
   if(assets.has(path)&&req.method==='GET'){
    const asset=assets.get(path);res.writeHead(200,{'Content-Type':asset.type+'; charset=utf-8'});return res.end(asset.body);
   }
   return json(404,{error:'Not found'});
  }catch(e){if(!res.writableEnded)json(e.status||400,{error:e instanceof SyntaxError?'Invalid JSON':e.message});}
 });
 server.requestTimeout=20000;server.headersTimeout=15000;
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve);});
 return server;
}
