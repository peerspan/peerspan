const $=s=>document.querySelector(s);
let current=null,timer;
const node=(tag,className,text)=>{const e=document.createElement(tag);if(className)e.className=className;if(text!==undefined)e.textContent=text;return e;};
const age=value=>{if(!value)return 'Not checked';const s=Math.max(0,Math.floor((Date.now()-Date.parse(value))/1000));return s<60?`${s}s ago`:s<3600?`${Math.floor(s/60)}m ago`:`${Math.floor(s/3600)}h ago`;};
const time=value=>value?new Date(value).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}):'—';
const badge=state=>node('span','badge '+state,String(state||'unknown').replaceAll('-',' '));
async function api(path,body){const r=await fetch(path,{...(body!==undefined?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}:{})});const data=await r.json();if(!r.ok){if(r.status===401){$('#login').hidden=false;$('#console').hidden=true;}throw Error(data.error||'Request failed');}return data;}
function notice(text){$('#notice').textContent=text;$('#notice').hidden=!text;}
function statistic(label,value){const e=node('div');e.append(node('span','',label),node('strong','',String(value)));return e;}
function workflowCard(w,observed){
 const run=current.runs.find(r=>r.workflowId===w.id&&['submitting','queued','running'].includes(r.state));
 const state=observed?w.phase:run?.state||(!w.enabled?'paused':w.blockedReason?.includes('limit')?'paused':'scheduled');
 const card=node('article','workflow-card'),body=node('div','card-body'),head=node('div','card-heading'),title=node('div');
 title.append(node('h3','',w.name),node('small','',observed?'EXTERNAL PROGRAM · READ ONLY':'MANAGED ASSIGNMENT'));
 head.append(node('div','workflow-icon',observed?'◈':'↻'),title,badge(state));body.append(head);
 body.append(node('p','card-description',observed?w.task?.lane||'An existing program, observed without changing its work.':w.instructions));
 const stats=node('div','card-stats');
 if(observed){stats.append(statistic('Current batch',w.cycle||'—'),statistic('Last complete',w.lastBatch?.key?.replace(/.*-0*/, '#')||'—'),statistic('Heartbeat',age(w.lastTickAt)));}
 else{stats.append(statistic('Repeat',`${w.intervalMinutes} min`),statistic('Daily limit',`${w.maxRunsPerDay} runs`),statistic('Next eligible',time(w.nextRunAt)));}
 body.append(stats);card.append(body);const foot=node('div','card-footer');
 foot.append(node('span','',observed?w.error||'Observed only · Managed by its original controller':w.blockedReason||'Ready for scheduling'));
 if(!observed){
  const toggle=node('button','',w.enabled?'Pause':'Resume');toggle.addEventListener('click',()=>action(w.id,w.enabled?'pause':'resume',toggle));
  const runNow=node('button','','Run next');runNow.disabled=!w.enabled||!!run;runNow.addEventListener('click',()=>action(w.id,'run',runNow));foot.append(toggle,runNow);
 }card.append(foot);return card;
}
function empty(title,description){const e=node('div','empty');e.append(node('strong','',title),node('p','',description));return e;}
function render(data){
 current=data;$('#login').hidden=true;$('#console').hidden=false;
 const running=data.workflows.filter(w=>w.enabled).length+data.observed.filter(w=>w.enabled&&w.available).length;
 $('#m-active').textContent=running;$('#m-workers').textContent=data.connections.filter(c=>c.readiness.ready).length;
 $('#m-complete').textContent=data.runs.filter(r=>r.state==='succeeded').length;
 $('#m-attention').textContent=data.connections.filter(c=>!c.readiness.ready).length+data.observed.filter(s=>!s.available||s.error).length+data.workflows.filter(w=>w.failureStreak>=3).length;
 $('#nav-count').textContent=data.workflows.length+data.observed.length;
 $('#refresh-state').textContent='Updated just now';notice(data.meta.error||'');
 const grid=$('#workflow-grid');grid.replaceChildren(...data.workflows.map(w=>workflowCard(w,false)),...data.observed.map(w=>workflowCard(w,true)));
 if(!grid.children.length)grid.append(empty('Create your first recurring assignment','Connect an existing Peerspan worker, then set a schedule and a daily dispatch limit. Your task history will be retained here.'));
 $('#run-count').textContent=data.runs.length+' runs';const runs=$('#runs');runs.replaceChildren();
 for(const r of data.runs){
  const row=node('div','run-row'),button=node('button');
  button.append(node('strong','',data.workflows.find(w=>w.id===r.workflowId)?.name||'Workflow'),node('small','',`${age(r.createdAt)} · ${r.taskId.slice(0,17)}…`));
  button.addEventListener('click',()=>{$('#result-meta').textContent=`${r.state} · ${r.taskId}`;$('#result-output').textContent=r.output||r.error||'No result has been reported yet. A task state is not independent verification of its output.';$('#result-dialog').showModal();});
  row.append(button,badge(r.state));runs.append(row);
 }
 if(!data.runs.length)runs.append(empty('No managed runs yet','External programs keep their own run history. New assignments dispatched from this console will appear here with their actual results.'));
 const workers=$('#worker-list');workers.replaceChildren();
 for(const c of data.connections){const row=node('div','worker-row'),text=node('div');text.append(node('strong','',c.name),node('small','',c.readiness.reason));row.append(node('span','status-dot'+(c.readiness.ready?'':' offline')),text);workers.append(row);}
 if(!data.connections.length)workers.append(empty('Connect a dedicated worker','Register a prepared Peerspan attachment with the connect command in managed/README.md. Existing observed programs stay independent.'));
 const select=$('#connection'),selected=select.value;select.replaceChildren(...data.connections.map(c=>{const o=node('option','',c.name+(c.readiness.ready?'':' · waiting for readiness'));o.value=c.id;return o;}));if(selected)select.value=selected;
 $('#open-create').disabled=!data.connections.length;$('#open-create').title=data.connections.length?'Create a recurring assignment':'Connect a worker from the CLI first';
}
async function refresh(){try{render(await api('/api/snapshot'));}catch(e){if(!$('#console').hidden){notice(e.message);$('#refresh-state').textContent='Connection interrupted';}}}
async function action(id,name,button){button.disabled=true;try{await api(`/api/workflows/${id}/${name}`,{});await refresh();}catch(e){notice(e.message);button.disabled=false;}}
$('#login-form').addEventListener('submit',async e=>{e.preventDefault();$('#login-error').textContent='';try{await api('/api/login',{token:$('#token').value.trim()});$('#token').value='';await refresh();}catch(e){$('#login-error').textContent=e.message;}});
$('#logout').addEventListener('click',async()=>{try{await api('/api/logout',{});$('#console').hidden=true;$('#login').hidden=false;}catch(e){notice(e.message);}});
$('#open-create').addEventListener('click',()=>{$('#create-error').textContent='';$('#create-dialog').showModal();});
$('#close-create').addEventListener('click',()=>$('#create-dialog').close());$('#close-result').addEventListener('click',()=>$('#result-dialog').close());
$('#workflow-form').addEventListener('submit',async e=>{e.preventDefault();const form=e.currentTarget,button=form.querySelector('button[type="submit"]');button.disabled=true;
 const data=Object.fromEntries(new FormData(form));for(const key of ['intervalMinutes','maxRunsPerDay','acceptanceMinutes'])data[key]=Number(data[key]);data.enabled=form.elements.enabled.checked;
 try{await api('/api/workflows',data);$('#create-dialog').close();form.reset();await refresh();}catch(e){$('#create-error').textContent=e.message;}finally{button.disabled=false;}
});
void refresh();timer=setInterval(refresh,5000);window.addEventListener('pagehide',()=>clearInterval(timer));
