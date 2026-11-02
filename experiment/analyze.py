import json,glob,os,re,sys,datetime
base=os.path.dirname(os.path.abspath(__file__)); OUT=base+'/out'
RUB={'T1':[('answer',[r'\b37\b'])],'T2':[('answer',[r'sunday.*02:40|02:40.*sunday'])],'T3':[('answer',[r'05:00|\b5:00\b|\b5 ?am\b'])],'T4':[('answer',[r'1024']),('blocker',[r'thursday|cdn|wednesday'])]}
def ts(s): return datetime.datetime.fromisoformat(s.replace('Z','+00:00')).timestamp()
res=[]
for d in sorted(d for d in glob.glob(OUT+'/set*/') if os.path.exists(d+'bob.notifications.json')):
    n=int(re.search(r'set(\d+)',d).group(1))
    ev=[json.loads(l) for l in open(d+'events.jsonl')]
    arm=[e for e in ev if e['event']=='set_start'][-1]['arm']
    tasks={}
    for e in ev:
        if e['event']=='conversation': tasks[e['task']]={'conv':e['conv']}
        if e['event']=='said': tasks[e['task']]['t0']=e['at']
        if e['event']=='conversation': tasks[e['task']]['begin']=e['at']
        if e['event']=='task_end': tasks[e['task']].update(end=e['at'],seconds=e['seconds'],timed_out=e['timed_out'])
    launched=[e for e in ev if e['event']=='launched'][0]['at']
    calls=[]
    for f in glob.glob(d+'*.0.jsonl')+glob.glob(d+'*.1.jsonl'):
        name=os.path.basename(f).split('.')[0]; seen={}
        for l in open(f):
            e=json.loads(l)
            if e.get('type')=='assistant':
                m=e['message']; 
                if m.get('model','').startswith('<'):continue
                seen[m['id']]=(ts(e['timestamp']),m.get('usage') or {})
        for t,u in seen.values(): calls.append((t,name,u))
    def tot(cs):
        k={'calls':len(cs)}
        for a,b in (('input','input_tokens'),('cache_read','cache_read_input_tokens'),('cache_write','cache_creation_input_tokens'),('output','output_tokens')):
            k[a]=sum(c[2].get(b,0) for c in cs)
        return k
    ord_=sorted(tasks.items(),key=lambda x:x[1]['begin'])
    launch=[c for c in calls if c[0]<ord_[0][1]['begin']]
    rows=[]
    notes=[]
    for h in ('alice','bob'):
        notes+=json.load(open(d+h+'.notifications.json'))
    for i,(task,t) in enumerate(ord_):
        nxt=ord_[i+1][1]['begin'] if i+1<len(ord_) else 1e18
        cs=[c for c in calls if t['begin']<=c[0]<nxt]
        ms=json.load(open(d+task+'.messages.json'))
        ag=[m for m in ms if m.get('author_kind')=='agent' or str(m.get('author','')).startswith('agent:')]
        ns=[r for r in notes if r['conversation_id']==t['conv']]
        claimed=lambda k:sum(1 for r in ns if r['kind']==k and r['session_id'] is not None)
        scores={}
        for key,pats in RUB[task]:
            hit=None
            for m in ag:
                if all(re.search(p,m['content'],re.I|re.S) for p in pats):
                    hit=m;break
            when=None
            if hit:
                sent=ts(hit['sent_at'][:26]+'Z') if '.' in hit['sent_at'] else ts(hit['sent_at'])
                when=round(sent-t['t0'],1)
            scores[key]={'pass':bool(hit),'seconds':when,'by':(hit or {}).get('author_label')}
        per={}
        for c in cs: per[c[1]]=per.get(c[1],0)+1
        rows.append(dict(task=task,conv=t['conv'],**tot(cs),calls_by_agent=per,wakes_message=claimed('message'),wakes_roster=claimed('roster'),parked_unclaimed=sum(1 for r in ns if r['kind']=='message' and r['session_id'] is None),agent_messages=len(ag),task_seconds=t['seconds'],timed_out=t['timed_out'],scores=scores,addresses=[(m.get('author_label'),m.get('addressed_to_labels')) for m in ag],texts=[(m.get('author_label'),m.get('addressed_to_labels'),m['content'][:400]) for m in ag]))
    res.append(dict(set=n,arm=arm,launch=tot(launch),tasks=rows,total=tot(calls)))
json.dump(res,open(base+'/analysis.json','w'),indent=1)
for r in res:
    print('set',r['set'],r['arm'],'launch',r['launch']['calls'],r['launch']['cache_read'],'total',r['total']['calls'],r['total']['cache_read'])
    for t in r['tasks']:
        print(' ',t['task'],'wakes',t['wakes_message'],'+r',t['wakes_roster'],'parked',t['parked_unclaimed'],'calls',t['calls'],'cr',t['cache_read'],'cw',t['cache_write'],'in',t['input'],'out',t['output'],'msgs',t['agent_messages'],'sec',t['task_seconds'],'to' if t['timed_out'] else '',{k:(v['pass'],v['seconds'],v['by']) for k,v in t['scores'].items()})
