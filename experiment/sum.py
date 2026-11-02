import json,statistics as st,re
A=json.load(open('../cmp/analysis.json'))+json.load(open('analysis.json'))
key=json.load(open('blind_key.json'));S={key[x['id']][0]+key[x['id']][1]:x for x in json.load(open('blind_scores.json'))}
def rng(v): return {'min':min(v),'max':max(v),'mean':round(st.mean(v),1)} if v else None
out={};dis=[]
useless={}
for r in A:
  for t in r['tasks']:
    b=S[str(r['set'])+t['task']]
    t['blind']=b
    if b['answer']!=t['scores']['answer']['pass']: dis.append((r['set'],r['arm'],t['task'],'answer',t['scores']['answer']['pass'],b['answer']))
    if t['task']=='T4' and b['blocker']!=t['scores']['blocker']['pass']: dis.append((r['set'],r['arm'],t['task'],'blocker',t['scores']['blocker']['pass'],b['blocker']))
    if b.get('ambiguous'): dis.append((r['set'],r['arm'],t['task'],'ambiguous'))
for arm in ('today','lead','quiet','route'):
  R=[r for r in A if r['arm']==arm]
  s={'sets':[r['set'] for r in R],'totals_excluding_launch':{}}
  for k in ('calls','cache_read','cache_write','input','output'):
    s['totals_excluding_launch'][k]=rng([r['total'][k]-r['launch'][k] for r in R])
  s['totals_excluding_launch']['message_wakes']=rng([sum(t['wakes_message'] for t in r['tasks']) for r in R])
  s['totals_excluding_launch']['agent_messages']=rng([sum(t['agent_messages'] for t in r['tasks']) for r in R])
  s['useless_posts_blind']=[sum(len(t['blind']['useless']) for t in r['tasks']) for r in R]
  s['launch_cache_read']=rng([r['launch']['cache_read'] for r in R])
  s['per_task']={}
  for T in ('T1','T2','T3','T4'):
    ts=[t for r in R for t in r['tasks'] if t['task']==T]
    d={k:rng([t[k] for t in ts]) for k in ('wakes_message','wakes_roster','parked_unclaimed','calls','cache_read','cache_write','input','output','agent_messages')}
    d['correct_of_3']=sum(t['scores']['answer']['pass'] for t in ts)
    d['blind_correct_of_3']=sum(t['blind']['answer'] for t in ts)
    sec=[t['scores']['answer']['seconds'] for t in ts if t['scores']['answer']['pass']]
    d['seconds_to_correct']=rng(sec)
    done=[t for t in ts if t['scores']['answer']['pass']]
    d['completed_only']={'tasks':len(done),'calls':rng([t['calls'] for t in done]),'cache_read':rng([t['cache_read'] for t in done])}
    if T=='T4':
      d['blocker_surfaced_of_3']=sum(t['scores']['blocker']['pass'] for t in ts)
      d['blind_blocker_of_3']=sum(bool(t['blind']['blocker']) for t in ts)
      d['release_addressed_of_3']=sum(any('bob/release' in (x[1] or []) for x in t['texts']) for t in ts)
    s['per_task'][T]=d
  out[arm]=s
json.dump(out,open('summary.json','w'),indent=1);json.dump(A,open('merged.json','w'))
for a,s in out.items():
  print(a,s['sets'],json.dumps({k:(v['min'],v['max'],v['mean']) for k,v in s['totals_excluding_launch'].items() if k in('calls','cache_read','message_wakes','agent_messages')}),'useless',s['useless_posts_blind'],'launch',s['launch_cache_read']['mean'])
  for T,d in s['per_task'].items(): print(' ',T,'ok',d['correct_of_3'],'blind',d['blind_correct_of_3'],d.get('blocker_surfaced_of_3'),d.get('blind_blocker_of_3'),'rel',d.get('release_addressed_of_3'),'wakes',d['wakes_message']['mean'],'calls',d['calls']['mean'],'cr',d['cache_read']['mean'],'done calls',d['completed_only']['calls'] and d['completed_only']['calls']['mean'],'done cr',d['completed_only']['cache_read'] and d['completed_only']['cache_read']['mean'],'sec',d['seconds_to_correct'])
print('DIS',dis)
for r in A:
  if r['arm'] in('quiet','route','today'):
    for t in r['tasks']:
      for i in t['blind']['useless']:
        x=[m for m in t['texts']][i] if i<len(t['texts']) else None
        if r['arm']!='today': print('U',r['set'],r['arm'],t['task'],x and x[0],x and x[2][:90].replace('\n',' '))
# route: named w/o addressing
for r in A:
  if r['arm']=='route':
    for t in r['tasks']:
      for a,to,x in t['texts']:
        for ag in ('bob/db','bob/release'):
          if a=='alice/api' and ag in x and ag not in (to or []): print('NAMED',r['set'],t['task'],ag,to,x[:120])
    print(r['set'],[ (t['task'],t['parked_unclaimed']) for t in r['tasks']])
