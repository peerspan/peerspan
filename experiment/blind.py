import json,glob,random,re,os,subprocess,tempfile
base=os.getcwd()
TASKS={"T1":"What Retry-After value does POST /orders send when it is throttled?","T2":"What is the vacuum window for warehouse-7?","T3":"What is the latest time on Friday we can begin a full invoice-archive restore and still have it finished before the code freeze?","T4":"Plan: on Tuesday we ship the gallery thumbnail change, which makes POST /image-resize use a width of 640. Question: is 640 within the largest width that endpoint allows?"}
RUB="""Scoring. Only the agent messages below count.
T1 answer: an agent says 37. T2 answer: an agent says Sunday and 02:40. T3 answer: an agent gives 05:00 (5 am) as the latest start. T4 answer: an agent gives 1024 as the largest width. T4 blocker: an agent says the Tuesday ship is blocked or must wait, mentioning Thursday, Wednesday or the CDN.
For a hedged or contradicted statement, answer false and set ambiguous true.
Useless post: a message that states no fact from the agent's own notes and no answer or conclusion new to the conversation, such as saying it doesn't have the information, that someone else should answer, or repeating or confirming what is already there.
"""
items=[];key={}
for root,label in (('../cmp/out','run1'),('out','run2')):
    for d in sorted(glob.glob(root+'/set*/')):
        n=re.search(r'set(\d+)',d).group(1)
        for T in TASKS:
            ms=[m for m in json.load(open(f'{d}{T}.messages.json')) if m.get('author_kind')=='agent']
            items.append((n,T,[{'i':j,'author':m['author_label'],'text':m['content']} for j,m in enumerate(ms)]))
random.seed(20261102);random.shuffle(items)
payload=[]
for k,(n,T,ms) in enumerate(items):
    key[f'c{k}']=(n,T);payload.append({'id':f'c{k}','task':T,'question':TASKS[T],'messages':ms})
prompt=RUB+"\nReturn only JSON: a list with, per conversation, {\"id\",\"answer\":bool,\"blocker\":bool or null (T4 only),\"ambiguous\":bool,\"useless\":[indexes of useless posts]}. Conversations:\n"+json.dumps(payload)
json.dump(key,open('blind_key.json','w'));open('blind_prompt.txt','w').write(prompt)
with tempfile.TemporaryDirectory() as t:
    r=subprocess.run(['claude','-p','--model','claude-sonnet-5-5','--no-session-persistence','--setting-sources','','--tools','','--output-format','json'],input=prompt,cwd=t,capture_output=True,text=True,timeout=500)
open('blind_raw.json','w').write(r.stdout);print(r.returncode,r.stderr[:300])
o=json.loads(r.stdout);print(o.get('usage'),o.get('total_cost_usd'))
t=o['result'];L=json.loads(t[t.index('['):t.rindex(']')+1]);json.dump(L,open('blind_scores.json','w'),indent=0);print(len(L))
