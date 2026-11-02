import glob,json,os,subprocess,sys,time
base=os.path.dirname(os.path.abspath(__file__)); R=base+'/repo'; OUT=base+'/out'
os.makedirs(OUT,exist_ok=True)
def used():
    t=0
    for f in glob.glob(base+'/out*/**/*.jsonl',recursive=True):
        if f.endswith('events.jsonl'):continue
        seen={}
        for l in open(f):
            try:e=json.loads(l)
            except: continue
            if e.get('type')=='assistant':
                m=e['message'];seen[m.get('id')]=m.get('usage') or {}
        t+=sum(u.get('cache_read_input_tokens',0) for u in seen.values())
    return t
for n,arm in [(int(x.split(':')[0]),x.split(':')[1]) for x in sys.argv[1:]]:
    u=used(); print('before set',n,arm,'cache_read',u,flush=True)
    if u>36_000_000: print('CEILING STOP',flush=True); break
    env=dict(os.environ,LEAD_SET=str(n),LEAD_ARM=arm,LEAD_OUT=OUT,LEAD_MODE='run')
    r=subprocess.run(['python3','experiment/run_set.py','--bin',base+'/target/release'],cwd=R,env=env,capture_output=True,text=True)
    open(f'{OUT}/set{n}.log','w').write(r.stdout+r.stderr)
    print(n,arm,'rc',r.returncode,[l for l in r.stdout.splitlines() if l.startswith(('FAIL','lead_comparison'))],flush=True)
    panes=''.join(open(f).read() for f in glob.glob(f'{OUT}/set{n}/*.pane.txt'))
    if any(s in panes.lower() for s in ('usage limit','rate limit','limit reached',"you've hit")):
        print('RATE LIMIT STOP',flush=True); break
    if r.returncode: print('HARNESS STOP',flush=True); break
print('done cache_read',used(),flush=True)
