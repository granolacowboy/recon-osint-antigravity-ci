#!/usr/bin/env python3
import json, pathlib, subprocess, urllib.parse
from datetime import datetime, timezone

USER='granolacowboy'
DATE='2025-05-24'
EXPECTED_STARS=2664
OUT=pathlib.Path('repo-garden-output')
OUT.mkdir(exist_ok=True)

def api(endpoint, paginate=False):
    cmd=['gh','api']
    if paginate: cmd.append('--paginate')
    cmd.append(endpoint)
    p=subprocess.run(cmd,check=True,text=True,capture_output=True)
    s=p.stdout.strip()
    if not s: return None
    if not paginate: return json.loads(s)
    dec=json.JSONDecoder(); pos=0; vals=[]
    while pos < len(s):
        while pos < len(s) and s[pos].isspace(): pos+=1
        if pos>=len(s): break
        v,pos=dec.raw_decode(s,pos); vals.append(v)
    return [x for v in vals for x in v] if vals and all(isinstance(v,list) for v in vals) else vals

def search_all(q):
    rows=[]; page=1
    while True:
        ep='/search/repositories?'+urllib.parse.urlencode({'q':q,'per_page':100,'page':page})
        obj=api(ep); items=obj.get('items',[]); rows.extend(items)
        if len(rows)>=int(obj.get('total_count',len(rows))) or not items: break
        page+=1
    return rows

def iso(s): return datetime.fromisoformat(s.replace('Z','+00:00'))

def fast(meta):
    return bool(meta.get('fork') and meta.get('parent') and not meta.get('disabled') and not meta.get('has_pages') and not meta.get('has_discussions') and int(meta.get('open_issues_count') or 0)==0 and meta.get('created_at') and meta.get('pushed_at') and iso(meta['pushed_at']) <= iso(meta['created_at']))

def analyze(summary,star_ids):
    name=summary['full_name']; row={'repo_id':int(summary['id']),'full_name':name,'fork':True,'current_disposition':'DEFER'}
    try: meta=api('/repos/'+name)
    except subprocess.CalledProcessError:
        row.update(safety_status='DEFER',unique_state=True,reason='OWNED_REPO_METADATA_ERROR'); return row
    parent=meta.get('parent'); source=meta.get('source')
    if not parent:
        row.update(safety_status='DEFER',unique_state=True,reason='ORPHAN_OR_INACCESSIBLE_PARENT'); return row
    canonical=source or parent
    row.update(parent_repo_id=int(parent['id']),parent_full_name=parent['full_name'],source_repo_id=int(canonical['id']),source_full_name=canonical['full_name'],canonical_repo_id=int(canonical['id']),canonical_full_name=canonical['full_name'],canonical_starred=int(canonical['id']) in star_ids,created_at=meta.get('created_at'),pushed_at=meta.get('pushed_at'),has_pages=bool(meta.get('has_pages')),open_issues_count=int(meta.get('open_issues_count') or 0),has_discussions=bool(meta.get('has_discussions')))
    if fast(meta):
        row.update(safety_status='PASS_METADATA_FAST_PATH',unique_state=False,reason='NO_POST_FORK_PUSH_AND_NO_ACCOUNT_SIDE_ACTIVITY_SIGNALS',confidence=.985)
    else:
        branch=meta['default_branch']; pbranch=parent.get('default_branch') or branch
        try:
            comp=api(f"/repos/{parent['full_name']}/compare/{urllib.parse.quote(pbranch,safe='')}...{urllib.parse.quote(USER+':'+branch,safe=':')}")
            refs=api('/repos/'+name+'/git/refs'); refnames=[r['ref'] for r in refs]
            extra=[r for r in refnames if r!=f'refs/heads/{branch}']; ahead=int(comp.get('ahead_by',0))
            if ahead>0: row.update(safety_status='DEFER',unique_state=True,reason='UNIQUE_DEFAULT_BRANCH_COMMITS',ahead_by=ahead,extra_refs=extra,confidence=.7)
            elif extra: row.update(safety_status='DEFER',unique_state=True,reason='EXTRA_BRANCH_OR_TAG_REFS',ahead_by=0,extra_refs=extra,confidence=.7)
            else: row.update(safety_status='PASS_LEVEL1',unique_state=False,ahead_by=0,behind_by=int(comp.get('behind_by',0)),extra_refs=[],confidence=.995)
        except subprocess.CalledProcessError:
            row.update(safety_status='DEFER',unique_state=True,reason='LEVEL1_COMPARE_ERROR',confidence=.4)
    row['recommended_disposition']='DELETE_REDUNDANT_FORK' if row.get('safety_status','').startswith('PASS') and row.get('canonical_starred') and not row.get('unique_state') else 'DEFER'
    return row

def write_jsonl(path,rows):
    with open(path,'w',encoding='utf-8') as f:
        for r in rows: f.write(json.dumps(r,sort_keys=True,separators=(',',':'))+'\n')

stars=api(f'/users/{USER}/starred?per_page=100',paginate=True)
starrows=[{'repo_id':int(x['id']),'full_name':x['full_name']} for x in stars]; starids={x['repo_id'] for x in starrows}
q=f'user:{USER} fork:only created:{DATE} pushed:<2025-05-25'
candidates=search_all(q)
rows=[]
for i,x in enumerate(candidates,1):
    rows.append(analyze(x,starids))
    if i%25==0: print(f'{i}/{len(candidates)}')
safe_starred=[r for r in rows if r.get('recommended_disposition')=='DELETE_REDUNDANT_FORK']
safe_nonstarred=[r for r in rows if r.get('safety_status','').startswith('PASS') and not r.get('canonical_starred')]
anom=[r for r in rows if not r.get('safety_status','').startswith('PASS')]
write_jsonl(OUT/'live_stars.jsonl',starrows); write_jsonl(OUT/'level0.jsonl',rows); write_jsonl(OUT/'redundant_starred.jsonl',safe_starred); write_jsonl(OUT/'nonstarred_review.jsonl',safe_nonstarred); write_jsonl(OUT/'anomalies.jsonl',anom)
summary={'generated_at':datetime.now(timezone.utc).isoformat(),'live_stars':len(starrows),'expected_stars':EXPECTED_STARS,'star_set_complete':len(starrows)==EXPECTED_STARS,'level0_candidates':len(rows),'safe_starred':len(safe_starred),'safe_nonstarred':len(safe_nonstarred),'anomalies':len(anom)}
(OUT/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
print(json.dumps(summary,indent=2))
