#!/usr/bin/env python3
"""Offline recovery; originals are never modified. Output contains private student data."""
import argparse, copy, datetime, json, pathlib

def recover(source):
    data=json.loads(pathlib.Path(source).read_text())
    slots=data['slots']; baseline=slots['mvdb9b263vdes']['payload']
    assert len(baseline['master']['students'])==47
    master=copy.deepcopy(baseline['master']); master['settings']['cloud']={'on':True,'url':'','token':''}
    cutoff=int(datetime.datetime(2026,10,28,18,30,tzinfo=datetime.timezone(datetime.timedelta(hours=8))).timestamp()*1000)
    arrays=['records','attendanceRemarks','studentFeedbacks','prizes','prizeOrders','nominations','praises','studyLog']
    tombs={'tomb':'records','prizeTomb':'prizes','orderTomb':'prizeOrders','praiseTomb':'praises'}
    shared={k:{} for k in ['attendance','attTomb',*tombs]}; items={k:{} for k in arrays}
    pending={}; conflicts=[]
    for dev,slot in sorted(slots.items(),key=lambda kv:kv[1]['ts']):
        sh=slot.get('payload',{}).get('shared',{})
        for key in arrays:
            for item in sh.get(key,[]):
                if not isinstance(item,dict) or not item.get('id'):continue
                old=items[key].get(item['id'])
                if old and old!=item:conflicts.append({'field':key,'id':item['id'],'device':dev,'decision':'latest preserved slot; inspect original evidence if needed'})
                items[key][item['id']]=copy.deepcopy(item)
        for date,day in sh.get('attendance',{}).items():
            for session,entries in day.items():
                target=shared['attendance'].setdefault(date,{}).setdefault(session,{})
                for sid,value in entries.items():
                    old=target.get(sid)
                    if not old or value.get('ts',0)>=old.get('ts',0):target[sid]=copy.deepcopy(value)
        for key in [*tombs,'attTomb']:
            for rid,ts in sh.get(key,{}).items():
                if not isinstance(ts,(float,int)):continue
                if ts>=cutoff:
                    pending.setdefault(key,{})[rid]=max(ts,pending.get(key,{}).get(rid,0))
                else:shared[key][rid]=max(ts,shared[key].get(rid,0))
    # Uncertain deleted scoring records are quarantined, never counted automatically.
    quarantined=[]
    for rid in pending.get('tomb',{}):
        if rid in items['records']:
            quarantined.append(items['records'].pop(rid))
            shared['tomb'][rid]=pending['tomb'][rid]
    for key in arrays:
        deleted=next((t for t,k in tombs.items() if k==key),None)
        shared[key]=[v for rid,v in items[key].items() if not deleted or rid not in shared[deleted]]
    for key in shared['attTomb']:
        parts=key.split('|')
        if len(parts)==3:shared['attendance'].get(parts[0],{}).get(parts[1],{}).pop(parts[2],None)
    # Keep historical restores of non-scoring content, but preserve suspect deletes in review file.
    now=int(datetime.datetime.now().timestamp()*1000)
    master['ts']=now;master['rulesUpdatedAt']=now
    assert not any('HACKER' in s['name'].upper() for s in master['students'])
    assert len(master['rulesBlocks'])==63
    state={'format':2,'epoch':'incident-20261028-v2','rev':data['rev']+1000,'ts':now,'master':master,'shared':shared}
    review={'source_rev':data['rev'],'master_baseline':'mvdb9b263vdes, 2026-10-25','suspect_deletions':pending,'quarantined_scoring_records':quarantined,'variant_records':conflicts,'counts':{k:len(v) for k,v in shared.items()}}
    return state,review
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('source');p.add_argument('output');a=p.parse_args()
    state,review=recover(a.source);out=pathlib.Path(a.output);out.mkdir(parents=True,exist_ok=True)
    for name,obj in [('recovered-state.json',state),('recovery-review.json',review)]:
        f=out/name;f.write_text(json.dumps(obj,ensure_ascii=False,indent=2));f.chmod(0o600)
    print(json.dumps({'students':len(state['master']['students']),'exams':len(state['master']['exams']),'rules':len(state['master']['rulesBlocks']),'shared':review['counts'],'quarantined_records':len(review['quarantined_scoring_records'])},ensure_ascii=False))
