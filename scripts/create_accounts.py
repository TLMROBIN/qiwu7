#!/usr/bin/env python3
"""Generate new temporary credentials from private incident sources, never log passwords."""
import csv,importlib.util,json,pathlib,re,secrets,sys,time
root=pathlib.Path(sys.argv[1]);repo=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(repo))
spec=importlib.util.spec_from_file_location('server',repo/'qiwu7_server.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
source=(root/'qiwu7/index.html').read_text();rows=json.loads(re.search(r'const PINYIN_MAP=(\[.*?\n\]);',source,re.S)[1]);state=json.loads((root/'recovery/recovered-state.json').read_text());by={s['name']:s for s in state['master']['students']}
users={};credentials=[]
for role,name,account,sid in [('teacher','班主任','teacher','')]+[('personal',r[1],r[2].lower(),by[r[1]]['id']) for r in rows]:
 password=secrets.token_urlsafe(12)
 users[account]={'role':role,'name':name,'sid':sid,'version':1,'mustChange':True,'temporaryExpires':time.time()+7*86400,**m.hash_password(password)}
 credentials.append({'姓名':name,'账号':account,'临时密码':password,'入口':'教师端或班级一体机' if role=='teacher' else '学生个人端'})
f=root/'recovery/users.json';f.write_text(json.dumps({'users':users},ensure_ascii=False));f.chmod(0o600)
f=root/'新登录凭据-仅教师保管.csv'
with f.open('w',encoding='utf-8-sig',newline='') as out:
 w=csv.DictWriter(out,fieldnames=['姓名','账号','临时密码','入口']);w.writeheader();w.writerows(credentials)
f.chmod(0o600)
print('Created',len(users),'accounts with salted password hashes; private credential CSV saved.')
