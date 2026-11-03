#!/usr/bin/env python3
"""Qiwu7 authenticated sync server, standard library only.
Private state and password hashes live outside the web root. No legacy token API.
"""
import copy
import datetime as dt
import hashlib
import hmac
import json
import math
import os
import re
from pathlib import Path
import secrets
import shutil
import ssl
import sys
import threading
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from qiwu7_security import Denied, ZONE, date_now, identifier, number, read_view, reverse_delta, schema, scoring_key, text

BASE = Path(__file__).resolve().parent
PRIVATE = Path(os.environ.get('QIWU7_PRIVATE_DIR', str(BASE.parent / 'qiwu7_private')))
PORT = int(sys.argv[1]) if __name__=='__main__' and len(sys.argv)>1 else int(os.environ.get('QIWU7_PORT','18090'))
LOCK = threading.RLock()
SESSIONS = {}
ATTEMPTS = {}
WRITES = {}
AUTH_WORKERS = threading.BoundedSemaphore(4)
TLS_CERT = os.environ.get('QIWU7_TLS_CERT', '')
TLS_KEY = os.environ.get('QIWU7_TLS_KEY', '')
TRUST_PROXY = os.environ.get('QIWU7_TRUST_LOOPBACK_PROXY') == '1'
REQUIRE_TLS = os.environ.get('QIWU7_REQUIRE_TLS') == '1'
MAX_STATE = 32*1024*1024
MAX_ARCHIVE = int(os.environ.get('QIWU7_ARCHIVE_MB', '256'))*1024*1024
MAX_AUDIT = 32*1024*1024
MAX_BODY = 16*1024*1024
COOKIE = 'qiwu7_session_v3'
ARRAYS = ['records','attendanceRemarks','studentFeedbacks','prizes','prizeOrders','nominations','praises','studyLog']
TOMBS = {'tomb':'records','prizeTomb':'prizes','orderTomb':'prizeOrders','praiseTomb':'praises'}


def now():return int(time.time()*1000)
def encode(obj):return json.dumps(obj,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
def load_json(name):return json.loads((PRIVATE/name).read_text())
def atomic(name,obj):
    path=PRIVATE/name;tmp=path.with_suffix(path.suffix+'.tmp')
    with open(tmp,'wb') as f:
        os.chmod(tmp,0o600);f.write(encode(obj));f.flush();os.fsync(f.fileno())
    os.replace(tmp,path)
def audit(event,**fields):
    with LOCK:
        path=PRIVATE/'audit.jsonl'
        if path.exists() and path.stat().st_size>=MAX_AUDIT:return
        with open(PRIVATE/'audit.jsonl','ab') as f:f.write(encode({'ts':now(),'event':event,**fields})+b'\n')
def hash_password(password,salt=None):
    salt=salt or secrets.token_hex(16)
    return {'salt':salt,'hash':hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),260000).hex()}
def valid_password(password,user):
    digest=hash_password(password,user['salt'])['hash']
    return hmac.compare_digest(digest,user['hash'])
def public_identity(s):return {k:s.get(k,'') for k in ['role','sid','name','account','mustChange']}

class Conflict(Exception):pass
class Capacity(Exception):pass
class Limited(Exception):pass

def throttle(account, limit=20, window=60):
    stamp=time.time();key=(account,window)
    entries=[t for t in WRITES.get(key,[]) if stamp-t<window]
    if len(entries)>=limit:raise Limited('操作过于频繁，请稍后再试')
    WRITES[key]=entries+[stamp]

def commit(candidate,s,ip):
    """Full periodic snapshots plus per-write reverse deltas; never delete old evidence."""
    global CURRENT
    if candidate==CURRENT:return
    candidate['rev']=CURRENT['rev']+1;candidate['ts']=now()
    encoded=encode(candidate)
    if len(encoded)>MAX_STATE:raise Capacity('数据容量已达上限，请联系老师归档；暂未保存')
    backup=PRIVATE/'backups';backup.mkdir(mode=0o700,exist_ok=True)
    snapshots=list(backup.glob('state-*.json'))
    last=max((p.stat().st_mtime for p in snapshots),default=0)
    delta=encode(reverse_delta(CURRENT,candidate))
    snapshot=encode(CURRENT) if time.time()-last>=600 else None
    size=sum(p.stat().st_size for p in backup.iterdir() if p.is_file())
    if size+len(delta)+(len(snapshot) if snapshot else 0)>MAX_ARCHIVE or shutil.disk_usage(PRIVATE).free<len(encoded)*2+32*1024*1024:
        raise Capacity('存储空间不足，已暂停写入，请联系老师归档备份')
    log=PRIVATE/'audit.jsonl'
    if log.exists() and log.stat().st_size>=MAX_AUDIT:raise Capacity('审计空间已满，已暂停写入，请联系老师归档')
    old_hash=hashlib.sha256(encode(CURRENT)).hexdigest()
    for prefix,content in [('delta',delta),('state',snapshot)]:
        if content is None:continue
        path=backup/('%s-%s-%s.json'%(prefix,CURRENT['rev'],now()))
        with open(path,'xb') as f:
            os.chmod(path,0o600);f.write(content);f.flush();os.fsync(f.fileno())
    changed=[k for k in ['master','shared'] if candidate[k]!=CURRENT[k]]
    atomic('state.json',candidate);CURRENT=candidate
    audit('sync',account=s['account'],role=s['role'],sid=s.get('sid'),ip=ip,rev=CURRENT['rev'],changed=changed,before=old_hash,after=hashlib.sha256(encoded).hexdigest())

class BoundedServer(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,*args,**kwargs):
        self.slots=threading.BoundedSemaphore(40)
        super().__init__(*args,**kwargs)
    def get_request(self):
        conn,addr=super().get_request();conn.settimeout(10)
        if getattr(self,'tls_context',None):
            conn=self.tls_context.wrap_socket(conn,server_side=True,do_handshake_on_connect=False)
        return conn,addr
    def process_request(self,request,client_address):
        if not self.slots.acquire(blocking=False):self.shutdown_request(request);return
        try:super().process_request(request,client_address)
        except BaseException:self.slots.release();raise
    def process_request_thread(self,*args):
        try:super().process_request_thread(*args)
        finally:self.slots.release()

def check_json(value,depth=0):
    if depth>24:raise Denied('数据嵌套过深')
    if isinstance(value,dict):
        if len(value)>30000:raise Denied('数据过多')
        for key,item in value.items():
            if not isinstance(key,str) or key in ['__proto__','constructor','prototype']:raise Denied('非法字段')
            check_json(item,depth+1)
    elif isinstance(value,list):
        if len(value)>30000:raise Denied('数据过多')
        for item in value:check_json(item,depth+1)
    elif isinstance(value,str):
        if len(value)>500000:raise Denied('文本过长')
    elif isinstance(value,float) and not math.isfinite(value):raise Denied('数值无效')

def permissions(master,s):
    stu=next((x for x in master['students'] if x['id']==s.get('sid')),None)
    if not stu:raise Denied('学生不在当前名单')
    role=stu.get('role','');name=stu['name']
    full=name in ['张喆祎','黎科麟','周雨轩'] or '班长' in role or '学习委员' in role
    return stu,{'full':full,'homework':full or '课代表' in role or '组长' in role,'answer':full or '课代表' in role or '组长' in role,'health':name=='张涵' or '卫生委员' in role}

def validate_student_item(key,item,s,master,perm,stu):
    sid=s['sid'];name=stu['name'];ids={x['id'] for x in master['students']}
    if key=='records':
        amount=item.get('amount');cat=item.get('cat');kind=item.get('type')
        if item.get('studentId') not in ids or kind not in ['bonus','deduct'] or not isinstance(amount,(int,float)) or isinstance(amount,bool) or not 0<amount<=20:raise Denied('积分记录无效')
        allowed=perm['full'] or (cat=='作业' and kind=='bonus' and amount==1 and perm['homework']) or (cat=='回答问题' and kind=='bonus' and amount in [1,3] and perm['answer']) or (cat=='班级卫生' and kind=='deduct' and perm['health'])
        if not allowed:raise Denied('没有登记此类积分的权限')
        item['operator']=name;item['source']='personal';item['actorSid']=sid
    elif key=='studentFeedbacks':
        text(item.get('text'),2000,True)
        if item.get('name')!=name or item.get('read'):raise Denied('只能提交本人的未读反馈')
        item['sid']=sid;item['studentId']=sid;item['read']=False;item['source']='personal'
    elif key=='attendanceRemarks':
        if item.get('studentId')!=sid or item.get('status')!='pending':raise Denied('只能提交本人的待审核考勤说明')
        text(item.get('text'),2000,True)
        if item.get('date')!=date_now().isoformat() or item.get('session') not in [x['id'] for x in master.get('settings',{}).get('sessions',[])]:raise Denied('考勤说明日期或时段无效')
    elif key=='studyLog':
        raise Denied('学习时长由服务器计时，请使用开始、暂停和结束按钮')
    elif key=='prizeOrders':
        prize=next((p for p in CURRENT['shared'].get('prizes',[]) if p.get('id')==item.get('prizeId')),None)
        if item.get('sid')!=sid or item.get('name')!=name or item.get('status')!='pending' or not prize or prize.get('active') is False or item.get('cost')!=prize.get('cost') or item.get('statusTs',0)!=0:raise Denied('兑换申请无效')
        number(item['cost'],0.01)
        item['prizeName']=prize.get('name','')
    elif key=='nominations':
        amount=item.get('amount')
        if item.get('sid')!=sid or item.get('name')!=name or item.get('status')!='pending' or item.get('recordId') or item.get('approvedAmount') is not None or item.get('statusTs',0)!=0 or type(amount) not in (int,float) or not 1<=amount<=5:raise Denied('加分申请无效')
        text(item.get('what'),2000,True);text(item.get('why'),2000,True)
    elif key=='praises':
        if item.get('fromSid')!=sid or item.get('fromName')!=name or item.get('fromRole')!='personal' or item.get('toSid') not in ids:raise Denied('表扬署名无效')
        text(item.get('reason'),2000,True)
        item['toName']=next(x['name'] for x in master['students'] if x['id']==item['toSid'])
    else:raise Denied('没有修改此类数据的权限')
    item['ts']=now();item['timeStr']=time.strftime('%Y-%m-%d %H:%M',time.gmtime(time.time()+8*3600))

def merge_shared(existing,incoming,s,master):
    if not isinstance(incoming,dict) or set(incoming)-set(existing):raise Denied('共享数据字段无效')
    visible=read_view({'master':master,'shared':existing},s)['shared']
    if s['role']=='classroom':
        if any(value!=visible.get(key) for key,value in incoming.items()):raise Denied('一体机为只读展示；登记请使用班干个人账号')
        return copy.deepcopy(existing)
    out=copy.deepcopy(existing);priv=s['role']=='teacher'
    stu,perm=permissions(master,s) if not priv else (None,None)
    added=0
    for key in ARRAYS:
        values=incoming.get(key,visible.get(key,[]))
        if not isinstance(values,list):raise Denied('列表格式无效')
        original={x['id']:x for x in existing.get(key,[])}
        projected={x['id']:x for x in visible.get(key,[])}
        target={} if priv else {x['id']:x for x in out.get(key,[])}
        for value in values:
            if not isinstance(value,dict) or not isinstance(value.get('id'),str) or not 1<=len(value['id'])<=100:raise Denied('记录编号无效')
            item=copy.deepcopy(value);rid=item['id'];old=original.get(rid)
            if old==item or (not priv and projected.get(rid)==item):
                if priv:target[rid]=item
                continue
            schema(key,item)
            if key=='records' and item.get('studentId') not in {x['id'] for x in master['students']}:raise Denied('积分学生无效')
            if not priv:
                if old:raise Denied('不能改写已经提交的记录')
                if key in TOMBS.values() and rid in existing.get(next(k for k,v in TOMBS.items() if v==key),{}):raise Denied('不能重新提交已撤销记录')
                validate_student_item(key,item,s,master,perm,stu)
                if key=='records':
                    item['eventKey']=scoring_key(item,s['sid'])
                    if any(x.get('eventKey')==item['eventKey'] for x in target.values()):raise Denied('同一登记事项不能重复加扣分')
                added+=1
                if added>1000:raise Denied('单次提交记录过多')
                if key!='records':
                    today=date_now().isoformat()
                    count=sum(1 for x in target.values() if x.get('timeStr','').startswith(today) and (x.get('sid')==s['sid'] or x.get('studentId')==s['sid'] or x.get('fromSid')==s['sid']))
                    if count>=50:raise Limited('今日此类提交已达上限，请联系老师')
            target[rid]=item
        out[key]=list(target.values())
    for key,field in TOMBS.items():
        values=incoming.get(key,{})
        if not isinstance(values,dict):raise Denied('删除标记无效')
        for rid,ts in values.items():
            if visible.get(key,{}).get(rid)==ts:continue
            if not isinstance(ts,(float,int)) or isinstance(ts,bool):raise Denied('删除时间无效')
            if not priv:
                obj=next((x for x in out[field] if x['id']==rid),None)
                if key=='orderTomb':allowed=obj and obj.get('sid')==s['sid'] and obj.get('status')=='pending'
                elif key=='tomb':allowed=obj and obj.get('actorSid')==s['sid'] and obj.get('ts',0)>=s['created']*1000
                else:allowed=False
                if not allowed:raise Denied('没有撤销此记录的权限')
            out.setdefault(key,{})[rid]=now()
        out[field]=[x for x in out[field] if x['id'] not in out.get(key,{})]
    att=incoming.get('attendance',{})
    if not isinstance(att,dict):raise Denied('考勤格式无效')
    for date,day in att.items():
        if not isinstance(day,dict):raise Denied('考勤格式无效')
        for sess,entries in day.items():
            if not isinstance(entries,dict):raise Denied('考勤格式无效')
            target=out.setdefault('attendance',{}).setdefault(date,{}).setdefault(sess,{})
            for sid,value in entries.items():
                if not isinstance(value,dict):raise Denied('考勤记录无效')
                if value==target.get(sid):continue
                if not priv:
                    today=time.strftime('%Y-%m-%d',time.gmtime(time.time()+8*3600))
                    session=next((x for x in master.get('settings',{}).get('sessions',[]) if x.get('id')==sess),None)
                    if sid!=s['sid'] or date!=today or not session:raise Denied('只能登记本人今天的到班记录')
                    arrival=time.strftime('%H:%M',time.gmtime(time.time()+8*3600))
                    value={'time':arrival,'status':'ok' if arrival<=session.get('deadline','00:00') else 'late','ts':now()}
                target[sid]=value
    ats=incoming.get('attTomb',{})
    if not isinstance(ats,dict):raise Denied('考勤删除标记无效')
    if not priv and ats!=visible.get('attTomb',{}):raise Denied('没有删除考勤的权限')
    if priv:
        for key,ts in ats.items():
            if out.get('attTomb',{}).get(key)!=ts:out.setdefault('attTomb',{})[key]=now()
        for key in out.get('attTomb',{}):
            parts=key.split('|')
            if len(parts)==3:out.get('attendance',{}).get(parts[0],{}).get(parts[1],{}).pop(parts[2],None)
    return out

def study_public(s):
    if s['role']!='personal':return None
    active=STUDY.get(s.get('sid'))
    if not active:return None
    return {k:active[k] for k in ['id','mode','startTs','accMs','pausedAt']}

def study_action(obj,s,ip):
    if s['role']!='personal':raise Denied('仅个人端可计时')
    permissions(CURRENT['master'],s)
    sid=s['sid'];active=copy.deepcopy(STUDY.get(sid));stamp=now();action=obj.get('action')
    if action not in ['start','pause','resume','stop']:raise Denied('计时操作无效')
    if action=='start':
        if active:return study_public(s)
        mode=obj.get('mode','free')
        if mode not in ['free','pomo']:raise Denied('计时模式无效')
        active={'id':secrets.token_hex(16),'mode':mode,'startTs':stamp,'accMs':0,'pausedAt':0,'segments':[]}
    else:
        if not active:
            if action=='stop':return None  # Retried completion cannot create another row.
            raise Denied('计时已结束，请重新开始')
        if obj.get('id')!=active['id']:raise Denied('计时已变化，请刷新页面')
        if action in ['pause','stop'] and not active['pausedAt']:
            # A server timer establishes elapsed wall time, not proof of attention.
            end=min(stamp,active['startTs']+24*3600*1000)
            active['segments'].append([active['startTs'],end]);active['accMs']+=end-active['startTs'];active['pausedAt']=stamp
        if action=='resume' and active['pausedAt']:
            active['startTs']=stamp;active['pausedAt']=0
        if len(active['segments'])>200:raise Denied('分段过多，请结束本段后重新开始')
        if action=='stop':
            daily={}
            for start,end in active['segments']:
                while start<end:
                    day=dt.datetime.fromtimestamp(start/1000,ZONE).date()
                    midnight=int(dt.datetime.combine(day+dt.timedelta(days=1),dt.time(),ZONE).timestamp()*1000)
                    edge=min(midnight,end);key=day.isoformat()
                    row=daily.setdefault(key,{'start':start,'end':edge,'ms':0});row['end']=edge;row['ms']+=edge-start;start=edge
            candidate=copy.deepcopy(CURRENT)
            rows=candidate['shared']['studyLog'];ids={x['id'] for x in rows}
            for date,segment in daily.items():
                rid=active['id']+'_'+date
                if rid in ids:continue
                duration=segment['ms']//60000
                used=sum(x.get('dur',0) for x in rows if x.get('sid')==sid and x.get('date')==date)
                duration=min(duration,max(0,1440-used))
                if not duration:continue
                rows.append({'id':rid,'sid':sid,'date':date,'startTs':segment['start'],'endTs':segment['end'],
                             'dur':duration,'mode':active['mode'],'ts':stamp,'verified':'server-elapsed'})
            commit(candidate,s,ip)
            # If persisting runtime fails, retry sees the same IDs and cannot double count.
            updated=copy.deepcopy(STUDY);updated.pop(sid,None);atomic('study.json',updated);STUDY.clear();STUDY.update(updated)
            return None
    updated=copy.deepcopy(STUDY);updated[sid]=active;atomic('study.json',updated);STUDY.clear();STUDY.update(updated)
    return study_public(s)

LOGIN_HTML='''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>栖梧7班 · 安全登录</title><style>body{font:16px system-ui;background:#f2f5f8;margin:0;padding:8vh 20px}main{max-width:380px;margin:auto;background:white;padding:28px;border-radius:18px}input,select,button{box-sizing:border-box;width:100%;padding:12px;margin:8px 0;border:1px solid #bfc9d4;border-radius:8px;font:inherit}button{background:#2359b8;color:white}#msg{color:#b3261e}</style><main><h2>栖梧7班 · 登录</h2><p>系统已完成安全升级，请使用老师发放的新密码。班级一体机由老师授权登录。</p><form id="f"><label>入口<select id="role"><option value="personal">学生个人端</option><option value="teacher">教师端</option><option value="classroom">班级一体机（教师授权）</option></select></label><label>账号<input id="u" autocomplete="username" required></label><label>密码<input id="p" type="password" autocomplete="current-password" required></label><button>登录</button></form><p id="msg" role="alert"></p></main><script>document.getElementById('f').onsubmit=async e=>{e.preventDefault();const msg=document.getElementById('msg');msg.textContent='正在登录…';try{const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({role:document.getElementById('role').value,account:document.getElementById('u').value,password:document.getElementById('p').value})});const d=await r.json();if(!r.ok)throw Error(d.error||'登录失败');location.replace(d.mustChange?'/account':'/')}catch(e){msg.textContent=e.message}};</script></html>'''
ACCOUNT_HTML='''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>修改密码</title><style>body{font:16px system-ui;max-width:420px;margin:8vh auto;padding:20px}input,button{width:100%;box-sizing:border-box;padding:12px;margin:10px 0;font:inherit}#msg{color:#b3261e}</style><h2>设置新密码</h2><p>首次登录请更换临时密码。新密码至少 12 位，请勿使用身份证信息。</p><form id="f"><input id="old" type="password" placeholder="当前密码" autocomplete="current-password" required><input id="new" type="password" placeholder="新密码（至少12位）" minlength="12" autocomplete="new-password" required><input id="confirm" type="password" placeholder="再次输入新密码" autocomplete="new-password" required><button>保存并进入系统</button></form><p id="msg" role="alert"></p><script>__BOOT__
document.getElementById('f').onsubmit=async e=>{e.preventDefault();const msg=document.getElementById('msg');try{const p=document.getElementById('new').value;if(p!==document.getElementById('confirm').value)throw Error('两次新密码不一致');const r=await fetch('/api/auth/password',{method:'POST',headers:{'Content-Type':'application/json','X-Qiwu7-CSRF':window.__QIWU7_BOOT__.csrf},body:JSON.stringify({current:document.getElementById('old').value,password:p})});const d=await r.json();if(!r.ok)throw Error(d.error||'保存失败');location.replace('/')}catch(e){msg.textContent=e.message}};</script></html>'''

class Handler(BaseHTTPRequestHandler):
    server_version='Qiwu7/3'
    def log_message(self,*args):pass  # Never log URLs, passwords or cookies.
    def encrypted(self):
        return isinstance(self.connection,ssl.SSLSocket) or (TRUST_PROXY and self.client_address[0] in ['127.0.0.1','::1'] and self.headers.get('X-Forwarded-Proto')=='https')
    def transport_allowed(self):
        host=urlsplit('//'+self.headers.get('Host','')).hostname
        return self.encrypted() or (self.client_address[0] in ['127.0.0.1','::1'] and host in ['localhost','127.0.0.1','::1'])
    def require_transport(self):
        if not REQUIRE_TLS or self.transport_allowed():return True
        self.send({'ok':False,'error':'为保护密码和班级数据，请使用受信任的 HTTPS 入口'},426)
        return False
    def headers_common(self):
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'nonce-%s'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self' data:; media-src 'self' blob:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'" % getattr(self,'_nonce','none'))
        if self.encrypted():self.send_header('Strict-Transport-Security','max-age=31536000')
    def send(self,body,code=200,ctype='application/json; charset=utf-8',extra=None):
        if not isinstance(body,bytes):body=encode(body)
        self.send_response(code);self.headers_common();self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(body)))
        for key,value in (extra or {}).items():self.send_header(key,value)
        self.end_headers();self.wfile.write(body)
    def html(self,body,code=200):
        self._nonce=secrets.token_urlsafe(24)
        body=body.replace('<script>','<script nonce="'+self._nonce+'">')
        self.send(body.encode(),code,'text/html; charset=utf-8')
    def body(self,limit=MAX_BODY):
        if self.headers.get('Transfer-Encoding'):raise Denied('不支持分块请求')
        if self.headers.get('Content-Type','').split(';')[0]!='application/json':raise Denied('仅接受 JSON 请求')
        try:length=int(self.headers.get('Content-Length','0'))
        except ValueError:raise Denied('请求长度无效')
        if not 0<length<=limit:raise Denied('请求长度无效')
        obj=json.loads(self.rfile.read(length));check_json(obj)
        if not isinstance(obj,dict):raise Denied('请求格式无效')
        return obj
    def session(self):
        try:
            jar=cookies.SimpleCookie();jar.load(self.headers.get('Cookie',''));token=jar[COOKIE].value
        except (KeyError,cookies.CookieError):return None
        with LOCK:
            s=SESSIONS.get(token)
            if not s or s['expires']<time.time():SESSIONS.pop(token,None);return None
            # Password rotation revokes other sessions even if a stale cookie survives.
            user=USERS['users'].get(s['account'])
            if not user or s['version']!=user.get('version',1):return None
            return s
    def same_origin(self):
        origin=self.headers.get('Origin')
        host=self.headers.get('Host','')
        return bool(origin and origin in ['http://'+host,'https://'+host] and host in ALLOWED_HOSTS)
    def boot(self,s,include_state=False):
        boot={**public_identity(s),'csrf':s['csrf'],'epoch':CURRENT['epoch']}
        if include_state:boot.update({'rev':CURRENT['rev'],'initial':read_view(CURRENT,s),'study':study_public(s)})
        return 'window.__QIWU7_BOOT__='+encode(boot).decode().replace('<','\\u003c')+';'
    def do_GET(self):
        path=urlsplit(self.path).path
        if self.headers.get('Host','') not in ALLOWED_HOSTS:return self.send({'ok':False},403)
        s=self.session()
        if path=='/api/ping':return self.send({'ok':True,'name':'qiwu7','securityVersion':3})
        if not self.require_transport():return
        if path in ['/','/index.html','/login']:
            if not s:return self.html(LOGIN_HTML)
            if s['mustChange']:return self.send(b'',303,extra={'Location':'/account'})
            with LOCK:
                html=(BASE/'index.html').read_text();html=html.replace('<head>','<head><script>'+self.boot(s,True)+'</script>',1)
            return self.html(html)
        if path=='/account':
            if not s:return self.send(b'',303,extra={'Location':'/'})
            return self.html(ACCOUNT_HTML.replace('__BOOT__',self.boot(s)))
        if path=='/api/auth/session':
            if not s:return self.send({'ok':False,'error':'请重新登录'},401)
            return self.send({'ok':True,**public_identity(s),'csrf':s['csrf'],'epoch':CURRENT['epoch']})
        if path=='/api/study':
            if not s or s['mustChange'] or s['role']!='personal':return self.send({'ok':False},403)
            with LOCK:result={'ok':True,'study':study_public(s)}
            return self.send(result)
        if path in ['/api/sync','/api/backup']:
            if not s:return self.send({'ok':False,'error':'请刷新页面并使用新密码登录'},401)
            if s['mustChange']:return self.send({'ok':False,'error':'请先修改临时密码'},403)
            if path=='/api/backup':
                if s['role']!='teacher':return self.send({'ok':False,'error':'仅教师可备份'},403)
                with LOCK:result=encode(CURRENT)
                return self.send(result,extra={'Content-Disposition':'attachment; filename="qiwu7-backup.json"'})
            with LOCK:
                payload={'app':'qiwu7-sync','ver':28,**read_view(CURRENT,s)}
                result={'ok':True,'rev':CURRENT['rev'],'ts':CURRENT['ts'],'epoch':CURRENT['epoch'],'slots':{'authoritative':{'rev':CURRENT['rev'],'ts':CURRENT['ts'],'payload':payload}},'slotsRev':{'authoritative':CURRENT['rev']},'count':1}
            return self.send(result)
        return self.send({'ok':False,'error':'not found'},404)
    def do_OPTIONS(self):self.send({'ok':False},405)
    def do_POST(self):
        global CURRENT
        path=urlsplit(self.path).path
        if self.headers.get('Host','') not in ALLOWED_HOSTS or not self.same_origin():return self.send({'ok':False,'error':'请求来源不被允许'},403)
        if not self.require_transport():return
        try:
            if path=='/api/auth/login':return self.login(self.body(4096))
            s=self.session()
            if not s:return self.send({'ok':False,'error':'请刷新页面并登录'},401)
            if not hmac.compare_digest(str(self.headers.get('X-Qiwu7-CSRF','')),s['csrf']):raise Denied('请刷新页面后重试')
            obj=self.body()
            if path=='/api/auth/logout':
                with LOCK:
                    for token,value in list(SESSIONS.items()):
                        if value is s:del SESSIONS[token]
                return self.send({'ok':True},extra={'Clear-Site-Data':'"cache", "cookies", "storage"','Set-Cookie':COOKIE+'=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'+('; Secure' if self.encrypted() else '')})
            if path=='/api/auth/password':return self.password(obj,s)
            if s['mustChange']:raise Denied('请先修改临时密码')
            if path=='/api/study':
                with LOCK:
                    throttle(s['account'],30)
                    result=study_action(obj,s,self.client_address[0])
                return self.send({'ok':True,'study':result,'rev':CURRENT['rev']})
            if path!='/api/sync':return self.send({'ok':False},404)
            with LOCK:
                throttle(s['account'],60 if s['role']=='teacher' else 20)
                if obj.get('epoch')!=CURRENT['epoch']:raise Denied('旧版数据已停用，请刷新页面重新登录')
                if obj.get('baseRev')!=CURRENT['rev']:raise Conflict()
                payload=obj.get('payload')
                if not isinstance(payload,dict):raise Denied('同步格式无效')
                if payload.get('role')!=s['role']:raise Denied('会话角色与提交角色不一致')
                candidate=copy.deepcopy(CURRENT)
                if 'master' in payload:
                    if s['role']!='teacher':raise Denied('仅教师可以修改名单、条例和成绩')
                    m=copy.deepcopy(payload['master'])
                    if not isinstance(m,dict) or set(m)!=set(CURRENT['master']):raise Denied('教师数据字段无效')
                    if not isinstance(m.get('students'),list) or not 1<=len(m['students'])<=200:raise Denied('名单格式无效')
                    ids=[]
                    for student in m['students']:
                        if not isinstance(student,dict) or not isinstance(student.get('id'),str) or not isinstance(student.get('name'),str) or not 1<=len(student['name'])<=40:raise Denied('学生信息无效')
                        identifier(student['id'])
                        ids.append(student['id'])
                    if len(set(ids))!=len(ids):raise Denied('学生编号重复')
                    if not isinstance(m.get('settings'),dict) or not isinstance(m.get('exams'),list) or not isinstance(m.get('rulesBlocks'),list):raise Denied('教师数据格式无效')
                    m['settings']['cloud']={'on':True,'url':'','token':''}
                    m['ts']=CURRENT['master']['ts']
                    if (m.get('rulesBlocks'),m.get('rulesContent'))!=(CURRENT['master'].get('rulesBlocks'),CURRENT['master'].get('rulesContent')):m['rulesUpdatedAt']=now()
                    else:m['rulesUpdatedAt']=CURRENT['master']['rulesUpdatedAt']
                    if m!=CURRENT['master']:m['ts']=now()
                    candidate['master']=m
                candidate['shared']=merge_shared(CURRENT['shared'],payload.get('shared',{}),s,candidate['master'])
                commit(candidate,s,self.client_address[0])
                result={'ok':True,'rev':CURRENT['rev'],'ts':CURRENT['ts'],'slotRev':CURRENT['rev']}
            return self.send(result)
        except Conflict:return self.send({'ok':False,'conflict':True,'rev':CURRENT['rev'],'error':'有新数据，请合并后重试'},409)
        except Limited as e:return self.send({'ok':False,'error':str(e)},429)
        except Capacity as e:return self.send({'ok':False,'error':str(e)},507)
        except (Denied,ValueError,TypeError,KeyError) as e:
            audit('rejected',path=path,ip=self.client_address[0],reason=str(e)[:160])
            return self.send({'ok':False,'error':str(e)[:160]},403 if isinstance(e,Denied) else 400)
        except Exception as e:
            audit('server_error',path=path,error=type(e).__name__)
            return self.send({'ok':False,'error':'服务器处理失败，数据未确认保存，请联系老师'},500)
    def login(self,obj):
        account=str(obj.get('account','')).strip().lower();role=obj.get('role');password=obj.get('password','')
        if not 1<=len(account)<=64 or role not in ['teacher','classroom','personal'] or not isinstance(password,str) or len(password)>256:raise Denied('账号或密码错误')
        ip=self.client_address[0];key=(ip,account);stamp=time.time()
        with LOCK:
            for attempt_key,entries in list(ATTEMPTS.items()):
                live=[x for x in entries if stamp-x<900]
                if live:ATTEMPTS[attempt_key]=live
                else:ATTEMPTS.pop(attempt_key,None)
            if len(ATTEMPTS)>10000:raise Limited('请求过于频繁，请稍后重试')
            times=ATTEMPTS.setdefault(key,[])
            ip_count=sum(len(v) for (source,_),v in ATTEMPTS.items() if source==ip)
            account_count=sum(len(v) for (_,name),v in ATTEMPTS.items() if name==account)
            if len(times)>=8 or ip_count>=80 or account_count>=40:raise Limited('尝试过于频繁，请15分钟后重试')
            times.append(stamp)  # Reserve before expensive work, including concurrent requests.
            user=copy.deepcopy(USERS['users'].get(account))
        correct_role=user and ((role in ['teacher','classroom'] and user['role']=='teacher') or (role=='personal' and user['role']=='personal'))
        if not AUTH_WORKERS.acquire(blocking=False):raise Limited('登录繁忙，请稍后重试')
        try:
            correct=bool(correct_role and valid_password(password,user))
        finally:AUTH_WORKERS.release()
        with LOCK:
            if not correct or user!=USERS['users'].get(account) or user.get('temporaryExpires',float('inf'))<stamp:
                audit('login_failed',account=account,ip=ip)
                return self.send({'ok':False,'error':'账号或密码错误，或临时密码已过期'},401)
            for k,v in list(SESSIONS.items()):
                if v['expires']<time.time():del SESSIONS[k]
            if len(SESSIONS)>=1000 or sum(v['account']==account for v in SESSIONS.values())>=10:raise Limited('会话过多，请先退出其他设备')
            token=secrets.token_urlsafe(32);s={'account':account,'role':role,'sid':user.get('sid',''),'name':user.get('name',''),'csrf':secrets.token_urlsafe(24),'created':time.time(),'expires':time.time()+12*3600,'version':user.get('version',1),'mustChange':user.get('mustChange',False)}
            SESSIONS[token]=s;audit('login',account=account,role=role,ip=ip)
            header=COOKIE+'='+token+'; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200'+('; Secure' if self.encrypted() else '')
            return self.send({'ok':True,**public_identity(s)},extra={'Set-Cookie':header})
    def password(self,obj,s):
        password=obj.get('password','');current=obj.get('current','')
        if not isinstance(password,str) or not 12<=len(password)<=128:raise Denied('新密码需要12—128位')
        with LOCK:
            throttle(s['account']+':password',5,900)
            user=copy.deepcopy(USERS['users'][s['account']])
        if not isinstance(current,str) or len(current)>256:raise Denied('当前密码错误')
        if not AUTH_WORKERS.acquire(blocking=False):raise Limited('认证繁忙，请稍后重试')
        try:
            if not valid_password(current,user):raise Denied('当前密码错误')
            if password==current:raise Denied('新密码不能与原密码相同')
            rotated=hash_password(password)
        finally:AUTH_WORKERS.release()
        with LOCK:
            if user!=USERS['users'][s['account']]:raise Denied('密码已变化，请重新登录')
            user.update(rotated);user['version']=user.get('version',1)+1;user['mustChange']=False;user.pop('temporaryExpires',None)
            updated=copy.deepcopy(USERS);updated['users'][s['account']]=user
            atomic('users.json',updated);USERS.clear();USERS.update(updated);s['version']=user['version'];s['mustChange']=False
            audit('password_changed',account=s['account'],ip=self.client_address[0])
            return self.send({'ok':True})

def main():
    global CURRENT,USERS,ALLOWED_HOSTS,STUDY
    os.umask(0o077);PRIVATE.mkdir(mode=0o700,parents=True,exist_ok=True)
    CURRENT=load_json('state.json');USERS=load_json('users.json')
    STUDY=load_json('study.json') if (PRIVATE/'study.json').exists() else {}
    if CURRENT.get('format')!=2:raise SystemExit('Refusing legacy unauthenticated storage')
    ALLOWED_HOSTS=set(os.environ.get('QIWU7_ALLOWED_HOSTS','10.50.159.62:18090,localhost:%s,127.0.0.1:%s'%(PORT,PORT)).split(','))
    bind=os.environ.get('QIWU7_BIND','0.0.0.0')
    if REQUIRE_TLS and bind not in ['127.0.0.1','::1'] and not (TLS_CERT and TLS_KEY):raise SystemExit('TLS-required listener requires QIWU7_TLS_CERT and QIWU7_TLS_KEY')
    if TRUST_PROXY and bind not in ['127.0.0.1','::1']:raise SystemExit('Trusted proxy requires loopback binding')
    server=BoundedServer((bind,PORT),Handler)
    if TLS_CERT and TLS_KEY:
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(TLS_CERT,TLS_KEY);server.tls_context=context
    audit('started',securityVersion=3,epoch=CURRENT['epoch'],rev=CURRENT['rev'],tls=bool(TLS_CERT))
    print('Qiwu7 security v3 listening on port %s; TLS=%s'%(PORT,bool(TLS_CERT)),flush=True)
    server.serve_forever()
if __name__=='__main__':main()
