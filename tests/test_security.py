import copy, http.cookiejar, importlib.util, json, os, pathlib, socket, subprocess, tempfile, time, unittest, urllib.request, urllib.error
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('qiwu7',ROOT/'qiwu7_server.py');server=importlib.util.module_from_spec(spec);spec.loader.exec_module(server)

class SecurityTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();cls.private=pathlib.Path(cls.tmp.name)
  s=socket.socket();s.bind(('127.0.0.1',0));cls.port=s.getsockname()[1];s.close();cls.origin='http://127.0.0.1:'+str(cls.port)
  master={'ts':1,'students':[{'id':'s1','name':'普通学生','role':'组员','group':1},{'id':'s2','name':'课代表','role':'物理课代表','group':1}],'groupCount':1,'settings':{'cloud':{'on':True,'url':'','token':''},'sessions':[{'id':'morning','deadline':'07:15'}]},'exams':[],'rulesBlocks':[],'rulesContent':'','rulesUpdatedAt':1}
  master.update({k:{} for k in ['positionPoints','weeklyNotes','weekly','reportComments','growthEdits','pushedGrowth','pushedReport','pushedGrowthTomb','pushedReportTomb']})
  shared={k:[] for k in server.ARRAYS};shared.update({k:{} for k in ['attendance','attTomb',*server.TOMBS]})
  state={'format':2,'epoch':'test-epoch','rev':1,'ts':1,'master':master,'shared':shared}
  cls.initial=state
  (cls.private/'state.json').write_text(json.dumps(state))
  users={}
  for account,role,sid,name in [('teacher','teacher','','老师'),('student','personal','s1','普通学生'),('representative','personal','s2','课代表')]:
   users[account]={'role':role,'sid':sid,'name':name,'version':1,'mustChange':False,**server.hash_password('test-password-123')}
  (cls.private/'users.json').write_text(json.dumps({'users':users}))
  env={**os.environ,'QIWU7_PRIVATE_DIR':str(cls.private),'QIWU7_BIND':'127.0.0.1'}
  cls.proc=subprocess.Popen(['python3',str(ROOT/'qiwu7_server.py'),str(cls.port)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  for _ in range(100):
   try:urllib.request.urlopen(cls.origin+'/api/ping',timeout=.2);break
   except Exception:time.sleep(.03)
  else:raise RuntimeError('server did not start')
 @classmethod
 def tearDownClass(cls):cls.proc.terminate();cls.proc.wait(timeout=5);cls.tmp.cleanup()
 def request(self,path,obj=None,opener=None,csrf=None,origin=True):
  headers={}
  if obj is not None:
   headers={'Content-Type':'application/json'}
   if origin:headers['Origin']=self.origin
   if csrf:headers['X-Qiwu7-CSRF']=csrf
  req=urllib.request.Request(self.origin+path,data=json.dumps(obj).encode() if obj is not None else None,headers=headers)
  try:r=(opener or urllib.request.build_opener()).open(req);status=r.status;body=r.read()
  except urllib.error.HTTPError as e:status=e.code;body=e.read()
  try:return status,json.loads(body)
  except Exception:return status,body.decode()
 def login(self,account='teacher',role='teacher'):
  jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
  status,data=self.request('/api/auth/login',{'account':account,'password':'test-password-123','role':role},opener)
  self.assertEqual(status,200);status,data=self.request('/api/auth/session',opener=opener);self.assertEqual(status,200)
  return opener,data['csrf']
 def payload(self,opener,role):
  _,d=self.request('/api/sync',opener=opener);p=d['slots']['authoritative']['payload'];p['role']=role
  if role!='teacher':p.pop('master')
  return {'epoch':d['epoch'],'baseRev':d['rev'],'payload':p}
 def test_anonymous_legacy_and_files(self):
  self.assertEqual(self.request('/api/sync?token=qiwu7')[0],401)
  self.assertEqual(self.request('/api/backup?token=qiwu7')[0],401)
  for path in ['/qiwu7.env','/qiwu7_data/data.json','/.git/HEAD','/qiwu7_server.py','/%2e%2e/qiwu7_private/users.json']:
   self.assertEqual(self.request(path)[0],404,path)
  _,html=self.request('/');self.assertNotIn('PINYIN_MAP',html);self.assertIn('安全升级',html)
 def test_teacher_persist_and_conflict(self):
  op,csrf=self.login();body=self.payload(op,'teacher');stale=copy.deepcopy(body)
  body['payload']['master']['rulesBlocks']=[{'type':'title','text':'恢复后规则'}]
  self.assertEqual(self.request('/api/sync',body,op,csrf)[0],200)
  self.assertEqual(self.request('/api/sync',stale,op,csrf)[0],409)
  _,d=self.request('/api/sync',opener=op);self.assertEqual(d['slots']['authoritative']['payload']['master']['rulesBlocks'][0]['text'],'恢复后规则')
  self.assertTrue(list((self.private/'backups').glob('*.json')))
 def test_origin_csrf_epoch_and_role(self):
  op,csrf=self.login();body=self.payload(op,'teacher')
  self.assertEqual(self.request('/api/sync',body,op)[0],403)
  self.assertEqual(self.request('/api/sync',body,op,csrf,origin=False)[0],403)
  body['epoch']='old';self.assertEqual(self.request('/api/sync',body,op,csrf)[0],403)
  body=self.payload(op,'teacher');body['payload']['role']='classroom';self.assertEqual(self.request('/api/sync',body,op,csrf)[0],403)
 def test_student_permissions_and_identity(self):
  op,csrf=self.login('student','personal');body=self.payload(op,'personal');body['payload']['master']=copy.deepcopy(self.initial['master'])
  self.assertEqual(self.request('/api/sync',body,op,csrf)[0],403)
  body=self.payload(op,'personal');body['payload']['shared']['records'].append({'id':'evil-score','studentId':'s1','type':'bonus','amount':20,'cat':'其他加分'})
  self.assertEqual(self.request('/api/sync',body,op,csrf)[0],403)
  body=self.payload(op,'personal');body['payload']['shared']['studentFeedbacks'].append({'id':'forged-feedback','name':'课代表','text':'x','read':False})
  self.assertEqual(self.request('/api/sync',body,op,csrf)[0],403)
  body=self.payload(op,'personal');body['payload']['shared']['studentFeedbacks'].append({'id':'own-feedback','name':'普通学生','text':'反馈测试','read':False})
  self.assertEqual(self.request('/api/sync',body,op,csrf)[0],200)
  body=self.payload(op,'personal');body['payload']['shared']['nominations'].append({'id':'forged-approval','sid':'s1','name':'普通学生','status':'approved','amount':5,'recordId':'x'})
  self.assertEqual(self.request('/api/sync',body,op,csrf)[0],403)
 def test_personal_attendance_uses_server_time(self):
  op,csrf=self.login('student','personal');body=self.payload(op,'personal');date=time.strftime('%Y-%m-%d',time.gmtime(time.time()+8*3600))
  att=body['payload']['shared']['attendance'];att.setdefault(date,{}).setdefault('morning',{})['s1']={'time':'00:01','status':'ok','ts':1}
  self.assertEqual(self.request('/api/sync',body,op,csrf)[0],200)
  _,d=self.request('/api/sync',opener=op);record=d['slots']['authoritative']['payload']['shared']['attendance'][date]['morning']['s1'];self.assertNotEqual(record['time'],'00:01');self.assertGreater(record['ts'],1)
  body=self.payload(op,'personal');body['payload']['shared']['attendance'][date]['morning']['s2']={'time':'00:01','status':'ok','ts':1}
  self.assertEqual(self.request('/api/sync',body,op,csrf)[0],403)
 def test_representative_and_classroom_scope(self):
  op,csrf=self.login('representative','personal');body=self.payload(op,'personal');body['payload']['shared']['records'].append({'id':'homework-1','studentId':'s1','weekKey':server.date_now().strftime('%G-W%V'),'type':'bonus','amount':1,'cat':'作业','operator':'spoof'})
  self.assertEqual(self.request('/api/sync',body,op,csrf)[0],200)
  _,d=self.request('/api/sync',opener=op);r=next(x for x in d['slots']['authoritative']['payload']['shared']['records'] if x['id']=='homework-1');self.assertEqual(r['operator'],'课代表')
  op,csrf=self.login('teacher','classroom');body=self.payload(op,'classroom');body['payload']['master']=self.initial['master']
  self.assertEqual(self.request('/api/sync',body,op,csrf)[0],403)
  body=self.payload(op,'classroom');body['payload']['shared']['attendance']={'2026-10-28':{'morning':{'s1':{'time':'07:05','status':'present'}}}}
  self.assertEqual(self.request('/api/sync',body,op,csrf)[0],403)
 def test_password_revocation(self):
  # Create an account solely for rotation to avoid mutating other tests' fixture login.
  op1,csrf1=self.login();op2,csrf2=self.login()
  self.assertEqual(self.request('/api/auth/password',{'current':'test-password-123','password':'new-strong-password-456'},op1,csrf1)[0],200)
  self.assertEqual(self.request('/api/auth/session',opener=op2)[0],401)
  self.assertEqual(self.request('/api/auth/session',opener=op1)[0],200)
  self.assertEqual(self.request('/api/auth/password',{'current':'new-strong-password-456','password':'test-password-123'},op1,csrf1)[0],200)

if __name__=='__main__':unittest.main()
