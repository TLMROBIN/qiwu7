const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../index.html'),'utf8');
assert(!source.includes('EMBEDDED_EXAMS'));
assert(!source.includes('BASELINE_DATA'));
assert(source.includes('const PINYIN_MAP=[];'));
const start=source.indexOf('function viewScoreTeacherOrClubUI(){'),end=source.indexOf('function bindScore(){',start);
const ctx={state:{settings:{baseScore:5},groupCount:0,students:[]},currentWeekKey:()=> 'audit-week',weekCN:x=>x,isClassroom:()=>false,weekRecords:()=>ctx.rows,studentById:()=>null,esc:x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),ROOM_SCORE_NAMES:[]};
vm.createContext(ctx);vm.runInContext(source.slice(start,end),ctx);
const row={id:'id',studentId:'s1',type:'bonus',amount:1,cat:'作业',reason:'x',weekKey:'audit-week'};
ctx.rows=[{...row,batchId:'__proto__'}];
assert.doesNotThrow(()=>ctx.viewScoreTeacherOrClubUI(),'legacy reserved strings must not break rendering');
ctx.rows=[{...row,id:'"><b id="audit-id">x</b>',batchId:'"><b id="audit-batch">x</b>',timeStr:'<b id="audit-time">x</b>'}];
const html=ctx.viewScoreTeacherOrClubUI();
assert(!html.includes('<b id="audit-'),'legacy values must be escaped');
assert(html.includes('&lt;b'),'escaped text should remain readable');
console.log('5 frontend security checks passed: no embedded exams/baseline/accounts; reserved batch values; escaped attributes.');

const navSource=source.slice(source.indexOf('function visibleTabs(){'),source.indexOf('function showPortal(){'));
const nav={TABS:[{id:'rules',label:'rules'},{id:'score',label:'score'},{id:'attend',label:'attend'}],role:'personal',authorized:false,
  isTeacher:()=>nav.role==='teacher',isClassroom:()=>nav.role==='classroom',isPersonal:()=>nav.role==='personal',hasPerm:()=>nav.authorized};
vm.createContext(nav);vm.runInContext(navSource,nav);
assert(!nav.visibleTabs().some(t=>t.id==='score'),'ordinary students must not see score registration');
nav.authorized=true;
assert.equal(nav.visibleTabs().find(t=>t.id==='score').label,'积分登记','authorized personal accounts must have a usable registration entry');
nav.role='classroom';assert.equal(nav.visibleTabs().find(t=>t.id==='score').label,'积分展示');
nav.role='teacher';assert.equal(nav.visibleTabs().length,nav.TABS.length);
console.log('4 navigation checks passed: ordinary student, authorized personal account, classroom, teacher.');
