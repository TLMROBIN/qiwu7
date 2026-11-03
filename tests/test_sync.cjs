const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(require('node:path').join(__dirname,'../index.html'),'utf8');
const code=source.slice(source.indexOf('var secureReady='),source.indexOf('function load(){',source.indexOf('var secureReady=')));
const clone=x=>JSON.parse(JSON.stringify(x));
const response=records=>({ok:true,status:200,json:async()=>({rev:2,slots:{authoritative:{payload:{master:{ts:2,settings:{deviceName:''},students:[]},shared:{records:clone(records),attendance:{},tomb:{}}}}}})});
function setup(){
 const store=new Map();const ctx={console,JSON,Map,Set,LS_KEY:'test',cloudRev:1,cloudBusy:false,cloudPushTimer:null,cloudTimer:null,currentRole:'teacher',state:{settings:{deviceName:''},students:[],records:[],attendance:{},tomb:{},syncMeta:{}},window:{__QIWU7_BOOT__:{epoch:'test',csrf:'test',account:'teacher'}},location:{origin:'http://test'},document:{querySelector:()=>null},localStorage:{setItem:(k,v)=>store.set(k,v),getItem:k=>store.get(k)||null,removeItem:k=>store.delete(k)},setTimeout:()=>1,clearTimeout:()=>{},setInterval:()=>1,clearInterval:()=>{},cloudSet:()=>{},toast:()=>{},render:()=>{}};
 ctx.buildPayload=()=>({role:ctx.currentRole,exportedAt:Date.now()+Math.random(),shared:{records:clone(ctx.state.records),attendance:clone(ctx.state.attendance),tomb:clone(ctx.state.tomb)},master:{ts:Date.now()+Math.random(),students:clone(ctx.state.students),settings:clone(ctx.state.settings)}});
 vm.createContext(ctx);vm.runInContext(code,ctx);ctx.secureReady=true;ctx.secureBase=ctx.secureSnapshot();return ctx;
}
(async()=>{
 const a=setup();assert.equal(JSON.stringify(a.secureSnapshot()),JSON.stringify(a.secureSnapshot()),'export timestamps must not create phantom edits');
 let release;const gate=new Promise(resolve=>release=resolve);a.fetch=async()=>{await gate;return response([{id:'remote'}]);};
 const pull=a.cloudPull(true);a.state.records.push({id:'local-during-pull'});a.secureDirty=true;release();await pull;
 assert.deepEqual(clone(a.state.records).map(x=>x.id),['remote','local-during-pull'],'edits during a pull must survive');
 const b=setup();b.state.records.push({id:'first'});b.secureDirty=true;let confirmStarted,releaseConfirm;const started=new Promise(r=>confirmStarted=r),confirmGate=new Promise(r=>releaseConfirm=r);
 b.fetch=async(url,options)=>{if(options&&options.method==='POST')return {ok:true,status:200,json:async()=>({ok:true,rev:2})};confirmStarted();await confirmGate;return response([{id:'first'}]);};
 const push=b.cloudPush(0);await started;b.state.records.push({id:'second-during-confirmation'});releaseConfirm();await push;
 assert.deepEqual(clone(b.state.records).map(x=>x.id),['first','second-during-confirmation']);assert.equal(b.secureDirty,true,'new edits must remain queued after the first save');
 console.log('3 sync regression checks passed: stable snapshots; edits during pull; edits during save confirmation.');
})().catch(e=>{console.error(e);process.exitCode=1;});
