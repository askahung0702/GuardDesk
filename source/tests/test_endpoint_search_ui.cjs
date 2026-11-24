// Actual UI helpers and submit handler, with an owned DOM adapter; no HTTP/center.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const folder=path.join(__dirname,'../guarddesk/static');
(async()=>{
const app=fs.readFileSync(path.join(folder,'app.js'),'utf8');
const helper=app.slice(app.indexOf('// Endpoint search uses'),app.indexOf('// End endpoint search.'));
class Field{
 constructor(value=''){this.value=value;this.disabled=false;this.checked=false;this.type='text';this.listeners={};this.validationMessage='';this.reports=0;}
 addEventListener(type,fn){(this.listeners[type]??=[]).push(fn);}
 dispatchEvent(event){for(const fn of this.listeners[event.type]||[])fn(event);return true;}
 async fire(type){for(const fn of this.listeners[type]||[])await fn({type,target:this,currentTarget:this,preventDefault(){}});}
 setCustomValidity(value){this.validationMessage=value;}
 reportValidity(){this.reports++;return !this.validationMessage;}
}
class SearchBox{
 constructor(id='',text='',activeOnly=false,allowAll=false){
  this.dataset={activeOnly:String(activeOnly),allowAll:String(allowAll)};
  this.input=new Field(text);this.hidden=new Field(id);this.list={children:[],replaceChildren(...items){this.children=items;}};this.status={textContent:''};this.all=allowAll?new Field():null;
 }
 querySelector(s){return {'input[type=search]':this.input,'input[type=hidden]':this.hidden,datalist:this.list,'[data-endpoint-status]':this.status,'[data-endpoint-all]':this.all}[s]||null;}
}
class Root{
 constructor(box){this.box=box;this.hidden=true;}
 querySelectorAll(s){return s==='[data-endpoint-search]'?[this.box]:s==='input'?[this.box.input,this.box.hidden]:[];}
}
const devices=[{id:'a1',name:'LAB-01',inventory:{agent_version:'0.4.113'}},{id:'p1',name:'LAB-02'},{id:'r1',name:'Retired',revoked:true},
 {id:'d1',name:'Duplicate'},{id:'d2',name:'Duplicate'},{id:'x1',name:'<img src=x onerror=bad()>',department:'IT'}];
const apiCalls=[],messages=[];let refreshes=0,dispatchHTML='';
const dispatchButtons={'#update-dispatch-confirm':new Field(),'#update-dispatch-ready':new Field(),'#dialog':{close(){}}};
const previewReply={preview_id:'preview-fixture',version:'0.4.117',not_before:100,expires:200,allow_downgrade:false,
 targets:[{device_id:'p1',name:'LAB-02',state:'ready',reason:'可安排更新'},{device_id:'x1',name:'<test>',state:'waiting',reason:'等候端點上線'}]};
const document={createElement:()=>({}),querySelector:()=>null,querySelectorAll:()=>[]};
const ctx=vm.createContext({document,Event:class{constructor(type,options){this.type=type;Object.assign(this,options);}},state:{devices,groups:[{id:'g1',path:['IT']}]},
 console,URLSearchParams,Date,date:String,dialog:(title,html)=>dispatchHTML=html,
 toast:m=>messages.push(m),api:async(url,body)=>{apiCalls.push({url,body});return url.endsWith('/preview')?previewReply:{job_ids:['j1'],scheduled:1,reserved:0,skipped:1};},refresh:async()=>refreshes++});
vm.runInContext(app.split('\n').find(s=>s.startsWith('const esc =')),ctx);
vm.runInContext(helper,ctx);
const clean=value=>JSON.parse(JSON.stringify(value));
let tests=0;
function test(name,fn){fn();tests++;console.log('PASS '+name);}
function bind(box){ctx.root=new Root(box);ctx.bindEndpointSearches(ctx.root);return box;}
async function type(box,value){box.input.value=value;await box.input.fire('input');}
test('catalog discriminates identical names and keeps revoked history for audit',()=>{
 const entries=ctx.endpointSearchEntries(devices);assert.equal(ctx.resolveEndpointSearch(entries,'  lab-01  ',true),'a1');
 assert.equal(ctx.resolveEndpointSearch(entries,'Duplicate',true),null);
 assert.equal(ctx.resolveEndpointSearch(entries,'Duplicate [d2]',true),'d2');
 assert.equal(ctx.resolveEndpointSearch(entries,'r1',true),'r1');
 assert.equal(ctx.resolveEndpointSearch(ctx.endpointSearchEntries(devices,true),'r1'),null);
 assert.equal(ctx.resolveEndpointSearch(entries,'LAB',true),null);
});
test('suggestions remain bounded for a large catalog and empty search',()=>{
 const entries=ctx.endpointSearchEntries(Array.from({length:10000},(_,i)=>({id:String(i),name:'PC-'+i})));
 assert.equal(ctx.endpointSearchMatches(entries,'PC').length,20);assert.equal(ctx.endpointSearchMatches(entries,'').length,0);
 assert.equal(ctx.resolveEndpointSearch(entries,'PC-9999'),'9999');
});
test('render escapes endpoint display and IDs in existing HTML boundary',()=>{
 const html=ctx.endpointSearchField('owned','device','x1',{allowAll:true});
 assert.ok(html.includes('&lt;img'));assert.ok(!html.includes('value="<img'));
 assert.ok(html.includes('list="owned-choices"'));assert.ok(html.includes('type="hidden" name="device"'));
});
const audit=bind(new SearchBox('a1','LAB-01',false,true));
test('a fresh audit selection permits normal automatic refresh',()=>assert.equal(ctx.hasEndpointSearchDraft(new Root(audit)),false));
await type(audit,'LAB');
test('editing endpoint pauses automatic refresh even after leaving the input',()=>assert.equal(ctx.hasEndpointSearchDraft(new Root(audit)),true));
test('typing a partial name clears previous ID and cannot broaden query',()=>{assert.equal(audit.hidden.value,'');assert.ok(audit.input.validationMessage);assert.equal(audit.endpointSearch.validate(),false);});
await type(audit,'LAB-02');
test('exact input resolves to a real ID without requiring raw ID entry',()=>{assert.equal(audit.hidden.value,'p1');assert.equal(audit.input.validationMessage,'');});
await type(audit,'Not an endpoint');
await audit.all.fire('click');
test('explicit all-endpoints control clears invalid input and selection',()=>{assert.equal(audit.input.value,'');assert.equal(audit.hidden.value,'');assert.equal(audit.input.validationMessage,'');assert.ok(audit.status.textContent.includes('全部端點'));});
await type(audit,'LAB-01');
ctx.state.devices=devices.filter(d=>d.id!=='a1').concat({id:'new-id',name:'LAB-01'});
audit.endpointSearch.refresh();
test('catalog refresh cannot silently switch selected ID to a replacement with same name',()=>{assert.equal(audit.hidden.value,'a1');assert.ok(audit.input.validationMessage);});
test('rerendered draft cannot resolve a removed selection to another endpoint with same name',()=>{
 const restored=bind(new SearchBox(audit.hidden.value,audit.input.value,false,true));
 assert.equal(restored.endpointSearch.validate(),false);assert.equal(restored.hidden.value,'a1');
});
ctx.state.devices=devices;
const active=bind(new SearchBox('a1','LAB-01',true,false));
ctx.state.devices=devices.map(d=>d.id==='a1'?{...d,revoked:true}:d);active.endpointSearch.refresh();
test('a selected endpoint revoked after selection is rejected before dispatch',()=>{assert.equal(active.endpointSearch.validate(),false);assert.equal(active.hidden.value,'a1');});
ctx.state.devices=devices;
const draft=bind(new SearchBox('a1','LAB-01',false,true));
draft.hidden.value='';draft.input.value='unfinished';ctx.restoreEndpointSearches(new Root(draft));
test('draft restoration preserves unfinished text and invalid state',()=>{assert.equal(draft.input.value,'unfinished');assert.equal(draft.hidden.value,'');assert.ok(draft.input.validationMessage);});
const auditDraft=bind(new SearchBox('a1','LAB-01',false,true));
const auditDraftFields={device:auditDraft.hidden,device_query:auditDraft.input,q:new Field('')};
const auditForm={elements:{namedItem:name=>auditDraftFields[name]},querySelectorAll:s=>s==='[data-endpoint-search]'?[auditDraft]:[]};
ctx.$=s=>s==='#search-form'?auditForm:null;
vm.runInContext(app.split('\n').find(s=>s.startsWith('function restoreQueryDraft(')),ctx);
ctx.restoreQueryDraft({id:'search-form',values:[['device',''],['device_query','unfinished audit'],['q','keep keyword']]});
test('actual audit draft restore retains typed endpoint, hidden ID and other filters',()=>{
 assert.equal(auditDraft.input.value,'unfinished audit');assert.equal(auditDraft.hidden.value,'');assert.ok(auditDraft.input.validationMessage);assert.equal(auditDraftFields.q.value,'keep keyword');
});
vm.runInContext(fs.readFileSync(path.join(folder,'updates_ui.js'),'utf8'),ctx);
vm.runInContext("updatesData={releases:[],jobs:[],presence:[{device_id:'a1',role:'native',version:'0.4.113',broker_version:'0.4.113'},{device_id:'a1',role:'main',version:'0.4.113'}]}",ctx);
test('update target scopes serialize exact IDs and original group API shape',()=>{
 assert.deepEqual(clean(ctx.updateTargetBody('all','garbage',devices,ctx.state.groups)),{device_ids:['a1','p1','d1','d2','x1']});
 assert.deepEqual(clean(ctx.updateTargetBody('group:g1','a1',devices,ctx.state.groups)),{group_id:'g1'});
 assert.deepEqual(clean(ctx.updateTargetBody('device','p1',devices,ctx.state.groups)),{device_ids:['p1']});
 for(const [scope,id] of [['device',''],['device','r1'],['device','LAB-01'],['group:missing',''],['','a1'],['device:a1','']])assert.throws(()=>ctx.updateTargetBody(scope,id,devices,ctx.state.groups));
});
test('update HTML lists all first, groups, then separate endpoint search',()=>{
 vm.runInContext("heading=()=>'';card=(title,help,body)=>body;bundledVersionCard=()=>'';updateProgressCard=()=>''",ctx);
 const html=ctx.updatesPage();const select=html.match(/<select name="target" required>([\s\S]*?)<\/select>/)[1];
 assert.ok(select.startsWith('<option value="all">'));assert.ok(select.includes('value="group:g1"'));assert.ok(select.includes('value="device"'));
 assert.ok(!select.includes('value="device:'));assert.ok(html.includes('data-update-device hidden'));
 assert.ok(html.includes('name="device_id_query"'));assert.ok(html.includes('name="legacy_preflight_confirmed"'));
});
class Form extends Field{
 constructor(box){super();this.wrapper=new Root(box);this.box=box;this.submit=new Field();this.fields={target:new Field('all'),release_id:new Field('release'),device_id:box.hidden,device_id_query:box.input,not_before:new Field('2026-11-19T09:00'),legacy_preflight_confirmed:new Field(),allow_downgrade:new Field()};this.fields.legacy_preflight_confirmed.type='checkbox';this.fields.legacy_preflight_confirmed.checked=true;this.fields.allow_downgrade.type='checkbox';this.elements={...this.fields,namedItem:key=>this.fields[key]};}
 querySelector(s){return s==='[data-update-device]'?this.wrapper:s==='[data-endpoint-search]'?this.box:s==='button[type=submit]'?this.submit:null;}
 querySelectorAll(s){return this.wrapper.querySelectorAll(s);}
}
ctx.FormData=class extends Map{constructor(form){super();for(const [name,field] of Object.entries(form.fields)){if(field.disabled||field.type==='checkbox'&&!field.checked)continue;this.set(name,field.type==='checkbox'?'on':field.value);}}};
const update=bind(new SearchBox('', '',true,false)),form=new Form(update);
ctx.$=s=>s==='#update-job'?form:dispatchButtons[s]||null;document.querySelector=ctx.$;
ctx.bindUpdates();
test('all/group modes disable required endpoint input so it cannot leak into request',()=>{
 assert.equal(update.input.disabled,true);assert.equal(form.wrapper.hidden,true);
 ctx.setUpdateTarget(form,'group:g1');assert.equal(update.hidden.disabled,true);
});
ctx.setUpdateTarget(form,'device:a1');
test('context preselection switches mode and retains version readiness details',()=>{
 assert.equal(form.elements.target.value,'device');assert.equal(update.hidden.value,'a1');assert.equal(update.input.disabled,false);
 assert.ok(update.status.textContent.includes('0.4.113'));assert.ok(update.status.textContent.includes('更新器'));
});
await type(update,'LAB');await form.fire('submit');
test('actual submit handler sends no API request for incomplete endpoint input',()=>assert.equal(apiCalls.length,0));
await type(update,'LAB-02');await form.fire('submit');
test('actual submit preserves release, old-updater acknowledgement and Taipei schedule',()=>{
 assert.equal(apiCalls.length,1);assert.equal(apiCalls[0].url,'/api/updates/jobs/preview');
 assert.deepEqual(clean(apiCalls[0].body),{release_id:'release',legacy_preflight_confirmed:true,allow_downgrade:false,device_ids:['p1'],not_before:new Date('2026-11-19T09:00:00+08:00').getTime()/1000});
 assert.equal(refreshes,0);assert.ok(dispatchHTML.includes('可更新 1 台')&&dispatchHTML.includes('等候上線／回報 1 台'));
 assert.ok(dispatchHTML.includes('&lt;test&gt;'));
});
await dispatchButtons['#update-dispatch-ready'].onclick();
test('confirmation uses the saved preview and creates only ready work when selected',()=>{
 assert.equal(apiCalls[1].url,'/api/updates/jobs');
 assert.deepEqual(clean(apiCalls[1].body),{confirm:'deploy',preview_id:'preview-fixture',ready_only:true});
 assert.equal(refreshes,1);
});
ctx.setUpdateTarget(form,'all');await form.fire('submit');
test('all sends server-side selection and excludes single-device flags',()=>{
 assert.equal(apiCalls[2].body.all_endpoints,true);assert.equal(apiCalls[2].body.device_ids,undefined);
 assert.equal(apiCalls[2].body.legacy_preflight_confirmed,false);
});
ctx.setUpdateTarget(form,'device:a1');await type(update,'unfinished');
vm.runInContext('updatesDirty=true',ctx);const saved=ctx.captureUpdatesDraft();
update.input.value='lost';update.hidden.value='';form.elements.target.value='all';ctx.restoreUpdatesDraft(saved);
test('actual update draft round-trip keeps separate mode and unfinished input',()=>{
 assert.equal(form.elements.target.value,'device');assert.equal(update.input.value,'unfinished');assert.equal(update.hidden.value,'');assert.equal(update.input.disabled,false);assert.ok(update.input.validationMessage);
});
const query=fs.readFileSync(path.join(folder,'audit_ui.js'),'utf8').split('\n').find(s=>s.startsWith('function auditQuery('));
Object.assign(ctx,{page:'audit',search:'invoice',severity:'warning',auditDevice:'a1',auditCategory:'documents',auditKind:'file.deleted',offset:50,auditStart:'2026-11-18T00:00',auditEnd:'2026-11-19T00:00',auditPerson:null,auditReportDevice:null,auditEndExclusive:true,auditSort:'occurred',auditSortDirection:'desc'});
vm.runInContext(query,ctx);
test('audit query keeps committed endpoint ID, dates, category and fifty-row paging',()=>{
 const q=new URLSearchParams(ctx.auditQuery());assert.equal(q.get('device'),'a1');assert.equal(q.get('limit'),'50');assert.equal(q.get('offset'),'50');assert.equal(q.get('category'),'documents');assert.equal(q.get('q'),'invoice');assert.equal(q.get('end_exclusive'),'1');assert.equal(q.get('start'),String(new Date('2026-11-18T00:00:00+08:00').getTime()/1000));assert.equal(new URLSearchParams(ctx.auditQuery(true)).get('offset'),'0');
});
console.log(JSON.stringify({passed:tests,center_started:false,network_calls:0,api_calls_are_owned_stubs:true,native_browser_validation:false}));
})().catch(error=>{console.error(error);process.exitCode=1;});
