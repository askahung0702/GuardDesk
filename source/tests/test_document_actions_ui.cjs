// Actual catalog, form renderer and toggle handler; owned DOM, no browser or HTTP.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const root=path.join(__dirname,'../guarddesk/static');
const app=fs.readFileSync(path.join(root,'app.js'),'utf8');
const audit=fs.readFileSync(path.join(root,'audit_ui.js'),'utf8');
const listeners={};let networkCalls=0,refreshes=0;
const esc=v=>String(v??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
const ctx=vm.createContext({esc,URLSearchParams,Date,console,
 document:{addEventListener(type,fn){(listeners[type]??=[]).push(fn);}},
 fetch(){networkCalls++;throw Error('No network permitted');},refresh(){refreshes++;},
 heading:()=>'',auditPersonNotice:()=>'',documentAuditNotice:()=>'',documentDiagnosticsButton:()=>'',
 endpointSearchField:()=>'<input name="device" value="owned-device">',
 auditSortHeader:()=>'<th></th>',empty:()=>'',level:()=>'',date:v=>'time-'+v,
 events:{items:[],total:0},search:'draft',severity:'',auditDevice:'owned-device',offset:0,
 auditPerson:null,auditReportAction:'',auditReportDevice:null,auditEndExclusive:true,page:'audit',
 auditSort:'occurred',auditSortDirection:'desc'});
const run=s=>vm.runInContext(s,ctx);
run(app.split('\n').find(l=>l.startsWith('const kinds =')));
for(const line of [...app.split('\n'),...audit.split('\n')])if(line.startsWith('Object.assign(kinds,'))run(line);
run(audit.slice(0,audit.indexOf('// End audit action catalog.')));
run(audit.split('\n').find(l=>l.startsWith('function detailedAudit()')));
run(audit.split('\n').find(l=>l.startsWith('function auditQuery(')));
run(audit.slice(audit.indexOf('function fileWriteEvidence('),audit.indexOf('function documentAuditNotice(')));
const options=(category,selected='',expanded=false)=>run(`auditActionOptions(${JSON.stringify(category)},${JSON.stringify(selected)},${expanded})`);
const keys=html=>[...html.matchAll(/<option value="([^"]*)"/g)].map(m=>m[1]);
const normal=['','file.created','file.deleted','file.copy_candidate','file.opened','file.written','file.saved','file.moved','file.renamed',
 'web.upload_started','web.upload_response','web.upload_failed','web.upload_redirected','web.upload_interrupted'];
assert.deepEqual(keys(options('documents')).sort(),normal.sort());
const extra=['file.modified','file.web_handoff','file.open_requested','file.delete_requested','file.rename_from','file.rename_to','web.upload_gap'];
for(const kind of extra){
 assert.ok(!keys(options('documents')).includes(kind));
 assert.ok(keys(options('documents','',true)).includes(kind));
 const pinned=options('documents',kind,false);
 assert.ok(pinned.includes(`value="${kind}" selected`));
 assert.equal(keys(pinned).filter(k=>k===kind).length,1);
}
assert.ok(!keys(options('applications','',true)).some(k=>k.startsWith('file.')));
assert.ok(keys(options('web')).includes('web.navigation'));
assert.ok(keys(options('uploads','',true)).every(k=>!k||k.startsWith('web.upload_')));
assert.ok(!keys(options('files')).some(k=>k.startsWith('web.')));
assert.ok(!keys(options('')).includes('file.modified'));
run("auditCategory='documents';auditKind='file.modified'");
assert.ok(run('detailedAudit()').includes('value="file.modified" selected'));
assert.ok(run('detailedAudit()').includes('data-audit-advanced-actions'));
const draft={value:'file.rename_from',innerHTML:''};
const checkbox={checked:false,matches:s=>s==='[data-audit-advanced-actions]',closest:()=>({querySelector:()=>draft})};
listeners.change[0]({target:checkbox});
assert.ok(draft.innerHTML.includes('value="file.rename_from" selected'));
assert.ok(!draft.innerHTML.includes('value="file.modified"'));
checkbox.checked=true;listeners.change[0]({target:checkbox});
assert.ok(draft.innerHTML.includes('value="file.modified"'));
assert.equal(refreshes,0);assert.equal(networkCalls,0);
const query=new URLSearchParams(run('auditQuery()'));
assert.equal(query.get('kind'),'file.modified');assert.equal(query.get('device'),'owned-device');
assert.equal(query.get('limit'),'50');assert.equal(query.get('category'),'documents');
assert.ok(query.has('start')&&query.has('end'));
// Labels still pass through the same HTML encoding boundary after curation.
run("kinds['file.owned_test']='<img src=x onerror=bad()>'");
assert.ok(options('documents').includes('&lt;img'));
assert.ok(!options('documents').includes('<img'));
run("delete kinds['file.owned_test']");
// Real row rendering must not infer the person's name or a content modification.
run("auditKind='';auditAdvancedActions=false");
ctx.events.items=[{id:'word',kind:'file.opened',occurred:1,received:2,device_name:'Owned-PC',severity:'info',
 details:{path:String.raw`C:\Docs\report.docx`,process:String.raw`C:\Office\WINWORD.EXE`,user:null,
 evidence:'completed_native_read',interaction:'recent_input_foreground'}}];
const row=run('detailedAudit()');
assert.ok(row.includes('WINWORD.EXE'));assert.ok(row.includes('report.docx'));assert.ok(row.includes('來源未提供'));
assert.ok(!row.includes('檔案內容或屬性變更（歷史）'));
assert.ok(row.includes('最近輸入與前景程式關聯'));assert.ok(row.includes('未證明人工閱讀'));
ctx.events.items[0].kind='file.written';ctx.events.items[0].details.written_bytes=1024;
run("auditKind='file.written'");
const written=run('detailedAudit()');
assert.ok(written.includes('value="file.written" selected'));
assert.ok(written.includes('檔案寫入'));
assert.ok(written.includes('已完成資料寫入 1024 位元組'));
ctx.events.items[0].details.size_updates=1;ctx.events.items[0].details.file_size_after=0;
ctx.events.items[0].details.written_bytes=0;
const empty=run('detailedAudit()');
assert.ok(empty.includes('已完成長度設定：0 位元組'));
assert.ok(!empty.includes('已完成資料寫入 0 位元組'));
ctx.events.items[0].details.process_id=4;
const legacySystem=run('detailedAudit()');
assert.ok(legacySystem.includes('系統回報長度操作，實際長度變化未確認'));
assert.ok(!legacySystem.includes('已完成長度設定：0 位元組'));
ctx.events.items[0].kind='file.saved';
ctx.events.items[0].details={path:'new-sheet.xlsx',process:'EXCEL.EXE',evidence:'same_directory_replacement',observations:6};
run("auditKind='file.saved'");
const saved=run('detailedAudit()');
assert.ok(saved.includes('value="file.saved" selected'));
assert.ok(saved.includes('文件儲存')&&saved.includes('new-sheet.xlsx')&&saved.includes('EXCEL.EXE'));
assert.ok(saved.includes('已合併 6 筆觀察'));
console.log(JSON.stringify({passed:true,supplemental_cases:extra.length,network_calls:networkCalls,refreshes}));
