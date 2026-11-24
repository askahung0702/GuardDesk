// Exercise the production editor and audit table helpers without a server.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.join(__dirname, '../guarddesk/static');
const app = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
const audit = fs.readFileSync(path.join(root, 'audit_ui.js'), 'utf8');
const context = vm.createContext({
  document: {addEventListener() {}},
  FormData: class { constructor(form) { return form.data; } },
  esc: String, structuredClone, state: {policy:{body:{}},devices:[]},
  date: String, auditSortHeader: () => '', applicationControlFields: () => '',
  websiteFields: () => '', uploadRow: () => '', kinds:{},
});
function evaluate(script) { return vm.runInContext(script, context); }
function fn(text, name, next) {
  const start=text.indexOf('function '+name+'(');
  const end=text.indexOf('\n'+next,start);
  assert.ok(start>=0 && end>start,name);
  evaluate(text.slice(start,end));
}
evaluate(app.slice(0,app.indexOf('const $ =')));
fn(app,'readPolicyForm','async function');
fn(audit,'applicationAuditFields','function');
fn(app,'endpointModuleFields','function');
fn(audit,'browserAuditTable','function');
context.policy={browser_audit:false,browser_visit_detail:'detailed',browser_upload_mode:'enabled',
  application_audit:true,application_audit_exclusions:[],application_stop_mode:'selected',
  application_stop_programs:['writer.exe'],upload_rules:[],file_audit:{exclude_paths:[]}};
const html=evaluate('endpointModuleFields(policy)');
assert.match(html.browser,/value="enabled" selected/);
assert.match(html.browser,/value="detailed" selected/);
assert.match(html.apps,/value="selected" selected/);
assert.match(html.apps,/writer\.exe/);
assert.match(html.files,/data-claude-temp-preset/);
const values=new Map([['browser_visit_detail','domain'],['browser_upload_mode','enabled'],
  ['application_audit','on'],['application_stop_mode','selected'],['application_stop_programs','writer.exe\nreader.exe']]);
context.form={id:'baseline',data:values,querySelector:()=>({dataset:{}}),querySelectorAll:()=>[]};
const saved=evaluate('readPolicyForm(form)');
assert.equal(saved.browser_audit,false);
assert.equal(saved.browser_upload_mode,'enabled');
assert.equal(saved.browser_visit_detail,'domain');
assert.deepEqual(Array.from(saved.application_stop_programs),['writer.exe','reader.exe']);
const row=evaluate("browserAuditTable([{details:{domain:'office.test',source:'browser_history'}}])");
assert.match(row,/office\.test/);
assert.match(row,/僅記網域/);
evaluate(audit.slice(audit.indexOf('function groupedAuditRows('),audit.indexOf('// End audit action catalog.')));
evaluate("auditSort='occurred'");
context.renderRow=e=>`<tr data-id="${e.id}"></tr>`;
const event=(id,kind,at,device,extra)=>({id,kind,occurred:at,device_id:device,device_name:device,severity:'warning',details:extra});
const upload={source:'browser_webrequest',upload_id:'one',user:'test',browser:'edge'};
const gap={source:'windows_etw_file_io',reason:'bounded_document_collection'};
context.rows=[event(1,'web.upload_started',5,'A',upload),event(2,'web.upload_response',8,'A',upload),
  event(3,'web.upload_started',9,'B',upload),event(4,'agent.audit_gap',20,'A',gap),
  event(5,'agent.audit_gap',24,'A',gap),event(6,'agent.audit_gap',26,'A',{...gap,reason:'different'}),
  event(7,'agent.audit_gap',95,'A',gap)];
const groups=evaluate('groupedAuditRows(rows,7,renderRow)');
assert.equal((groups.match(/<details /g)||[]).length,2);
assert.equal((groups.match(/data-id=/g)||[]).length,7);
assert.match(groups,/本頁 2 筆/);
evaluate("auditSort='device'");
assert.doesNotMatch(evaluate('groupedAuditRows(rows,7,renderRow)'),/<details /);
console.log('PASS audit editor, domain-only table, upload phases and gap grouping');
