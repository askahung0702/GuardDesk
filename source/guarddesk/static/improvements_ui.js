'use strict';
let policyPublishDraft=null,policyPreviewOffset=0,templateDraft=null,fleetPage=0;
let baselinePublishDraft=null,historyData=null,historySetId=null,previewAccount=null;
const developmentRule='@guarddesk:development-cache:v1';
const settingFields={mode:'mode',allow_export:'allow_export',extensions:'blocked_extensions',keywords:'keywords',max_export_mb:'max_export_mb',usb_mode:'usb_mode',file_audit_enabled:'file_audit.enabled',file_audit_scope:'file_audit.scope',file_excludes:'file_audit.exclude_paths',browser_audit:'browser_audit',application_audit:'application_audit',application_audit_exclusions:'application_audit_exclusions',app_control_enabled:'application_control.enabled',app_control_mode:'application_control.mode',app_block_msi:'application_control.block_msi'};
const settingLabels={'file_audit.enabled':'檔案稽核啟用','file_audit.scope':'檔案稽核範圍','file_audit.exclude_paths':'檔案排除清單','application_control.enabled':'應用程式管制啟用','application_control.mode':'黑／白名單','application_control.block_msi':'MSI 安裝限制','application_control.rules':'應用程式規則'};
const appendSettings=new Set(['file_audit.exclude_paths','application_audit_exclusions']);
function selectedEditorSet(){return state.policy_sets.find(p=>p.id===editingSet)||(editingSet==='new'?templateDraft:null);}
function editorValue(p,path){return path.split('.').reduce((v,key)=>v?.[key],p);}
function policyEditorValues(existing){const result={...structuredClone(state.policy.body),...structuredClone(existing?.overrides||{})};for(const op of existing?.operations||[]){const parts=op.path.split('.'),key=parts.pop();let target=result;for(const part of parts)target=target[part];target[key]=op.op==='append'?[...new Set([...target[key],...op.value])]:structuredClone(op.value);}return result;}
function installSettingModes(form){
  const existing=selectedEditorSet();
  const fields={...settingFields};
  for(const [name,path] of Object.entries(fields)){
    const control=form.querySelector(`[name="${name}"]`);if(!control)continue;
    const box=control.closest('[data-module-panel]');if(!box)continue;
    const op=existing?.operations?.find(v=>v.path===path),top=path.split('.')[0];
    const mode=op?.op||(existing?.operations?.length&&!(top in (existing?.overrides||{}))?'inherit':'set');
    const label=document.createElement('label');label.className='setting-mode';
    label.innerHTML=`<span>${esc(settingLabels[path]||fieldNames[top]||path)}的設定來源</span><select data-setting-path="${path}" data-setting-name="${name}" aria-label="${esc(settingLabels[path]||fieldNames[top]||path)}設定來源"><option value="inherit">沿用上層</option><option value="set">本策略設定${appendSettings.has(path)?'（取代清單）':''}</option>${appendSettings.has(path)?'<option value="append">追加到上層清單</option>':''}</select>`;
    control.closest('label').before(label);label.querySelector('select').value=mode;
    if(op?.op==='append'){
      if(name==='file_excludes'){control.value=op.value.filter(v=>v!==developmentRule).join('\n');form.querySelector('[name=exclude_development]').checked=op.value.includes(developmentRule);}
      else control.value=op.value.join('\n');
    }
  }
  for(const [id,path,module] of [['application-rules','application_control.rules','appcontrol'],['upload-rules','upload_rules','upload']]){
    const table=form.querySelector('#'+id);if(!table)continue;
    const op=existing?.operations?.find(v=>v.path===path),top=path.split('.')[0];
    const mode=op?.op||(existing?.operations?.length&&!(top in (existing?.overrides||{}))?'inherit':'set');
    const label=document.createElement('label');label.className='setting-mode';label.innerHTML=`規則清單設定來源<select data-setting-path="${path}" data-setting-table="${id}"><option value="inherit">沿用上層</option><option value="set">本策略取代清單</option></select>`;table.closest('.table-wrap').before(label);label.querySelector('select').value=mode;
  }
  form.addEventListener('change',()=>updateSettingModes(form));updateSettingModes(form);
}
function updateSettingModes(form){
  for(const selector of form.querySelectorAll('[data-setting-path]')){
    const inherited=selector.value==='inherit';
    if(selector.dataset.settingName){const c=form.querySelector(`[name="${selector.dataset.settingName}"]`);c.disabled=inherited;if(selector.dataset.settingPath==='application_audit_exclusions')form.querySelector('[data-app-exclusion-preset]').disabled=inherited;if(selector.dataset.settingPath==='file_audit.exclude_paths')for(const name of ['exclude_development','exclude_hidden'])form.querySelector('[name='+name+']').disabled=inherited;}
    else for(const c of form.querySelector('#'+selector.dataset.settingTable).querySelectorAll('input,select,button'))c.disabled=inherited;
  }
}
function collectSetDraft(form){
  const f=new FormData(form),full=readPolicyForm(form),overrides={},operations=[];
  for(const [module,keys] of Object.entries(moduleKeys)){
    if(!f.has('module_'+module))continue;
    const panel=form.querySelector(`[data-module-panel="${module}"]`),selectors=[...panel.querySelectorAll('[data-setting-path]')];
    if(selectors.every(c=>c.value==='set')){for(const key of keys)overrides[key]=full[key];}
    else for(const c of selectors)if(c.value!=='inherit')operations.push({path:c.dataset.settingPath,op:c.value,value:editorValue(full,c.dataset.settingPath)});
  }
  if(!Object.keys(overrides).length&&!operations.length)throw new Error('請至少設定一項；全部沿用不需要建立策略');
  const category_refs=readCategoryRefs(form);
  if(category_refs.application_deny&&!overrides.application_control)throw new Error('引用應用分類時，請將應用程式管制各欄設為本策略設定');
  const existing=selectedEditorSet();return {category_refs,id:existing?.id,revision:existing?.id?existing.revision:undefined,name:f.get('set_name'),description:f.get('set_description'),enabled:f.has('set_enabled'),overrides,operations};
}
function previewValue(path,value){if(typeof value==='boolean')return value?'啟用':'停用';return typeof value==='object'?JSON.stringify(value):simpleValue(path.includes('.')?'leaf':path,value);}
function previewRows(result){return result.items.length?`<div class="table-wrap preview-table"><table><thead><tr><th>端點</th><th>欄位</th><th>目前</th><th>套用後</th><th>來源</th></tr></thead><tbody>${result.items.flatMap(d=>d.changes.length?d.changes.map(c=>`<tr><td>${esc(d.name)}<small>${d.online?'上線':'離線，等待重連'}</small></td><td>${esc(settingLabels[c.path]||fieldNames[c.path]||c.path)}</td><td class="full-path">${esc(previewValue(c.path,c.before))}</td><td class="full-path">${esc(previewValue(c.path,c.after))}</td><td>${esc(c.source.name)}</td></tr>`):[`<tr><td>${esc(d.name)}</td><td colspan="4">設定值相同，來源／版本會更新</td></tr>`]).join('')}</tbody></table></div>`:'<p>此範圍沒有設定值異動。尚未指派的策略只會儲存，之後可指定對象。</p>';}
function previewContent(result,kind){return `<div class="notice"><strong>${result.scope_count??result.affected_count} 台在範圍內 · ${result.changed_count} 台設定會改變</strong><p>${result.offline_count} 台離線 · ${result.conflict_count} 項同層覆寫；最終結果以每台有效策略為準。</p></div>${previewRows(result)}${result.personal_accounts?.length?`<label>個人指派範圍（逐一預覽）<select data-preview-account>${result.personal_accounts.map(a=>`<option value="${esc(a)}" ${a===(previewAccount||result.personal_accounts[0])?'selected':''}>${esc(a)}</option>`).join('')}</select></label>`:''}${(result.personal_scopes||[]).map(p=>`<details><summary>個人範圍 ${esc(p.account)} · ${p.affected_count} 台（含之後可能登入的端點）</summary>${previewRows(p)}</details>`).join('')}${result.has_more?`<button class="secondary" type="button" data-preview-more="${kind}" data-offset="${result.offset+result.limit}">查看後續端點</button>`:''}${result.offset?`<button class="secondary" type="button" data-preview-more="${kind}" data-offset="${Math.max(0,result.offset-result.limit)}">上一批端點</button>`:''}<p class="help">不會因預覽執行端點控制；發布後請追蹤接收與元件回報。</p>`;}
async function submitPolicySet(event){event.preventDefault();try{policyPublishDraft=collectSetDraft(event.target);policyPreviewOffset=0;previewAccount=null;await showSetPreview();}catch(error){toast(error.message);}}
async function showSetPreview(){const result=await api('/api/policy-sets/preview',{...policyPublishDraft,preview_offset:policyPreviewOffset,...(previewAccount?{preview_account:previewAccount}:{})});policyPublishDraft.expected_generation=result.generation;dialog('發布前確認實際差異',previewContent(result,'set')+'<button class="primary" data-improve-publish>確認發布策略集</button>',true);}
async function submitPolicyAssignment(event){event.preventDefault();const f=new FormData(event.target);pendingAssignment={set_id:f.get('set_id'),target_type:f.get('target_type'),target_id:f.get('target_id')||'',priority:Number(f.get('priority')),enabled:true};policyPreviewOffset=0;await showAssignmentPreview();}
async function showAssignmentPreview(){const result=await api('/api/assignments/preview',{...pendingAssignment,preview_offset:policyPreviewOffset});pendingAssignment.expected_generation=result.generation;dialog('指派前確認實際差異',previewContent(result,'assignment')+'<button class="primary" data-action="assignment-confirm">確認指派'+(result.conflict_count?'（依顯示順位覆寫）':'')+'</button>',true);}
savePolicy=async function(event){event.preventDefault();try{baselinePublishDraft={base_version:state.policy.version,body:readPolicyForm(event.target)};policyPreviewOffset=0;await showBaselinePreview();}catch(error){toast(error.message);}};
async function showBaselinePreview(){const result=await api('/api/policy/preview',{...baselinePublishDraft,preview_offset:policyPreviewOffset});baselinePublishDraft.expected_generation=result.generation;dialog('全域預設發布前差異',previewContent(result,'baseline')+'<button class="primary" data-improve-baseline-publish>確認發布全域預設</button>',true);}
async function policyHistory(id){historySetId=id;historyData=(await api('/api/policy-sets/history?id='+encodeURIComponent(id))).items;dialog('版本比較與復原',`<p>復原會建立新版本，原始歷史保留；套用前仍會預覽全部受影響端點。</p>${historyData.map(r=>`<section class="card card-body"><h3>v${r.revision} · ${date(r.created)}</h3><p>${esc(r.name)} · ${esc(r.actor)}</p><details><summary>檢視當時設定</summary><pre>${esc(JSON.stringify({overrides:r.overrides,operations:r.operations,category_refs:r.category_refs},null,2))}</pre></details>${user.role==='admin'?`<button class="secondary" data-policy-restore="${r.revision}">預覽以新版本恢復此設定</button>`:''}</section>`).join('')}`,true);}
const policyTemplates=[{name:'USB 唯讀',description:'限制 USB 儲存磁碟寫入；其他功能沿用上層。',overrides:{usb_mode:'read_only'},operations:[]},{name:'一般同仁稽核',description:'啟用文件、普通網站與程式啟停稽核，其餘設定沿用上層。',overrides:{},operations:[{path:'file_audit.enabled',op:'set',value:true},{path:'browser_audit',op:'set',value:true},{path:'application_audit',op:'set',value:true}]},{name:'資訊／開發機降噪',description:'追加明確開發快取與 conhost／docker 普通啟停排除，安全事件保留。',overrides:{},operations:[{path:'file_audit.exclude_paths',op:'append',value:['@guarddesk:development-cache:v1']},{path:'application_audit_exclusions',op:'append',value:['conhost.exe','docker.exe']}]}];
const originalPolicyLibrary=policySetLibrary;
policySetLibrary=function(){return (user.role==='admin'?`<section class="card"><div class="card-body"><h2>從情境範本建立草稿</h2><p>範本只填入設定，不會自動發布或指派。</p><div class="toolbar"><select id="policy-template" aria-label="策略情境範本">${policyTemplates.map((p,i)=>`<option value="${i}">${esc(p.name)}</option>`).join('')}</select><button class="secondary" data-policy-template>使用此範本</button></div></div></section>`:'')+originalPolicyLibrary();};
const originalBindManagement=bindManagement;
bindManagement=function(){originalBindManagement();const form=$('#set-form');if(form){installSettingModes(form);form.querySelector('.module-inheritance-help').insertAdjacentHTML('beforeend','<br>沿用欄位的灰色值僅為編輯參考；不同群組的實際繼承值，請以發布前的逐端點預覽確認。');}};
moduleGuides.appcontrol.short='依黑／白名單限制應用程式執行及 MSI 安裝。';
const originalDetailBasic=detailBasic;
detailBasic=function(){const d=detailData.device,rows=d.policy_progress||[];return `<h3 class="subheading">策略發布、接收與元件回報</h3><p class="help">端點回報設定完成，仍需實測確認控制效果。下列狀態不會把「已接收」當成 USB／程式已實際阻擋。</p><div class="table-wrap"><table><thead><tr><th>功能</th><th>有效設定</th><th>來源</th><th>接收</th><th>元件回報／待處理原因</th></tr></thead><tbody>${rows.map(r=>`<tr><td>${esc(r.name)}</td><td>${esc(previewValue(r.key,r.desired))}</td><td>${esc(r.source)}<small>v${r.published_version}</small></td><td>${r.received?'已接收':'待接收'}</td><td><span class="badge ${r.state==='failed'?'danger':r.state==='pending'||r.state==='offline'?'warning':''}">${esc({pending:'待確認',failed:'失敗',reported:'元件回報',replug:'設定讀回／待重插',offline:'離線',disabled:'已停收'}[r.state]||r.state)}</span><small>${esc(r.reason)}</small></td></tr>`).join('')}</tbody></table></div>`+originalDetailBasic();};
const originalEffectiveView=effectiveView;
effectiveView=function(p){return originalEffectiveView(p)+`<details><summary>逐欄繼承與追加來源</summary><div class="table-wrap"><table><thead><tr><th>欄位</th><th>有效值</th><th>來源</th><th>方式</th></tr></thead><tbody>${Object.entries(p.setting_sources||{}).map(([path,s])=>`<tr><td>${esc(settingLabels[path]||fieldNames[path]||path)}</td><td class="full-path">${esc(previewValue(path,editorValue(p.body,path)))}</td><td>${esc(s.name)} · v${s.revision}</td><td>${s.operation==='append'?'追加排除':s.kind==='baseline'?'全域預設':'明確設定'}</td></tr>`).join('')}</tbody></table></div></details>`;};
document.addEventListener('click',async event=>{
  try{
    if(event.target.closest('[data-improve-publish]')){await api('/api/policy-sets',policyPublishDraft);policyPublishDraft=null;templateDraft=null;editingSet=null;$('#dialog').close();await refresh();toast('策略已發布，請追蹤端點接收與元件回報');}
    if(event.target.closest('[data-improve-baseline-publish]')){await api('/api/policy',baselinePublishDraft);baselinePublishDraft=null;$('#dialog').close();await refresh();toast('全域預設已發布，端點依繼承結果接收');}
    const more=event.target.closest('[data-preview-more]');if(more){policyPreviewOffset=Number(more.dataset.offset);await (more.dataset.previewMore==='set'?showSetPreview():more.dataset.previewMore==='baseline'?showBaselinePreview():showAssignmentPreview());}
    if(event.target.closest('[data-policy-template]')){templateDraft={...structuredClone(policyTemplates[Number($('#policy-template').value)]),enabled:true,revision:0,assignment_count:0};editingSet='new';render();}
    const restore=event.target.closest('[data-policy-restore]');if(restore){const old=historyData.find(r=>r.revision===Number(restore.dataset.policyRestore)),current=state.policy_sets.find(p=>p.id===historySetId);policyPublishDraft={id:current.id,revision:current.revision,name:old.name,description:old.description,enabled:!!old.enabled,overrides:old.overrides,operations:old.operations,category_refs:old.category_refs||{}};policyPreviewOffset=0;previewAccount=null;await showSetPreview();}
  }catch(error){toast(error.message);}
});

// Preserve old HTTP/CSV callers while the current audit UI uses signed cursors.
let eventCursors=[null],eventCursorQuery='';
const originalAuditQuery=auditQuery;
auditQuery=function(csv=false){const base=originalAuditQuery(csv);if(page!=='audit')return base;const q=new URLSearchParams(base);if(!auditDevice&&state?.groups?.some(g=>g.id===fleetGroup))q.set('group',fleetGroup);if(csv)return q.toString();const identity=new URLSearchParams(q);identity.delete('offset');if(identity.toString()!==eventCursorQuery){eventCursorQuery=identity.toString();eventCursors=[null];offset=0;q.set('offset','0');}const index=Math.floor(offset/50);if(index>0&&!eventCursors[index]){offset=0;q.set('offset','0');}q.set('cursor_mode','1');if(eventCursors[Math.floor(offset/50)])q.set('cursor',eventCursors[Math.floor(offset/50)]);return q.toString();};
const originalDetailedAudit=detailedAudit;
detailedAudit=function(){if(events.next_cursor)eventCursors[Math.floor(offset/50)+1]=events.next_cursor;let html=originalDetailedAudit();if(events.total===null){html=html.replace('共 null 筆',`第 ${Math.floor(offset/50)+1} 頁 · 每頁最多 50 筆`);const wrapper=document.createElement('div');wrapper.innerHTML=html;const next=wrapper.querySelector('[data-action=next]');if(next)next.disabled=!events.has_more;html=wrapper.innerHTML;}return html;};

const originalFleetRows=fleetRows;
let fleetResult=null,fleetResultQuery='',fleetTimer;
function fleetQueryString(){return new URLSearchParams({group:fleetGroup,q:fleetQuery,health:fleetHealth,sort:fleetSort,offset:String(fleetPage*50)}).toString();}
async function loadFleet(){const query=fleetQueryString(),result=await api('/api/fleet?'+query);if(query!==fleetQueryString())return;fleetResult=result;fleetResultQuery=query;if(fleetPage&&fleetPage*50>=result.total){fleetPage=Math.max(0,Math.ceil(result.total/50)-1);return loadFleet();}}
function reloadFleetRows(){clearTimeout(fleetTimer);fleetTimer=setTimeout(async()=>{try{await loadFleet();if(page==='devices'&&$('#fleet-rows'))$('#fleet-rows').innerHTML=fleetRows();}catch(error){toast(error.message);}},180);}
fleetRows=function(){if(!fleetResult||fleetResultQuery!==fleetQueryString())return '<p role="status">正在讀取端點分頁…</p>';const original=selectedFleet;selectedFleet=()=>fleetResult.items;let html;try{html=originalFleetRows();}finally{selectedFleet=original;}const pages=Math.max(1,Math.ceil(fleetResult.total/50));return html+`<div class="pagination"><span>${fleetResult.total} 台 · 第 ${fleetPage+1}／${pages} 頁</span><button class="secondary" data-fleet-page="${fleetPage-1}" ${fleetPage===0?'disabled':''}>上一頁</button><button class="secondary" data-fleet-page="${fleetPage+1}" ${!fleetResult.has_more?'disabled':''}>下一頁</button></div>`;};
document.addEventListener('click',async event=>{const b=event.target.closest('[data-fleet-page]');if(b&&!b.disabled){fleetPage=Number(b.dataset.fleetPage);b.disabled=true;try{await loadFleet();$('#fleet-rows').innerHTML=fleetRows();}catch(error){toast(error.message);b.disabled=false;}}});


const originalArchives=archivesPage;
archivesPage=function(){return originalArchives()+'<section class="card"><div class="card-body"><h2>事件儲存與容量</h2><p>查看每日事件檔、待落盤資料與主資料庫容量；可啟用分日儲存，舊事件保留並統一查詢。</p><button class="secondary" data-storage-open>查看儲存狀態</button></div></section>';};
async function storageDialog(){const s=await api('/api/audit/storage'),m=s.migration;dialog('事件儲存與容量',`<div class="notice"><strong>${s.mode==='daily-v1'?'分日事件儲存已啟用':'目前使用單一事件資料庫'}</strong><p>主資料庫 ${(s.control_bytes/1048576).toFixed(1)} MiB · WAL ${(s.wal_bytes/1048576).toFixed(1)} MiB<br>舊格式待搬移 ${(s.legacy_rows||0).toLocaleString()} 筆 · 主庫可回收空間 ${((s.reusable_control_bytes||0)/1048576).toFixed(1)} MiB<br>待寫日檔 ${s.pending_rows} 筆／${(s.pending_bytes/1048576).toFixed(1)} MiB</p><p>主庫備份 ${(s.backup_bytes/1048576).toFixed(1)} MiB（不含備份的日檔） · 索引／統計已包含在主庫，不重複相加。</p>${s.error?`<p class="warn">${esc(s.error)}</p>`:''}${m?`<p>啟用工作：${esc({working:'備份與切換中',completed:'完成',failed:'失敗，原資料保留'}[m.state]||m.state)}</p>`:''}</div><section class="notice"><strong>歷史搬移與主庫壓縮</strong><p>停止管理中心後，在資料目錄雙擊 <code>Optimize-Storage.cmd</code>。工具會先建立一致性備份、分批搬移舊事件到接收日期日檔、驗證完整稽核鏈，再壓縮主庫。事件 ID、原始時間與內容不變；失敗可修復後續跑。完成後用原 Start-Management.cmd 啟動。主庫保留查詢索引與設定，仍會隨事件成長；不要刪除 AuditData 或搬移前備份。</p></section>${s.mode!=='daily-v1'&&user.role==='admin'?'<p>啟用前會建立完整主庫快照，期間寫入可能短暫等待；新事件依台北接收日期保存，保留發生時間供查詢。舊事件不刪除，也不會立即縮小既有檔案。日後備份須包含主庫與對應日檔，不能只換回舊版 EXE。</p><button class="primary" data-storage-enable '+(m?.state==='working'?'disabled':'')+'>建立快照並啟用分日儲存</button>':''}<div class="table-wrap"><table><thead><tr><th>台北接收日期</th><th>事件筆數</th><th>日檔大小</th><th>狀態</th></tr></thead><tbody>${s.days.map(d=>`<tr><td>${esc(d.day)}</td><td>${d.rows}</td><td>${d.bytes===null?'尚無日檔':(d.bytes/1048576).toFixed(2)+' MiB'}</td><td>${esc({online:'日檔存在（讀取時驗證）',pending:'待寫日檔（仍可查待寫事件）',missing:'日檔缺失，請還原'}[d.state]||d.state)}</td></tr>`).join('')}</tbody></table></div><h3>最近接收日的主要來源（最多 100 筆）</h3><p class="help">封裝大小僅為事件壓縮內容；日檔含頁面成本，主庫另含索引，舊庫不在此來源統計內。</p><div class="table-wrap"><table><thead><tr><th>日期</th><th>端點</th><th>類型</th><th>筆數</th><th>壓縮內容</th></tr></thead><tbody>${s.sources.map(r=>`<tr><td>${esc(r.day)}</td><td>${esc(r.device_name)}</td><td>${esc(kinds[r.kind]||r.kind)}</td><td>${r.rows}</td><td>${(r.payload_bytes/1048576).toFixed(2)} MiB</td></tr>`).join('')}</tbody></table></div><button class="secondary" data-storage-open>重新整理狀態</button>`,true);}
document.addEventListener('click',async event=>{try{if(event.target.closest('[data-storage-open]'))await storageDialog();const b=event.target.closest('[data-storage-enable]');if(b&&!b.disabled){b.disabled=true;await api('/api/audit/storage/enable',{confirm:'enable_daily'});await storageDialog();toast('已開始備份與啟用工作，請稍後重新整理狀態');}}catch(error){toast(error.message);}});

// Copy complete values, never the visual ellipsis. Original evidence stays in
// the existing detail view; long technical notices can remain expanded there.
const originalRender=render;
render=function(){originalRender();for(const cell of document.querySelectorAll('.detailed-audit td.full-path')){if(cell.dataset.copyReady)continue;cell.dataset.copyReady='1';const value=cell.childNodes[0]?.textContent||'';if(!value||value==='—')continue;cell.classList.add('compact-path');const button=document.createElement('button');button.type='button';button.className='path-copy';button.textContent='複製';button.setAttribute('aria-label','複製完整路徑或網址');button.addEventListener('click',async()=>{try{await navigator.clipboard.writeText(value);toast('已複製完整值');}catch{toast('無法存取剪貼簿，請由明細選取複製');}});cell.append(button);cell.title=value;}};

document.addEventListener('change',async event=>{if(event.target.matches('[data-preview-account]')){previewAccount=event.target.value;policyPreviewOffset=0;try{await showSetPreview();}catch(error){toast(error.message);}}});

// Context is session memory only. It preselects a target, never grants access
// or publishes a policy/update without the existing explicit action.
let contextDevice='',fleetHealth='all',fleetSort='name';
const unfilteredFleet=selectedFleet;
selectedFleet=function(){return unfilteredFleet().filter(d=>fleetHealth==='all'||(fleetHealth==='offline'?d.status==='offline':fleetHealth==='pending'?!d.policy_received:fleetHealth==='backlog'?Number(d.inventory.outbox?.pending||0)>0:d.policy_progress?.some(r=>r.state==='failed'))).sort((a,b)=>fleetSort==='name'?a.name.localeCompare(b.name,'zh-TW'):fleetSort==='seen'?b.last_seen-a.last_seen:Number(b.inventory.outbox?.pending||0)-Number(a.inventory.outbox?.pending||0));};
const contextShowDevice=showDeviceDetail;
showDeviceDetail=async function(id){await contextShowDevice(id);contextDevice=id;};
const contextDevices=devices;
devices=function(){let html=contextDevices();const wrapper=document.createElement('div');wrapper.innerHTML=html;const toolbar=wrapper.querySelector('.toolbar');toolbar?.insertAdjacentHTML('beforeend',`<select id="fleet-health" aria-label="端點健康篩選">${[['all','全部健康狀態'],['offline','離線'],['pending','策略待接收'],['backlog','有待補送日誌'],['failed','元件回報失敗']].map(([v,l])=>`<option value="${v}" ${fleetHealth===v?'selected':''}>${l}</option>`).join('')}</select><select id="fleet-sort" aria-label="端點排序">${[['name','按電腦名稱'],['seen','最近心跳'],['backlog','待補送最多']].map(([v,l])=>`<option value="${v}" ${fleetSort===v?'selected':''}>${l}</option>`).join('')}</select>${user.role==='admin'?'<button class="secondary" data-select-page>選取本頁</button><button class="secondary" data-select-clear>清除選取</button>':''}`);return wrapper.innerHTML;};
document.addEventListener('change',e=>{if(e.target.id==='fleet-health'||e.target.id==='fleet-sort'){if(e.target.id==='fleet-health')fleetHealth=e.target.value;else fleetSort=e.target.value;fleetPage=0;reloadFleetRows();}});
document.addEventListener('click',e=>{if(e.target.closest('[data-select-page]')){for(const d of fleetResult?.items||[])if(fleetSelection.size<200)fleetSelection.add(d.id);render();}if(e.target.closest('[data-select-clear]')){fleetSelection.clear();render();}});
const contextRender=render;
render=function(){contextRender();if(user.role==='support')return;
  const device=state.devices.find(d=>d.id===contextDevice&&!d.revoked),group=state.groups.find(g=>g.id===fleetGroup);
  if(device||group){const banner=document.createElement('div');banner.className='notice context-banner';banner.innerHTML=`<strong>目前對象：${esc(device?device.name:group.path.join(' / '))}</strong><span>僅帶入查詢／指派對象；全域預設仍適用全所。</span><div class="actions"><button class="secondary" data-context-go="audit">查日誌</button><button class="secondary" data-context-go="policy">指派策略</button>${user.role==='admin'?'<button class="secondary" data-context-go="updates">更新 Agent</button>':''}<button class="text-button" data-context-clear>清除對象</button></div>`;$('#workspace').prepend(banner);}
  if(page==='updates'){const select=$('#update-job [name=target]');if(select&&!updatesDirty){const target=device?'device:'+device.id:group?'group:'+group.id:'';if(target)select.value=target;}}
  installColumnPreferences();
};
document.addEventListener('click',async e=>{try{if(e.target.closest('[data-context-clear]')){contextDevice='';fleetGroup='all';auditDevice='';offset=0;await refresh();}const button=e.target.closest('[data-context-go]');if(button){page=button.dataset.contextGo;offset=0;if(page==='audit')auditDevice=contextDevice;if(page==='policy'){policyTab='assignments';assignmentDraft={target_type:contextDevice?'device':'group',target_id:contextDevice||fleetGroup};}await refresh();}const group=e.target.closest('[data-action=fleet-group]');if(group){contextDevice='';fleetPage=0;render();reloadFleetRows();}}catch(error){toast(error.message);}});

let columnObserver=null;
function installColumnPreferences(){columnObserver?.disconnect();let saved={};try{saved=JSON.parse(localStorage.getItem('guarddesk.column-widths.v1')||'{}');}catch{}if(!saved||typeof saved!=='object'||Array.isArray(saved))saved={};columnObserver=new ResizeObserver(entries=>{for(const entry of entries){const header=entry.target,width=Math.round(entry.contentRect.width);if(header.dataset.ready==='1'&&width>=80&&width<=900)saved[header.dataset.columnKey]=width;header.dataset.ready='1';}try{localStorage.setItem('guarddesk.column-widths.v1',JSON.stringify(saved));}catch{}});for(const [tableIndex,table] of [...document.querySelectorAll('#workspace table')].entries()){for(const [index,header] of [...table.querySelectorAll('thead th')].entries()){const key=[page,table.className,tableIndex,index].join(':');header.dataset.columnKey=key;if(Number.isFinite(saved[key])&&saved[key]>=80&&saved[key]<=900)header.style.width=saved[key]+'px';columnObserver.observe(header);}}}
const contextShowLogin=showLogin;
showLogin=function(){contextDevice='';fleetGroup='all';fleetSelection.clear();fleetResult=null;eventCursors=[null];policyPublishDraft=null;templateDraft=null;historyData=null;columnObserver?.disconnect();contextShowLogin();};
