'use strict';
const fileAccessPrefix='@guarddesk:file-access:v1:',fileAccessProcess=fileAccessPrefix+'process:',fileAccessServices=fileAccessPrefix+'include-services',fileAccessAll=fileAccessPrefix+'include-background',fileAccessInterval=fileAccessPrefix+'interaction-seconds:';
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const labels = {overview:'安全總覽',devices:'端點裝置',policy:'安全策略',audit:'稽核事件',coverage:'功能與範圍',updates:'Agent 集中更新',software:'MSI 軟體派送'};
const kinds = {'device.enrolled':'端點完成註冊','device.revoked':'端點已撤銷','policy.published':'安全策略已發布','policy.applied':'端點回報策略版本','admin.login':'管理員登入','enrollment.created':'建立端點註冊碼','file.created':'發現新檔案','file.modified':'檔案內容或屬性變更（歷史）','file.deleted':'檔案已刪除','agent.started':'Agent 啟動','agent.scan_partial':'檔案掃描未完整','export.requested':'受控外發已提出','export.completed':'受控外發已完成','export.blocked':'策略已阻擋受控外發','export.failed':'受控外發寫入失敗'};
Object.assign(kinds,{'file.copy_candidate':'可能複製（讀寫關聯）','file.opened':'檔案存取（程序開啟／讀取）','file.open_requested':'檔案開啟請求','file.delete_requested':'檔案刪除請求','file.rename_from':'檔案重新命名前','file.rename_to':'檔案重新命名後','web.navigation':'網站瀏覽紀錄','network.upload':'網站傳出流量','network.proxy_error':'網站代理錯誤','agent.controls_status':'端點控制套用狀態','agent.audit_gap':'檔案稽核缺漏警示','agent.audit_unavailable':'Windows 稽核無法讀取','agent.audit_watch_failed':'原生目錄監看失敗','agent.audit_unresolved_delete':'無法還原刪除檔名'});
let user, state, events = {items:[],total:0}, page = 'overview', offset = 0, search = '', severity = '', busy = false, toastTimer;
const date = t => new Date(t * 1000).toLocaleString('zh-TW',{timeZone:'Asia/Taipei',hour12:false});
const relative = t => { const seconds = Math.max(0,Math.floor(Date.now()/1000-t)); return seconds<60 ? '剛剛' : seconds<3600 ? `${Math.floor(seconds/60)} 分鐘前` : seconds<86400 ? `${Math.floor(seconds/3600)} 小時前` : date(t); };
const status = d => `<span class="badge ${d.status==='online'?'good':d.status==='revoked'?'revoked':''}">${{online:'● 上線',offline:'○ 離線',revoked:'已撤銷'}[d.status]}</span>`;
const level = s => `<span class="badge ${s==='info'?'good':s}">${{info:'一般',warning:'注意',critical:'高風險'}[s] || esc(s)}</span>`;
function toast(message) { $('#toast').textContent=message; $('#toast').hidden=false; clearTimeout(toastTimer); toastTimer=setTimeout(()=>$('#toast').hidden=true,6500); }
async function api(path, body, signal) {
  const response = await fetch(path, {method:body===undefined?'GET':'POST',headers:body===undefined?{}:{'Content-Type':'application/json','X-CSRF-Token':user?.csrf || ''},body:body===undefined?undefined:JSON.stringify(body),signal});
  const value = await response.json();
  if (!response.ok) {
    if (response.status===401 && path!=='/api/login') showLogin();
    throw new Error(value.error || `請求失敗 (${response.status})`);
  }
  return value;
}
function showLogin() { refreshController?.abort();if(typeof auditExportController!=='undefined')auditExportController?.abort();queryAutoPaused=false;auditQueryFailed=false;search='';state=null;events={items:[],total:null,query_pending:true};refreshSerial++;busy=false;refreshAgain=false;renderedPage='';if(typeof auditSort!=='undefined'){auditSort='occurred';auditSortDirection='desc';}if(typeof auditReportDevice!=='undefined'){auditReportDevice=null;auditPerson=null;auditEndExclusive=false;} user=null; $('#shell').hidden=true; $('#login').hidden=false; $('#workspace').replaceChildren(); if(typeof archiveData!=='undefined')archiveData=null; if(typeof reportData!=='undefined')reportData=null; }
function showShell() { applyDefaultQueryDates(true); document.querySelectorAll('nav [data-page]').forEach(b=>b.hidden=(user.role==='support'&&b.dataset.page!=='remote')||(['updates','archives','mail','software'].includes(b.dataset.page)&&user.role!=='admin')); if(user.role==='support')page='remote'; else if(user.role!=='admin'&&['updates','archives','mail','software'].includes(page))page='overview'; $('#login').hidden=true; $('#shell').hidden=false; $('#user-name').textContent=user.username; $('#user-role').textContent=user.role==='admin'?'管理員':user.role==='support'?'遠端支援人員':'稽核員 · 唯讀'; }
function heading(eyebrow,title,description,action='') { return `<div class="page-heading"><div><p class="eyebrow">${eyebrow}</p><h1>${title}</h1><p>${description}</p></div>${action}</div>`; }
function enrollButton() { return user.role==='admin'?'<div class="actions"><button class="primary" data-action="endpoint-package">下載端點安裝包</button><button class="secondary" data-action="deployment-settings">部署碼管理</button></div>':''; }
async function deploymentDialog(){const d=await api('/api/deployment');dialog('共用部署碼管理',`<p>安裝包已包含 Server 位址及共用部署碼。新端點解壓後雙擊 <code>Setup-Endpoint.cmd</code>，自動註冊，由 MIS 核准 Windows UAC 即接續安裝，不必輸入註冊碼或 IP。</p><p class="help">同一部署碼可供多台註冊；每台取得獨立端點憑證。安裝包具有新增端點的權限，只交內部授權人員保管。Chrome／Edge 擴充仍須另行部署。</p><div class="notice">${d.active?'狀態：已啟用':d.created?'狀態：已停用，請重新產生後下載新版安裝包':'狀態：尚未建立；首次下載會自動建立'}${d.code?`<br>部署版本：${esc(d.code.id)}<br>此版本註冊台數：${d.code.uses}`:''}</div><p>停用或更換後，舊安裝包不能再註冊新端點；已註冊端點不受影響。更換後請重新下載並發放安裝包。</p><div class="actions"><button class="secondary" data-action="deployment-confirm" data-kind="rotate">更換／產生部署碼</button><button class="danger" data-action="deployment-confirm" data-kind="revoke" ${d.active?'':'disabled'}>停用部署碼</button></div>`);}
function card(title,subtitle,body,action='') { return `<section class="card"><div class="card-heading"><div><h2>${title}</h2>${subtitle?`<p>${subtitle}</p>`:''}</div>${action}</div>${body}</section>`; }
function empty(title,text) { return `<div class="empty"><strong>${title}</strong>${text}</div>`; }
function deviceTable(devices, compact=false) {
  if (!devices.length) return empty('尚未註冊端點','下載端點安裝包，交給同事解壓並執行 Setup-Endpoint.cmd。');
  return `<div class="table-wrap"><table><thead><tr><th>端點名稱</th><th>狀態</th><th>策略版本</th>${compact?'':'<th>最後心跳</th>'}<th></th></tr></thead><tbody>${devices.map(d=>`<tr><td><strong>${esc(d.name)}</strong></td><td>${status(d)}</td><td><span class="badge ${d.policy_received?'good':'warning'}">v${d.policy_version}</span><small>${d.policy_received?'已接收':'待接收 v'+(d.expected_version||state.generation)}</small></td>${compact?'':`<td>${esc(relative(d.last_seen))}<small>${date(d.last_seen)}</small></td>`}<td><button class="text-button" data-action="device" data-id="${esc(d.id)}">查看 →</button></td></tr>`).join('')}</tbody></table></div>`;
}
function timeline(items) {
  if (!items.length) return empty('尚無事件','Agent 連線後，檔案活動會顯示在這裡。');
  return `<div class="timeline">${items.map(e=>`<div class="event-line"><span class="event-dot">${e.severity==='critical'?'!':'↗'}</span><div><strong>${esc(kinds[e.kind]||e.kind)}</strong><p>${esc(e.device_name)}${e.details.path?' · '+esc(e.details.path):''}</p></div><time>${esc(relative(e.received))}</time></div>`).join('')}</div>`;
}
function overview() {
  const active=state.devices.filter(d=>!d.revoked), online=active.filter(d=>d.status==='online'), synced=active.filter(d=>d.policy_received).length;
  return heading('SECURITY OVERVIEW','安全總覽','掌握端點連線、策略同步與檔案活動。',enrollButton())+
    `<div class="stats"><div class="stat"><div class="stat-top">已納管端點<span class="stat-icon">▣</span></div><div class="stat-value">${active.length}</div><small><span class="good">${online.length} 台上線</span> · ${active.length-online.length} 台離線</small></div><div class="stat"><div class="stat-top">策略接收率<span class="stat-icon">⌘</span></div><div class="stat-value">${active.length?Math.round(synced/active.length*100):0}<small>%</small></div><small>${synced} / ${active.length} 台已接收目前有效設定</small></div><div class="stat"><div class="stat-top">近 24 小時警示<span class="stat-icon">◉</span></div><div class="stat-value">${state.stats.alerts_today}</div><small class="warn">含策略異動與外發風險紀錄</small></div><div class="stat"><div class="stat-top">受控外發阻擋<span class="stat-icon">◇</span></div><div class="stat-value">${state.stats.blocked}</div><small>自系統啟用以來累計</small></div></div>`+
    `<div class="grid">${card('端點狀態','每 30 秒心跳 · 90 秒未回報視為離線',deviceTable(state.devices.slice(0,5),true),'<button class="text-button" data-action="go" data-page="devices">查看全部 →</button>')}${card('全域預設摘要',`全域策略 · v${state.policy.version}`,`<div class="card-body"><div class="policy-summary"><div class="policy-shield">◇</div><div><h3>${state.policy.body.mode==='enforce'?'受控外發阻擋模式':'觀察模式'}</h3><p>${state.policy.body.mode==='enforce'?'命中規則時，外發指令停止寫入':'命中規則仍允許外發，留下風險紀錄'}</p></div></div><div class="key-row"><span>受控外發入口</span><strong>${state.policy.body.allow_export?'開放':'禁止'}</strong></div><div class="key-row"><span>敏感字詞 / 副檔名</span><strong>${state.policy.body.keywords.length} / ${state.policy.body.blocked_extensions.length} 項</strong></div><div class="key-row"><span>最後發布</span><strong>${date(state.policy.created)}</strong></div><button class="text-button" data-action="go" data-page="policy">查看策略設定 →</button></div>`)}</div>`+
    `<div class="grid">${card('最近安全事件','依管理中心接收時間排序',timeline(events.items.slice(0,5)),'<button class="text-button" data-action="go" data-page="audit">開啟稽核紀錄 →</button>')}${card('事件概況',`最近 ${events.items.length} 筆已載入事件`, `<div class="card-body">${['info','warning','critical'].map(s=>{const count=events.items.filter(e=>e.severity===s).length;return `<div class="bar-row"><span>${{info:'一般事件',warning:'注意事件',critical:'高風險事件'}[s]}</span><progress max="${Math.max(events.items.length,1)}" value="${count}"></progress><b>${count}</b></div>`;}).join('')}<div class="key-row"><span>稽核事件總數</span><strong>${state.stats.events}</strong></div><button class="text-button" data-action="integrity">驗證稽核鏈完整性 →</button></div>`)}</div>`+
    '<div class="notice"><strong>目前保護範圍：</strong>已加入 USB 儲存策略、Windows 檔案事件、Chrome／Edge 網址稽核及上傳限速。需在端點完成原生控制安裝；0.4.12 一般網頁日誌免擴充，網站限速仍需擴充／代理；收集器實際狀態見端點明細。</div>';
}
function flatDevices() { return heading('ENDPOINT FLEET','端點裝置','查看真實 Agent 回報的資產與策略同步狀態。',enrollButton())+card('納管清單',`${state.devices.length} 台紀錄 · 含已撤銷端點`,deviceTable(state.devices))+ '<div class="notice">撤銷後，端點憑證立即無法使用管理中心 API；該 Agent 的受控外發也會停止。撤銷不會遠端移除程式或刪除使用者檔案。</div>'; }
function exportFields(p) {
  return `<label>執行模式<select name="mode"><option value="monitor" ${p.mode==='monitor'?'selected':''}>觀察模式 — 記錄風險並允許外發</option><option value="enforce" ${p.mode==='enforce'?'selected':''}>阻擋模式 — 命中任一規則即禁止外發</option></select></label><label class="toggle-label">允許使用受控外發入口<input name="allow_export" type="checkbox" ${p.allow_export?'checked':''}></label><label>禁止外發的副檔名<input name="extensions" value="${esc(p.blocked_extensions.join(', '))}" placeholder=".pem, .key"></label><p class="help">以逗號分隔，例如 .key。空白代表不限制副檔名。</p><label>敏感字詞<textarea name="keywords" rows="4" placeholder="每行一個字詞">${esc(p.keywords.join('\n'))}</textarea></label><p class="help">僅掃描 UTF-8 / UTF-16 純文字；不解析 PDF、Office、壓縮檔或影像內容。</p><label>單檔外發上限（MB）<input name="max_export_mb" type="number" min="1" max="10" value="${p.max_export_mb}" required></label>`;
}
function exportPolicy(policyBody=state.policy.body) {
  const p=policyBody, readonly=user.role!=='admin';
  return heading('POLICY CENTER','安全策略','發布全域策略；Agent 下一次心跳取得版本後回報接收狀態。',`<span class="hero-status"><span class="dot"></span>目前版本 v${state.policy.version}</span>`)+
    `<form id="policy-form"><div class="form-grid"><section class="card form-card"><h2>受控外發規則</h2><p class="help">設定適用於 GuardDesk export 指令的檢查規則。</p><fieldset ${readonly?'disabled':''}>${exportFields(p)}</fieldset><div class="form-actions"><span class="${readonly?'read-only':'help'}">${readonly?'稽核員僅能檢視策略':'發布將保留新版本與操作紀錄'}</span>${readonly?'':'<button class="primary" type="submit">發布策略 →</button>'}</div></section><div>${card('策略如何生效','從管理中心到端點',`<div class="card-body"><div class="key-row"><span>01 發布策略</span><strong>建立不可覆寫的新版本</strong></div><div class="key-row"><span>02 Agent 心跳</span><strong>取得並儲存最新策略</strong></div><div class="key-row"><span>03 下次回報</span><strong>確認端點已接收</strong></div><div class="key-row"><span>04 執行外發</span><strong>即時連線再檢查規則</strong></div><p class="help">連線中斷或憑證撤銷時，受控外發停止。本機檔案稽核仍保留在佇列，待連線後補送。</p></div>`)}<div class="notice"><strong>模式說明：</strong>觀察模式會允許命中規則的檔案外發。若要實際阻擋，請選擇阻擋模式。所有規則都只作用於 GuardDesk 受控外發入口。</div></div></div></form>`;
}
function uploadRow(rule={type:'domain',target:'',rate_kbps:1000}) {
  return `<tr class="upload-rule"><td><select aria-label="限制類型" class="rule-type">${[['domain','網站／網域'],['app','應用程式'],['user','使用者']].map(([value,label])=>`<option value="${value}" ${rule.type===value?'selected':''}>${label}</option>`).join('')}</select></td><td><input class="rule-target" aria-label="限制目標" value="${esc(rule.target)}" placeholder="example.com／app.exe／DOMAIN\\user" required></td><td><input class="rule-rate" aria-label="上傳速率 Kbit/s" type="number" min="8" max="10000000" value="${rule.rate_kbps}" required></td><td><button type="button" class="text-button" data-action="rule-remove">移除</button></td></tr>`;
}
function endpointModuleFields(p) {
  const developmentRule='@guarddesk:development-cache:v1',hiddenRule='@guarddesk:hidden-files:v1';
  return {
    usb: `<label>USB 儲存裝置<select name="usb_mode"><option value="allow" ${p.usb_mode==='allow'?'selected':''}>允許（還原既有公司基準）</option><option value="read_only" ${p.usb_mode==='read_only'?'selected':''}>唯讀 — 禁止寫入</option><option value="block" ${p.usb_mode==='block'?'selected':''}>禁止讀取與寫入</option></select></label><p class="help">針對 Windows 可卸除磁碟類別；需要管理員安裝及 Agent 權限，既有連線可能需要重新插拔或重新開機。</p>`,
    files: `<label class="toggle-label">檔案開啟／新增／刪除／移動與重新命名稽核<input type="checkbox" name="file_audit_enabled" ${p.file_audit.enabled?'checked':''}></label><p class="help">原生元件 0.4.51 起，讀取與複製候選直接沿用本項的範圍與額外排除路徑，不必另建自訂設定。讀取紀錄不代表人工閱讀；同程序同次開啟合併一次，收集狀態與缺漏可在端點明細查看。</p><label>稽核範圍<select name="file_audit_scope"><option value="all_local" ${p.file_audit.scope==='all_local'?'selected':''}>所有本機固定磁碟（排除系統／開機）</option><option value="managed" ${p.file_audit.scope==='managed'?'selected':''}>僅註冊時指定的資料夾</option></select></label><label class="toggle-label">排除開發工具產物與快取<input type="checkbox" name="exclude_development" ${p.file_audit.exclude_paths.includes(developmentRule)?'checked':''}></label><p class="help">由 MIS 指派給資訊人員／開發機群組或單一端點。只排除 node_modules、.git、.venv、__pycache__ 等明確目錄及 pip／npm／NuGet／Cargo 快取；不依副檔名猜測，不自動排除整個 AppData、build、dist 或專案原始碼。要連原始碼也不收，可在下方填入專案根目錄。</p><label class="toggle-label">排除隱藏檔案／資料夾<input type="checkbox" name="exclude_hidden" ${p.file_audit.exclude_paths.includes(hiddenRule)?'checked':''}></label><p class="help">需一般 Agent 與原生元件 0.4.57。依 Windows 隱藏屬性排除檔案及隱藏資料夾內的普通檔案活動；檔名前有 . 不等於隱藏檔。預設不勾選，避免漏記刻意設為隱藏的文件。跨排除邊界移動、網站上傳與安全告警保留；刪除後無屬性證據、權限不足或查詢達上限時保留紀錄，不猜測。屬性快取最多 2 秒，不回溯刪除歷史。</p><label class="toggle-label">排除系統服務的背景開啟／讀取（建議）<input type="checkbox" name="exclude_file_services" ${!p.file_audit.exclude_paths.includes(fileAccessServices)?'checked':''}></label><label>文件開啟記錄方式<select name="file_access_mode"><option value="interactive" ${!p.file_audit.exclude_paths.includes(fileAccessAll)?'selected':''}>最近輸入與前景程式關聯（建議）</option><option value="all" ${p.file_audit.exclude_paths.includes(fileAccessAll)?'selected':''}>完整程序存取（診斷）</option></select></label><label>最近輸入有效秒數（5～600）<input name="file_access_seconds" type="number" min="5" max="600" step="1" value="${esc((p.file_audit.exclude_paths.find(path=>path.startsWith(fileAccessInterval))||fileAccessInterval+'30').slice(fileAccessInterval.length))}"></label><p class="help">需原生元件 0.4.54。互動模式排除鎖定、離席與無前景關聯的普通存取；收集最後輸入時間與前景程序，不收按鍵或畫面。無法取得情境會明示能力不足。互動關聯不代表已證明人工閱讀。同次開啟合併，不再每 60 秒重複；新輸入後重開另記。刪除、上傳與安全告警保留。</p><label>不記錄檔案開啟／讀取的程式（每行一個）<textarea name="file_read_processes" rows="3" placeholder="OneDrive.exe 或完整程式路徑">${esc(p.file_audit.exclude_paths.filter(path=>path.startsWith(fileAccessProcess)).map(path=>path.slice(fileAccessProcess.length)).join('\n'))}</textarea></label><p class="help">需原生元件 0.4.53；以已確認的 Session 0 程序排除系統／服務背景讀取，GuardDesk 收集器自身存取及目錄查詢不列成文件開啟。程式排除只影響開啟／讀取，不影響檔案異動、網站上傳、安全事件或程式執行；檔名規則可能被改名規避，可改用精確路徑。記事本、Word 等互動程式仍保留程序證據，不代表每一筆都是員工手動操作。</p><label>額外排除資料夾／檔案的完整路徑（每行一個）<textarea name="file_excludes" rows="3">${esc(p.file_audit.exclude_paths.filter(path=>path!==developmentRule&&path!==hiddenRule&&!path.startsWith('@guarddesk:file-access:')).join('\n'))}</textarea></label><p class="help">填完整路徑，例如 C:\\Dev 或 D:\\Projects；支援 C:\\Users\\{user}\\workspace；{user} 代表該位置的一層使用者資料夾，可涵蓋各帳號，不是目前登入者。僅可出現一次且須獨立成目錄；不支援 *、?、%USERPROFILE% 或 ..。排除整個 C:\\Users\\{user} 會包含桌面、文件與下載。Server 0.4.31 起支援此寫法；Agent 升至 0.4.31 才能在來源停收。只影響檔案操作日誌；一般文件、應用程式啟停、網頁、外發與安全事件依各自設定保留。跨排除範圍的移動仍記錄兩端路徑。Server 0.4.26 起會過濾新到達的排除事件；端點更新至 0.4.26 才能在來源停收開發快取，歷史日誌保留。</p>`,
    browser: `<label class="toggle-label">記錄瀏覽網站、網址與時間<input name="browser_audit" type="checkbox" ${p.browser_audit?'checked':''}></label><p class="help">一般 Agent 0.4.12 起自動收集 Chrome／Edge 已保存的一般瀏覽紀錄，不需另裝擴充。記錄時間、標題、網址路徑與查詢字串，敏感憑證參數遮蔽；不涵蓋無痕、不擷取 HTTPS 內容。Agent 0.4.22 配合另行部署的擴充 0.3.0，可額外記錄瀏覽器提供的上傳檔案路徑與 HTTP 結果；只有檔名時標示候選，不能保證涵蓋所有網站。</p>`,
    apps: applicationAuditFields(p),
    appcontrol: applicationControlFields(p),
    website: websiteFields(p),
    upload: `<p class="help">速率單位為 Kbit/s（1 Mbit/s = 1000 Kbit/s）。網站用本機代理；應用程式及使用者用 Windows QoS。可同時設定三種類型。</p><div class="table-wrap"><table class="rule-table"><thead><tr><th>類型</th><th>目標</th><th>Kbit/s</th><th></th></tr></thead><tbody id="upload-rules">${p.upload_rules.map(uploadRow).join('')}</tbody></table></div><button class="secondary" type="button" data-action="rule-add">＋ 新增限制</button><p class="help">網域例如 example.com 或 *.example.com；應用程式例如 OneDrive.exe；使用者請填 DOMAIN\\account。Windows 規則接收成功不代表已套用，請查看端點明細的收集器狀態。</p>`
  };
}
function endpointFields(p) {
  const fields=endpointModuleFields(p);
  return `<hr><h2>Windows 端點控制</h2>${fields.usb}${fields.files}${fields.browser}<hr><h2>應用程式啟停稽核</h2>${fields.apps}<hr><h2>應用程式執行管制</h2>${fields.appcontrol}<hr><h2>網站存取管制</h2>${fields.website}<hr><h2>上傳流量限制</h2>${fields.upload}`;
}
function baselinePolicy() {
  return exportPolicy().replace('</fieldset>',endpointFields(state.policy.body)+'</fieldset>').replace('所有規則都只作用於 GuardDesk 受控外發入口。','外發檔案規則作用於 export 指令；USB、Windows 稽核與 QoS 是獨立的系統控制，需完成端點安裝。網站限速需瀏覽器擴充。').replace('設定適用於 GuardDesk export 指令的檢查規則。','檔案外發、USB、檔案／上網稽核與三種類型的上傳限制。');
}
function baseAudit() {
  const rows=events.items;
  return heading('AUDIT EXPLORER','稽核事件','搜尋檔案活動與管理操作，匯出可追溯的稽核紀錄。','<button class="secondary" data-action="integrity">◇ 驗證完整性</button>')+
    `<section class="card"><form id="search-form" class="toolbar"><input name="q" aria-label="搜尋事件" placeholder="搜尋事件、檔名、端點…" value="${esc(search)}"><select name="severity" aria-label="風險等級"><option value="">所有等級</option>${['info','warning','critical'].map(s=>`<option value="${s}" ${severity===s?'selected':''}>${{info:'一般',warning:'注意',critical:'高風險'}[s]}</option>`).join('')}</select><button class="secondary">搜尋</button><button class="secondary" type="button" data-action="csv">↓ 匯出 CSV</button></form>${rows.length?`<div class="table-wrap"><table><thead><tr><th>接收時間（台北）</th><th>端點</th><th>事件</th><th>等級</th><th></th></tr></thead><tbody>${rows.map(e=>`<tr><td>${date(e.received)}<small>#${e.id}</small></td><td>${esc(e.device_name)}</td><td><strong>${esc(kinds[e.kind]||e.kind)}</strong><small>${esc(e.details.path||e.details.url||e.details.domain||e.kind)}</small></td><td>${level(e.severity)}</td><td><button class="text-button" data-action="event" data-id="${e.id}">明細 →</button></td></tr>`).join('')}</tbody></table></div>`:empty('沒有符合條件的事件','可調整搜尋字詞或風險等級。')}<div class="pagination"><span>共 ${events.total} 筆 · ${events.total?offset+1:0}–${Math.min(offset+rows.length,events.total)}</span><div><button class="secondary" data-action="prev" ${offset===0?'disabled':''}>上一頁</button><button class="secondary" data-action="next" ${offset+rows.length>=events.total?'disabled':''}>下一頁</button></div></div></section><p class="help">CSV 依目前搜尋條件匯出，單次最多 5,000 筆。稽核鏈可偵測紀錄變動；尚未提供獨立儲存的防竄改錨點。</p>`;
}
const modules = [
 ['基本策略管控','已實作核心','註冊、心跳、全域版本策略、憑證撤銷。',true],['資產管理','部分實作','作業系統、磁碟、CPU 數與 Windows 軟體登錄盤點。',true],['文檔操作管控','Windows 原生整合','目錄通知與 Security 事件；排除系統／啟動路徑，具缺漏警示與離線補送。',true],['報表管理','部分實作','事件篩選、CSV 匯出及 M365 每日檔案異動報表。',true],['移動儲存管控','已加入適配器','可卸除磁碟允許／唯讀／禁用。需管理員安裝，插拔實機驗收待完成。',true],['設備管控','尚未實作','需要裝置類別與驅動整合。'],['應用程式管控','AppLocker 試用適配器','EXE／MSI 黑白名單與程序啟停日誌；需更新背景工作及實際阻擋驗收。',true],['遠端協助','逐次同意的試用功能','指定人員／端點授權；一般桌面檢視與操作，真實雙機驗收待完成。',true],['網頁瀏覽管控','Chrome／Edge 整合','0.4.12 起免擴充收集已保存的一般瀏覽紀錄；時間、帳號、標題及網址離線補送。不涵蓋無痕、未保存或讀取前已刪除資料。',true],['網路流量管控','已加入三種規則','網站代理、程式／使用者 Windows QoS。生效需安裝與權限，實機吞吐驗收待完成。',true],['網路管控','尚未實作','需防火牆策略、隔離與衝突處理。'],['列印管控','尚未實作','需列印佇列與內容擷取整合。'],['螢幕監視','尚未實作','需明示告知、授權與保留規則。'],['遠端維護','尚未實作','需受授權連線與操作稽核。'],['郵件管控','尚未實作','需郵件閘道或用戶端整合。'],['即時通訊管控','尚未實作','需逐一評估支援範圍與應用程式整合。'],['文檔雲端備份','尚未實作','需集中備份、版本與還原驗證。'],['文件加密（V+）','部分實作','CLI AES-256-GCM 封裝與還原；非透明加密。',true]
];
function coverage() { return heading('CAPABILITY MAP','功能與範圍','依公開產品資料建立模組對照，清楚標示本版交付範圍。')+'<div class="notice"><strong>本版定位：</strong>Windows 10／11、1–20 台的內部功能試用。公開網站分析無法證明原廠內部實作；本系統為獨立實作。完整 REA 證據、架構與後續驗收條件見專案 doc/。</div>'+`<div class="module-grid">${modules.map(m=>`<article class="module"><span class="badge ${m[3]?'good':''}">${m[1]}</span><h3>${m[0]}</h3><p>${m[2]}</p></article>`).join('')}</div><p class="help">來源：<a href="https://www.tecsols.com/products/endpoint/modules/" target="_blank" rel="noreferrer">原廠端點模組一覽</a> · <a href="https://www.tecsols.com/products/encryption/features/" target="_blank" rel="noreferrer">文件加密功能一覽</a></p>`; }
function render() {
  renderedPage=page;
  $('#breadcrumb').textContent=labels[page];
  document.querySelectorAll('nav button').forEach(b=>b.classList.toggle('active',b.dataset.page===page));
  $('#nav-count').textContent=state.devices.filter(d=>!d.revoked).length;
  $('#workspace').innerHTML=({overview,devices,policy,audit,coverage,updates:updatesPage,software:softwarePage,remote:remotePage,reports:reportsPage,archives:archivesPage,custom:customSettingsPage,mail:mailReportsPage,categories:categoriesPage})[page]();
  if(page==='categories')bindCategories();
  if(page==='custom')bindCustomSettings();
  if(page==='mail')bindMailReports();
  if(page==='remote')bindRemote();
  $('#policy-form')?.addEventListener('submit',savePolicy);
  if(typeof bindManagement==='function')bindManagement();
  if(page==='updates')bindUpdates();if(page==='software')bindSoftware();
  if(page==='reports'||page==='archives')bindReports();
  $('#search-form')?.addEventListener('submit',async event=>{event.preventDefault();const f=new FormData(event.target);search=f.get('q');severity=f.get('severity');auditDevice=f.get('device')||'';auditKind=f.get('kind')||'';auditStart=f.get('start')||'';auditEnd=f.get('end')||'';auditEndExclusive=true;auditDateMode='custom';offset=0;await refresh();});
}
let refreshAgain=false,renderFingerprint='',renderedPage='',refreshSerial=0,refreshController=null,refreshKey='',queryAutoPaused=false,auditQueryFailed=false;
function queryFormValues(){const form=$('#search-form')||$('#report-form');return form?{id:form.id,values:[...new FormData(form)]}:null;}
function restoreQueryDraft(draft){if(!draft)return;const form=$('#'+draft.id);if(!form)return;for(const [name,value] of draft.values){const control=form.elements.namedItem(name);if(control&&(!control.options||[...control.options].some(o=>o.value===value)))control.value=value;}}
function queryFeedback(serial,cancel){
  const form=$('#search-form')||$('#report-form');if(!form)return ()=>{};
  $('#query-feedback')?.remove();const node=document.createElement('div');node.id='query-feedback';node.className='query-feedback';node.setAttribute('role','status');node.setAttribute('aria-live','polite');
  node.innerHTML='<span class="query-spinner" aria-hidden="true"></span><div><strong>查詢中…</strong><span data-query-elapsed></span><small data-query-description>完成前下方仍是上次查詢結果，可取消等待或切換其他頁面。</small></div><button type="button" class="secondary" data-query-cancel>取消等待</button>';
  if(events.query_pending){node.querySelector('[data-query-description]').textContent='正在準備查詢結果，可取消等待或切換其他頁面。';const placeholder=$('[data-query-empty]');if(placeholder)placeholder.textContent='正在準備查詢結果…';}
  form.after(node);$('#workspace').setAttribute('aria-busy','true');node.dataset.serial=String(serial);node.querySelector('[data-query-cancel]').onclick=cancel;
  const submit=form.querySelector('button:not([type]),button[type=submit]'),label=submit?.dataset.queryLabel||submit?.textContent;if(submit){submit.dataset.queryLabel=label;submit.disabled=true;submit.textContent='查詢中…';}
  for(const button of document.querySelectorAll('#workspace .pagination button,#workspace [data-report-chart],#workspace [data-report-prev],#workspace [data-report-next],#workspace button[data-report-person],#search-form [data-action=csv],#workspace [data-audit-sort]'))button.disabled=true;
  const start=performance.now(),tick=()=>{node.querySelector('[data-query-elapsed]').textContent=`已等待 ${Math.floor((performance.now()-start)/1000)} 秒`;};tick();const timer=setInterval(tick,1000);
  const finish=outcome=>{clearInterval(timer);if(node.dataset.serial!==String(refreshSerial))return;$('#workspace').removeAttribute('aria-busy');for(const b of document.querySelectorAll('[data-audit-sort]'))b.disabled=false;if(submit){submit.disabled=false;submit.textContent=label;delete submit.dataset.queryLabel;}
    if(outcome&&node.isConnected){node.classList.add('query-incomplete');node.setAttribute('role','alert');node.replaceChildren();const text=document.createElement('span');text.textContent=outcome+(events.query_pending?' 請調整條件後搜尋，或清除關鍵字。':' 下方仍是上次查詢結果，請重新搜尋。');node.append(text);}
    else node.remove();
  };
  finish.index=value=>{if(!node.isConnected)return;node.querySelector('strong').textContent=value.purpose==='sort'?'準備欄位排序索引中…':'建立搜尋索引中…';node.querySelector('[data-query-description]').textContent=`背景已建立 ${Number(value.indexed_rows).toLocaleString()} 筆索引，優先處理新資料並補齊歷史；收件忙碌時會暫緩。完成後自動查詢一次，可取消或切換頁面。`;};return finish;
}
async function refresh(options={}) {
  const automatic=options.automatic===true;
  if(automatic&&page==='software')return;
  if (!user) return;
  if(automatic&&((page==='audit'&&(search||auditSort!=='occurred'||auditSortDirection!=='desc'||auditExportController))||(queryAutoPaused&&['audit','reports'].includes(page))))return;
  if(automatic&&page==='custom'&&typeof libraryEditor!=='undefined'&&libraryEditor)return;
  if(automatic&&page==='mail'&&typeof mailDraft!=='undefined'&&mailDraft)return;
  if(automatic&&(document.hidden||document.activeElement?.closest('#workspace input,#workspace textarea,#workspace select')||$('#workspace details[open]')))return;
  if(user.role==='support')page='remote';
  applyDefaultQueryDates();
  const requestedPage=page,query=auditQuery(false),reportQuery=reportQueryString(),requestUser=user;
  const updateQuery=requestedPage==='updates'?updatesQueryString():'';
  const key=JSON.stringify([requestedPage,query,reportQuery,updateQuery,requestedPage==='categories'?categoryPath():'']);
  if(busy&&key===refreshKey){if(!automatic&&!['audit','reports'].includes(requestedPage))refreshAgain=true;return;}
  if(busy){refreshController?.abort();refreshAgain=false;}
  const serial=++refreshSerial;refreshKey=key;refreshController=new AbortController();const signal=refreshController.signal;busy=true;
  $('#workspace').removeAttribute('aria-busy');$('#query-feedback')?.remove();
  if(renderedPage!==page){if(page==='audit'){state=state||{devices:[],groups:[]};events={items:[],total:null,has_more:false,query_pending:true};render();}else{renderedPage=page;$('#breadcrumb').textContent=labels[page];document.querySelectorAll('nav button').forEach(b=>b.classList.toggle('active',b.dataset.page===page));$('#workspace').innerHTML=heading('',esc(labels[page]),'')+'<section class="card"><div class="card-body" role="status" aria-live="polite">正在載入資料…</div></section>';}}
  const isQuery=['audit','reports'].includes(requestedPage),controller=refreshController,initialDraft=isQuery?queryFormValues():null;
  if(!automatic){queryAutoPaused=false;if(requestedPage==='audit')auditQueryFailed=false;}
  const requestID=requestedPage==='audit'&&!automatic?[...crypto.getRandomValues(new Uint8Array(16))].map(n=>n.toString(16).padStart(2,'0')).join(''):'';
  let cancelled=false,timedOut=false,incomplete='',queryActive=true,timeout=null;
  signal.addEventListener('abort',()=>{if(queryActive&&requestID)fetch('/api/audit/search/cancel',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':requestUser.csrf},body:JSON.stringify({request_id:requestID}),keepalive:true}).catch(()=>{});},{once:true});
  const finishFeedback=isQuery&&!automatic?queryFeedback(serial,()=>{cancelled=true;controller.abort();}):()=>{};
  const armTimeout=()=>{if(timeout)clearTimeout(timeout);if(isQuery)timeout=setTimeout(()=>{timedOut=true;controller.abort();},20000);};armTimeout();
  const loadEvents=async()=>{const q=new URLSearchParams(query);if(requestID)q.set('request_id',requestID);const start=performance.now();for(;;){const result=await api('/api/events?'+q,undefined,signal);if(!result.search_pending)return result;if(result.search_cursor)q.set('cursor',result.search_cursor);if(result.search_index.error)throw new Error(result.search_index.error);if(performance.now()-start>600000)throw new Error('搜尋索引仍在背景準備，請稍後再查詢。');finishFeedback.index?.(result.search_index);armTimeout();await new Promise((resolve,reject)=>{const abort=()=>{clearTimeout(timer);reject(new DOMException('Aborted','AbortError'));};const timer=setTimeout(()=>{signal.removeEventListener('abort',abort);resolve();},1000);signal.addEventListener('abort',abort,{once:true});if(signal.aborted)abort();});}};
  try {
    const extraPath=({software:'/api/software',remote:'/api/remote/catalog',updates:'/api/updates?'+updateQuery,reports:'/api/audit/summary?'+reportQuery,archives:'/api/audit/exports',custom:'/api/custom-library',mail:'/api/mail-reports',categories:categoryPath(),policy:'/api/categories'})[requestedPage];
    const [s,e,extra]=await Promise.all([
      user.role==='support'?Promise.resolve(null):api('/api/state?compact=1'+(requestedPage==='overview'?'':'&stats=0'),undefined,signal).then(s=>{if(s&&serial===refreshSerial&&requestedPage==='audit'){state={...s,stats:s.stats??state?.stats};const select=$('#search-form [name=device]');if(select)for(const device of s.devices)if(![...select.options].some(o=>o.value===device.id))select.add(new Option(device.name,device.id,false,device.id===auditDevice));}return s;}),
      ['overview','audit'].includes(requestedPage)?loadEvents():Promise.resolve(events),
      extraPath?api(extraPath,undefined,signal):Promise.resolve(null)]);
    if(serial!==refreshSerial||user!==requestUser)return;
    if(requestedPage==='categories'||requestedPage==='policy')categoryData=extra;
    if(requestedPage==='custom')customData=extra;if(requestedPage==='mail')mailData=extra;
    if(requestedPage==='software')softwareData=extra;if(requestedPage==='remote')remoteData=extra;if(requestedPage==='updates')updatesData=extra;if(requestedPage==='reports')reportData=extra;if(requestedPage==='archives')archiveData=extra;
    if(user.role==='support'){state={devices:remoteData.devices};$('#connection').textContent='● 已連線';render();return;}
    if(user!==requestUser)return;
    if(requestedPage!==page||query!==auditQuery(false)||(requestedPage==='reports'&&reportQuery!==reportQueryString())||(requestedPage==='updates'&&updateQuery!==updatesQueryString())){refreshAgain=true;return;}
    if(requestedPage==='updates'&&updatesData.progress)updatesPageNumber=updatesData.progress.page;
    state={...s,stats:s.stats??state?.stats}; events=e;if(requestedPage==='devices'&&typeof loadFleet==='function')await loadFleet();if(serial!==refreshSerial)return; $('#connection').textContent='● 已連線';
    // A response may arrive after the user starts editing. Do not replace
    // focused controls or an expanded audit row during automatic refresh.
    if(automatic&&(document.activeElement?.closest('#workspace input,#workspace textarea,#workspace select')||$('#workspace details[open]')))return;
    const fingerprint=JSON.stringify([page,{...s,server_time:undefined},e,page==='updates'?updatesData:page==='reports'?reportData:page==='archives'?archiveData:page==='custom'?customData:page==='mail'?mailData:page==='categories'||page==='policy'?categoryData:null]);
    if(!automatic||fingerprint!==renderFingerprint){const y=window.scrollY,currentDraft=isQuery?queryFormValues():null,draft=initialDraft&&JSON.stringify(currentDraft)!==JSON.stringify(initialDraft)?currentDraft:null,updateDraft=requestedPage==='updates'?captureUpdatesDraft():null;render();restoreQueryDraft(draft);if(requestedPage==='updates')restoreUpdatesDraft(updateDraft);if(automatic)window.scrollTo(0,y);renderFingerprint=fingerprint;}
  } catch(error) {if(serial===refreshSerial){
      incomplete=timedOut?'查詢等待逾時，請縮小日期或指定端點後重試。':cancelled?'已取消等待。':error.name!=='AbortError'?error.message:'';
      if(incomplete&&!signal.aborted)controller.abort();
      if(incomplete){if(isQuery){queryAutoPaused=true;if(requestedPage==='audit')auditQueryFailed=true;const placeholder=$('[data-query-empty]');if(placeholder)placeholder.textContent='本次查詢未完成，請修改條件或清除關鍵字。';}$('#connection').textContent=isQuery?'○ 查詢未完成':'○ 連線失敗';toast(incomplete);if(isQuery&&!$('#search-form')&&!$('#report-form')){const status=$('#workspace [role=status]');if(status){status.setAttribute('role','alert');status.textContent=incomplete;}}}
    }} finally {queryActive=false;if(timeout)clearTimeout(timeout);finishFeedback(incomplete);if(serial===refreshSerial){busy=false;if(refreshAgain){refreshAgain=false;queueMicrotask(()=>refresh());}}}
}
function dialog(title, content, wide=false) { $('#dialog').classList.toggle('wide',wide); $('#dialog-content').innerHTML=`<h2>${esc(title)}</h2>${content}`; if(!$('#dialog').open) $('#dialog').showModal(); }
function readPolicyForm(form) {
  const f=new FormData(form);
  return {mode:f.get('mode'),allow_export:f.has('allow_export'),blocked_extensions:(f.get('extensions')||'').split(/[,，]/).map(s=>s.trim()).filter(Boolean),keywords:(f.get('keywords')||'').split('\n').map(s=>s.trim()).filter(Boolean),max_export_mb:Number(f.get('max_export_mb')),usb_mode:f.get('usb_mode'),file_audit:{enabled:f.has('file_audit_enabled'),scope:f.get('file_audit_scope'),exclude_paths:[...new Set([...(f.get('file_excludes')||'').split('\n').map(s=>s.trim()).filter(Boolean),...(f.has('exclude_development')?['@guarddesk:development-cache:v1']:[]),...(f.has('exclude_hidden')?['@guarddesk:hidden-files:v1']:[]),...(f.has('exclude_file_services')?[]:[fileAccessServices]),...(f.get('file_access_mode')==='all'?[fileAccessAll]:[]),fileAccessInterval+String(Number(f.get('file_access_seconds')||30)),...(f.get('file_read_processes')||'').split('\n').map(s=>s.trim()).filter(Boolean).map(s=>fileAccessProcess+s)])]},browser_audit:f.has('browser_audit'),application_audit:f.has('application_audit'),application_audit_exclusions:(f.get('application_audit_exclusions')||'').split('\n').map(s=>s.trim()).filter(Boolean),application_control:{enabled:f.has('app_control_enabled'),mode:f.get('app_control_mode')||'denylist',block_msi:f.has('app_block_msi'),rules:Array.from(form.querySelectorAll('.application-rule')).map(row=>({name:row.querySelector('.app-name').value.trim(),collection:row.querySelector('.app-collection').value,type:row.querySelector('.app-type').value,value:row.querySelector('.app-value').value.trim()}))},application_publishers:structuredClone((form.id==='set-form'?selectedEditorSet()?.overrides?.application_publishers:state.policy.body.application_publishers)||[]),website_control:{enabled:f.has('website_enabled'),browsers:['chrome','edge'].filter(b=>f.has('website_'+b)),blocked:[...new Set((f.get('website_blocked')||'').split('\n').map(s=>s.trim().toLowerCase()).filter(Boolean))],allowed:[...new Set((f.get('website_allowed')||'').split('\n').map(s=>s.trim().toLowerCase()).filter(Boolean))]},upload_rules:Array.from(form.querySelectorAll('.upload-rule')).map(row=>({type:row.querySelector('.rule-type').value,target:row.querySelector('.rule-target').value.trim(),rate_kbps:Number(row.querySelector('.rule-rate').value)}))};
}
async function savePolicy(event) {
  event.preventDefault(); const f=new FormData(event.target), button=event.target.querySelector('button[type="submit"]');button.disabled=true;
  const body=readPolicyForm(event.target);
  try {const p=await api('/api/policy',{base_version:state.policy.version,body});toast(`策略 v${p.version} 已發布，等待端點同步`);await refresh();}catch(error){toast(error.message);button.disabled=false;}
}
document.addEventListener('click', async event=>{
  const nav=event.target.closest('nav [data-page]');if(nav){if(remoteSession&&nav.dataset.page!=='remote')await stopRemoteSession();if(nav.dataset.page==='audit'&&auditQueryFailed){search='';auditSort='occurred';auditSortDirection='desc';queryAutoPaused=false;auditQueryFailed=false;}page=nav.dataset.page;offset=0;return refresh();}
  const b=event.target.closest('[data-action]');if(!b || b.disabled)return;
  const action=b.dataset.action;
  try {
    if(action==='rule-add'){$('#upload-rules').insertAdjacentHTML('beforeend',uploadRow());return;}
    if(action==='rule-remove'){b.closest('tr').remove();return;}
    if(action==='go'){if(b.dataset.page==='audit'&&auditQueryFailed){search='';auditSort='occurred';auditSortDirection='desc';queryAutoPaused=false;auditQueryFailed=false;}page=b.dataset.page;offset=0;await refresh();}
    if(action==='endpoint-package') {b.disabled=true;toast('正在製作端點安裝包，請稍候');const response=await fetch('/api/endpoint-package',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':user.csrf},body:'{}'});if(!response.ok){const value=await response.json();throw new Error(value.error||'安裝包下載失敗');}const blob=await response.blob(),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=(response.headers.get('Content-Disposition')||'').match(/GuardDesk-Endpoint-[0-9.]+\.zip/)?.[0]||'GuardDesk-Endpoint.zip';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);toast('已下載端點安裝包；解壓後執行 Setup-Endpoint.cmd');}
    if(action==='deployment-settings'){await deploymentDialog();}
    if(action==='deployment-confirm'){const kind=b.dataset.kind;dialog(kind==='rotate'?'確認更換共用部署碼':'確認停用共用部署碼',`<p>舊安裝包將無法再註冊新端點，已註冊端點維持運作。${kind==='rotate'?'完成後請下載並發放新版安裝包。':'需要新增端點時，先重新產生部署碼。'}</p><button class="danger" data-action="deployment-apply" data-kind="${kind}">確認${kind==='rotate'?'更換':'停用'}</button>`);}
    if(action==='deployment-apply'){const kind=b.dataset.kind;await api('/api/deployment/'+kind,{confirm:kind});await deploymentDialog();toast(kind==='rotate'?'已更換部署碼，請重新下載安裝包':'已停用部署碼；已註冊端點不受影響');}
    if(action==='device') {await showDeviceDetail(b.dataset.id);}
    if(action==='confirm-revoke') {dialog('確認撤銷端點憑證','<p>此端點將無法連線管理中心與使用受控外發。重新納管需要新的註冊碼與設定檔。</p>'+`<button class="danger" data-action="revoke" data-id="${esc(b.dataset.id)}">確認撤銷</button>`);}
    if(action==='revoke') {await api('/api/devices/revoke',{device_id:b.dataset.id});$('#dialog').close();toast('端點憑證已撤銷');await refresh();}
    if(action==='event') {const e=events.items.find(v=>v.id===Number(b.dataset.id));dialog(kinds[e.kind]||e.kind,eventDescription(e),true);}
    if(action==='integrity') {b.disabled=true;const v=await api('/api/integrity');dialog('稽核鏈完整性',`<p>${v.valid?'✓ 已驗證 '+v.checked+' 筆紀錄，雜湊鏈一致。':'偵測到紀錄變動，斷點 #'+v.broken_at}</p><pre>${esc(JSON.stringify(v,null,2))}</pre><p class="help">結果只驗證目前資料庫的鏈一致性；不保證資料庫管理員無法重寫整條鏈或刪除尾端。正式環境需外部簽章錨點或 WORM 儲存。</p>`);}
    if(action==='prev'){offset=Math.max(0,offset-50);await refresh();}
    if(action==='next'){offset+=50;await refresh();}
    if(action==='csv')await downloadAuditCSV(event.target.closest('[data-action=csv]'));
  } catch(error){toast(error.message);} finally {b.disabled=false;}
});
$('#login-form').addEventListener('submit',async event=>{event.preventDefault();const b=event.target.querySelector('button');b.disabled=true;$('#login-error').textContent='';try{const f=new FormData(event.target);user=await api('/api/login',{username:f.get('username'),password:f.get('password')});event.target.reset();showShell();await refresh();}catch(error){$('#login-error').textContent=error.message;}finally{b.disabled=false;}});
$('#logout').addEventListener('click',async()=>{try{if(remoteSession)await stopRemoteSession();await api('/api/logout',{});showLogin();}catch(error){toast(error.message);}});
$('#refresh').addEventListener('click',refresh);
$('#close-dialog').addEventListener('click',()=>$('#dialog').close());
setInterval(()=>{$('#clock').textContent=new Date().toLocaleString('zh-TW',{timeZone:'Asia/Taipei',hour12:false});},1000);
setInterval(()=>{const editingSearch=Boolean(document.activeElement?.closest('#search-form'));if(user && (page==='overview'||page==='devices'||(page==='updates'&&!updatesDirty&&!updatesFilterDirty)||page==='reports'||page==='archives'||(page==='audit'&&offset===0&&!editingSearch)) && !$('#dialog').open)refresh({automatic:true});},15000);
window.addEventListener('DOMContentLoaded',async()=>{try{user=await api('/api/me');showShell();await refresh();}catch{showLogin();}});
