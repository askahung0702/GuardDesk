'use strict';
let softwareData=null,softwareBusy=false;
function softwareJobDiagnostic(j){
  const stages={DETECT_PRODUCT:'查詢已安裝版本',SYSTEM_DIRECTORY:'取得系統目錄',SPACE_CHECK:'檢查磁碟空間',DOWNLOAD:'下載 MSI',CACHE_PROTECTION:'檢查快取權限',INSPECT_PACKAGE:'讀取 MSI 資料',VERIFY_PUBLISHER:'核對發行者',INSTALL_LOCK:'取得安裝鎖',FINAL_PROTECTION:'安裝前權限檢查',FINAL_HASH:'安裝前雜湊檢查',AUTHORIZE:'確認派送授權',SAVE_INTENT:'保存安裝意圖',LAUNCH:'啟動安裝器',DETECT_RESULT:'確認安裝後版本',SAVE_RESULT:'保存結果'};
  const domains={MSI_API:'MSI API',AUTHENTICODE:'簽章驗證',WIN32:'Windows',ERRNO:'檔案 I/O errno',HTTP:'HTTP',UNKNOWN:'未取得代碼'};
  const matched=/^INSTALL_(?:PREPARATION_)?(.+)_(MSI_API|AUTHENTICODE|WIN32|ERRNO|HTTP|UNKNOWN)_ERROR$/.exec(j.error||'');
  if(matched&&stages[matched[1]])return stages[matched[1]]+'失敗 · '+domains[matched[2]]+(j.exit_code==null?'':' '+j.exit_code)+'（'+j.error+'）';
  if(j.error==='INSTALL_PREPARATION_API_OR_IO_ERROR')return '舊版未保留失敗步驟，需查端點紀錄'+(j.exit_code==null?'':' · Windows '+j.exit_code)+'（'+j.error+'）';
  return (j.error||'')+(j.exit_code==null?'':' · '+(j.error==='INSTALL_API_OR_IO_ERROR'?'Windows':'安裝程式回傳碼')+' '+j.exit_code);
}
let softwareUploadFeedback={phase:'idle',message:'',percent:null},softwareUploadOwner=null;
function softwareUploadView(){return softwareUploadOwner===user?softwareUploadFeedback:{phase:'idle',message:'',percent:null};}
function softwareUploadFeedbackSet(phase,message,percent=null){
  softwareUploadFeedback={phase,message,percent};
  if(softwareUploadOwner!==user)return;
  const feedback=$('#software-feedback'),progress=$('#software-progress');
  if(feedback){feedback.textContent=message;feedback.setAttribute('data-phase',phase);}
  if(progress){progress.hidden=!['uploading','validating'].includes(phase);if(percent===null)progress.removeAttribute('value');else progress.value=percent;}
}
function softwareUploadFailure(status,reason){
  const messages={
    'MSI requires a three-part ProductVersion':'此MSI的版本格式目前不支援，需核對廠商的ProductVersion。',
    'MSI requires a three- or four-part numeric ProductVersion':'此MSI需使用三段或四段數字版本，且各欄位須在支援範圍內。',
    'MSI ProductVersion requires 3 or more numeric fields (maximum 128 characters)':'此MSI版本需至少三段數字，以點分隔且總長不超過128字元。',
    'Only vendor-authored per-machine MSI packages are supported':'此MSI未宣告支援全機安裝，需使用廠商提供的全機安裝套件。',
    'MSI must contain its cabinets; external payloads are unsupported':'此MSI需要外部CAB，現版只接受內含所需檔案的套件。',
    'MSI contains external uncompressed files':'此MSI需要外部未壓縮檔案，現版不支援這種套件。',
    'Not an MSI compound database':'檔案內容不是可讀取的MSI安裝資料庫。',
  };
  const detail=typeof reason==='string'&&reason.trim()?reason.trim().slice(0,240):'中心未提供可讀取的錯誤原因。';
  return `上傳失敗（HTTP ${status}）：${messages[detail]?messages[detail]+' 原始原因：':''}${detail}`;
}
function softwareUploadRequest(file,budget,csrf,notify){
  return new Promise((resolve,reject)=>{
    const request=new XMLHttpRequest();let settled=false,timer=null,validationStarted=0;
    const finish=(error,result)=>{if(settled)return;settled=true;if(timer!==null)clearInterval(timer);if(error)reject(error);else resolve(result);};
    const unknown=message=>finish(new Error(message+'；尚未確認是否加入軟體庫，請先更新進度核對結果。'));
    request.upload.onprogress=e=>{if(!settled&&e.lengthComputable){const percent=Math.min(100,Math.max(0,Math.floor(e.loaded/e.total*100)));notify('uploading',`正在傳送MSI檔案：${percent}%`,percent);}};
    request.upload.onload=()=>{
      if(settled||timer!==null)return;validationStarted=Date.now();notify('validating','檔案已傳送，正在等待管理中心驗證MSI…',100);
      timer=setInterval(()=>{if(!settled)notify('validating',`檔案已傳送，管理中心驗證中（已等待 ${Math.max(0,Math.floor((Date.now()-validationStarted)/1000))} 秒）…`,100);},1000);
    };
    request.onload=()=>{
      if(settled)return;let result=null;
      try{if(request.responseText.length<=65536)result=JSON.parse(request.responseText);}catch(error){}
      if(request.status<200||request.status>=300){finish(new Error(softwareUploadFailure(request.status,result?.error)));return;}
      if(!result||!result.package||typeof result.package.sha256!=='string'||!/^[0-9a-f]{64}$/.test(result.package.sha256)){
        unknown('中心回覆格式不完整');return;
      }
      finish(null,result);
    };
    request.onerror=()=>unknown('連線中斷');request.onabort=()=>unknown('已停止等待');request.ontimeout=()=>unknown('連線等待逾時');
    // Upload completion is not validation success. Keep the existing same-origin
    // authorization and never retry an uncertain POST automatically.
    request.open('POST','/api/software/import',true);
    request.setRequestHeader('Content-Type','application/x-msi');request.setRequestHeader('X-CSRF-Token',csrf);
    request.setRequestHeader('X-GuardDesk-Authorize','install-msi-machine');request.setRequestHeader('X-Install-Bytes',String(budget));
    try{request.send(file);}catch(error){unknown('無法送出上傳請求');}
  });
}
const softwareStates={queued:'等待端點',downloading:'下載／驗證中',installing:'安裝中',review_required:'需人工確認，未重新安裝',succeeded:'安裝與版本確認完成',already_installed:'已安裝相同版本',reboot_required:'安裝完成，需另行重開機',failed:'失敗',cancelled:'已取消'};
function softwarePage(){
  const d=softwareData||{packages:[],jobs:[],endpoints:[],limits:{package_bytes:8*1024**3,library_bytes:32*1024**3}};
  const upload=softwareUploadView(),uploading=['uploading','validating'].includes(upload.phase);
  return heading('SOFTWARE DEPLOYMENT','MSI 軟體派送','全機靜默安裝；最多選擇 20 台、同時處理 2 台。不自動重新啟動。','<button id="software-refresh" class="secondary">更新進度</button>')+
    '<div class="notice">內部試用。僅接受可驗證簽章、內含 CAB、廠商支援全機靜默安裝的 MSI；不支援 EXE、外部 CAB、MST、每使用者安裝或自訂參數。請先單台驗收。超過三段的版本套件需 Agent 0.4.110 以上。舊 Agent 必須先升級配套版本，才會出現在下方。</div>'+
    card('MSI 軟體庫',`單包上限 ${d.limits.package_bytes/1024**3} GiB；軟體庫上限 ${d.limits.library_bytes/1024**3} GiB／100 包。`,`<form id="software-upload" class="card-body"><label>MSI 安裝包<input name="file" type="file" accept=".msi" required></label><label>安裝空間預算（GiB，包含廠商所需空間）<input name="space" type="number" min="1" max="256" value="4" required></label><label><input type="checkbox" required> 我已確認此套件來源、授權與全機靜默安裝方式</label><button class="primary" type="submit" ${softwareBusy?'disabled':''}>上傳並驗證 MSI</button><progress id="software-progress" aria-label="MSI檔案傳送進度" max="100" ${upload.percent===null?'':`value="${upload.percent}"`} ${uploading?'':'hidden'}></progress><p id="software-feedback" role="status" data-phase="${upload.phase}">${esc(upload.message)}</p></form>`)+
    card('容量與套件管理','只清除中心保管的 MSI，不移除端點已安裝軟體。',`<form id="software-limits" class="card-body"><label>單包配額（GiB，1–64）<input name="package" type="number" min="1" max="64" value="${d.limits.package_bytes/1024**3}" required></label><label>軟體庫配額（GiB，最多 1024）<input name="library" type="number" min="1" max="1024" value="${d.limits.library_bytes/1024**3}" required></label><button>儲存配額</button></form><div class="card-body">${d.packages.map(p=>`<p>${esc(p.name)} ${esc(p.version)} <button type="button" data-software-delete="${esc(p.sha256)}">從軟體庫刪除</button></p>`).join('')}</div>`)+
    card('派送安裝','先選套件與已支援 MSI 的端點。',`<form id="software-deploy" class="card-body"><label>安裝包<select name="package_id" required><option value="">請選擇</option>${d.packages.map(p=>`<option value="${esc(p.sha256)}">${esc(p.name)} ${esc(p.version)} · ${esc(p.publisher)}</option>`).join('')}</select></label><label>端點（按 Ctrl 可複選）<select name="device_ids" multiple size="6" required>${d.endpoints.map(e=>`<option value="${esc(e.id)}">${esc(e.name)} · ${Date.now()/1000-e.received<120?'就緒':'未連線'}</option>`).join('')}</select></label><label><input type="checkbox" required> 確認以 SYSTEM 在所選端點安裝，不需要登入者具備管理員權限</label><button class="primary">建立安裝工作</button></form>`)+
    card('最近 100 筆工作','有安裝意圖但結果不明時保留工作，不自動重裝。',`<div class="table-wrap"><table><thead><tr><th>端點／套件</th><th>狀態</th><th>回報</th><th></th></tr></thead><tbody>${d.jobs.map(j=>`<tr><td>${esc(j.device_name||j.device_id)}<small>${esc(d.packages.find(p=>p.sha256===j.package_id)?.name||j.package_id)}</small></td><td>${esc(softwareStates[j.state]||j.state)}</td><td>${esc(softwareJobDiagnostic(j))}<small>${date(j.updated)}</small></td><td>${['queued','downloading'].includes(j.state)?`<button type="button" data-software-cancel="${esc(j.id)}">取消</button>`:j.state==='review_required'?`<button type="button" data-software-review="${esc(j.id)}">確認後結案</button>`:''}</td></tr>`).join('')}</tbody></table></div>`);
}
function bindSoftware(){
  $('#software-refresh').onclick=()=>{if(!softwareBusy)refresh();};
  $('#software-limits').onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{await api('/api/software/limits',{package_bytes:Number(f.get('package'))*1024**3,library_bytes:Number(f.get('library'))*1024**3});await refresh();}catch(err){toast(err.message);}};
  for(const b of document.querySelectorAll('[data-software-delete]'))b.onclick=async()=>{if(!confirm('從中心軟體庫刪除這個 MSI？端點軟體不會被解除安裝。'))return;try{await api('/api/software/delete',{package_id:b.dataset.softwareDelete});await refresh();}catch(err){toast(err.message);}};
  $('#software-upload').onsubmit=async e=>{
    e.preventDefault();if(softwareBusy)return;const f=new FormData(e.target),file=f.get('file'),budget=Number(f.get('space'))*1024**3;
    softwareUploadOwner=user;const owner=user;
    if(!file||typeof file.name!=='string'||!file.name.toLowerCase().endsWith('.msi')||!Number.isSafeInteger(file.size)||!file.size||file.size>(softwareData?.limits.package_bytes||8*1024**3)||!Number.isSafeInteger(budget)||budget<file.size||budget<1024**3||budget>256*1024**3){
      const message='請選擇配額以內的MSI；安裝預算需為1–256 GiB且不能小於檔案大小。';softwareUploadFeedbackSet('error',message);toast(message);return;
    }
    softwareBusy=true;const button=e.target.querySelector('button');button.disabled=true;softwareUploadFeedbackSet('uploading','正在傳送MSI檔案：0%',0);
    try{
      await softwareUploadRequest(file,budget,owner.csrf,(phase,message,percent)=>{if(user===owner)softwareUploadFeedbackSet(phase,message,percent);});
      if(user===owner){softwareUploadFeedbackSet('success','MSI已驗證並加入軟體庫，可在下方選擇套件及端點。');toast('MSI 已驗證並加入軟體庫');
        try{await refresh();}catch(error){if(user===owner)softwareUploadFeedbackSet('success','MSI已驗證並加入軟體庫；套件清單尚未更新，請按「更新進度」。');}}
    }catch(error){if(user===owner){softwareUploadFeedbackSet('error',error.message);toast(error.message);}}
    finally{softwareBusy=false;button.disabled=false;const current=$('#software-upload')?.querySelector('button');if(current)current.disabled=false;}
  };
  $('#software-deploy').onsubmit=async e=>{e.preventDefault();if(softwareBusy)return;const f=new FormData(e.target);softwareBusy=true;try{await api('/api/software/jobs',{package_id:f.get('package_id'),device_ids:f.getAll('device_ids'),confirm:'install-msi-machine'});toast('安裝工作已建立');await refresh();}catch(err){toast(err.message);}finally{softwareBusy=false;}};
  for(const b of document.querySelectorAll('[data-software-review]'))b.onclick=async()=>{if(!confirm('請先在端點確認該 Windows Installer 程序已結束，並檢查安裝結果。結案只解除工作互斥，不代表安裝成功，也不會重試。已完成確認？'))return;try{await api('/api/software/close-review',{job_id:b.dataset.softwareReview,confirm:'installer-stopped-and-result-reviewed'});await refresh();}catch(err){toast(err.message);}};
  for(const b of document.querySelectorAll('[data-software-cancel]'))b.onclick=async()=>{try{await api('/api/software/cancel',{job_id:b.dataset.softwareCancel});await refresh();}catch(err){toast(err.message);}};
}
