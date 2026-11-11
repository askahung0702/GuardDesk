'use strict';
const HOST='com.guarddesk.agent', MAX_QUEUE=1000, MAX_BYTES=4*1024*1024, MAX_ACTIVE=128, ACTIVE_TTL=30*60*1000;
let port=null, serial=Promise.resolve(), inflight=new Map(), flushing=false, flushTimer=null, policyAt=0, currentPolicy=null, policyFlight=null;
const browserName=()=>navigator.userAgent.includes('Edg/')?'edge':'chrome';
const activeIds=new Set();let activeReady=false;
const hydration=chrome.storage.local.get({active_uploads:{}}).then(d=>{for(const id of Object.keys(d.active_uploads))activeIds.add(id);activeReady=true;});
const selections=new Map();
const bodyIntents=[],bodyRequests=new Map();
let capacityNoticePending=false;
chrome.runtime.onMessage.addListener((m,sender,reply)=>{
  if(sender.id!==chrome.runtime.id||!sender.tab||!/^https?:\/\//i.test(sender.url||''))return;
  if(m?.type==='upload_observer_status'){policy().then(s=>reply({enabled:s.web_upload_audit===true&&s.memory_upload_v1===true,audit_enabled:s.web_upload_audit===true}),()=>reply({enabled:false,audit_enabled:false}));return true;}
  if(currentPolicy?.web_upload_audit!==true)return;
  if(m?.type==='upload_body_metadata'){
    const s=selections.get(sender.tab.id+':'+sender.frameId),f=m.file;
    if(currentPolicy.memory_upload_v1!==true||!s||s.documentId!==sender.documentId||Date.now()-s.at>300000||!s.files.some(v=>v.name===f?.name&&v.size===f?.size)||typeof m.url!=='string'||m.url.length>8192||!['POST','PUT','PATCH'].includes(m.method))return;
    while(bodyIntents.length&&Date.now()-bodyIntents[0].at>2000)bodyIntents.shift();
    if(bodyIntents.length>=128)return;
    bodyIntents.push({key:sender.tab.id+':'+sender.frameId,documentId:sender.documentId,url:safeUrl(m.url),method:m.method,name:f.name,at:Date.now()});return;
  }
  if(m?.type!=='file_selection_metadata'||!Array.isArray(m.files))return;
  const files=m.files.slice(0,32).filter(f=>typeof f?.name==='string'&&f.name.length>0&&f.name.length<=512&&!/[\\/\x00-\x1f]/.test(f.name)&&Number.isSafeInteger(f.size)&&f.size>=0).map(f=>({name:f.name,size:f.size}));
  if(!files.length)return;
  const key=sender.tab.id+':'+sender.frameId;
  if(!selections.has(key)&&selections.size>=128)selections.delete(selections.keys().next().value);
  selections.set(key,{files,at:Date.now(),documentId:sender.documentId});
  // Session storage survives MV3 worker suspension, not browser restart.
  chrome.storage.session.set({file_selections:Object.fromEntries(selections)}).catch(console.error);
});
const selectionReady=chrome.storage.session.get({file_selections:{}}).then(d=>{for(const [k,v] of Object.entries(d.file_selections).slice(0,128))if(!selections.has(k)&&Date.now()-v.at<300000)selections.set(k,v);});
function native(message) {
  if(!port) {
    port=chrome.runtime.connectNative(HOST);
    port.onMessage.addListener(reply=>{const p=inflight.get(reply.request_id);if(p){inflight.delete(reply.request_id);clearTimeout(p.timer);reply.ok?p.resolve(reply):p.reject(new Error(reply.error));}});
    port.onDisconnect.addListener(()=>{const reason=chrome.runtime.lastError?.message||'Native host disconnected';port=null;policyAt=0;for(const p of inflight.values()){clearTimeout(p.timer);p.reject(new Error(reason));}inflight.clear();});
  }
  return new Promise((resolve,reject)=>{const id=crypto.randomUUID();const timer=setTimeout(()=>{inflight.delete(id);reject(new Error('Native host timeout'));},15000);inflight.set(id,{resolve,reject,timer});port.postMessage({...message,request_id:id});});
}
function serialized(task){const next=serial.then(task);serial=next.catch(()=>{});return next;}
async function policy() {
  if(currentPolicy&&Date.now()-policyAt<30000)return currentPolicy;
  if(policyFlight)return policyFlight;
  policyFlight=(async()=>{
    const value=await native({type:'status',browser:browserName(),extension_version:chrome.runtime.getManifest().version});
    const desired=value.proxy_required?value.pac:null;
    const legacyProxy=value.proxy_required&&!['proxy_not_configured','configured_requires_runtime_check','not_required'].includes(value.proxy_policy_state);
    // Reapplying proxy settings can reset live connections. Inspect actual
    // settings on worker restart; change them only when the policy differs.
    const actual=await chrome.proxy.settings.get({incognito:false});
    if(legacyProxy) {
      // The extension can arrive before the Agent. Old hosts cannot prove
      // whether a proxy was configured: preserve existing settings, never
      // introduce a new PAC or clear a previously working one during rollout.
      value.proxy_policy_state='agent_upgrade_required';
    } else if(desired!==null) {
      if(actual.value?.mode!=='pac_script'||actual.value?.pacScript?.data!==desired||actual.value?.pacScript?.mandatory!==true)
        await chrome.proxy.settings.set({value:{mode:'pac_script',pacScript:{data:desired,mandatory:true}},scope:'regular'});
    } else if(actual.levelOfControl==='controlled_by_this_extension')await chrome.proxy.settings.clear({scope:'regular'});
    currentPolicy=value;policyAt=Date.now();
    if(!value.web_upload_audit){selections.clear();bodyIntents.length=0;bodyRequests.clear();await chrome.storage.session.remove('file_selections');}
    await chrome.storage.local.set({host_status:{connected:true,browser_audit:value.browser_audit,web_upload_audit:value.web_upload_audit===true,proxy_required:value.proxy_required,proxy_policy_state:value.proxy_policy_state||'unknown',checked:Date.now()}});
    return value;
  })();
  try{return await policyFlight;}finally{policyFlight=null;}
}
function safeUrl(value){try{const u=new URL(value);if(!['http:','https:'].includes(u.protocol))return '';u.username='';u.password='';u.hash='';if(value.length>8192)return u.origin+'/';for(const k of [...u.searchParams.keys()])if(/^(token|access_token|id_token|refresh_token|password|passwd|secret|client_secret|authorization|code|sig|signature|api_key|apikey)$/i.test(k))u.searchParams.set(k,'[REDACTED]');return u.href;}catch{return '';}}
function event(message){for(const key of ['url','redirect_url','response_url'])if(message[key]){if(message[key].length>8192)message[key+'_truncated']=true;message[key]=safeUrl(message[key]);}return {...message,event_id:'browser-'+crypto.randomUUID(),browser:browserName()};}
function scheduleFlush(){if(!flushTimer)flushTimer=setTimeout(()=>{flushTimer=null;flush().catch(console.error);},250);}
function add(queue,item) {
  if(queue.length>=MAX_QUEUE||JSON.stringify(queue).length+JSON.stringify(item).length>MAX_BYTES/2)return false;
  queue.push(item);return true;
}
async function persist(items,extra={}) {
  const data=await chrome.storage.local.get({queue:[],queue_overflow:0});let overflow=data.queue_overflow;
  for(const item of items)if(!add(data.queue,item))overflow++;
  await chrome.storage.local.set({...extra,queue:data.queue,queue_overflow:overflow});
  if(overflow){await chrome.action.setBadgeText({text:'!'});await chrome.action.setBadgeBackgroundColor({color:'#b64c42'});}
  scheduleFlush();
}
async function flush() {
  if(flushing)return;flushing=true;
  try {
    const status=await policy();
    if(!status.browser_audit)return;
    const data=await serialized(()=>chrome.storage.local.get({queue:[]}));
    // Do not hold the persistence lock during a native timeout: new events
    // must remain durable even while the host is unavailable.
    const ack=[];
    for(const item of data.queue.slice(0,50)){const reply=await native(item);if(reply.recorded===false){policyAt=0;break;}ack.push(item.event_id);}
    await serialized(async()=>{
      const latest=await chrome.storage.local.get({queue:[],queue_overflow:0});
      const ids=new Set(ack),queue=latest.queue.filter(item=>!ids.has(item.event_id));
      let overflow=latest.queue_overflow;
      if(overflow&&status.web_upload_audit&&add(queue,event({type:'upload_gap',url:'https://guarddesk.invalid/',reason:'queue_capacity',lost_count:overflow,timestamp:Date.now()})))overflow=0;
      await chrome.storage.local.set({queue,queue_overflow:overflow});
      if(queue.length)scheduleFlush();
      await chrome.action.setBadgeText({text:overflow?'!':''});
    });
  } catch(error) {
    policyAt=0;
    await chrome.storage.local.set({host_status:{connected:false,error:String(error.message).slice(0,300),checked:Date.now()}});
    await chrome.action.setBadgeText({text:'!'});await chrome.action.setBadgeBackgroundColor({color:'#b64c42'});
  } finally{flushing=false;}
}
function navigate(d) {
  if(d.frameId!==0||!/^https?:\/\//i.test(d.url))return;
  serialized(async()=>{const data=await chrome.storage.local.get({host_status:{}});if(data.host_status.browser_audit===false)return;await persist([event({type:'navigation',url:d.url,tab_id:d.tabId,timestamp:d.timeStamp})]);}).catch(console.error);
}
chrome.webNavigation.onCommitted.addListener(navigate);
chrome.webNavigation.onHistoryStateUpdated.addListener(navigate);
chrome.webNavigation.onCompleted.addListener(d=>{
  if(d.frameId!==0||!/^https?:\/\//i.test(d.url))return;
  serialized(async()=>{
    const status=await chrome.storage.local.get({host_status:{}});if(status.host_status.browser_audit===false)return;
    const tab=await chrome.tabs.get(d.tabId);if(tab.url!==d.url||!tab.title)return;
    await persist([event({type:'page_title',url:d.url,title:tab.title.slice(0,500),timestamp:d.timeStamp,tab_id:d.tabId})]);
  }).catch(console.error);
});

// Nonblocking metadata only. MAIN-world references are untrusted candidates;
// no file reading, hashing, response-body parsing or per-packet native calls.
const filter={urls:['http://*/*','https://*/*']};
function uploadMessage(a,phase,d) {
  return event({type:'web_upload',upload_id:a.upload_id,phase,url:phase==='started'?d.url:a.url,response_url:d.url,files:a.files,
    site_origin:a.site_origin,
    files_truncated:a.files_truncated,url_truncated:phase==='started'?d.url.length>8192:a.url_truncated,method:a.method,tab_id:d.tabId,timestamp:d.timeStamp,
    status_code:d.statusCode,error:d.error,redirect_url:d.redirectUrl});
}
chrome.webRequest.onBeforeRequest.addListener(d=>{
  if(currentPolicy?.web_upload_audit===false)return;
  if(!['POST','PUT','PATCH'].includes(d.method)||d.tabId<0)return;
  // Copy only file path strings. Never retain requestBody or ArrayBuffer bytes
  // in a queued closure; form fields, headers and cookies are not persisted.
  const files=[],raw=d.requestBody?.raw||[];
  for(let i=0;i<Math.min(raw.length,256);i++)if(typeof raw[i].file==='string'&&raw[i].file.length<=4096&&files.length<32)files.push({path:raw[i].file});
  // FormData may expose only filenames. Match against recent user-selected
  // names in this tab/frame; label this explicitly as a candidate, not an
  // absolute path or proof that this exact file's bytes were transmitted.
  const key=d.tabId+':'+d.frameId,selection=selections.get(key);
  if(!files.length&&selection&&selection.documentId===d.documentId&&Date.now()-selection.at<300000){
    const names=new Set(selection.files.map(f=>f.name));let checked=0;
    for(const values of Object.values(d.requestBody?.formData||{}).slice(0,256))for(const value of values.slice(0,32)){
      if(++checked>512)break;
      if(typeof value==='string'&&names.has(value)&&files.length<32&&!files.some(f=>f.path===value))files.push({path:value,evidence:'selected_filename_match'});
    }
  }
  const unavailable=Boolean(d.requestBody?.error),truncated=raw.length>256||files.length===32;
  const memory=!files.length&&currentPolicy?.memory_upload_v1===true&&selection&&selection.documentId===d.documentId&&Date.now()-selection.at<300000&&(unavailable||raw.some(x=>x.bytes instanceof ArrayBuffer));
  if(!files.length&&!unavailable&&!memory)return;
  if(activeIds.size>=MAX_ACTIVE){
    if(!capacityNoticePending){capacityNoticePending=true;const url=safeUrl(d.url),timestamp=d.timeStamp;
      serialized(async()=>{const data=await chrome.storage.local.get({gap_at:0});if(Date.now()-data.gap_at>300000)await persist([event({type:'upload_gap',reason:'request_capacity',url,timestamp})],{gap_at:Date.now()});}).catch(console.error).finally(()=>{capacityNoticePending=false;});}
    return;
  }
  activeIds.add(d.requestId);
  // Coalesce only metadata for 100ms. Never block/modify the actual request.
  // Parallel same-URL requests are ambiguous; none gets promoted to a file.
  const documentId=d.documentId,requestKey=key+':'+documentId+':'+d.method+':'+safeUrl(d.url);
  let group=null;
  if(memory){group=bodyRequests.get(requestKey);if(group)group.ambiguous=true;else{group={ambiguous:false};bodyRequests.set(requestKey,group);}}
  const observed={url:d.url,tabId:d.tabId,timeStamp:d.timeStamp,requestId:d.requestId,method:d.method};
  let siteOrigin='';try{if(d.initiator&&/^https?:\/\//.test(d.initiator))siteOrigin=new URL(d.initiator).origin;}catch{}
  const settle=memory?new Promise(r=>setTimeout(r,100)):Promise.resolve();
  serialized(async()=>{
    await settle;
    await selectionReady;
    const data=await chrome.storage.local.get({host_status:{},active_uploads:{},gap_at:0});
    if(data.host_status.web_upload_audit!==true){activeIds.delete(observed.requestId);return;}
    const gap=async reason=>{if(Date.now()-data.gap_at>300000)await persist([event({type:'upload_gap',reason,url:observed.url,timestamp:observed.timeStamp})],{gap_at:Date.now()});};
    if(memory){
      const intents=bodyIntents.filter(v=>v.key===key&&v.documentId===documentId&&v.method===observed.method&&v.url===safeUrl(observed.url)&&Math.abs(Date.now()-v.at)<2000);
      if(intents.length===1&&!group.ambiguous)files.push({path:intents[0].name,evidence:'page_body_metadata_candidate'});
      for(const v of intents){const i=bodyIntents.indexOf(v);if(i>=0)bodyIntents.splice(i,1);}
      bodyRequests.delete(requestKey);
      // An unrelated JSON/buffer request after a selection is not an upload.
      // Emit a gap only when file-related metadata existed or the browser
      // itself reported unavailable body metadata.
      if(!files.length&&!unavailable&&!intents.length){activeIds.delete(observed.requestId);return;}
    }
    if(!files.length){activeIds.delete(observed.requestId);await gap(memory?'body_metadata_unresolved':'request_body_unavailable');return;}
    if(Object.keys(data.active_uploads).length>=MAX_ACTIVE&&!data.active_uploads[observed.requestId]){activeIds.delete(observed.requestId);await gap('request_capacity');return;}
    const a=data.active_uploads[observed.requestId]||{upload_id:crypto.randomUUID(),files,site_origin:siteOrigin,method:observed.method,files_truncated:truncated,started:Date.now(),url:safeUrl(observed.url),url_truncated:observed.url.length>8192,tabId:observed.tabId};
    data.active_uploads[observed.requestId]=a;
    await persist([uploadMessage(a,'started',observed)],{active_uploads:data.active_uploads});
  }).catch(error=>{activeIds.delete(observed.requestId);bodyRequests.delete(requestKey);console.error(error);});
},filter,['requestBody']);
function finishUpload(phase,d) {
  // The ordinary GET/image/script hot path performs no storage/native calls.
  if(activeReady&&!activeIds.has(d.requestId))return;
  const observed={requestId:d.requestId,url:d.url,tabId:d.tabId,timeStamp:d.timeStamp,statusCode:d.statusCode,error:d.error,redirectUrl:d.redirectUrl};
  serialized(async()=>{
    await hydration;
    const data=await chrome.storage.local.get({active_uploads:{}}),a=data.active_uploads[observed.requestId];if(!a)return;
    if(phase!=='redirected'){delete data.active_uploads[observed.requestId];activeIds.delete(observed.requestId);}
    await persist([uploadMessage(a,phase,observed)],{active_uploads:data.active_uploads});
  }).catch(console.error);
}
chrome.webRequest.onCompleted.addListener(d=>finishUpload('response',d),filter);
chrome.webRequest.onErrorOccurred.addListener(d=>finishUpload('failed',d),filter);
chrome.webRequest.onBeforeRedirect.addListener(d=>finishUpload('redirected',d),filter);
async function expireUploads(all=false) {
  await serialized(async()=>{
    const data=await chrome.storage.local.get({active_uploads:{}}),expired=[];
    for(const [id,a] of Object.entries(data.active_uploads))if(all||Date.now()-a.started>ACTIVE_TTL){expired.push(uploadMessage(a,'interrupted',{url:a.url,tabId:a.tabId,timeStamp:Date.now()}));delete data.active_uploads[id];activeIds.delete(id);}
    if(expired.length)await persist(expired,{active_uploads:data.active_uploads});
  });
}
chrome.alarms.onAlarm.addListener(a=>{if(a.name==='guarddesk-sync'){expireUploads().catch(console.error);flush().catch(console.error);}});
chrome.runtime.onInstalled.addListener(()=>{chrome.alarms.create('guarddesk-sync',{periodInMinutes:0.5});flush().catch(console.error);});
chrome.runtime.onStartup.addListener(()=>{chrome.alarms.create('guarddesk-sync',{periodInMinutes:0.5});expireUploads(true).then(flush).catch(console.error);});
chrome.alarms.create('guarddesk-sync',{periodInMinutes:0.5});
