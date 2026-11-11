'use strict';
// Isolated world. Trusted selection is independent from the page-visible
// observer; its messages are still untrusted candidates, never full paths.
let selectedFiles=[],selectedAt=0,enabled=false,auditEnabled=false,windowAt=0,count=0;
function selected(files){if(!auditEnabled)return;const items=[];for(let i=0;i<Math.min(files?.length||0,32);i++){const f=files[i];if(f.name.length<=512)items.push({name:f.name,size:f.size});}selectedFiles=items;selectedAt=Date.now();if(items.length)chrome.runtime.sendMessage({type:'file_selection_metadata',files:items}).catch(()=>{});}
document.addEventListener('change',e=>{if(e.isTrusted&&e.target instanceof HTMLInputElement&&e.target.type==='file')selected(e.target.files);},true);
document.addEventListener('drop',e=>{if(e.isTrusted)selected(e.dataTransfer?.files);},true);
function control(){chrome.runtime.sendMessage({type:'upload_observer_status'}).then(s=>{enabled=s?.enabled===true;auditEnabled=s?.audit_enabled===true;if(!auditEnabled){selectedFiles=[];selectedAt=0;}window.postMessage({guarddesk_control_v1:true,enabled},location.origin);}).catch(()=>{enabled=false;auditEnabled=false;selectedFiles=[];selectedAt=0;window.postMessage({guarddesk_control_v1:true,enabled:false},location.origin);});}
// Periodic policy refresh only; no timers or native calls per file chunk.
control();setInterval(control,30000);
window.addEventListener('message',e=>{
  if(!enabled||e.source!==window||e.origin!==location.origin||e.data?.guarddesk_body_v1!==true||Date.now()-selectedAt>300000)return;
  const m=e.data,f=m.file;
  if(!f||!selectedFiles.some(s=>s.name===f.name&&s.size===f.size)||typeof m.url!=='string'||m.url.length>8192||!['POST','PUT','PATCH'].includes(m.method))return;
  if(Date.now()-windowAt>1000){windowAt=Date.now();count=0;}if(++count>64)return;
  chrome.runtime.sendMessage({type:'upload_body_metadata',url:m.url,method:m.method,file:{name:f.name,size:f.size}}).catch(()=>{});
});
