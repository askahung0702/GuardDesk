/* Page-visible metadata observer. This world is NOT a trusted evidence source.
 * Only object lineage is observed: never read/copy/hash a file or network body.
 * The isolated bridge requires trusted selection; the worker independently
 * requires an actual browser request and labels all such matches candidates.
 */
(()=>{
  'use strict';
  const lineage=new WeakMap(),requests=new WeakMap(),xhr=new WeakMap();
  const fileName=Object.getOwnPropertyDescriptor(File.prototype,'name')?.get;
  const blobSize=Object.getOwnPropertyDescriptor(Blob.prototype,'size')?.get;
  const post=window.postMessage.bind(window),apply=Reflect.apply,then=Promise.prototype.then;
  const own=(object,key)=>{const d=object&&Object.getOwnPropertyDescriptor(object,key);return d&&'value' in d?d:null;};
  let enabled=false;
  window.addEventListener('message',e=>{if(e.source===window&&e.data?.guarddesk_control_v1===true)enabled=e.data.enabled===true;});
  function metadata(value){
    try{
      if(!value||typeof value!=='object')return null;
      const saved=lineage.get(value);if(saved)return saved;
      if(value instanceof File)return {name:apply(fileName,value,[]),size:apply(blobSize,value,[])};
      if(ArrayBuffer.isView(value)){const parent=lineage.get(value.buffer);if(parent)return parent;}
    }catch{}
    return null;
  }
  const slice=Blob.prototype.slice,arrayBuffer=Blob.prototype.arrayBuffer;
  Blob.prototype.slice=function(...args){const result=apply(slice,this,args);if(enabled){const m=metadata(this);if(m)lineage.set(result,m);}return result;};
  Blob.prototype.arrayBuffer=function(...args){
    const promise=apply(arrayBuffer,this,args);
    try{if(enabled){const m=metadata(this);if(m)apply(then,promise,[buffer=>{lineage.set(buffer,m);},()=>{}]);}}catch{}
    return promise; // Preserve the original promise, result and rejection.
  };
  const BlobOriginal=window.Blob;
  window.Blob=new Proxy(BlobOriginal,{construct(target,args,newTarget){
    const result=Reflect.construct(target,args,newTarget);
    try{if(enabled&&Array.isArray(args[0])&&args[0].length>0&&args[0].length<=32){
      let m=null,valid=true;
      for(let i=0;i<args[0].length;i++){const item=own(args[0],String(i)),v=item&&metadata(item.value);if(!v||m&&(v.name!==m.name||v.size!==m.size)){valid=false;break;}m=v;}
      if(valid&&m)lineage.set(result,m);
    }}catch{}
    return result;
  }});
  // Observe the result object returned to the site; do not call a read method
  // ourselves or allocate a second buffer. Workers remain outside this scope.
  const readers=new WeakMap(),read=FileReader.prototype.readAsArrayBuffer;
  const resultDescriptor=Object.getOwnPropertyDescriptor(FileReader.prototype,'result');
  FileReader.prototype.readAsArrayBuffer=function(blob){
    const m=enabled?metadata(blob):null;if(m)readers.set(this,m);else readers.delete(this);
    try{return apply(read,this,arguments);}catch(error){readers.delete(this);throw error;}
  };
  if(resultDescriptor?.configurable)Object.defineProperty(FileReader.prototype,'result',{...resultDescriptor,get(){
    const result=apply(resultDescriptor.get,this,[]);
    try{const m=enabled&&readers.get(this);if(m&&result instanceof ArrayBuffer)lineage.set(result,m);}catch{}
    return result;
  }});
  function note(url,method,body){
    if(!enabled||!['POST','PUT','PATCH'].includes(method))return;
    const m=metadata(body);if(!m)return;
    try{const u=new URL(url,location.href);if(!['http:','https:'].includes(u.protocol))return;
      post({guarddesk_body_v1:true,url:u.href,method,file:{name:m.name,size:m.size}},location.origin);
    }catch{} // Observation must never prevent the site's request.
  }
  const fetch=window.fetch,RequestOriginal=window.Request,clone=RequestOriginal.prototype.clone;
  // Request objects hide their body. Track only constructor-supplied lineage;
  // never clone/read a stream to reconstruct data or guess missing provenance.
  window.Request=new Proxy(RequestOriginal,{construct(target,args,newTarget){
    const result=Reflect.construct(target,args,newTarget),options=args[1];
    try{if(enabled){const body=own(options,'body'),m=body?metadata(body.value):options?null:requests.get(args[0]);if(m)requests.set(result,m);}}catch{}
    return result;
  }});
  RequestOriginal.prototype.clone=function(...args){const result=apply(clone,this,args),m=requests.get(this);if(m)requests.set(result,m);return result;};
  window.fetch=function(input,options){
    try{
      if(enabled){const req=input instanceof RequestOriginal;
        const methodField=own(options,'method'),bodyField=own(options,'body');
        if(options&&(!bodyField&&'body' in options||!methodField&&'method' in options))return apply(fetch,this,arguments);
        const method=String(methodField?.value||(req?input.method:'GET')).toUpperCase();
        const body=bodyField?.value;
        const m=body?metadata(body):req?requests.get(input):null;
        if(m&&(req||typeof input==='string')){const token={};lineage.set(token,m);note(req?input.url:input,method,token);}
      }
    }catch{}
    return apply(fetch,this,arguments);
  };
  const open=XMLHttpRequest.prototype.open,send=XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open=function(method,url){const result=apply(open,this,arguments);if(typeof method==='string'&&typeof url==='string')xhr.set(this,{url,method:method.toUpperCase()});else xhr.delete(this);return result;};
  XMLHttpRequest.prototype.send=function(body){try{const r=xhr.get(this);if(r)note(r.url,r.method,body);}catch{}return apply(send,this,arguments);};
})();
