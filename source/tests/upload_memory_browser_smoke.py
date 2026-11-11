"""Owned loopback uploads only; reproduce 0.4.55 extension format boundaries.

Uses an isolated Chromium profile and a test-only loopback Native Messaging
adapter. Never touches employee profiles, registry, production enrollment or
ChatGPT, and never saves request bodies, headers or cookies in evidence.
"""
import hashlib,json,shutil,struct,subprocess,sys,tempfile,threading,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk.agent import Agent,private_write
from guarddesk.browser_host import handle_message
from guarddesk import __version__
from playwright.sync_api import sync_playwright


def main():
    with tempfile.TemporaryDirectory(prefix='upload-format-proof-',dir=ROOT/'runtime') as temporary:
        root=Path(temporary);watch=root/'documents';watch.mkdir();file=watch/'owned-upload.txt';file.write_bytes(b'GuardDesk owned non-confidential upload test.\n')
        config=root/'runtime/agent/config.json'
        private_write(config,{'server':'http://127.0.0.1:1','device_id':'owned-upload-format-only','token':'offline-fixture','watch':str(watch)})
        agent=Agent(config);requests=[];frozen='--frozen-host' in sys.argv
        def native_call(message):
            if not frozen:return handle_message(agent,message)
            data=json.dumps(message).encode();process=subprocess.run([str(ROOT/'dist/GuardDesk/GuardDesk.exe'),'browser-host','--config',str(config)],input=struct.pack('<I',len(data))+data,capture_output=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
            assert process.returncode==0 and len(process.stdout)>=4
            size=struct.unpack('<I',process.stdout[:4])[0];assert size<=1048576 and len(process.stdout)==size+4
            return json.loads(process.stdout[4:])
        class Handler(BaseHTTPRequestHandler):
            def log_message(*args):pass
            def do_GET(self):
                payload=b'<title>Owned upload format fixture</title><input type=file id=file>'
                self.send_response(200);self.send_header('Content-Type','text/html');self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
            def do_POST(self):
                length=int(self.headers.get('Content-Length',0))
                if self.path=='/native':
                    assert length<65536
                    reply=native_call(json.loads(self.rfile.read(length)))
                    payload=json.dumps(reply).encode()
                else:
                    left=length
                    while left:
                        block=self.rfile.read(min(left,65536));left-=len(block)
                        if not block:break
                    requests.append({'route':self.path,'method':self.command,'received_bytes':length-left});payload=b'{}'
                self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
            do_PUT=do_POST
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start();url='http://127.0.0.1:'+str(server.server_port)
        try:
            with sync_playwright() as p:
                extension=root/'extension';shutil.copytree(ROOT/'browser-extension',extension)
                background=extension/'background.js';background.write_text(background.read_text(encoding='utf-8').replace("HOST='com.guarddesk.agent'","HOST='com.guarddesk.owned_format_test'"),encoding='utf-8')
                context=p.chromium.launch_persistent_context(str(root/'profile'),channel='chromium',headless=True,args=['--disable-extensions-except='+str(extension),'--load-extension='+str(extension)])
                try:
                    sw=context.service_workers[0] if context.service_workers else context.wait_for_event('serviceworker')
                    sw.evaluate('''async url=>{
                      native=async m=>{let r=await fetch(url+'/native',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(m)});return await r.json();};
                      while(flushing)await new Promise(r=>setTimeout(r,20));policyAt=0;await policy();
                      globalThis.shapes=[];chrome.webRequest.onBeforeRequest.addListener(d=>{if(d.tabId>=0&&['POST','PUT'].includes(d.method))shapes.push({route:new URL(d.url).pathname,hasError:!!d.requestBody?.error,hasFilePart:(d.requestBody?.raw||[]).some(x=>typeof x.file==='string'),hasBytePart:(d.requestBody?.raw||[]).some(x=>x.bytes instanceof ArrayBuffer),hasFormData:!!d.requestBody?.formData});},{urls:['http://*/*']},['requestBody']);
                    }''',url)
                    page=context.new_page();page.goto(url);page.locator('#file').set_input_files(str(file))
                    page.wait_for_timeout(500)
                    for mode in ('multipart','file_put','buffer_put','slice_put','view_put','request_put','xhr_put','reader_put','blob_put','unrelated_json','parallel'):
                        response=page.evaluate('''async mode=>{let file=document.querySelector('#file').files[0],body=file;if(mode==='multipart'){body=new FormData();body.append('file',file);}if(mode==='buffer_put'||mode==='view_put')body=await file.arrayBuffer();if(mode==='slice_put')body=await file.slice(0,10).arrayBuffer();if(mode==='view_put')body=new Uint8Array(body);if(mode==='unrelated_json')body=JSON.stringify({ordinary:true});if(mode==='request_put'){let r=await fetch(new Request(location.origin+'/'+mode,{method:'PUT',body:await file.arrayBuffer()}));return r.status;}if(mode==='xhr_put')return await new Promise(resolve=>{let x=new XMLHttpRequest();x.open('PUT','/'+mode);x.onload=()=>resolve(x.status);x.send(file);});if(mode==='reader_put')body=await new Promise(resolve=>{const r=new FileReader();r.onload=()=>resolve(r.result);r.readAsArrayBuffer(file);});if(mode==='blob_put')body=new Blob([file]);if(mode==='parallel'){const a=await file.arrayBuffer();await Promise.all([fetch('/parallel',{method:'PUT',body:a}),fetch('/parallel',{method:'PUT',body:a})]);return 200;}let r=await fetch('/'+mode,{method:mode==='multipart'?'POST':'PUT',body});return r.status;}''',mode)
                        assert response==200;time.sleep(.5)
                    # flush() returns early when the existing flusher owns
                    # the queue. Wait for ALL expected response records, not
                    # the first three rows while a cold frozen host is active.
                    deadline=time.monotonic()+45
                    expected=set(('multipart','file_put','buffer_put','slice_put','view_put','request_put','xhr_put','reader_put','blob_put'))
                    while time.monotonic()<deadline:
                        sw.evaluate('async()=>await flush()')
                        with agent.db() as db:observed=[json.loads(r[0]) for r in db.execute('SELECT payload FROM outbox WHERE payload LIKE ?',('%web.upload_response%',))]
                        completed={e['details'].get('url','').split('/')[-1] for e in observed}
                        if expected<=completed and not sw.evaluate('flushing'):break
                        time.sleep(.1)
                    else:raise AssertionError('All expected uploads did not finish draining: '+str(completed))
                    with agent.db() as db:
                        events=[json.loads(r[0]) for r in db.execute('SELECT payload FROM outbox WHERE payload LIKE ?',('%web.upload%',))]
                    sanitized=[{'kind':e['kind'],'route':e['details'].get('url','').split(str(server.server_port))[-1],'file_name':e['details'].get('file_name'),'path_evidence':e['details'].get('path_evidence'),'reason':e['details'].get('reason'),'source_path_provided':bool(e['details'].get('source_path'))} for e in events]
                    assert any(e['kind']=='web.upload_started' and e['details'].get('file_name')==file.name for e in events),'Fixture did not establish working multipart collection'
                    
                    covered={e['details'].get('url','').split('/')[-1] for e in events if e['kind']=='web.upload_started'}
                    assert set(('multipart','file_put','buffer_put','slice_put','view_put','request_put','xhr_put','reader_put','blob_put'))<=covered, covered
                    assert 'unrelated_json' not in covered
                    assert 'parallel' not in covered
                    assert not any('/unrelated_json' in e['details'].get('url','') for e in events)
                    result={'passed_reproduction':True,'product_version':__version__,'extension_version':json.loads((extension/'manifest.json').read_text(encoding='utf-8'))['version'],'scope':'owned_Chromium_loopback_not_actual_ChatGPT_or_installed_Native_Host','frozen_host_used':frozen,'exe_sha256':hashlib.sha256((ROOT/'dist/GuardDesk/GuardDesk.exe').read_bytes()).hexdigest() if frozen else None,'requests':requests,'browser_metadata_shapes':sw.evaluate('shapes'),'events':sanitized,'raw_formats_covered':any(e['kind']=='web.upload_started' and any(mode in e['details'].get('url','') for mode in ('file_put','buffer_put')) for e in events),'actual_ChatGPT_request_format_confirmed':False,'office_changed':False,'request_body_contents_saved':False,'production_registry_accessed':False}
                finally:context.close()
            out=ROOT/('evidence/maintenance/upload-formats-fixed-0.4.56'+('-frozen' if frozen else '')+'.json');out.write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result))
        finally:server.shutdown();server.server_close();agent.close_collectors()


if __name__=='__main__':main()
