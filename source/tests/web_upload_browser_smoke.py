"""Owned Chromium profile/pages/files; no existing registry/profile changes.

The browser extension uses an isolated loopback native adapter invoking the
actual Python Native Messaging handler. Framing/frozen EXE are tested elsewhere.
"""
import copy
import json
import socket
import shutil
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from guarddesk import __version__
from guarddesk.agent import Agent,private_write
from guarddesk.browser_host import handle_message
from guarddesk.policy import DEFAULT_POLICY
from guarddesk.store import canonical
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime') as temp:
        root=Path(temp);watch=root/'documents';watch.mkdir();config=root/'runtime/agent/config.json'
        private_write(config,{'server':'http://127.0.0.1:1','device_id':'upload-fixture','token':'fixture-offline-token','watch':str(watch)})
        agent=Agent(config);fail_native=False;received=[]
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith('/asset/'):
                    data=b'owned';kind='text/plain'
                else:
                    data=b'<title>Owned upload fixture</title><input type=file multiple id=f><input id=typing><div id=drop>Drop here</div>';kind='text/html'
                self.send_response(200);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
            def do_POST(self):
                length=int(self.headers.get('Content-Length',0));body=self.rfile.read(length)
                if self.path=='/native':
                    if fail_native:self.send_error(503);return
                    try:result=handle_message(agent,json.loads(body))
                    except Exception as e:result={'ok':False,'error':str(e)}
                    data=json.dumps(result).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data);return
                received.append({'path':self.path.split('?')[0],'bytes':length})
                if self.path=='/abort':self.connection.shutdown(socket.SHUT_RDWR);self.connection.close();return
                if self.path=='/redirect':self.send_response(307);self.send_header('Location','/final?token=fixture-secret');self.send_header('Content-Length','0');self.end_headers();return
                self.send_response(413 if self.path=='/reject' else 204);self.send_header('Content-Length','0');self.end_headers()
            do_PUT=do_POST
            def log_message(*a):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),H);threading.Thread(target=server.serve_forever,daemon=True).start();url=f'http://127.0.0.1:{server.server_port}'
        report={'passed':False,'checks':[],'limitations':['Owned Chromium, not installed Chrome/Edge profile','Loopback native adapter invokes actual handler; does not test installed native-host registry','Multipart file evidence only; not universal website coverage','Timing from synthetic local fixture, not office network or boot benchmark']}
        try:
            small=watch/'upload-fixture.txt';small.write_bytes(b'owned upload fixture')
            large=watch/'large-fixture.bin'
            with large.open('wb') as f:
                for _ in range(16):f.write(b'x'*1024*1024)
            def rows():
                with agent.db() as db:return [json.loads(r[0]) for r in db.execute('SELECT payload FROM outbox')]
            with sync_playwright() as p:
                extension_copy=root/'extension';shutil.copytree(ROOT/'browser-extension',extension_copy)
                background=extension_copy/'background.js';background.write_text(background.read_text(encoding='utf-8').replace("HOST='com.guarddesk.agent'","HOST='com.guarddesk.owned_test_unregistered'"),encoding='utf-8')
                ext=str(extension_copy)
                context=p.chromium.launch_persistent_context(str(root/'profile'),channel='chromium',headless=True,args=['--disable-extensions-except='+ext,'--load-extension='+ext])
                errors=[]
                try:
                    worker=context.service_workers[0] if context.service_workers else context.wait_for_event('serviceworker',timeout=15000)
                    worker.evaluate("""async url=>{
                      globalThis.logged=[];console.error=(...args)=>logged.push(args.map(String));
                      native=async message=>{const response=await fetch(url+'/native',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(message)});if(!response.ok)throw new Error('fixture host offline');const value=await response.json();if(!value.ok)throw new Error(value.error);return value;};
                      globalThis.proxyCalls={set:0,clear:0};
                      for(const name of ['set','clear']){const original=chrome.proxy.settings[name].bind(chrome.proxy.settings);chrome.proxy.settings[name]=(...args)=>{proxyCalls[name]++;return original(...args);};}
                      while(flushing)await new Promise(r=>setTimeout(r,20));policyAt=0;await flush();
                      globalThis.shapes=[];chrome.webRequest.onBeforeRequest.addListener(d=>{if(['POST','PUT'].includes(d.method)&&d.tabId>=0)shapes.push({url:d.url.split('?')[0],keys:Object.keys(d.requestBody||{}),files:(d.requestBody?.raw||[]).filter(p=>p.file).map(p=>p.file),error:d.requestBody?.error});},{urls:['http://*/*']},['requestBody']);
                    }""",url)
                    long_url=worker.evaluate("()=>event({type:'web_upload',url:'https://name:password@fixture.invalid/'+('a'.repeat(9000))})")
                    assert long_url['url']=='https://fixture.invalid/' and long_url['url_truncated'] is True
                    page=context.new_page();page.on('pageerror',lambda e:errors.append(str(e)));page.goto(url)
                    page.locator('#f').set_input_files(str(small))
                    page.evaluate("async()=>{for(let i=0;i<6;i++)history.pushState({},'', '/page-'+i);}")
                    def upload(path='/upload',mode='multipart'):
                        return page.evaluate("""async ({path,mode})=>{let file=document.querySelector('#f').files[0],body=file;if(mode!=='raw'){body=new FormData();body.append('attachment',file);if(mode==='mixed')body.append('password','fixture-form-secret');}let t=performance.now();try{const r=await fetch(path,{method:mode==='raw'?'PUT':'POST',body});return {status:r.status,ms:performance.now()-t};}catch{return {error:true,ms:performance.now()-t};}}""",{'path':path,'mode':mode})
                    def wait_for(predicate,seconds=15):
                        until=time.monotonic()+seconds
                        while time.monotonic()<until:
                            if predicate():return
                            time.sleep(.1)
                        raise AssertionError('Timed out waiting for upload evidence: '+json.dumps({'storage':worker.evaluate('async()=>await chrome.storage.local.get(null)'), 'shapes':worker.evaluate('shapes'), 'errors':worker.evaluate('logged'), 'rows':rows()}))
                    first=upload('/upload?token=fixture-secret');wait_for(lambda:any(r['kind']=='web.upload_response' for r in rows()))
                    evidence=[r for r in rows() if r['kind'].startswith('web.upload_')]
                    assert any(r['details'].get('source_path')==str(small) for r in evidence),evidence
                    assert len({r['details'].get('upload_id') for r in evidence if r['kind']!='web.upload_gap'})==1
                    assert all(r['details']['application_success']=='unknown' for r in evidence)
                    assert 'fixture-form-secret' not in canonical(rows()) and 'fixture-secret' not in canonical(rows())
                    report['checks'].append('Real multipart request: exact local path -> redacted destination, stable flow, HTTP response; no form values or content stored')
                    upload('/mixed','mixed');wait_for(lambda:any('/mixed' in r['details'].get('url','') and r['kind']=='web.upload_response' for r in rows()))
                    mixed=[r['details'] for r in rows() if '/mixed' in r['details'].get('url','')]
                    assert all(d.get('source_path')=='' and d.get('path_evidence')=='selected_filename_match' for d in mixed),mixed
                    assert 'fixture-form-secret' not in canonical(rows())
                    report['checks'].append('Mixed FormData filename matched recent selection, explicitly candidate only, absolute path absent; password omitted')
                    upload('/redirect');upload('/reject');upload('/abort')
                    wait_for(lambda:any(r['kind']=='web.upload_failed' for r in rows()) and any(r['kind']=='web.upload_redirected' for r in rows()))
                    assert any(r['details'].get('status_code')==413 for r in rows())
                    report['checks'].append('307 redirect, HTTP 413 and network failure recorded separately; HTTP 2xx not application success')
                    upload('/raw','raw');wait_for(lambda:any('/raw' in r['details'].get('url','') and r['kind']=='web.upload_response' for r in rows()))
                    assert all(r['details'].get('path_evidence')=='page_body_metadata_candidate' for r in rows() if '/raw' in r['details'].get('url',''))
                    report['checks'].append('Raw File PUT matches selected metadata candidate and actual request, never invents a full path')
                    fail_native=True
                    upload('/offline');time.sleep(.6)
                    queued=worker.evaluate('async()=>await chrome.storage.local.get({queue:[]})')
                    assert any('/offline' in r.get('url','') for r in queued['queue'])
                    assert 'fixture-secret' not in json.dumps(queued)
                    fail_native=False;worker.evaluate('async()=>{policyAt=0;await flush();}')
                    wait_for(lambda:any('/offline' in r['details'].get('url','') for r in rows()))
                    report['checks'].append('Offline host queue persisted redacted events and replayed to durable Agent SQLite')
                    # Exercise queue mutation while native send is in flight.
                    page.locator('#f').set_input_files(str(large));large_result=upload('/large')
                    wait_for(lambda:any('/large' in r['details'].get('url','') and r['kind']=='web.upload_response' for r in rows()))
                    report['multipart_16mib_ms']=round(large_result['ms'],2)
                    # GET resource bursts do not perform persistence/native work.
                    count_before=len(rows());timer=page.evaluate("""async()=>{let t=performance.now();await Promise.all(Array.from({length:100},(_,i)=>fetch('/asset/'+i)));return performance.now()-t;}""")
                    report['get_100_ms']=round(timer,2)
                    page.locator('#typing').fill('typing remains responsive')
                    calls=worker.evaluate('proxyCalls');assert calls=={'set':0,'clear':0},calls
                    # Corporate automatic deployment must not send browsing to
                    # an unconfigured local proxy just because a domain rule
                    # already exists on the Server.
                    domain_policy=copy.deepcopy(DEFAULT_POLICY)
                    domain_policy['upload_rules']=[{'type':'domain','target':'example.com','rate_kbps':1000}]
                    with agent.db() as db:db.execute("INSERT OR REPLACE INTO state VALUES ('policy',?)",(canonical({'version':2,'body':domain_policy}),))
                    state=worker.evaluate('async()=>{policyAt=0;return await policy();}')
                    assert not state['proxy_required'] and state['proxy_policy_state']=='proxy_not_configured',state
                    assert worker.evaluate('proxyCalls')=={'set':0,'clear':0}
                    report['checks'].append('Existing domain rule with automatic audit-only host does not set PAC when local proxy is unconfigured')
                    # Same actual PAC should not be re-applied after cache expiry.
                    worker.evaluate("""async()=>{const real=native;native=async m=>m.type==='status'?{ok:true,browser_audit:true,web_upload_audit:true,proxy_required:true,pac:'function FindProxyForURL(){return "DIRECT";}'}:real(m);policyAt=0;await policy();}""")
                    assert worker.evaluate('proxyCalls')=={'set':0,'clear':0}
                    assert worker.evaluate('currentPolicy.proxy_policy_state')=='agent_upgrade_required'
                    report['checks'].append('Extension arriving before an older Agent preserves proxy settings instead of applying an unverified PAC')
                    worker.evaluate("""async()=>{native=async()=>({ok:true,browser_audit:true,web_upload_audit:true,proxy_required:true,proxy_policy_state:'configured_requires_runtime_check',pac:'function FindProxyForURL(){return "DIRECT";}'});policyAt=0;await policy();policyAt=0;await policy();}""")
                    calls=worker.evaluate('proxyCalls');assert calls['set']==1 and calls['clear']==0,calls
                    report['checks'].append('No proxy set/clear on ordinary navigation; unchanged PAC applied once across repeated policy refresh')
                    # Preserve past durable backlog while collection is disabled.
                    policy=copy.deepcopy(DEFAULT_POLICY);policy['browser_audit']=False
                    with agent.db() as db:db.execute("INSERT OR REPLACE INTO state VALUES ('policy',?)",(canonical({'version':2,'body':policy}),))
                    worker.evaluate("""async()=>{await chrome.storage.local.set({queue:[event({type:'navigation',url:'https://fixture.invalid/preserved',timestamp:Date.now()})]});native=async m=>({ok:true,browser_audit:false,web_upload_audit:false,proxy_required:false});policyAt=0;await flush();}""")
                    assert len(worker.evaluate('async()=>(await chrome.storage.local.get({queue:[]})).queue'))==1
                    report['checks'].append('Disabled audit preserves backlog; native policy independently prevents new upload logging')
                    assert not errors,errors
                finally:context.close()
            report.update(passed=True,version=__version__,first_multipart_ms=round(first['ms'],2),proxy_setting_calls=calls,browser_page_errors=errors,received_fixture_requests=received)
            (ROOT/f'evidence/web-upload-browser-{__version__}.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report,indent=2))
        finally:server.shutdown();server.server_close();agent.close_collectors()


if __name__=='__main__':main()
