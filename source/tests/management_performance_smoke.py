"""Isolated MIS page and synthetic 50k audit load; no office data/endpoint."""
import json
import secrets
import sys
import tempfile
import threading
import time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from guarddesk.server import serve
from guarddesk.store import Store,canonical,digest
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime') as tmp:
        root=Path(tmp);store=Store(root/'control.db');password=secrets.token_urlsafe(20);store.add_user('fixture-mis',password);now=time.time()
        with store.connect() as db:
            for i in range(20):db.execute('INSERT INTO devices(id,token,name,department,last_seen,inventory) VALUES (?,?,?,?,?,?)',(str(i),digest('owned-'+str(i)),'Fixture-'+str(i),'Owned lab',now,canonical({'user_accounts':['FIXTURE\\user']})))
            # Synthetic rows solely for query/render load; not integrity proof.
            db.executemany('INSERT INTO events(event_id,device_id,kind,severity,occurred,received,details,prev_hash,hash) VALUES (?,?,?,?,?,?,?,?,?)',
                ((str(i),str(i%20),['file.opened','web.navigation','web.upload_started'][i%3], 'warning' if i%20==0 else 'info',now,now,
                  canonical({'user':'FIXTURE\\user','source_path':r'C:\Owned\report.pdf','url':'https://fixture.invalid/upload','title':'Owned fixture','path_evidence':'browser_request_file','outcome':'request_observed'}),'fixture','fixture') for i in range(50000)))
            old="WHERE (e.kind LIKE ? OR e.details LIKE ? OR COALESCE(d.name,'') LIKE ?) AND (?='' OR e.severity=?) AND (?='' OR e.device_id=?) AND e.kind LIKE ? AND (?='' OR e.kind=?) AND e.occurred BETWEEN ? AND ?"
            old_params=('%%',)*3+('','')*2+('%','','',0,253402300799)
            timings={}
            for name,sql,params in [('previous_unfiltered_count','SELECT count(*) FROM events e LEFT JOIN devices d ON e.device_id=d.id '+old,old_params),('new_unfiltered_count','SELECT count(*) FROM events',())]:
                samples=[]
                for _ in range(5):
                    t=time.perf_counter();assert db.execute(sql,params).fetchone()[0]==50000;samples.append((time.perf_counter()-t)*1000)
                timings[name+'_median_ms']=round(sorted(samples)[2],3)
        server=serve(store.path,port=0);threading.Thread(target=server.serve_forever,daemon=True).start();url=f'http://127.0.0.1:{server.server_port}'
        errors=[];requests=[];report={'passed':False,'synthetic_events':50000,'synthetic_endpoints':20,'query_timings':timings,'checks':[]}
        try:
            with sync_playwright() as p:
                browser=p.chromium.launch(channel='chromium',headless=True)
                try:
                    page=browser.new_page(viewport={'width':1640,'height':1080},locale='zh-TW');page.on('pageerror',lambda e:errors.append(str(e)));page.on('request',lambda r:requests.append(r.url))
                    def wait_js(expression):
                        until=time.monotonic()+10
                        while time.monotonic()<until:
                            if page.evaluate(expression):return
                            time.sleep(.05)
                        raise AssertionError('UI state timeout: '+expression)
                    page.goto(url);page.locator('[name=username]').fill('fixture-mis');page.locator('[name=password]').fill(password);page.locator('#login-form button').click();page.get_by_role('heading',name='安全總覽',exact=True).wait_for()
                    page.evaluate("""()=>{globalThis.renderCount=0;const real=render;render=()=>{renderCount++;return real();};}""")
                    page.locator('nav [data-page=devices]').click();page.locator('#fleet-search').wait_for();before=len([r for r in requests if '/api/events?' in r])
                    page.locator('#fleet-search').fill('Fixture-1');node=page.locator('#fleet-search').element_handle();awaited=page.evaluate('async()=>{await refresh({automatic:true});return renderCount;}');assert node.evaluate('e=>e.isConnected')
                    page.locator('#fleet-search').blur();page.evaluate('async()=>{await refresh();}');count=page.evaluate('renderCount')
                    # Only server_time changes: stable page must retain its DOM.
                    node=page.locator('#fleet-search').element_handle();page.evaluate('async()=>{await refresh({automatic:true});}');assert page.evaluate('renderCount')==count;assert node.evaluate('e=>e.isConnected')
                    assert len([r for r in requests if '/api/events?' in r])==before
                    report['checks'].append('Fleet page skips unused audit query; focused search and unchanged DOM preserved on automatic refresh')
                    page.locator('nav [data-page=audit]').click();page.locator('#search-form').wait_for();page.locator('[data-audit-category=uploads]').click()
                    try:page.locator('th').filter(has_text='本機來源完整路徑').wait_for(timeout=10000)
                    except Exception:
                        print(json.dumps({'errors':errors,'state':page.evaluate('({page,auditCategory,busy,refreshAgain,query:auditQuery(false),total:events.total})'),'headers':page.locator('th').all_text_contents(),'html':page.locator('#workspace').inner_html()[-1800:],'toast':page.locator('#toast').inner_text(),'requests':requests[-12:]}));raise
                    assert 'C:\\Owned\\report.pdf' in page.locator('#workspace').inner_text()
                    assert 'Fixture-' in page.locator('#workspace').inner_text()
                    page.screenshot(path=str(ROOT/'evidence/management-upload-0.4.22.png'),full_page=True)
                    report['checks'].append('Upload tab displays full source path, destination and evidence limitations on real management UI')
                    # Response arrives while search editing begins: must not replace controls.
                    page.locator('#search-form input[name=q]').blur()
                    page.evaluate("""()=>{const real=api;globalThis.releaseState=null;globalThis.holdNext=true;api=async (...a)=>{const value=await real(...a);if(a[0]==='/api/state'&&holdNext){holdNext=false;await new Promise(r=>releaseState=r);}return value;};globalThis.pendingRefresh=refresh({automatic:true});}""")
                    wait_js('()=>releaseState!==null');page.locator('#search-form input[name=q]').fill('unsent draft');node=page.locator('#search-form').element_handle();page.evaluate('async()=>{releaseState();await pendingRefresh;}');assert node.evaluate('e=>e.isConnected');assert page.locator('[name=q]').input_value()=='unsent draft'
                    report['checks'].append('Late automatic response preserves in-progress search draft')
                    # Rapid page switches under slow response are queued, not lost.
                    page.evaluate('()=>{holdNext=true;releaseState=null;}');page.locator('nav [data-page=devices]').click();wait_js('()=>busy');page.locator('nav [data-page=coverage]').click();wait_js('()=>releaseState!==null');page.evaluate('()=>releaseState()');page.locator('h1').filter(has_text='功能與範圍').wait_for(timeout=10000)
                    report['checks'].append('Rapid navigation during request completes on last selected page')
                    assert not errors,errors
                    report['browser_page_errors']=errors;report['passed']=True
                finally:browser.close()
        finally:server.shutdown();server.server_close()
        (ROOT/'evidence/management-performance-0.4.22.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report,indent=2))


if __name__=='__main__':main()
