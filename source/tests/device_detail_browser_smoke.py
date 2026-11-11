"""Owned browser/API benchmark; audit reads are denied during device detail."""
import ast
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import statistics
import sys
import tempfile
import threading
import time
from unittest.mock import patch
import zipfile

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk import __version__,server as server_module
from guarddesk.server import Handler,serve
from guarddesk.store import Store
from guarddesk import event_storage
from playwright.sync_api import sync_playwright,expect


def main():
    errors=[];reads=[];detail_times=[];mode={'old':False};requests=[]
    # Benchmark the real previous handler, extracted only from our sealed source.
    prior=ROOT/'dist/GuardDesk-0.4.34-source.zip'
    assert hashlib.sha256(prior.read_bytes()).hexdigest()=='ef1af7309907c2148528cf9e21d5094f508198585723b6963278ccd39ed7e6a6'
    with zipfile.ZipFile(prior) as z:tree=ast.parse(z.read('guarddesk/server.py'))
    cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Handler')
    node=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='route')
    namespace=vars(server_module).copy();exec(compile(ast.Module(body=[node],type_ignores=[]),'sealed-0.4.34-route','exec'),namespace)
    old_route=namespace['route'];current=Handler.route
    def guarded(handler,db,method,path,body):
        if path!='/api/device-detail':return current(handler,db,method,path,body)
        if mode['old']:return old_route(handler,db,method,path,body)
        def authorize(action,table,column,schema,origin):
            if action==sqlite3.SQLITE_READ:
                reads.append(table)
                if table=='events' or table.startswith(('events_','event_')):return sqlite3.SQLITE_DENY
            if action==sqlite3.SQLITE_FUNCTION and column in ('event_value','event_identifier'):return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        db.set_authorizer(authorize);started=time.perf_counter()
        try:return current(handler,db,method,path,body)
        finally:detail_times.append((time.perf_counter()-started)*1000);db.set_authorizer(None)
    with tempfile.TemporaryDirectory(prefix='detail-browser-',dir=ROOT/'runtime') as tmp:
        store=Store(Path(tmp)/'control.sqlite3');password=secrets.token_urlsafe(24);store.add_user('owned-mis',password)
        inventory={'user_accounts':['OWNED\\fixture'],'agent_version':'owned-fixture','collectors':{}}
        with store.connect() as db:
            db.execute('INSERT INTO devices(id,token,name,department,last_seen,inventory) VALUES (?,?,?,?,?,?)',('owned-device',secrets.token_hex(20),'測試端點','隔離測試',time.time(),json.dumps(inventory)))
            for i in range(3000):
                Store.event(db,'owned-device','web.navigation' if i%2 else 'application.started','info',{'domain':f'owned-{i%50}.example','url':f'https://owned-{i%50}.example/path','process':f'C:\\Owned\\app{i%30}.exe'},f'legacy-{i}')
        with store.connect() as db:event_storage.enable(db,store.path,snapshot_backup=False)
        with store.connect() as db:
            for i in range(3000):Store.event(db,'owned-device','web.navigation' if i%2 else 'application.stopped','info',{'domain':f'owned-{i%50}.example','url':f'https://owned-{i%50}.example/path','process':f'C:\\Owned\\app{i%30}.exe'},f'daily-{i}')
        for _ in range(32):
            event_storage.flush(store)
            with store.connect() as db:
                if not db.execute('SELECT count(*) FROM event_pending').fetchone()[0]:break
        else:raise AssertionError('Fixture daily flush did not finish')
        with patch.object(Handler,'route',guarded):
            server=serve(store.path,port=0);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            url=f'http://127.0.0.1:{server.server_port}'
            try:
                with sync_playwright() as p:
                    browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True)
                    try:
                        context=browser.new_context(viewport={'width':1600,'height':1050},timezone_id='Asia/Taipei')
                        assert context.request.post(url+'/api/login',data={'username':'owned-mis','password':password}).ok
                        samples={}
                        for old in (True,False):
                            mode['old']=old;samples[old]=[]
                            for _ in range(3):
                                started=time.perf_counter();response=context.request.get(url+'/api/device-detail?device_id=owned-device')
                                assert response.ok,response.text();samples[old].append((time.perf_counter()-started)*1000)
                        assert set(response.json())=={'device','effective_policy','preview_policy'}
                        page=context.new_page();page.on('pageerror',lambda e:errors.append(str(e)))
                        page.on('request',lambda r:requests.append(r.url))
                        page.goto(url);expect(page.locator('#shell')).to_be_visible()
                        page.locator('nav [data-page=devices]').click();expect(page.locator('[data-action=device][data-id=owned-device]')).to_be_visible()
                        requests.clear();started=time.perf_counter()
                        page.locator('[data-action=device][data-id=owned-device]').click()
                        expect(page.locator('#dialog .detail-summary')).to_be_visible()
                        modal_ms=(time.perf_counter()-started)*1000
                        assert page.locator('[data-action=detail-tab]').all_text_contents()==['基本資料','有效策略與來源']
                        page.locator('[data-action=detail-tab][data-tab=effective]').click()
                        with page.expect_response(lambda r:'/api/device-detail?' in r.url):page.locator('#detail-principal').select_option('OWNED\\fixture')
                        assert not any('/api/events' in r or '/api/audit/reports' in r for r in requests)
                        page.screenshot(path=str(ROOT/f'evidence/device-detail-{__version__}.png'),full_page=True)
                        page.locator('#close-dialog').click();page.locator('nav [data-page=audit]').click()
                        expect(page.locator('#search-form')).to_be_visible();expect(page.locator('.detailed-audit tbody tr')).to_have_count(50)
                        assert not errors,errors
                    finally:browser.close()
            finally:server.shutdown();server.server_close();thread.join(5)
    assert reads and not any(t=='events' or t.startswith(('events_','event_')) for t in reads)
    report={'version':__version__,'passed':True,'fixture_legacy_events':3000,'fixture_daily_events':3000,
            'old_0_4_34_api_median_ms':round(statistics.median(samples[True]),2),
            'new_api_median_ms':round(statistics.median(samples[False]),2),
            'new_handler_median_ms':round(statistics.median(detail_times),2),'modal_ready_ms':round(modal_ms,2),
            'audit_reads_denied_and_detail_succeeded':True,'only_basic_and_effective_tabs':True,
            'personal_preview_works':True,'audit_screen_still_pages_50':True,'page_errors':errors,
            'limits':['Owned 6000-event localhost fixture, not office database latency','Previous handler runs against the same fixture and current shared helpers; same authenticated HTTP path','No office endpoint, policy, credentials or data changed']}
    (ROOT/f'evidence/device-detail-{__version__}.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,ensure_ascii=True))


if __name__=='__main__':main()
