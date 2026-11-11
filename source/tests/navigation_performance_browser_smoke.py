"""Real Chromium: slow old page cannot freeze navigation or overwrite new page."""
import json
from pathlib import Path
import secrets
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs,urlsplit
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk import __version__
from guarddesk.server import Handler,serve
from guarddesk.store import Store
from guarddesk.audit_reports import index_batch
from playwright.sync_api import sync_playwright,expect


def main():
    errors=[];started=threading.Event();finished=threading.Event();armed=threading.Event();state_requests=[]
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime',prefix='navigation-') as tmp:
        store=Store(Path(tmp)/'control.sqlite3');password=secrets.token_urlsafe(24);store.add_user('owned-mis',password)
        with store.connect() as db:
            for i in range(60):Store.event(db,'fixture','file.deleted','info',{'path':f'C:\\Owned\\{i}.txt'},f'owned-{i}')
        while index_batch(store):pass
        original=Handler.route
        def delayed(handler,db,method,path,body):
            q=parse_qs(urlsplit(handler.path).query)
            if armed.is_set() and path=='/api/state':state_requests.append(q.get('stats'))
            if armed.is_set() and path=='/api/events' and q.get('cursor_mode')==['1'] and not started.is_set():
                started.set();time.sleep(2.5);finished.set()
            return original(handler,db,method,path,body)
        with patch.object(Handler,'route',delayed):
            server=serve(store.path,port=0);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                with sync_playwright() as p:
                    browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True)
                    try:
                        page=browser.new_page(viewport={'width':1500,'height':1050});page.on('pageerror',lambda e:errors.append(str(e)))
                        page.goto(f'http://127.0.0.1:{server.server_port}');page.locator('[name=username]').fill('owned-mis');page.locator('[name=password]').fill(password);page.locator('#login-form button').click()
                        expect(page.locator('.stats')).to_be_visible();armed.set()
                        t=time.perf_counter();page.locator('nav [data-page=audit]').click()
                        expect(page.locator('#breadcrumb')).to_have_text('稽核事件',timeout=800)
                        expect(page.locator('#search-form')).to_be_visible();expect(page.locator('#query-feedback[role=status]')).to_be_visible()
                        loading_ms=round((time.perf_counter()-t)*1000,2)
                        assert started.wait(1)
                        t=time.perf_counter();page.locator('nav [data-page=reports]').click()
                        expect(page.locator('#workspace .report-stats')).to_be_visible(timeout=1500)
                        report_ms=round((time.perf_counter()-t)*1000,2)
                        assert not finished.is_set(),'New page waited for the old 2.5s request'
                        expect(page.locator('#workspace h1')).to_have_text('稽核總表')
                        page.wait_for_timeout(2700);expect(page.locator('#workspace h1')).to_have_text('稽核總表')
                        assert state_requests and all(v==['0'] for v in state_requests),state_requests
                        page.screenshot(path=str(ROOT/f'evidence/navigation-performance-{__version__}.png'),full_page=True)
                        assert not errors,errors
                    finally:browser.close()
            finally:server.shutdown();server.server_close();thread.join(5)
    report={'passed':True,'version':__version__,'loading_feedback_ms':loading_ms,'new_report_ready_ms':report_ms,
            'artificial_old_query_ms':2500,'stats_skipped_for_audit_and_report':True,'late_response_did_not_overwrite':True,'page_errors':errors,
            'limits':['Owned 60-event fixture; proves navigation independence, not office Server database latency']}
    (ROOT/f'evidence/navigation-performance-{__version__}.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()
