"""Actual Chrome ordering, keyboard headers, drafts, wait/cancel and CSV."""
import csv,hashlib,json,subprocess,sys,time
from pathlib import Path
from urllib.parse import parse_qs,urlsplit
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import test_system
from guarddesk import __version__,audit_sort,audit_search_index
from guarddesk.store import Store
from playwright.sync_api import sync_playwright,expect,Error

def main():
    case=test_system.SystemTest('runTest');case.setUp();process=None;errors=[];checks=[];frozen='--frozen' in sys.argv
    try:
        _,did,_=case.make_agent()
        with case.store.connect() as db:
            for i in range(130):Store.event(db,did,'file.deleted','info',{'path':f'C:\\Owned\\{129-i:03d}.docx','process':'tool.exe'},f'owned-sort-{i}',time.time()-100-(i%7))
        case.server.search_index.close()
        while audit_sort.index_batch(case.store):pass
        while audit_search_index.index_batch(case.store):pass
        if frozen:
            case.server.shutdown();case.server.server_close();case.thread.join(5)
            process=subprocess.Popen([str(ROOT/'dist/GuardDesk/GuardDesk.exe'),'serve','--db',str(case.db),'--port',case.url.rsplit(':',1)[1]],cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
            for _ in range(100):
                try:
                    if case.api('/api/health')['version']==__version__:break
                except (OSError,ConnectionError):pass
                time.sleep(.1)
            else:raise AssertionError('frozen Server did not start')
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True)
            try:
                page=browser.new_page(viewport={'width':1700,'height':1050},locale='zh-TW');page.on('pageerror',lambda e:errors.append(str(e)))
                requests=[];cancellations=[];held=[];mode={'pending':0,'hold':False,'csv_fail':False}
                def route(r):
                    url=urlsplit(r.request.url);q=parse_qs(url.query)
                    if url.path=='/api/audit/search/cancel':cancellations.append(r.request.post_data_json['request_id'])
                    if url.path=='/api/events':
                        requests.append(q)
                        if mode['hold']:held.append(r);return
                        if mode['pending']:
                            mode['pending']-=1;r.fulfill(status=200,content_type='application/json',body=json.dumps({'search_pending':True,'search_index':{'purpose':'sort','indexed_rows':42,'error':''}}));return
                    if url.path=='/api/events.csv' and mode['csv_fail']:
                        r.fulfill(status=409,content_type='application/json',body=json.dumps({'error':'owned CSV not ready'}));return
                    r.continue_()
                page.route('**/api/**',route)
                def wait():
                    deadline=time.monotonic()+20
                    while time.monotonic()<deadline:
                        if page.evaluate('()=>!busy'):return
                        page.wait_for_timeout(30)
                    raise AssertionError('UI remained busy')
                def paths():return page.evaluate('events.items.map(e=>e.details.path)')
                def sort(field):page.locator(f'[data-audit-sort="{field}"]').click();wait()
                page.goto(case.url);page.locator('#login-form [name=username]').fill('admin');page.locator('#login-form [name=password]').fill(case.password);page.locator('#login-form button').click();wait()
                page.locator('nav [data-page=audit]').click();wait();page.locator('[data-audit-category=documents]').click();wait()
                expect(page.locator('[data-audit-sort=occurred]').locator('..')).to_have_attribute('aria-sort','descending')
                sort('path');expect(page.locator('[data-audit-sort=path]').locator('..')).to_have_attribute('aria-sort','ascending');seen=paths();assert seen[0]==r'C:\Owned\000.docx'
                for size in (50,30):page.locator('[data-action=next]').click();wait();assert len(paths())==size;seen+=paths()
                assert len(seen)==130 and seen==sorted(seen) and len(set(seen))==130
                expect(page.locator('[data-action=next]')).to_be_disabled();checks.append('global path order across 50/50/30 cursor pages, with no skipped or duplicated rows')
                page.locator('[data-audit-sort=path]').focus();page.keyboard.press('Enter');wait();assert paths()[0]==r'C:\Owned\129.docx';assert page.evaluate('offset')==0
                expect(page.locator('[data-audit-sort=path]').locator('..')).to_have_attribute('aria-sort','descending');checks.append('keyboard activates descending sort, arrow/aria-sort match and page resets to first')
                page.locator('#search-form [name=q]').fill('Owned');sort('device');expect(page.locator('#search-form [name=q]')).to_have_value('Owned');assert requests[-1]['q']==['Owned']
                before=len(requests);page.evaluate('async()=>{for(let i=0;i<3;i++)await refresh({automatic:true});}');assert len(requests)==before;checks.append('unsent visible filters applied without loss; nondefault sorted results are not automatically re-sorted')
                page.locator('[data-query-clear]').click();wait();mode['pending']=2
                page.locator('[data-audit-sort=process]').click();expect(page.locator('#query-feedback')).to_contain_text('準備欄位排序索引中');expect(page.locator('[data-audit-sort=path]')).to_be_disabled();wait();checks.append('derived-key preparation uses explicit progress; column clicks disabled while pending')
                mode['hold']=True;page.locator('[data-audit-sort=path]').click();expect(page.locator('[data-query-cancel]')).to_be_visible()
                expect(page.locator('[data-audit-sort=path]')).to_be_disabled()
                before=len(requests);page.evaluate('()=>{for(let i=0;i<8;i++)document.querySelector("[data-audit-sort=path]").click()}');page.wait_for_timeout(100);assert len(requests)==before
                page.locator('[data-query-cancel]').click();expect(page.locator('#query-feedback')).to_contain_text('已取消等待');expect(page.locator('[data-audit-sort=path]')).to_be_enabled()
                mode['hold']=False
                for r in held:
                    try:r.abort()
                    except Error:pass
                held.clear();sort('path');assert paths()[0]==r'C:\Owned\129.docx';sort('path');assert paths()[0]==r'C:\Owned\000.docx';checks.append('eight repeated clicks do not multiply requests; no-keyword sort sends Server cancellation and can recover')
                with page.expect_download() as download:page.locator('[data-action=csv]').click()
                rows=list(csv.DictReader(Path(download.value.path()).read_text(encoding='utf-8-sig').splitlines()));assert len(rows)==130
                assert [r['source_path'] for r in rows]==sorted(r['source_path'] for r in rows);checks.append('downloaded CSV contains same global sort and all 130 filtered rows')
                mode['csv_fail']=True;page.locator('[data-action=csv]').click();expect(page.locator('#toast')).to_have_text('owned CSV not ready');expect(page.locator('[data-action=csv]')).to_be_enabled();checks.append('CSV readiness/error is visible, never a fake successful download')
                original_start=page.locator('#search-form [name=start]').input_value();page.locator('#search-form [name=start]').fill(original_start[:-2]+'01');sort('device')
                assert page.evaluate('auditDateMode')=='custom';expect(page.locator('#search-form [name=start]')).to_have_value(original_start[:-2]+'01')
                page.locator('[data-audit-today]').click();wait();expect(page.locator('#search-form [name=start]')).to_have_value(original_start);sort('path');checks.append('sorting applies edited dates as custom range; Today restores the automatic Taipei day')
                mode['csv_fail']=False;page.locator('#toast').evaluate('(el)=>el.hidden=true');page.screenshot(path=str(ROOT/f'evidence/audit-sort-desktop-{__version__}.png'))
                page.set_viewport_size({'width':390,'height':844});assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1');page.screenshot(path=str(ROOT/f'evidence/audit-sort-mobile-{__version__}.png'),full_page=True)
                page.set_viewport_size({'width':1700,'height':1050});sort('process');page.locator('[data-audit-category=web]').click();wait()
                assert page.evaluate('auditSort')=='occurred';expect(page.locator('[data-audit-sort=occurred]').locator('..')).to_have_attribute('aria-sort','descending')
                page.evaluate('async()=>await refresh({automatic:true})');assert 'request_id' not in requests[-1];checks.append('automatic default refresh has no replacement nonce, so it cannot cancel a manual query in another tab');sort('title')
                page.locator('[data-audit-category=uploads]').click();wait();assert page.evaluate('auditSort')=='occurred';sort('upload_path');checks.append('web/upload headers work; unsupported sort resets to visible default when switching categories')
                assert cancellations and not errors,errors
            finally:browser.close()
        report={'passed':True,'version':__version__,'frozen_server_used':frozen,'page_errors':errors,'checks':checks,'office_accessed':False,'limits':['130 synthetic file events for browser behavior; large-volume and ingestion measurements are separate','Browser route holds/pending responses verify presentation and burst behavior; SQL cancellation/atomicity verified in unit tests']}
        if frozen:report['exe_sha256']=hashlib.sha256((ROOT/'dist/GuardDesk/GuardDesk.exe').read_bytes()).hexdigest()
        (ROOT/f'evidence/audit-sort-browser-{__version__}{"" if frozen else "-source"}.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,ensure_ascii=False))
    finally:
        if process:process.terminate();process.wait(20)
        case.tearDown()

if __name__=='__main__':main()
