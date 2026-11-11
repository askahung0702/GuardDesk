"""Real Chrome: same-page query feedback/cancel/errors/drafts and navigation."""
import hashlib,json,subprocess,sys,time
from pathlib import Path
from urllib.parse import parse_qs,urlsplit
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk import __version__
from guarddesk.store import Store
from guarddesk.audit_reports import index_batch
import test_system
from playwright.sync_api import sync_playwright,expect,Error

def main():
    case=test_system.SystemTest('runTest');case.setUp();process=None;frozen='--frozen' in sys.argv;errors=[];checks=[]
    try:
        _,did,_=case.make_agent()
        with case.store.connect() as db:
            for i in range(70):Store.event(db,did,'file.deleted','info',{'path':f'C:\\Owned\\26C0018\\{i}.docx'},f'owned-query-{i}')
        while index_batch(case.store):pass
        if frozen:
            case.server.shutdown();case.server.server_close();case.thread.join(5)
            process=subprocess.Popen([str(ROOT/'dist/GuardDesk/GuardDesk.exe'),'serve','--db',str(case.db),'--port',case.url.rsplit(':',1)[1]],cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
            for _ in range(100):
                try:
                    if case.api('/api/health')['version']==__version__:break
                except (OSError,ConnectionError):pass
                time.sleep(.1)
            else:raise AssertionError('frozen server did not start')
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True)
            try:
                page=browser.new_page(viewport={'width':1700,'height':1100},locale='zh-TW');page.on('pageerror',lambda e:errors.append(str(e)))
                def wait_eval(expression):
                    deadline=time.monotonic()+10
                    while time.monotonic()<deadline:
                        if page.evaluate(expression):return
                        page.wait_for_timeout(30)
                    raise AssertionError('UI condition did not complete: '+expression)
                held=[];requests=[];cancelled=[];mode={'hold':set(),'report':False,'fail_next':False,'index_pending':0,'fail_state':False}
                def route(r):
                    url=urlsplit(r.request.url);q=parse_qs(url.query).get('q',[''])[0]
                    if url.path=='/api/state' and mode['fail_state']:
                        mode['fail_state']=False;r.fulfill(status=500,content_type='application/json',body=json.dumps({'error':'owned parallel state failure'}));return
                    if url.path=='/api/events':requests.append(q)
                    if url.path=='/api/audit/search/cancel':cancelled.append(r.request.post_data_json['request_id'])
                    if url.path=='/api/events' and mode['fail_next']:
                        mode['fail_next']=False;r.fulfill(status=408,content_type='application/json',body=json.dumps({'error':'關鍵字搜尋超過時間限制，請重試。'}));return
                    if url.path=='/api/events' and mode['index_pending']:
                        mode['index_pending']-=1;r.fulfill(status=200,content_type='application/json',body=json.dumps({'search_pending':True,'search_index':{'indexed_rows':1500,'error':''}}));return
                    if url.path=='/api/events' and q=='ERROR':r.fulfill(status=408,content_type='application/json',body=json.dumps({'error':'關鍵字搜尋超過時間限制，請縮小日期後重試。'}));return
                    if (url.path=='/api/events' and q in mode['hold']) or (url.path=='/api/audit/summary' and mode['report']):held.append(r);return
                    r.continue_()
                page.route('**/api/**',route)
                page.goto(case.url);page.locator('[name=username]').fill('admin');page.locator('[name=password]').fill(case.password);page.locator('#login-form button').click();expect(page.locator('.stats')).to_be_visible()
                page.locator('nav [data-page=audit]').click();page.locator('[data-audit-category=documents]').click();expect(page.locator('#search-form')).to_be_visible();wait_eval('()=>(!busy)')
                def search(value):page.locator('#search-form [name=q]').fill(value);page.locator('#search-form button').first.click()
                def wait_held():
                    wait_eval("()=>(document.querySelector('#query-feedback [data-query-cancel]')!==null)")
                    for _ in range(30):
                        if held:return
                        page.wait_for_timeout(30)
                    raise AssertionError('search request was not held')
                def release(abort=False):
                    r=held.pop(0)
                    try:r.abort() if abort else r.continue_()
                    except Error:
                        if not abort:raise
                mode['hold'].add('26C0018');start=time.perf_counter();search('26C0018');wait_held()
                expect(page.locator('#query-feedback')).to_contain_text('查詢中');expect(page.locator('#search-form button').first).to_be_disabled();expect(page.locator('#workspace')).to_have_attribute('aria-busy','true')
                feedback_ms=round((time.perf_counter()-start)*1000,2);old=page.evaluate('events.items.map(e=>e.id)');assert len(old)==50
                page.locator('#search-form [name=q]').fill('尚未送出的草稿');page.screenshot(path=str(ROOT/f'evidence/audit-search-wait-{__version__}.png'),full_page=True)
                mode['hold'].clear();release();wait_eval('()=>(!busy)');expect(page.locator('#query-feedback')).to_have_count(0);expect(page.locator('#search-form [name=q]')).to_have_value('尚未送出的草稿');assert page.evaluate('events.items.length')==50
                page.locator('[data-action=next]').click();wait_eval('()=>(!busy && events.items.length===20)');page.locator('[data-action=prev]').click();wait_eval('()=>(!busy && events.items.length===50)');checks.append('same-page waiting/elapsed/disabled submit; draft survives response; 50/20 cursor pages')
                mode['hold'].add('CANCEL');search('CANCEL');wait_held();page.locator('[data-query-cancel]').click();expect(page.locator('#query-feedback')).to_contain_text('已取消等待');expect(page.locator('#search-form button').first).to_be_enabled();expect(page.locator('[data-action=next]')).to_be_disabled();release(True);checks.append('cancel restores controls, marks old results and disables stale pagination')
                mode['hold'].clear();search('ERROR');expect(page.locator('#query-feedback[role=alert]')).to_contain_text('超過時間限制');expect(page.locator('#query-feedback')).to_contain_text('上次查詢結果');expect(page.locator('#search-form button').first).to_be_enabled();checks.append('server error is visible beside query; no false empty or successful results')
                page.evaluate('window.savedSearchTimeout=window.setTimeout;window.setTimeout=(f,ms,...args)=>savedSearchTimeout(f,ms===20000?1000:ms,...args)')
                mode['hold'].add('CLIENTTIMEOUT');search('CLIENTTIMEOUT');wait_held();expect(page.locator('#query-feedback[role=alert]')).to_contain_text('等待逾時',timeout=3000);release(True);page.evaluate('window.setTimeout=window.savedSearchTimeout');checks.append('client wait timeout restores retry instead of leaving a permanent spinner')
                mode['hold'].add('LATE');search('LATE');wait_held();page.locator('nav [data-page=reports]').click();expect(page.locator('#report-form')).to_be_visible(timeout=2000);wait_eval('()=>(!busy)');release(True);expect(page.locator('#workspace')).not_to_have_attribute('aria-busy','true');expect(page.locator('#workspace h1')).to_have_text('稽核總表');checks.append('navigation cancels old wait and cannot leave the next page busy')
                mode['report']=True;page.locator('#report-form button').first.click();wait_held();expect(page.locator('#query-feedback')).to_contain_text('查詢中');mode['report']=False;release();wait_eval('()=>(!busy)');expect(page.locator('#query-feedback')).to_have_count(0);checks.append('same-page summary query also has waiting feedback')
                mode['hold'].clear();page.locator('nav [data-page=audit]').click();wait_eval('()=>(!busy)');search('26C0018');wait_eval('()=>(!busy)');expect(page.locator('#query-feedback')).to_have_count(0)
                page.set_viewport_size({'width':390,'height':844});mode['hold'].add('MOBILE');search('MOBILE');wait_held();assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1');page.screenshot(path=str(ROOT/f'evidence/audit-search-mobile-{__version__}.png'),full_page=True);page.locator('[data-query-cancel]').click();release(True)
                mode['hold'].clear();page.set_viewport_size({'width':1700,'height':1100})
                page.locator('nav [data-page=reports]').click();wait_eval('()=>(!busy)');mode['fail_next']=True
                page.locator('nav [data-page=audit]').click();expect(page.locator('#search-form')).to_be_visible();expect(page.locator('#query-feedback[role=alert]')).to_be_visible();expect(page.locator('[data-query-clear]')).to_be_enabled();expect(page.locator('[data-query-empty]')).to_contain_text('本次查詢未完成')
                page.screenshot(path=str(ROOT/f'evidence/search-recovery-error-{__version__}.png'),full_page=True)
                before=len(requests);page.evaluate('async()=>{for(let n=0;n<5;n++)await refresh({automatic:true});}');page.wait_for_timeout(200);assert len(requests)==before
                page.locator('nav [data-page=reports]').click();wait_eval('()=>(!busy)');page.locator('nav [data-page=audit]').click();wait_eval('()=>(!busy)');expect(page.locator('#search-form [name=q]')).to_have_value('');assert page.evaluate('events.items.length')==50
                checks.append('first-load error retains editable form; automatic retries paused; Audit navigation clears failed keyword and returns plain page')
                mode['index_pending']=2;search('26C0018');expect(page.locator('#query-feedback')).to_contain_text('建立搜尋索引中');wait_eval('()=>(!busy)');assert page.evaluate('events.items.length')==50
                before=len(requests);page.evaluate('async()=>{for(let n=0;n<5;n++)await refresh({automatic:true});}');assert len(requests)==before
                checks.append('index preparation shows progress and polls lightly before one real search; successful keyword searches are not auto replayed')
                mode['hold'].add('BURST');search('BURST');wait_held();before=len(requests)
                for _ in range(8):page.locator('nav [data-page=audit]').click()
                assert len(requests)==before,'repeat navigation spawned searches'
                page.locator('[data-query-clear]').click();wait_eval('()=>(!busy)');release(True);assert page.evaluate('events.items.length')==50
                assert cancelled and all(len(value)==32 for value in cancelled)
                checks.append('eight repeated Audit clicks create no extra pending search; clear cancels old request on Server and loads normal list')
                mode['hold'].clear();mode['index_pending']=20;mode['fail_state']=True;search('STATEFAIL');expect(page.locator('#query-feedback[role=alert]')).to_contain_text('owned parallel state failure');before=len(requests);page.wait_for_timeout(1300);assert len(requests)==before,'a failed sibling API left a zombie index poll';checks.append('parallel state API failure aborts sibling index polling and notifies Server cancellation')
                assert not errors,errors
            finally:browser.close()
        result={'passed':True,'version':__version__,'frozen_server_used':frozen,'feedback_ms':feedback_ms,'checks':checks,'page_errors':errors,'live_office_access':False,'limits':['Synthetic 70-file fixture; requests held at browser network boundary to verify visible waiting and cancellation','Cancellation requests carry an authenticated session-scoped request ID; real Server SQL cancellation and slot release are separately exercised by unit tests']}
        if frozen:result['exe_sha256']=hashlib.sha256((ROOT/'dist/GuardDesk/GuardDesk.exe').read_bytes()).hexdigest()
        (ROOT/f'evidence/audit-search-browser-{__version__}{"" if frozen else "-source"}.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps(result,ensure_ascii=False))
    finally:
        if process:process.terminate();process.wait(20)
        case.tearDown()
if __name__=='__main__':main()
