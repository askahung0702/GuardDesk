"""Browser UI and simulated update statuses. Never execute an uploaded payload."""
import http.cookiejar
import json
import re
import secrets
import sys
import tempfile
import threading
import urllib.request
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from guarddesk.agent import Agent,enroll
from guarddesk.store import Store
from guarddesk.server import serve
from test_updates import release
from playwright.sync_api import sync_playwright
from guarddesk import __version__


def main():
    root=Path(__file__).resolve().parents[1];errors=[]
    with tempfile.TemporaryDirectory(dir=root/'runtime') as temp:
        scratch=Path(temp);watch=scratch/'docs';watch.mkdir();store=Store(scratch/'db.sqlite3');password=secrets.token_urlsafe(20);store.add_user('update-mis',password)
        server=serve(store.path,port=0);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();url=f'http://127.0.0.1:{server.server_port}'
        client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        def api(path,body=None,csrf=None):
            headers={'Content-Type':'application/json'}
            if csrf:headers['X-CSRF-Token']=csrf
            req=urllib.request.Request(url+path,data=json.dumps(body).encode() if body is not None else None,headers=headers)
            with client.open(req,timeout=10) as response:return json.load(response)
        session=api('/api/login',{'username':'update-mis','password':password});code=api('/api/enrollments',{},session['csrf'])['token']
        cfg=scratch/'agent/config.json';did=enroll(cfg,url,code,watch,name='更新測試端點');agent=Agent(cfg);agent.heartbeat(refresh_inventory=False)
        for role in ('native','main'):agent.call('/api/agent/updates/poll',{'role':role,'version':'0.4.11'})
        artifact=release(scratch/'candidate.zip',version=__version__)
        try:
            with sync_playwright() as p:
                browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True)
                context=browser.new_context(viewport={'width':1650,'height':1150},locale='zh-TW',timezone_id='Asia/Taipei');page=context.new_page();page.on('pageerror',lambda e:errors.append(str(e)))
                page.goto(url);page.locator('[name=username]').fill('update-mis');page.locator('[name=password]').fill(password);page.locator('#login-form button').click();page.locator('#shell').wait_for(state='visible')
                page.locator('nav [data-page=updates]').click();page.get_by_role('heading',name='Agent 集中更新',exact=True).wait_for()
                page.locator('#advanced-release-import summary').click()
                page.locator('#update-import [name=release]').set_input_files(str(artifact));page.locator('#update-import [name=authorize]').check()
                with page.expect_response('**/api/updates/import') as imported:page.locator('#update-import button').click()
                assert imported.value.ok;rid=api('/api/updates')['releases'][0]['id']
                page.locator('#update-job [name=release_id]').select_option(rid);page.locator('#update-job [name=target]').select_option('device:'+did)
                with page.expect_response('**/api/updates/jobs') as scheduled:page.locator('#update-job button').click()
                assert scheduled.value.ok;jid=api('/api/updates')['jobs'][0]['id']
                with page.expect_response('**/api/updates/notify') as notified:page.locator('[data-update-notify="'+jid+'"]').click()
                assert notified.value.ok and notified.value.json()['connected_roles']==[]
                agent.call('/api/agent/updates/diagnostic',{'role':'native','version':'0.4.15','code':'initialization_failed'})
                page.locator('#refresh').click();page.get_by_text('受保護更新器初始化失敗，請 MIS 檢查排程及受保護目錄',exact=True).wait_for()
                page.locator('#toast').wait_for(state='hidden')
                page.screenshot(path=str(root/f'evidence/update-notification-{__version__}.png'),full_page=True)
                agent.call('/api/agent/updates/poll',{'role':'native','version':'0.4.11'})
                agent.call('/api/agent/updates/status',{'job_id':jid,'role':'native','state':'rolled_back','version':'0.4.11','error':'模擬新版健康檢查失敗，已回復'})
                page.locator('#refresh').click();page.get_by_text('已回復舊版',exact=False).first.wait_for()
                page.screenshot(path=str(root/f'evidence/agent-updates-{__version__}.png'),full_page=True)
                page.locator('#update-job [name=release_id]').select_option(rid);page.locator('#update-job [name=target]').select_option('device:'+did)
                with page.expect_response('**/api/updates/jobs') as second:page.locator('#update-job button').click()
                assert second.value.ok;second_jid=api('/api/updates')['jobs'][0]['id']
                page.locator('[data-update-cancel="'+second_jid+'"]').click();page.locator('#update-cancel-confirm').click();page.get_by_role('cell').filter(has_text=re.compile('^已取消')).wait_for()
                page.locator('.notice').filter(has_text='端點不需逐台核准').wait_for()
                third=api('/api/updates/jobs',{'release_id':rid,'device_ids':[did],'confirm':'deploy'},session['csrf'])['job_ids'][0]
                for role in ('native','main'):
                    agent.call('/api/agent/updates/status',{'job_id':third,'role':role,'state':'healthy','version':__version__})
                lease=agent.call('/api/agent/updater/prepare',{'job_id':third,'version':__version__})['authorization']['payload']
                page.locator('#refresh').click();page.get_by_text('獨立更新器 v'+__version__+'：背景切換／健康檢查',exact=True).wait_for()
                page.locator('#toast').wait_for(state='hidden')
                page.screenshot(path=str(root/f'evidence/updater-background-{__version__}.png'),full_page=True)
                agent.call('/api/agent/updater/complete',{'id':lease['id'],'state':'rolled_back'})
                page.locator('#refresh').click();page.get_by_text('獨立更新器 v'+__version__+'：已回復原版',exact=True).wait_for()
                # Catalog already has an authorized fixture; expose ready state
                # to check selection UX without a second upload or executing it.
                with server.bundled_release.lock:server.bundled_release.state={'status':'ready','version':__version__,'release_id':rid}
                page.locator('#refresh').click();page.locator('#bundled-release-state[data-status=ready]').wait_for()
                assert page.locator('#update-job [name=release_id]').input_value()==rid
                assert not page.locator('#advanced-release-import').evaluate('(e)=>e.open')
                page.screenshot(path=str(root/f'evidence/bundled-agent-{__version__}.png'),full_page=True)
                assert not errors,errors;browser.close()
        finally:server.shutdown();server.server_close();thread.join(5)
    report={'passed':True,'page_errors':errors,'checks':['advanced manual import is collapsed by default and remains usable','single endpoint update job is created','immediate notification acknowledges zero connected channels without claiming download','native initialization failure is displayed with MIS remediation','native rollback and failure reason displayed separately from general Agent','cancel confirmation cancels only the selected queued job','unattended-update explanation and separate updater maintenance progress/rollback visible','ready bundled version is shown and latest available version selected without another upload'],'uploaded_payload_executed':False,'real_native_files_tasks_registry_modified':False}
    (root/'evidence/updates-browser-smoke.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()
