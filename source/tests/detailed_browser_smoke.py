"""Isolated management server and simulated endpoint; no real screen capture."""
import base64
import json
import secrets
import sys
import tempfile
import threading
import time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from guarddesk.server import serve
from guarddesk.store import Store
from guarddesk.agent import Agent,enroll,private_write
from playwright.sync_api import sync_playwright


def main():
    root=Path(__file__).resolve().parents[1];errors=[];password=secrets.token_urlsafe(20);stop=threading.Event()
    with tempfile.TemporaryDirectory(dir=root/'runtime') as temp:
        scratch=Path(temp);watch=scratch/'docs';watch.mkdir();store=Store(scratch/'db.sqlite3');store.add_user('test-admin',password)
        from test_server_deployment import certificate
        cert,key=certificate(scratch/'tls')
        endpoint_server=serve(store.path,port=0,cert=cert,key=key,surface='agent')
        threading.Thread(target=endpoint_server.serve_forever,daemon=True).start()
        endpoint_url=f'https://127.0.0.1:{endpoint_server.server_port}'
        import zipfile,hashlib
        with zipfile.ZipFile(scratch/'Endpoint-Connection.zip','w') as bundle:
            bundle.writestr('GuardDesk-CA.pem',cert.read_bytes())
            bundle.writestr('endpoint-connection.json',json.dumps({'version':1,'server':endpoint_url,'ca':'GuardDesk-CA.pem','ca_sha256':hashlib.sha256(cert.read_bytes()).hexdigest()}))
        server=serve(store.path,port=0,surface='console',shared=endpoint_server)
        threading.Thread(target=server.serve_forever,daemon=True).start();url=f'http://127.0.0.1:{server.server_port}'
        with store.connect() as db:
            import hashlib
            token=secrets.token_urlsafe(24);db.execute('INSERT INTO enrollments VALUES (?,?,0)',(hashlib.sha256(token.encode()).hexdigest(),time.time()+60))
        config=scratch/'agent/config.json';enroll(config,endpoint_url,token,watch,name='UI 模擬端點',ca=str(cert));agent=Agent(config);eid=agent.config['device_id']
        agent.queue('application.started',{'user':r'ACME\alice','process':r'C:\Program Files\Example\editor.exe','path':r'C:\Program Files\Example\editor.exe','process_id':'0x123'})
        agent.queue('file.moved',{'user':r'ACME\alice','source_path':r'C:\Users\alice\Documents\原始資料夾\合約.docx','path':r'C:\Users\alice\Documents\原始資料夾\合約.docx','destination_path':r'C:\Users\alice\Documents\目的資料夾\合約.docx','correlation':'test_fixture'})
        agent.queue('web.page_title',{'user':r'ACME\alice','url':'https://example.com/report?q=review','title':'測試報表 <安全輸出>'});agent.flush()
        agent.call('/api/agent/remote/poll',{'account':r'ACME\alice','ready':True})
        # This endpoint simulator never uses GDI, SendInput or a consent window.
        png='iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADUlEQVR4nGNgYGAAAAAEAAH2FzhVAAAAAElFTkSuQmCC'
        def endpoint():
            while not stop.wait(.5):
                try:
                    result=agent.call('/api/agent/remote/poll',{'account':r'ACME\alice','ready':True});session=result.get('session')
                    if session:
                        if session['status']=='requested':agent.call('/api/agent/remote/update',{'session_id':session['id'],'action':'approve','account':r'ACME\alice'})
                        agent.call('/api/agent/remote/update',{'session_id':session['id'],'action':'frame','frame':{'png':png,'width':1,'height':1}})
                except (ConnectionError,OSError):pass
        worker=threading.Thread(target=endpoint,daemon=True);worker.start()
        try:
            with sync_playwright() as p:
                browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True)
                context=browser.new_context(viewport={'width':1700,'height':1100},locale='zh-TW',timezone_id='Asia/Taipei');page=context.new_page();page.on('pageerror',lambda e:errors.append(str(e)))
                def login(page,name,login_password=password):
                    page.goto(url);page.locator('[name=username]').fill(name);page.locator('[name=password]').fill(login_password);page.locator('#login-form button').click();page.locator('#shell').wait_for(state='visible')
                login(page,'test-admin')
                with page.expect_download(timeout=60000) as download:
                    page.locator('[data-action=endpoint-package]').click()
                downloaded=scratch/'download.zip';download.value.save_as(downloaded)
                with zipfile.ZipFile(downloaded) as bundle:
                    assert 'Setup-Endpoint.cmd' in bundle.namelist() and 'GuardDesk/GuardDeskAgent.exe' in bundle.namelist()
                    assert 'token' not in json.loads(bundle.read('endpoint-connection.json'))
                    assert not any('runtime' in name.split('/') or name.endswith('.key') for name in bundle.namelist())
                page.locator('[data-action=deployment-settings]').click();page.get_by_role('heading',name='共用部署碼管理',exact=True).wait_for()
                assert '不必輸入註冊碼或 IP' in page.locator('#dialog-content').inner_text()
                assert page.locator('#dialog-content input').count()==0
                original_code=json.loads(zipfile.ZipFile(downloaded).read('endpoint-connection.json'))['deployment_code']
                assert original_code not in page.locator('#dialog-content').inner_text()
                page.screenshot(path=str(root/'evidence/shared-deployment-0.4.10.png'),full_page=True)
                page.locator('[data-action=deployment-confirm][data-kind=revoke]').click()
                page.locator('[data-action=deployment-apply]').click();page.get_by_text('狀態：已停用，請重新產生後下載新版安裝包',exact=False).wait_for()
                page.locator('[data-action=deployment-confirm][data-kind=rotate]').click()
                page.locator('[data-action=deployment-apply]').click();page.get_by_text('狀態：已啟用',exact=False).wait_for()
                page.locator('#close-dialog').click()
                with page.expect_download(timeout=60000) as replacement:page.locator('[data-action=endpoint-package]').click()
                new_download=scratch/'new-package.zip';replacement.value.save_as(new_download)
                with zipfile.ZipFile(new_download) as bundle:assert json.loads(bundle.read('endpoint-connection.json'))['deployment_code']!=original_code
                page.locator('nav [data-page=audit]').click();page.get_by_role('heading',name='詳細日誌').wait_for()
                page.locator('[data-audit-category=web]').click();page.get_by_text('測試報表 <安全輸出>',exact=True).wait_for()
                page.clock.install()
                agent.queue('web.navigation',{'user':r'ACME\alice','url':'https://example.com/fresh-audit','title':'自動更新驗證'});agent.flush()
                with page.expect_response('**/api/events?*'):
                    page.clock.fast_forward(15000)
                page.get_by_text('自動更新驗證',exact=True).wait_for()
                page.locator('#search-form [name=q]').fill('尚未提交的條件')
                requests=[]
                def audit_request(request):
                    if '/api/events?' in request.url:requests.append(request.url)
                page.on('request',audit_request);page.clock.fast_forward(15000)
                assert not requests and page.locator('#search-form [name=q]').input_value()=='尚未提交的條件'
                page.remove_listener('request',audit_request);page.clock.resume()
                page.locator('[data-audit-category=documents]').click();page.get_by_text(r'C:\Users\alice\Documents\目的資料夾\合約.docx',exact=True).wait_for()
                page.screenshot(path=str(root/'evidence/detailed-file-audit-0.4.png'),full_page=True)
                page.locator('[data-action=event]').first.click();assert '移動／重新命名目的地' in page.locator('#dialog-content').inner_text();page.locator('#close-dialog').click()
                page.locator('nav [data-page=policy]').click();page.locator('[data-action=policy-tab][data-tab=sets]').click();page.locator('[data-action=set-new]').click()
                page.locator('[name=set_name]').fill('應用程式管制 UI 驗證');page.locator('[name=module_apps]').check();page.locator('[name=module_appcontrol]').check()
                page.locator('[data-app-add]').click();page.locator('.app-name').fill('Blocked example');page.locator('.app-value').fill(r'*\blocked-example.exe');page.locator('[name=app_control_enabled]').check()
                page.screenshot(path=str(root/'evidence/application-policy-0.4.png'),full_page=True)
                with page.expect_response(lambda r:r.url.endswith('/api/policy-sets') and r.request.method=='POST') as saved:page.locator('#set-form button[type=submit]').click()
                assert saved.value.ok,saved.value.text()
                published=page.evaluate("fetch('/api/state').then(r=>r.json())")['policy_sets']
                assert next(s for s in published if s['id']==saved.value.json()['id'])['overrides']['application_control']['mode']=='denylist'
                page.locator('nav [data-page=remote]').click();page.locator('#remote-account [name=username]').fill('test-helper');page.locator('#remote-account [name=password]').fill('7')
                with page.expect_response('**/api/remote/account') as account:page.locator('#remote-account button').click()
                assert account.value.ok
                page.locator('#remote-grant [name=username]').select_option('test-helper');page.locator('#remote-grant [name=device_id]').select_option(eid)
                with page.expect_response('**/api/remote/grant') as grant:page.locator('#remote-grant button').click()
                assert grant.value.ok;page.screenshot(path=str(root/'evidence/remote-permissions-0.4.png'),full_page=True)
                support_context=browser.new_context(viewport={'width':1500,'height':1000});support=support_context.new_page();support.on('pageerror',lambda e:errors.append(str(e)));login(support,'test-helper','7')
                support.get_by_role('heading',name='遠端協助',exact=True).wait_for();assert support.locator('nav [data-page=policy]').is_hidden()
                support.get_by_role('heading',name='使用獨立 Windows 遠端協助程式',exact=True).wait_for()
                assert not support.locator('#legacy-remote').evaluate('(node)=>node.open')
                support.locator('#legacy-remote > summary').click()
                support.locator('#remote-request [name=reason]').fill('模擬端點協助驗證');support.locator('#remote-request button').click();support.get_by_role('heading',name='協助進行中',exact=True).wait_for()
                support.locator('#remote-screen[src^="data:image/png"]').wait_for();support.screenshot(path=str(root/'evidence/remote-simulated-session-0.4.png'),full_page=True)
                page.locator('[data-revoke-remote]').click();support.get_by_role('heading',name='協助已結束',exact=True).wait_for(timeout=10000)
                assert not support.locator('#remote-screen').get_attribute('src');assert not errors,errors
                agent.assets={'agent_version':'0.4.4','capabilities':['remote_uninstall_v1'],'hostname':'SIMULATED-PC','os':'Windows 11 (simulation)','user_accounts':[r'EXAMPLE\tester'],'software':[]}
                agent.heartbeat(refresh_inventory=False);packet=agent.call('/api/agent/native-usb-policy',{})
                agent.call('/api/agent/native-usb-status',{**packet,'status':'configured_replug_required','registry':{'Deny_Read':0,'Deny_Write':0},'worker_version':'0.4.4'})
                page.locator('nav [data-page=devices]').click();page.locator('[data-action=device][data-id="'+eid+'"]').click()
                page.locator('[data-action=uninstall-device]').click();page.locator('#uninstall-form [name=confirm_name]').fill('UI 模擬端點');page.locator('#uninstall-form [name=reason]').fill('僅建立隔離測試工作，不移除實機')
                with page.expect_response('**/api/devices/uninstall') as removal:page.locator('#uninstall-form button').click()
                assert removal.value.ok;page.get_by_text('遠端解除安裝：等待端點連線（尚未執行）',exact=True).wait_for()
                assert removal.value.json()['device_id']==eid
                page.screenshot(path=str(root/'evidence/remote-uninstall-0.4.4.png'),full_page=True)
                assert not errors,errors
                browser.close()
        finally:
            stop.set();worker.join(5);server.shutdown();server.server_close();endpoint_server.shutdown();endpoint_server.server_close()
    report={'passed':True,'page_errors':errors,'checks':['audit first page auto refreshes fresh web event','editing an unsubmitted filter pauses auto refresh','full source and destination paths visible','structured event detail','application policy module publishes blacklist','separate support account and per-device grants','support cannot view policy navigation','simulated endpoint approval/frame displayed','grant revocation closes session and removes frame','typed endpoint confirmation creates only that endpoint removal job and shows queued status'],'real_desktop_control_tested':False,'real_endpoint_uninstalled':False,'company_policy_modified':False}
    report['management_listener']='loopback-only HTTP'
    report['checks'].extend(['admin UI downloads single endpoint ZIP with setup launcher, GUI Agent and embedded reusable enrollment code','deployment dialog shows automatic registration without exposing bootstrap code; confirmed revoke/rotate changes downloaded package'])
    report['agent_listener']='agent-only HTTPS, verified test CA'
    (root/'evidence/detailed-browser-smoke.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()
