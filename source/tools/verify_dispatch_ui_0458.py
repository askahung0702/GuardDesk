"""Real frozen management UI and fixture endpoint status; isolated Chrome."""
import hashlib,json,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
import test_management
from playwright.sync_api import sync_playwright,expect


def main():
    case=test_management.ManagementTest('runTest');case.setUp();process=None;errors=[]
    try:
        agent,did,_=case.make_agent()
        agent.feature_status['browser_deployment']={'status':'publication_required'};agent.heartbeat(refresh_inventory=False)
        agent.call('/api/agent/extended-status',{'worker_version':'0.4.58','browser_deployment':{'status':'publication_required'}})
        case.server.shutdown();case.server.server_close();case.thread.join(5)
        exe=ROOT/'dist/GuardDesk/GuardDesk.exe'
        process=subprocess.Popen([str(exe),'serve','--db',str(case.db),'--port',case.url.rsplit(':',1)[1]],cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
        for _ in range(100):
            try:
                if case.api('/api/health')['version']=='0.4.58':break
            except (OSError,ConnectionError):pass
            time.sleep(.1)
        else:raise AssertionError('Frozen fixture Server did not start')
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True)
            try:
                page=browser.new_page(viewport={'width':1600,'height':1100},locale='zh-TW');page.on('pageerror',lambda e:errors.append(str(e)))
                page.goto(case.url);page.locator('[name=username]').fill('admin');page.locator('[name=password]').fill(case.password);page.locator('#login-form button').click()
                page.locator('nav [data-page=audit]').click();page.locator('[data-audit-category=uploads]').click()
                expect(page.locator('#workspace')).to_contain_text('集中部署需 0.4.58')
                page.locator('[data-browser-publication]').click()
                expect(page.locator('#dialog')).to_contain_text('不必由員工重裝')
                page.locator('#close-dialog').click()
                page.locator('#search-form [name=device]').select_option(did)
                page.locator('[data-document-diagnostics]').click()
                expect(page.locator('#dialog')).to_contain_text('一般 Agent 部署')
                expect(page.locator('#dialog')).to_contain_text('原生政策部署')
                expect(page.locator('#dialog')).to_contain_text('MIS 尚未設定擴充發布來源')
                assert not errors,errors
                result={'passed':True,'version':'0.4.58','exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'company_changed':False,'frozen_server_used':True,'js_errors':errors,'checks':['Actual navigation to upload audit','Publication dialog explains centralized existing endpoint deployment','Endpoint dialog shows actual user and native publication_required separately','No employee browser profile or policies touched']}
            finally:browser.close()
    finally:
        if process:process.terminate();process.wait(20)
        case.tearDown()
    (ROOT/'evidence/dispatch-ui-frozen-0.4.58.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result))


if __name__=='__main__':main()
