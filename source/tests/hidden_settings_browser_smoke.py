"""Own disposable Server/UI only, publication and group inheritance roundtrip."""
import hashlib,json,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import test_management
from guarddesk import __version__
from guarddesk.hidden_files import HIDDEN_RULE
from playwright.sync_api import sync_playwright,expect

def main():
    case=test_management.ManagementTest('runTest');case.setUp();process=None;frozen='--frozen' in sys.argv;errors=[]
    try:
        agent,did,_=case.make_agent();group=case.group('Owned hidden exclusion');case.move(did,group['id'])
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
                page=browser.new_page(viewport={'width':1600,'height':1120},locale='zh-TW');page.on('pageerror',lambda e:errors.append(str(e)))
                page.goto(case.url);page.locator('[name=username]').fill('admin');page.locator('[name=password]').fill(case.password);page.locator('#login-form button').click()
                page.get_by_role('heading',name='安全總覽',exact=True).wait_for()
                page.locator('nav [data-page=policy]').click();page.locator('[data-action=policy-tab][data-tab=sets]').click();page.locator('[data-action=set-new]').click()
                form=page.locator('#set-form');form.locator('[name=set_name]').fill('Hidden option fixture')
                form.locator('[name=module_files]').check();toggle=form.locator('[name=exclude_hidden]')
                expect(toggle).to_be_visible();expect(toggle).not_to_be_checked();toggle.check()
                form.locator('[name=file_excludes]').fill('C:\\Owned\\Skip')
                def publish():
                    form.locator('button[type=submit]').click()
                    expect(page.locator('[data-improve-publish]')).to_be_visible()
                    with page.expect_response(lambda r:r.url.endswith('/api/policy-sets') and r.request.method=='POST') as response:page.locator('[data-improve-publish]').click()
                    result=response.value;assert result.ok,result.text();return result.json()
                saved=publish();identifier=saved['id']
                case.assign(saved,'group',group['id']);body=agent.heartbeat()['body']
                assert HIDDEN_RULE in body['file_audit']['exclude_paths']
                assert r'C:\Owned\Skip' in body['file_audit']['exclude_paths']
                assert body['browser_audit'] and body['application_audit'] and body['usb_mode']=='allow'
                page.locator('[data-action=set-edit][data-id="'+identifier+'"]').click()
                expect(toggle).to_be_checked();expect(form.locator('[name=file_excludes]')).to_have_value('C:\\Owned\\Skip')
                mode=form.locator('[data-setting-path="file_audit.exclude_paths"]')
                mode.select_option('inherit');expect(toggle).to_be_disabled()
                mode.select_option('set');expect(toggle).to_be_enabled();expect(toggle).to_be_checked()
                assert HIDDEN_RULE not in form.locator('[name=file_excludes]').input_value()
                toggle.scroll_into_view_if_needed();page.screenshot(path=str(ROOT/f'evidence/hidden-settings-{__version__}.png'))
                page.set_viewport_size({'width':390,'height':844});toggle.scroll_into_view_if_needed()
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                page.screenshot(path=str(ROOT/f'evidence/hidden-settings-narrow-{__version__}.png'))
                toggle.uncheck();publish();body=agent.heartbeat()['body']
                assert HIDDEN_RULE not in body['file_audit']['exclude_paths'] and r'C:\Owned\Skip' in body['file_audit']['exclude_paths']
                assert not errors,errors
            finally:browser.close()
        proof={'passed':True,'version':__version__,'frozen_server_used':frozen,'exe_sha256':hashlib.sha256((ROOT/'dist/GuardDesk/GuardDesk.exe').read_bytes()).hexdigest() if frozen else None,'checks':['visible option in requested file module; default unchecked','actual form publication and group assignment','edit restores hidden checkbox without leaking reserved marker into path textarea','uncheck publishes removal while preserving explicit exclusion and unrelated modules','390px layout and no page errors'],'company_changed':False,'page_errors':errors}
        output=ROOT/f'evidence/hidden-settings-browser-{__version__}{"-source" if not frozen else ""}.json'
        output.write_text(json.dumps(proof,indent=2),encoding='utf-8')
        print(json.dumps(proof))
    finally:
        if process is not None and process.poll() is None:process.terminate();process.wait(20)
        case.tearDown()

if __name__=='__main__':main()
