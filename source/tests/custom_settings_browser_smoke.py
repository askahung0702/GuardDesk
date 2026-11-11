"""Isolated browser acceptance; no live company controls or endpoints."""
import json
import sys
import hashlib
import subprocess
import time
import urllib.error
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from playwright.sync_api import sync_playwright,expect
import test_system
from guarddesk import __version__


def main():
    if tuple(map(int,__version__.split('.'))) >= (0,4,39):
        from custom_library_browser_smoke import main as library_main
        return library_main()
    root=Path(__file__).resolve().parents[1];case=test_system.SystemTest('runTest');case.setUp();errors=[];process=None;frozen='--frozen' in sys.argv;suffix='-'+__version__ if frozen else ''
    try:
        if frozen:
            case.server.shutdown();case.server.server_close();case.thread.join(5)
            exe=root/'dist/GuardDesk/GuardDesk.exe'
            process=subprocess.Popen([str(exe),'serve','--db',str(case.db),'--port',case.url.rsplit(':',1)[1]],cwd=root,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
            for _ in range(100):
                try:
                    assert case.api('/api/health')['version']==__version__;break
                except (urllib.error.URLError,ConnectionError):time.sleep(.1)
            else:raise AssertionError('Frozen custom settings server did not start')
        agent,eid,_=case.make_agent();group=case.api('/api/groups',{'name':'Custom Test Group'})
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True)
            page=browser.new_page(viewport={'width':1600,'height':1100},locale='zh-TW');page.on('pageerror',lambda e:errors.append(str(e)))
            page.goto(case.url);page.locator('[name=username]').fill('admin');page.locator('[name=password]').fill(case.password);page.locator('#login-form button').click();page.locator('nav [data-page=custom]').click()
            page.locator('#custom-form').wait_for();expect(page.locator('[data-custom-add=schedule]')).to_be_disabled()
            page.select_option('[name=own_schedules]','override');page.locator('[data-custom-add=schedule]').click();expect(page.locator('.custom-schedule')).to_have_count(1)
            page.locator('[name=schedule_message]').fill('<img src=x onerror=alert(1)> Test reminder')
            page.select_option('[name=own_software]','override');page.locator('[data-custom-template=LINE]').click();assert not page.locator('#custom-form').evaluate('(f)=>f.checkValidity()')
            page.locator('[name=software_publisher]').fill('CN=Example Test Publisher, O=Example');page.locator('[name=software_product]').fill('Example Product');page.locator('[name=software_binary]').fill('*')
            assert page.locator('#custom-form').evaluate('(f)=>f.checkValidity()')
            page.locator('#custom-form button[type=submit]').click();page.locator('#custom-confirm-publish').wait_for();assert '影響 1 台' in page.locator('#dialog-content').inner_text();page.locator('#custom-confirm-publish').click();page.locator('#dialog').wait_for(state='hidden')
            expect(page.locator('.custom-schedule')).to_have_count(1);assert page.locator('[name=schedule_message]').input_value().startswith('<img')
            assert case.api('/api/custom-settings')['profiles'][0]['body']['software'][0]['product']=='Example Product'
            # Switching a classification to inheritance restores its parent view.
            page.select_option('[name=own_software]','inherit');expect(page.locator('[data-custom-template=LINE]')).to_be_disabled();page.locator('#custom-discard').click();expect(page.locator('[name=own_software]')).to_have_value('override')
            page.locator('#custom-history').click();page.locator('[data-custom-version="1"]').click();expect(page.locator('#dialog')).not_to_be_visible()
            # Preview conflicts never silently publish an outdated draft.
            page.locator('#custom-form button[type=submit]').click();page.locator('#custom-confirm-publish').wait_for()
            with case.store.connect() as db:db.execute("UPDATE control_meta SET value=value+1 WHERE key='custom_generation'")
            page.locator('#custom-confirm-publish').click();expect(page.locator('#toast')).to_contain_text('預覽已過期');page.locator('#close-dialog').click()
            # Section-scoped settings don't alter the legacy policy editor.
            page.select_option('#custom-scope','device');expect(page.locator('#custom-target')).to_have_value(eid)
            page.select_option('[name=own_compatibility]','override');page.locator('[data-custom-add=compatibility]').click();page.locator('[name=compat_reason]').fill('Windows compatibility trial')
            page.locator('#custom-form button[type=submit]').click();page.locator('#custom-confirm-publish').click();page.locator('#dialog').wait_for(state='hidden')
            effective=case.api('/api/custom-settings/effective?device_id='+eid)
            assert len(effective['body']['software'])==1 and len(effective['body']['compatibility'])==1
            packet=agent.call('/api/agent/custom-settings',{'protocol':1})
            agent.call('/api/agent/custom-status',{'protocol':1,'role':'native','version':'0.4.37','fingerprint':packet['fingerprint'],'report':{'state':'reported','network':{'state':'unchanged'},'compatibility':[]}})
            page.evaluate('document.activeElement?.blur()');page.evaluate('refresh({automatic:true})');expect(page.get_by_text('原生 / 0.4.37',exact=True)).to_be_visible()
            page.evaluate('window.scrollTo(0,0)');page.screenshot(path=str(root/('evidence/custom-settings-desktop'+suffix+'.png')),full_page=True)
            page.set_viewport_size({'width':390,'height':844});assert page.evaluate('document.documentElement.scrollWidth<=innerWidth'),page.evaluate('document.documentElement.scrollWidth')
            page.screenshot(path=str(root/('evidence/custom-settings-mobile'+suffix+'.png')),full_page=True)
            page.set_viewport_size({'width':1600,'height':1100});page.locator('nav [data-page=policy]').click();page.get_by_role('heading',name='安全策略',exact=True).wait_for()
            page.locator('nav [data-page=audit]').click();page.get_by_role('heading',name='詳細日誌',exact=True).wait_for()
            assert not errors,errors
            browser.close()
        report={'passed':True,'isolated_server':True,'live_endpoint_controls_modified':False,'checks':['default inheritance','all form actions','invalid incomplete software template blocks publication','publisher rule publication','XSS escaping','section inheritance/discard','history restore draft','optimistic concurrency','device override retains inherited software','component-only status changes automatically repaint','desktop/mobile no page overflow','legacy policy/audit navigation'],'page_errors':errors}
        report['frozen_server_used']=frozen
        if frozen:report['exe_sha256']=hashlib.sha256(exe.read_bytes()).hexdigest()
        (root/('evidence/custom-settings-browser-smoke'+suffix+'.json')).write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))
    finally:
        if process:
            process.terminate();process.wait(timeout=20);case.temp.cleanup()
        elif not frozen:case.tearDown()

if __name__=='__main__':main()
