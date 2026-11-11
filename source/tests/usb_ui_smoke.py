"""Read-only live UI checks; simulated worker reports stay inside this browser."""
import json
import time
from pathlib import Path
from playwright.sync_api import sync_playwright


def main():
    root=Path(__file__).resolve().parents[1]
    credentials=dict(line.split(': ',1) for line in (root/'runtime/access.txt').read_text(encoding='utf-8').splitlines())
    errors=[];checks=[]
    with sync_playwright() as p:
        browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True)
        page=browser.new_page(viewport={'width':1600,'height':1100},locale='zh-TW')
        page.on('pageerror',lambda error:errors.append(str(error)))
        page.goto(credentials['URL']);page.locator('[name=username]').fill(credentials['Username']);page.locator('[name=password]').fill(credentials['Password']);page.locator('#login-form button').click()
        page.get_by_role('heading',name='安全總覽',exact=True).wait_for()
        state=page.evaluate("fetch('/api/state').then(r=>r.json())")
        device=next(d for d in state['devices'] if not d['revoked'])
        eid=device['id']
        page.locator('nav [data-page=devices]').click()
        def open_detail():page.locator('[data-action=device][data-id="'+eid+'"]').click();page.locator('#dialog-content .detail-summary').wait_for()
        open_detail()
        if not device.get('native_usb'):
            assert 'Install-Endpoint.cmd' in page.locator('#dialog-content').inner_text()
            page.screenshot(path=str(root/'evidence/usb-native-install-ui.png'),full_page=True)
            checks.append('actual endpoint shows USB installation instructions')
        else:
            assert 'USB 原生控制' in page.locator('#dialog-content').inner_text()
            page.screenshot(path=str(root/'evidence/usb-native-installed-ui.png'),full_page=True)
            checks.append('actual endpoint shows independent native USB report')
        page.locator('#dialog').evaluate('(e)=>e.close()')
        fixture={'version':1,'usb_mode':'read_only','expected_mode':'read_only','status':'configured_replug_required','registry':{'Deny_Read':0,'Deny_Write':1},'verified_readback':True,'matches_policy':True,'fresh':True,'received':time.time(),'resources':{'private_bytes':20*1048576}}
        def intercept(route):
            response=route.fetch();body=response.json();body['device']['native_usb']=dict(fixture)
            body['device']['name']='模擬 USB 回報（僅此瀏覽器）'
            route.fulfill(response=response,json=body)
        page.route('**/api/device-detail?*',intercept)
        for name,changes,expected in [
            ('verified',{},'登錄設定已核對，待 USB 插拔驗收'),
            ('stale',{'fresh':False},'USB 背景工作逾時未回報'),
            ('failed',{'fresh':True,'status':'failed','verified_readback':False},'USB 套用失敗'),
            ('pending',{'status':'configured_replug_required','matches_policy':False},'等待同步新 USB 策略')]:
            fixture.update(changes);open_detail();assert expected in page.locator('#dialog-content').inner_text()
            if name=='verified':
                assert '設定讀回核對不等於實體 USB 已通過測試' in page.locator('#dialog-content').inner_text()
                page.screenshot(path=str(root/'evidence/usb-native-status-fixture.png'),full_page=True)
            checks.append('client-only fixture: '+name);page.locator('#dialog').evaluate('(e)=>e.close()')
        assert not errors,errors
        browser.close()
    report={'passed':True,'checks':checks,'server_policy_mutated':False,'fake_status_posted':False,'page_errors':errors}
    (root/'evidence/usb-ui-smoke.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()
