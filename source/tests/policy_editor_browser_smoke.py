"""Verify progressive module settings and the exact published policy payload."""
import json
import secrets
from pathlib import Path
from playwright.sync_api import sync_playwright,expect


def main():
    root=Path(__file__).resolve().parents[1]
    credentials=dict(line.split(': ',1) for line in (root/'runtime/access.txt').read_text(encoding='utf-8').splitlines())
    errors=[];saved_id=None;payloads=[]
    with sync_playwright() as p:
        browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True)
        page=browser.new_page(viewport={'width':1600,'height':1200},locale='zh-TW')
        page.on('pageerror',lambda error:errors.append(str(error)))
        def publish():
            nonlocal saved_id
            with page.expect_response(lambda r:r.url.endswith('/api/policy-sets') and r.request.method=='POST') as response:
                page.locator('#set-form button[type=submit]').click()
            result=response.value;assert result.ok,result.text();payloads.append(result.request.post_data_json['overrides'])
            saved_id=result.json()['id'];page.locator('[data-action=set-edit][data-id="'+saved_id+'"]').wait_for()
        def edit():page.locator('[data-action=set-edit][data-id="'+saved_id+'"]').click()
        def toggle(module,checked=True):page.locator('[name=module_'+module+']').set_checked(checked)
        try:
            page.goto(credentials['URL']);page.locator('[name=username]').fill(credentials['Username']);page.locator('[name=password]').fill(credentials['Password']);page.locator('#login-form button').click()
            page.get_by_role('heading',name='安全總覽',exact=True).wait_for()
            page.locator('nav [data-page=policy]').click();page.locator('[data-action=policy-tab][data-tab=sets]').click();page.locator('[data-action=set-new]').click()
            form=page.locator('#set-form');form.locator('[name=set_name]').fill('UI 驗收－禁止 USB '+secrets.token_hex(3))
            expect(form.locator('.module-settings-panel:visible')).to_have_count(0)
            expect(form.locator('button[type=submit]')).to_be_disabled();expect(page.locator('#set-module-empty')).to_be_visible()
            toggle('usb');form.locator('[name=usb_mode]').select_option('block')
            expect(form.locator('.module-settings-panel:visible')).to_have_count(1)
            expect(page.locator('#set-module-usb')).to_be_visible();expect(page.locator('#set-module-export')).to_be_hidden()
            expect(form.locator('[name=mode]')).to_be_disabled()
            assert '並不是關閉該功能' in form.inner_text()
            page.screenshot(path=str(root/'evidence/policy-editor-usb-desktop.png'),full_page=True)
            toggle('export');expect(page.locator('#set-module-export')).to_be_visible()
            assert '不會自動攔截所有程式' in page.locator('#set-module-export').inner_text()
            form.locator('[name=max_export_mb]').fill('');toggle('export',False)
            assert form.evaluate('(form)=>form.checkValidity()'),'Hidden required field blocked USB-only publish'
            publish();assert payloads[-1]=={'usb_mode':'block'},payloads[-1]
            edit();expect(form.locator('[name=module_usb]')).to_be_checked();expect(form.locator('[name=usb_mode]')).to_have_value('block')
            expect(form.locator('.module-settings-panel:visible')).to_have_count(1)
            toggle('export');form.locator('[name=mode]').select_option('enforce');form.locator('[name=keywords]').fill('TEST_ONLY');form.locator('[name=max_export_mb]').fill('4')
            toggle('export',False);toggle('export');expect(form.locator('[name=keywords]')).to_have_value('TEST_ONLY')
            page.screenshot(path=str(root/'evidence/policy-editor-export-desktop.png'),full_page=True)
            toggle('upload');form.locator('[data-action=rule-add]').click();toggle('upload',False)
            assert form.evaluate('(form)=>form.checkValidity()')
            toggle('upload');assert not form.evaluate('(form)=>form.checkValidity()')
            form.locator('.rule-target').fill('uploads.example.com');form.locator('.rule-rate').fill('1000')
            publish();assert set(payloads[-1])=={'usb_mode','mode','allow_export','blocked_extensions','keywords','max_export_mb','upload_rules'}
            assert payloads[-1]['keywords']==['TEST_ONLY'] and payloads[-1]['max_export_mb']==4 and payloads[-1]['usb_mode']=='block'
            edit();toggle('usb',False);publish();assert 'usb_mode' not in payloads[-1] and 'upload_rules' in payloads[-1]
            edit();toggle('export',False);toggle('upload',False);toggle('usb');form.locator('[name=usb_mode]').select_option('block')
            page.set_viewport_size({'width':390,'height':844});assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            page.screenshot(path=str(root/'evidence/policy-editor-usb-mobile.png'),full_page=True)
            assert not errors,errors
        finally:
            if saved_id:
                page.evaluate("""async(id)=>{const me=await(await fetch('/api/me')).json(),state=await(await fetch('/api/state')).json(),p=state.policy_sets.find(p=>p.id===id);const r=await fetch('/api/policy-sets/archive',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':me.csrf},body:JSON.stringify({id,revision:p.revision})});if(!r.ok)throw new Error(await r.text());}""",saved_id)
            browser.close()
    report={'passed':True,'checks':['unchecked modules have no visible settings','zero modules disables publication','USB-only settings and function guide','hidden invalid fields do not block publication','only selected module keys published','edit restores checked modules and values','uncheck/recheck preserves draft values','selected upload rules still validate','deselected module removed on new version','390px no page overflow','test policy archived'],'page_errors':errors}
    (root/'evidence/policy-editor-browser-smoke.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()
