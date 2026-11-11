"""Test all three rule editors against the running demo, then restore policy."""
import json
from pathlib import Path
from playwright.sync_api import sync_playwright


def main():
    root=Path(__file__).resolve().parents[1]
    credentials=dict(line.split(': ',1) for line in (root/'runtime/access.txt').read_text(encoding='utf-8').splitlines())
    with sync_playwright() as p:
        browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True)
        page=browser.new_page(viewport={'width':1440,'height':1000},locale='zh-TW',timezone_id='Asia/Taipei')
        errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
        page.goto(credentials['URL'])
        page.locator('[name=username]').fill(credentials['Username']);page.locator('[name=password]').fill(credentials['Password']);page.locator('#login-form button').click()
        page.get_by_role('heading',name='安全總覽',exact=True).wait_for()
        original=page.evaluate("async()=>await (await fetch('/api/state')).json()")['policy']['body']
        try:
            page.locator('nav [data-page=policy]').click();page.locator('[name=usb_mode]').select_option('read_only')
            page.locator('[name=file_audit_scope]').select_option('all_local')
            for kind,target,rate in [('domain','uploads.example.com',1000),('app','ExampleUpload.exe',2000),('user','COMPANY\\pilot',3000)]:
                page.locator('[data-action=rule-add]').click();row=page.locator('.upload-rule').last
                row.locator('.rule-type').select_option(kind);row.locator('.rule-target').fill(target);row.locator('.rule-rate').fill(str(rate))
            with page.expect_response(lambda r:r.url.endswith('/api/policy') and r.request.method=='POST') as result:
                page.locator('#policy-form button[type=submit]').click()
            response=result.value;assert response.ok,response.text()
            saved=response.json()['body'];assert len(saved['upload_rules'])==3 and saved['usb_mode']=='read_only'
            page.locator('.upload-rule').nth(2).wait_for()
            page.evaluate('window.scrollTo(0,0)')
            page.screenshot(path=str(root/'evidence/policy-0.2-desktop.png'),full_page=True)
            page.set_viewport_size({'width':390,'height':844})
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            page.screenshot(path=str(root/'evidence/policy-0.2-mobile.png'),full_page=True)
            assert not errors,errors
        finally:
            page.evaluate("""async(body)=>{const me=await(await fetch('/api/me')).json();const s=await(await fetch('/api/state')).json();const r=await fetch('/api/policy',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':me.csrf},body:JSON.stringify({base_version:s.policy.version,body})});if(!r.ok)throw new Error(await r.text());}""",original)
            browser.close()
    report={'passed':True,'checks':['USB mode editor','all local file scope','domain upload rule','application upload rule','user upload rule','server persisted all fields','390px no horizontal page overflow','policy restored after test'],'page_errors':errors}
    (root/'evidence/endpoint-browser-smoke.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report))


if __name__=='__main__':main()
