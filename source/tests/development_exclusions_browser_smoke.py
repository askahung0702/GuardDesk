"""Real browser UI; isolated local fixture, no office Server changes."""
import json
import secrets
import sys
import tempfile
import threading
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from guarddesk.server import serve
from guarddesk.store import Store
from guarddesk.file_exclusions import DEVELOPMENT_RULE
from playwright.sync_api import sync_playwright,expect
ROOT=Path(__file__).resolve().parents[1]


def main():
    errors=[]
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime') as tmp:
        store=Store(Path(tmp)/'control.db');password=secrets.token_urlsafe(20);store.add_user('fixture-mis',password)
        server=serve(store.path,port=0);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with sync_playwright() as p:
                browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True)
                try:
                    page=browser.new_page(viewport={'width':1500,'height':1100},locale='zh-TW');page.on('pageerror',lambda e:errors.append(str(e)))
                    page.goto(f'http://127.0.0.1:{server.server_port}');page.locator('[name=username]').fill('fixture-mis');page.locator('[name=password]').fill(password);page.locator('#login-form button').click()
                    page.locator('nav [data-page=policy]').click();page.locator('[data-action=policy-tab][data-tab=sets]').click();page.locator('[data-action=set-new]').click()
                    form=page.locator('#set-form');form.locator('[name=set_name]').fill('資訊人員開發快取排除')
                    expect(form.locator('[name=exclude_development]')).to_be_hidden()
                    form.locator('[name=module_files]').check();expect(form.locator('[name=exclude_development]')).not_to_be_checked()
                    form.locator('[name=exclude_development]').check();form.locator('[name=file_excludes]').fill(r'D:\Projects')
                    page.screenshot(path=str(ROOT/'evidence/development-exclusions-desktop-0.4.26.png'),full_page=True)
                    with page.expect_response(lambda r:r.url.endswith('/api/policy-sets') and r.request.method=='POST') as response:form.locator('button[type=submit]').click()
                    result=response.value;assert result.ok,result.text();payload=result.request.post_data_json['overrides'];pid=result.json()['id']
                    assert payload=={'file_audit':{'enabled':True,'scope':'all_local','exclude_paths':[r'D:\Projects',DEVELOPMENT_RULE]}},payload
                    page.locator('[data-action=set-edit][data-id="'+pid+'"]').click()
                    expect(form.locator('[name=exclude_development]')).to_be_checked();expect(form.locator('[name=file_excludes]')).to_have_value(r'D:\Projects')
                    assert DEVELOPMENT_RULE not in form.inner_text()
                    form.locator('[name=exclude_development]').uncheck()
                    with page.expect_response(lambda r:r.url.endswith('/api/policy-sets') and r.request.method=='POST') as response:form.locator('button[type=submit]').click()
                    assert response.value.request.post_data_json['overrides']['file_audit']['exclude_paths']==[r'D:\Projects']
                    page.locator('[data-action=set-edit][data-id="'+pid+'"]').click();page.set_viewport_size({'width':390,'height':844})
                    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                    page.screenshot(path=str(ROOT/'evidence/development-exclusions-mobile-0.4.26.png'),full_page=True)
                    assert not errors,errors
                finally:browser.close()
        finally:server.shutdown();server.server_close();thread.join(5)
    report={'passed':True,'checks':['Opt-in checkbox only visible with selected file module','Only file_audit override published; application, browser and control fields untouched','Edit restores checkbox and custom paths without exposing wire token','Unchecking removes only built-in development rule','390px no overflow'],'page_errors':errors,'limitations':['Synthetic localhost database; no physical fleet/Defender acceptance']}
    (ROOT/'evidence/development-exclusions-browser-0.4.26.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()
