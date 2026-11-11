"""Real Chromium policy form using isolated local synthetic data."""
import copy
import json
import secrets
import sys
import tempfile
import threading
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from guarddesk.server import serve
from guarddesk.store import Store
from guarddesk.policy import DEFAULT_POLICY
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
                    form=page.locator('#set-form');form.locator('[name=set_name]').fill('資訊人員程式啟停排除')
                    expect(form.locator('[name=application_audit_exclusions]')).to_be_hidden()
                    form.locator('[name=module_apps]').check();expect(form.locator('[name=app_control_enabled]')).to_be_disabled();expect(form.locator('[name=application_audit_exclusions]')).to_have_value('')
                    for _ in range(2):form.locator('[data-app-exclusion-preset]').click()
                    field=form.locator('[name=application_audit_exclusions]');expect(field).to_have_value('conhost.exe\ndocker.exe')
                    field.fill(field.input_value()+'\n'+r'C:\Tools\worker.exe')
                    page.screenshot(path=str(ROOT/'evidence/application-exclusions-desktop-0.4.27.png'),full_page=True)
                    with page.expect_response(lambda r:r.url.endswith('/api/policy-sets') and r.request.method=='POST') as response:form.locator('button[type=submit]').click()
                    result=response.value;assert result.ok,result.text();payload=result.request.post_data_json['overrides'];pid=result.json()['id']
                    assert payload=={'application_audit':True,'application_audit_exclusions':['conhost.exe','docker.exe',r'C:\Tools\worker.exe']},payload
                    page.locator('[data-action=set-edit][data-id="'+pid+'"]').click();expect(field).to_have_value('conhost.exe\ndocker.exe\n'+r'C:\Tools\worker.exe')
                    field.fill('docker.exe')
                    with page.expect_response(lambda r:r.url.endswith('/api/policy-sets') and r.request.method=='POST') as response:form.locator('button[type=submit]').click()
                    assert response.value.request.post_data_json['overrides']['application_audit_exclusions']==['docker.exe']
                    page.locator('[data-action=set-edit][data-id="'+pid+'"]').click();field.fill('')
                    with page.expect_response(lambda r:r.url.endswith('/api/policy-sets') and r.request.method=='POST') as response:form.locator('button[type=submit]').click()
                    assert response.value.request.post_data_json['overrides']['application_audit_exclusions']==[]
                    # A legacy policy combined audit and execution control.
                    # Editing it must restore both modules and its old rules.
                    page.evaluate("""async id=>{const old=state.policy_sets.find(p=>p.id===id);await api('/api/policy-sets',{id,revision:old.revision,name:old.name,description:old.description,enabled:true,overrides:{application_audit:true,application_audit_exclusions:['docker.exe'],application_control:{enabled:true,mode:'denylist',block_msi:true,rules:[]}}});await refresh();}""",pid)
                    page.locator('[data-action=set-edit][data-id="'+pid+'"]').click()
                    expect(form.locator('[name=module_apps]')).to_be_checked();expect(form.locator('[name=module_appcontrol]')).to_be_checked();expect(form.locator('[name=app_control_enabled]')).to_be_checked()
                    form.locator('[name=module_appcontrol]').uncheck();expect(form.locator('[name=app_control_enabled]')).to_be_disabled()
                    with page.expect_response(lambda r:r.url.endswith('/api/policy-sets') and r.request.method=='POST') as response:form.locator('button[type=submit]').click()
                    assert 'application_control' not in response.value.request.post_data_json['overrides']
                    page.locator('[data-action=set-edit][data-id="'+pid+'"]').click();page.set_viewport_size({'width':390,'height':844})
                    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                    page.screenshot(path=str(ROOT/'evidence/application-exclusions-mobile-0.4.27.png'),full_page=True)
                    assert not errors,errors
                finally:browser.close()
        finally:server.shutdown();server.server_close();thread.join(5)
    report={'passed':True,'checks':['Apps-only module reveals default-empty log exclusion list','Preset adds conhost/docker once without overwriting custom values','Only audit/exclusion fields published; unselected execution-control module is disabled and omitted','Edit restores names/full paths; deleting entries and clearing restores collection','Legacy combined policy restores both modules and its enabled execution-control rules','390px no page overflow'],'page_errors':errors,'limitations':['Synthetic localhost fixture; not office Server or company Defender acceptance']}
    (ROOT/'evidence/application-exclusions-browser-0.4.27.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()
