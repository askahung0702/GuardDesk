"""Owned headless browser + isolated fixture, no real endpoint or desktop control."""
import json
from pathlib import Path
import sys
import time
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
from playwright.sync_api import sync_playwright
from guarddesk import __version__
from guarddesk.agent import Agent,enroll
from guarddesk.remote_client import RemoteClient
from test_native_remote import NativeRemoteTest


def run():
    fixture=NativeRemoteTest();fixture.setUp();errors=[]
    try:
        fixture.api('/api/remote/account',{'username':'MIS-helper','password':'7'})
        token=fixture.api('/api/enrollments',{})['token'];config=fixture.root/'fixture-agent'/'config.json'
        did=enroll(config,fixture.url,token,fixture.watch,name='SIMULATED-PC-01')
        agent=Agent(config);agent.call('/api/agent/remote/poll',{'account':r'TEST\employee','ready':True,'protocol':2})
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True)
            try:
                context=browser.new_context(viewport={'width':1700,'height':1200},locale='zh-TW',timezone_id='Asia/Taipei')
                page=context.new_page();page.on('pageerror',lambda e:errors.append(str(e)))
                page.goto(fixture.url);page.locator('[name=username]').fill('admin');page.locator('[name=password]').fill(fixture.password)
                page.locator('#login-form button').click();page.locator('nav [data-page=remote]').click()
                form=page.locator('#remote-grant');form.wait_for()
                assert form.locator('[name=device_id]').input_value()=='*'
                assert form.locator('[name=days]').input_value()=='0'
                form.locator('[name=username]').select_option('MIS-helper')
                form.locator('[name=device_id]').select_option(did)
                assert form.locator('[name=days]').input_value()=='1' and form.locator('[name=days]').get_attribute('min')=='1'
                form.locator('[name=device_id]').select_option('*')
                assert form.locator('[name=days]').input_value()=='0'
                form.locator('[name=can_control]').check()
                with page.expect_response('**/api/remote/grant') as saved:form.locator('button').click()
                assert saved.value.ok,saved.value.text()
                page.get_by_role('button',name='撤銷全部端點預設',exact=True).wait_for()
                assert page.get_by_role('cell',name='全部端點（含未來新增）',exact=True).count()==1
                assert page.get_by_role('cell',name='直到撤銷',exact=True).count()==1
                # A later enrollment is visible without another grant operation.
                token=fixture.api('/api/enrollments',{})['token'];later=fixture.root/'later-agent'/'config.json'
                did2=enroll(later,fixture.url,token,fixture.watch,name='SIMULATED-PC-02')
                client=RemoteClient(fixture.url);client.login('MIS-helper','7');fixture.clients.append(client)
                catalog=client.catalog();assert {d['id'] for d in catalog['devices']}=={did,did2}
                assert len(catalog['grants'])==2 and len(catalog['grant_rules'])==1
                page.screenshot(path=str(ROOT/f'evidence/remote-all-grants-{__version__}.png'),full_page=True)
                support_context=browser.new_context();support=support_context.new_page();support.on('pageerror',lambda e:errors.append(str(e)))
                support.goto(fixture.url);support.locator('[name=username]').fill('MIS-helper');support.locator('[name=password]').fill('7')
                support.locator('#login-form button').click();support.get_by_role('heading',name='遠端協助',exact=True).wait_for()
                assert support.locator('#remote-grant').count()==0
                support.get_by_role('cell',name='全部端點（含未來新增）',exact=True).wait_for()
                with page.expect_response('**/api/remote/grant') as removed:page.get_by_role('button',name='撤銷全部端點預設',exact=True).click()
                assert removed.value.ok;page.get_by_role('button',name='撤銷全部端點預設',exact=True).wait_for(state='detached')
                assert client.catalog()['devices']==[] and not errors,errors
            finally:browser.close()
    finally:fixture.tearDown()
    report={'passed':True,'version':__version__,'page_errors':errors,
        'checks':['default all-endpoint scope and until-revoked duration','individual scope updates valid-day minimum',
                  'saved all-endpoint rule rendered once with readable expiry','future endpoint visible without a second grant',
                  'legacy viewer catalog contains effective per-device grants','support sees own default but cannot grant',
                  'global revocation removes inherited endpoint access'],
        'scope':'isolated HTTP loopback, headless owned browser, simulated endpoints; no GDI or SendInput',
        'office_server_modified':False}
    (ROOT/f'evidence/remote-all-browser-smoke-{__version__}.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report))


if __name__=='__main__':run()
