"""Actual console UI using synthetic latest inventory, no employee profile."""
import json,sys,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
import test_system
from playwright.sync_api import sync_playwright,expect

def main():
    fixture=test_system.SystemTest();fixture.setUp();uid=uuid.uuid4().hex
    report={'version':'0.4.64','passed':False,'scope':'owned_headless_console_synthetic_inventory','page_errors':[],'company_changed':False}
    try:
        agent,did,_=fixture.make_agent()
        inventory={'agent_version':'0.4.64','agent_account':'OWNED\\B<&>',
            'machine_agent':{'scope':'all_logged_on_users','sessions':[{'id':1,'user':'OWNED\\B<&>','active':True}]},
            'collectors':{'directory_notifications':{'status':'machine_worker_owned'}}}
        with fixture.store.connect() as db:db.execute('UPDATE devices SET inventory=? WHERE id=?',(json.dumps(inventory),did))
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True,chromium_sandbox=True)
            try:
                page=browser.new_page(viewport={'width':1500,'height':1100},locale='zh-TW')
                page.on('pageerror',lambda error:report['page_errors'].append(str(error)))
                page.goto(fixture.url);page.locator('[name=username]').fill('admin');page.locator('[name=password]').fill(fixture.password);page.locator('#login-form button').click()
                page.get_by_role('heading',name='安全總覽',exact=True).wait_for()
                page.locator('nav [data-page=devices]').click();page.locator('[data-action=device]').click()
                expect(page.locator('#dialog')).to_contain_text('全機（各登入帳號）')
                expect(page.locator('#dialog')).to_contain_text('OWNED\\B<&>')
                expect(page.locator('#dialog')).to_contain_text('由全機元件收集')
                expect(page.locator('#dialog')).not_to_contain_text('undefined 個磁碟')
                report['passed']=not report['page_errors'];report['checks']=['machine scope visible','actual reporting account escaped','machine-owned collector label']
            finally:browser.close()
    finally:
        fixture.tearDown()
        path=ROOT/'evidence'/('machine-agent-ui-'+uid+'.json');path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8');print(path);print(json.dumps(report,ensure_ascii=False))
    return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
