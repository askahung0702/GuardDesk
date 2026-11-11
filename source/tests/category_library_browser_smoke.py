"""Owned loopback console, isolated profile, synthetic rules; no HKLM mutation."""
import json
import sys
import time
import uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_system
from playwright.sync_api import sync_playwright,expect


def main():
    root=Path(__file__).resolve().parents[1];probe=uuid.uuid4().hex
    result={'probe_id':probe,'scope':'isolated_loopback_console_headless','machine_policy_modified':False,'employee_profile_used':False,'passed':False,'page_errors':[]}
    test=test_system.SystemTest();test.setUp()
    try:
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True,chromium_sandbox=True)
            try:
                page=browser.new_page(viewport={'width':1500,'height':1000},locale='zh-TW')
                page.on('pageerror',lambda e:result['page_errors'].append(str(e)))
                page.goto(test.url);page.locator('[name=username]').fill('admin');page.locator('[name=password]').fill(test.password);page.locator('#login-form button').click()
                page.get_by_role('heading',name='安全總覽',exact=True).wait_for()
                page.locator('nav [data-page=categories]').click();page.get_by_role('heading',name='分類管理',exact=True).wait_for()
                page.locator('[data-category-action=new]').click();page.locator('#category-editor [name=name]').fill('Synthetic cloud')
                page.locator('[data-category-action=bulk]').click();page.locator('#category-bulk [name=domains]').fill('\n'.join(f's{i}.example.com' for i in range(51)))
                page.locator('#category-bulk button').click();page.locator('#category-editor button.primary').click()
                page.locator('[data-category-action=preview]').wait_for();page.locator('[data-category-action=preview]').click();page.locator('#category-publish').click()
                page.get_by_text('已發布 v2',exact=False).first.wait_for()
                expect(page.locator('#workspace tbody tr')).to_have_count(50)
                page.locator('[data-category-page="1"]').click();expect(page.locator('#workspace tbody tr')).to_have_count(1)
                page.locator('[data-category-page="-1"]').click();expect(page.locator('#workspace tbody tr')).to_have_count(50)
                page.locator('#category-search input').fill('s50.example.com');page.locator('#category-search button').click()
                expect(page.locator('#workspace tbody tr')).to_have_count(1)
                page.locator('[data-category-action=edit]').click()
                expect(page.locator('#category-editor')).to_contain_text('51 個成員')
                expect(page.locator('#category-editor tbody tr')).to_have_count(50)
                page.locator('[data-category-edit-page="1"]').click();expect(page.locator('#category-editor tbody tr')).to_have_count(1)
                page.locator('#category-editor [name=name]').fill('Synthetic cloud renamed')
                page.locator('#category-editor button.primary').click()
                page.get_by_text('草稿 v3',exact=False).first.wait_for()
                page.locator('[data-category-action=preview]').click();page.locator('#category-publish').click()
                page.get_by_text('已發布 v4',exact=False).first.wait_for()
                page.locator('[data-category-action=history]').click();page.locator('[data-category-restore="1"]').click()
                expect(page.locator('#category-editor [name=name]')).to_have_value('Synthetic cloud')
                expect(page.locator('#category-editor')).to_contain_text('51 個成員')
                page.locator('#close-dialog').click()
                page.locator('[data-category-action=export]').wait_for()
                page.screenshot(path=str(root/'evidence'/('category-library-'+probe+'.png')),full_page=True)
                page.locator('nav [data-page=policy]').click();page.locator('[data-action=policy-tab][data-tab=sets]').click();page.locator('[data-action=set-new]').click()
                form=page.locator('#set-form');form.locator('[name=set_name]').fill('Synthetic website blocking')
                form.locator('[name=module_website]').check();form.locator('[name=website_enabled]').check();form.locator('[data-category-ref=website_blocked]').check()
                form.locator('button[type=submit]').click();page.locator('[data-improve-publish]').wait_for()
                with page.expect_response(lambda r:r.url.endswith('/api/policy-sets') and r.request.method=='POST') as response:page.locator('[data-improve-publish]').click()
                assert response.value.ok,response.value.text()
                policy=test.api('/api/state')['policy_sets'][0]
                assert len(policy['category_refs']['website_blocked'])==1
                page.locator('[data-action=set-edit]').click();expect(page.locator('[data-category-ref=website_blocked]')).to_be_checked()
                page.screenshot(path=str(root/'evidence'/('category-policy-'+probe+'.png')),full_page=True)
                assert not result['page_errors'],result['page_errors']
                result.update(passed=True,checks=['navigation','typed bulk website draft','explicit preview and publication','50 plus 1 pagination','policy category selection','published refs retained on edit','filtered edit preserves all 51 members','editor 50 plus 1 pagination','history restores original snapshot to draft','no browser page errors'])
            finally:browser.close()
    except Exception as exc:
        result['failure']=type(exc).__name__+': '+str(exc)[:1800]
        raise
    finally:
        test.tearDown();(root/'evidence'/('category-browser-smoke-'+probe+'.json')).write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':main()
