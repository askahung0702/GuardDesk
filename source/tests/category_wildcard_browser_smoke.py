"""Actual owned console UI, headless isolated Chrome, synthetic host patterns."""
import json
import sys
import uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_system
from playwright.sync_api import sync_playwright,expect


def main():
    root=Path(__file__).resolve().parents[1];probe=uuid.uuid4().hex
    result={'probe_id':probe,'scope':'owned_headless_console_no_employee_profile','passed':False,'page_errors':[],'machine_policy_modified':False}
    test=test_system.SystemTest();test.setUp()
    try:
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True,chromium_sandbox=True)
            try:
                page=browser.new_page(viewport={'width':1500,'height':1100},locale='zh-TW');page.on('pageerror',lambda e:result['page_errors'].append(str(e)))
                page.goto(test.url);page.locator('[name=username]').fill('admin');page.locator('[name=password]').fill(test.password);page.locator('#login-form button').click()
                page.get_by_role('heading',name='安全總覽',exact=True).wait_for();page.locator('nav [data-page=categories]').click()
                page.locator('[data-category-action=new]').click();page.locator('#category-editor [name=name]').fill('Wildcard cloud fixture')
                page.locator('[data-category-action=bulk]').click();page.locator('#category-bulk [name=domains]').fill('*.box.com\n*.dropbox.*\n*documentcloud*');page.locator('#category-bulk button').click()
                page.locator('[data-category-action=member-add]').click();page.locator('#category-member-form [name=name]').fill('Retain unsaved input')
                page.locator('#category-member-form [name=domain]').fill('*.draft.example');page.locator('#category-member-form [name=type]').select_option('host_glob')
                expect(page.locator('#category-member-form [name=name]')).to_have_value('Retain unsaved input')
                expect(page.locator('#category-member-form [name=pattern]')).to_have_value('*.draft.example')
                page.locator('#category-member-form button.primary').click();page.locator('[data-category-remove="3"]').click()
                page.locator('[data-category-action=match-draft]').click();page.locator('#category-match [name=urls]').fill('https://box.com/\nhttps://www.dropbox.jp/\nhttps://box.com.evil.test/')
                page.locator('#category-match button').click();expect(page.locator('#category-match-result')).to_contain_text('符合類別模式，未列入原生管制範圍')
                expect(page.locator('#category-match-result')).to_contain_text('未命中此類別');page.locator('#category-match-back').click()
                expect(page.locator('#category-editor [name=name]')).to_have_value('Wildcard cloud fixture')
                page.locator('#category-editor button.primary').click();page.locator('[data-category-action=edit]').wait_for()
                expect(page.locator('#workspace tbody tr')).to_have_count(3);expect(page.locator('#workspace')).to_contain_text('*.dropbox.*')
                page.locator('[data-category-action=edit]').click()
                for index,host in [(1,'dropbox.com'),(2,'documentcloud.adobe.com')]:
                    page.locator(f'[data-category-member="{index}"]').click();expect(page.locator('[name=type]')).to_have_value('host_glob')
                    page.locator('[name=enforcement_domains]').fill(host);page.locator('#category-member-form button.primary').click()
                page.locator('#category-editor button.primary').click();page.get_by_text('草稿 v2',exact=False).first.wait_for()
                page.locator('[data-category-action=preview]').click();page.locator('#category-publish').click();page.get_by_text('已發布 v3',exact=False).first.wait_for()
                page.locator('[data-category-action=match]').click();page.locator('#category-match [name=urls]').fill('https://www.dropbox.com/\nhttps://dropbox.jp/')
                page.locator('#category-match button').click();expect(page.locator('#category-match-result')).to_contain_text('僅列出網域，未涵蓋整個模式')
                expect(page.locator('#category-match-result')).to_contain_text('列入原生管制範圍')
                page.screenshot(path=str(root/'evidence'/('category-wildcard-ui-'+probe+'.png')),full_page=True)
                selected=test.api('/api/categories')['items'][0];members=test.api('/api/categories?id='+selected['id'])['selected']['members']
                assert members[1]['pattern']=='*.dropbox.*' and members[1]['enforcement_domains']==['dropbox.com']
                assert not result['page_errors'],result['page_errors']
                result.update(passed=True,checks=['bulk wildcard input','member type switch retains unsaved fields','unsaved draft match','draft retained','normalized host_glob editor','finite mappings retained','publish and reload','coverage preview','host boundary negative','no page errors'])
            finally:browser.close()
    except Exception as exc:
        result['failure']=type(exc).__name__+': '+str(exc)[:1800];raise
    finally:
        test.tearDown();path=root/'evidence'/('category-wildcard-browser-'+probe+'.json');path.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8');print(path);print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':main()
