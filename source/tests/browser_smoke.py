"""Manual integration check against a running local demo; no credentials in artifacts."""
import json
import secrets
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from playwright.sync_api import sync_playwright
from guarddesk.agent import Agent


def run():
    root=Path(__file__).resolve().parents[1]
    credentials=dict(line.split(': ',1) for line in (root/'runtime/access.txt').read_text(encoding='utf-8').splitlines())
    output=root/'evidence'
    errors=[]
    with sync_playwright() as p:
        browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True)
        page=browser.new_page(viewport={'width':1440,'height':1100},locale='zh-TW',timezone_id='Asia/Taipei')
        page.on('pageerror',lambda error:errors.append(str(error)))
        page.goto(credentials['URL'])
        page.locator('#login-form [name=username]').fill(credentials['Username'])
        page.locator('#login-form [name=password]').fill(credentials['Password'])
        page.locator('#login-form button').click()
        page.get_by_role('heading',name='安全總覽',exact=True).wait_for()
        assert page.locator('#nav-count').inner_text()!='0'
        page.locator('nav [data-page=policy]').click()
        page.locator('#policy-form').wait_for()
        page.locator('[name=mode]').select_option('enforce')
        page.locator('#policy-form button[type=submit]').click()
        page.get_by_text('策略 v',exact=False).first.wait_for()
        # Use real endpoint operations, not seeded audit rows.
        agent=Agent(root/'runtime/agent/config.json')
        nonce=secrets.token_hex(4)
        clean=root/'runtime/exports'/f'clean-{nonce}.txt'
        blocked=root/'runtime/exports'/f'blocked-{nonce}.txt'
        agent.export(root/'runtime/managed/welcome.txt',clean)
        try:
            agent.export(root/'runtime/managed/confidential.txt',blocked)
            raise AssertionError('Sensitive export unexpectedly allowed')
        except PermissionError:
            assert not blocked.exists()
        agent.heartbeat()
        page.locator('nav [data-page=audit]').click()
        page.locator('#search-form').wait_for()
        page.locator('#search-form [name=q]').fill('confidential')
        page.locator('#search-form button').first.click()
        page.get_by_text('策略已阻擋受控外發',exact=True).first.wait_for()
        page.screenshot(path=str(output/'audit-desktop.png'),full_page=True)
        page.locator('[data-action=integrity]').click()
        page.get_by_role('dialog').wait_for()
        assert '雜湊鏈一致' in page.locator('#dialog-content').inner_text()
        page.locator('#close-dialog').click()
        page.locator('nav [data-page=devices]').click()
        page.get_by_role('heading',name='端點裝置',exact=True).wait_for()
        page.locator('[data-action=device]').first.click()
        page.locator('#dialog-content').get_by_text('磁碟可用',exact=True).wait_for()
        page.locator('#close-dialog').click()
        page.locator('nav [data-page=overview]').click()
        page.get_by_role('heading',name='安全總覽',exact=True).wait_for()
        page.screenshot(path=str(output/'overview-desktop.png'),full_page=True)
        page.set_viewport_size({'width':390,'height':844})
        page.screenshot(path=str(output/'overview-mobile.png'),full_page=True)
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        assert not errors,errors
        browser.close()
    report={'passed':True,'checks':['browser login','real device inventory','publish policy','clean export writes file','sensitive export writes nothing','audit search','audit chain verification','desktop layout','390px mobile no overflow','no browser page errors'],'page_errors':errors}
    (output/'browser-smoke.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False))


if __name__=='__main__':
    run()
