"""Isolated real Chromium acceptance for the 0.4.28 management workflow."""
import json
import secrets
import sys
import tempfile
import threading
import time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from guarddesk import __version__
from guarddesk.server import serve
from guarddesk.store import Store
from playwright.sync_api import sync_playwright,expect
ROOT=Path(__file__).resolve().parents[1]


def wait_js(page, predicate, timeout=10000):
    deadline=time.monotonic()+timeout/1000
    while time.monotonic()<deadline:
        if page.evaluate(predicate):return
        time.sleep(.1)
    raise AssertionError("Browser condition timed out: "+predicate)


def main():
    errors=[];checks=[]
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime',prefix='improvements-browser-') as tmp:
        store=Store(Path(tmp)/'control.sqlite3');password=secrets.token_urlsafe(20);store.add_user('fixture-mis',password)
        with store.connect() as db:
            db.execute("INSERT INTO endpoint_groups VALUES ('fixture-team','測試資訊組',NULL,1,?)",(time.time(),))
            for i in range(61):
                db.execute('INSERT INTO devices(id,token,name,department,last_seen,inventory,group_id) VALUES (?,?,?,?,?,?,?)',(f'fixture-{i}',secrets.token_hex(20),f'測試電腦-{i:02d}','合成資料',time.time(),'{}','fixture-team'))
            for i in range(65):Store.event(db,'fixture-0','file.deleted','info',{'path':r'C:\Owned\report-'+str(i)+'.docx'},'browser-fixture-'+str(i))
        server=serve(store.path,port=0);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with sync_playwright() as p:
                browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True)
                try:
                    page=browser.new_page(viewport={'width':1500,'height':1050},locale='zh-TW');page.on('pageerror',lambda e:errors.append(str(e)))
                    page.goto(f'http://127.0.0.1:{server.server_port}');page.locator('[name=username]').fill('fixture-mis');page.locator('[name=password]').fill(password);page.locator('#login-form button').click()
                    page.locator('nav [data-page=devices]').click();expect(page.locator('.fleet-table tbody tr')).to_have_count(50)
                    page.locator('[data-fleet-page="1"]').click();expect(page.locator('.fleet-table tbody tr')).to_have_count(11);checks.append('61 endpoint table paginates 50/11')
                    page.locator('nav [data-page=policy]').click();page.locator('[data-action=policy-tab][data-tab=sets]').click();page.locator('[data-action=set-new]').click()
                    form=page.locator('#set-form');form.locator('[name=set_name]').fill('欄位繼承驗證');form.locator('[name=module_files]').check()
                    form.locator('[data-setting-path="file_audit.enabled"]').select_option('inherit');form.locator('[data-setting-path="file_audit.scope"]').select_option('inherit');form.locator('[data-setting-path="file_audit.exclude_paths"]').select_option('append');form.locator('[name=file_excludes]').fill('C:\\OwnedDev\nC:\\Users\\{user}\\workspace')
                    expect(form).to_contain_text('{user} 代表該位置的一層使用者資料夾')
                    expect(form.locator('[name=file_audit_enabled]')).to_be_disabled()
                    form.locator('button[type=submit]').click();expect(page.locator('[data-improve-publish]')).to_be_visible()
                    assert page.evaluate('state.policy_sets.length')==0
                    with page.expect_response(lambda r:r.url.endswith('/api/policy-sets') and r.request.method=='POST') as response:page.locator('[data-improve-publish]').click()
                    result=response.value;assert result.ok,result.text();body=result.request.post_data_json;pid=result.json()['id']
                    assert body['overrides']=={} and body['operations']==[{'path':'file_audit.exclude_paths','op':'append','value':[r'C:\OwnedDev',r'C:\Users\{user}\workspace']}],body
                    checks.append('User path token help and literal template survive real UI preview/publication')
                    checks.append('Inheritance and append serialize narrowly; preview does not publish')
                    page.locator('[data-action=set-assign][data-id="'+pid+'"]').click();page.locator('#assignment-form button.primary').click()
                    expect(page.locator('#dialog-content')).to_contain_text('61 台')
                    page.screenshot(path=str(ROOT/f'evidence/improvements-preview-{__version__}.png'),full_page=True)
                    page.locator('[data-action=assignment-confirm]').click();wait_js(page,'() => state.assignments.length===1');checks.append('Assignment previews all 61 scopes with before/after changes')
                    page.locator('[data-action=policy-tab][data-tab=sets]').click();page.locator('[data-action=set-edit][data-id="'+pid+'"]').click()
                    form.locator('[name=file_excludes]').fill(r'C:\OwnedV2');form.locator('button[type=submit]').click();page.locator('[data-improve-publish]').click()
                    wait_js(page,'() => state.policy_sets[0].revision===2')
                    page.locator('[data-action=set-history][data-id="'+pid+'"]').click();page.locator('[data-policy-restore="1"]').click()
                    expect(page.locator('#dialog-content')).to_contain_text('61 台設定會改變');page.locator('[data-improve-publish]').click()
                    wait_js(page,'() => state.policy_sets[0].revision===3');checks.append('History restores original settings as new revision after diff preview')
                    page.locator('nav [data-page=devices]').click();page.locator('#fleet-search').fill('測試電腦-00');page.locator('[data-action=device][data-id=fixture-0]').click()
                    expect(page.locator('#dialog-content')).to_contain_text('策略發布、接收與元件回報');expect(page.locator('#dialog-content')).to_contain_text('待確認')
                    page.screenshot(path=str(ROOT/f'evidence/improvements-progress-{__version__}.png'),full_page=True);page.locator('#close-dialog').click();checks.append('Device view distinguishes receipt from missing component evidence')
                    page.locator('nav [data-page=audit]').click();page.locator('[data-audit-category=documents]').click();wait_js(page,'() => events.items.length===50 && events.total===null')
                    first=page.evaluate('events.items.map(x=>x.id)');page.locator('[data-action=next]').click();wait_js(page,'() => events.items.length===15')
                    second=page.evaluate('events.items.map(x=>x.id)');assert not set(first)&set(second);checks.append('Signed cursor audit pages retain exact 50/15 results without overlap')
                    page.locator('nav [data-page=archives]').click();page.locator('[data-storage-open]').last.click();page.locator('[data-storage-enable]').click()
                    wait_js(page,"async()=> (await api('/api/audit/storage')).mode==='daily-v1'",timeout=10000)
                    page.locator('[data-storage-open]').last.click();expect(page.locator('#dialog-content')).to_contain_text('分日事件儲存已啟用')
                    with server.store.connect() as db:Store.event(db,'fixture-0','file.moved','info',{'source_path':r'C:\Owned\new.docx','destination_path':r'D:\Owned\new.docx'},'browser-after-activation')
                    page.locator('[data-storage-open]').last.click();page.screenshot(path=str(ROOT/f'evidence/improvements-storage-{__version__}.png'),full_page=True)
                    assert server.store.verify()['valid'];page.locator('#close-dialog').click();checks.append('MIS can activate daily storage asynchronously; old/new event chain remains valid')
                    page.locator('nav [data-page=policy]').click();page.locator('[data-action=policy-tab][data-tab=sets]').click();page.locator('#policy-template').select_option('2');page.locator('[data-policy-template]').click()
                    expect(form.locator('[name=module_files]')).to_be_checked();expect(form.locator('[name=module_apps]')).to_be_checked();expect(form.locator('[data-setting-path=application_audit]')).to_have_value('inherit')
                    with server.bundled_release.lock:
                        server.bundled_release.state={'version':__version__,'status':'failed','code':'source_not_private','diagnostic':{'path':r'C:\GuardDesk\<synthetic>.dll','reason':'untrusted_write'}}
                    page.locator('nav [data-page=updates]').click()
                    expect(page.locator('#workspace')).to_contain_text(r'C:\GuardDesk\<synthetic>.dll')
                    expect(page.locator('#workspace')).to_contain_text('其他帳戶可改寫此位置')
                    assert page.locator('synthetic').count()==0
                    page.screenshot(path=str(ROOT/f'evidence/source-permissions-browser-{__version__}.png'),full_page=True)
                    checks.append('Bundled-source diagnostics name the failed location and safely escape text')
                    page.locator('nav [data-page=policy]').click()
                    page.set_viewport_size({'width':390,'height':844});assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                    page.screenshot(path=str(ROOT/f'evidence/improvements-mobile-{__version__}.png'),full_page=True);checks.append('Development template is an unpublished narrow draft; 390px layout has no page overflow')
                    assert not errors,errors
                finally:
                    if errors:print('PAGE_ERRORS',errors)
                    browser.close()
        finally:server.shutdown();server.server_close();thread.join(5)
    report={'passed':True,'checks':checks,'page_errors':errors,'scope':'Synthetic localhost real Chromium; no office endpoint or Defender acceptance'}
    (ROOT/f'evidence/improvements-browser-{__version__}.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,ensure_ascii=False))


if __name__=='__main__':main()
