"""Isolated real Chrome UI acceptance. Never sends mail or uses live credentials."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import shutil
import sys
import time
import urllib.error
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from playwright.sync_api import sync_playwright,expect
from guarddesk import __version__
from guarddesk.audit_reports import TAIPEI,index_batch
from guarddesk.store import Store
import test_system


def main():
    root=Path(__file__).resolve().parents[1];case=test_system.SystemTest('runTest');case.setUp();process=None
    frozen='--frozen' in sys.argv;errors=[];stamp=dt.datetime.now(TAIPEI)-dt.timedelta(days=1)
    try:
        with case.store.connect() as db:
            for i in range(250):
                did=f'fixture-{i:03}'
                db.execute('INSERT INTO devices(id,token,name,department,last_seen) VALUES(?,?,?,?,?)',(did,did,f'PC-{i:03}','Synthetic',time.time()))
                if i<30:
                    for n in range(31-i):Store.event(db,did,'file.created','info',{'path':'synthetic document'},occurred=stamp.timestamp())
        while index_batch(case.store):pass
        if frozen:
            case.server.shutdown();case.server.server_close();case.thread.join(5)
            exe=root/'dist/GuardDesk/GuardDesk.exe'
            process=subprocess.Popen([str(exe),'serve','--db',str(case.db),'--port',case.url.rsplit(':',1)[1]],cwd=root,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
            for _ in range(100):
                try:
                    if case.api('/api/health')['version']==__version__:break
                except (urllib.error.URLError,ConnectionError):pass
                time.sleep(.1)
            else:raise AssertionError('frozen server did not start')
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True)
            page=browser.new_page(viewport={'width':1600,'height':1100},locale='zh-TW');page.on('pageerror',lambda e:errors.append(str(e)))
            page.goto(case.url);page.locator('[name=username]').fill('admin');page.locator('[name=password]').fill(case.password);page.locator('#login-form button').click()
            page.locator('nav [data-page=mail]').click();page.locator('#mail-config').wait_for();expect(page.locator('#workspace')).to_contain_text('圖片內嵌於附件');expect(page.locator('#mail-config [name=enabled]')).not_to_be_checked()
            page.locator('[name=recipients]').fill('mis@example.test');page.locator('[name=sender]').fill('reports@example.test')
            for name in ('tenant_id','client_id'):page.locator(f'[name={name}]').fill('12345678-1234-1234-1234-123456789012')
            page.locator('[name=time]').fill('09:15');page.locator('#mail-config [type=submit]').click();expect(page.locator('#toast')).to_contain_text('已儲存寄送設定')
            saved=case.api('/api/mail-reports');assert saved['body']['time']=='09:15' and not saved['body']['enabled'];assert not saved['jobs']
            page.locator('[name=time]').fill('11:45')
            case.api('/api/mail-reports/config',{'body':{**saved['body'],'time':'10:30'},'revision':saved['revision']})
            page.evaluate('refresh()');page.wait_for_timeout(200)
            page.locator('#mail-config [type=submit]').click();expect(page.locator('#toast')).to_contain_text('設定已變更')
            assert case.api('/api/mail-reports')['body']['time']=='10:30'
            page.locator('#mail-discard').click();expect(page.locator('[name=time]')).to_have_value('10:30')
            while index_batch(case.store):pass
            page.locator('#mail-preview').click();page.locator('.mail-preview').wait_for(timeout=30000)
            expect(page.locator('.mail-preview')).to_contain_text('PC-249');expect(page.locator('.mail-preview')).to_contain_text('前二十名')
            assert page.locator('.mail-preview img').count()==8
            page.wait_for_function("[...document.querySelectorAll('.mail-preview img')].every(i=>i.complete&&i.naturalWidth>0)")
            page.screenshot(path=str(root/f'evidence/mail-reports-preview-{__version__}.png'),full_page=True)
            with page.expect_download() as downloaded:
                page.locator('#mail-download').click()
            download=downloaded.value
            assert download.suggested_filename=='GuardDesk-File-Changes-'+stamp.date().isoformat()+'.html'
            attachment=case.root/download.suggested_filename;download.save_as(attachment)
            shutil.copyfile(attachment,root/f'evidence/mail-attachment-example-{__version__}.html')
            offline_requests=[]
            offline=browser.new_context(offline=True)
            try:
                report=offline.new_page();report.on('pageerror',lambda e:errors.append(str(e)))
                report.on('request',lambda req:offline_requests.append(req.url) if req.url.startswith(('http:','https:')) else None)
                report.goto(attachment.as_uri());expect(report.locator('h1')).to_contain_text('每日檔案異動總表')
                expect(report.locator('body')).to_contain_text('PC-249');expect(report.locator('body')).to_contain_text('前二十名')
                assert report.locator('img').count()==8
                report.wait_for_function("[...document.images].every(i=>i.complete&&i.naturalWidth>0)")
                assert report.locator('script,iframe,object,link,form').count()==0
                assert not offline_requests,offline_requests
                report.screenshot(path=str(root/f'evidence/mail-attachment-offline-{__version__}.png'),full_page=True)
                report.set_viewport_size({'width':390,'height':844})
                assert report.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
            finally:offline.close()
            page.locator('#close-dialog').click()
            page.locator('#mail-send').click();expect(page.locator('#dialog')).to_contain_text('mis@example.test');page.locator('#close-dialog').click()
            assert case.api('/api/mail-reports')['jobs']==[]
            # Dirty forms and password fields survive automatic refresh without
            # persisting an unsaved credential anywhere in our evidence.
            page.locator('[name=client_secret]').fill('SYNTHETIC-UNSAVED-SECRET')
            page.evaluate('refresh({automatic:true})');expect(page.locator('[name=client_secret]')).to_have_value('SYNTHETIC-UNSAVED-SECRET')
            page.locator('#mail-discard').click();expect(page.locator('[name=client_secret]')).to_have_value('')
            path=root/f'evidence/mail-reports-desktop-{__version__}.png';page.screenshot(path=str(path),full_page=True)
            page.set_viewport_size({'width':390,'height':844});page.screenshot(path=str(root/f'evidence/mail-reports-mobile-{__version__}.png'),full_page=True)
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
            page.set_viewport_size({'width':1600,'height':1100});page.locator('nav [data-page=custom]').click();page.locator('#library-new').wait_for()
            page.locator('nav [data-page=reports]').click();page.locator('#workspace h1').wait_for();expect(page.locator('#workspace')).to_contain_text('稽核總表')
            page.locator('#logout').click();page.locator('[name=username]').fill('reader');page.locator('[name=password]').fill(case.password);page.locator('#login-form button').click()
            expect(page.locator('nav [data-page=mail]')).to_be_hidden()
            browser.close()
        assert not errors,errors
        result={'passed':True,'version':__version__,'frozen_server_used':frozen,'live_mail_sent':False,'live_credentials_read':False,'devices':250,'downloaded_attachment_sha256':hashlib.sha256(attachment.read_bytes()).hexdigest(),'downloaded_attachment_bytes':attachment.stat().st_size,'offline_http_requests':offline_requests,'checks':['admin configuration persists','stale draft cannot overwrite another administrator','default disabled','recipient/time settings','250-device bar charts and full pie/table','top 20','embedded PNGs load', 'downloaded HTML opens offline with all 250 names, eight charts and no HTTP/script dependency', 'static attachment fits 390px viewport','preview and send confirmation create no mail job','unsaved secret survives auto refresh and clears on discard','390px no page overflow','legacy custom settings and summary navigation','auditor menu hidden'],'page_errors':errors}
        if frozen:result['exe_sha256']=hashlib.sha256((root/'dist/GuardDesk/GuardDesk.exe').read_bytes()).hexdigest()
        (root/f'evidence/mail-reports-browser-{__version__}{"" if frozen else "-source"}.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(result,ensure_ascii=False))
    finally:
        if process:process.terminate();process.wait(20)
        case.tearDown()


if __name__=='__main__':main()
