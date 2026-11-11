"""Owned Chrome UI and frozen API; does not access employee browser profiles."""
import hashlib
import io
import json
import subprocess
import sys
import time
import zipfile
from pathlib import Path
import tempfile
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import test_system
from guarddesk import __version__,audit_sort,audit_search_index
from guarddesk.store import Store
from guarddesk.policy import DEFAULT_POLICY
from playwright.sync_api import sync_playwright,expect


def main():
    # Real signer ACL validation must run inside an actual private Server root,
    # not the broadly inherited generic test_system TemporaryDirectory.
    original_temp=tempfile.TemporaryDirectory
    def private_temp(*args,**kwargs):
        from guarddesk.server_setup import secure_directory
        temporary=original_temp(*args,**kwargs);folder=Path(temporary.name)/'private-server';secure_directory(folder)
        class Owned:
            name=str(folder)
            def cleanup(self):temporary.cleanup()
        return Owned()
    case=test_system.SystemTest('runTest')
    with patch.object(test_system.tempfile,'TemporaryDirectory',side_effect=private_temp):case.setUp()
    process=None;errors=[];frozen='--frozen' in sys.argv
    try:
        agent,did,_=case.make_agent()
        agent.heartbeat()
        with case.store.connect() as db:
            for kind in ('file.opened','file.created','file.copy_candidate','web.upload_started','web.upload_response','web.navigation'):
                details={'source_path':r'C:\Owned\readme.txt','destination_path':r'C:\Owned\copied.txt' if kind=='file.copy_candidate' else None,'operation_confirmed':False,'url':'https://owned.example/upload','source':'windows_etw_file_io' if kind=='file.copy_candidate' else 'windows_security' if kind.startswith('file.') else 'browser_webrequest','upload_id':'owned-flow','application_success':'unknown','phase':'response' if kind.endswith('response') else 'started'}
                Store.event(db,did,kind,'info',details,occurred=time.time()-1)
            Store.event(db,did,'file.opened','info',{'path':r'C:\Owned\mapped.txt','source':'windows_etw_file_io','evidence':'completed_native_open','read_confirmed':False,'human_read_confirmed':False,'process':r'C:\Windows\notepad.exe','process_id':123},occurred=time.time()-1)
            Store.event(db,did,'file.opened','info',{'path':r'C:\Owned\History1','source':'windows_etw_file_io','evidence':'completed_native_read','read_bytes':64,'human_read_confirmed':False,'process':r'C:\Owned\background.exe','process_id':124},occurred=time.time()-1)
        with case.store.connect() as db:Store.event(db,did,'web.upload_started','info',{'source_path':'','file_name':'memory-candidate.txt','url':'https://storage.owned.example/body','site_origin':'https://owned.example','correlation':'page_body_metadata_candidate','upload_id':'owned-memory-flow','application_success':'unknown'},occurred=time.time()-1)
        case.server.search_index.close()
        while audit_sort.index_batch(case.store):pass
        while audit_search_index.index_batch(case.store):pass
        if frozen:
            case.server.shutdown();case.server.server_close();case.thread.join(5)
            process=subprocess.Popen([str(ROOT/'dist/GuardDesk/GuardDesk.exe'),'serve','--db',str(case.db),'--port',case.url.rsplit(':',1)[1]],cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
            for _ in range(100):
                try:
                    if case.api('/api/health')['version']==__version__:break
                except (OSError,ConnectionError):pass
                time.sleep(.1)
            else:raise AssertionError('frozen Server did not start')
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True)
            try:
                page=browser.new_page(viewport={'width':1700,'height':1050},locale='zh-TW');page.on('pageerror',lambda e:errors.append(str(e)))
                def wait():
                    deadline=time.monotonic()+20
                    while time.monotonic()<deadline:
                        if page.evaluate('()=>!busy'):return
                        page.wait_for_timeout(30)
                    raise AssertionError('UI remained busy')
                page.goto(case.url)
                page.locator('#login-form [name=username]').fill('admin');page.locator('#login-form [name=password]').fill(case.password);page.locator('#login-form button').click();wait()
                form_policy=json.loads(json.dumps(DEFAULT_POLICY));form_policy['file_audit']['exclude_paths']=[r'C:\Owned','@guarddesk:file-access:v1:process:OneDrive.exe','@guarddesk:file-access:v1:include-services','@guarddesk:file-access:v1:include-background','@guarddesk:file-access:v1:interaction-seconds:45']
                policy_roundtrip=page.evaluate('''(p)=>{const form=document.createElement('form');form.innerHTML=Object.values(endpointModuleFields(p)).join('');const rules=readPolicyForm(form).file_audit.exclude_paths;return {rules,pathValue:form.querySelector('[name=file_excludes]').value,programs:form.querySelector('[name=file_read_processes]').value,services:form.querySelector('[name=exclude_file_services]').checked};}''',form_policy)
                assert set(policy_roundtrip['rules'])==set(form_policy['file_audit']['exclude_paths'])
                assert policy_roundtrip['pathValue']==r'C:\Owned' and policy_roundtrip['programs']=='OneDrive.exe' and not policy_roundtrip['services']
                interactive=page.evaluate('''(p)=>{const form=document.createElement('form');form.innerHTML=Object.values(endpointModuleFields(p)).join('');form.querySelector('[name=file_access_mode]').value='interactive';form.querySelector('[name=file_access_seconds]').value='60';return readPolicyForm(form).file_audit.exclude_paths;}''',form_policy)
                assert '@guarddesk:file-access:v1:include-background' not in interactive
                assert '@guarddesk:file-access:v1:interaction-seconds:60' in interactive
                page.locator('nav [data-page=audit]').click();wait()
                page.locator('[data-audit-category=documents]').click();wait()
                kinds=page.evaluate('events.items.map(e=>e.kind)')
                assert set(kinds)=={'file.opened','file.created','file.copy_candidate','web.upload_started','web.upload_response'},kinds
                expect(page.locator('.notice').filter(has_text='文檔操作：')).to_be_visible()
                assert '一般複製尚未提供' not in page.locator('#workspace').inner_text()
                # This diagnostic uses selected draft endpoint, not an event
                # search or a scan of previous file/upload activity.
                page.locator('#search-form [name=device]').select_option(did)
                readiness_calls=[];page.on('request',lambda r:readiness_calls.append(r.url) if '/api/events?' in r.url else None)
                page.locator('[data-document-diagnostics]').click()
                expect(page.locator('[data-document-general]')).to_contain_text('不需要另建自訂設定')
                expect(page.get_by_text('尚未觀察到擴充連線；需要 MIS 部署或開啟瀏覽器',exact=True)).to_be_visible()
                assert not readiness_calls,readiness_calls
                page.locator('#close-dialog').click()
                assert '網站保存結果未知' in page.locator('table.detailed-audit').inner_text()
                assert '可能複製（讀寫關聯）' in page.locator('table.detailed-audit').inner_text()
                assert '未確認整份複製／內容相同' in page.locator('table.detailed-audit').inner_text()
                candidate_row=page.locator('table.detailed-audit tbody tr').filter(has_text='memory-candidate.txt')
                expect(candidate_row.locator('td').nth(4)).to_contain_text('memory-candidate.txt')
                expect(candidate_row).to_contain_text('未確認完整來源')
                mapped_row=page.locator('table.detailed-audit tbody tr').filter(has_text='mapped.txt')
                expect(mapped_row).to_contain_text('notepad.exe')
                expect(mapped_row).to_contain_text('未證明讀取內容或人工開啟')
                background_row=page.locator('table.detailed-audit tbody tr').filter(has_text='History1')
                expect(background_row).to_contain_text('background.exe')
                expect(background_row).to_contain_text('不代表員工手動開啟或閱讀')
                assert 'copied.txt' in page.locator('table.detailed-audit').inner_text()
                expect(page.locator('#search-form [name=kind] option[value="web.upload_started"]')).to_have_count(1)
                expect(page.locator('#search-form [name=kind] option[value="web.navigation"]')).to_have_count(0)
                page.screenshot(path=str(ROOT/f'evidence/document-audit-desktop-{__version__}.png'))
                page.locator('[data-audit-category=uploads]').click();wait()
                with page.expect_download() as download:page.locator('[data-browser-package]').click()
                with zipfile.ZipFile(download.value.path()) as archive:
                    assert json.loads(archive.read('deployment-status.json'))['status']=='publication_required'
                expect(page.locator('[data-upload-readiness]')).to_contain_text('尚未連線／未回報')
                page.locator('[data-browser-publication]').click()
                expect(page.locator('[data-publication-state]')).to_contain_text('尚未發布')
                page.locator('#browser-publication-create [name=base_url]').fill('https://company-fixture.test:8787/browser-extension/')
                page.locator('#browser-publication-create [name=confirm_company_identity]').check()
                page.locator('#browser-publication-create button').click()
                expect(page.locator('[data-publication-state]')).to_contain_text('已發布',timeout=15000)
                expect(page.locator('[data-publication-state]')).to_contain_text('請重新下載端點安裝包')
                assert (case.root/'BrowserSigner/extension-signing.pem').is_file()
                page.screenshot(path=str(ROOT/f'evidence/browser-publication-{__version__}.png'))
                page.locator('#close-dialog').click()
                # No audit-history request should be introduced by endpoint detail.
                calls=[];page.on('request',lambda r:calls.append(r.url) if '/api/events?' in r.url else None)
                page.evaluate('(id)=>showDeviceDetail(id)',did)
                expect(page.get_by_text('文檔能力就緒狀態',exact=True)).to_be_visible()
                expect(page.locator('.key-row').filter(has_text='一般檔案複製')).to_contain_text('尚未取得新版原生工作回報')
                expect(page.get_by_text('尚未觀察到擴充連線；需要 MIS 部署或開啟瀏覽器',exact=True)).to_be_visible()
                assert not calls,calls
                page.get_by_text('文檔能力就緒狀態',exact=True).scroll_into_view_if_needed()
                page.screenshot(path=str(ROOT/f'evidence/document-readiness-{__version__}.png'))
                assert not errors,errors
            finally:browser.close()
        report={'passed':True,'version':__version__,'frozen_server_used':frozen,'page_errors':errors,
                'checks':['Unified document filtering preserves read/file/upload phases, excludes browsing','Evidence boundaries visible without claiming successful upload','Upload actions available in unified action filter','MIS deployment ZIP downloaded from authenticated UI','Read/copy/upload readiness visible without history API','Selected draft endpoint diagnostics show general policy and missing extension without querying event history','Obsolete copy-unavailable banner removed','Latest upload connectivity summary visible without event history scan','MIS creates a stable company signing identity and self-host publication from authenticated UI; no system trust or endpoint changed'],
                'office_accessed':False,'live_policy_applied':False}
        if frozen:report['exe_sha256']=hashlib.sha256((ROOT/'dist/GuardDesk/GuardDesk.exe').read_bytes()).hexdigest()
        (ROOT/f'evidence/document-audit-browser-{__version__}{"" if frozen else "-source"}.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(report,ensure_ascii=True))
    finally:
        if process:process.terminate();process.wait(20)
        agent.close_collectors();case.tearDown()


if __name__=='__main__':main()
