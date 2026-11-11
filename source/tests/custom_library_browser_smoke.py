"""Owned synthetic data + real Chrome. Never executes endpoint system actions."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from playwright.sync_api import sync_playwright,expect
from guarddesk import __version__
import test_system


def main():
    root=Path(__file__).resolve().parents[1];case=test_system.SystemTest('runTest');case.setUp();process=None;errors=[];frozen='--frozen' in sys.argv
    try:
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
        agent,eid,_=case.make_agent();group=case.api('/api/groups',{'name':'IT-MIS'})
        case.api('/api/devices/move-many',{'items':[{'id':eid,'revision':1}],'group_id':group['id']})
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True)
            page=browser.new_page(viewport={'width':1600,'height':1100},locale='zh-TW');page.on('pageerror',lambda e:errors.append(str(e)))
            page.goto(case.url);page.locator('[name=username]').fill('admin');page.locator('[name=password]').fill(case.password);page.locator('#login-form button').click();page.locator('nav [data-page=custom]').click();page.locator('#library-new').wait_for()
            def confirm():
                page.locator('#library-confirm').wait_for()
                if page.locator('#library-network-ack').count():page.locator('#library-network-ack').check()
                page.locator('#library-confirm').click();expect(page.locator('#dialog')).not_to_be_visible()
                expect(page.locator('#toast')).to_contain_text('已發布')
            def new(kind,name):
                page.locator('#library-new').click();page.locator(f'[data-library-new-kind={kind}]').click();page.locator('[name=item_name]').fill(name)
            # Separate editors: network form contains no scheduling/app controls.
            new('network','MIS 網路：IPv4 優先');assert page.locator('.library-schedule').count()==0;assert page.locator('.custom-software').count()==0
            page.locator('[name=ipv6]').select_option('prefer_ipv4');page.locator('#library-editor [type=submit]').click();confirm()
            saved=case.api('/api/custom-library');network=saved['items'][0];assert saved['bindings']==[]
            page.locator(f'[data-lib-assign="{network["id"]}"]').click();page.locator('#library-binding [name=target_type]').select_option('group');page.locator('#library-binding [name=target_id]').select_option(group['id']);page.locator('#library-binding [type=submit]').click();confirm()
            new('schedules','一般同仁：下班反覆提醒');expect(page.locator('[name=schedule_mode]')).to_have_value('repeat');page.locator('[name=repeat_minutes]').fill('60');page.locator('[name=repeat_until]').fill('02:00')
            page.locator('#library-editor [type=submit]').click();confirm()
            saved=case.api('/api/custom-library');reminder=next(i for i in saved['items'] if i['kind']=='schedules');assert reminder['body'][0]['repeat']=={'interval_minutes':60,'until':'02:00'}
            page.locator(f'[data-lib-assign="{reminder["id"]}"]').click();page.locator('#library-binding [name=target_type]').select_option('group');page.locator('#library-binding [name=target_id]').select_option(group['id']);page.locator('#library-binding [type=submit]').click();confirm()
            page.locator('[data-lib-tab=assign]').click();page.locator(f'[data-library-scope=group][data-target="{group["id"]}"]').click();expect(page.locator('#library-effective')).to_contain_text('一般同仁：下班反覆提醒')
            page.locator(f'[data-library-expand="{group["id"]}"]').click();page.locator(f'[data-library-scope=device][data-target="{eid}"]').click();expect(page.locator('#library-effective')).to_contain_text('IT-MIS')
            page.locator(f'[data-lib-exclude="{reminder["id"]}"]').click();expect(page.locator('#library-binding [name=binding_state]')).to_have_value('exclude');page.locator('#library-binding [type=submit]').click();confirm();expect(page.locator('#library-effective')).to_contain_text('明確排除')
            binding=next(b for b in case.api('/api/custom-library')['bindings'] if b['target_type']=='device')
            page.locator(f'[data-lib-remove-binding="{binding["id"]}"]').click();confirm();expect(page.locator('#library-effective')).not_to_contain_text('明確排除')
            # Additive document editor and endpoint assignment preserve all old settings.
            page.locator('[data-lib-tab=library]').click()
            new('documents','MIS 文件稽核：測試範圍')
            assert page.locator('.library-schedule').count()==0 and page.locator('.custom-software').count()==0
            page.locator('[name=document_path]').fill(r'C:\Company\Documents')
            page.locator('[name=document_copy]').check()
            page.locator('#library-editor [type=submit]').click();confirm()
            document=next(i for i in case.api('/api/custom-library')['items'] if i['kind']=='documents')
            page.locator(f'[data-lib-assign="{document["id"]}"]').click()
            page.locator('#library-binding [name=target_type]').select_option('device')
            page.locator('#library-binding [name=target_id]').select_option(eid)
            page.locator('#library-binding [type=submit]').click();confirm()
            projected=agent.call('/api/agent/custom-settings',{'protocol':2})
            assert projected['documents']['rules'][0]['copy'] is True
            assert projected['body']['network']['ipv6']=='prefer_ipv4' and projected['body']['schedules']
            page.locator(f'[data-lib-edit="{document["id"]}"]').click()
            expect(page.locator('[name=document_path]')).to_have_value(r'C:\Company\Documents')
            page.screenshot(path=str(root/f'evidence/document-settings-{__version__}.png'),full_page=True)
            page.locator('#library-editor-close').click()
            document_binding=next(b for b in case.api('/api/custom-library')['bindings'] if b['item_id']==document['id'])
            request={'op':'remove_binding','id':document_binding['id'],'revision':document_binding['revision']}
            preview=case.api('/api/custom-library/preview',request)
            case.api('/api/custom-library/publish',{**request,'expected_generation':preview['generation'],'expected_scope_generation':preview['scope_generation'],'confirm':'publish_custom_library'})
            # History restore remains a draft and no-op previews don't publish.
            page.locator('[data-lib-tab=library]').click();page.locator(f'[data-lib-history="{reminder["id"]}"]').click();page.locator('[data-library-version]').first.click();expect(page.locator('#library-editor')).to_be_visible();page.screenshot(path=str(root/f'evidence/custom-library-repeat-{__version__}.png'),full_page=True);page.locator('#library-editor-close').click()
            # Dirty draft stays bound to its original version across refresh.
            page.locator(f'[data-lib-edit="{reminder["id"]}"]').click();page.locator('[name=item_name]').fill('Unsaved draft')
            changed={k:reminder[k] for k in ('id','name','kind','body','description','enabled','revision')};changed['name']='一般同仁：下班反覆提醒（新版）'
            preview=case.api('/api/custom-library/preview',{'op':'save_item','item':changed});case.api('/api/custom-library/publish',{'op':'save_item','item':changed,'expected_generation':preview['generation'],'expected_scope_generation':preview['scope_generation'],'confirm':'publish_custom_library'})
            page.evaluate('refresh()');page.wait_for_timeout(200);expect(page.locator('[name=item_name]')).to_have_value('Unsaved draft');page.locator('#library-editor [type=submit]').click();expect(page.locator('#toast')).to_contain_text('項目已更新');page.locator('#library-editor-close').click()
            # Plain text rendering of admin item labels, including HTML chars.
            new('network','<img src=x onerror=alert(1)>');page.locator('#library-editor [type=submit]').click();confirm();assert page.locator('#library-list img').count()==0
            unsafe=next(i for i in case.api('/api/custom-library')['items'] if i['name'].startswith('<img'))
            page.locator(f'[data-lib-archive="{unsafe["id"]}"]').click();confirm()
            page.screenshot(path=str(root/f'evidence/custom-library-desktop-{__version__}.png'),full_page=True)
            page.locator('[data-lib-tab=assign]').click();page.screenshot(path=str(root/f'evidence/custom-library-assign-{__version__}.png'),full_page=True)
            page.locator('[data-lib-tab=status]').click();expect(page.locator('#workspace')).to_contain_text('等待 0.4.39 元件回報')
            # Component-only changes must repaint, independent of policy state.
            packet=agent.call('/api/agent/custom-settings',{'protocol':2});agent.call('/api/agent/custom-status',{'protocol':2,'role':'native','version':__version__,'fingerprint':packet['fingerprint'],'report':{'state':'reported','schedule':{'state':'deferred','next_prompt':time.time()+3600}}});page.evaluate('refresh({automatic:true})');expect(page.locator('#workspace')).to_contain_text('使用者已延後')
            page.set_viewport_size({'width':390,'height':844});assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1');page.screenshot(path=str(root/f'evidence/custom-library-mobile-{__version__}.png'),full_page=True)
            page.set_viewport_size({'width':1600,'height':1100});page.locator('nav [data-page=mail]').click();page.locator('#mail-config').wait_for();page.locator('nav [data-page=reports]').click();expect(page.locator('#workspace')).to_contain_text('稽核總表')
            page.locator('#logout').click();page.locator('[name=username]').fill('reader');page.locator('[name=password]').fill(case.password);page.locator('#login-form button').click();page.locator('nav [data-page=custom]').click();expect(page.locator('#workspace')).to_contain_text('可重複使用的設定項目');assert page.locator('#library-new').count()==0
            browser.close()
        assert not errors,errors
        result={'passed':True,'version':__version__,'frozen_server_used':frozen,'live_endpoint_actions':False,'page_errors':errors,'checks':['document scope editor and endpoint assignment without legacy changes','single-category editors','named reusable items','group assignment','device inheritance sources','per-item exclude and restore','repeat interval and cross-midnight cutoff','history restore draft','stale revision after refresh','XSS escaped names','component-only automatic repaint','390px no overflow','legacy mail and summary navigation','auditor read-only']}
        if frozen:result['exe_sha256']=hashlib.sha256((root/'dist/GuardDesk/GuardDesk.exe').read_bytes()).hexdigest()
        (root/f'evidence/custom-library-browser-{__version__}{"" if frozen else "-source"}.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps(result,ensure_ascii=False))
    finally:
        if process:process.terminate();process.wait(20)
        case.tearDown()


if __name__=='__main__':main()
