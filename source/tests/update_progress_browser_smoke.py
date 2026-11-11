"""Owned browser/HTTP fixtures; uploaded payloads are never executed."""
import hashlib,json,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import test_updates as fixtures
from guarddesk import __version__
from playwright.sync_api import sync_playwright,expect


def main():
    case=fixtures.UpdateServerTest('runTest');case.setUp();process=None;errors=[];frozen='--frozen' in sys.argv
    try:
        release=case.upload(fixtures.release(case.root/'progress.zip',version=__version__))
        agent,did,_=case.make_agent();_,never,_=case.make_agent();_,current,_=case.make_agent();now=time.time()
        group=case.api('/api/groups',{'name':'部署測試群組','parent_id':None});child=case.api('/api/groups',{'name':'MIS','parent_id':group['id']})
        case.api('/api/devices/move',{'device_id':did,'group_id':child['id'],'revision':1})
        with case.store.connect() as db:
            db.execute('UPDATE devices SET inventory=? WHERE id=?',(json.dumps({'agent_version':__version__,'user_accounts':['EXAMPLE\\progress-user']}),did))
            for role in ('main','native'):db.execute('INSERT INTO update_presence VALUES(?,?,?,?,?)',(current,role,'0.4.99',now,''))
            for i in range(123):
                jid=f'{i+1:032x}';status='completed' if i==121 else 'pending'
                db.execute('INSERT INTO update_jobs VALUES(?,?,?,?,?,?,?,?,?)',(jid,did,release['id'],'admin',now+i*.001,now-1,now+7200,0,status))
                for role in ('native','main'):
                    state='healthy' if status=='completed' else 'downloading' if i==122 and role=='native' else 'queued'
                    db.execute('INSERT INTO update_status VALUES(?,?,?,?,?,?)',(jid,role,state,__version__ if state=='healthy' else '', '',now if state!='queued' else 0))
        if frozen:
            case.server.shutdown();case.server.server_close();case.thread.join(5)
            process=subprocess.Popen([str(ROOT/'dist/GuardDesk/GuardDesk.exe'),'serve','--db',str(case.db),'--port',case.url.rsplit(':',1)[1]],cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
            for _ in range(100):
                try:
                    if case.api('/api/health')['version']==__version__:break
                except (OSError,ConnectionError):pass
                time.sleep(.1)
            else:raise AssertionError('Frozen test Server did not start')
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True)
            try:
                page=browser.new_page(viewport={'width':1700,'height':1100},locale='zh-TW');page.on('pageerror',lambda e:errors.append(str(e)))
                def wait():
                    deadline=time.monotonic()+20
                    while time.monotonic()<deadline:
                        if page.evaluate('()=>!busy'):return
                        page.wait_for_timeout(30)
                    raise AssertionError('Update progress UI remained busy')
                def search(state,query='',release_id=None,group_id=''):
                    form=page.locator('#update-progress-filter');form.locator('[name=state]').select_option(state);form.locator('[name=q]').fill(query)
                    form.locator('[name=group]').select_option(group_id)
                    if release_id is not None:form.locator('[name=release]').select_option(release_id)
                    form.locator('button[type=submit]').click();wait()
                page.goto(case.url);page.locator('#login-form [name=username]').fill('admin');page.locator('#login-form [name=password]').fill(case.password);page.locator('#login-form button').click();wait()
                page.locator('nav [data-page=updates]').click();wait()
                expect(page.locator('#update-progress-table tbody tr')).to_have_count(50)
                expect(page.locator('#update-page-summary')).to_contain_text('共 123 筆')
                before=set(page.locator('[data-update-job]').evaluate_all('(rows)=>rows.map(r=>r.dataset.updateJob)'))
                job=page.locator('#update-job');job.locator('[name=target]').select_option('device:'+did);job.locator('[name=not_before]').fill('2026-10-23T08:00')
                page.locator('#advanced-release-import summary').click();page.locator('#update-import [name=release]').set_input_files(str(case.root/'progress.zip'));page.locator('#update-import [name=authorize]').check()
                page.get_by_role('button',name='下一頁',exact=True).first.click();wait()
                expect(page.locator('#update-page-summary')).to_contain_text('第 2／3 頁')
                after=set(page.locator('[data-update-job]').evaluate_all('(rows)=>rows.map(r=>r.dataset.updateJob)'));assert not before&after
                assert job.locator('[name=target]').input_value()=='device:'+did
                assert job.locator('[name=not_before]').input_value()=='2026-10-23T08:00'
                assert page.locator('#update-import [name=release]').evaluate('(f)=>f.files[0]?.name')=='progress.zip'
                expect(page.locator('#update-import [name=authorize]')).to_be_checked()
                assert page.locator('#advanced-release-import').evaluate('(e)=>e.open')
                page.locator('#advanced-release-import summary').click()
                search('waiting',r'EXAMPLE\progress-user',release['id'],group['id'])
                expect(page.locator('#update-page-summary')).to_contain_text('共 121 筆')
                expect(page.locator('#update-cancel-waiting')).to_contain_text('121')
                page.locator('#update-progress-filter').evaluate('(f)=>f.closest(".card").scrollIntoView({block:"start"})')
                page.screenshot(path=str(ROOT/f'evidence/update-progress-desktop-{__version__}.png'))
                page.locator('#update-cancel-waiting').click();expect(page.locator('#update-cancel-waiting-confirm')).to_contain_text('121')
                claimed=agent.call('/api/agent/updates/poll',{'role':'native','version':'0.4.49'})['job']['payload']['id']
                with case.store.connect() as db:
                    db.execute('INSERT INTO update_jobs VALUES(?,?,?,?,?,?,?,?,?)',('f'*32,did,release['id'],'admin',now+10,now-1,now+7200,0,'pending'))
                    for role in ('native','main'):db.execute('INSERT INTO update_status VALUES(?,?,?,?,?,?)',('f'*32,role,'queued','','',0))
                with page.expect_response('**/api/updates/cancel-waiting') as response:page.locator('#update-cancel-waiting-confirm').click()
                result=response.value.json();assert result['cancelled']==120 and result['skipped']==1,result
                wait();expect(page.locator('#update-page-summary')).to_contain_text('共 1 筆')
                assert page.locator('[data-update-job]').get_attribute('data-update-job')=='f'*32
                search('running');expect(page.locator('#update-progress-table tbody tr')).to_have_count(2)
                assert claimed in page.locator('[data-update-job]').evaluate_all('(rows)=>rows.map(r=>r.dataset.updateJob)')
                search('not_updated',release_id=release['id'])
                ids=set(page.locator('[data-update-device]').evaluate_all('(rows)=>rows.map(r=>r.dataset.updateDevice)'));assert ids=={did,never},ids
                expect(page.locator('[data-update-device="'+never+'"]')).to_contain_text('尚未派送')
                expect(page.locator('[data-update-device="'+never+'"]')).to_contain_text('版本未知')
                search('waiting');page.locator('#update-progress-filter [name=q]').fill('尚未送出的搜尋草稿')
                expect(page.locator('#update-cancel-waiting')).to_be_disabled()
                page.locator('#update-progress-filter [name=q]').blur();page.evaluate('()=>refresh({automatic:true})');wait()
                assert page.locator('#update-progress-filter [name=q]').input_value()=='尚未送出的搜尋草稿'
                expect(page.locator('#update-cancel-waiting')).to_be_disabled()
                page.locator('#update-filter-clear').click();wait()
                expect(page.locator('#update-page-summary')).to_contain_text('共 124 筆')
                assert job.locator('[name=target]').input_value()=='device:'+did
                page.set_viewport_size({'width':900,'height':1000});page.locator('#update-progress-filter').evaluate('(f)=>f.closest(".card").scrollIntoView({block:"start"})');page.screenshot(path=str(ROOT/f'evidence/update-progress-narrow-{__version__}.png'))
                assert not errors,errors
            finally:browser.close()
        result={'passed':True,'version':__version__,'frozen_server_used':frozen,'page_errors':errors,'checks':['50-row global paging/count/stable non-overlap','computer/domain-account/group/version/status filters','not-updated includes never-sent and unknown; numeric newer versions excluded','cross-page preview frozen IDs; newly claimed download skipped; newer job preserved','job/date drafts survive paging/filtering; unsent filter draft preserved and bulk disabled','narrow layout and explicit candidate cancellation scope'],'fixture_jobs':124,'bulk_cancelled':120,'concurrent_claim_skipped':1,'office_changed':False,'uploaded_payload_executed':False}
        if frozen:result['exe_sha256']=hashlib.sha256((ROOT/'dist/GuardDesk/GuardDesk.exe').read_bytes()).hexdigest()
        (ROOT/f'evidence/update-progress-browser-{__version__}.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result))
    finally:
        if process:process.terminate();process.wait(10)
        case.tearDown()


if __name__=='__main__':main()
