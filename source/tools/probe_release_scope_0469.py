"""Actual frozen Server and browser; synthetic endpoints, no company policies."""
import hashlib,json,secrets,socket,subprocess,sys,tempfile,time,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from guarddesk.store import Store,canonical,digest
from guarddesk.server_setup import secure_directory
from guarddesk import update_packages as packages
from playwright.sync_api import sync_playwright,expect


def main():
    exe=ROOT/'dist/GuardDesk/GuardDesk.exe';target=ROOT/'evidence/release-scope-browser-0.4.69.json';assert not target.exists()
    report={'passed':False,'version':'0.4.69','exe_sha256':packages.file_hash(exe),'company_changed':False,'page_errors':[]}
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime',prefix='scope-owned-') as tmp:
        root=Path(tmp);secure_directory(root,allow_empty=True);store=Store(root/'control.sqlite3')
        password=secrets.token_urlsafe(24);store.add_user('owned-scope',password)
        private=packages.signer(root)
        installed=secure_directory(root/'owned-private-program')/'GuardDesk'
        __import__('shutil').copytree(exe.parent,installed);exe=installed/'GuardDesk.exe'
        with store.connect() as db:
            for i in range(2):db.execute('INSERT INTO devices(id,token,name,department,last_seen) VALUES (?,?,?,?,?)',(str(i)*24,digest('owned-only-'+str(i)),f'Owned-{i}','Owned lab',time.time()))
            # Simulate a preexisting 68 repository row without altering its history.
            manifest={'format':1,'version':'0.4.68','architecture':'windows-x64','sha256':'f'*64,'bytes':1,'files':{'GuardDesk.exe':'0'*64,'GuardDeskAgent.exe':'0'*64,'_internal/fixture':'0'*64}}
            db.execute('INSERT INTO update_releases VALUES (?,?,?,?,?)',('f'*64,'0.4.68',canonical(packages.sign(private,manifest)),time.time(),'legacy-fixture'))
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        url=f'http://127.0.0.1:{port}'
        with (root/'server.log').open('w') as log:
            server=subprocess.Popen([str(exe),'serve','--db',str(store.path),'--host','127.0.0.1','--port',str(port)],stdout=log,stderr=log,creationflags=subprocess.CREATE_NO_WINDOW)
            try:
                with sync_playwright() as p:
                    browser=p.chromium.launch(channel='chromium',headless=True)
                    try:
                        page=browser.new_page(viewport={'width':1640,'height':1080},locale='zh-TW');page.on('pageerror',lambda e:report['page_errors'].append(str(e)))
                        for _ in range(150):
                            try:
                                page.goto(url,timeout=2000);break
                            except Exception:
                                if server.poll() is not None:raise
                                time.sleep(.1)
                        page.locator('[name=username]').fill('owned-scope');page.locator('[name=password]').fill(password);page.locator('#login-form button').click()
                        page.get_by_role('heading',name='安全總覽',exact=True).wait_for();page.locator('nav [data-page=updates]').click()
                        expect(page.locator('[data-release-scope=endpoint]')).to_contain_text('管理中心 v0.4.69')
                        expect(page.locator('#bundled-release-state')).to_have_attribute('data-status','ready',timeout=60000)
                        expect(page.locator('#update-job [name=release_id] option')).to_have_count(2)
                        self_options=page.locator('#update-job [name=release_id]').inner_text();assert '0.4.68' not in self_options
                        expect(page.locator('#update-progress-filter [name=release]')).to_contain_text('0.4.68')
                        form=page.locator('#update-job');form.locator('[name=target]').select_option('device:'+'0'*24)
                        with page.expect_response(lambda r:r.url.endswith('/api/updates/jobs')) as pending:form.locator('button[type=submit]').click()
                        assert pending.value.status==409
                        form.locator('summary').click();form.locator('[name=legacy_preflight_confirmed]').check()
                        form.locator('[name=target]').select_option('all')
                        with page.expect_response(lambda r:r.url.endswith('/api/updates/jobs')) as pending:form.locator('button[type=submit]').click()
                        assert pending.value.status==409
                        form.locator('[name=target]').select_option('device:'+'0'*24)
                        with page.expect_response(lambda r:r.url.endswith('/api/updates/jobs')) as pending:form.locator('button[type=submit]').click()
                        assert pending.value.status==200
                        expect(page.locator('#update-progress-table tbody tr')).to_have_count(1)
                        image=ROOT/'evidence/release-scope-browser-0.4.69.png';page.screenshot(path=str(image),full_page=True)
                        assert not report['page_errors']
                        report.update(passed=True,server_version_separate=True,known68_target_excluded=True,history68_preserved=True,
                            old_updater_default_rejected=True,batch_attestation_rejected=True,explicit_single_pilot_created=True,
                            screenshot=image.relative_to(ROOT).as_posix(),scope='Actual frozen Server, own browser profile and dummy devices; no endpoint update executed')
                    finally:browser.close()
            finally:
                if server.poll() is None:server.terminate();server.wait(timeout=10)
    target.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(report,ensure_ascii=False))


if __name__=='__main__':main()
