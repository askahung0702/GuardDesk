"""Frozen Server + Chromium: defaults, old-center merge and editable removal."""
import copy
from contextlib import closing
import json
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk import __version__
from guarddesk.policy import DEFAULT_POLICY
from guarddesk.policy_defaults import ROAMING,APPLICATIONS,MARKER
from guarddesk.store import Store,canonical
from playwright.sync_api import sync_playwright,expect


def main():
    exe=ROOT/'dist/GuardDesk/GuardDesk.exe';errors=[]
    with tempfile.TemporaryDirectory(prefix='default-audit-',dir=ROOT/'runtime') as tmp:
        path=Path(tmp)/'control.sqlite3';store=Store(path);password=secrets.token_urlsafe(24)
        store.add_user('owned-mis',password)
        with store.connect() as db:
            initial=Store.policy(db)['body']
            assert initial['file_audit']['exclude_paths']==[ROAMING]
            assert initial['application_audit_exclusions']==list(APPLICATIONS)
            legacy=copy.deepcopy(DEFAULT_POLICY);legacy['file_audit']['exclude_paths']=[r'D:\Owned']
            legacy['application_audit_exclusions']=['custom.exe']
            db.execute('UPDATE policies SET body=? WHERE version=1',(canonical(legacy),))
            db.execute('DELETE FROM control_meta WHERE key=?',(MARKER,))
        def start():
            with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
            process=subprocess.Popen([str(exe),'serve','--db',str(path),'--host','127.0.0.1','--port',str(port)],
                                     cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                                     creationflags=subprocess.CREATE_NO_WINDOW)
            try:
                for _ in range(100):
                    try:
                        with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health',timeout=.3) as r:
                            assert json.load(r)['version']==__version__
                        return process,f'http://127.0.0.1:{port}'
                    except OSError:
                        if process.poll() is not None:raise AssertionError('Owned Server exited')
                        time.sleep(.05)
                raise AssertionError('Owned Server startup timeout')
            except BaseException:process.terminate();process.wait(10);raise
        process,url=start()
        try:
            with sync_playwright() as p:
                browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True)
                try:
                    page=browser.new_page(viewport={'width':1500,'height':1050},locale='zh-TW')
                    page.on('pageerror',lambda e:errors.append(str(e)))
                    page.goto(url);page.locator('[name=username]').fill('owned-mis');page.locator('[name=password]').fill(password);page.locator('#login-form button').click()
                    page.locator('nav [data-page=policy]').click()
                    form=page.locator('#policy-form');files=form.locator('[name=file_excludes]');apps=form.locator('[name=application_audit_exclusions]')
                    expect(files).to_have_value('D:\\Owned\n'+ROAMING)
                    expected='custom.exe\n'+'\n'.join(APPLICATIONS)
                    expect(apps).to_have_value(expected)
                    for _ in range(2):form.locator('[data-app-exclusion-preset]').click()
                    expect(apps).to_have_value(expected)
                    apps.scroll_into_view_if_needed();page.screenshot(path=str(ROOT/f'evidence/default-audit-exclusions-{__version__}.png'),full_page=False)
                    page.locator('[data-action=policy-tab][data-tab=sets]').click();page.locator('[data-action=set-new]').click()
                    editor=page.locator('#set-form');editor.locator('[name=module_apps]').check()
                    expect(editor.locator('[name=application_audit_exclusions]')).to_have_value(expected)
                    page.locator('[data-action=policy-tab][data-tab=baseline]').click()
                    files.fill('');apps.fill('');form.locator('button[type=submit]').click()
                    with page.expect_response(lambda r:r.url.endswith('/api/policy') and r.request.method=='POST') as response:
                        page.locator('[data-improve-baseline-publish]').click()
                    assert response.value.ok,response.value.text()
                    body=response.value.json()['body']
                    assert body['file_audit']['exclude_paths']==[] and body['application_audit_exclusions']==[]
                    assert not errors,errors
                finally:browser.close()
        finally:process.terminate();process.wait(10)
        process,_=start()
        try:
            with closing(sqlite3.connect(path)) as db:
                current=json.loads(db.execute('SELECT body FROM policies ORDER BY version DESC LIMIT 1').fetchone()[0])
                assert current['file_audit']['exclude_paths']==[] and current['application_audit_exclusions']==[]
                assert json.loads(db.execute('SELECT body FROM policies WHERE version=1').fetchone()[0])==legacy
                assert db.execute('SELECT count(*) FROM policies').fetchone()[0]==3
        finally:process.terminate();process.wait(10)
    report={'passed':True,'version':__version__,'frozen_server_used':True,
            'checks':['Fresh center explicit defaults','Existing center merges with custom rules once, preserves original policy','Real baseline and new named-set editor show merged defaults','Preset never duplicates or clears custom items','MIS can publish empty lists through existing preview/CSRF flow','Frozen Server restart preserves explicit removal'],
            'page_errors':errors,'office_systems_modified':False,'limitations':['Owned localhost DB and browser, not office rollout or Defender acceptance']}
    (ROOT/f'evidence/default-audit-exclusions-{__version__}.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report))


if __name__=='__main__':main()
