"""Actual MIS UI on owned database/profile; chart drilldown and backup download."""
import datetime as dt
import json
import secrets
import sys
import tempfile
import threading
import time
import zipfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from guarddesk.server import serve
from guarddesk.store import Store,digest
from guarddesk.audit_reports import TAIPEI,day_bounds
from guarddesk.audit_archive import verify_directory
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime') as tmp:
        root=Path(tmp);store=Store(root/'control.db');password=secrets.token_urlsafe(20);store.add_user('fixture-mis',password);store.add_user('fixture-reader',password,'auditor')
        day=dt.datetime.now(TAIPEI).date();base=day_bounds(day)[0]
        with store.connect() as db:
            for did,name in [('owned-dev','DEV-01'),('owned-user1','user1'),('other-user1','user1')]:
                db.execute('INSERT INTO devices(id,token,name,department,last_seen) VALUES (?,?,?,?,?)',(did,digest(did),name,'Fixture',time.time()))
            for i in range(105):
                user=r'ACME\Alice' if i<45 or i>=90 else r'ACME\Bob' if i<75 else ''
                kind='file.modified' if i<45 else 'file.deleted' if i<75 else 'file.created' if i<90 else 'file.opened' if i<100 else 'file.open_requested'
                did='owned-dev' if i<45 or i>=90 else 'owned-user1' if i<75 else 'other-user1'
                Store.event(db,did,kind,'info',{'user':None if did=='owned-dev' else user,'path':r'C:\Owned\report-'+str(i)+'.docx','source':'owned_browser_fixture'},occurred=base+3600+i)
        server=serve(store.path,port=0);threading.Thread(target=server.serve_forever,daemon=True).start();url=f'http://127.0.0.1:{server.server_port}'
        report={'passed':False,'checks':[],'limitations':['Synthetic local data, not office Server/NAS or employee records','No originals deleted or protected endpoint changes']};errors=[]
        try:
            with sync_playwright() as p:
                browser=p.chromium.launch(channel='chromium',headless=True)
                try:
                    page=browser.new_page(viewport={'width':1700,'height':1100},locale='zh-TW');page.on('pageerror',lambda e:errors.append(str(e)))
                    def login(username):
                        page.goto(url);page.locator('[name=username]').fill(username);page.locator('[name=password]').fill(password);page.locator('#login-form button').click();page.locator('#shell').wait_for(state='visible')
                    def wait_js(expression):
                        until=time.monotonic()+20
                        while time.monotonic()<until:
                            if page.evaluate(expression):return
                            time.sleep(.05)
                        raise AssertionError('UI state timed out: '+expression)
                    login('fixture-mis');page.locator('nav [data-page=reports]').click();page.locator('#report-form').wait_for()
                    wait_js('()=>reportData?.caught_up===true');assert page.evaluate('reportData.total')==90
                    assert page.evaluate('reportData.device_total')==3 and page.evaluate('reportData.group_by')=='device'
                    assert page.evaluate('reportData.items.map(r=>r.label)')==['DEV-01','user1','user1']
                    assert '未識別帳號' not in page.locator('#workspace').inner_text()
                    page.screenshot(path=str(ROOT/'evidence/audit-summary-bar-0.4.25.png'),full_page=True)
                    alice=page.evaluate("reportData.items.findIndex(p=>p.device_id==='owned-dev')")
                    assert alice==0
                    page.locator(f'svg g[data-report-person="{alice}"]').first.click();page.locator('#search-form').wait_for()
                    assert page.evaluate('events.total')==45
                    assert page.evaluate("events.items.every(e=>e.device_id==='owned-dev'&&e.kind==='file.modified'&&e.details.user===null)")
                    assert page.evaluate("auditPerson===null&&auditReportDevice==='owned-dev'")
                    assert page.evaluate('auditEndExclusive') is True
                    page.locator('[data-action=event]').first.click();page.locator('#dialog').wait_for(state='visible');assert 'C:\\Owned\\report-' in page.locator('#dialog').inner_text()
                    page.locator('#close-dialog').click();page.locator('[data-report-return]').click();page.locator('#report-form').wait_for();page.locator('[data-report-chart=pie]').click()
                    assert page.locator('.report-pie svg g[data-report-person]').count()==3
                    page.screenshot(path=str(ROOT/'evidence/audit-summary-pie-0.4.25.png'),full_page=True)
                    report['checks'].append('Computer-name bar/pie render including actor-less records; same names remain separate, exact endpoint/date/action drilldown and full paths')
                    page.locator('#report-form [name=action]').select_option('opened');page.locator('#report-form button[type=submit],#report-form button.primary').first.click();wait_js("()=>reportData.action==='opened'&&reportData.total===10")
                    report['checks'].append('Read operations excluded by default and selectable independently')
                    page.locator('nav [data-page=archives]').click();page.locator('#archive-form').wait_for()
                    page.locator('#archive-form button.primary').click();wait_js('()=>archiveData.jobs.length>0')
                    until=time.monotonic()+20
                    while time.monotonic()<until:
                        data=page.evaluate("async()=>await api('/api/audit/exports')");job=data['jobs'][0]
                        if job['state']=='completed':break
                        if job['state'] in ('failed','interrupted'):raise AssertionError(job)
                        time.sleep(.1)
                    else:raise AssertionError('Backup did not finish')
                    page.evaluate('async()=>await refresh()');page.locator('a[href*="/api/audit/exports/download"]').wait_for()
                    with page.expect_download() as download:page.locator('a[href*="/api/audit/exports/download"]').first.click()
                    path=root/'download.zip';download.value.save_as(path)
                    with zipfile.ZipFile(path) as archive:
                        assert archive.testzip() is None
                        names=archive.namelist();prefix=day.strftime('%Y%m/%Y%m%d/')
                        assert any(n.startswith(prefix) and n.endswith('.jsonl.gz') for n in names)
                        assert any(n.startswith(prefix) and n.endswith('.csv') for n in names)
                        assert 'manifest.json' in names
                    assert verify_directory(job['folder'])['valid'];assert store.verify()['valid']
                    page.screenshot(path=str(ROOT/'evidence/audit-export-0.4.25.png'),full_page=True)
                    report['checks'].append('Background export completes and validates before ZIP download; date folders/CSV/JSONL/manifests and original chain preserved')
                    page.locator('#logout').click();login('fixture-reader');assert page.locator('nav [data-page=archives]').is_hidden();wait_js("()=>document.querySelector('#workspace h1')?.textContent==='安全總覽'");assert page.locator('#archive-form').count()==0
                    page.locator('nav [data-page=reports]').click();page.locator('#report-form').wait_for()
                    report['checks'].append('Auditor may view summary; backup management hidden and API protected for MIS admin')
                    assert not errors,errors
                    report.update(passed=True,browser_errors=errors,export_rows=job['rows'],zip_sha256=job['zip_sha256'])
                finally:browser.close()
        finally:server.shutdown();server.server_close()
        (ROOT/'evidence/audit-reports-browser-0.4.25.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report,indent=2))


if __name__=='__main__':main()
