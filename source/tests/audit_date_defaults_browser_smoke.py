"""Chromium acceptance: Taipei day boundaries, 50-row pages and drilldown."""
import datetime as dt
import json
from pathlib import Path
import secrets
import sys
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from guarddesk import __version__
from guarddesk.audit_reports import TAIPEI,day_bounds,index_batch
from guarddesk.server import serve
from guarddesk.store import Store
from playwright.sync_api import sync_playwright,expect


def main():
    errors=[];checks=[]
    day=dt.datetime.now(TAIPEI).date();start,end=day_bounds(day)
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime',prefix='audit-date-') as tmp:
        store=Store(Path(tmp)/'control.sqlite3');password=secrets.token_urlsafe(24);store.add_user('owned-mis',password)
        with store.connect() as db:
            for i in range(51):
                device=f'owned-{i:02d}'
                db.execute('INSERT INTO devices(id,token,name,department,last_seen) VALUES (?,?,?,?,?)',(device,secrets.token_hex(20),device,'Owned fixture',time.time()))
                for n in range(51 if i==0 else 1):
                    occurred=start if n==0 else end-.001 if n==50 else start+3600+n
                    Store.event(db,device,'file.deleted','info',{'path':f'C:\\Owned\\{i}-{n}.txt'},occurred=occurred)
            Store.event(db,'owned-00','file.deleted','info',{'path':r'C:\Owned\yesterday.txt'},occurred=start-.001)
            Store.event(db,'owned-00','file.deleted','info',{'path':r'C:\Owned\tomorrow.txt'},occurred=end)
        while index_batch(store):pass
        server=serve(store.path,port=0);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with sync_playwright() as p:
                browser=p.chromium.launch(executable_path=r'C:\Program Files\Google\Chrome\Application\chrome.exe',headless=True)
                try:
                    page=browser.new_page(viewport={'width':1700,'height':1100},timezone_id='America/Los_Angeles')
                    page.on('pageerror',lambda e:errors.append(str(e)))
                    def wait(expression):
                        deadline=time.monotonic()+20
                        while time.monotonic()<deadline:
                            if page.evaluate('() => ('+expression+')'):return
                            time.sleep(.05)
                        raise AssertionError('UI condition timed out: '+expression)
                    page.goto(f'http://127.0.0.1:{server.server_port}')
                    page.locator('[name=username]').fill('owned-mis');page.locator('[name=password]').fill(password);page.locator('#login-form button').click()
                    expect(page.locator('.stats')).to_be_visible()
                    page.locator('nav [data-page=audit]').click();page.locator('[data-audit-category=documents]').click()
                    wait('events.items.length===50 && !busy')
                    assert page.locator('#search-form [name=start]').input_value()==day.isoformat()+'T00:00'
                    assert page.locator('#search-form [name=end]').input_value()==(day+dt.timedelta(days=1)).isoformat()+'T00:00'
                    query=page.evaluate('Object.fromEntries(new URLSearchParams(auditQuery()))')
                    assert float(query['start'])==start and float(query['end'])==end and query['end_exclusive']=='1' and query['limit']=='50'
                    all_rows=[]
                    for size in [50,50,1]:
                        wait(f'events.items.length==={size} && !busy')
                        all_rows+=page.evaluate('events.items.map(e=>({id:e.id,occurred:e.occurred}))')
                        if size!=1:page.locator('[data-action=next]').click()
                    assert len({r['id'] for r in all_rows})==101 and all(start<=r['occurred']<end for r in all_rows)
                    assert any(r['occurred']==start for r in all_rows) and any(r['occurred']==end-.001 for r in all_rows)
                    expect(page.locator('[data-action=next]')).to_be_disabled()
                    page.locator('[data-action=prev]').click();wait('events.items.length===50 && !busy')
                    checks.append('Audit defaults to Taipei [00:00,next 00:00), even in a non-Taipei browser; exact 50/50/1 unique cursor pages and both midnight boundaries')
                    page.locator('[data-audit-all-dates]').click();wait("auditDateMode==='all' && !busy")
                    assert 'start' not in page.evaluate('Object.fromEntries(new URLSearchParams(auditQuery()))')
                    page.locator('[data-audit-today]').click();wait("auditDateMode==='today' && !busy")
                    expect(page.locator('[data-action=prev]')).to_be_disabled()
                    page.screenshot(path=str(ROOT/f'evidence/audit-today-{__version__}.png'))
                    page.locator('#search-form [name=start]').fill((day-dt.timedelta(days=1)).isoformat()+'T00:00')
                    page.locator('#search-form button').first.click();wait("auditDateMode==='custom' && !busy")
                    assert float(page.evaluate("new URLSearchParams(auditQuery()).get('start')"))==start-86400
                    assert page.evaluate("new URLSearchParams(auditQuery()).get('end_exclusive')")=='1'
                    checks.append('Explicit all-date/custom searches remain available; Today resets page/cursor and includes the complete final minute')
                    page.locator('nav [data-page=reports]').click();wait('reportData?.caught_up && !busy')
                    assert page.locator('#report-form [name=start]').input_value()==day.isoformat()
                    assert page.locator('#report-form [name=end]').input_value()==day.isoformat()
                    assert page.evaluate('reportData.total')==101
                    expect(page.locator('#workspace table tbody tr')).to_have_count(50)
                    expect(page.locator('.report-bars [data-report-person]')).to_have_count(50)
                    page.locator('[data-report-next]').click();expect(page.locator('#workspace table tbody tr')).to_have_count(1)
                    page.locator('[data-report-chart=pie]').click();expect(page.locator('.report-pie g[data-report-person]')).to_have_count(51)
                    page.locator('[data-report-prev]').click();page.locator('table [data-report-person="0"]').last.click()
                    wait("page==='audit' && events.items.length===50 && !busy")
                    first=page.evaluate('events.items.map(e=>e.id)');page.locator('[data-action=next]').click();wait('events.items.length===1 && !busy')
                    assert page.evaluate('events.items[0].id') not in first
                    assert page.evaluate('auditEndExclusive') and page.evaluate('auditDateMode')=='custom'
                    page.locator('[data-report-return]').click();wait("page==='reports' && !busy")
                    page.locator('[data-report-week]').click();wait("reportDateMode==='custom' && !busy")
                    assert page.evaluate('reportSettings.start')==(day-dt.timedelta(days=6)).isoformat()
                    page.locator('[data-report-today]').click();wait("reportDateMode==='today' && !busy")
                    checks.append('Summary defaults to today, pages rankings/bar 50/1 while total/pie cover all 51 devices; drilldown pages 50/1 and custom report dates remain available')
                    result=page.evaluate("""() => {
                      const now=Date.now,custom=auditStart;
                      try {Date.now=()=>now()+86400000;applyDefaultQueryDates();
                        const customKept=auditStart===custom,reportRolled=reportSettings.start===todayTaipei();
                        auditDateMode='today';applyDefaultQueryDates();
                        return {customKept,reportRolled,auditRolled:auditStart===todayTaipei()+'T00:00'};
                      } finally {Date.now=now;applyDefaultQueryDates();}
                    }""")
                    assert all(result.values()),result
                    page.screenshot(path=str(ROOT/f'evidence/audit-date-defaults-{__version__}.png'),full_page=True)
                    checks.append('Default Today ranges advance across Taipei midnight; manually selected history and report drilldown dates are preserved')
                    page.locator('nav [data-page=audit]').click();wait("page==='audit' && !busy")
                    page.locator('[data-audit-all-dates]').click();wait("auditDateMode==='all' && !busy")
                    page.locator('#logout').click();expect(page.locator('#login')).to_be_visible()
                    page.locator('[name=username]').fill('owned-mis');page.locator('[name=password]').fill(password);page.locator('#login-form button').click()
                    expect(page.locator('#shell')).to_be_visible();wait('!busy')
                    assert page.evaluate('auditDateMode')=='today' and page.evaluate('auditStart')==day.isoformat()+'T00:00'
                    assert page.evaluate('reportSettings.start')==page.evaluate('reportSettings.end')==day.isoformat()
                    checks.append('A fresh login resets an explicit all-date query to the current Taipei day')
                    assert not errors,errors
                finally:browser.close()
        finally:server.shutdown();server.server_close();thread.join(5)
    report={'passed':True,'version':__version__,'checks':checks,'page_errors':errors,'limits':['Synthetic owned fixture on this Windows 11 workstation; not office Server or physical fleet acceptance']}
    (ROOT/f'evidence/audit-date-defaults-{__version__}.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False))


if __name__=='__main__':main()
