"""Frozen Server + frozen archive verifier using owned local fixtures."""
import datetime as dt
import hashlib
import http.cookiejar
import json
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from guarddesk import __version__
from guarddesk.store import Store,canonical
from guarddesk.audit_reports import day_bounds
ROOT=Path(__file__).resolve().parents[1]


def main():
    exe=ROOT/'dist/GuardDesk/GuardDesk.exe'
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime') as tmp:
        root=Path(tmp);store=Store(root/'control.db');password=secrets.token_urlsafe(20);store.add_user('frozen-mis',password)
        base=day_bounds(dt.date(2026,10,17))[0]
        with store.connect() as db:
            for i in range(6):Store.event(db,'owned-device','file.modified','info',{'user':r'LAB\Alice','path':r'C:\Owned\report.docx'},occurred=int(base+i))
        with socket.socket() as port:port.bind(('127.0.0.1',0));number=port.getsockname()[1]
        process=subprocess.Popen([str(exe),'serve','--db',str(store.path),'--port',str(number)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
        client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));url=f'http://127.0.0.1:{number}';csrf=''
        def api(path,body=None):
            req=urllib.request.Request(url+path,data=None if body is None else canonical(body).encode(),headers={'Content-Type':'application/json','X-CSRF-Token':csrf})
            with client.open(req,timeout=15) as r:
                data=r.read();return json.loads(data) if 'application/json' in r.headers['Content-Type'] else data
        try:
            until=time.monotonic()+20
            while time.monotonic()<until:
                try:
                    health=api('/api/health');break
                except OSError:time.sleep(.1)
            else:raise AssertionError('Frozen Server did not start')
            assert health['version']==__version__
            csrf=api('/api/login',{'username':'frozen-mis','password':password})['csrf']
            assert b'reportsPage' in api('/audit_reports_ui.js')
            until=time.monotonic()+10
            while True:
                summary=api('/api/audit/summary?start=2026-10-17&end=2026-10-17')
                if summary['caught_up']:break
                if time.monotonic()>until:raise AssertionError('Frozen summary did not catch up')
                time.sleep(.1)
            assert summary['total']==6 and summary['people_total']==1
            device_summary=api('/api/audit/summary?start=2026-10-17&end=2026-10-17&group_by=device')
            assert device_summary['total']==6 and device_summary['device_total']==1
            assert device_summary['items'][0]['device_id']=='owned-device'
            rows=api('/api/events?device=owned-device&category=files&file_action=changes')
            assert rows['total']==6 and all(r['device_id']=='owned-device' for r in rows['items'])
            jid=api('/api/audit/exports',{'start':'2026-10-17','end':'2026-10-18','csv':True})['id'];until=time.monotonic()+20
            while True:
                job=next(j for j in api('/api/audit/exports')['jobs'] if j['id']==jid)
                if job['state']=='completed':break
                if job['state'] in ('failed','interrupted') or time.monotonic()>until:raise AssertionError(job)
                time.sleep(.1)
            verified=subprocess.run([str(exe),'verify-audit-archive','--directory',job['folder']],capture_output=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
            assert verified.returncode==0,verified.stderr.decode('utf-8',errors='replace')
            result=json.loads(verified.stdout);assert result['valid'] and result['rows']==6
            data=api('/api/audit/exports/download?id='+jid);assert data[:2]==b'PK' and hashlib.sha256(data).hexdigest()==job['zip_sha256']
            assert store.verify()['valid']
        finally:
            process.terminate();process.wait(timeout=15)
    report={'version':__version__,'passed':True,'exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
            'checks':['Frozen report JS and summary background index','Frozen date archive and authenticated streamed download','Frozen CLI verifies directory SHA-256 and original row hashes','Downloaded ZIP SHA-256 matches MIS catalog','Original audit chain preserved'],
            'limitations':['Owned loopback fixtures, not office Server or NAS','No protected endpoint, company Defender or production data changes']}
    (ROOT/'evidence/packaged-audit-reports-0.4.25.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report,indent=2))


if __name__=='__main__':main()
