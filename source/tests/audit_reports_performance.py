"""Synthetic 20k valid events; summary/export concurrency and memory evidence."""
import datetime as dt
import http.cookiejar
import json
import secrets
import sys
import tempfile
import threading
import time
import tracemalloc
import urllib.request
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from guarddesk.audit_reports import TAIPEI,day_bounds
from guarddesk.server import serve
from guarddesk.store import Store,canonical
ROOT=Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime') as tmp:
        store=Store(Path(tmp)/'control.db');password=secrets.token_urlsafe(20);store.add_user('owned-mis',password)
        day=dt.date(2026,10,18);base=day_bounds(day)[0]
        with store.connect() as db:
            for i in range(20000):Store.event(db,'owned-device','file.modified','info',{'user':'LAB\\person'+str(i%20),'path':'C:\\Owned\\'+str(i)+'.txt','source':'synthetic'},occurred=base+i)
        server=serve(store.path,port=0);threading.Thread(target=server.serve_forever,daemon=True).start();url=f'http://127.0.0.1:{server.server_port}'
        client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        csrf=''
        def api(path,body=None):
            req=urllib.request.Request(url+path,data=None if body is None else canonical(body).encode(),headers={'Content-Type':'application/json','X-CSRF-Token':csrf})
            with client.open(req,timeout=15) as response:return json.load(response)
        try:
            csrf=api('/api/login',{'username':'owned-mis','password':password})['csrf'];samples=[];until=time.monotonic()+30
            while True:
                t=time.perf_counter();s=api('/api/audit/summary?start=2026-10-18&end=2026-10-18&group_by=device');samples.append((time.perf_counter()-t)*1000)
                if s['caught_up']:break
                if time.monotonic()>until:raise AssertionError('Synthetic rollup did not catch up')
                time.sleep(.1)
            assert s['total']==20000 and s['device_total']==1 and s['items'][0]['device_id']=='owned-device'
            tracemalloc.start();jid=api('/api/audit/exports',{'start':'2026-10-18','end':'2026-10-18','csv':True})['id'];durations=[];until=time.monotonic()+90
            while True:
                t=time.perf_counter();assert api('/api/health')['status']=='ok';durations.append((time.perf_counter()-t)*1000)
                job=next(j for j in api('/api/audit/exports')['jobs'] if j['id']==jid)
                if job['state'] not in ('queued','running'):break
                if time.monotonic()>until:raise AssertionError('Synthetic export did not finish')
                time.sleep(.1)
            current,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
            assert job['state']=='completed' and job['rows']==20000,job
            report={'passed':True,'synthetic_events':20000,'users':20,'summary_request_max_ms':round(max(samples),2),'summary_request_median_ms':round(sorted(samples)[len(samples)//2],2),'health_during_export_max_ms':round(max(durations),2),'health_samples':len(durations),'python_traced_peak_mib':round(peak/1024**2,2),'source_preserved':store.verify()['valid'],
                    'limitations':['Single Windows development workstation and loopback network','tracemalloc covers Python allocations in this process, not browser/native/OS buffers','No office hardware, NAS, Defender or large historical production database acceptance']}
            (ROOT/'evidence/audit-reports-performance-0.4.25.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report,indent=2))
        finally:server.shutdown();server.server_close()


if __name__=='__main__':main()
