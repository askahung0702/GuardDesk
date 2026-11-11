"""Synthetic 250-device rollup/PNG cost, never sends mail or reads company data."""
import base64
import datetime as dt
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from guarddesk.store import Store,canonical
from guarddesk import mail_reports as m


def main():
    root=Path(__file__).resolve().parents[1]
    day=(dt.datetime.now(m.TAIPEI).date()-dt.timedelta(days=1)).isoformat()
    with tempfile.TemporaryDirectory(dir=root/'runtime',prefix='mail-benchmark-') as folder:
        store=Store(Path(folder)/'control.sqlite3')
        with store.connect() as db:
            for i in range(250):
                did=f'fixture-{i:03}'
                db.execute('INSERT INTO devices(id,token,name,department,last_seen) VALUES(?,?,?,?,?)',(did,did,f'PC-{i:03}','Synthetic',time.time()))
                for action in m.ACTIONS:db.execute('INSERT INTO audit_daily VALUES(?,?,?,?,?,?,?,?)',(day,did,'','',action,'info',2500,time.time()-86400))
        samples=[]
        for _ in range(20):
            start=time.perf_counter()
            with store.connect() as db:data=m.snapshot(db,day)
            samples.append((time.perf_counter()-start)*1000)
        start=time.perf_counter();images=m.charts(data);chart_seconds=time.perf_counter()-start
        body={'message':{'body':m.render(data,images),'attachments':[{'contentBytes':base64.b64encode(raw).decode()} for _,raw in images]}}
        result={'passed':True,'synthetic_only':True,'devices':250,'rollup_rows':1000,'represented_events':2500000,'raw_event_payloads_created_or_scanned':False,'snapshot_median_ms':statistics.median(samples),'snapshot_max_ms':max(samples),'charts_seconds':chart_seconds,'image_count':len(images),'image_bytes':sum(len(raw) for _,raw in images),'estimated_json_bytes':len(canonical(body).encode()),'live_mail_sent':False,'not_a_concurrent_fleet_acceptance':True}
        (root/'evidence/mail-reports-250-performance.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(result))


if __name__=='__main__':main()
