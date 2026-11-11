"""Synthetic library/preview metadata cost. No endpoints or OS controls touched."""
import copy
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from guarddesk.store import Store,canonical
from guarddesk import custom_library as lib


def main():
    root=Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(dir=root/'runtime',prefix='library-benchmark-') as folder:
        store=Store(Path(folder)/'control.sqlite3');stamp=time.time()
        with store.connect() as db:
            for i in range(20):
                gid=f'{i:024x}';iid=f'{i+100:024x}';aid=f'{i+200:024x}'
                db.execute('INSERT INTO endpoint_groups VALUES (?,?,NULL,1,?)',(gid,'Synthetic group '+str(i),stamp))
                rule={'id':'schedule-'+str(i),'name':'Fixture reminder','action':'shutdown','days':[1,2,3,4,5,6,7],'times':['22:00'],'delay_seconds':1200,'allow_cancel':True,'defer_minutes':0,'idle_minutes':0,'message':'Synthetic notice','repeat':{'interval_minutes':60,'until':'06:00'}}
                db.execute('INSERT INTO custom_items VALUES (?,?,?,?,?,?,?,?,?,?,?)',(iid,'Reminder '+str(i),'schedules',canonical([rule]),'Synthetic',1,1,0,'',stamp,'fixture'))
                db.execute('INSERT INTO custom_bindings VALUES (?,?,?,?,?,?,?,?,?,?)',(aid,iid,'group',gid,'apply',100,'merge',1,stamp,'fixture'))
            for i in range(250):
                did=f'{i+1000:024x}';gid=f'{i%20:024x}'
                db.execute('INSERT INTO devices(id,token,name,department,last_seen,group_id,inventory) VALUES(?,?,?,?,?,?,?)',(did,'synthetic-'+str(i),'PC-'+str(i),'Synthetic',stamp,gid,canonical({'agent_version':'0.4.39'})))
            data=lib.state(db)
            for d in lib.devices(db):
                packet=lib.resolve(db,d,data)
                for role in ('main','native'):
                    report={'protocol':2,'role':role,'version':'0.4.39','fingerprint':packet['fingerprint'],'report':{'state':'reported','schedule':{'state':'idle'}}}
                    db.execute('INSERT INTO custom_status VALUES(?,?,?,?)',(d['id'],role,canonical(report),stamp))
        catalog_times=[];preview_times=[]
        for _ in range(15):
            start=time.perf_counter()
            with store.connect() as db:catalog=lib.catalog(db)
            catalog_times.append((time.perf_counter()-start)*1000)
            candidate=copy.deepcopy(catalog['items'][0]);candidate={k:candidate[k] for k in ('id','name','kind','body','description','enabled','revision')};candidate['body'][0]['repeat']['interval_minutes']=30
            start=time.perf_counter()
            with store.connect() as db:preview=lib.preview(db,{'op':'save_item','item':candidate})
            preview_times.append((time.perf_counter()-start)*1000)
        result={'passed':True,'synthetic_only':True,'devices':250,'groups':20,'items':20,'reports':500,'catalog_median_ms':statistics.median(catalog_times),'catalog_max_ms':max(catalog_times),'preview_median_ms':statistics.median(preview_times),'preview_max_ms':max(preview_times),'catalog_bytes':len(canonical(catalog).encode()),'affected_devices':preview['affected_count'],'events_scanned':False,'live_controls_modified':False,'not_a_concurrent_fleet_acceptance':True}
        (root/'evidence/custom-library-250-performance.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps(result))


if __name__=='__main__':main()
