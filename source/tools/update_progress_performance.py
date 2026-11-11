"""Metadata-only progress benchmark on own synthetic DB; no office data."""
import hashlib,json,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk.store import Store
from guarddesk import updates,update_progress,__version__


def main():
    results=[];now=time.time();rid='a'*64
    with tempfile.TemporaryDirectory(prefix='update-progress-perf-',dir=ROOT/'runtime') as d:
        store=Store(Path(d)/'owned.sqlite3')
        with store.connect() as db:
            db.execute('INSERT INTO update_releases VALUES(?,?,?,?,?)',(rid,__version__,'{}',now,'fixture'))
            for i in range(250):
                did=f'{i+1:024x}'
                db.execute('INSERT INTO devices(id,token,name,department,last_seen,inventory) VALUES(?,?,?,?,?,?)',(did,'synthetic-'+str(i),'PC-'+str(i).zfill(3),'MIS',now,json.dumps({'agent_version':'0.4.49','user_accounts':['FIXTURE\\user'+str(i)]})))
            db.executemany('INSERT INTO update_jobs VALUES(?,?,?,?,?,?,?,?,?)',((f'{i+1:032x}',f'{i%250+1:024x}',rid,'fixture',now-i,now-1,now+86400,0,'pending' if i<250 else 'completed') for i in range(100000)))
            db.executemany('INSERT INTO update_status VALUES(?,?,?,?,?,?)',((f'{i+1:032x}',role,'queued' if i<250 else 'healthy',__version__ if i>=250 else '', '',0 if i<250 else now) for i in range(100000) for role in ('native','main')))
        for params in ({},{'state':['waiting']},{'state':['completed'],'page':['1000']},{'q':['PC-249'],'release':[rid]},{'state':['not_updated'],'release':[rid]}):
            with store.connect(flush_events=False) as db:
                statements=[];db.set_trace_callback(statements.append);start=time.perf_counter();result=updates.catalog(db,params=params);elapsed=time.perf_counter()-start
                assert len(result['jobs'])<=50 and len(result['pending_devices'])<=50
                assert not any('event_value' in s or 'FROM events' in s for s in statements)
                results.append({'filters':params,'total':result['progress']['total'],'returned':len(result['jobs'])+len(result['pending_devices']),'seconds':round(elapsed,4),'event_payload_reads':0})
        with store.connect(flush_events=False) as db:
            f=update_progress.parameters(db,{'state':['waiting']},rid);preview=update_progress.preview(db,f);assert preview['total']==250
            start=time.perf_counter();cancelled=update_progress.cancel_waiting(db,{'username':'fixture'},{'confirm':'cancel_waiting','job_ids':preview['job_ids']});cancel_seconds=time.perf_counter()-start
            assert cancelled['cancelled']==250
    result={'version':__version__,'passed':True,'scope':'100000_synthetic_update_jobs_200000_component_rows_250_devices','results':results,'bulk_cancelled':250,'bulk_cancel_sql_seconds':round(cancel_seconds,4),'office_changed':False,'limits':['Synthetic local metadata; not company database/fleet/Defender acceptance','Exact counts and deep OFFSET still cost metadata work; no constant-time claim','Bulk cancellation holds the ordinary management writer transaction, bounded to 1000 IDs'],
      'source_sha256':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ('guarddesk/update_progress.py','guarddesk/updates.py','guarddesk/store.py','tools/update_progress_performance.py')}}
    (ROOT/f'evidence/update-progress-performance-{__version__}.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result))


if __name__=='__main__':main()
