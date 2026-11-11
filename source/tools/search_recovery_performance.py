"""Owned million-event upgrade fixture: rare/missing terms and index growth."""
import ctypes,datetime as dt,hashlib,json,shutil,sqlite3,sys,tempfile,time
from pathlib import Path
from contextlib import closing
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk import __version__,audit_search,audit_search_index as search,event_storage as storage
from guarddesk.store import Store,canonical,digest

def main():
    assert shutil.disk_usage(ROOT).free>4*1024**3
    runtime=ROOT/'runtime';temp=tempfile.TemporaryDirectory(dir=runtime,prefix='sparse-search-');root=Path(temp.name).resolve();assert root.parent==runtime.resolve()
    try:
        store=Store(root/'control.sqlite3');now=1792512000.;previous='0'*64;identifier=0
        print('Seeding 700000 previous-day events',flush=True)
        with store.connect() as db:
            db.execute("INSERT INTO devices(id,token,name,department,last_seen) VALUES('owned','fixture-hash','Owned-DEV','Fixture',?)",(now,))
            batch=[]
            for i in range(700000):
                details={'path':'C:\\Owned\\History\\ordinary.docx'};logical={'event_id':'history-'+str(i),'device_id':'owned','kind':'file.deleted','severity':'info','occurred':now-86400,'received':now-86400,'details':details}
                signature=digest(previous+canonical(logical));identifier+=1
                batch.append((identifier,logical['event_id'],'owned','file.deleted','info',now-86400,now-86400,canonical(details),previous,signature));previous=signature
                if len(batch)==5000:db.executemany('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?)',batch);batch=[]
        with store.connect() as db:storage.enable(db,store.path,snapshot_backup=False)
        print('Seeding 300000 current-day compressed events; only 12 rare hits',flush=True)
        day=dt.datetime.fromtimestamp(now,dt.timezone(dt.timedelta(hours=8))).strftime('%Y%m%d');path=storage.day_file(store.path,day,create=True)
        kinds=['application.started','file.deleted'];counts=[0,0];sizes=[0,0]
        with store.connect() as db,closing(sqlite3.connect(path)) as daily:
            daily.execute('CREATE TABLE events(id INTEGER PRIMARY KEY,payload BLOB NOT NULL)')
            for category,value in [('device','owned'),*[('kind',kind) for kind in kinds]]:db.execute('INSERT INTO event_terms(category,value) VALUES(?,?)',(category,value))
            keys={r['value']:r['id'] for r in db.execute('SELECT id,value FROM event_terms')};meta=[];payloads=[]
            rare_positions={1000+i*24000 for i in range(12)}
            for i in range(300000):
                k=1 if i%20==0 else 0;kind=kinds[k]
                details={'path':f'C:\\Owned\\Matter-{i%15000}\\ordinary.docx'} if k else {'process':'C:\\Tools\\jcmd.exe','pid':i%800,'user':'OWNED\\Tester'}
                if i in rare_positions:details['path']='C:\\Owned\\26C0018\\稀有報告耀.docx'
                logical={'event_id':'today-'+str(i),'device_id':'owned','kind':kind,'severity':'info','occurred':now+1,'received':now+1,'details':details}
                signature=digest(previous+canonical(logical));identifier+=1
                row={**logical,'id':identifier,'details':canonical(details),'prev_hash':previous,'hash':signature};payload=storage.pack(row);previous=signature
                meta.append((identifier,storage.encode_id(logical['event_id']),keys['owned'],keys[kind],0,now+1,now+1,day,bytes.fromhex(signature),1,len(payload),storage.family(kind)))
                payloads.append((identifier,payload));counts[k]+=1;sizes[k]+=len(payload)
                if len(meta)==5000:
                    daily.executemany('INSERT INTO events VALUES(?,?)',payloads);daily.commit()
                    db.executemany('INSERT INTO event_catalog(id,event_id,device_id,kind,severity,occurred,received,day,hash,stored,payload_bytes,family) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',meta);meta=[];payloads=[]
            db.execute('INSERT INTO event_storage_daily VALUES(?,?,?)',(day,300000,sum(sizes)))
            for k,kind in enumerate(kinds):db.execute('INSERT INTO event_storage_sources VALUES(?,?,?,?,?)',(day,keys['owned'],keys[kind],counts[k],sizes[k]))
            # New schema being installed into an existing populated Server.
            db.execute('UPDATE audit_search_state SET low_id=?,high_id=?,indexed_rows=0',(identifier+1,identifier))
        values=(now,now+86400);clause='WHERE e.occurred>=? AND e.occurred<?';original=storage.Reader.value;results={}
        for name,indexed,term in [('baseline_sparse',False,'26C0018'),('indexed_sparse',True,'26C0018'),('indexed_missing',True,'ABSENT-987654321'),('indexed_two_char',True,'報告'),('indexed_one_char',True,'耀'),('indexed_common',True,'jcmd')]:
            if name=='indexed_sparse':
                with store.connect() as db:db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                before_bytes=store.path.stat().st_size;started=time.perf_counter();cpu=time.process_time();batches=0
                while True:
                    with store.connect() as db:
                        if search.ready(db,clause,values,time_filtered=True)[0]:break
                    assert search.index_batch(store);batches+=1
                build={'seconds':round(time.perf_counter()-started,3),'cpu_seconds':round(time.process_time()-cpu,3),'batches':batches}
                with store.connect() as db:
                    build.update(search.state(db));build['distinct_documents']=db.execute('SELECT count(*) FROM audit_search_documents').fetchone()[0]
                    self_value=db.execute('SELECT grams FROM audit_search_grams WHERE audit_search_grams MATCH ? LIMIT 1',(search.match('jcmd'),)).fetchone();assert self_value[0] is None
                    db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                build['control_growth_bytes']=store.path.stat().st_size-before_bytes
                print('Current-day index ready: '+json.dumps(build),flush=True)
            seen=set()
            def observed(reader,event_id,field):seen.add(event_id);return original(reader,event_id,field)
            started=time.perf_counter();cpu=time.process_time();timed_out=False
            with patch.object(storage.Reader,'value',observed),store.connect() as db:
                db.execute('PRAGMA query_only=ON');before_head=storage.head(db)
                try:ids,_=audit_search.identifiers(db,clause,values,'',term,51,seconds=10,time_filtered=True,indexed=indexed)
                except audit_search.SearchTimeout:timed_out=True;ids=[]
                assert storage.head(db)==before_head
            results[name]={'seconds':round(time.perf_counter()-started,4),'cpu_seconds':round(time.process_time()-cpu,4),'payload_events_read':len(seen),'timed_out':timed_out,'rows':len(ids)}
            if indexed:
                assert not timed_out
                assert len(ids)==(0 if name=='indexed_missing' else 51 if name=='indexed_common' else 12),(name,len(ids))
                assert len(seen)<100 if name!='indexed_common' else len(seen)<=51
            print(name+': '+json.dumps(results[name]),flush=True)
        report={'passed':True,'version':__version__,'synthetic_rows':1000000,'today_rows':300000,'today_rare_matches':12,'query_heads_unchanged':True,'no_office_database_read':True,'index':build,'queries':results,'environment':{'python':sys.version.split()[0],'sqlite':sqlite3.sqlite_version,'platform':sys.platform,'temp_store':'compiled default FILE'},'limits':['Single developer workstation; no office Server latency or physical 250-endpoint acceptance','Index growth and build CPU/wall time measured for current-day 300000 rows only; 700000 historical rows intentionally not indexed yet','Offline benchmark removes background throttling to measure build work; production indexes bounded batches only while an active request renews interest','Oversize records remain exact-verification candidates and can still cost time; ordinary records tested here','Local build/regression activity may overlap; timings are indicative, not controlled office capacity or SLA measurements','Head checked around measured read queries. Index-build preservation is covered by separate restart/rollback tests and write-path review, not a million-row global rehash.']}
        (ROOT/f'evidence/search-recovery-performance-{__version__}.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,ensure_ascii=False))
    finally:
        assert root.parent==runtime.resolve() and root.name.startswith('sparse-search-');temp.cleanup()

if __name__=='__main__':main()
