"""Owned 300000-event upgrade fixture: rare/missing terms and index growth."""
import ctypes,datetime as dt,hashlib,json,shutil,sqlite3,sys,tempfile,time
from pathlib import Path
from contextlib import closing
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk import __version__,audit_search,audit_search_index as search,audit_sort,event_storage as storage
from guarddesk.store import Store,canonical,digest

def main():
    assert shutil.disk_usage(ROOT).free>4*1024**3
    runtime=ROOT/'runtime';temp=tempfile.TemporaryDirectory(dir=runtime,prefix='global-sort-');root=Path(temp.name).resolve();assert root.parent==runtime.resolve()
    try:
        store=Store(root/'control.sqlite3');now=1792512000.;previous='0'*64;identifier=0
        print('Seeding 100000 previous-day events',flush=True)
        with store.connect() as db:
            db.execute("INSERT INTO devices(id,token,name,department,last_seen) VALUES('owned','fixture-hash','Owned-DEV','Fixture',?)",(now,))
            batch=[]
            for i in range(100000):
                details={'path':'C:\\Owned\\History\\ordinary.docx'};logical={'event_id':'history-'+str(i),'device_id':'owned','kind':'file.deleted','severity':'info','occurred':now-86400,'received':now-86400,'details':details}
                signature=digest(previous+canonical(logical));identifier+=1
                batch.append((identifier,logical['event_id'],'owned','file.deleted','info',now-86400,now-86400,canonical(details),previous,signature));previous=signature
                if len(batch)==5000:db.executemany('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?)',batch);batch=[]
        with store.connect() as db:storage.enable(db,store.path,snapshot_backup=False)
        print('Seeding 200000 current-day compressed events; file-heavy unique paths',flush=True)
        day=dt.datetime.fromtimestamp(now,dt.timezone(dt.timedelta(hours=8))).strftime('%Y%m%d');path=storage.day_file(store.path,day,create=True)
        kinds=['application.started','file.deleted'];counts=[0,0];sizes=[0,0]
        with store.connect() as db,closing(sqlite3.connect(path)) as daily:
            daily.execute('CREATE TABLE events(id INTEGER PRIMARY KEY,payload BLOB NOT NULL)')
            for category,value in [('device','owned'),*[('kind',kind) for kind in kinds]]:db.execute('INSERT INTO event_terms(category,value) VALUES(?,?)',(category,value))
            keys={r['value']:r['id'] for r in db.execute('SELECT id,value FROM event_terms')};meta=[];payloads=[]
            rare_positions={1000+i*24000 for i in range(12)}
            for i in range(200000):
                k=1 if i%4 else 0;kind=kinds[k]
                details={'path':f'C:\\Owned\\Matter-{i}\\ordinary.docx'} if k else {'process':'C:\\Tools\\jcmd.exe','pid':i%800,'user':'OWNED\\Tester'}
                if i in rare_positions:details['path']='C:\\Owned\\26C0018\\稀有報告耀.docx'
                logical={'event_id':'today-'+str(i),'device_id':'owned','kind':kind,'severity':'info','occurred':now+1,'received':now+1,'details':details}
                signature=digest(previous+canonical(logical));identifier+=1
                row={**logical,'id':identifier,'details':canonical(details),'prev_hash':previous,'hash':signature};payload=storage.pack(row);previous=signature
                meta.append((identifier,storage.encode_id(logical['event_id']),keys['owned'],keys[kind],0,now+1,now+1,day,bytes.fromhex(signature),1,len(payload),storage.family(kind)))
                payloads.append((identifier,payload));counts[k]+=1;sizes[k]+=len(payload)
                if len(meta)==5000:
                    daily.executemany('INSERT INTO events VALUES(?,?)',payloads);daily.commit()
                    db.executemany('INSERT INTO event_catalog(id,event_id,device_id,kind,severity,occurred,received,day,hash,stored,payload_bytes,family) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',meta);meta=[];payloads=[]
            db.execute('INSERT INTO event_storage_daily VALUES(?,?,?)',(day,200000,sum(sizes)))
            for k,kind in enumerate(kinds):db.execute('INSERT INTO event_storage_sources VALUES(?,?,?,?,?)',(day,keys['owned'],keys[kind],counts[k],sizes[k]))
            # New schema being installed into an existing populated Server.
            db.execute('UPDATE audit_sort_state SET low_id=?,high_id=?,indexed_rows=0',(identifier+1,identifier))
        values=(now,now+86400);clause='WHERE e.occurred>=? AND e.occurred<?'
        with store.connect() as db:db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        before_bytes=store.path.stat().st_size;started=time.perf_counter();cpu=time.process_time();batches=0
        while True:
            with store.connect() as db:
                if audit_sort.ready(db,clause,values,time_filtered=True)[0]:break
            assert audit_sort.index_batch(store);batches+=1
        build={'seconds':round(time.perf_counter()-started,3),'cpu_seconds':round(time.process_time()-cpu,3),'batches':batches}
        with store.connect() as db:
            build.update(audit_sort.state(db));build['distinct_strings']=db.execute('SELECT count(*) FROM audit_sort_values').fetchone()[0];db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        build['control_growth_bytes']=store.path.stat().st_size-before_bytes;print('BUILD '+json.dumps(build),flush=True)
        results={}
        for field in ('occurred','device','kind','process','path','destination'):
            for direction in ('asc','desc'):
                with patch.object(storage.Reader,'value',side_effect=AssertionError('sort decompressed evidence')),store.connect() as db:
                    before_head=storage.head(db);started=time.perf_counter();cpu=time.process_time()
                    ids,_=audit_search.identifiers(db,clause,values,'','',51,seconds=10,time_filtered=True,sort=field,direction=direction)
                    second,_=audit_search.identifiers(db,clause,values,'','',51,seconds=10,time_filtered=True,sort=field,direction=direction,anchor=ids[49])
                    assert len(ids)==51 and len(second)==51 and second[0]==ids[50] and not set(ids[:50])&set(second)
                    assert storage.head(db)==before_head
                result={'two_pages_seconds':round(time.perf_counter()-started,4),'cpu_seconds':round(time.process_time()-cpu,4),'payload_events_read':0,'unique_rows':101};results[field+'_'+direction]=result;print(field+' '+direction+' '+json.dumps(result),flush=True)
        report={'passed':True,'version':__version__,'synthetic_rows':300000,'today_rows':200000,'index':build,'queries':results,'source_heads_unchanged':True,'no_office_database_read':True,'source_sha256':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in ('guarddesk/audit_sort.py','guarddesk/audit_search.py','tools/audit_sort_performance.py')},'limits':['One developer Windows workstation, no physical fleet or office acceptance','100000 legacy and 200000 compressed current-day rows; sorts measured over 200000 rows, not all history','Offline index build omits production quiet gaps; automatic ingestion measurements reported separately','Full strings consume extra disk; 150000 file events use mostly unique paths; process identities repeat; arbitrary unique long paths may cost substantially more','Metadata sorting may use temporary B-trees and is bounded by cancellation/deadline/2 shared query slots; no constant-time claim']}
        (ROOT/f'evidence/audit-sort-performance-{__version__}.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    finally:
        assert root.parent==runtime.resolve() and root.name.startswith('global-sort-');temp.cleanup()

if __name__=='__main__':main()
