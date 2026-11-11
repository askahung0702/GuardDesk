"""Owned million-row fixture; baseline payload-UNION vs metadata-first search."""
import argparse,hashlib,json,shutil,sys,tempfile,time
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk import __version__,audit_search,event_storage as storage
from guarddesk.store import Store,canonical,digest

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--history',type=int,default=1000000);parser.add_argument('--selected',type=int,default=15000);args=parser.parse_args()
    assert 0<args.history<=1000000 and 0<args.selected<=50000
    assert shutil.disk_usage(ROOT).free>3*1024**3,'Owned large fixture requires 3 GiB free'
    runtime=ROOT/'runtime';temp=tempfile.TemporaryDirectory(dir=runtime,prefix='audit-search-benchmark-');root=Path(temp.name).resolve();assert root.parent==runtime.resolve()
    print('Creating owned synthetic history',flush=True)
    try:
        store=Store(root/'control.sqlite3');now=1792512000.0;previous='0'*64;last=0
        with store.connect() as db:
            db.execute('INSERT INTO devices(id,token,name,department,last_seen) VALUES (?,?,?,?,?)',('owned','fixture-hash','Owned-DEV','Synthetic',now))
            batch=[]
            for i in range(args.history):
                record={'event_id':'history-'+str(i),'device_id':'owned','kind':'file.deleted','severity':'info','occurred':now-86400,'received':now-86400,'details':{'path':r'C:\Owned\History\report-'+str(i)+'.docx'}}
                signature=digest(previous+canonical(record));last+=1
                batch.append((last,record['event_id'],record['device_id'],record['kind'],record['severity'],record['occurred'],record['received'],canonical(record['details']),previous,signature));previous=signature
                if len(batch)==5000:db.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?)',batch);batch=[]
            if batch:db.executemany('INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?)',batch)
        with store.connect() as db:storage.enable(db,store.path,snapshot_backup=False)
        writer=storage.DayWriter();store.storage_writer=writer
        try:
            for start in range(0,2*args.selected,1000):
                with store.connect() as db:
                    for i in range(start,min(start+1000,2*args.selected)):
                        Store.event(db,'owned' if i%2 else 'other','file.deleted','info',{'path':r'C:\Owned\26C0018\report-'+str(i)+'.docx','padding':'synthetic '*20},'daily-'+str(i),now+1)
            while True:
                with store.connect() as db:pending=db.execute('SELECT count(*) FROM event_pending').fetchone()[0]
                if not pending:break
                storage.flush(store)
        finally:writer.close();store.storage_writer=None
        values=('owned','file',now,now+86400,last+2*args.selected,last+2*args.selected+1)
        clause='WHERE e.device_id=? AND e.family=? AND e.occurred>=? AND e.occurred<? AND e.id<=? AND e.id<?'
        old_clause=clause.replace('e.family=?','CAST(('+storage.FAMILY_SQL.replace('kind','e.kind')+') AS TEXT)=?')
        old_sql="SELECT e.id FROM events e LEFT JOIN devices d ON e.device_id=d.id "+old_clause+" AND (e.kind LIKE ? OR e.details LIKE ? OR COALESCE(d.name,'') LIKE ?) ORDER BY e.id DESC LIMIT 51"
        original=storage.Reader.value;results={}
        for name in ('baseline','metadata_first'):
            seen=set();calls=[0]
            def observed(reader,identifier,field):seen.add(identifier);calls[0]+=1;return original(reader,identifier,field)
            print('Measuring '+name,flush=True);started=time.perf_counter()
            with patch.object(storage.Reader,'value',observed),store.connect() as db:
                db.execute('PRAGMA query_only=ON');before=storage.head(db)
                deadline=time.monotonic()+180;db.set_progress_handler(lambda:int(time.monotonic()>deadline),10000)
                if name=='baseline':ids=[r[0] for r in db.execute(old_sql,values+('%26C0018%',)*3)]
                else:ids=audit_search.identifiers(db,clause,values,'','26C0018',51,time_filtered=True)[0]
                db.set_progress_handler(None,0);assert storage.head(db)==before
            results[name]={'seconds':round(time.perf_counter()-started,4),'payload_events_read':len(seen),'payload_field_calls':calls[0],'ids':ids}
        assert results['baseline']['ids']==results['metadata_first']['ids'] and len(results['metadata_first']['ids'])==51
        assert results['baseline']['payload_events_read']==args.selected and results['metadata_first']['payload_events_read']==51
        for value in results.values():value.pop('ids')
        report={'passed':True,'version':__version__,'synthetic_rows':args.history+2*args.selected,'legacy_outside_date':args.history,'daily_in_date':2*args.selected,'matching_device_rows':args.selected,'page_rows':50,'lookahead':1,'results':results,'same_page_ids':True,'source_head_unchanged':True,'no_office_database_read':True,'limits':['Single owned synthetic fixture and developer workstation, not measured office Server latency','All selected rows match the keyword. Rare/missing substring still must scan in-scope candidates and has a time budget','No new full-text index or duplicate payload storage added']}
        (ROOT/f'evidence/audit-search-performance-{__version__}.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report))
    finally:
        assert root.parent==runtime.resolve() and root.name.startswith('audit-search-benchmark-');temp.cleanup()
if __name__=='__main__':main()
