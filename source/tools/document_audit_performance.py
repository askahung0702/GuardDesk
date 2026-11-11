"""Bounded unified-category metadata query on owned 300k synthetic events."""
import hashlib,json,sys,tempfile,time
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk import __version__,audit_search,event_storage
from guarddesk.store import Store,canonical,digest


def main():
    with tempfile.TemporaryDirectory(prefix='owned-document-query-',dir=ROOT/'runtime') as temp:
        store=Store(Path(temp)/'control.sqlite3');now=time.time()-10;previous='0'*64
        with store.connect() as db:
            for i in range(3):db.execute("INSERT INTO devices(id,token,name,department,last_seen) VALUES(?,?,?,?,?)",(f'owned-{i}',f'fixture-{i}',f'Owned-{i}','Fixture',now))
            batch=[]
            for i in range(300000):
                kind=('file.opened','web.upload_started','web.upload_response','application.started')[i%4]
                occurred=now-86400 if i<100000 else now
                details={'path':r'C:\Owned\report.txt'}
                logical={'event_id':f'owned-{i}','device_id':f'owned-{i%3}','kind':kind,'severity':'info','occurred':occurred,'received':occurred,'details':details}
                signature=digest(previous+canonical(logical))
                batch.append((i+1,logical['event_id'],logical['device_id'],kind,'info',occurred,occurred,canonical(details),previous,signature));previous=signature
                if len(batch)==5000:db.executemany('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?)',batch);batch=[]
        results=[]
        for device in (None,'owned-1'):
            for field in ('id','occurred','device','kind'):
                clause="WHERE e.family IN ('file','uploads') AND e.occurred>=? AND e.occurred<?";values=(now-1,now+1)
                if device:clause+=' AND e.device_id=?';values+= (device,)
                started=time.perf_counter()
                with store.connect() as db,patch.object(event_storage.Reader,'value',side_effect=AssertionError('metadata query read payload')):
                    ids,_=audit_search.identifiers(db,clause,values,'','',51,seconds=10,time_filtered=True,sort=field,direction='desc')
                    second,_=audit_search.identifiers(db,clause,values,'','',51,seconds=10,time_filtered=True,sort=field,direction='desc',anchor=ids[49])
                    assert second[0]==ids[50] and not set(ids[:50])&set(second)
                elapsed=time.perf_counter()-started
                assert elapsed<10
                results.append({'device':device,'field':field,'two_pages_seconds':round(elapsed,4),'unique_rows':101,'payload_events_read':0})
        report={'passed':True,'version':__version__,'synthetic_rows':300000,'today_rows':200000,'results':results,
                'source_sha256':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in ('guarddesk/server.py','guarddesk/audit_search.py','guarddesk/event_storage.py','tools/document_audit_performance.py')},
                'limits':['Synthetic legacy metadata only; compressed daily storage covered by existing tests','No keyword/new derived-key benchmark; those algorithms are unchanged','No live office database, endpoint intake or fleet acceptance; not a constant-time claim']}
        (ROOT/f'evidence/document-audit-performance-{__version__}.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(report,ensure_ascii=True))


if __name__=='__main__':main()
