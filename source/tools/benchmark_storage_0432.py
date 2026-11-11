"""Read-only source -> private disposable copy; aggregate numbers only."""
import argparse
import contextlib
import hashlib
import json
from pathlib import Path
import sqlite3
import statistics
import sys
import tempfile
import time
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from guarddesk.store import Store
from guarddesk.server_setup import secure_directory
from guarddesk.server_backup import snapshot
from guarddesk.storage_maintenance import optimize
from guarddesk.audit_reports import summary
from guarddesk import event_storage


def timed(db,sql,args=(),repeats=3):
    samples=[];count=None
    for _ in range(repeats):
        start=time.perf_counter();rows=db.execute(sql,args).fetchall();samples.append(round((time.perf_counter()-start)*1000,3));count=len(rows)
    return {'ms':samples,'median_ms':statistics.median(samples),'returned_rows':count}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--resume-root');args=parser.parse_args()
    source=ROOT/'runtime/control.sqlite3'
    original_size=source.stat().st_size
    with source.open('rb') as stream:original_sha=hashlib.file_digest(stream,'sha256').hexdigest()
    if args.resume_root:
        resumed=Path(args.resume_root).resolve()
        assert resumed.is_relative_to((ROOT/'runtime').resolve()) and resumed.name.startswith('storage-0432-')
    context=contextlib.nullcontext(str(resumed)) if args.resume_root else tempfile.TemporaryDirectory(dir=ROOT/'runtime',prefix='storage-0432-')
    with context as temporary:
        root=Path(temporary);copy=root/'control.sqlite3'
        if not args.resume_root:
            secure_directory(root,allow_empty=True);snapshot(source,copy)
        db=sqlite3.connect(source.as_uri()+'?mode=ro',uri=True);count=db.execute('SELECT count(*) FROM events').fetchone()[0];source_head=db.execute('SELECT hash FROM events ORDER BY id DESC LIMIT 1').fetchone()[0];db.close()
        db=sqlite3.connect(copy)
        if args.resume_root:
            baseline=json.loads((ROOT/'evidence/storage-performance-0.4.32-before-header-fix.txt').read_text(encoding='utf-8-sig').splitlines()[0])
            before=baseline['timings'];db.close();assert baseline['events']==count
            from guarddesk.storage_maintenance import DatabaseLease,_complete_migration
            with DatabaseLease(copy):
                store=Store(copy)
                with store.connect() as connection:assert connection.execute('SELECT count(*) FROM events_legacy').fetchone()[0]==0
                start=time.monotonic();store.storage_writer=event_storage.DayWriter()
                try:
                    with contextlib.closing(sqlite3.connect(copy)):
                        moved,verified=_complete_migration(store,0,lambda value:print(json.dumps(value),flush=True))
                finally:store.storage_writer.close();store.storage_writer=None
                assert moved==0 and verified['valid'] and verified['checked']==count and verified['head']==source_head
                with contextlib.closing(sqlite3.connect(copy)) as connection:
                    connection.execute('PRAGMA wal_checkpoint(TRUNCATE)');connection.execute('VACUUM');connection.execute('PRAGMA optimize')
                    assert connection.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
                days=list(event_storage.storage_root(copy).glob('*/*/events.sqlite3'))
                result={'passed':True,'events':count,'head':verified['head'],'history_preserved':True,'before_control_bytes':original_size,
                        'control_bytes':copy.stat().st_size,'day_bytes':sum(p.stat().st_size for p in days),
                        'legacy_events_migrated_before_resume':count,'resume_seconds':round(time.monotonic()-start,2)}
        else:
            before={'alerts':timed(db,"SELECT count(*) FROM events WHERE severity IN ('warning','critical') AND received>?",(time.time()-86400,)),
                    'file_first_page':timed(db,"SELECT * FROM events WHERE kind>='file.' AND kind<'file/' ORDER BY id DESC LIMIT 51"),
                    'head':timed(db,'SELECT COALESCE(max(id),0) FROM events')}
            db.close()
            print(json.dumps({'phase':'before','events':count,'timings':before}),flush=True)
            result=optimize(copy,lambda value:print(json.dumps(value),flush=True))
        store=Store(copy)
        after={}
        with store.connect() as db:
            after['alerts']=timed(db,"SELECT count(*) FROM event_headers WHERE severity IN ('warning','critical') AND received>?",(time.time()-86400,))
            after['file_first_page_ids']=timed(db,"SELECT id FROM event_headers WHERE family='file' ORDER BY id DESC LIMIT 51")
            samples=[]
            for _ in range(3):
                start=time.perf_counter()
                ids=[r[0] for r in db.execute("SELECT id FROM event_headers WHERE family='file' ORDER BY id DESC LIMIT 51")]
                rows=[dict(db.execute('SELECT * FROM events WHERE id=?',(i,)).fetchone()) for i in ids]
                samples.append(round((time.perf_counter()-start)*1000,3))
            after['file_first_page_full']={'ms':samples,'median_ms':statistics.median(samples),'returned_rows':len(rows)}
            samples=[]
            for _ in range(3):
                start=time.perf_counter();event_storage.head(db);samples.append(round((time.perf_counter()-start)*1000,3))
            after['head']={'ms':samples,'median_ms':statistics.median(samples)}
            samples=[]
            for _ in range(3):
                start=time.perf_counter();r=summary(db,{'start':['2026-01-01'],'end':['2026-12-31'],'group_by':['device']});samples.append(round((time.perf_counter()-start)*1000,3))
            after['summary']={'ms':samples,'median_ms':statistics.median(samples),'counted_file_events':r['total'],'caught_up':r['caught_up']}
            after_count=db.execute('SELECT count(*) FROM event_headers').fetchone()[0]
        assert count==after_count and result['events']==count
        result.pop('backup',None)
    with source.open('rb') as stream:assert hashlib.file_digest(stream,'sha256').hexdigest()==original_sha
    report={'passed':True,'version':'0.4.32','events':count,'source_bytes':original_size,'original_sha256_unchanged':original_sha,
            'before':before,'after':after,'optimization':result,'resumed_private_copy':bool(args.resume_root),
            'limits':['Read-only existing development audit DB; transformation and all writes only on a private disposable copy',
                      'Three local SQL measurements, not HTTP or office Server latency; caches influence repeats',
                      'Source was an older single-table schema; deployed Server may already have additional indexes',
                      'All original logical events retained, new derived statistics/indexes included; backups separate',
                      'Not 250 concurrent physical Agents or guaranteed production capacity',
                      'Resumed mode continues the private copy after correcting metadata affinity; copy/migration throughput is not a fresh full-run benchmark']}
    (ROOT/'evidence/storage-performance-0.4.32.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False),flush=True)


if __name__=='__main__':main()
