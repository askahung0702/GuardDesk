"""Bounded, synthetic logical-event comparison; never opens office databases."""
import hashlib
import json
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from guarddesk import __version__,event_storage
from guarddesk.store import Store
from guarddesk.audit_reports import index_batch

ROOT=Path(__file__).resolve().parents[1]


def measure(root,daily,count=5000):
    store=Store(root/'control.sqlite3')
    if daily:
        with store.connect() as db:event_storage.enable(db,store.path)
    started=time.perf_counter()
    for offset in range(0,count,100):
        with store.connect() as db:
            for i in range(offset,min(count,offset+100)):
                device=f'fixture-{i%250:03d}'
                kind=['file.deleted','file.moved','application.started','web.navigation'][i%4]
                details={'source':'synthetic','user':f'EXAMPLE\\fixture-{i%250:03d}',
                         'path':f'C:\\Users\\fixture-{i%250:03d}\\Documents\\Case-{i%71}\\Document-{i}.docx',
                         'process':r'C:\Program Files\Example\Example.exe','process_id':1000+i%101}
                if kind=='file.moved':details['destination_path']=f'D:\\Owned\\Case-{i%71}\\Document-{i}.docx'
                if kind=='web.navigation':details.update(url=f'https://example.invalid/case/{i%71}/document/{i}',title=f'Synthetic case {i%71}')
                Store.event(db,device,kind,'info',details,hashlib.md5(str(i).encode()).hexdigest(),1792339200+i)
    write_seconds=time.perf_counter()-started
    print(f"mode={daily} wrote {count} in {write_seconds:.3f}s",file=sys.stderr,flush=True)
    n=0
    while index_batch(store):
        n+=1
        if n%5==0:print(f"mode={daily} index batches={n}",file=sys.stderr,flush=True)
    with store.connect() as db:
        db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        try:objects={r[0]:r[1] for r in db.execute('SELECT name,sum(pgsize) FROM dbstat GROUP BY name')}
        except sqlite3.OperationalError:objects={}
        start=time.perf_counter();rows=list(db.execute('SELECT * FROM events WHERE id<? ORDER BY id DESC LIMIT 50',(1000,)))
        query_ms=(time.perf_counter()-start)*1000
    assert len(rows)==50 and store.verify()['valid']
    day_bytes=sum(p.stat().st_size for p in event_storage.storage_root(store.path).glob('*/*/events.sqlite3'))
    backups=sum(p.stat().st_size for p in (root/'StorageBackups').glob('*.sqlite3'))
    control=store.path.stat().st_size
    indexes=sum(v for k,v in objects.items() if k.startswith('event_catalog_') or k.startswith('events_') or k.startswith('sqlite_autoindex_events') or k.startswith('sqlite_autoindex_event_catalog'))
    return {'events':count,'write_seconds':round(write_seconds,3),'cursor_50_rows_ms':round(query_ms,3),
            'control_bytes_including_indexes_rollups_and_staging':control,'event_index_bytes_included_in_control':indexes if objects else None,
            'index_measurement':'dbstat per-object pages' if objects else 'SQLite dbstat unavailable; all index pages included in control total',
            'control_objects_bytes':objects,'wal_bytes':Path(str(store.path)+'-wal').stat().st_size if Path(str(store.path)+'-wal').exists() else 0,
            'day_bytes':day_bytes,'preactivation_backup_bytes_separate':backups,'online_total_bytes':control+day_bytes,
            'chain_valid':True}


def main():
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime',prefix='daily-benchmark-') as td:
        root=Path(td)
        for name in ('legacy','daily'):(root/name).mkdir()
        legacy=measure(root/'legacy',False);daily=measure(root/'daily',True)
    result={'passed':True,'version':__version__,'legacy':legacy,'daily':daily,
            'online_change_percent':round((daily['online_total_bytes']/legacy['online_total_bytes']-1)*100,2),
            'limits':['5000 synthetic events across 250 identifiers, sequential batches, not 250 concurrent Agents',
                      'Same complete logical records and derived rollups; no filtering included in this storage comparison',
                      'Control includes all event indexes, pending capacity and rollups; backup measured separately; checkpointed WAL',
                      'Not a guaranteed production compression ratio, per-day capacity or latency result']}
    (ROOT/f'evidence/daily-storage-benchmark-{__version__}.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':main()
