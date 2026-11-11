"""Owned synthetic storage experiment, not a 250-endpoint load acceptance."""
import argparse
import gzip
import json
from pathlib import Path
import sys
import tempfile
import time
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from guarddesk.store import Store,canonical
from guarddesk.audit_reports import index_batch,summary


def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--events',type=int,default=20000);args=p.parse_args()
    if not 1<=args.events<=50000:raise ValueError('Synthetic event limit 1..50000')
    with tempfile.TemporaryDirectory(prefix='capacity-benchmark-',dir=ROOT/'runtime') as tmp:
        root=Path(tmp);store=Store(root/'synthetic.sqlite3')
        kinds=['file.created','file.deleted','application.started','application.stopped','file.renamed'];base=1792339200
        t=time.monotonic()
        for start in range(0,args.events,100):
            with store.connect() as db:
                for n in range(start,min(start+100,args.events)):
                    kind=kinds[n%len(kinds)];path=rf'C:\Users\fixture\Documents\案件\2026\文件-{n%500:04d}.docx'
                    details={'path':path,'user':None if kind.startswith('file.') else r'LAB\fixture','source':'synthetic_capacity',
                             'process':None if kind.startswith('file.') else r'C:\Program Files\Office\EXCEL.EXE'}
                    if kind=='file.renamed':details.update(source_path=path,destination_path=path.replace('.docx','-新版.docx'))
                    Store.event(db,'owned-synthetic-device',kind,'info',details,occurred=base+n/10)
        inserted=time.monotonic()-t;before_index=store.path.stat().st_size
        with store.connect() as keeper:
            keeper.execute('SELECT 1')
            while index_batch(store):pass
        after_index=store.path.stat().st_size;jsonl=0
        with store.connect() as db,gzip.open(root/'archive.jsonl.gz','wb',compresslevel=1) as archive:
            for row in db.execute('SELECT * FROM events ORDER BY id'):
                data=dict(row);data['details']=json.loads(data['details']);line=(canonical(data)+'\n').encode();jsonl+=len(line);archive.write(line)
        with store.connect() as db:
            result=summary(db,{'start':['2026-10-19'],'end':['2026-10-19'],'action':['all'],'group_by':['device']})
        # Summary excludes application events by design; three of five kinds
        # in this synthetic trace are file mutations.
        expected=sum(1 for n in range(args.events) if kinds[n%5].startswith('file.'))
        report={'events':args.events,'insert_seconds':round(inserted,2),'db_before_rollup_bytes':before_index,'db_after_rollup_bytes':after_index,
                'bytes_per_event_including_rollup':round(after_index/args.events,2),'rollup_increment_bytes':after_index-before_index,
                'jsonl_bytes':jsonl,'gzip1_jsonl_bytes':(root/'archive.jsonl.gz').stat().st_size,
                'archive_to_jsonl_ratio':round((root/'archive.jsonl.gz').stat().st_size/jsonl,5),
                'passed':store.verify()['valid'] and result['total']==expected,
                'limitations':['Synthetic documents and process records only; no real employee data',
                               'Direct Store writes in batches, not authenticated HTTP, 250-agent concurrency, disk-failure or offline-burst validation',
                               'Includes hash chain and current schema indexes; archive size is not a searchable online DB size',
                               'No source DB or endpoint configuration changed']}
    with args.output.open('x',encoding='utf-8') as stream:json.dump(report,stream,indent=2)
    print(json.dumps(report,indent=2));return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
