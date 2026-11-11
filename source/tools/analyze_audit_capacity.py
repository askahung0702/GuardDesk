"""Read-only local capacity analysis; writes aggregates, never raw employee events."""
import argparse
from collections import Counter
import datetime as dt
from email.parser import BytesHeaderParser
import hashlib
import json
import math
import ntpath
from pathlib import Path
import sqlite3
import struct
import time
import zlib


def entropy(data):
    n=len(data)
    return round(-sum((v/n)*math.log2(v/n) for v in Counter(data).values()),5) if n else 0


def container_frames(path):
    """Observed framing only: 24-byte prefix, then ID/type/size headers.

    Decode bounded zlib blocks in RAM, never reconstruct/export original files.
    Unknown fields are deliberately left unnamed rather than called event IDs.
    """
    size=path.stat().st_size;offset=24;count=0;types=Counter();codecs=Counter();classes=Counter();identities=set();parts=Counter()
    stored=expanded=0;sampled=0;errors=[]
    with path.open('rb') as stream:
        while offset+24<=size:
            stream.seek(offset);header=stream.read(24);kind,length=struct.unpack_from('<II',header,16)
            if length<56 or length>2*1024*1024 or offset+24+length>size:
                errors.append('frame_bounds_or_limit');break
            body=stream.read(length);payload_size=struct.unpack_from('<I',body,52)[0]
            if payload_size!=length-56:
                errors.append('payload_length_mismatch');break
            part,codec=struct.unpack_from('<II',body,44);data=body[56:]
            if codec==1:
                try:
                    decoder=zlib.decompressobj();plain=decoder.decompress(data,2*1024*1024)
                    if not decoder.eof or decoder.unconsumed_tail or decoder.unused_data:
                        errors.append('zlib_incomplete_or_limit');break
                except zlib.error:
                    errors.append('zlib_decode_error');break
            elif codec==0:plain=data
            else:
                errors.append('unknown_codec');break
            count+=1;types[kind]+=1;codecs[codec]+=1;identities.add(body[:16]);parts[part]+=1
            stored+=len(data);expanded+=len(plain)
            if part==1 and sampled<64:
                sampled+=1
                headers=BytesHeaderParser().parsebytes(plain[:16384]);names={k.lower() for k in headers.keys()}
                if len(names&{'date','from','subject'})>=2:classes['email_header_payload']+=1
                elif plain.startswith(b'PK\x03\x04') and b'[Content_Types].xml' in plain[:128]:classes['office_package_payload']+=1
                elif plain.startswith(b'%PDF-'):classes['pdf_payload']+=1
                else:classes['other_or_continuation']+=1
            offset+=24+length
    return {'complete_to_eof':offset==size,'frames':count,'frame_types':dict(types),'codecs':dict(codecs),
            'stored_payload_bytes':stored,'decoded_payload_bytes':expanded,
            'stored_to_decoded_ratio':round(stored/max(1,expanded),5),'body_identifier_distinct':len(identities),
            'counter_field_one':parts[1],'counter_field_max':max(parts,default=0),
            'sampled_counter_one_blocks':sampled,'sampled_payload_classification':dict(classes),'errors':errors,
            'limits':['Frame is not an audit event; object/part meaning is inferred, not a vendor specification',
                      'Only up to 64 first-counter blocks classified per file; no mail values/content or documents exported']}


def artifacts(root):
    result=[]
    for path in sorted(root.iterdir()):
        if not path.is_file():continue
        before=path.stat();size=before.st_size;digest=hashlib.sha256();positions=[];markers=0;tail=b''
        with path.open('rb') as stream:
            header=stream.read(96);stream.seek(0)
            # The supplied filenames name 2024-09-19; only match that observed
            # integer as a structural candidate, never treat it as event count.
            pattern=struct.pack('<II',20240919,20240919);offset=0
            while chunk:=stream.read(1024*1024):
                digest.update(chunk);data=tail+chunk;start=0
                while True:
                    index=data.find(pattern,start)
                    if index<0:break
                    absolute=offset-len(tail)+index
                    # Previous tail is shorter than the pattern, so each full
                    # match is found exactly once, including chunk boundaries.
                    markers+=1
                    if len(positions)<128:positions.append(absolute)
                    start=index+len(pattern)
                tail=data[-7:];offset+=len(chunk)
            samples=[]
            for offset in sorted({0,max(0,size//4),max(0,size//2),max(0,size*3//4),max(0,size-65536)}):
                stream.seek(offset);data=stream.read(65536)
                samples.append({'offset':offset,'bytes':len(data),'entropy_bits_per_byte':entropy(data),
                                'zlib6_ratio':round(len(zlib.compress(data,6))/len(data),5) if data else None})
        frames=container_frames(path)
        after=path.stat()
        result.append({'name':path.name,'suffix':path.suffix,'bytes':size,'sha256':digest.hexdigest(),
                       'header_first_48_hex':header[:48].hex(),'date_pattern_candidates':markers,
                       'first_date_pattern_offsets':positions[:8],
                       'first_date_pattern_spacing':[b-a for a,b in zip(positions,positions[1:])][:12],
                       'samples':samples,'framing':frames,'source_stat_unchanged':(before.st_size,before.st_mtime_ns)==(after.st_size,after.st_mtime_ns)})
    return {'files':result,'bytes':sum(r['bytes'] for r in result),
            'limitations':['Proprietary fields not fully specified: frames/date hits are not decoded audit events, machines or users',
                           'Codec-1 blocks are verified bounded zlib; high-entropy bytes alone do not prove encryption',
                           'Payload classifications do not establish event-log scope or original endpoint count',
                           'Bounded payload blocks decoded only in RAM; no employee document/mail was reconstructed, exported or executed']}


def category(path):
    p=ntpath.normcase(ntpath.normpath(path or ''))
    if not path:return 'no_path'
    if '\\workspace\\ipguard\\' in p or '\\guarddesk' in p:return 'guarddesk_or_development'
    if '\\appdata\\local\\google\\chrome\\' in p or '\\appdata\\local\\microsoft\\edge\\' in p:return 'browser_profile_and_cache'
    if '\\programdata\\microsoft\\search\\' in p:return 'windows_search_index'
    if '\\appdata\\local\\temp\\' in p or p.startswith('c:\\windows\\temp\\'):return 'temporary_files'
    if '\\appdata\\' in p:return 'other_appdata'
    if p.startswith('\\\\'):return 'network_path'
    if any(part in p for part in ('\\documents\\','\\desktop\\','\\downloads\\','\\onedrive')):return 'user_document_locations'
    if p.startswith('c:\\windows\\') or p.startswith(('c:\\program files\\','c:\\program files (x86)\\')):return 'windows_or_program_files'
    if '\\programdata\\' in p:return 'other_programdata'
    return 'other_paths'


def database(path,sample_limit):
    before=path.stat();started=time.monotonic()
    db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=2);db.row_factory=sqlite3.Row
    db.execute('PRAGMA query_only=ON');db.execute('PRAGMA cache_size=-4096')
    deadline=time.monotonic()+90
    db.set_progress_handler(lambda: int(time.monotonic()>deadline),10000)
    report={'source_name':path.name,'source_label':'workspace historical database; not office Server live database',
            'database_bytes':before.st_size,'sqlite_runtime':sqlite3.sqlite_version,'sample_limit_per_kind':sample_limit}
    try:
        report['page_size']=db.execute('PRAGMA page_size').fetchone()[0]
        report['page_count']=db.execute('PRAGMA page_count').fetchone()[0]
        report['free_pages']=db.execute('PRAGMA freelist_count').fetchone()[0]
        report['wal_bytes']=Path(str(path)+'-wal').stat().st_size if Path(str(path)+'-wal').exists() else 0
        report['devices']=[{'name':r['name'],'inventory_agent_version':json.loads(r['inventory'] or '{}').get('agent_version')} for r in db.execute('SELECT name,inventory FROM devices')]
        report['events_by_kind']=[dict(r) for r in db.execute('SELECT kind,count(*) records,sum(length(CAST(details AS BLOB))) detail_bytes FROM events NOT INDEXED GROUP BY kind ORDER BY records DESC')]
        columns=['event_id','device_id','kind','severity','details','prev_hash','hash']
        report['text_column_bytes']=dict(zip(columns,db.execute('SELECT '+','.join('sum(length(CAST('+name+' AS BLOB)))' for name in columns)+' FROM events NOT INDEXED').fetchone()))
        report['event_indexes']=[r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='events'")]
        report['events']=sum(r['records'] for r in report['events_by_kind'])
        report['physical_bytes_per_event']=round(before.st_size/max(1,report['events']),2)
        report['daily']=[dict(r) for r in db.execute("SELECT strftime('%Y-%m-%d',occurred,'unixepoch','+8 hours') day,count(*) records FROM events GROUP BY day ORDER BY day")]
        try:
            report['physical_objects']=[dict(r) for r in db.execute('SELECT name,sum(pgsize) bytes,sum(payload) payload_bytes,sum(unused) unused_bytes,count(*) pages FROM dbstat GROUP BY name ORDER BY bytes DESC')]
        except sqlite3.OperationalError as exc:report['physical_objects_unavailable']=str(exc)
        report['samples']=[]
        for item in report['events_by_kind']:
            if item['records']<100 or not item['kind'].startswith(('file.','application.')):continue
            buckets=Counter();processes=Counter();sources=Counter();keys=Counter();lines=bytearray();per_row_zlib=0;logical_bytes=0;records=0;min_time=None;max_time=None
            for row in db.execute('SELECT * FROM events WHERE kind=? ORDER BY id DESC LIMIT ?',(item['kind'],sample_limit)):
                details=json.loads(row['details']);records+=1
                event_path=details.get('source_path') or details.get('path') or '';buckets[category(event_path)]+=1
                process=details.get('process') or (details.get('path') if row['kind'].startswith('application.') else '') or ''
                processes[ntpath.basename(process) or '(missing)']+=1;sources[details.get('source') or '(missing)']+=1
                semantic=[row['device_id'],row['kind'],row['severity'],details.get('user'),process,details.get('process_id'),details.get('parent_process_id'),event_path,details.get('destination_path'),details.get('url'),details.get('source'),int(row['occurred'])]
                keys[hashlib.sha256(json.dumps(semantic,ensure_ascii=False,sort_keys=True).encode()).digest()]+=1
                full=dict(row);full['details']=details
                line=json.dumps(full,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()+b'\n'
                logical_bytes+=len(line);per_row_zlib+=len(zlib.compress(line,6))
                # Keep a strict 8 MiB compression sample; no raw bytes leave RAM.
                if len(lines)+len(line)<=8*1024*1024:lines.extend(line)
                min_time=row['occurred'] if min_time is None else min(min_time,row['occurred']);max_time=row['occurred'] if max_time is None else max(max_time,row['occurred'])
            report['samples'].append({'kind':item['kind'],'records':records,'occurred_min':min_time,'occurred_max':max_time,
                'path_categories':dict(buckets),'process_basenames':processes.most_common(12),'sources':dict(sources),
                'same_second_semantic_repeat_candidates':sum(n-1 for n in keys.values()),
                'logical_bytes':logical_bytes,'per_row_zlib_ratio':round(per_row_zlib/max(1,logical_bytes),5),
                'block_zlib_sample_bytes':len(lines),'block_zlib_ratio':round(len(zlib.compress(lines,6))/max(1,len(lines)),5)})
        report['elapsed_seconds']=round(time.monotonic()-started,2)
    finally:db.close()
    after=path.stat();report['source_stat_unchanged']=(before.st_size,before.st_mtime_ns)==(after.st_size,after.st_mtime_ns)
    report['limitations']=['Historical workspace DB does not establish current office Server daily growth or 250-agent capacity',
                           'Per-kind latest-row samples are not a random all-day sample; repeat candidates can include real repeated operations',
                           'Compression ratios are in-memory metadata experiments, not an implemented searchable compressed schema',
                           'Only aggregate counts, categories and process basenames are exported; no employee paths or full events']
    return report


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--ipguard-directory',type=Path,required=True);parser.add_argument('--db',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--sample-limit',type=int,default=5000)
    args=parser.parse_args()
    if not 1<=args.sample_limit<=10000:raise ValueError('Sample limit must be 1..10000')
    output={'created_at':dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),
            'ipguard':artifacts(args.ipguard_directory.resolve()),'guarddesk':database(args.db.resolve(),args.sample_limit)}
    args.output.parent.mkdir(exist_ok=True,parents=True)
    with args.output.open('x',encoding='utf-8') as stream:json.dump(output,stream,ensure_ascii=False,indent=2)
    print(json.dumps({'ipguard_bytes':output['ipguard']['bytes'],'guarddesk_bytes':output['guarddesk']['database_bytes'],
                      'guarddesk_events':output['guarddesk']['events'],'source_unchanged':output['guarddesk']['source_stat_unchanged'],'report':str(args.output)},ensure_ascii=False))


if __name__=='__main__':main()
