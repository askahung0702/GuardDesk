"""Owned HTTP ingestion comparison; automatic backfill/tail, no search trigger.

250 logical device identities, eight concurrent HTTP senders, not 250 physical
endpoints. Reports timings instead of claiming workstation results are an SLA.
"""
import concurrent.futures,contextlib,hashlib,json,shutil,sqlite3,sys,tempfile,threading,time,urllib.request
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk import __version__,audit_search,audit_search_index as index,event_storage as storage
from guarddesk.server import serve
from guarddesk.store import Store,canonical,digest
from guarddesk.performance import ProcessSampler

HISTORY=12000;SENDERS=8;BATCHES=30;ROWS=25;INTERVAL=.2

class IdleWorker:
    error=''
    thread=threading.Thread()
    def close(self):pass

def percentile(values,p):return round(sorted(values)[min(len(values)-1,int((len(values)-1)*p))]*1000,3)

def scenario(root,enabled,profile):
    batches,interval=(30,.2) if profile=='burst' else (12,.8)
    root.mkdir();store=Store(root/'control.sqlite3')
    with store.connect() as db:
        for i in range(250):db.execute('INSERT INTO devices(id,token,name,department,last_seen) VALUES(?,?,?,?,?)',(f'owned-{i}',digest(f'owned-token-{i}'),f'Owned-{i}','Synthetic',time.time()))
        for i in range(HISTORY):Store.event(db,f'owned-{i%250}','file.deleted','info',{'path':f'C:\\Owned\\History-{i}\\ordinary.txt'},f'history-{i}')
    with store.connect() as db:
        storage.enable(db,store.path,snapshot_backup=False)
        last=storage.head(db)[0];db.execute('UPDATE audit_search_state SET low_id=?,high_id=?,indexed_rows=0',(last+1,last))
    with patch('guarddesk.audit_search_index.Worker',index.Worker if enabled else lambda _:IdleWorker()),patch('guarddesk.bundled_release.Publisher.start'):
        server=serve(store.path,port=0)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    url=f'http://127.0.0.1:{server.server_port}';started=time.perf_counter();cpu=time.process_time();samples=[];observed=[];errors=[];stop=threading.Event();sampler=ProcessSampler()
    def monitor():
        while not stop.wait(.1):
            samples.append(sampler.sample())
            with server.store.connect(flush_events=False) as db:
                s=index.state(db);s.update(head=storage.head(db)[0],seconds=time.perf_counter()-started)
                observed.append(s)
    monitoring=threading.Thread(target=monitor,daemon=True);monitoring.start();barrier=threading.Barrier(SENDERS)
    def payload(sender,n):
        return {'events':[{'event_id':f'upload-{sender}-{n}-{i}','kind':'application.started' if i%2 else 'file.deleted','severity':'info','occurred':time.time(), 'details':{'process':'C:\\Owned\\tool.exe','pid':i%5} if i%2 else {'path':f'C:\\Owned\\26C0018-{sender}-{n}-{i}.txt'}} for i in range(ROWS)]}
    def send(opener,body,device):
        req=urllib.request.Request(url+'/api/agent/events',data=canonical(body).encode(),headers={'Content-Type':'application/json','Authorization':f'Bearer owned-token-{device}'})
        before=time.perf_counter()
        with opener.open(req,timeout=15) as response:reply=json.load(response)
        assert reply['accepted']==[e['event_id'] for e in body['events']]
        return time.perf_counter()-before
    def sender(number):
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));times=[];barrier.wait();base=time.perf_counter()
        for n in range(batches):
            delay=base+n*interval+(number*interval/SENDERS if profile=='steady' else 0)-time.perf_counter()
            if delay>0:time.sleep(delay)
            try:times.append(send(opener,payload(number,n),(n*SENDERS+number)%250))
            except Exception as exc:errors.append(type(exc).__name__+': '+str(exc))
        return times
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=SENDERS) as pool:latencies=[t for group in pool.map(sender,range(SENDERS)) for t in group]
        receive_seconds=time.perf_counter()-started;receive_cpu=time.process_time()-cpu
        with server.store.connect(flush_events=False) as db:
            after=storage.head(db);at_ack=index.state(db);counts=db.execute("SELECT count(*) FROM events WHERE event_id LIKE 'upload-%'").fetchone()[0]
        assert not errors and counts==SENDERS*batches*ROWS,(errors,counts)
        # ACK was durable: a duplicate upload cannot append a second event.
        send(urllib.request.build_opener(urllib.request.ProxyHandler({})),payload(0,0),0)
        with server.store.connect(flush_events=False) as db:assert storage.head(db)==after
        tail_seconds=None;complete_seconds=None
        if enabled:
            deadline=time.monotonic()+120
            while time.monotonic()<deadline:
                with server.store.connect(flush_events=False) as db:
                    s=index.state(db);ready,_=index.ready(db,'',())
                if s['high_id']==after[0] and tail_seconds is None:tail_seconds=time.perf_counter()-started-receive_seconds
                if ready:complete_seconds=time.perf_counter()-started-receive_seconds;break
                time.sleep(.1)
            assert complete_seconds is not None,(s,server.search_index.error)
            with server.store.connect(flush_events=False) as db:
                q=time.perf_counter();ids,_=audit_search.identifiers(db,'',(),'','26C0018',51,indexed=True);query_ms=(time.perf_counter()-q)*1000
                assert len(ids)==51
        else:query_ms=None
        verification=server.store.verify();assert verification['valid'] and verification['checked']==HISTORY+counts,verification
        stop.set();monitoring.join(5)
        with server.store.connect(flush_events=False) as db:
            final=index.state(db);docs=db.execute('SELECT count(*) FROM audit_search_documents').fetchone()[0]
            assert storage.head(db)==after
        return {'index_enabled':enabled,'http_requests':len(latencies),'new_events':counts,'history_events':HISTORY,'logical_devices':250,'concurrent_http_senders':SENDERS,'profile':profile,'target_requests_per_second':SENDERS/interval,'batch_size':ROWS,'ack_ms':{'p50':percentile(latencies,.5),'p95':percentile(latencies,.95),'p99':percentile(latencies,.99),'max':round(max(latencies)*1000,3)},'receive_seconds':round(receive_seconds,3),'receive_process_cpu_seconds':round(receive_cpu,3),'http_errors':errors,'source_chain':verification,'duplicate_upload_appended':False,'state_at_last_ack':at_ack,'state_final':final,'tail_caught_up_seconds_after_uploads':round(tail_seconds,3) if tail_seconds is not None else None,'all_history_ready_seconds_after_uploads':round(complete_seconds,3) if complete_seconds is not None else None,'indexed_search_ms':round(query_ms,3) if query_ms is not None else None,'distinct_documents':docs,'total_process_cpu_seconds':round(time.process_time()-cpu,3),'peak_sampled_working_set_bytes':max((s.get('working_set_bytes',0) for s in samples),default=0),'progress_samples':observed,'queries_triggered_index':False}
    finally:
        stop.set();monitoring.join(5);server.shutdown();server.server_close();thread.join(5)

def main():
    source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),ROOT/'guarddesk/audit_search_index.py',ROOT/'guarddesk/store.py',ROOT/'guarddesk/server.py']}
    runtime=ROOT/'runtime';runtime.mkdir(exist_ok=True);assert shutil.disk_usage(runtime).free>2*1024**3
    with tempfile.TemporaryDirectory(dir=runtime,prefix='automatic-index-') as temp:
        owned=Path(temp).resolve();assert owned.parent==runtime.resolve() and owned.name.startswith('automatic-index-')
        results=[]
        for profile in ('burst','steady'):
            for enabled in (False,True):
                name=profile+('-automatic' if enabled else '-baseline')
                print('Scenario '+name,flush=True);result=scenario(owned/name,enabled,profile);results.append(result)
                base=owned/name
                result['storage_bytes_after_close']={'control':(base/'control.sqlite3').stat().st_size,'daily':sum(p.stat().st_size for p in (base/'AuditData').rglob('*') if p.is_file()),'control_wal':(base/'control.sqlite3-wal').stat().st_size if (base/'control.sqlite3-wal').exists() else 0}
                print(json.dumps({k:v for k,v in result.items() if k!='progress_samples'},ensure_ascii=False),flush=True)
        report={'passed':True,'version':__version__,'scenarios':results,'source_sha256':source_sha256,'no_office_database_read':True,'no_live_endpoints_changed':True,'limits':['Source Python, loopback HTTP, one developer Windows workstation; not office Server or 250 physical endpoints','Eight senders cycle through 250 synthetic identities: burst target 40 requests/sec, steady target 10 requests/sec with staggered arrivals, 25 events/batch; not 250 simultaneous connections','Baseline then automatic, same process; cache/order effects apply; sampled memory is whole-process, not isolated index allocation','Includes durable staging/daily flush, hash verification and duplicate replay; no fault injected into production','CPU/memory/disk can still compete; sustained busy ingestion deliberately postpones index work; no universal latency guarantee']}
        (ROOT/f'evidence/automatic-index-performance-{__version__}.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('PASSED',flush=True)

if __name__=='__main__':main()
