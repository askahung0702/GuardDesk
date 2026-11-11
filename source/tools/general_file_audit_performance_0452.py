"""Bounded correlator cost, not a substitute for company ETW/Defender testing."""
import hashlib,json,sys,time,tracemalloc,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk.document_io import CopyCorrelator,ReadObserver


def main():
    emitted=0
    def emit(d,t):
        nonlocal emitted
        emitted+=1
    read_observations=[0]
    def observe(d,t):read_observations[0]+=1
    reader=ReadObserver(observe,clock=lambda:now)
    now=0;correlator=CopyCorrelator(emit,clock=lambda:now)
    tracemalloc.start();cpu=time.process_time();start=time.perf_counter()
    for i in range(50000):
        now=i*.001
        e={'path':r'C:\Owned\source-'+str(i)+'.dat','pid':100+i%10,'tid':1000+i%10,'status':0,'op':'read','bytes':65536,'offset':0}
        reader.feed({**e,'open_id':i});correlator.feed(e);correlator.feed({**e,'op':'write','path':r'C:\Owned\target-'+str(i)+'.dat'})
    seconds=time.perf_counter()-start;cpu=time.process_time()-cpu;_,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
    assert emitted==50000 and len(correlator.reads)<=1024 and len(correlator.sent)<=2048
    from guarddesk.agent import Agent
    from guarddesk.document_queue import CandidateQueue,MAX_PENDING
    with tempfile.TemporaryDirectory(prefix='document-outbox-',dir=ROOT/'runtime') as d:
        agent=object.__new__(Agent);agent.state=Path(d)/'own.sqlite3'
        with agent.db() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.executescript('CREATE TABLE outbox(event_id TEXT PRIMARY KEY,payload TEXT,created REAL);CREATE TABLE state(key TEXT PRIMARY KEY,value TEXT);')
        queue=CandidateQueue(agent);queue.initialize();start_queue=time.perf_counter();latencies=[]
        for i in range(5000):
            queue.add({'path':r'C:\Owned\source.dat','destination_path':r'C:\Owned\target.dat','operation_confirmed':False,'sequence':i},i,kind='file.opened' if i%2 else 'file.copy_candidate')
            if (i+1)%64==0:
                tick=time.perf_counter();queue.flush();latencies.append(time.perf_counter()-tick)
        queue.flush()
        queue_seconds=time.perf_counter()-start_queue
        with agent.db() as db:
            pending=db.execute('SELECT count(*) FROM outbox').fetchone()[0]
            assert pending==MAX_PENDING
            suppressed=int(db.execute("SELECT value FROM state WHERE key='document_copy_overflow'").fetchone()[0]);assert suppressed==5000-MAX_PENDING
            db.execute('DELETE FROM outbox')
        restarted=CandidateQueue(agent);restarted.initialize();restarted.flush()
        with agent.db() as db:
            assert db.execute('SELECT count(*) FROM outbox').fetchone()[0]==1
            gap=json.loads(db.execute('SELECT payload FROM outbox').fetchone()[0]);assert gap['details']['suppressed_candidates']==suppressed
        admission={'synthetic_candidates':5000,'pending_cap':MAX_PENDING,'retained':pending,'suppressed_with_durable_counter':suppressed,'elapsed_seconds':round(queue_seconds,3),'max_batch_seconds':round(max(latencies),4),'ack_recovery_single_gap':True}
    result={'passed':True,'scope':'100000_synthetic_completed_io_metadata_events_and_owned_sqlite_admission','events':100000,'candidates':emitted,'read_observations':read_observations[0],'read_dedup_capacity':4096,'elapsed_seconds':round(seconds,3),'cpu_seconds':round(cpu,3),'python_peak_allocated_bytes':peak,'cache_limits':{'reads':1024,'candidate_dedup':2048},'outbox_admission':admission,'native_etw_defender_performance_accepted':False,'source_sha256':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ('guarddesk/document_scope.py','guarddesk/document_io.py','guarddesk/document_worker.py','guarddesk/document_queue.py','native/document_trace.cpp','guarddesk/document_sacl.py')}}
    (ROOT/'evidence/general-file-audit-performance-0.4.52.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result))


if __name__=='__main__':main()
