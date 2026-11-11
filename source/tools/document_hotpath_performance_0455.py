"""Compare identical metadata workload against immutable 0.4.54 sources.

This microbenchmark isolates parsing/allocation cost, not OS ETW or user lag.
"""
import ctypes,hashlib,json,statistics,sys,time,types,zipfile
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk import file_access as current
from guarddesk.document_io import NativeTrace


def main():
    old={}
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.54-source.zip') as archive:
        for name in ('file_access','document_io'):
            module=types.ModuleType('guarddesk.sealed054_'+name);module.__package__='guarddesk'
            exec(compile(archive.read('guarddesk/'+name+'.py'),'sealed-054/'+name+'.py','exec'),module.__dict__)
            old[name]=module
    rules=[current.PROCESS+'background-'+str(i)+'.exe' for i in range(32)]
    rules+=['C:\\Excluded\\'+str(i) for i in range(32)]
    item={'path':r'C:\Owned\file.txt','process_id':123456,'process':r'C:\Apps\notepad.exe',
          'process_identity_status':'creation_time_checked','process_session_id':1,'object_type':'file','evidence':'completed_native_read'}
    def filters(cls):
        f=cls();start=time.perf_counter();cpu=time.process_time();kept=0
        for _ in range(10000):kept+=f.check(dict(item),rules) is None
        assert kept==10000
        return {'seconds':time.perf_counter()-start,'cpu_seconds':time.process_time()-cpu,'retained':kept}
    def polls(cls):
        trace=object.__new__(cls);trace.mappings=[];calls=0
        def poll(data,size,stats):
            nonlocal calls
            calls+=1
            for i in range(4):stats[i]=0
            return 0
        def aux(data,size):data[0]=0;data[1]=0;return 0
        trace.api=SimpleNamespace(gd_trace_poll=poll,gd_trace_aux_stats=aux)
        start=time.perf_counter();cpu=time.process_time()
        for _ in range(20000):assert trace.poll()==[]
        assert calls==20000
        return {'seconds':time.perf_counter()-start,'cpu_seconds':time.process_time()-cpu,'polls':calls}
    rows={'sealed_054':{'filters':[],'idle_polls':[]},'candidate_055':{'filters':[],'idle_polls':[]}}
    for trial in range(3):
        sequence=[('sealed_054',old['file_access'].Filter,old['document_io'].NativeTrace),('candidate_055',current.Filter,NativeTrace)]
        if trial%2:sequence.reverse()
        for label,filter_type,trace_type in sequence:
            rows[label]['filters'].append(filters(filter_type));rows[label]['idle_polls'].append(polls(trace_type))
    medians={label:{kind:statistics.median(r['seconds'] for r in runs) for kind,runs in cases.items()} for label,cases in rows.items()}
    result={'passed':True,'version':'0.4.55','scope':'identical_synthetic_metadata_no_actual_ETW_or_foreground_acceptance',
            'rounds':rows,'median_seconds':medians,'improvement_percent':{kind:round((1-medians['candidate_055'][kind]/medians['sealed_054'][kind])*100,2) for kind in ('filters','idle_polls')},
            'native_transfer_bytes':ctypes.sizeof(NativeTrace.Record)*256,'new_idle_buffer_allocations_per_trace':1,
            'source_sha256':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in ('guarddesk/file_access.py','guarddesk/document_io.py','guarddesk/document_context.py','guarddesk/document_worker.py')},
            'office_changed':False,'full_endpoint_performance_accepted':False}
    (ROOT/'evidence/document-hotpath-performance-0.4.55.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result))


if __name__=='__main__':main()
