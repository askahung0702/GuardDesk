"""Completed native I/O metadata and conservative copy candidates.

Copy correlation is NOT a CopyFile API attestation or content equality check.
Unknown PID, ambiguous source, failed/pending I/O and gaps never become a copy.
"""
import collections
import ctypes
import hashlib
import json
import ntpath
import os
import time
from pathlib import Path
from .document_settings import covers,validate


class CopyCorrelator:
    def __init__(self,emit,clock=time.monotonic):
        self.emit=emit;self.clock=clock;self.reads=collections.OrderedDict();self.sent=collections.OrderedDict();self.ambiguous=0

    def gap(self):self.reads.clear();self.sent.clear()

    def feed(self,event):
        now=self.clock()
        for mapping,ttl in ((self.reads,10),(self.sent,60)):
            while mapping and now-next(iter(mapping.values()))['seen']>ttl:mapping.popitem(last=False)
        if event.get('status')!=0 or type(event.get('pid')) is not int or event['pid']<=4 or type(event.get('bytes')) is not int or not 0<event['bytes']<=2**32 or type(event.get('offset')) is not int or not 0<=event['offset']<2**63:return
        path=ntpath.normcase(event['path']);pid=event['pid'];offset=event['offset'];length=event['bytes']
        if event['op']=='read':
            key=(pid,path,offset)
            self.reads.pop(key,None);self.reads[key]={'seen':now,**event}
            while len(self.reads)>1024:self.reads.popitem(last=False)
            return
        if event['op']!='write':return
        matches=[r for (p,s,o),r in self.reads.items() if p==pid and s!=path and o<=offset and offset+length<=o+r['bytes']]
        same_thread=[r for r in matches if event.get('tid') and r.get('tid')==event['tid']]
        if same_thread:matches=same_thread
        sources={ntpath.normcase(r['path']) for r in matches}
        if len(sources)!=1:
            if sources:self.ambiguous+=1
            return
        source=matches[-1];key=(pid,next(iter(sources)),path)
        # Consume the matched read range even for a deduplicated pair. Keeping
        # old ranges would make the next sequential copy falsely ambiguous.
        for read in matches:self.reads.pop((pid,ntpath.normcase(read['path']),read['offset']),None)
        if key in self.sent:return
        self.sent[key]={'seen':now}
        while len(self.sent)>2048:self.sent.popitem(last=False)
        self.emit({'path':source['path'],'source_path':source['path'],'destination_path':event['path'],'process_id':pid,'thread_id':event.get('tid'),
                   'source':'windows_etw_file_io','evidence':'completed_io_range_candidate','offset':offset,'matched_bytes':length,
                   'operation_confirmed':False,'content_compared':False,'coverage':'partial_range_not_whole_file','user':None},event.get('occurred',time.time()))


class ReadObserver:
    """One observation per native open lifetime; bounded metadata.

    Multiple read buffers are not multiple human opens. A new observed open ID
    is distinct even when the same process reopens the same file immediately.
    """
    def __init__(self,emit,clock=time.monotonic,resolver=None):
        self.emit=emit;self.clock=clock;self.resolver=resolver;self.seen=collections.OrderedDict();self.pending=collections.OrderedDict()
        self.observed=0;self.open_observations=0;self.read_observations=0;self.pending_overflow=0;self.lifecycle_evictions=0
    def gap(self):self.seen.clear();self.pending.clear()
    def tick(self):
        now=self.clock()
        while self.pending and now-next(iter(self.pending.values()))[0]>=1:
            key,(_,event)=self.pending.popitem(last=False)
            if key not in self.seen:self.observe(key,event,now,False)
    def observe(self,key,event,now,read):
        self.seen[key]=now
        while len(self.seen)>4096:self.seen.popitem(last=False);self.lifecycle_evictions+=1
        self.observed+=1
        if read:self.read_observations+=1
        else:self.open_observations+=1
        details={'path':event['path'],'process_id':event['pid'],'thread_id':event.get('tid'),
                 'source':'windows_etw_file_io','evidence':'completed_native_read' if read else 'completed_native_open',
                 'user':None,'human_read_confirmed':False,'deduplication':'observed_open_lifetime','native_open_id':event.get('open_id',0)}
        if read:details['read_bytes']=event['bytes']
        else:details['read_confirmed']=False
        if event.get('non_directory_confirmed'):details['object_type']='file';details['object_type_evidence']='native_non_directory_option'
        if self.resolver:details.update(self.resolver.resolve(event))
        self.emit(details,event.get('occurred',time.time()))
    def feed(self,event):
        if event.get('op')=='close':
            key=(event.get('pid'),ntpath.normcase(event['path']),event.get('open_id',0))
            pending=self.pending.pop(key,None)
            if pending and key not in self.seen:self.observe(key,pending[1],self.clock(),False)
            self.seen.pop(key,None)
            return
        if event.get('op') not in ('read','open') or event.get('status')!=0 or type(event.get('pid')) is not int or event['pid']<=4:return
        if event['op']=='read' and (type(event.get('bytes')) is not int or event['bytes']<=0):return
        now=self.clock()
        key=(event['pid'],ntpath.normcase(event['path']),event.get('open_id',0))
        if key in self.seen:return
        if event['op']=='open':
            if key not in self.pending:
                self.pending[key]=(now,dict(event))
                if len(self.pending)>4096:self.pending.popitem(last=False);self.pending_overflow+=1
            return
        self.pending.pop(key,None);self.observe(key,event,now,True)


class NativeTrace:
    class Record(ctypes.Structure):
        _fields_=[('time',ctypes.c_uint64),('offset',ctypes.c_uint64),('bytes',ctypes.c_uint64),('pid',ctypes.c_uint32),('tid',ctypes.c_uint32),('op',ctypes.c_uint32),('status',ctypes.c_uint32),('open_id',ctypes.c_uint64),('path',ctypes.c_wchar*512)]

    def __init__(self,dll=None):
        if os.name!='nt':raise OSError('Windows ETW required')
        dll=Path(dll) if dll else Path(__file__).with_name('windows')/'native/GuardDeskFileTrace.dll'
        import sys
        if getattr(sys,'frozen',False):
            from .update_native import protected_tree
            protected_tree(dll.parent,recursive=False);protected_tree(dll);protected_tree(dll.with_name('document-trace-build.json'))
        metadata=json.loads(dll.with_name('document-trace-build.json').read_text(encoding='utf-8'))
        if hashlib.sha256(dll.read_bytes()).hexdigest()!=metadata['dll_sha256']:raise OSError('Native trace binary integrity mismatch')
        self.api=ctypes.WinDLL(str(dll));self.api.gd_trace_record_size.restype=ctypes.c_uint32
        if self.api.gd_trace_record_size()!=ctypes.sizeof(self.Record):raise OSError('Native trace ABI mismatch')
        if not hasattr(self.api,'gd_trace_lifecycle_version'):raise OSError('Native trace open-lifetime capability missing; upgrade complete native component')
        self.api.gd_trace_lifecycle_version.restype=ctypes.c_uint32
        if self.api.gd_trace_lifecycle_version()!=1:raise OSError('Unsupported native open-lifetime version')
        if not hasattr(self.api,'gd_trace_aux_stats'):raise OSError('Native trace completed-open capability missing; upgrade complete native component')
        self.api.gd_trace_aux_stats.argtypes=[ctypes.POINTER(ctypes.c_uint64),ctypes.c_uint32];self.api.gd_trace_aux_stats.restype=ctypes.c_uint32
        self.api.gd_trace_start.argtypes=[ctypes.POINTER(ctypes.c_wchar_p),ctypes.c_uint32];self.api.gd_trace_start.restype=ctypes.c_uint32
        self.api.gd_trace_start_filtered.argtypes=[ctypes.POINTER(ctypes.c_wchar_p),ctypes.c_uint32,ctypes.POINTER(ctypes.c_wchar_p),ctypes.c_uint32];self.api.gd_trace_start_filtered.restype=ctypes.c_uint32
        self.api.gd_trace_poll.argtypes=[ctypes.POINTER(self.Record),ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint64)];self.api.gd_trace_poll.restype=ctypes.c_uint32
        self.api.gd_trace_stop.argtypes=[];self.api.gd_trace_stop.restype=ctypes.c_uint32
        self.active=False;self.mappings=[];self.stats={}

    def start(self,rules):
        validate(rules)
        return self._start_paths([r['path'] for r in rules])

    def start_policy(self,policy,watch,runtime=None):
        from .document_scope import paths,early_exclusions
        return self._start_paths(paths(policy,watch),early_exclusions(policy,runtime),skip_unsupported=policy['scope']=='all_local')

    def _start_paths(self,paths,exclusions=(),skip_unsupported=False):
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.QueryDosDeviceW.argtypes=[ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_uint32];kernel.QueryDosDeviceW.restype=ctypes.c_uint32
        kernel.GetDriveTypeW.argtypes=[ctypes.c_wchar_p];kernel.GetDriveTypeW.restype=ctypes.c_uint32
        selected=[];self.mappings=[];self.unsupported_volumes=0
        def device_path(path):
            drive,tail=ntpath.splitdrive(path);buffer=ctypes.create_unicode_buffer(32768)
            if not kernel.QueryDosDeviceW(drive,buffer,len(buffer)):raise ctypes.WinError(ctypes.get_last_error())
            device=buffer.value
            from .document_scope import local_device
            if kernel.GetDriveTypeW(drive+'\\')!=3 or not local_device(device):raise OSError('ETW volume mapping is not supported for this local drive')
            if (device,drive) not in self.mappings:self.mappings.append((device,drive))
            return device+tail.rstrip('\\')
        for path in paths:
            try:selected.append(device_path(path))
            except OSError:
                if not skip_unsupported:raise
                self.unsupported_volumes+=1
        rejected=[]
        for path in exclusions:
            if len(ntpath.splitdrive(path)[0])!=2:continue
            try:
                value=device_path(path.casefold())
                if len(value)<=510:rejected.append(value)
            except OSError:continue # authoritative exclusion still applies before queueing
        if not selected:return
        from .process_audit import security_privilege
        try:
            with security_privilege(ctypes.WinDLL('advapi32',use_last_error=True),'SeSystemProfilePrivilege'):
                code=self.api.gd_trace_start_filtered((ctypes.c_wchar_p*len(selected))(*selected),len(selected),(ctypes.c_wchar_p*len(rejected))(*rejected),len(rejected))
                if not code:self.active=True
        except OSError:
            self.stop();raise
        if code:raise ctypes.WinError(code)

    def poll(self):
        # Single consumer, fixed ABI. Reuse the 274 KiB transfer buffer even
        # during idle polls; only the returned count is valid on each call.
        if not hasattr(self,'_poll_buffer'):
            self._poll_buffer=(self.Record*256)();self._poll_stats=(ctypes.c_uint64*4)();self._poll_aux=(ctypes.c_uint64*2)()
        data=self._poll_buffer;stats=self._poll_stats;aux=self._poll_aux
        count=self.api.gd_trace_poll(data,256,stats)
        if count>256:raise OSError('Native trace result invalid')
        self.stats=dict(zip(('dropped','schema_unresolved','completed','consumer_result'),stats));events=[]
        if self.api.gd_trace_aux_stats(aux,2):raise OSError('Native trace statistics unavailable')
        self.stats.update(merged_completed_ranges=aux[0],coalesced_opens_1s=aux[1])
        self.stats['unsupported_volumes']=getattr(self,'unsupported_volumes',0)
        for index in range(count):
            record=data[index]
            path=record.path
            for device,drive in self.mappings:
                if path.casefold().startswith(device.casefold()+'\\'):path=drive+path[len(device):];break
            if not ntpath.splitdrive(path)[0]:continue
            if record.op not in (64,66,67,68):continue
            events.append({'path':path,'pid':record.pid,'tid':record.tid,'open_id':record.open_id,'offset':record.offset,'bytes':record.bytes,'status':record.status,'op':{64:'open',66:'close',67:'read',68:'write'}[record.op],'non_directory_confirmed':record.op==64 and record.bytes==1,'occurred':record.time/10000000-11644473600})
        return events

    def stop(self):
        if self.active:
            code=self.api.gd_trace_stop()
            if code not in (0,4201):raise ctypes.WinError(code)
            self.active=False
