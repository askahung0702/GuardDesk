"""Unprivileged real DLL ABI/poll check, no trace start or installation."""
import ctypes,hashlib,json,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk.document_io import NativeTrace


def main():
    trace=NativeTrace();addresses=set();start=time.perf_counter()
    try:
        for _ in range(10000):
            assert trace.poll()==[]
            assert not trace.active and all(trace.stats[k]==0 for k in ('dropped','schema_unresolved','completed','consumer_result'))
            addresses.add(ctypes.addressof(trace._poll_buffer))
        assert len(addresses)==1
        result={'passed':True,'version':'0.4.55','scope':'real_local_DLL_ABI_and_unstarted_empty_poll_only_not_completed_OS_events',
                'polls':10000,'transfer_buffer_allocations':len(addresses),'transfer_bytes':ctypes.sizeof(trace._poll_buffer),
                'elapsed_seconds':round(time.perf_counter()-start,4),'trace_started':False,'admin_required':False,'office_changed':False,
                'fresh_privileged_ETW_fixture_accepted':False,'dll_sha256':hashlib.sha256((ROOT/'guarddesk/windows/native/GuardDeskFileTrace.dll').read_bytes()).hexdigest(),
                'wrapper_sha256':hashlib.sha256((ROOT/'guarddesk/document_io.py').read_bytes()).hexdigest()}
    finally:trace.stop()
    (ROOT/'evidence/native-poll-buffer-contract-0.4.55.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result))


if __name__=='__main__':main()
