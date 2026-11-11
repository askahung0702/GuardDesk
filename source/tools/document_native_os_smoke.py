"""Admin-only acceptance on disposable own fixtures. No global audit changes.

Never opens installed enrollment/configuration, employee documents, browser
profiles, Defender settings, scheduled tasks, services, or network destinations.
"""
import ctypes,hashlib,json,os,shutil,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk.document_sacl import WindowsSacl,add_audit
from guarddesk.document_io import NativeTrace,CopyCorrelator
from guarddesk.document_settings import validate


def main():
    result={'admin_token':bool(ctypes.windll.shell32.IsUserAnAdmin()),'global_audit_policy_changed':False,'defender_changed':False,'live_enrollment_accessed':False,'scope':'own_disposable_fixture_only','passed':False}
    output=ROOT/'evidence/document-native-os-0.4.49.json'
    if not result['admin_token']:
        result['status']='requires_uac';output.write_text(json.dumps(result,indent=2),encoding='utf-8');return 2
    fixture=ROOT/'runtime/document-native-os';fixture.mkdir(parents=True,exist_ok=True)
    trace=None;backend=WindowsSacl();original=None;changed=False;events=[];candidates=[];calls=[]
    def instrument(api,name):
        function=getattr(api,name)
        def invoke(*arguments):
            value=function(*arguments);calls.append({'api':name,'result':int(value or 0),'last_error':ctypes.get_last_error()});return value
        setattr(api,name,invoke)
    for name in ('CreateFileW','GetFileInformationByHandle','GetFinalPathNameByHandleW'):instrument(backend.k,name)
    for name in ('GetKernelObjectSecurity','GetSecurityDescriptorSacl','SetSecurityInfo'):instrument(backend.a,name)
    with tempfile.TemporaryDirectory(prefix='owned-',dir=fixture) as d:
        directory=Path(d);source=directory/'source.dat';target=directory/'copied.dat';source.write_bytes(bytes(range(256))*32768)
        try:
            with backend.open(source,directory) as (handle,info):
                original=backend.get(handle);after=add_audit(original,1);backend.set(handle,after);changed=True
                assert backend.get(handle)==after
                result['sacl_handle_identity_checked']=bool(info['identity']);result['sacl_apply_readback']=True
            trace=NativeTrace();trace.start(validate([{'path':str(directory),'recursive':True,'read':True,'copy':True}]))
            time.sleep(1)
            for i in range(4):
                with source.open('rb',buffering=0) as reader:
                    with target.open('wb',buffering=0) as writer:
                        while chunk:=reader.read(65536):writer.write(chunk)
                time.sleep(.5);events.extend(trace.poll())
            deadline=time.monotonic()+8
            while time.monotonic()<deadline:
                events.extend(trace.poll())
                if any(e['op']=='read' for e in events) and any(e['op']=='write' for e in events):break
                time.sleep(.25)
            trace.stop()
            correlation=CopyCorrelator(lambda details,t:candidates.append(details))
            for e in events:correlation.feed(e)
            result.update(native_events=len(events),read_events=sum(e['op']=='read' for e in events),write_events=sum(e['op']=='write' for e in events),pid_matches=sum(e['pid']==os.getpid() for e in events),copy_candidates=len(candidates),native_stats=trace.stats,dll_sha256=hashlib.sha256((ROOT/'guarddesk/windows/native/GuardDeskFileTrace.dll').read_bytes()).hexdigest())
            assert result['read_events'] and result['write_events'],'No completed native read/write events observed'
            assert result['pid_matches'],'Issuing process identity not resolved'
            assert candidates,'No candidate correlation observed for controlled copy fixture'
            assert all(not c['operation_confirmed'] for c in candidates)
            result['passed']=True;result['status']='passed_fixture_only'
        except Exception as exc:result.update(status='failed',error=str(exc)[:300],api_calls=calls)
        finally:
            if trace:
                try:trace.stop()
                except OSError as exc:result['trace_stop_error']=str(exc);result['passed']=False
            if changed:
                with backend.open(source,directory) as (handle,info):
                    backend.set(handle,original);result['sacl_restored']=backend.get(handle)==original
                if not result['sacl_restored']:result['passed']=False
            output.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result));return 0 if result['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
