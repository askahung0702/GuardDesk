"""Admin acceptance on owned files only; no SACL or global audit changes."""
import ctypes
import hashlib
import mmap
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk.document_io import NativeTrace,ReadObserver,CopyCorrelator
from guarddesk.document_process import ProcessResolver
from guarddesk.file_access import Filter


def main():
    result={'passed':False,'scope':'own_disposable_fixture_general_managed_policy',
            'named_document_rules':0,'sacl_changed':False,'global_audit_policy_changed':False,
            'defender_changed':False,'live_enrollment_accessed':False,'admin_token':bool(ctypes.windll.shell32.IsUserAnAdmin())}
    output=ROOT/'evidence/general-file-audit-os-0.4.55.json';trace=None;child=None
    if not result['admin_token']:
        result['status']='requires_uac';output.write_text(json.dumps(result,indent=2));return 2
    observations=[];copies=[];events=[]
    with tempfile.TemporaryDirectory(prefix='general-read-',dir=ROOT/'runtime') as temporary:
        root=Path(temporary);source=root/'source.dat';target=root/'copied.dat'
        excluded=root/'private';excluded.mkdir();secret=excluded/'secret.dat'
        cache=root/'users/alice/cache';cache.mkdir(parents=True);cached=cache/'cached.dat'
        empty=root/'empty.txt';empty.write_bytes(b'')
        mapped=root/'mapped.txt';mapped.write_bytes(b'GuardDesk owned mapped fixture.\n'*2048)
        data=bytes(range(256))*8192
        for path in (source,secret,cached):path.write_bytes(data)
        policy={'enabled':True,'scope':'managed','exclude_paths':[str(excluded),str(root/'users/{user}/cache')]}
        try:
            trace=NativeTrace()
            fixture_start=trace.api.gd_trace_start_fixture_filtered
            fixture_start.argtypes=trace.api.gd_trace_start_filtered.argtypes;fixture_start.restype=trace.api.gd_trace_start_filtered.restype
            trace.api.gd_trace_start_filtered=fixture_start
            trace.start_policy(policy,str(root),str(root/'internal'));assert trace.active
            def drain():
                time.sleep(.3);events.extend(trace.poll())
            time.sleep(.5)
            for _ in range(2):
                with source.open('rb',buffering=0) as reader,target.open('wb',buffering=0) as writer:
                    while chunk:=reader.read(65536):writer.write(chunk)
                drain()
            with mapped.open('rb') as reader:
                with mmap.mmap(reader.fileno(),0,access=mmap.ACCESS_READ) as view:assert view[:10]==b'GuardDesk '
            with empty.open('rb') as reader:assert reader.read()==b''
            try:(root/'missing.txt').open('rb')
            except FileNotFoundError:pass
            drain()
            for path in (secret,cached):
                with path.open('rb',buffering=0) as reader:
                    while reader.read(65536):pass
                drain()
            child=subprocess.Popen([sys.executable,str(Path(__file__)), '--producer',str(root)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            for _ in range(8):drain()
            trace.stop()
            assert not any('secret.dat' in e['path'] or 'cached.dat' in e['path'] for e in events),'Native early exclusion failed'
            observer=ReadObserver(lambda d,t:observations.append(d));correlator=CopyCorrelator(lambda d,t:copies.append(d))
            source_events=[e for e in events if e['path'].casefold()==str(source).casefold() and e['pid']==os.getpid() and e['op']=='read']
            for e in events:observer.feed(e);correlator.feed(e)
            time.sleep(1.05);observer.tick()
            own_reads=[o for o in observations if o['path'].casefold()==str(source).casefold() and o['process_id']==os.getpid()]
            assert source_events,'No completed own native reads'
            assert len({e['open_id'] for e in source_events})>=2,'Immediate reopen did not get distinct native open identity'
            assert len(own_reads)>=2,'Immediate reopen observation lost'
            assert copies,'Controlled copy did not produce candidate'
            mapped_opens=[o for o in observations if o['path'].casefold()==str(mapped).casefold() and o['process_id']==os.getpid()]
            assert mapped_opens,'Mapped file open was missed'
            assert any(o['evidence']=='completed_native_open' and not o['read_confirmed'] for o in mapped_opens),'Mapped-only access incorrectly claimed ReadData'
            empty_opens=[o for o in observations if o['path'].casefold()==str(empty).casefold() and o['process_id']==os.getpid()]
            assert empty_opens and all(o['evidence']=='completed_native_open' and not o['read_confirmed'] and 'read_bytes' not in o for o in empty_opens),'Empty file open missed or fabricated ReadData'
            result.update(empty_file_open_observations=len(empty_opens),empty_file_no_fabricated_read=True)
            assert not any('missing.txt' in o['path'] for o in observations),'Failed open became successful'
            resolver=ProcessResolver();filtered=Filter();kept=[]
            for item in observations:
                if item['process_id']!=child.pid:continue
                event=next(e for e in events if e['pid']==child.pid and e['path']==item['path'])
                identity=resolver.resolve(event);item.update(identity)
                if filtered.check(item,[]) is None:kept.append(item)
            assert any(o['path'].casefold()==str(empty).casefold() and o.get('process_identity_status')=='creation_time_checked' and type(o.get('process_session_id')) is int for o in kept),'Actual child empty open, process birth/session and source filter failed'
            assert any(o['path'].casefold()==str(mapped).casefold() for o in kept),'Source filter lost mapped child file'
            assert filtered.check({'path':str(root),'process_id':child.pid,'evidence':'completed_native_open'},[])=='directory'
            assert filtered.check({'path':root.anchor,'process_id':child.pid,'evidence':'completed_native_open'},[])=='directory'
            assert filtered.check({'path':str(empty),'process_id':os.getpid(),'evidence':'completed_native_open'},[])=='collector_self'
            result.update(child_empty_and_mapped_survive_real_source_filter=True,child_process_birth_image_session_verified=True,actual_directory_and_drive_root_rejected=True,collector_self_rejected=True)
            result.update(mapped_open_observations=len(mapped_opens),mapped_open_not_claimed_read=True,failed_open_not_emitted=True,fixed_fixture_session_separate_from_live_agent=True)
            result.update(passed=True,status='passed_fixture_only',native_events=len(events),source_read_buffers=len(source_events),
                          own_read_observations=len(own_reads),distinct_native_opens=len({e['open_id'] for e in source_events}),
                          copy_candidates=len(copies),literal_and_user_template_native_exclusions_passed=True,native_stats=trace.stats)
        except BaseException as exc:result.update(status='failed',error=str(exc)[:400])
        finally:
            (ROOT/'runtime/general-file-audit-os-0455-events.json').write_text(json.dumps(events),encoding='utf-8')
            if child:
                child.wait(timeout=20)
            if trace:
                try:trace.stop();result['own_trace_stopped']=not trace.active
                except OSError as exc:result.update(passed=False,stop_error=str(exc))
    result['dll_sha256']=hashlib.sha256((ROOT/'guarddesk/windows/native/GuardDeskFileTrace.dll').read_bytes()).hexdigest()
    output.write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result));return 0 if result['passed'] else 1


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--producer':
        root=Path(sys.argv[2])
        with (root/'empty.txt').open('rb') as stream:assert stream.read()==b''
        with (root/'mapped.txt').open('rb') as stream:
            with mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as view:assert view[:10]==b'GuardDesk '
        time.sleep(12)
    else:raise SystemExit(main())
