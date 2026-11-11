"""Exact-artifact self-review, with explicit external/legacy acceptance gaps."""
import hashlib,json,sys,zipfile
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));VERSION='0.4.56'

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def main():
    from run_regression_0456 import snapshot
    full=read(ROOT/f'evidence/full-tests-{VERSION}.json')
    assert full['passed'] and full['source_unchanged_during_run'] and full['source_sha256']==snapshot()
    assert full['skipped']==1 and sha(ROOT/full['log'])==full['log_sha256']
    folder=ROOT/f'evidence/security/{VERSION}';folder.mkdir(parents=True,exist_ok=True)
    for filename,target in ((full['log'],'full-regression.log'),(read(ROOT/f'evidence/full-tests-{VERSION}-first-failure.json')['log'],'first-regression-failure.log'),(read(ROOT/f'evidence/full-tests-{VERSION}-intermediate-cancelled.json')['log'],'intermediate-cancelled.log')):
        (folder/target).write_bytes((ROOT/filename).read_bytes())
    app=ROOT/'dist/GuardDesk';actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    smoke=read(ROOT/'evidence/packaged-smoke.json');assert smoke['passed'] and smoke['application_files']==actual
    (ROOT/f'evidence/packaged-smoke-{VERSION}.json').write_text(json.dumps(smoke,indent=2),encoding='utf-8')
    manifest=read(app/'_internal/agent-release.json');assert manifest['version']==VERSION
    assert manifest['files']=={k:v for k,v in actual.items() if k!='_internal/agent-release.json'}
    pyz=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz');compiled=[]
    for path in (ROOT/'guarddesk').glob('*.py'):
        name='guarddesk' if path.stem=='__init__' else 'guarddesk.'+path.stem
        if name in pyz.toc:
            assert pyz.extract(name)==compile(path.read_bytes(),str(path),'exec'),name
            compiled.append(name)
    assert all('guarddesk.'+name in compiled for name in ('browser_publication','browser_identity','web_upload','browser_host'))
    for area,target in ((ROOT/'guarddesk/static','_internal/guarddesk/static'),(ROOT/'guarddesk/windows','_internal/guarddesk/windows'),(ROOT/'browser-extension','_internal/browser-extension')):
        for path in area.rglob('*'):
            if path.is_file():assert actual[target+'/'+path.relative_to(area).as_posix()]==sha(path),path
    for prefix in ('update-progress-browser','document-audit-browser','browser-bundle-frozen','packaged-web-upload'):
        proof=read(ROOT/f'evidence/{prefix}-{VERSION}.json')
        assert proof['passed'] and proof['exe_sha256']==actual['GuardDesk.exe'],prefix
    uploads=read(ROOT/f'evidence/maintenance/upload-formats-fixed-{VERSION}-frozen.json')
    assert uploads['passed_reproduction'] and uploads['raw_formats_covered'] and uploads['frozen_host_used'] and uploads['exe_sha256']==actual['GuardDesk.exe']
    assert not uploads['actual_ChatGPT_request_format_confirmed'] and not uploads['production_registry_accessed']
    old={'GuardDesk-0.4.55-windows-x64.zip':'395be52635f9f992a7e8a1fe4f68a96d4267e1116b003a0c5187ce3778cf8578','GuardDesk-0.4.55-source.zip':'280371dd6c25362d3b701db5924a873c35f9055ebb49a2c25eea19fb92114100'}
    assert all(sha(ROOT/'dist'/p)==h for p,h in old.items())
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.55-source.zip') as archive:
        old_manifest=json.loads(archive.read('MANIFEST-SHA256.json'))
        unchanged=['guarddesk/policy.py','guarddesk/file_access.py','guarddesk/document_io.py','guarddesk/document_worker.py','guarddesk/document_context.py','guarddesk/agent.py','guarddesk/application_control.py','guarddesk/server_backup.py','guarddesk/remote_viewer.py','guarddesk/remote_client.py','guarddesk/remote_windows.py','native/document_trace.cpp','requirements.txt','requirements-build.txt','app.py']
        assert all(sha(ROOT/name)==old_manifest[name] for name in unchanged)
        changed=sorted(p.relative_to(ROOT).as_posix() for area in ('guarddesk','browser-extension') for p in (ROOT/area).rglob('*') if p.is_file() and '__pycache__' not in p.parts and old_manifest.get(p.relative_to(ROOT).as_posix())!=sha(p))
    native=read(ROOT/'guarddesk/windows/native/document-trace-build.json')
    assert native['source_sha256']==sha(ROOT/'native/document_trace.cpp') and native['dll_sha256']==actual['_internal/guarddesk/windows/native/GuardDeskFileTrace.dll']
    signatures=read(ROOT/f'evidence/authenticode-{VERSION}.json');assert all(p['Status']=='NotSigned' for p in signatures)
    boundary=read(ROOT/f'evidence/maintenance/viewer-execution-boundary-{VERSION}.json')
    assert boundary['same_final_binary_compared'] and boundary['normal_environment_full_smoke_passed'] and boundary['exe_sha256']==actual['GuardDesk.exe']
    remaining=['Restricted execution produced a Tcl init.tcl error; same final artifact passes the original full packaged smoke in normal execution. Exact environment cause unconfirmed; ineffective path experiment reverted, viewer source unchanged. Company UI lifecycle pending','Company Server/DEV/user1 unchanged; actual enterprise policy install and installed browser -> Native Host -> company center not accepted','Actual ChatGPT request format and successful capture after company deployment not yet verified','Browser-trusted HTTPS and domain/GPO qualifications must be checked by MIS; no root trust installed','One sealed 0.4.53 decoder test unavailable: historic archive missing; existing policy/file_access bytes match sealed 0.4.55','Main-world metadata is an untrusted filename candidate, not full path or byte identity; Worker/streams/transforms/WebSocket not universal','Unsigned EXEs; formal Authenticode, independent review, full SBOM/vulnerability and Win10/11 company Defender/EDR lifecycle not accepted','8/24h whole-endpoint+browser+Defender resource/Office/Teams acceptance pending; local fixture timing is not a no-stall guarantee','Existing manually loaded legacy extension must be disabled by MIS before the new company ID to avoid duplicates/proxy conflict; no employee profiles edited','Server BrowserSigner must be safely backed up separately; DB-only snapshot excludes keys; no HSM/key-vault integration']
    result={'version':VERSION,'internal_checks_passed':True,'self_review_only':True,'formal_release_ready':False,'office_changed':False,'exe_sha256':actual['GuardDesk.exe'],'gui_sha256':actual['GuardDeskAgent.exe'],'compiled_modules_verified':compiled,'application_files':len(actual),'source_changes_from_055':changed,'unchanged_boundaries_verified':unchanged,'native_dll_sha256':native['dll_sha256'],'archived_055_hashes_verified':old,'regression_run':full['tests'],'regression_skipped':full['skipped'],'regression_passed':full['tests']-full['skipped'],'gd':['GD-005','GD-007','GD-008','GD-009','GD-013','GD-015','GD-017','GD-018','GD-020','GD-021','GD-023','GD-024'],'requirements':['SEC-01','SEC-02','SEC-03','SEC-04','SEC-05','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11','DEF-01','DEF-02','DEF-04'],'pending_formal':['SEC-09','DEF-03','DEF-05','DEF-06'],'remaining':remaining}
    (folder/'requirements-review.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps({k:v for k,v in result.items() if k!='compiled_modules_verified'}))


if __name__=='__main__':main()
