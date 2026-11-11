"""Exact frozen/source self-review; formal and company acceptance remain open."""
import hashlib,json,zipfile
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
ROOT=Path(__file__).resolve().parents[1];VERSION='0.4.57'

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_text(encoding='utf-8-sig'))

def main():
    from run_regression_0457 import snapshot
    full=read(ROOT/f'evidence/full-tests-{VERSION}.json')
    scoped=read(ROOT/f'evidence/scoped-regression-{VERSION}.json')
    assert full['exit_code']==0 and full['tests']==619
    assert scoped['passed'] and scoped['source_unchanged_during_run'] and scoped['source_sha256']==snapshot()
    assert full['source_sha256'].keys()==scoped['source_sha256'].keys()
    delta=[name for name,digest in full['source_sha256'].items() if scoped['source_sha256'][name]!=digest]
    assert delta==['guarddesk\\windows_watch.py'],delta
    assert full['skipped']==1 and sha(ROOT/full['log'])==full['log_sha256']
    assert sha(ROOT/scoped['log'])==scoped['log_sha256']
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
    assert 'guarddesk.hidden_files' in compiled
    for area,target in ((ROOT/'guarddesk/static','_internal/guarddesk/static'),(ROOT/'guarddesk/windows','_internal/guarddesk/windows'),(ROOT/'browser-extension','_internal/browser-extension')):
        for path in area.rglob('*'):
            if path.is_file():assert actual[target+'/'+path.relative_to(area).as_posix()]==sha(path),path
    for prefix in ('hidden-settings-browser','packaged-hidden'):
        proof=read(ROOT/f'evidence/{prefix}-{VERSION}.json')
        assert proof['passed'] and proof['exe_sha256']==actual['GuardDesk.exe'] and not proof['company_changed']
    old={'GuardDesk-0.4.56-windows-x64.zip':'8e56586519fe1c874d12d8a5332f9e333edc9f279035d5938d2ef7402aa80bc6','GuardDesk-0.4.56-source.zip':'886d1f3e8245cde15b778171080503f48d335c2541234e323bc1cfe056be25f8'}
    old.update({'GuardDesk-0.4.55-windows-x64.zip':'395be52635f9f992a7e8a1fe4f68a96d4267e1116b003a0c5187ce3778cf8578','GuardDesk-0.4.55-source.zip':'280371dd6c25362d3b701db5924a873c35f9055ebb49a2c25eea19fb92114100'})
    assert all(sha(ROOT/'dist'/p)==h for p,h in old.items())
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.56-source.zip') as archive:
        previous=json.loads(archive.read('MANIFEST-SHA256.json'))
        unchanged=['guarddesk/policy.py','guarddesk/application_control.py','guarddesk/file_access.py','guarddesk/snapshot.py','guarddesk/document_io.py','guarddesk/document_worker.py','guarddesk/document_context.py','guarddesk/native_installer.py','guarddesk/endpoint_package.py','guarddesk/endpoint_setup.py','guarddesk/update_packages.py','guarddesk/update_native.py','guarddesk/browser_publication.py','guarddesk/browser_release.py','guarddesk/browser_host.py','guarddesk/web_upload.py','guarddesk/remote_viewer.py','guarddesk/remote_client.py','guarddesk/remote_windows.py','native/document_trace.cpp','requirements.txt','requirements-build.txt','app.py']
        assert all(sha(ROOT/name)==previous[name] for name in unchanged)
        for path in (ROOT/'browser-extension').rglob('*'):
            if path.is_file():assert sha(path)==previous[path.relative_to(ROOT).as_posix()]
        changed=sorted(p.relative_to(ROOT).as_posix() for area in ('guarddesk','browser-extension') for p in (ROOT/area).rglob('*') if p.is_file() and '__pycache__' not in p.parts and previous.get(p.relative_to(ROOT).as_posix())!=sha(p))
    native=read(ROOT/'guarddesk/windows/native/document-trace-build.json')
    assert native['source_sha256']==sha(ROOT/'native/document_trace.cpp') and native['dll_sha256']==actual['_internal/guarddesk/windows/native/GuardDeskFileTrace.dll']
    assert all(p['Status']=='NotSigned' for p in read(ROOT/f'evidence/authenticode-{VERSION}.json'))
    folder=ROOT/f'evidence/security/{VERSION}';folder.mkdir(parents=True,exist_ok=True)
    (folder/'full-regression.log').write_bytes((ROOT/full['log']).read_bytes())
    first=read(ROOT/f'evidence/full-tests-{VERSION}-first-failure.json')
    assert not first['passed'] and sha(ROOT/first['log'])==first['log_sha256']
    (folder/'first-regression-failure.log').write_bytes((ROOT/first['log']).read_bytes())
    result={'version':VERSION,'internal_checks_passed':True,'self_review_only':True,'formal_release_ready':False,'office_changed':False,'exe_sha256':actual['GuardDesk.exe'],'gui_sha256':actual['GuardDeskAgent.exe'],'compiled_modules_verified':compiled,'application_files':len(actual),'source_changes_from_056':changed,'unchanged_boundaries_verified':unchanged,'native_dll_sha256':native['dll_sha256'],'archived_prior_hashes_verified':old,'regression_run':full['tests'],'regression_skipped':full['skipped'],'regression_passed':full['tests']-full['skipped'],'gd':['GD-005','GD-007','GD-011','GD-012','GD-013','GD-017','GD-019','GD-020','GD-023'],'requirements':['SEC-01','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11','DEF-01','DEF-02','DEF-04'],'remaining':['First full run failed at owned installer fixture directory switching with WinError 5; original log retained, same unchanged installer 29 targeted cases passed. Specific initial ACL/handle/security cause unconfirmed; company installation still pending','Company Server/DEV/user1 unchanged; real deployed policy, updater and continuous SYSTEM collector acceptance pending','Hidden attributes need both ordinary Agent and native worker 0.4.57; older decoder accepts marker but cannot enforce it','Unknown/deleted-without-evidence/inaccessible paths, reparse traversal, UNC, deep paths and query-capacity exhaustion retain events; metadata cache consistency window up to 2 seconds','One historic 0.4.53 decoder test skipped because sealed source missing; real sealed 0.4.56 decoder tested','Unsigned internal trial: formal Authenticode, independent review, full SBOM/vulnerability and company Win10/11 Defender/EDR lifecycle pending','8/24h complete endpoint/browser/Defender/Office/Teams resource acceptance pending; bounded metadata is not a guarantee of zero latency','Actual enterprise browser installation and ChatGPT capture remain pending per 0.4.56; browser code unchanged, no new field claim']}
    result.update(validation_method='Full suite exit 0 on pre-final watcher, plus 67 scoped cases on final source; not a full final-snapshot rerun',final_delta_files=delta,scoped_regression_run=scoped['tests'],scoped_regression_passed=scoped['tests']-scoped['skipped'],final_source_sha256=scoped['source_sha256'])
    (folder/'requirements-review.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps({k:v for k,v in result.items() if k not in ('compiled_modules_verified','final_source_sha256')}))

if __name__=='__main__':main()
