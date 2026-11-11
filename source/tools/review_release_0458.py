"""Self-review of final unsigned candidate; field checks are distinct."""
import hashlib,json,re,shutil,zipfile
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
from run_regression_0458 import snapshot
ROOT=Path(__file__).resolve().parents[1];VERSION='0.4.58'


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf-8-sig'))


def main():
    full=read(ROOT/f'evidence/full-tests-{VERSION}.json');scoped=read(ROOT/f'evidence/scoped-regression-{VERSION}.json')
    assert full['passed'] and full['source_unchanged_during_run'] and full['tests']==633 and full['skipped']==1
    assert scoped['passed'] and scoped['tests']==49 and scoped['skipped']==1 and scoped['source_sha256']==snapshot()
    assert full['source_sha256'].keys()==scoped['source_sha256'].keys()
    delta=sorted(p for p,h in full['source_sha256'].items() if scoped['source_sha256'][p]!=h)
    assert delta==['guarddesk\\browser_deployment.py','guarddesk\\static\\audit_ui.js','tests\\test_browser_dispatch.py'],delta
    assert sha(ROOT/full['log'])==full['log_sha256'] and sha(ROOT/scoped['log'])==scoped['log_sha256']
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
    assert {'guarddesk.context_permissions','guarddesk.browser_dispatch','guarddesk.document_context'}<=set(compiled)
    for area,target in ((ROOT/'guarddesk/static','_internal/guarddesk/static'),(ROOT/'guarddesk/windows','_internal/guarddesk/windows'),(ROOT/'browser-extension','_internal/browser-extension')):
        for path in area.rglob('*'):
            if path.is_file():assert actual[target+'/'+path.relative_to(area).as_posix()]==sha(path),path
    for prefix in ('browser-dispatch-frozen','dispatch-ui-frozen','document-context-frozen'):
        proof=read(ROOT/f'evidence/{prefix}-{VERSION}.json')
        assert proof['passed'] and proof['exe_sha256']==actual['GuardDesk.exe']
    assert read(ROOT/'evidence/maintenance/wts-context-before-after-20261027.json')['passed']
    access=read(ROOT/'evidence/maintenance/standard-user-public-private-access-20261027.json')['results']
    for label in ('public_exe','public_dll'):
        assert access[label]['read']['allowed'] and not access[label]['write']['allowed'] and not access[label]['delete']['allowed']
    assert not any(p['allowed'] for p in access['private_config'].values())
    old={'GuardDesk-0.4.57-windows-x64.zip':'164ca9a92ac3065277437bd01eb3817cc01c055e8c7fc569d03ff61ddeccbc23',
         'GuardDesk-0.4.57-source.zip':'f83266c3853af48e11a75d88cb0d864b5f6c71408b8228ff6eed0dd1f286fff7'}
    assert all(sha(ROOT/'dist'/p)==h for p,h in old.items())
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.57-source.zip') as z:previous=json.loads(z.read('MANIFEST-SHA256.json'))
    unchanged=['guarddesk/policy.py','guarddesk/file_access.py','guarddesk/document_io.py','guarddesk/document_worker.py','guarddesk/native_installer.py','guarddesk/endpoint_package.py','guarddesk/endpoint_setup.py','guarddesk/update_packages.py','guarddesk/update_native.py','guarddesk/browser_publication.py','guarddesk/browser_host.py','guarddesk/web_upload.py','native/document_trace.cpp','requirements.txt','requirements-build.txt','app.py']
    assert all(sha(ROOT/name)==previous[name] for name in unchanged)
    for p in (ROOT/'browser-extension').rglob('*'):
        if p.is_file():assert sha(p)==previous[p.relative_to(ROOT).as_posix()]
    native=read(ROOT/'guarddesk/windows/native/document-trace-build.json')
    assert native['source_sha256']==sha(ROOT/'native/document_trace.cpp') and native['dll_sha256']==actual['_internal/guarddesk/windows/native/GuardDeskFileTrace.dll']
    assert all(p['Status']=='NotSigned' for p in read(ROOT/f'evidence/authenticode-{VERSION}.json'))
    links=0
    for name in ('README.md','AGENTS.md','doc/README.md','doc/11-security-and-defender-guidelines.md','doc/60-engineering-lessons-and-regression-rules.md','doc/77-central-dispatch-and-session-context-0.4.58.md'):
        file=ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',file.read_text(encoding='utf-8')):
            if target.startswith(('http:','https:','#','mailto:')):continue
            assert (file.parent/target.split('#')[0]).exists(),(name,target);links+=1
    folder=ROOT/f'evidence/security/{VERSION}';folder.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(ROOT/full['log'],folder/'full-regression.log')
    result={'version':VERSION,'internal_checks_passed':True,'self_review_only':True,'formal_release_ready':False,
            'company_changed':True,'company_change_scope':'DEV public Program Files native code RX only, backed up; no Server/Agent binary/identity/config/outbox/Defender change',
            'candidate_deployed_to_office':False,'exe_sha256':actual['GuardDesk.exe'],'gui_sha256':actual['GuardDeskAgent.exe'],
            'compiled_modules_verified':compiled,'application_files':len(actual),'final_source_sha256':scoped['source_sha256'],
            'validation_method':'633-case unchanged full baseline (632 passed, one missing historical archive skipped); only the browser policy equal-value no-flush guard, final UI explanation and added native/registry integration regressions differ. Final 49-case scoped regression (48 passed, same skip), real frozen UI and complete packaged smoke cover final delta. Counts overlap and are not added.',
            'final_delta_files':delta,'unchanged_boundaries_verified':unchanged,'archived_057_hashes_verified':old,'documentation_links_checked':links,
            'gd':['GD-005','GD-007','GD-008','GD-018','GD-020','GD-021','GD-022','GD-024'],
            'requirements':['SEC-01','SEC-02','SEC-03','SEC-05','SEC-06','SEC-10','SEC-11','DEF-01','DEF-02'],
            'remaining':['Actual new native SYSTEM -> session helper -> installed Agent -> company center end-to-end acceptance pending; real WTS comparison and installed standard-user pipe are separate evidence',
                         'Company Server/DEV/user1 binaries not deployed to this candidate; company extension publication still unconfigured (configured Agent HTTPS path returned 404)',
                         'Browser-trusted HTTPS/domain policy eligibility, actual force installation/Native Host handshake and ChatGPT file request capture pending; no root trust changed',
                         'Installed DEV next-update broker version diagnostic still awaits OS consent; no successful read assumed',
                         '8/24h whole-endpoint and browser/Defender responsiveness and Windows 10/11 company lifecycle pending; short helper sample is not a no-stall guarantee',
                         'Unsigned internal trial; formal signing, independent review, full SBOM/vulnerability and Defender/EDR acceptance pending',
                         'Sealed 0.4.53 source archive missing; historic decoder test explicitly skipped; no fabricated substitute']}
    (folder/'requirements-review.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('compiled_modules_verified','final_source_sha256')}))


if __name__=='__main__':main()
