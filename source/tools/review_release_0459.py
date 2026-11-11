"""Exact candidate self-review. Formal company rollout remains separate."""
import hashlib,json,re,shutil,zipfile
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
from run_regression_0459 import snapshot
ROOT=Path(__file__).resolve().parents[1];VERSION='0.4.59'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf-8-sig'))


def main():
    full=read(ROOT/f'evidence/full-tests-{VERSION}.json')
    assert full['passed'] and full['source_unchanged_during_run'] and full['source_sha256']==snapshot()
    assert full['tests']>=640 and full['skipped']==1
    assert sha(ROOT/full['log'])==full['log_sha256']
    app=ROOT/'dist/GuardDesk';actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    smoke=read(ROOT/'evidence/packaged-smoke.json');assert smoke['passed'] and smoke['application_files']==actual
    (ROOT/f'evidence/packaged-smoke-{VERSION}.json').write_text(json.dumps(smoke,indent=2),encoding='utf-8')
    manifest=read(app/'_internal/agent-release.json')
    assert manifest['version']==VERSION and manifest['files']=={k:v for k,v in actual.items() if k!='_internal/agent-release.json'}
    pyz=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz');compiled=[]
    for path in (ROOT/'guarddesk').glob('*.py'):
        name='guarddesk' if path.stem=='__init__' else 'guarddesk.'+path.stem
        if name in pyz.toc:
            assert pyz.extract(name)==compile(path.read_bytes(),str(path),'exec'),name
            compiled.append(name)
    assert {'guarddesk.browser_auto_publication','guarddesk.browser_trust','guarddesk.browser_dispatch'}<=set(compiled)
    for area,target in ((ROOT/'guarddesk/static','_internal/guarddesk/static'),(ROOT/'guarddesk/windows','_internal/guarddesk/windows'),(ROOT/'browser-extension','_internal/browser-extension')):
        for path in area.rglob('*'):
            if path.is_file():assert actual[target+'/'+path.relative_to(area).as_posix()]==sha(path),path
    for prefix in ('browser-dispatch-frozen','dispatch-ui-frozen'):
        proof=read(ROOT/f'evidence/{prefix}-{VERSION}.json')
        assert proof['passed'] and proof['exe_sha256']==actual['GuardDesk.exe'],prefix
    trust=read(ROOT/f'evidence/browser-trust-windows-{VERSION}.json')
    assert trust['passed'] and trust['cleanup_verified'] and trust['root_store_restored'] and trust['preexisting_preserved'] and not trust['company_ca_installed']
    assert trust['trust_source_sha256']==sha(ROOT/'guarddesk/browser_trust.py') and trust['frozen_module_used']
    old={'GuardDesk-0.4.58-windows-x64.zip':'681ed4750669c574df0b3a8c29d2cf926a27a284696dd032cff33295e74127be',
         'GuardDesk-0.4.58-source.zip':'6358e06f3f7518b22b8ee8d0d7ccd54f4e8abd16cfa7b0f8bf0d7d9715f8a2fe'}
    assert all(sha(ROOT/'dist'/p)==h for p,h in old.items())
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.58-source.zip') as z:previous=json.loads(z.read('MANIFEST-SHA256.json'))
    unchanged=['guarddesk/policy.py','guarddesk/file_access.py','guarddesk/document_io.py','guarddesk/document_worker.py','guarddesk/document_context.py','guarddesk/context_permissions.py','guarddesk/update_packages.py','guarddesk/update_native.py','guarddesk/update_client.py','guarddesk/update_windows.py','guarddesk/updater_refresh.py','guarddesk/browser_publication.py','guarddesk/browser_host.py','guarddesk/web_upload.py','native/document_trace.cpp','requirements.txt','requirements-build.txt','app.py']
    assert all(sha(ROOT/name)==previous[name] for name in unchanged)
    for p in (ROOT/'browser-extension').rglob('*'):
        if p.is_file():assert sha(p)==previous[p.relative_to(ROOT).as_posix()]
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.57-source.zip') as z:actor=json.loads(z.read('MANIFEST-SHA256.json'))
    actor_modules=['guarddesk/update_packages.py','guarddesk/update_native.py','guarddesk/update_client.py','guarddesk/update_windows.py','guarddesk/updater_refresh.py']
    assert all(sha(ROOT/name)==actor[name] for name in actor_modules)
    assert read(ROOT/'evidence/maintenance/installed-update-actor-20261027.json')['broker']['version']=='0.4.57'
    native=read(ROOT/'guarddesk/windows/native/document-trace-build.json')
    assert native['source_sha256']==sha(ROOT/'native/document_trace.cpp') and native['dll_sha256']==actual['_internal/guarddesk/windows/native/GuardDeskFileTrace.dll']
    assert all(p['Status']=='NotSigned' for p in read(ROOT/f'evidence/authenticode-{VERSION}.json'))
    links=0
    for name in ('README.md','AGENTS.md','doc/README.md','doc/11-security-and-defender-guidelines.md','doc/60-engineering-lessons-and-regression-rules.md','doc/78-automatic-browser-publication-and-ca-trust-0.4.59.md'):
        file=ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',file.read_text(encoding='utf-8')):
            if target.startswith(('http:','https:','#','mailto:')):continue
            assert (file.parent/target.split('#')[0]).exists(),(name,target);links+=1
    folder=ROOT/f'evidence/security/{VERSION}';folder.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(ROOT/full['log'],folder/'full-regression.log')
    if full.get('initial_attempt'):
        shutil.copyfile(ROOT/full['initial_attempt']['log'],folder/'initial-regression.log')
        shutil.copyfile(ROOT/full['resume']['log'],folder/'resumed-regression.log')
    result={'version':VERSION,'internal_checks_passed':True,'self_review_only':True,'formal_release_ready':False,
            'company_changed':False,'company_change_scope':'No company Server/Agent/CA/Defender changes this candidate; only uniquely generated disposable CA temporarily added then removed with full Root store equality verified',
            'candidate_deployed_to_office':False,'exe_sha256':actual['GuardDesk.exe'],'gui_sha256':actual['GuardDeskAgent.exe'],
            'compiled_modules_verified':compiled,'application_files':len(actual),'final_source_sha256':full['source_sha256'],
            'trust_windows_test':{'exe_sha256':trust['exe_sha256'],'trust_source_sha256':trust['trust_source_sha256'],'same_exact_trust_code_verified_in_final_pyz':True,'later_changes':'Only preparation-failure UI/API status changed; trust module remained byte-for-byte unchanged'},
            'validation_method':full.get('validation_method','Unchanged final source full regression')+'; final frozen actual HTTPS publication and endpoint ZIP; real isolated Chrome UI; full packaged smoke; same unchanged frozen trust module with real LocalMachine Root lifecycle and complete cleanup. No actual employee browser installation or ChatGPT capture claimed.',
            'regression_initial_attempt':full.get('initial_attempt'),'regression_resume':full.get('resume'),
            'archived_regression_logs':['full-regression.log','initial-regression.log','resumed-regression.log'],
            'unchanged_boundaries_verified':unchanged,'installed_057_actor_modules_unchanged':actor_modules,'archived_058_hashes_verified':old,'documentation_links_checked':links,
            'gd':['GD-005','GD-007','GD-008','GD-018','GD-020','GD-021','GD-022','GD-024'],
            'requirements':['SEC-01','SEC-02','SEC-03','SEC-04','SEC-05','SEC-06','SEC-10','SEC-11','DEF-01','DEF-02'],
            'remaining':['Company Server and both endpoint components not deployed to this candidate; installer UAC company CA action explicitly authorized but company root not yet installed',
                         'Actual company Chrome/Edge enterprise policy acceptance, forced extension installation, Native Host handshake and ChatGPT non-confidential request/center receipt pending',
                         'Installed SYSTEM -> session helper -> center end-to-end file acceptance pending; unchanged 0.4.58 context code is not new field acceptance',
                         '8/24h whole-endpoint/browser/Defender responsiveness and Windows 10/11 company lifecycle pending; bounded trust operations are not a no-stall guarantee',
                         'Unsigned internal trial; formal signing, independent review, full SBOM/vulnerability and Defender/EDR acceptance pending',
                         'Sealed 0.4.53 source archive missing; one historical decoder test explicitly skipped, no fabricated substitute']}
    (folder/'requirements-review.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('compiled_modules_verified','final_source_sha256')}))


if __name__=='__main__':main()
