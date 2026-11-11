"""Review the SYSTEM query fix against exact test, OS fixture and build bytes."""
import json,re,shutil,subprocess,sys,zipfile
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
from review_release_0441 import ROOT,sha,read
sys.path.insert(0,str(ROOT))
VERSION='0.4.42'
def main():
    folder=ROOT/f'evidence/security/{VERSION}';folder.mkdir(exist_ok=True)
    logs={}
    for name,count in [('system-health-regression-0.4.42.txt',472),('system-health-targeted-final-0.4.42.txt',28)]:
        path=ROOT/'runtime'/name;body=path.read_text(encoding='utf-8-sig',errors='replace').replace('\r\n','\n')
        match=re.search(r'Ran (\d+) tests in ([\d.]+)s',body)
        assert match and int(match[1])==count and '\nOK\n' in body and 'FAILED (' not in body,body[-1500:]
        logs[name]={'tests':count,'seconds':float(match[2]),'sha256':sha(path),'passed':True}
    app=ROOT/'dist/GuardDesk';actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()};smoke=read(ROOT/'evidence/packaged-smoke.json')
    assert smoke['passed'] and smoke['application_files']==actual and smoke['exe_sha256']==actual['GuardDesk.exe'] and smoke['gui_sha256']==actual['GuardDeskAgent.exe']
    browsers={}
    for name in (f'custom-library-browser-{VERSION}.json',f'mail-reports-browser-{VERSION}.json'):
        value=read(ROOT/'evidence'/name);assert value['passed'] and value['frozen_server_used'] and value['exe_sha256']==actual['GuardDesk.exe'] and value['page_errors']==[];browsers[name]=value
    modules=[];archive=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz')
    for path in (ROOT/'guarddesk').glob('*.py'):
        name='guarddesk' if path.stem=='__init__' else 'guarddesk.'+path.stem
        if name in archive.toc:assert archive.extract(name)==compile(path.read_bytes(),str(path),'exec'),name;modules.append(name)
    assert 'guarddesk.native_installer' in modules
    for area in ('static','windows'):
        for path in (ROOT/'guarddesk'/area).rglob('*'):
            if path.is_file():assert path.read_bytes()==(app/'_internal/guarddesk'/area/path.relative_to(ROOT/'guarddesk'/area)).read_bytes(),path
    manifest=read(app/'_internal/agent-release.json');assert manifest['version']==VERSION and manifest['files']=={k:v for k,v in actual.items() if k!='_internal/agent-release.json'}
    from guarddesk.native_installer import source_files
    verified,total=source_files(app);assert verified==actual
    prior={'GuardDesk-0.4.41-windows-x64.zip':'51ff51719b80fc434fcbf50d05ff6c7c0ac1d4fc807c1aabe5ad6134f903beaf','GuardDesk-0.4.41-source.zip':'95d41b33ca8a11e3a45cdc6447ce76b751655fd859c648d661e71ea19d8cb990'}
    prior.update(read(ROOT/'evidence/security/0.4.41/requirements-review.json')['prior_archives_unchanged'])
    for name,digest in prior.items():assert sha(ROOT/'dist'/name)==digest
    critical=read(ROOT/'evidence/security/0.4.41/requirements-review.json')['critical_sources_unchanged']
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.41-source.zip') as z:
        for name in critical:assert z.read(name)==(ROOT/name).read_bytes(),name
    os_result=read(ROOT/'evidence/native-worker-health-os-20261021.json')
    assert os_result['passed'] and os_result['task_identity']=='S-1-5-18' and not os_result['cleanup_errors']
    assert os_result['installer_source_sha256']==sha(ROOT/'guarddesk/native_installer.py') and os_result['compiled_exe_sha256']==actual['GuardDesk.exe']
    failure=read(ROOT/'evidence/native-worker-health-os-reproduced-access-denied-20261021.json')
    assert failure['health']['sid']=='S-1-5-18' and 'WinError 5' in failure['diagnosis_error'] and not failure['passed']
    assert not any(Path(r'C:\ProgramData').glob('GuardDesk-HealthCheck-*')),'Owned test directories need cleanup'
    signatures=read(folder/'signatures.json')
    for record in signatures:assert sha(ROOT/record['path'])==record['sha256']
    regression={'passed':True,'logs':logs,'final_unique_cases':473,'note':'472 full tests then all 28 installer cases after final fail-closed privilege restoration, including one added case. Real SYSTEM fixture uses the exact compiled installer module; full endpoint installation is separate acceptance.'}
    (folder/'regression.json').write_text(json.dumps(regression,indent=2)+'\n',encoding='utf-8')
    shutil.copyfile(ROOT/'evidence/packaged-smoke.json',ROOT/f'evidence/packaged-smoke-{VERSION}.json')
    report={'version':VERSION,'release_status':'unsigned_internal_trial','passed_with_gaps':True,'review_type':'developer_self_review_not_independent','lessons':['GD-004','GD-007','GD-009','GD-020','GD-021'],'requirements':['SEC-01','SEC-02','SEC-03','SEC-06','SEC-08','SEC-09','SEC-10','SEC-11','DEF-01','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],'root_cause':'Real SYSTEM fixture has valid health but UAC admin OpenProcess limited query returns error 5; 0.4.41 swallowed this and timed out. Old installer used CIM provider instead. Actual user endpoint has same timeout symptom; its protected diagnostic was not remotely read.','controls':['Normal read-only image query first; only error 5 retries exact same PID with existing admin SeDebugPrivilege scoped to this thread','ImpersonateSelf plus token-state restoration and RevertToSelf, including exceptions; restoration failure terminates installer instead of continuing under an uncertain scope','No account rights, system policy, process ACL, Defender/EDR/ASR or PowerShell settings changed; no memory/read-write/termination process rights requested','Preserves fresh finite time, exact version and PID-to-protected-image checks; last failure code visible; never accepts file-only health','Existing identity/trust/CA/queues, private staging, rollback and installation entry retained; critical worker/update/collection/storage/library modules byte-identical to 0.4.41','Actual SYSTEM task fixture plus exact compiled module verifies health and privilege reset; temporary test tasks/files removed; no office deployment or mail'],'gaps':['Affected endpoint full installation not yet verified; screenshot alone cannot exclude other startup errors','Company-trusted signing, full supply-chain/vulnerability assessment, independent review and company Windows 10/11 Defender/EDR/App Control lifecycle/resource acceptance incomplete','Company may remove SeDebugPrivilege; installer does not grant it or weaken policy and will still fail honestly','Optional software controls retain PowerShell dependencies; GD-006 generic Server source error remains open'],'regression':regression,'compiled_modules_equal_source':modules,'application_files':len(actual),'application_bytes':total,'critical_sources_unchanged':critical,'prior_archives_unchanged':prior,'signatures':signatures,'real_system_test':os_result,'frozen_browsers':browsers,'office_server_or_endpoints_changed':False,'historical_41_os_test_replaced':False}
    out=folder/'requirements-review.json';out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    links=0
    for name in ('README.md','doc/README.md','doc/60-engineering-lessons-and-regression-rules.md','doc/62-system-worker-install-health-0.4.42.md'):
        path=ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8-sig')):
            if target.startswith(('http:','https:','#','mailto:')):continue
            assert (path.parent/target.split('#')[0]).exists(),(name,target)
            links+=1
    report['document_links_checked']=links;out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':True,'full_tests':472,'final_installer_tests':28,'compiled_modules':len(modules),'application_files':len(actual),'document_links':links,'real_system_fixture_passed':True,'live_deployed':False}))
if __name__=='__main__':main()
