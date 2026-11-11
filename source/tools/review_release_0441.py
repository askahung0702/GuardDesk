"""Review the exact 0.4.41 internal trial, including incomplete OS acceptance."""
import hashlib,json,re,shutil,subprocess,sys,zipfile
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
VERSION='0.4.41'
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_text(encoding='utf-8-sig'))
def main():
    folder=ROOT/f'evidence/security/{VERSION}';folder.mkdir(exist_ok=True)
    path=ROOT/'runtime/native-installer-regression.txt';log=path.read_text(encoding='utf-8-sig',errors='replace').replace('\r\n','\n')
    match=re.search(r'Ran (\d+) tests in ([\d.]+)s',log)
    assert match and int(match[1])==464 and '\nOK\n' in log and 'FAILED (' not in log,log[-1500:]
    final_path=ROOT/'runtime/native-installer-targeted-final.txt';final=final_path.read_text(encoding='utf-8-sig',errors='replace').replace('\r\n','\n')
    final_match=re.search(r'Ran (\d+) tests in ([\d.]+)s',final)
    assert final_match and int(final_match[1])==21 and '\nOK\n' in final and 'FAILED (' not in final,final[-1500:]
    regression={'passed':True,'tests':int(match[1]),'seconds':float(match[2]),'log_sha256':sha(path),'final_native_tests':21,'final_native_seconds':float(final_match[2]),'final_native_log_sha256':sha(final_path),'final_unique_tests':466,'scope':'Complete 464-test regression, followed by all 21 native installer tests after the final concurrent-update guard, including two added race cases. Isolated fixture OS operations are not actual endpoint installation acceptance.'}
    app=ROOT/'dist/GuardDesk';smoke=read(ROOT/'evidence/packaged-smoke.json')
    actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    assert smoke['passed'] and smoke['application_files']==actual and smoke['exe_sha256']==sha(app/'GuardDesk.exe') and smoke['gui_sha256']==sha(app/'GuardDeskAgent.exe')
    browsers={}
    for name in (f'custom-library-browser-{VERSION}.json',f'mail-reports-browser-{VERSION}.json'):
        value=read(ROOT/'evidence'/name)
        assert value['passed'] and value['frozen_server_used'] and value['exe_sha256']==sha(app/'GuardDesk.exe') and value['page_errors']==[]
        browsers[name]=value
    timeout_path=ROOT/'runtime/native-installer-custom-browser-initial-timeout.txt'
    assert 'TimeoutError' in timeout_path.read_text(errors='replace')
    browser_retry={'initial_result':'custom library locator timed out during concurrent checks','initial_log_sha256':sha(timeout_path),'retry':'same unchanged compiled bytes passed complete custom-library browser test','root_cause':'not established; not claimed as a production fix','production_sources_changed_for_retry':False}
    compiled=[];archive=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz')
    for path in (ROOT/'guarddesk').glob('*.py'):
        name='guarddesk' if path.stem=='__init__' else 'guarddesk.'+path.stem
        if name in archive.toc:
            assert archive.extract(name)==compile(path.read_bytes(),str(path),'exec'),name
            compiled.append(name)
    assert all('guarddesk.'+name in compiled for name in ('native_installer','endpoint_setup','endpoint_package','usb_install','installer_channel','custom_library','mail_reports'))
    for area in ('static','windows'):
        for path in (ROOT/'guarddesk'/area).rglob('*'):
            if path.is_file():assert path.read_bytes()==(app/'_internal/guarddesk'/area/path.relative_to(ROOT/'guarddesk'/area)).read_bytes(),path
    manifest=read(app/'_internal/agent-release.json')
    assert manifest['version']==VERSION and manifest['files']=={k:v for k,v in actual.items() if k!='_internal/agent-release.json'}
    from guarddesk.native_installer import source_files
    verified,total=source_files(app);assert verified==actual
    from guarddesk.windows_controls import is_admin
    assert not is_admin(),'This review deliberately verifies non-admin guard, never elevation'
    probe=subprocess.run([str(app/'GuardDesk.exe'),'endpoint-native-install','--config',str(ROOT/'runtime/nonexistent-readonly-probe.json'),'--action','Status','--diagnostic-pipe','GuardDesk-invalid-probe'],capture_output=True,timeout=15)
    assert probe.returncode!=0 and '此步驟需要安裝入口提出的 Windows UAC' in (probe.stdout+probe.stderr).decode('utf-8',errors='replace')
    prior={'GuardDesk-0.4.40-windows-x64.zip':'3a813cd9fabdf8d0f1d142e132561a963b164902ff1a18a4b67e89f937c5154c','GuardDesk-0.4.40-source.zip':'5704f250c6630ae9d0f6da20b1174b53de6586e36de49ce804d7e548fbee9fde','GuardDesk-0.4.39-windows-x64.zip':'936d81b2f3bd99791332db2f9b16dd6454ca39e338348a7caafe3e04c111cfed','GuardDesk-0.4.39-source.zip':'30db6c2194033b91303bca0af869c77df34af26fe0af3ddb34f1ba4a5d80d251'}
    for name,digest in prior.items():assert sha(ROOT/'dist'/name)==digest
    critical=['guarddesk/agent.py','guarddesk/endpoint_setup.py','guarddesk/endpoint_package.py','guarddesk/installer_channel.py','guarddesk/policy.py','guarddesk/policy_defaults.py','guarddesk/native_usb.py','guarddesk/application_control.py','guarddesk/remote.py','guarddesk/removal.py','guarddesk/update_native.py','guarddesk/update_client.py','guarddesk/update_windows.py','guarddesk/updater_refresh.py','guarddesk/updater_maintenance.py','guarddesk/updates.py','guarddesk/event_storage.py','guarddesk/audit_reports.py','guarddesk/audit_archive.py','guarddesk/custom_network.py','guarddesk/custom_software.py','guarddesk/custom_library.py','guarddesk/custom_settings.py','guarddesk/custom_client.py','guarddesk/custom_windows.py','guarddesk/mail_reports.py','requirements.txt','requirements-build.txt']
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.40-source.zip') as z:
        critical += [n for n in z.namelist() if n.startswith(('browser-extension/','guarddesk/windows/'))]
        for name in critical:assert z.read(name)==(ROOT/name).read_bytes(),name
    signatures=read(folder/'signatures.json')
    for record in signatures:assert sha(ROOT/record['path'])==record['sha256']
    initial=read(ROOT/'evidence/native-installer-os-primitives-initial-failure-0.4.41.json')
    assert not initial['passed'] and len(initial['checks'])==3 and initial['cleanup_errors']==[]
    scope={'version':VERSION,'user_policy_evidence':{'source':'user supplied Get-ExecutionPolicy -List on affected Windows client','scopes':{s:'Undefined' for s in ('MachinePolicy','UserPolicy','Process','CurrentUser','LocalMachine')},'default_inference':'Restricted on Windows client; corroborated by user script-disabled screenshot','does_not_prove_absence_of_other_company_controls':True},'initial_elevated_os_test':initial,'fix':'Exact image-file lock replaces querying unrelated same-name process handles. Real unprivileged image-lock test passed in full regression.','elevated_retest':{'status':'UAC_cancelled','windows_error':1223,'complete_current_os_test_passed':False,'no_repeated_UAC_prompts':True},'live_endpoint_installation_verified':False,'office_server_or_endpoint_modified_this_change':False,'execution_policy_changed':False,'defender_or_company_controls_weakened':False}
    (ROOT/'evidence/native-installer-validation-scope-0.4.41.json').write_text(json.dumps(scope,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    (folder/'regression.json').write_text(json.dumps(regression,indent=2)+'\n',encoding='utf-8')
    shutil.copyfile(ROOT/'evidence/packaged-smoke.json',ROOT/f'evidence/packaged-smoke-{VERSION}.json')
    requirements={'version':VERSION,'release_status':'unsigned_internal_trial','passed_with_gaps':True,'review_type':'developer_self_review_not_independent','lessons':['GD-003','GD-004','GD-005','GD-007','GD-009','GD-020','GD-021'],'requirements':['SEC-01','SEC-02','SEC-03','SEC-05','SEC-06','SEC-07','SEC-08','SEC-09','SEC-10','SEC-11','DEF-01','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],'authorization':'User requests working single-entry endpoint installation, no manual missing PS1. User supplied all policy scopes Undefined. Existing identity and queued data must be retained.','controls':['Fixed-purpose native installer uses official Win32 ACL and Task Scheduler; no PowerShell installation script, inline-script workaround, policy override, security exclusion, new dependency or remote shell','Retains existing fixed UAC helper and diagnostic-only bounded local pipe; native failure reports original stage and rollback status','Private Admin/SYSTEM owned paths, reparse and parent checks, exact manifest and bounded streaming hashes before and after staging','Two complete protected application trees staged before stopping prior tasks; precise image lock, fixed task identity validation, backups and transaction journal','Preserves original endpoint ID, connection identity, update trust pin, CA and ordinary Agent offline queue; refuses competing/foreign device tasks','Current and rollback workers require fresh exact-version health with exact protected executable PID; failed stop/restore remains unresolved and retains evidence','Removal restores control before deleting tasks and retains files/data; new installation restores control on failure','No live office deployment, no mail, no Defender/EDR/PS policy change; inherited storage/collection/update/custom library contracts byte-compared to 0.4.40'],'gaps':['Actual full UAC/installation/reboot/update/uninstall on affected endpoint not performed. Controlled OS primitives partially validated, later UAC cancelled; never labelled complete','Optional AppLocker/software identification and some controls remain PowerShell-dependent and must report policy block honestly','Power loss during directory switch requires MIS recovery from protected journal/backups; no automatic generation cleanup yet','Unsigned internal trial; company-trusted signing, actual Windows 10/11 Defender/EDR/App Control acceptance, independent review, full SBOM/vulnerability scans and company requirements mapping incomplete','GD-006 generic Server bundle error text remains open; prior onsite ACL repair is separate'],'regression':regression,'validation_scope':scope,'compiled_modules_equal_source':compiled,'application_files':len(actual),'static_windows_equal_source':True,'critical_sources_unchanged':critical,'prior_archives_unchanged':prior,'frozen_browsers':browsers,'signatures':signatures}
    out=folder/'requirements-review.json';out.write_text(json.dumps(requirements,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    links=0
    for name in ['README.md','doc/README.md','doc/60-engineering-lessons-and-regression-rules.md','doc/61-native-endpoint-installer-0.4.41.md']:
        source=ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',source.read_text(encoding='utf-8-sig')):
            if target.startswith(('http:','https:','#','mailto:')):continue
            assert (source.parent/target.split('#')[0]).exists(),(name,target)
            links+=1
    requirements['document_links_checked']=links;requirements['browser_retry']=browser_retry;requirements['native_source_validation']={'files':len(verified),'bytes':total};requirements['frozen_native_admin_guard']={'passed':True,'exit_code':probe.returncode,'live_mutation':False};out.write_text(json.dumps(requirements,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':True,'full_tests':regression['tests'],'compiled_modules':len(compiled),'application_files':len(actual),'document_links':links,'live_controls_changed':False,'full_os_acceptance':False,'status':'unsigned_internal_trial'}))
if __name__=='__main__':main()
