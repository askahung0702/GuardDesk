"""Exact-tree developer review of the limited 0.4.48 internal trial."""
import hashlib,json,re,shutil,sys,zipfile
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
VERSION='0.4.48'


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def main():
    folder=ROOT/f'evidence/security/{VERSION}';folder.mkdir(parents=True,exist_ok=True)
    log=ROOT/'runtime/document-audit-full-regression-0448-final.txt'
    text=log.read_text(encoding='utf-8-sig',errors='replace').replace('\r\n','\n')
    match=re.search(r'Ran (\d+) tests in ([\d.]+)s',text)
    assert match and int(match[1])==520 and '\nOK\n' in text and 'FAILED (' not in text,text[-2500:]
    target_log=ROOT/'runtime/document-audit-proxy-regression-after-0448.txt'
    target_text=target_log.read_text(encoding='utf-8-sig',errors='replace').replace('\r\n','\n')
    assert 'Ran 8 tests' in target_text and '\nOK\n' in target_text and 'FAILED (' not in target_text
    app=ROOT/'dist/GuardDesk'
    actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    smoke=read(ROOT/'evidence/packaged-smoke.json')
    assert smoke['passed'] and smoke['application_files']==actual and smoke['exe_sha256']==actual['GuardDesk.exe']
    archive=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz');compiled=[]
    for p in (ROOT/'guarddesk').glob('*.py'):
        name='guarddesk' if p.stem=='__init__' else 'guarddesk.'+p.stem
        if name in archive.toc:
            assert archive.extract(name)==compile(p.read_bytes(),str(p),'exec'),name
            compiled.append(name)
    assert {'guarddesk.browser_deployment','guarddesk.document_audit','guarddesk.file_audit_check'}<=set(compiled)
    for area in ('static','windows'):
        for p in (ROOT/'guarddesk'/area).rglob('*'):
            if p.is_file():assert p.read_bytes()==(app/'_internal/guarddesk'/area/p.relative_to(ROOT/'guarddesk'/area)).read_bytes(),p
    for p in (ROOT/'browser-extension').iterdir():
        if p.is_file():assert p.read_bytes()==(app/'_internal/browser-extension'/p.name).read_bytes()
    manifest=read(app/'_internal/agent-release.json')
    assert manifest['version']==VERSION and manifest['files']=={k:v for k,v in actual.items() if k!='_internal/agent-release.json'}
    from guarddesk.native_installer import source_files
    verified,total=source_files(app);assert verified==actual
    browsers={}
    for stem in ('document-audit','audit-sort','audit-search','mail-reports','custom-library'):
        value=read(ROOT/f'evidence/{stem}-browser-{VERSION}.json')
        assert value['passed'] and value['frozen_server_used'] and value['version']==VERSION and value['exe_sha256']==actual['GuardDesk.exe'] and not value['page_errors'],stem
        browsers[stem]=value
    native=read(ROOT/f'evidence/extension-native-smoke-{VERSION}.json')
    assert native['status']=='blocked_existing_native_host' and native['no_registry_writes_attempted'] and native['exe_sha256']==actual['GuardDesk.exe']
    upload=read(ROOT/f'evidence/web-upload-browser-{VERSION}.json');assert upload['passed'] and not upload['browser_page_errors']
    perf=read(ROOT/f'evidence/document-audit-performance-{VERSION}.json')
    assert perf['passed'] and perf['synthetic_rows']==300000 and len(perf['results'])==8
    for name,digest in perf['source_sha256'].items():assert sha(ROOT/name)==digest
    copy=read(ROOT/f'evidence/document-copy-native-poc-{VERSION}.json')
    assert copy['passed'] and not copy['general_copy_collector_implemented']
    final_assets=read(ROOT/f'evidence/extension-finalization-{VERSION}.json')
    assert final_assets['passed'] and final_assets['executables_and_console_assets_unchanged'] and final_assets['base_library_member_bytes_equal_sealed_047'] and final_assets['exe_sha256']==actual['GuardDesk.exe']
    previous=read(ROOT/'evidence/security/0.4.47/requirements-review.json')
    prior=previous['prior_archives_unchanged'].copy()
    for item in read(ROOT/'evidence/release-0.4.47-final.json')['archives']:prior[item['name']]=item['sha256']
    prior_missing=[];prior_verified={}
    for name,digest in prior.items():
        if not (ROOT/'dist'/name).is_file():prior_missing.append(name);continue
        assert sha(ROOT/'dist'/name)==digest,name
        prior_verified[name]=digest
    assert 'GuardDesk-0.4.47-windows-x64.zip' in prior_verified and 'GuardDesk-0.4.47-source.zip' in prior_verified
    changed=[];unchanged=[];added=[]
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.47-source.zip') as sealed:
        for p in sorted((ROOT/'guarddesk').rglob('*')):
            if not p.is_file() or '__pycache__' in p.parts:continue
            name=p.relative_to(ROOT).as_posix()
            if name not in sealed.namelist():added.append(name)
            elif p.read_bytes()==sealed.read(name):unchanged.append(name)
            else:changed.append(name)
        for name in ('requirements.txt','requirements-build.txt','app.py','tools/GuardDesk.spec'):
            assert (ROOT/name).read_bytes()==sealed.read(name),name
    for name in ('store','event_storage','audit_sort','audit_search','audit_search_index','audit_reports','mail_reports','native_installer','update_client','update_windows','updater_maintenance','updater_refresh','custom_library','custom_settings'):
        assert 'guarddesk/'+name+'.py' in unchanged,name
    signatures=read(folder/'signatures.json')
    for item in signatures:assert sha(ROOT/item['path'])==item['sha256']
    from guarddesk.browser_deployment import artifact
    enterprise=ROOT/f'dist/GuardDesk-Browser-Enterprise-{VERSION}.zip'
    # ZIP timestamps can differ; compare contents to the same compiled artifact
    # factory instead of requiring a timestamp-dependent outer hash.
    import io
    with zipfile.ZipFile(enterprise) as a,zipfile.ZipFile(io.BytesIO(artifact())) as b:
        assert a.namelist()==b.namelist()
        for name in a.namelist():
            if name.endswith('.zip'):
                with zipfile.ZipFile(io.BytesIO(a.read(name))) as x,zipfile.ZipFile(io.BytesIO(b.read(name))) as y:
                    assert x.namelist()==y.namelist()
                    assert all(x.read(n)==y.read(n) for n in x.namelist())
            else:assert a.read(name)==b.read(name)
    links=0
    for name in ('README.md','doc/README.md','doc/33-web-upload-and-console-performance-0.4.22.md','doc/60-engineering-lessons-and-regression-rules.md'):
        p=ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',p.read_text(encoding='utf-8-sig')):
            if target.startswith(('http:','https:','#','mailto:')):continue
            resolved=(p.parent/target.split('#')[0]).resolve()
            assert resolved.exists() or resolved==(folder/'requirements-review.json').resolve(),(name,target)
            links+=1
    report={'version':VERSION,'status':'unsigned_internal_trial_partial_capability','review_type':'developer_self_review_not_independent','passed_with_gaps':True,
            'requirements':['SEC-01','SEC-02','SEC-03','SEC-04','SEC-05','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11','DEF-01','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],
            'lessons':['GD-005','GD-007','GD-008','GD-009','GD-011','GD-012','GD-013','GD-014','GD-015','GD-017','GD-018','GD-020','GD-021','GD-023'],
            'implemented':['Unified document query projection without duplicating immutable evidence, preserving legacy files API and daily file-change report semantics','Read/file-copy/upload readiness from bounded current endpoint reports, not event history','Read-only Windows success audit query, last eligible read observation, single-object SACL diagnostic without traversal or security changes','Extension version/browser handshake bounded to two per-user DB entries and one write/minute/browser with freshness limit','Interactive desktop per-user Native Host registration without enabling proxy or changing identity; conflict preservation and owned host removal','New hosts reconnect to selected version after immutable user update; pre-48 running hosts still need first-migration verification','Admin/CSRF enterprise source ZIP with pending publication settings; protected native MIS plan/apply/restore additive policy transaction and uninstall restoration'],
            'not_implemented':['Automatic targeted SACL provisioning','Generic Explorer/other-application copy collection or minifilter driver','Company extension publication/CRX signing/managed installation and site-specific ChatGPT acceptance','Live office Server/endpoint deployment'],
            'threat_analysis':{'assets':'Existing path/account/URL evidence plus browser version and connection timestamps','boundaries':['Native Messaging untrusted fields -> strict browser/version validation and bounded user DB state','Admin CSRF download -> fixed product assets only; no credential/profile data','MIS CLI -> fixed protected native executable/config -> whitelisted HKLM browser ForceList slots and protected ownership journal','Read diagnostic -> one explicit Windows object SACL; no child traversal or content read'],
                'controls':['No additional endpoint policy schema or legacy wire fields, permissions, startup tasks or outbound destinations by default','No Defender/AMSI/ASR/AppControl/ExecutionPolicy changes; no injection, TLS interception or competitor code reuse','Typed HTTPS source validation; stable ID must match Native Host key; no silent signing-key replacement','Only new empty registry slots; durable journal before mutation, readback, rollback and external-conflict preservation; no browser kill/profile edits','Escaped UI, parameterized existing query pipeline, stable cursor/sort/CSV; original evidence unchanged'],
                'residual':'Connected is one browser observation, not all profiles or tamper-proof attestation; ReadData/ListDirectory does not prove human reading; HTTP response does not prove website saving. Company data classification, encryption/retention and formal rules still pending.'},
            'tests':{'full_run_cases':int(match[1]),'seconds':float(match[2]),'log_sha256':sha(log),'source_final_full_suite':False,'final_document_cases':8,'final_target_log_sha256':sha(target_log),'final_distinct_cases':521,'counting':'520 complete regression before final proxy guard; final eight document cases overlap seven already counted and add one reproducer. Complete 521-case rerun is not claimed. Final frozen integration/compiled checks cover the changed Native Host and extension.'},
            'compiled_modules_equal_source':compiled,'application_files':len(actual),'application_bytes':total,'source_changes':changed,'source_additions':added,'critical_sources_unchanged':unchanged,
            'frozen_browsers':browsers,'native_host':native,'web_upload':upload,'metadata_query_performance':perf,'controlled_copy_api_poc':copy,
            'extension_finalization':final_assets,'proxy_regression_reproducer':{'before_log_sha256':sha(ROOT/'runtime/document-audit-proxy-regression-before-0448.txt'),'after_log_sha256':sha(target_log),'failure_expected_before_fix':True,'final_document_cases_passed':8},
            'prior_archives_unchanged':prior_verified,'prior_archives_missing_at_review':prior_missing,'prior_archives_expected':prior,'document_links_checked':links,'signatures':signatures,
            'enterprise_package':{'path':str(enterprise.relative_to(ROOT)),'sha256':sha(enterprise),'status':'publication_required'},
            'development_findings':['Initial source browser test used wait_for_function string evaluation blocked by existing CSP; changed test polling, did not relax product CSP','Initial 516-case regression preceded final automatic-host/removal integration; subsequent full 520-case run passed','Final review reproduced an automatic-audit-only deployment routing domain rules to an unconfigured proxy. Added one negative/positive case, gated native response, exposed pending state, reran eight document cases and final browser/frozen integration; did not claim a full 521-case run','Sandbox HKCU write was denied. Separate bounded test outside sandbox detected an existing native registration and stopped before writes; no ACL or existing enrollment changed'],
            'gaps':['Unsigned components and source extension only; no matching CRX private key or publication source provided','No company Win10/11 Defender/EDR, actual deployment/removal, browser management or fleet resource acceptance','Registry policy transaction tests use an injected fixture; no live HKLM policy mutation. Real HKCU Native Host registration/browser test blocked by existing enrollment preflight; direct frozen Native Messaging and owned browser loopback tests are separate evidence','Read success-policy API and SACL diagnostic are not proof of full directory coverage; Security log can be overwritten under load','Only metadata unified-query performance measured; no newly enabled broad read-auditing load or generic kernel copy collector','No independent review/full SBOM/vulnerability scan or company regulatory/retention signoff'],
            'office_server_or_endpoints_changed':False,'live_mail_sent':False,'live_machine_policy_changed':False}
    (folder/'requirements-review.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    shutil.copyfile(ROOT/'evidence/packaged-smoke.json',ROOT/f'evidence/packaged-smoke-{VERSION}.json')
    print(json.dumps({'passed_with_gaps':True,'full_tests':int(match[1]),'compiled_modules':len(compiled),'application_files':len(actual),'office_deployed':False}))


if __name__=='__main__':main()
