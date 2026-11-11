"""Exact artifact self-review. Passing this is NOT formal release acceptance."""
import hashlib,json,re,sys
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));VERSION='0.4.49'


def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))


def main():
    from run_regression_0449 import snapshot
    full=read(ROOT/f'evidence/full-tests-{VERSION}.json')
    assert full['passed'] and full['source_unchanged_during_run'] and full['tests']>=540
    assert full['source_sha256']==snapshot(),'Source changed after final full regression'
    assert sha(ROOT/full['log'])==full['log_sha256']
    assert sha(ROOT/f'evidence/security/{VERSION}/full-regression.log')==full['log_sha256']
    app=ROOT/'dist/GuardDesk';actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    smoke=read(ROOT/'evidence/packaged-smoke.json');assert smoke['passed'] and smoke['application_files']==actual
    assert smoke['exe_sha256']==actual['GuardDesk.exe']
    archive=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz');compiled=[]
    for path in (ROOT/'guarddesk').glob('*.py'):
        name='guarddesk' if path.stem=='__init__' else 'guarddesk.'+path.stem
        if name in archive.toc:
            assert archive.extract(name)==compile(path.read_bytes(),str(path),'exec'),name
            compiled.append(name)
    assert {'guarddesk.document_io','guarddesk.document_sacl','guarddesk.document_worker','guarddesk.document_queue','guarddesk.document_settings','guarddesk.browser_release'}<=set(compiled)
    for area in ('windows','static'):
        for path in (ROOT/'guarddesk'/area).rglob('*'):
            if path.is_file():assert path.read_bytes()==(app/'_internal/guarddesk'/area/path.relative_to(ROOT/'guarddesk'/area)).read_bytes(),path
    for path in (ROOT/'browser-extension').iterdir():
        if path.is_file():assert path.read_bytes()==(app/'_internal/browser-extension'/path.name).read_bytes()
    manifest=read(app/'_internal/agent-release.json');assert manifest['version']==VERSION
    assert manifest['files']=={k:v for k,v in actual.items() if k!='_internal/agent-release.json'}
    from guarddesk.native_installer import source_files
    verified,_=source_files(app);assert verified==actual
    browser_checks=[]
    for stem in ('document-audit','custom-library','audit-sort','audit-search','mail-reports'):
        value=read(ROOT/f'evidence/{stem}-browser-{VERSION}.json')
        assert value['passed'] and value['version']==VERSION and value['frozen_server_used'] and value['exe_sha256']==actual['GuardDesk.exe'] and not value['page_errors'],stem
        browser_checks.append(stem)
    upload=read(ROOT/f'evidence/web-upload-browser-{VERSION}.json');assert upload['passed'] and not upload['browser_page_errors']
    for stem in ('document-audit-performance','document-native-performance'):
        value=read(ROOT/f'evidence/{stem}-{VERSION}.json');assert value['passed']
        for path,digest in value['source_sha256'].items():assert sha(ROOT/path)==digest,path
    native=read(ROOT/'guarddesk/windows/native/document-trace-build.json')
    assert sha(ROOT/'native/document_trace.cpp')==native['source_sha256']
    assert sha(app/'_internal/guarddesk/windows/native/GuardDeskFileTrace.dll')==native['dll_sha256']
    publication=read(ROOT/f'evidence/browser-publication-{VERSION}.json')
    assert publication['passed'] and publication['frozen_exe_sha256']==actual['GuardDesk.exe']
    assert publication['enterprise_zip_sha256']==sha(ROOT/f'dist/GuardDesk-Browser-Enterprise-{VERSION}.zip')
    old={
      'GuardDesk-0.4.48-windows-x64.zip':'b8390b3fd636402b4afd5a6fa962827d2e1b225c71ce5f297ec02847697860ae',
      'GuardDesk-0.4.48-source.zip':'873bd200321e45f6b7f9c59595201d8049b5707e89e69b430b49410155d904bd',
      'GuardDesk-Browser-Enterprise-0.4.48.zip':'9dc9f1259145f7bef9e90f4e40a5dc6bc367a852c3530f4b0e915e43372aefb7'}
    for name,digest in old.items():assert sha(ROOT/'dist'/name)==digest,name
    # Relative Markdown links in new/edited documentation must resolve. External
    # official links remain human-review sources, not fetched from the builder.
    links=[]
    for path in (ROOT/'README.md',ROOT/'doc/README.md',ROOT/'doc/60-engineering-lessons-and-regression-rules.md',ROOT/'doc/68-document-native-and-enterprise-0.4.49.md'):
        for target in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if '://' in target or target.startswith('#'):continue
            target=target.split('#')[0]
            if target:assert (path.parent/target).exists(),(path,target);links.append(target)
    os_test=read(ROOT/f'evidence/document-native-os-{VERSION}.json')
    accepted=bool(os_test.get('passed') and os_test.get('sacl_restored') and os_test.get('dll_sha256')==native['dll_sha256'])
    result={'version':VERSION,'internal_checks_passed':True,'formal_release_ready':False,'office_server_or_endpoint_changed':False,
      'full_regression_tests':full['tests'],'full_regression_log_sha256':full['log_sha256'],'compiled_modules_equal_source':len(compiled),'application_files':len(actual),'exe_sha256':actual['GuardDesk.exe'],'native_dll_sha256':native['dll_sha256'],'frozen_browser_checks':browser_checks,'markdown_links_checked':len(links),'previous_0448_archives_unchanged':old,
      'requirements':['SEC-01','SEC-02','SEC-03','SEC-04','SEC-05','SEC-06','SEC-07','SEC-08','SEC-09','SEC-10','SEC-11','DEF-01','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06','DEF-07'],
      'historical_controls':['GD-004','GD-005','GD-007','GD-011','GD-012','GD-013','GD-014','GD-015','GD-017','GD-018','GD-019','GD-020','GD-021','GD-022','GD-023'],
      'review_type':'developer_self_review_not_independent','native_admin_fixture_accepted':accepted,'native_admin_fixture_status':os_test.get('status'),
      'implemented':['named_document_items_group_endpoint_inheritance','bounded_handle_checked_sacl_provision_and_restore','native_completed_etw_io_candidate_collector','durable_batched_candidate_and_gap_quota_without_old_event_eviction','versioned_document_readiness','offline_crx3_and_https_update_feed_builder','existing_additive_enterprise_policy_lifecycle'],
      'remaining':['native_admin_fixture_acceptance' if not accepted else 'company_windows10_windows11_lifecycle_acceptance','confirmed_high_level_copy_not_provided_candidates_only','company_matching_extension_identity_signer_and_https_or_store_publication','authenticode_exe_dll_scripts_and_timestamp','actual_company_defender_edr_asr_app_control_matrix','independent_security_review_full_sbom_vulnerability_scan','real_user_native_host_and_browser_policy_rollout_not_performed'],
      'evidence':['evidence/full-tests-0.4.49.json','evidence/security/0.4.49/full-regression.log','evidence/packaged-smoke.json','evidence/document-native-performance-0.4.49.json','evidence/document-native-os-0.4.49.json','evidence/document-audit-performance-0.4.49.json'],
      'regression_findings':'CLI local getpass shadow fixed; payload probe isolated from background index without relaxing limit; performance checks serialized after concurrent test load failure; first viewer timeout kept as unconfirmed cause, rechecked on exact final build; actual SetSecurityInfo fixture required READ_CONTROL without DACL/owner write rights; native cache bounds supplemented by a transactional outbox quota including gap notifications',
      'control_evidence':[
        {'ids':['SEC-01','SEC-02','SEC-03','DEF-01','DEF-02'],'completed':'Threat/data-flow design, protected fixed executable/config gate, handle identity/reparse/hardlink checks, least privilege and actual own-file SACL apply/readback/restore; no global audit or Defender change in fixture','evidence':['doc/68-document-native-and-enterprise-0.4.49.md','evidence/document-native-os-0.4.49.json','evidence/sacl-access-variants-0.4.49.json'],'limits':'Installed SYSTEM lifecycle and company policy matrix pending'},
        {'ids':['SEC-04','SEC-05','SEC-06','SEC-07'],'completed':'Existing authenticated/CSRF API and TLS regression; new schema/path/fingerprint rejection; metadata-only candidates, escaped UI and evidence labels','evidence':['evidence/full-tests-0.4.49.json','evidence/document-audit-browser-0.4.49.json','evidence/custom-library-browser-0.4.49.json'],'limits':'No claim of complete ASVS/company retention or regulatory acceptance'},
        {'ids':['SEC-08','SEC-10','SEC-11'],'completed':'Journal before mutation, conflict-safe restore, bounded transactional admission and durable loss counters, crash retry and ACK recovery, frozen package manifests and bounded query/metadata benchmarks','evidence':['tests/test_document_native.py','evidence/packaged-smoke.json','evidence/document-native-performance-0.4.49.json','evidence/document-audit-performance-0.4.49.json'],'limits':'Own synthetic fixtures; no company fleet load, disk-failure no-loss guarantee or complete life-cycle acceptance'},
        {'ids':['SEC-09','DEF-03','DEF-04','DEF-05','DEF-06','DEF-07'],'completed':'Pinned native toolchain/source/DLL hashes, exact final app manifests, explicit unsigned state and preservation of old archives','evidence':['guarddesk/windows/native/document-trace-build.json','evidence/authenticode-0.4.49.json'],'limits':'Full SBOM/vulnerability and independent review, company signing/timestamps and Win10/11 Defender/EDR/ASR/App Control acceptance remain pending; no sample submitted'}]}
    folder=ROOT/f'evidence/security/{VERSION}';folder.mkdir(parents=True,exist_ok=True)
    (folder/'requirements-review.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps({k:v for k,v in result.items() if k not in ('previous_0448_archives_unchanged','requirements','historical_controls','implemented','remaining','evidence')}))


if __name__=='__main__':main()
