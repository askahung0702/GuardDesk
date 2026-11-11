"""Exact candidate self-review; never a formal company release approval."""
import hashlib,json,re,sys,zipfile
from importlib.metadata import version as dependency_version
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));VERSION='0.4.51'

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))

def main():
    from run_regression_0451 import snapshot
    full=read(ROOT/f'evidence/full-tests-{VERSION}.json')
    assert full['passed'] and full['source_unchanged_during_run'] and full['tests']>=565
    assert full['source_sha256']==snapshot()
    assert sha(ROOT/full['log'])==full['log_sha256']
    folder=ROOT/f'evidence/security/{VERSION}';folder.mkdir(parents=True,exist_ok=True)
    log=folder/'full-regression.log'
    if not log.exists():log.write_bytes((ROOT/full['log']).read_bytes())
    assert sha(log)==full['log_sha256']
    app=ROOT/'dist/GuardDesk';actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    smoke=read(ROOT/'evidence/packaged-smoke.json');assert smoke['passed'] and smoke['application_files']==actual
    assert smoke['exe_sha256']==actual['GuardDesk.exe'] and smoke['gui_sha256']==actual['GuardDeskAgent.exe']
    pyz=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz');compiled=[]
    for path in (ROOT/'guarddesk').glob('*.py'):
        name='guarddesk' if path.stem=='__init__' else 'guarddesk.'+path.stem
        if name in pyz.toc:assert pyz.extract(name)==compile(path.read_bytes(),str(path),'exec'),name;compiled.append(name)
    assert {'guarddesk.update_progress','guarddesk.updates','guarddesk.server','guarddesk.store'}<=set(compiled)
    assert {'guarddesk.document_scope','guarddesk.document_io','guarddesk.document_worker','guarddesk.document_queue','guarddesk.browser_host'}<=set(compiled)
    for area in ('windows','static'):
        for path in (ROOT/'guarddesk'/area).rglob('*'):
            if path.is_file():assert path.read_bytes()==(app/'_internal/guarddesk'/area/path.relative_to(ROOT/'guarddesk'/area)).read_bytes(),path
    for path in (ROOT/'browser-extension').iterdir():
        if path.is_file():assert path.read_bytes()==(app/'_internal/browser-extension'/path.name).read_bytes()
    manifest=read(app/'_internal/agent-release.json');assert manifest['version']==VERSION
    assert manifest['files']=={k:v for k,v in actual.items() if k!='_internal/agent-release.json'}
    from guarddesk.native_installer import source_files
    verified,_=source_files(app);assert verified==actual
    browser=[]
    for name in ('update-progress','document-audit','custom-library','audit-sort','audit-search','mail-reports'):
        result=read(ROOT/f'evidence/{name}-browser-{VERSION}.json')
        assert result['passed'] and result['version']==VERSION and result['frozen_server_used'] and result['exe_sha256']==actual['GuardDesk.exe'] and not result['page_errors'],name
        browser.append(name)
    existing=read(ROOT/'evidence/updates-browser-smoke.json');assert existing['passed'] and not existing['page_errors']
    perf=read(ROOT/f'evidence/update-progress-performance-{VERSION}.json');assert perf['passed']
    for path,digest in perf['source_sha256'].items():assert sha(ROOT/path)==digest,path
    old={'GuardDesk-0.4.49-windows-x64.zip':'977510524c149fcef93117a06b045bea29a0a68e5aa6fbad46bd2f47950ea20a','GuardDesk-0.4.49-source.zip':'ad513f76bb785c7aa59f4f08c6b8aecafee3b409e5cd55b47b40649065216a59','GuardDesk-Browser-Enterprise-0.4.49.zip':'1b10f1508df73f0322736614f7c86b450179199155cd08353d033257d52231c4'}
    old.update({'GuardDesk-0.4.50-windows-x64.zip':'69d92f118b76deda5b9330653ca8b654be0895ceaf994760d2d7aa91d874b92c','GuardDesk-0.4.50-source.zip':'e94b8af6eb3fbe61148a436f5c9b86662e8a1b423434c0fbc0202fb0b7e58664'})
    for name,digest in old.items():assert sha(ROOT/'dist'/name)==digest,name
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.49-windows-x64.zip') as archive:prior_dependencies=json.loads(archive.read('build-info.json'))
    observed_dependencies={name:dependency_version(name) for name in ('cryptography','cffi','pyinstaller','pyreadline3','Pillow')}
    assert all(prior_dependencies[name]==value for name,value in observed_dependencies.items())
    expected={'guarddesk/__init__.py','guarddesk/application_control.py','guarddesk/browser_host.py','guarddesk/document_audit.py','guarddesk/document_io.py','guarddesk/document_queue.py','guarddesk/document_scope.py','guarddesk/document_worker.py','guarddesk/policy_progress.py','guarddesk/server.py','guarddesk/static/app.js','guarddesk/static/audit_ui.js','guarddesk/static/index.html','guarddesk/static/management.js','guarddesk/windows/native/GuardDeskFileTrace.dll','guarddesk/windows/native/document-trace-build.json'}
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.50-source.zip') as archive:
        old_files=json.loads(archive.read('MANIFEST-SHA256.json'))
        changed={p.relative_to(ROOT).as_posix() for p in (ROOT/'guarddesk').rglob('*') if p.is_file() and '__pycache__' not in p.parts and old_files.get(p.relative_to(ROOT).as_posix())!=sha(p)}
        assert changed==expected,changed^expected
        for name in ('requirements.txt','requirements-build.txt'):assert sha(ROOT/name)==old_files[name],name
    native=read(ROOT/'guarddesk/windows/native/document-trace-build.json')
    assert native['source_sha256']==sha(ROOT/'native/document_trace.cpp')
    assert native['dll_sha256']==actual['_internal/guarddesk/windows/native/GuardDeskFileTrace.dll']
    os_proof=read(ROOT/f'evidence/general-file-audit-os-{VERSION}.json')
    assert os_proof['passed'] and os_proof['dll_sha256']==native['dll_sha256'] and os_proof['named_document_rules']==0
    assert not any(os_proof[k] for k in ('sacl_changed','global_audit_policy_changed','defender_changed','live_enrollment_accessed'))
    assert os_proof['distinct_native_opens']>=2 and os_proof['literal_and_user_template_native_exclusions_passed'] and os_proof['own_trace_stopped']
    general_perf=read(ROOT/f'evidence/general-file-audit-performance-{VERSION}.json');assert general_perf['passed']
    for name,digest in general_perf['source_sha256'].items():assert sha(ROOT/name)==digest,name
    links=0
    for path in (ROOT/'README.md',ROOT/'doc/README.md',ROOT/'doc/60-engineering-lessons-and-regression-rules.md',ROOT/'doc/70-document-readiness-and-test-isolation-0.4.51.md'):
        for target in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if '://' in target or target.startswith('#'):continue
            target=target.split('#')[0]
            if target:assert (path.parent/target).exists(),(path,target);links+=1
    signatures=read(ROOT/f'evidence/authenticode-{VERSION}.json')
    for signature in signatures:assert signature['SHA256']==sha(ROOT/signature['Path'])
    result={'version':VERSION,'internal_checks_passed':True,'formal_release_ready':False,'office_changed':True,'candidate_deployed_to_office':False,'review_type':'developer_self_review_not_independent','full_regression_tests':full['tests'],'full_regression_log_sha256':full['log_sha256'],'exe_sha256':actual['GuardDesk.exe'],'native_dll_sha256':actual['_internal/guarddesk/windows/native/GuardDeskFileTrace.dll'],'application_files':len(actual),'compiled_modules_equal_source':len(compiled),'changed_product_files':sorted(changed),'endpoint_installer_and_update_wire_protocols_unchanged':True,'native_trace_abi_changed_and_size_checked':True,'existing_0449_archives_unchanged':old,'direct_build_dependencies_unchanged_from_0449':observed_dependencies,'markdown_links_checked':links,'frozen_browser_checks':browser,
      'requirements':['SEC-01','SEC-02','SEC-03','SEC-04','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11','DEF-01','DEF-02','DEF-04','DEF-05'],
      'historical_controls':['GD-005','GD-006','GD-007','GD-008','GD-009','GD-010','GD-014','GD-017','GD-019','GD-020','GD-021','GD-022','GD-023'],
      'implemented':['general_file_policy_automatically_collects_native_reads_and_copy_candidates_without_named_custom_rules','same_base_scope_and_shared_exclusions_no_tree_scan_no_general_sacl_mutation','native_early_literal_and_user_template_exclusions','open_instance_dedup_retains_immediate_reopen','bounded_mixed_read_copy_durable_queue_and_gap_recovery','discard_mixed_batch_across_native_gap','automatic_native_host_registration_requires_selected_installation','preserve_all_conflicting_enrollment_and_browser_manifest_values','disposable_frozen_desktop_probe_compares_live_registry_before_after','audit_selected_endpoint_latest_metadata_diagnostics_without_history_queries','general_policy_enablement_separate_from_observed_collector_readiness','obsolete_copy_and_sacl_requirement_notices_corrected'],
      'evidence':['doc/70-document-readiness-and-test-isolation-0.4.51.md','tests/test_browser_deployment_lifecycle.py','tests/test_document_audit.py','evidence/full-tests-0.4.51.json','evidence/security/0.4.51/full-regression.log','evidence/document-audit-browser-0.4.51.json','evidence/packaged-smoke.json','evidence/dev-browser-registration-repair-20261022.json','evidence/authenticode-0.4.51.json'],
      'security':'New completed-read metadata source follows existing general file_audit consent, scope and exclusions with bounded ETW/caches/queues; no content, new OS privilege, destination, task or dependency. Automatic per-user registration narrowed to selected installation; fixed metadata diagnostics retain existing authorization, escaping and no history reads. Actual DEV repair was scoped, backed up and config hashes verified; no proxy, credential, queue, Defender or process change. General collection not deployed to office.',
      'historical_controls_document_fix':['GD-015','GD-018','GD-020','GD-021','GD-022','GD-024'],
      'remaining':['unsigned_internal_trial_authenticode_and_timestamp_pending','company_win10_win11_defender_edr_asr_app_control_lifecycle_acceptance_pending','full_sbom_vulnerability_and_independent_security_review_pending','company_extension_publication_source_and_matching_signing_identity_not_provided','DEV_native_component_upgrade_and_end_to_end_actual_reads_uploads_not_verified','candidate_not_deployed_to_office_server_or_agents','cached_DEV_host_failure_status_requires_next_agent_start_to_refresh','extension_installation_and_profile_coverage_not_proven_by_registry_repair','ETW_names_memory_mapped_or_preexisting_open_coverage_not_complete','real_general_all_local_workload_performance_under_company_Defender_not_accepted','SYSTEM_session_virtual_drive_and_alias_coverage_not_accepted'],
      'verification_observations':['Initial serial mail UI load timed out; identical EXE and unchanged test passed isolated rerun. First failure state not captured, root cause unconfirmed; both logs retained.']}
    (folder/'requirements-review.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('existing_0449_archives_unchanged','implemented','evidence','remaining','regression_findings')}))

if __name__=='__main__':main()
