"""Exact candidate self-review; never a formal company release approval."""
import copy,hashlib,json,re,sys,types,zipfile
from importlib.metadata import version as dependency_version
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));VERSION='0.4.53'

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))

def main():
    from run_regression_0453 import snapshot
    full=read(ROOT/f'evidence/full-tests-{VERSION}.json')
    assert full['passed'] and full['source_unchanged_during_run'] and full['tests']>=578
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
    assert {'guarddesk.file_access','guarddesk.document_scope','guarddesk.document_io','guarddesk.document_worker','guarddesk.document_queue','guarddesk.browser_host','guarddesk.document_process'}<=set(compiled)
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
    old={'GuardDesk-0.4.52-windows-x64.zip':'ba60b2e8d25e58d910113a6f7153858dd775c1f802d95479ab2ba6d32d0171b3','GuardDesk-0.4.52-source.zip':'b0a3f817f4f60cf48e2f3057cf6d8ec16c1a210c5d861acfb9dc57ca8ec351c9'}
    for name,digest in old.items():assert sha(ROOT/'dist'/name)==digest,name
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.52-windows-x64.zip') as archive:prior_dependencies=json.loads(archive.read('build-info.json'))
    observed_dependencies={name:dependency_version(name) for name in ('cryptography','cffi','pyinstaller','pyreadline3','Pillow')}
    assert all(prior_dependencies[name]==value for name,value in observed_dependencies.items())
    expected={'guarddesk/__init__.py','guarddesk/file_access.py','guarddesk/policy.py','guarddesk/policy_progress.py','guarddesk/server.py','guarddesk/static/management.js','guarddesk/document_io.py','guarddesk/document_process.py','guarddesk/document_worker.py','guarddesk/static/app.js','guarddesk/static/audit_ui.js','guarddesk/static/index.html','guarddesk/windows/native/GuardDeskFileTrace.dll','guarddesk/windows/native/document-trace-build.json'}
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.52-source.zip') as archive:
        old_files=json.loads(archive.read('MANIFEST-SHA256.json'))
        changed={p.relative_to(ROOT).as_posix() for p in (ROOT/'guarddesk').rglob('*') if p.is_file() and '__pycache__' not in p.parts and old_files.get(p.relative_to(ROOT).as_posix())!=sha(p)}
        assert changed==expected,changed^expected
        for name in ('requirements.txt','requirements-build.txt'):assert sha(ROOT/name)==old_files[name],name
        legacy=types.ModuleType('guarddesk.legacy_policy');legacy.__package__='guarddesk'
        exec(compile(archive.read('guarddesk/policy.py'),'sealed-0.4.52-policy.py','exec'),legacy.__dict__)
        from guarddesk.policy import DEFAULT_POLICY,agent_policy_wire
        from guarddesk.file_access import PROCESS,SERVICES
        policy=copy.deepcopy(DEFAULT_POLICY);policy['file_audit']['exclude_paths']=[PROCESS+'OneDrive.exe',SERVICES]
        assert legacy.decode_agent_policy(agent_policy_wire({'body':policy}))['body']==policy
    native=read(ROOT/'guarddesk/windows/native/document-trace-build.json')
    assert native['source_sha256']==sha(ROOT/'native/document_trace.cpp')
    assert native['dll_sha256']==actual['_internal/guarddesk/windows/native/GuardDeskFileTrace.dll']
    os_proof=read(ROOT/f'evidence/general-file-audit-os-{VERSION}.json')
    assert os_proof['passed'] and os_proof['dll_sha256']==native['dll_sha256'] and os_proof['named_document_rules']==0
    assert not any(os_proof[k] for k in ('sacl_changed','global_audit_policy_changed','defender_changed','live_enrollment_accessed'))
    assert os_proof['empty_file_open_observations']>=1 and os_proof['empty_file_no_fabricated_read']
    assert os_proof['mapped_open_observations']>=1 and os_proof['mapped_open_not_claimed_read'] and os_proof['failed_open_not_emitted']
    assert all(os_proof[k] for k in ('child_empty_and_mapped_survive_real_source_filter','child_process_birth_image_session_verified','actual_directory_and_drive_root_rejected','collector_self_rejected'))
    assert os_proof['native_stats']['dropped']==0 and os_proof['native_stats']['schema_unresolved']==0
    assert os_proof['distinct_native_opens']>=2 and os_proof['literal_and_user_template_native_exclusions_passed'] and os_proof['own_trace_stopped']
    general_perf=read(ROOT/f'evidence/general-file-audit-performance-{VERSION}.json');assert general_perf['passed']
    for name,digest in general_perf['source_sha256'].items():assert sha(ROOT/name)==digest,name
    links=0
    for path in (ROOT/'README.md',ROOT/'doc/README.md',ROOT/'doc/60-engineering-lessons-and-regression-rules.md',ROOT/'doc/72-file-access-noise-and-installed-notepad-0.4.53.md'):
        for target in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if '://' in target or target.startswith('#'):continue
            target=target.split('#')[0]
            if target:assert (path.parent/target).exists(),(path,target);links+=1
    signatures=read(ROOT/f'evidence/authenticode-{VERSION}.json')
    for signature in signatures:assert signature['SHA256']==sha(ROOT/signature['Path'])
    result={'version':VERSION,'internal_checks_passed':True,'formal_release_ready':False,'office_changed':False,'candidate_deployed_to_office':False,'review_type':'developer_self_review_not_independent','full_regression_tests':full['tests'],'full_regression_log_sha256':full['log_sha256'],'exe_sha256':actual['GuardDesk.exe'],'native_dll_sha256':actual['_internal/guarddesk/windows/native/GuardDeskFileTrace.dll'],'application_files':len(actual),'compiled_modules_equal_source':len(compiled),'changed_product_files':sorted(changed),'endpoint_installer_and_update_wire_protocols_unchanged':True,'native_trace_record_abi_unchanged_size_checked':True,'completed_open_and_aux_stats_capability_checked':True,'existing_0452_archives_unchanged':old,'direct_build_dependencies_unchanged_from_0452':observed_dependencies,'markdown_links_checked':links,'frozen_browser_checks':browser,
      'requirements':['SEC-01','SEC-02','SEC-03','SEC-04','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11','DEF-01','DEF-02','DEF-04','DEF-05'],
      'historical_controls':['GD-005','GD-006','GD-007','GD-008','GD-009','GD-010','GD-014','GD-017','GD-018','GD-019','GD-020','GD-021','GD-022','GD-023','GD-024'],
      'implemented':['default_verified_session_zero_background_filter','exact_program_file_open_read_exclusions_in_general_group_policy','positive_file_type_evidence_and_bounded_metadata_queries','source_collector_self_exclusion_no_feedback_loop','legacy_body_compatible_reserved_rules_and_versioned_receipt','ordinary_info_opens_only_warnings_mutations_uploads_history_preserved'],
      'evidence':['doc/72-file-access-noise-and-installed-notepad-0.4.53.md','tests/test_file_access.py','tests/test_general_file_audit.py','evidence/full-tests-0.4.53.json','evidence/security/0.4.53/full-regression.log','evidence/document-audit-browser-0.4.53.json','evidence/general-file-audit-os-0.4.53.json','evidence/installed-notepad-delivery-0.4.52.json','evidence/authenticode-0.4.53.json'],
      'security':'No new privilege, task, destination, content collection, dependency or defense change. Process session metadata follows birth-time checked limited query; type queries have 64/s budget and 512 cache. Unknown types skipped with reason counts; unknown process identity never guessed service. Independent fixed fixture trace retained. General policy inherits current scopes and exclusions.',
      'remaining':['unsigned_internal_trial_authenticode_timestamp_full_SBOM_independent_review_pending','company_win10_win11_Defender_EDR_ASR_AppControl_lifecycle_and_all_local_workload_acceptance_pending','0.4.53_background_filter_not_deployed_to_office','interactive_apps_background_vs_human_cannot_be_inferred_from_IO','unknown_process_or_object_types_query_budget_and_overload_can_leave_gaps','company_extension_publication_and_matching_signing_identity_still_needed'],
      'verification_observations':['Installed 0.4.52 Notepad target delivery confirmed separately with exact catalog IDs and redacted path hash; not a 0.4.53 deployment claim.','0.4.53 own child empty and mapped opens verified through native observer, process resolver and source Filter; actual directories and roots rejected.','First full suite failed at unrelated installer fixture switching before expected injected health failure; original cause not captured. Failure retained, expected failure-stage assertion strengthened, final complete 578 tests passed without installer product changes.','First restricted-desktop packaged probe did not see Tk window in 10 seconds; exact same candidate passed standard user interactive desktop including clean viewer close. No cause or Defender attribution confirmed; failed log retained.','Read-only evidence query first assumed packed payload includes kind; corrected to catalog term lookup, not an event collection failure.']}
    installed=read(ROOT/'evidence/installed-notepad-delivery-0.4.52.json')
    assert installed['passed'] and len(installed['events'])==2 and not installed['new_0.4.53_filter_deployed']
    (folder/'requirements-review.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('existing_0452_archives_unchanged','implemented','evidence','remaining','regression_findings')}))

if __name__=='__main__':main()
