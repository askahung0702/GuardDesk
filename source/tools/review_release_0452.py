"""Exact candidate self-review; never a formal company release approval."""
import hashlib,json,re,sys,zipfile
from importlib.metadata import version as dependency_version
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));VERSION='0.4.52'

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))

def main():
    from run_regression_0452 import snapshot
    full=read(ROOT/f'evidence/full-tests-{VERSION}.json')
    assert full['passed'] and full['source_unchanged_during_run'] and full['tests']>=569
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
    assert {'guarddesk.document_scope','guarddesk.document_io','guarddesk.document_worker','guarddesk.document_queue','guarddesk.browser_host','guarddesk.document_process'}<=set(compiled)
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
    old={'GuardDesk-0.4.51-windows-x64.zip':'3d98824671953d6c68f7777eb26a484c8aad81a96187a4d0550b592c40d64f09','GuardDesk-0.4.51-source.zip':'4d8a636ccb98c4dfa47fa376b067c56f611306a924c773ff67701566448c4d2d'}
    for name,digest in old.items():assert sha(ROOT/'dist'/name)==digest,name
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.51-windows-x64.zip') as archive:prior_dependencies=json.loads(archive.read('build-info.json'))
    observed_dependencies={name:dependency_version(name) for name in ('cryptography','cffi','pyinstaller','pyreadline3','Pillow')}
    assert all(prior_dependencies[name]==value for name,value in observed_dependencies.items())
    expected={'guarddesk/__init__.py','guarddesk/document_io.py','guarddesk/document_process.py','guarddesk/document_worker.py','guarddesk/static/app.js','guarddesk/static/audit_ui.js','guarddesk/static/index.html','guarddesk/windows/native/GuardDeskFileTrace.dll','guarddesk/windows/native/document-trace-build.json'}
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.51-source.zip') as archive:
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
    assert os_proof['empty_file_open_observations']>=1 and os_proof['empty_file_no_fabricated_read']
    assert os_proof['mapped_open_observations']>=1 and os_proof['mapped_open_not_claimed_read'] and os_proof['failed_open_not_emitted']
    assert os_proof['native_stats']['dropped']==0 and os_proof['native_stats']['schema_unresolved']==0
    assert os_proof['distinct_native_opens']>=2 and os_proof['literal_and_user_template_native_exclusions_passed'] and os_proof['own_trace_stopped']
    general_perf=read(ROOT/f'evidence/general-file-audit-performance-{VERSION}.json');assert general_perf['passed']
    for name,digest in general_perf['source_sha256'].items():assert sha(ROOT/name)==digest,name
    links=0
    for path in (ROOT/'README.md',ROOT/'doc/README.md',ROOT/'doc/60-engineering-lessons-and-regression-rules.md',ROOT/'doc/71-completed-file-open-and-process-evidence-0.4.52.md'):
        for target in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if '://' in target or target.startswith('#'):continue
            target=target.split('#')[0]
            if target:assert (path.parent/target).exists(),(path,target);links+=1
    signatures=read(ROOT/f'evidence/authenticode-{VERSION}.json')
    for signature in signatures:assert signature['SHA256']==sha(ROOT/signature['Path'])
    result={'version':VERSION,'internal_checks_passed':True,'formal_release_ready':False,'office_changed':True,'candidate_deployed_to_office':False,'review_type':'developer_self_review_not_independent','full_regression_tests':full['tests'],'full_regression_log_sha256':full['log_sha256'],'exe_sha256':actual['GuardDesk.exe'],'native_dll_sha256':actual['_internal/guarddesk/windows/native/GuardDeskFileTrace.dll'],'application_files':len(actual),'compiled_modules_equal_source':len(compiled),'changed_product_files':sorted(changed),'endpoint_installer_and_update_wire_protocols_unchanged':True,'native_trace_record_abi_unchanged_size_checked':True,'completed_open_and_aux_stats_capability_checked':True,'existing_0451_archives_unchanged':old,'direct_build_dependencies_unchanged_from_0451':observed_dependencies,'markdown_links_checked':links,'frozen_browser_checks':browser,
      'requirements':['SEC-01','SEC-02','SEC-03','SEC-04','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11','DEF-01','DEF-02','DEF-04','DEF-05'],
      'historical_controls':['GD-005','GD-006','GD-007','GD-008','GD-009','GD-010','GD-014','GD-017','GD-019','GD-020','GD-021','GD-022','GD-023'],
      'implemented':['successful_existing_open_completion_not_read_or_human_claim','bounded_one_second_read_preference_and_native_open_coalescing','contiguous_completed_io_ranges_coalesced_same_open_and_thread','bounded_multi_batch_drain_and_durable_loss_reporting','limited_query_process_image_with_birth_time_PID_reuse_check_and_rate_limit','background_vs_open_vs_read_evidence_and_process_visible_in_UI','fixed_separate_fixture_trace_does_not_stop_live_collector'],
      'evidence':['doc/71-completed-file-open-and-process-evidence-0.4.52.md','tests/test_browser_deployment_lifecycle.py','tests/test_document_audit.py','evidence/full-tests-0.4.52.json','evidence/security/0.4.52/full-regression.log','evidence/document-audit-browser-0.4.52.json','evidence/packaged-smoke.json','evidence/dev-browser-registration-repair-20261022.json','evidence/authenticode-0.4.52.json'],
      'security':'Existing file_audit scope, exclusions, privileges and queue limits retained; no file contents, command lines, credentials, new destination, task, dependency or defense change. Limited process image and birth-time query is bounded. Fixed fixture entry has no IPC and cannot stop production GUID. Prototype actual Notepad open observed with loss; exact final DLL owned mapped/open/read/failure/exclusion fixture passed, not office end-to-end acceptance.',
      'historical_controls_document_fix':['GD-015','GD-018','GD-020','GD-021','GD-022','GD-024'],
      'remaining':['unsigned_internal_trial_authenticode_timestamp_full_SBOM_independent_review_pending','company_win10_win11_Defender_EDR_ASR_AppControl_lifecycle_and_all_local_workload_acceptance_pending','final_candidate_not_deployed_to_office_Server_or_DEV','actual_user_Notepad_to_center_delivery_on_final_installed_build_pending','preexisting_handles_UI_tab_activation_aliases_and_overload_can_have_gaps_not_full_human_activity_coverage','process_image_can_be_unknown_due_to_access_or_exit_rate_limit','company_extension_publication_and_matching_signing_identity_still_needed'],
      'verification_observations':['Pre-burst actual Notepad prototype observed opens but had loss; preserved separately, not final delivery acceptance.','First regression deliberately interrupted after new burst issue; source changed, preserved failed evidence, not counted as complete pass.','Review baseline updated to sealed 0.4.51 actually present; older 0.4.49/50 archives unavailable in current dist, no new unchanged claim for those.']}
    (folder/'requirements-review.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('existing_0451_archives_unchanged','implemented','evidence','remaining','regression_findings')}))

if __name__=='__main__':main()
