"""Exact-artifact self-review; no claim of company performance acceptance."""
import hashlib,json,re,sys,zipfile
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));VERSION='0.4.55'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))


def main():
    from run_regression_0455 import snapshot
    full=read(ROOT/f'evidence/full-tests-{VERSION}.json')
    assert full['passed'] and full['tests']>=596 and full['source_unchanged_during_run']
    assert full['source_sha256']==snapshot() and sha(ROOT/full['log'])==full['log_sha256']
    folder=ROOT/f'evidence/security/{VERSION}';folder.mkdir(parents=True,exist_ok=True)
    (folder/'full-regression.log').write_bytes((ROOT/full['log']).read_bytes())
    app=ROOT/'dist/GuardDesk';actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    smoke=read(ROOT/'evidence/packaged-smoke.json');assert smoke['passed'] and smoke['application_files']==actual
    manifest=read(app/'_internal/agent-release.json');assert manifest['version']==VERSION
    assert manifest['files']=={k:v for k,v in actual.items() if k!='_internal/agent-release.json'}
    pyz=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz');compiled=[]
    for path in (ROOT/'guarddesk').glob('*.py'):
        name='guarddesk' if path.stem=='__init__' else 'guarddesk.'+path.stem
        if name in pyz.toc:
            assert pyz.extract(name)==compile(path.read_bytes(),str(path),'exec'),name
            compiled.append(name)
    for area in ('static','windows'):
        for p in (ROOT/'guarddesk'/area).rglob('*'):
            if p.is_file():assert actual['_internal/guarddesk/'+p.relative_to(ROOT/'guarddesk').as_posix()]==sha(p),p
    browser=[]
    for prefix in ('update-progress-browser','document-audit-browser'):
        proof=read(ROOT/f'evidence/{prefix}-{VERSION}.json')
        assert proof['passed'] and proof['frozen_server_used'] and proof['exe_sha256']==actual['GuardDesk.exe']
        browser.append(prefix)
    helper=read(ROOT/f'evidence/document-context-frozen-{VERSION}.json')
    assert helper['passed'] and helper['own_helper_stopped'] and helper['exe_sha256']==actual['GuardDesk.exe']
    native=read(ROOT/'guarddesk/windows/native/document-trace-build.json')
    assert native['source_sha256']==sha(ROOT/'native/document_trace.cpp') and native['dll_sha256']==actual['_internal/guarddesk/windows/native/GuardDeskFileTrace.dll']
    contract=read(ROOT/f'evidence/native-poll-buffer-contract-{VERSION}.json')
    assert contract['passed'] and not contract['trace_started'] and contract['polls']==10000 and contract['transfer_buffer_allocations']==1
    assert contract['dll_sha256']==native['dll_sha256'] and contract['wrapper_sha256']==sha(ROOT/'guarddesk/document_io.py')
    osproof=read(ROOT/f'evidence/general-file-audit-os-{VERSION}.json')
    assert osproof['dll_sha256']==native['dll_sha256']
    if osproof['passed']:
        assert osproof['own_trace_stopped'] and osproof['native_stats']['dropped']==0 and osproof['native_stats']['schema_unresolved']==0
    else:
        # Do not relabel a cancelled privileged test as passed. This artifact
        # can be an unsigned internal candidate only, with acceptance pending.
        assert osproof['status']=='uac_cancelled_before_test_started' and not osproof['test_executed'] and not osproof['own_trace_started']
    perf=read(ROOT/f'evidence/general-file-audit-performance-{VERSION}.json');assert perf['passed']
    hot=read(ROOT/f'evidence/document-hotpath-performance-{VERSION}.json');assert hot['passed']
    responsive=read(ROOT/f'evidence/endpoint-responsiveness-{VERSION}.json')
    assert responsive['passed_fixture_work_and_cleanup'] and responsive['own_children_stopped'] and responsive['snapshot_files_recorded']==624
    for proof in (perf,hot,responsive):assert all(sha(ROOT/p)==h for p,h in proof['source_sha256'].items())
    old={'GuardDesk-0.4.54-windows-x64.zip':'eedc9d2043d8dd4d9f7f8c96d288bbf2d9abd6dcac9b85290e42bfb369d4359b','GuardDesk-0.4.54-source.zip':'77d3935d591c2acae460c1caed380bcd4e2d7811f08c65cc046848c92d99fa41'}
    assert all(sha(ROOT/'dist'/p)==h for p,h in old.items())
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.54-source.zip') as archive:
        old_manifest=json.loads(archive.read('MANIFEST-SHA256.json'))
        for p in ('requirements.txt','requirements-build.txt','app.py','native/document_trace.cpp'):assert sha(ROOT/p)==old_manifest[p]
        changed={p.relative_to(ROOT).as_posix() for p in (ROOT/'guarddesk').rglob('*') if p.is_file() and '__pycache__' not in p.parts and old_manifest.get(p.relative_to(ROOT).as_posix())!=sha(p)}
    expected={'guarddesk/document_context.py','guarddesk/document_io.py','guarddesk/document_worker.py','guarddesk/file_access.py','guarddesk/__init__.py','guarddesk/static/index.html'}
    assert changed==expected,changed^expected
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.54-windows-x64.zip') as archive:
        old_runtime= json.loads(archive.read('GuardDesk/_internal/agent-release.json'))['files']
    removed_runtime=sorted(set(old_runtime)-set(manifest['files']))
    assert removed_runtime==['_internal/PIL/_imagingmath.cp313-win_amd64.pyd','_internal/_asyncio.pyd','_internal/_multiprocessing.pyd','_internal/_overlapped.pyd']
    assert all(name not in pyz.toc for name in ('PIL.ImageMath','asyncio','multiprocessing','_overlapped'))
    signatures=read(ROOT/f'evidence/authenticode-{VERSION}.json')
    for entry in signatures:assert entry['SHA256']==sha(ROOT/entry['Path'])
    links=0
    for p in (ROOT/'README.md',ROOT/'doc/README.md',ROOT/'doc/09-endpoint-performance.md',ROOT/'doc/60-engineering-lessons-and-regression-rules.md',ROOT/'doc/74-endpoint-responsiveness-0.4.55.md'):
        for target in re.findall(r'\]\(([^)]+)\)',p.read_text(encoding='utf-8')):
            if '://' not in target and not target.startswith('#'):
                target=target.split('#')[0]
                if target:assert (p.parent/target).exists(),(p,target);links+=1
    result={'version':VERSION,'internal_checks_passed':True,'internal_checks_scope':'available_automated_checks_only_privileged_ETW_cancelled','all_required_acceptance_passed':False,'fresh_privileged_ETW_fixture_passed':osproof['passed'],'formal_release_ready':False,'office_changed':False,'review_type':'developer_self_review_not_independent',
            'full_regression_tests':full['tests'],'exe_sha256':actual['GuardDesk.exe'],'native_dll_sha256':native['dll_sha256'],'compiled_modules_equal_source':len(compiled),
            'application_files':len(actual),'changed_product_files':sorted(changed),'clean_build_removed_optional_extensions':removed_runtime,'optional_parent_modules_not_in_current_frozen_import_graph':True,'markdown_links_checked':links,'previous_054_archives_unchanged':old,'frozen_browser_checks':browser,
            'requirements':['GD-005','GD-007','GD-011','GD-012','GD-013','GD-020','GD-023','SEC-01','SEC-06','SEC-08','SEC-10','SEC-11','DEF-02','DEF-04'],
            'implemented':['companion_actual_below_normal_thread_priority','single_policy_content_snapshot_with_mutation_and_clear_invalidation','fixed_native_transfer_buffer_only_valid_count_decoded','receipt_time_frame_validation_preserves_source_and_replay_checks'],
            'measurements_scope':['synthetic_metadata_unchanged_retained_count','isolated_source_user_Agent_and_context_helper_combined_process_totals_with_624_files_completed','native_DLL_unchanged_and_buffer_contract_unit_checked_fresh_ETW_fixture_cancelled','real_exact_frozen_helper_not_SYSTEM_WTS_launch'],
            'remaining':['unsigned_internal_trial_formal_signing_SBOM_independent_review_pending','fresh_privileged_ETW_fixture_cancelled_UAC_1223_not_executed','installed_protected_SYSTEM_WTS_and_user1_manual_idle_Notepad_Office_PDF_RDP_acceptance_pending','company_Defender_Win10_Win11_full_components_multi_session_15min_8h_24h_and_Office_Teams_latency_acceptance_pending','short_file_IO_samples_do_not_prove_zero_lag_or_pass_company_5percent_P95_threshold','strict_interaction_association_not_physical_human_attestation_and_can_omit_unavailable_delayed_context','initial_local_performance_fixture_incomplete_work_and_harness_cleanup_failures_preserved_not_used_as_acceptance','enterprise_upload_extension_publication_and_deployment_still_required','server_downgrade_new_054_options_requires_cleanup_or_consistent_backup_plan']}
    (folder/'requirements-review.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result))


if __name__=='__main__':main()
