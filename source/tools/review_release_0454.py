"""Reproducible developer review of this unsigned internal candidate."""
import hashlib,json,re,sys,zipfile
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));VERSION='0.4.54'

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_text(encoding='utf-8-sig'))

def main():
    from run_regression_0454 import snapshot
    full=read(ROOT/f'evidence/full-tests-{VERSION}.json')
    assert full['passed'] and full['source_unchanged_during_run'] and full['tests']>=592
    assert full['source_sha256']==snapshot();assert sha(ROOT/full['log'])==full['log_sha256']
    folder=ROOT/f'evidence/security/{VERSION}';folder.mkdir(parents=True,exist_ok=True)
    log=folder/'full-regression.log';log.write_bytes((ROOT/full['log']).read_bytes())
    app=ROOT/'dist/GuardDesk';actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    smoke=read(ROOT/'evidence/packaged-smoke.json')
    assert smoke['passed'] and smoke['application_files']==actual
    assert actual['GuardDesk.exe']==smoke['exe_sha256']
    manifest=read(app/'_internal/agent-release.json');assert manifest['version']==VERSION
    assert manifest['files']=={k:v for k,v in actual.items() if k!='_internal/agent-release.json'}
    pyz=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz');compiled=[]
    for path in (ROOT/'guarddesk').glob('*.py'):
        name='guarddesk' if path.stem=='__init__' else 'guarddesk.'+path.stem
        if name in pyz.toc:
            assert pyz.extract(name)==compile(path.read_bytes(),str(path),'exec'),name
            compiled.append(name)
    assert {'guarddesk.document_context','guarddesk.document_io','guarddesk.document_worker','guarddesk.policy','guarddesk.file_access'}<=set(compiled)
    for area in ('static','windows'):
        for p in (ROOT/'guarddesk'/area).rglob('*'):
            if p.is_file():assert actual['_internal/guarddesk/'+p.relative_to(ROOT/'guarddesk').as_posix()]==sha(p),p
    browser=[]
    for prefix in ('update-progress-browser','document-audit-browser','custom-library-browser','audit-sort-browser','audit-search-browser','mail-reports-browser'):
        proof=read(ROOT/f'evidence/{prefix}-{VERSION}.json')
        assert proof['passed'] and proof['frozen_server_used'] and proof['exe_sha256']==actual['GuardDesk.exe']
        browser.append(prefix)
    helper=read(ROOT/f'evidence/document-context-frozen-{VERSION}.json')
    assert helper['passed'] and helper['own_helper_stopped'] and helper['exe_sha256']==actual['GuardDesk.exe']
    native=read(ROOT/'guarddesk/windows/native/document-trace-build.json')
    assert native['source_sha256']==sha(ROOT/'native/document_trace.cpp') and native['dll_sha256']==actual['_internal/guarddesk/windows/native/GuardDeskFileTrace.dll']
    osproof=read(ROOT/f'evidence/general-file-audit-os-{VERSION}.json')
    assert osproof['passed'] and osproof['dll_sha256']==native['dll_sha256'] and osproof['own_trace_stopped']
    assert all(osproof[k] for k in ('empty_file_no_fabricated_read','mapped_open_not_claimed_read','failed_open_not_emitted','child_empty_and_mapped_survive_real_source_filter','actual_directory_and_drive_root_rejected','collector_self_rejected'))
    assert osproof['native_stats']['dropped']==0 and osproof['native_stats']['schema_unresolved']==0
    perf=read(ROOT/f'evidence/general-file-audit-performance-{VERSION}.json');assert perf['passed']
    assert all(sha(ROOT/p)==h for p,h in perf['source_sha256'].items())
    old={'GuardDesk-0.4.53-windows-x64.zip':'9682701e18292576c9fc205494e421b074518b44fe594d4b334c6e2660fe0d68','GuardDesk-0.4.53-source.zip':'1fc136d778d937c8408eab2befa3ee1b1294bf1989538f37566bd4685e361ae4'}
    assert all(sha(ROOT/'dist'/p)==h for p,h in old.items())
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.53-source.zip') as archive:
        old_manifest=json.loads(archive.read('MANIFEST-SHA256.json'))
        for p in ('requirements.txt','requirements-build.txt'):assert sha(ROOT/p)==old_manifest[p]
        changed={p.relative_to(ROOT).as_posix() for p in (ROOT/'guarddesk').rglob('*') if p.is_file() and '__pycache__' not in p.parts and old_manifest.get(p.relative_to(ROOT).as_posix())!=sha(p)}
    expected={'guarddesk/application_control.py','guarddesk/windows_events.py','guarddesk/document_context.py','guarddesk/document_io.py','guarddesk/document_process.py','guarddesk/document_worker.py','guarddesk/file_access.py','guarddesk/policy.py','guarddesk/policy_progress.py','guarddesk/__init__.py','guarddesk/__main__.py','guarddesk/static/app.js','guarddesk/static/audit_ui.js','guarddesk/static/index.html','guarddesk/static/management.js','guarddesk/windows/native/document-trace-build.json','guarddesk/windows/native/GuardDeskFileTrace.dll'}
    assert changed==expected,changed^expected
    signatures=read(ROOT/f'evidence/authenticode-{VERSION}.json')
    for entry in signatures:assert entry['SHA256']==sha(ROOT/entry['Path'])
    links=0
    for p in (ROOT/'README.md',ROOT/'doc/README.md',ROOT/'doc/60-engineering-lessons-and-regression-rules.md',ROOT/'doc/73-interactive-document-access-0.4.54.md'):
        for target in re.findall(r'\]\(([^)]+)\)',p.read_text(encoding='utf-8')):
            if '://' not in target and not target.startswith('#'):
                target=target.split('#')[0]
                if target:assert (p.parent/target).exists(),(p,target);links+=1
    result={'version':VERSION,'internal_checks_passed':True,'formal_release_ready':False,'office_changed':False,
            'review_type':'developer_self_review_not_independent','full_regression_tests':full['tests'],
            'exe_sha256':actual['GuardDesk.exe'],'native_dll_sha256':native['dll_sha256'],
            'compiled_modules_equal_source':len(compiled),'application_files':len(actual),'changed_product_files':sorted(changed|{'app.py'}),
            'markdown_links_checked':links,'previous_053_archives_unchanged':old,'frozen_browser_checks':browser,
            'requirements':['GD-005','GD-007','GD-011','GD-012','GD-013','GD-017','GD-018','GD-019','GD-020','GD-021','GD-023','GD-024','SEC-01','SEC-02','SEC-03','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11','DEF-01','DEF-02','DEF-04'],
            'implemented':['known_background_cache_root_directory_self_exclusions','per_user_session_recent_input_foreground_association','bounded_native_open_close_lifetime_and_logical_open_consolidation','MIS_general_policy_mode_interval_group_assignment','legacy_053_wire_projection_and_capability_gating','fixed_protected_executable_user_helper_local_pipe_DACL_and_exact_child_PID','ordinary_opens_only_preserve_mutations_uploads_warnings_history'],
            'evidence':['doc/73-interactive-document-access-0.4.54.md','tests/test_document_interaction.py',f'evidence/full-tests-{VERSION}.json',f'evidence/document-context-frozen-{VERSION}.json',f'evidence/general-file-audit-os-{VERSION}.json',f'evidence/general-file-audit-performance-{VERSION}.json'],
            'remaining':['unsigned_internal_trial_formal_signing_SBOM_independent_review_pending','protected_SYSTEM_to_WTS_helper_launch_not_yet_accepted_on_installed_candidate','user1_idle_vs_manual_Notepad_Office_PDF_and_RDP_office_acceptance_pending','first_ETW_fixture_distinct_read_open_failure_unconfirmed_retained_same_DLL_second_pass_not_root_cause_fix','interactive_metadata_is_association_not_physical_user_or_human_read_attestation','strict_interaction_mode_can_omit_delayed_helper_process_or_unavailable_context_reads_counters_visible_complete_mode_available','company_Defender_Win10_Win11_8h_24h_and_multi_session_total_resource_acceptance_pending','server_downgrade_after_saving_new_options_requires_policy_cleanup_or_consistent_backup_plan','enterprise_upload_extension_publication_and_deployment_still_required']}
    (folder/'requirements-review.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result))

if __name__=='__main__':main()
