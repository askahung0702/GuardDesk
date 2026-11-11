"""Exact candidate self-review; never a formal company release approval."""
import hashlib,json,re,sys,zipfile
from importlib.metadata import version as dependency_version
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));VERSION='0.4.50'

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))

def main():
    from run_regression_0450 import snapshot
    full=read(ROOT/f'evidence/full-tests-{VERSION}.json')
    assert full['passed'] and full['source_unchanged_during_run'] and full['tests']>=554
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
    for name,digest in old.items():assert sha(ROOT/'dist'/name)==digest,name
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.49-windows-x64.zip') as archive:prior_dependencies=json.loads(archive.read('build-info.json'))
    observed_dependencies={name:dependency_version(name) for name in ('cryptography','cffi','pyinstaller','pyreadline3','Pillow')}
    assert all(prior_dependencies[name]==value for name,value in observed_dependencies.items())
    expected={'guarddesk/__init__.py','guarddesk/server.py','guarddesk/store.py','guarddesk/updates.py','guarddesk/update_progress.py','guarddesk/static/app.js','guarddesk/static/index.html','guarddesk/static/style.css','guarddesk/static/updates_ui.js'}
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.49-source.zip') as archive:
        old_files=json.loads(archive.read('MANIFEST-SHA256.json'))
        changed={p.relative_to(ROOT).as_posix() for p in (ROOT/'guarddesk').rglob('*') if p.is_file() and '__pycache__' not in p.parts and old_files.get(p.relative_to(ROOT).as_posix())!=sha(p)}
        assert changed==expected,changed^expected
        for name in ('requirements.txt','requirements-build.txt','native/document_trace.cpp'):assert sha(ROOT/name)==old_files[name],name
    links=0
    for path in (ROOT/'README.md',ROOT/'doc/README.md',ROOT/'doc/60-engineering-lessons-and-regression-rules.md',ROOT/'doc/69-update-progress-paging-0.4.50.md'):
        for target in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if '://' in target or target.startswith('#'):continue
            target=target.split('#')[0]
            if target:assert (path.parent/target).exists(),(path,target);links+=1
    signatures=read(ROOT/f'evidence/authenticode-{VERSION}.json')
    for signature in signatures:assert signature['SHA256']==sha(ROOT/signature['Path'])
    result={'version':VERSION,'internal_checks_passed':True,'formal_release_ready':False,'office_changed':False,'review_type':'developer_self_review_not_independent','full_regression_tests':full['tests'],'full_regression_log_sha256':full['log_sha256'],'exe_sha256':actual['GuardDesk.exe'],'native_dll_sha256':actual['_internal/guarddesk/windows/native/GuardDeskFileTrace.dll'],'application_files':len(actual),'compiled_modules_equal_source':len(compiled),'changed_product_files':sorted(changed),'endpoint_native_installer_protocols_unchanged_except_shared_version_stamp':True,'existing_0449_archives_unchanged':old,'direct_build_dependencies_unchanged_from_0449':observed_dependencies,'markdown_links_checked':links,'frozen_browser_checks':browser,
      'requirements':['SEC-01','SEC-04','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11','DEF-02','DEF-04','DEF-05'],
      'historical_controls':['GD-005','GD-006','GD-007','GD-008','GD-009','GD-010','GD-014','GD-017','GD-019','GD-020','GD-021','GD-022','GD-023'],
      'implemented':['50_row_server_metadata_pagination_totals_stable_order','computer_account_group_descendants_release_status_filters','not_updated_includes_never_sent_unknown_and_numeric_newer_versions','snapshot_scoped_cross_page_cancel_with_immediate_writer_eligibility_recheck','unclaimed_only_retry_partial_maintenance_expired_protection','post_commit_notifications_audited_idempotent_skip','drafts_preserved_during_paging_submitted_drafts_cleared'],
      'evidence':['doc/69-update-progress-paging-0.4.50.md','tests/test_update_progress.py','evidence/full-tests-0.4.50.json','evidence/security/0.4.50/full-regression.log','evidence/update-progress-browser-0.4.50.json','evidence/update-progress-performance-0.4.50.json','evidence/packaged-smoke.json','evidence/authenticode-0.4.50.json'],
      'security':'Existing MIS admin/Session/CSRF; bounded validated IDs/filters and parameterized SQL; no new endpoint commands, collection, destinations, OS privilege, startup task, dependency or Defender change. Existing event store audit and transaction rollback retained.',
      'regression_findings':['Escaped DOMAIN account JSON-text search fixed with per-account values','Browser test caught accidental old-table render; new exact table/pager exercised','Only dirty import/job drafts preserved; committed import returns to collapsed state','Test wait changed for existing CSP without allowing unsafe-eval'],
      'remaining':['unsigned_internal_trial_authenticode_and_timestamp_pending','company_win10_win11_defender_edr_asr_app_control_lifecycle_acceptance_pending','full_sbom_vulnerability_and_independent_security_review_pending','actual_office_server_and_job_acceptance_not_performed','numeric_versions_are_last_observed_not_live_process_attestation','metadata_counts_and_deep_offsets_not_constant_time','bulk_confirmation_max_1000_ids_requires_narrower_scope_above_limit']}
    (folder/'requirements-review.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('existing_0449_archives_unchanged','implemented','evidence','remaining','regression_findings')}))

if __name__=='__main__':main()
