"""Review exact Server search/UI build; retain explicit acceptance gaps."""
import json,re,shutil,sys,zipfile
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
from review_release_0441 import ROOT,sha,read
sys.path.insert(0,str(ROOT))
VERSION='0.4.43'

def main():
    folder=ROOT/f'evidence/security/{VERSION}';folder.mkdir(parents=True,exist_ok=True)
    logs={}
    for name,count in [(f'audit-search-regression-{VERSION}.txt',479),('audit-search-targeted-final.txt',6),(f'audit-search-installer-isolated-{VERSION}.txt',28)]:
        path=ROOT/'runtime'/name;body=path.read_text(encoding='utf-8-sig',errors='replace').replace('\r\n','\n')
        match=re.search(r'Ran (\d+) tests in ([\d.]+)s',body)
        assert match and int(match[1])==count and '\nOK\n' in body and 'FAILED (' not in body,body[-2000:]
        logs[name]={'passed':True,'tests':count,'seconds':float(match[2]),'sha256':sha(path)}
    baseline=ROOT/'runtime/audit-search-baseline.txt'
    assert 'FAILED (' in baseline.read_text(errors='replace')
    initial=ROOT/f'runtime/audit-search-regression-{VERSION}-initial-access-denied.txt'
    initial_body=initial.read_text(encoding='utf-8-sig',errors='replace')
    assert 'FAILED (errors=1)' in initial_body and 'test_transaction_does_not_depend_on_process_script_policy' in initial_body and 'WinError 5' in initial_body
    fixture_retry={'initial_log_sha256':sha(initial),'initial_tests':479,'initial_errors':1,'case':'NativeInstallerTest.test_transaction_does_not_depend_on_process_script_policy','observation':'Raw Path.rename mocked by the fixture raised Windows access denied in an owned temporary Updater directory; no product search code on this call stack.','root_cause':'Not established; Defender involvement is not claimed.','followup':'All 28 installer cases passed in isolation, then the complete 479-case suite reran with unchanged application/test sources.','sources_changed_for_retry':False}
    app=ROOT/'dist/GuardDesk';actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    smoke=read(ROOT/'evidence/packaged-smoke.json');assert smoke['passed'] and smoke['application_files']==actual and smoke['exe_sha256']==actual['GuardDesk.exe'] and smoke['gui_sha256']==actual['GuardDeskAgent.exe']
    browsers={}
    for stem in ('audit-search','custom-library','mail-reports'):
        name=f'{stem}-browser-{VERSION}.json';value=read(ROOT/'evidence'/name)
        assert value['passed'] and value['version']==VERSION and value['frozen_server_used'] and value['exe_sha256']==actual['GuardDesk.exe'] and value['page_errors']==[]
        browsers[name]=value
    for stem in ('navigation-performance','audit-date-defaults'):
        value=read(ROOT/f'evidence/{stem}-{VERSION}.json');assert value['passed'] and value['version']==VERSION and not value['page_errors']
    modules=[];archive=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz')
    for path in (ROOT/'guarddesk').glob('*.py'):
        name='guarddesk' if path.stem=='__init__' else 'guarddesk.'+path.stem
        if name in archive.toc:assert archive.extract(name)==compile(path.read_bytes(),str(path),'exec'),name;modules.append(name)
    assert 'guarddesk.audit_search' in modules
    for area in ('static','windows'):
        for path in (ROOT/'guarddesk'/area).rglob('*'):
            if path.is_file():assert path.read_bytes()==(app/'_internal/guarddesk'/area/path.relative_to(ROOT/'guarddesk'/area)).read_bytes(),path
    manifest=read(app/'_internal/agent-release.json');assert manifest['version']==VERSION and manifest['files']=={k:v for k,v in actual.items() if k!='_internal/agent-release.json'}
    from guarddesk.native_installer import source_files
    verified,total=source_files(app);assert verified==actual
    prior=read(ROOT/'evidence/security/0.4.42/requirements-review.json')['prior_archives_unchanged']
    prior.update({'GuardDesk-0.4.42-windows-x64.zip':'99df3c3f91d4a6cc4b88f7cecb5dd4de67b73ecd3e07332ef9b1b4ed78674a6f','GuardDesk-0.4.42-source.zip':'87ecebed67bc3a387c7472ebc4dfd0afb6204d3049621f4e5938a0053573e6d2'})
    unavailable={name:digest for name,digest in prior.items() if not (ROOT/'dist'/name).is_file()}
    prior={name:digest for name,digest in prior.items() if name not in unavailable}
    assert 'GuardDesk-0.4.42-source.zip' in prior and 'GuardDesk-0.4.42-windows-x64.zip' in prior
    for name,digest in prior.items():assert sha(ROOT/'dist'/name)==digest,name
    allowed={'guarddesk/__init__.py','guarddesk/server.py','guarddesk/event_storage.py','guarddesk/static/app.js','guarddesk/static/index.html','guarddesk/static/style.css'}
    changed=set();critical=[]
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.42-source.zip') as z:
        for name in z.namelist():
            if name.startswith('guarddesk/') or name in ('requirements.txt','requirements-build.txt','app.py','tools/GuardDesk.spec','Setup-Management.cmd','Install-Endpoint.cmd','Install-Endpoint.ps1','Uninstall-Endpoint.cmd','Start-GuardDesk.ps1','Start-Remote.cmd','Diagnose-Remote.cmd') or name.startswith('browser-extension/'):
                p=ROOT/name
                assert p.is_file(),name
                if z.read(name)!=p.read_bytes():changed.add(name)
                else:critical.append(name)
    assert changed==allowed,changed
    assert 'guarddesk/native_installer.py' in critical and 'guarddesk/agent.py' in critical
    perf=read(ROOT/f'evidence/audit-search-performance-{VERSION}.json')
    assert perf['passed'] and perf['version']==VERSION and perf['synthetic_rows']==1030000 and perf['same_page_ids'] and perf['source_head_unchanged'] and perf['no_office_database_read']
    assert perf['results']['baseline']['payload_events_read']==15000 and perf['results']['metadata_first']['payload_events_read']==51
    signatures=read(folder/'signatures.json')
    for record in signatures:assert sha(ROOT/record['path'])==record['sha256']
    regression={'passed':True,'final_unique_cases':479,'logs':logs,'note':'Full 479-case regression includes all six targeted cases; targeted rerun is not added to the unique total. Browser tests and benchmark have separate fixture scopes.'}
    (folder/'regression.json').write_text(json.dumps(regression,indent=2)+'\n',encoding='utf-8')
    shutil.copyfile(ROOT/'evidence/packaged-smoke.json',ROOT/f'evidence/packaged-smoke-{VERSION}.json')
    report={'version':VERSION,'release_status':'unsigned_internal_trial','passed_with_gaps':True,'review_type':'developer_self_review_not_independent','requirements':['SEC-01','SEC-04','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11','DEF-02','DEF-04'],'lessons':['GD-014','GD-015','GD-016','GD-017','GD-020','GD-023'],'root_cause':'Same-page search had no feedback; payload UNION search can hydrate all in-scope matches before LIMIT. Date/device filters were not generally ignored. ID-ordered header plans can also visit historical rows outside a narrow date range.','controls':['Date/device/action/group/severity/person/cursor predicates precede candidate payload search; stops at one page plus lookahead','Narrow date search locks existing occurred indexes; no new payload index or event migration','SQL parameters, SQLite LIKE semantics, original chain, CSV escaping, authorization and CSP retained','Two shared search slots, 10s JSON/30s CSV cooperative budget, error instead of partial result; browser 20s wait limit and explicit cancellation outcome','Spinner/elapsed/status/old-result note; duplicate/stale-result actions disabled, draft and navigation retained; no fake percentage','No new permissions, collection, destinations, dependencies or startup tasks; non-search critical application sources byte-identical to sealed 0.4.42'],'gaps':['Office Server latency and real 250-endpoint concurrency not measured; benchmark is a single owned synthetic fixture on developer workstation','Rare or missing substrings still scan in-scope candidates; browser cancellation does not guarantee immediate SQL cancellation; blocking I/O/locks can exceed cooperative budget','Company signing, full SBOM/vulnerability review, independent review, company Windows 10/11 Defender/EDR lifecycle and resource acceptance incomplete','Installer 45-second health wait and Defender cloud-scan delay gap, GD-006 generic source validation message and other prior acceptance gaps remain outside this change'],'regression':regression,'baseline_regression_failure_sha256':sha(baseline),'benchmark':perf,'benchmark_source_sha256':sha(ROOT/'tools/audit_search_performance.py'),'source_files':{n:sha(ROOT/n) for n in sorted(allowed|{'guarddesk/audit_search.py'})},'compiled_modules_equal_source':modules,'critical_sources_unchanged':critical,'prior_archives_unchanged':prior,'application_files':len(actual),'application_bytes':total,'signatures':signatures,'frozen_browsers':browsers,'office_server_or_endpoints_changed':False,'live_mail_sent':False,'prior_system_fixture_not_rerun_or_relabelled':True}
    report['initial_fixture_error_and_retry']=fixture_retry
    report['historical_archives_unavailable_for_recheck']=unavailable
    if unavailable:report['gaps'].append('Historical 0.4.39–0.4.41 ZIPs are absent in this workspace; only available sealed 0.4.42 archives were rehashed. Historical recorded hashes are retained, not claimed as reverified or recreated.')
    out=folder/'requirements-review.json';out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    links=0
    for name in ('README.md','doc/README.md','doc/60-engineering-lessons-and-regression-rules.md','doc/63-audit-search-feedback-and-query-0.4.43.md'):
        path=ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8-sig')):
            if target.startswith(('http:','https:','#','mailto:')):continue
            assert (path.parent/target.split('#')[0]).exists(),(name,target)
            links+=1
    report['document_links_checked']=links;out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':True,'full_tests':479,'compiled_modules':len(modules),'application_files':len(actual),'document_links':links,'frozen_browsers':len(browsers),'live_deployed':False}))

if __name__=='__main__':main()
