"""Exact internal-trial gate for sparse search and recovery, with honest gaps."""
import json,re,shutil,sys,zipfile
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
from review_release_0441 import ROOT,sha,read
sys.path.insert(0,str(ROOT))
VERSION='0.4.44'

def main():
    folder=ROOT/f'evidence/security/{VERSION}';folder.mkdir(parents=True,exist_ok=True)
    logs={}
    for name,count in [('search-recovery-regression-tail-0444.txt',488),('search-recovery-unit-tail-0444.txt',9),('search-recovery-remote-isolated-0444.txt',8)]:
        path=ROOT/'runtime'/name;body=path.read_text(encoding='utf-8-sig',errors='replace').replace('\r\n','\n');match=re.search(r'Ran (\d+) tests in ([\d.]+)s',body)
        assert match and int(match[1])==count and '\nOK\n' in body and 'FAILED (' not in body,body[-2000:]
        logs[name]={'passed':True,'tests':count,'seconds':float(match[2]),'sha256':sha(path)}
    initial=ROOT/'runtime/search-recovery-regression-0444-initial-remote-timeout.txt';body=initial.read_text(encoding='utf-8-sig',errors='replace')
    assert 'FAILED (errors=1)' in body and 'test_consent_jpeg_sequence_repeat_and_independent_input_channel' in body
    app=ROOT/'dist/GuardDesk';actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()};smoke=read(ROOT/'evidence/packaged-smoke.json')
    assert smoke['passed'] and smoke['application_files']==actual and smoke['exe_sha256']==actual['GuardDesk.exe'] and smoke['gui_sha256']==actual['GuardDeskAgent.exe']
    browsers={}
    for stem in ('audit-search','custom-library','mail-reports'):
        name=f'{stem}-browser-{VERSION}.json';value=read(ROOT/'evidence'/name)
        assert value['passed'] and value['version']==VERSION and value['frozen_server_used'] and value['exe_sha256']==actual['GuardDesk.exe'] and not value['page_errors'];browsers[name]=value
    for stem in ('navigation-performance','audit-date-defaults'):
        value=read(ROOT/f'evidence/{stem}-{VERSION}.json');assert value['passed'] and value['version']==VERSION and not value['page_errors']
    archive=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz');modules=[]
    for p in (ROOT/'guarddesk').glob('*.py'):
        name='guarddesk' if p.stem=='__init__' else 'guarddesk.'+p.stem
        if name in archive.toc:assert archive.extract(name)==compile(p.read_bytes(),str(p),'exec'),name;modules.append(name)
    assert 'guarddesk.audit_search_index' in modules
    for area in ('static','windows'):
        for p in (ROOT/'guarddesk'/area).rglob('*'):
            if p.is_file():assert p.read_bytes()==(app/'_internal/guarddesk'/area/p.relative_to(ROOT/'guarddesk'/area)).read_bytes(),p
    manifest=read(app/'_internal/agent-release.json');assert manifest['version']==VERSION and manifest['files']=={k:v for k,v in actual.items() if k!='_internal/agent-release.json'}
    from guarddesk.native_installer import source_files
    verified,total=source_files(app);assert verified==actual
    previous=read(ROOT/'evidence/security/0.4.43/requirements-review.json');prior=previous['prior_archives_unchanged']
    prior.update({'GuardDesk-0.4.43-windows-x64.zip':'ebcf0acf938f65acaa3ff73dc6908652f8158aa75f61656c232874960f0501ef','GuardDesk-0.4.43-source.zip':'02fd5b50c370af818421cbce5b09378edef6aea9c0dc600214f116beb7ec3ebb'})
    for name,digest in prior.items():assert sha(ROOT/'dist'/name)==digest,name
    allowed={'guarddesk/__init__.py','guarddesk/audit_search.py','guarddesk/server.py','guarddesk/store.py','guarddesk/pagination.py','guarddesk/static/app.js','guarddesk/static/audit_ui.js','guarddesk/static/index.html'};changed=set();critical=[];engines={}
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.43-source.zip') as z:
        for name in z.namelist():
            if name.startswith(('guarddesk/','browser-extension/')) or name in ('requirements.txt','requirements-build.txt','app.py','tools/GuardDesk.spec','Setup-Management.cmd','Install-Endpoint.cmd','Install-Endpoint.ps1','Uninstall-Endpoint.cmd','Start-GuardDesk.ps1','Start-Remote.cmd','Diagnose-Remote.cmd'):
                assert (ROOT/name).is_file(),name
                if z.read(name)!=(ROOT/name).read_bytes():changed.add(name)
                else:critical.append(name)
    assert changed==allowed,changed
    assert 'guarddesk/native_installer.py' in critical and 'guarddesk/event_storage.py' in critical and 'guarddesk/remote_client.py' in critical
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.43-windows-x64.zip') as z:
        for name in z.namelist():
            if name.endswith('/sqlite3.dll'):
                p=app/name.removeprefix('GuardDesk/');assert z.read(name)==p.read_bytes();engines[name]=sha(p)
    assert engines
    perf=read(ROOT/f'evidence/search-recovery-performance-{VERSION}.json')
    assert perf['passed'] and perf['synthetic_rows']==1000000 and perf['today_rows']==300000 and perf['today_rare_matches']==12
    assert perf['queries']['baseline_sparse']['timed_out'] and perf['queries']['indexed_sparse']['rows']==12 and perf['queries']['indexed_sparse']['payload_events_read']==12
    assert perf['queries']['indexed_missing']['rows']==0 and perf['queries']['indexed_missing']['payload_events_read']==0
    assert perf['query_heads_unchanged'] and perf['no_office_database_read']
    resource=read(ROOT/f'evidence/search-recovery-resource-sample-{VERSION}.json');assert resource[0]['not_office_server']
    signatures=read(folder/'signatures.json')
    for record in signatures:assert sha(ROOT/record['path'])==record['sha256']
    regression={'passed':True,'final_unique_cases':488,'logs':logs,'note':'Initial 485-case run had one legacy remote timeout; isolated eight remote cases passed. Two index pause/atomic-rollback cases led to a complete 487-case pass. A primed-index tail-only/healthy-contention case was then added. Final complete 488-case run stands alone; overlapping targeted cases are not added again.'}
    (folder/'regression.json').write_text(json.dumps(regression,indent=2)+'\n',encoding='utf-8');shutil.copyfile(ROOT/'evidence/packaged-smoke.json',ROOT/f'evidence/packaged-smoke-{VERSION}.json')
    report={'version':VERSION,'release_status':'unsigned_internal_trial','passed_with_gaps':True,'review_type':'developer_self_review_not_independent','requirements':['SEC-01','SEC-04','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11','DEF-02','DEF-04'],'lessons':['GD-014','GD-015','GD-016','GD-017','GD-020','GD-023'],'root_cause':['0.4.43 metadata-only acceleration still scans all in-scope payloads for sparse/absent keywords; prior all-match benchmark missed this','Failed keyword persisted across navigation; automatic refresh could replay it; aborting browser wait did not notify Server','Initial page replaced form with a loading/error-only card, preventing local recovery'],'controls':['Shared contentless uni/bigram FTS candidates followed by exact original SQLite LIKE; no original event mutation or plaintext JSON copy','Deduplicated posting documents; oversize candidate fallback rather than false truncation; existing protected DB and backup path','On-demand recent-first 500-row/about-2-Mi-character batches, tokenization outside writer transaction, atomic coverage and postings, 250ms busy budget and low priority; 3s interest expiry pauses historical work after current batch; primed indexes maintain new tail in idle time; healthy SQLite contention retries','Pending index status does no payload query scan; signed cursor freezes snapshot during preparation; scoped progress, no false empty/success','Random request ID; CSRF and session-only cancellation; cooperative SQL/loop cancellation and two global slots; no unbounded queue','Form before result, error/cancel retains editable fields and clear action; failed keyword navigation clears keyword; no keyword automatic replays; duplicate clicks coalesced and late results ignored; sibling API errors abort index polling','No Agent collection, OS permission/startup/destination/dependency changes; sqlite3.dll, installer/updater, collector/exclusion, policy/custom/mail/remote engines byte-identical to 0.4.43'],'gaps':['Office database and real fleet latency/resource acceptance not measured; local build/test overlap may affect synthetic timings','Initial indexing has CPU/disk cost and adds capacity; observed repetition/dedup ratio is not a universal per-endpoint estimate','Candidate fragment collisions or many oversized records can still require substantial verification; cooperative execution budgets and visible recoverable errors remain','Cancelled or disconnected historical backfill pauses after a short grace and current batch, not a hard I/O deadline; lost cancellation notification falls back to execution budget','Company signing, full SBOM/vulnerability assessment, independent review and company Windows 10/11 Defender/EDR lifecycle acceptance incomplete','Prior installer 45-second health/cloud-scan gap and GD-006 generic source error remain outside scope'],'regression':regression,'initial_remote_timeout':{'log_sha256':sha(initial),'original_tests':485,'errors':1,'root_cause':'Not established; request used the existing unchanged three-second RemoteClient limit. No timeout was relaxed to pass.','isolated_then_complete_retry':True},'harness_corrections':{'performance_failure_sha256':sha(ROOT/'runtime/search-recovery-performance-0444-initial-harness-error.txt'),'reason':'Contentless columnsize=0 requires MATCH; direct SQLite fixture handle also needed explicit close for Windows cleanup. Production already used MATCH.','navigation_failure_sha256':sha(ROOT/'runtime/search-recovery-navigation-0444-initial-locator.txt'),'navigation_reason':'Old generic role locator resolved two live status nodes; now explicitly verifies form and query status.','tail_fixture_stub_sha256':sha(ROOT/'runtime/search-recovery-unit-tail-0444-initial-stub.txt'),'tail_fixture_reason':'The existing mock needed to accept the added tail_only keyword; production implementation already accepted it.'},'benchmark':perf,'resource_sample':resource,'benchmark_source_sha256':sha(ROOT/'tools/search_recovery_performance.py'),'compiled_modules_equal_source':modules,'application_files':len(actual),'application_bytes':total,'source_files':{n:sha(ROOT/n) for n in sorted(allowed|{'guarddesk/audit_search_index.py'})},'critical_sources_unchanged':critical,'sqlite_engine_unchanged':engines,'prior_archives_unchanged':prior,'historical_archives_unavailable_for_recheck':previous['historical_archives_unavailable_for_recheck'],'frozen_browsers':browsers,'signatures':signatures,'office_server_or_endpoints_changed':False,'live_mail_sent':False}
    out=folder/'requirements-review.json';out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');links=0
    for name in ('README.md','doc/README.md','doc/60-engineering-lessons-and-regression-rules.md','doc/64-sparse-search-and-query-recovery-0.4.44.md'):
        p=ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',p.read_text(encoding='utf-8-sig')):
            if target.startswith(('http:','https:','#','mailto:')):continue
            assert (p.parent/target.split('#')[0]).exists(),(name,target)
            links+=1
    report['document_links_checked']=links;out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':True,'unique_tests':488,'compiled_modules':len(modules),'document_links':links,'application_files':len(actual),'live_deployed':False}))

if __name__=='__main__':main()
