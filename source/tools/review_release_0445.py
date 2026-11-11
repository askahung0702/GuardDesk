"""Exact-artifact self-review: automatic indexing with receipt priority."""
import json,re,shutil,sys,zipfile
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
from review_release_0441 import ROOT,sha,read
sys.path.insert(0,str(ROOT))
VERSION='0.4.45'

def main():
    folder=ROOT/f'evidence/security/{VERSION}';folder.mkdir(parents=True,exist_ok=True)
    logs={}
    for name,count in [('automatic-index-unit-0445.txt',15),('automatic-index-regression-0445.txt',494)]:
        path=ROOT/'runtime'/name;body=path.read_text(encoding='utf-8-sig',errors='replace').replace('\r\n','\n');m=re.search(r'Ran (\d+) tests in ([\d.]+)s',body)
        assert m and int(m[1])==count and '\nOK\n' in body and 'FAILED (' not in body,body[-2500:]
        logs[name]={'passed':True,'tests':count,'seconds':float(m[2]),'sha256':sha(path)}
    app=ROOT/'dist/GuardDesk';actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    smoke=read(ROOT/'evidence/packaged-smoke.json')
    assert smoke['passed'] and smoke['application_files']==actual and smoke['exe_sha256']==actual['GuardDesk.exe'] and smoke['gui_sha256']==actual['GuardDeskAgent.exe']
    browsers={}
    for stem in ('audit-search','custom-library','mail-reports'):
        value=read(ROOT/f'evidence/{stem}-browser-{VERSION}.json')
        assert value['passed'] and value['version']==VERSION and value['frozen_server_used'] and value['exe_sha256']==actual['GuardDesk.exe'] and not value['page_errors'];browsers[stem]=value
    archive=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz');modules=[]
    for p in (ROOT/'guarddesk').glob('*.py'):
        name='guarddesk' if p.stem=='__init__' else 'guarddesk.'+p.stem
        if name in archive.toc:assert archive.extract(name)==compile(p.read_bytes(),str(p),'exec'),name;modules.append(name)
    for area in ('static','windows'):
        for p in (ROOT/'guarddesk'/area).rglob('*'):
            if p.is_file():assert p.read_bytes()==(app/'_internal/guarddesk'/area/p.relative_to(ROOT/'guarddesk'/area)).read_bytes(),p
    manifest=read(app/'_internal/agent-release.json');assert manifest['version']==VERSION and manifest['files']=={k:v for k,v in actual.items() if k!='_internal/agent-release.json'}
    from guarddesk.native_installer import source_files
    verified,total=source_files(app);assert verified==actual
    prior=read(ROOT/'evidence/security/0.4.44/requirements-review.json')['prior_archives_unchanged']
    prior.update({'GuardDesk-0.4.44-windows-x64.zip':'e0f7e688dcc6d91a3ab3843749588e798a1dbeb3ca3e8bfa3ccc1e3da89d04f7','GuardDesk-0.4.44-source.zip':'d43fe7e40e77edcc37510c689108b3d0037f6e639bdd79ee12e8b7b4d48b6875'})
    for name,digest in prior.items():assert sha(ROOT/'dist'/name)==digest,name
    allowed={'guarddesk/__init__.py','guarddesk/audit_search_index.py','guarddesk/store.py','guarddesk/server.py','guarddesk/static/app.js','guarddesk/static/index.html'};changed=set();unchanged=[]
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.44-source.zip') as z:
        for name in z.namelist():
            if name.startswith(('guarddesk/','browser-extension/')) or name in ('requirements.txt','requirements-build.txt','app.py','tools/GuardDesk.spec','Setup-Management.cmd','Install-Endpoint.cmd','Install-Endpoint.ps1','Uninstall-Endpoint.cmd','Start-GuardDesk.ps1','Start-Remote.cmd','Diagnose-Remote.cmd'):
                assert (ROOT/name).is_file(),name
                if z.read(name)!=(ROOT/name).read_bytes():changed.add(name)
                else:unchanged.append(name)
    assert changed==allowed,changed
    for name in ('guarddesk/native_installer.py','guarddesk/event_storage.py','guarddesk/audit_search.py','guarddesk/pagination.py','guarddesk/agent.py','guarddesk/updater_maintenance.py','guarddesk/updater_refresh.py'):
        assert name in unchanged,name
    engines={}
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.44-windows-x64.zip') as z:
        for name in z.namelist():
            if name.endswith('/sqlite3.dll'):
                p=app/name.removeprefix('GuardDesk/');assert z.read(name)==p.read_bytes();engines[name]=sha(p)
    assert engines
    perf=read(ROOT/f'evidence/automatic-index-performance-{VERSION}.json');assert perf['passed'] and len(perf['scenarios'])==4 and perf['no_office_database_read'] and perf['no_live_endpoints_changed']
    for name,digest in perf['source_sha256'].items():assert sha(ROOT/name)==digest,name
    for value in perf['scenarios']:
        assert not value['http_errors'] and value['source_chain']['valid'] and value['source_chain']['checked']==value['new_events']+value['history_events']
        assert not value['duplicate_upload_appended'] and not value['queries_triggered_index']
        if value['index_enabled']:assert value['state_final']['indexed_rows']==value['source_chain']['checked'] and value['all_history_ready_seconds_after_uploads'] is not None
    steady=next(s for s in perf['scenarios'] if s['profile']=='steady' and s['index_enabled']);assert steady['state_at_last_ack']['high_id']>steady['history_events']
    signatures=read(folder/'signatures.json')
    for value in signatures:assert sha(ROOT/value['path'])==value['sha256']
    report={'version':VERSION,'status':'unsigned_internal_trial','passed_with_gaps':True,'review_type':'developer_self_review_not_independent','requirements':['SEC-01','SEC-04','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11','DEF-02','DEF-04'],'lessons':['GD-014','GD-015','GD-016','GD-017','GD-020','GD-023'],
        'root_cause':'44 persisted a shared index, but first query gated historical work and indexed_rows>0 gated tail maintenance; idle historical work paused when query interest expired',
        'controls':['Automatic startup/first-receipt indexing, durable contiguous coverage; no source or index reset','Source receipt commits/flushes before notification; no synchronous FTS dependency on Agent ACK','Counter before writer admission through flush; finally cleanup; shared across console and HTTPS Stores','Priority to new tail, then recent-first historical backfill; no in-memory event queue','100 rows, approximately 2 Mi characters, 50ms preparation/25ms writer cooperative checkpoints, 25ms busy timeout, 100ms idle throttle/50ms requested throttle; individual SQL/commit/I/O is not hard real-time','Index connections do not trigger staging flush, single below-normal worker; 256MiB free-space reserve, bounded retry and visible error','Only committed prefix advances on mid-write yield; atomic posting/mapping/coverage rollback; cancellation still applies to search, normal indexing continues'],
        'threat_analysis':{'assets':'Immutable events, IDs/hashes, durable receipt ACK, query completeness, disk/CPU availability and sensitive derived fragments','trust_boundary':'Authenticated Agent -> Server receipt; internal low-priority derived worker has no new OS privileges, outbound destination or management grant','abuse':'Upload floods or large/unique contents can consume disk/write time; active receipt takes priority, input/event/thread bounds unchanged, index grammar/input and batch bounds retained; sustained load may delay indexing','storage':'Derived fragments remain sensitive and stay with protected control DB and existing full backup; actual disk-full receipt failure still requires existing Agent retry/outbox'},
        'tests':{'unique_full_regression_cases':494,'targeted_cases':15,'overlapping_counts_not_added':True,'logs':logs},'benchmark':perf,'frozen_browsers':browsers,'compiled_modules_equal_source':modules,'application_files':len(actual),'application_bytes':total,'source_files':{n:sha(ROOT/n) for n in sorted(allowed)},'critical_sources_unchanged':unchanged,'sqlite_engine_unchanged':engines,'prior_archives_unchanged':prior,'signatures':signatures,
        'development_corrections':['Initial prefix fixture assumed eight rows but setup login already added an audit row; use source head and assert complete coverage','Ready can be true with low_id=1 before sentinel-zero pass; test readiness rather than scheduling the extra empty pass','Harness Worker/Publisher imports are local; patch defining modules. Initial UTF-8 editing command used default cp950 and stopped; corrected explicit UTF-8 before final tests','Pilot/development performance runs retained under runtime; only final unchanged-source four-scenario run is acceptance evidence'],
        'gaps':['Synthetic source-Python HTTP comparison, not office DB/hardware or 250 physical endpoints; cache/order/system load apply','Index CPU, I/O, WAL and space overhead remains; background priority may postpone search readiness under sustained uploads','Cooperative row/time bounds do not interrupt one SQLite operation or disk commit; worker close may await I/O','Company signing, full SBOM/vulnerability checks, independent review and company Windows 10/11 Defender/EDR lifecycle acceptance incomplete','Prior installer 45-second health/cloud-scan gap and GD-006 generic source error remain outside scope'],
        'office_server_or_endpoints_changed':False,'live_mail_sent':False}
    links=0
    for name in ('README.md','doc/README.md','doc/60-engineering-lessons-and-regression-rules.md','doc/65-automatic-index-and-ingestion-0.4.45.md'):
        p=ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',p.read_text(encoding='utf-8-sig')):
            if target.startswith(('http:','https:','#','mailto:')):continue
            # This report is the one link that is being created now.
            resolved=(p.parent/target.split('#')[0]).resolve()
            assert resolved.exists() or resolved==(folder/'requirements-review.json').resolve(),(name,target)
            links+=1
    report['document_links_checked']=links
    (folder/'requirements-review.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    shutil.copyfile(ROOT/'evidence/packaged-smoke.json',ROOT/f'evidence/packaged-smoke-{VERSION}.json')
    print(json.dumps({'passed':True,'unique_tests':494,'compiled_modules':len(modules),'document_links':links,'application_files':len(actual),'live_deployed':False}))

if __name__=='__main__':main()
