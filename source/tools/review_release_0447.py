"""Evidence/source/binary self-review; never represents company acceptance."""
import ast,json,re,shutil,sys,zipfile
from PyInstaller.archive.readers import CArchiveReader
from review_release_0441 import ROOT,sha,read
sys.path.insert(0,str(ROOT))
VERSION='0.4.47'

def main():
    folder=ROOT/f'evidence/security/{VERSION}';folder.mkdir(parents=True,exist_ok=True)
    log=ROOT/'runtime/audit-sort-full-regression-0447.txt';text=log.read_text(encoding='utf-8-sig',errors='replace').replace('\r\n','\n')
    m=re.search(r'Ran (\d+) tests in ([\d.]+)s',text)
    assert m and int(m[1])==508 and '\nOK\n' in text and 'FAILED (' not in text,text[-2500:]
    final_log=ROOT/'runtime/audit-sort-unit-0447-final-13.txt';final_text=final_log.read_text(encoding='utf-8-sig',errors='replace').replace('\r\n','\n')
    fm=re.search(r'Ran (\d+) tests in ([\d.]+)s',final_text)
    assert fm and int(fm[1])==13 and '\nOK\n' in final_text and 'FAILED (' not in final_text
    app=ROOT/'dist/GuardDesk';actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    smoke=read(ROOT/'evidence/packaged-smoke.json')
    assert smoke['passed'] and smoke['application_files']==actual and smoke['exe_sha256']==actual['GuardDesk.exe'] and smoke['gui_sha256']==actual['GuardDeskAgent.exe']
    browsers={}
    for stem in ('audit-sort','audit-search','mail-reports','custom-library'):
        v=read(ROOT/f'evidence/{stem}-browser-{VERSION}.json')
        assert v['passed'] and v['frozen_server_used'] and v['version']==VERSION and v['exe_sha256']==actual['GuardDesk.exe'] and not v['page_errors'],stem
        browsers[stem]=v
    assert not browsers['mail-reports']['live_mail_sent'] and not browsers['mail-reports']['offline_http_requests']
    perf=read(ROOT/f'evidence/audit-sort-performance-{VERSION}.json');ingest=read(ROOT/f'evidence/sort-ingestion-performance-{VERSION}.json')
    assert perf['passed'] and perf['synthetic_rows']==300000 and perf['today_rows']==200000 and perf['index']['distinct_strings']>=150000
    assert all(v['payload_events_read']==0 and v['unique_rows']==101 for v in perf['queries'].values())
    for source,digest in perf['source_sha256'].items():assert sha(ROOT/source)==digest,source
    assert ingest['passed'] and len(ingest['scenarios'])==4
    for source,digest in ingest['source_sha256'].items():assert sha(ROOT/source)==digest,source
    for v in ingest['scenarios']:
        assert v['source_chain']['valid'] and not v['http_errors'] and not v['duplicate_upload_appended']
        if v['index_enabled']:assert v['state_final']['sort']['indexed_rows']==v['history_events']+v['new_events']
    comparison=read(ROOT/f'evidence/sort-ingestion-comparison-{VERSION}.json')
    assert comparison['passed'] and len(comparison['scenarios'])==2
    for source,digest in comparison['source_sha256'].items():assert sha(ROOT/source)==digest,source
    for v in comparison['scenarios']:
        assert v['source_chain']['valid'] and not v['http_errors'] and v['fts_enabled']
        assert v['state_final']['sort']['indexed_rows']==(v['history_events']+v['new_events'] if v['sort_enabled'] else 0)
    archive=CArchiveReader(str(app/'GuardDesk.exe')).open_embedded_archive('PYZ.pyz');modules=[]
    for p in (ROOT/'guarddesk').glob('*.py'):
        name='guarddesk' if p.stem=='__init__' else 'guarddesk.'+p.stem
        if name in archive.toc:
            assert archive.extract(name)==compile(p.read_bytes(),str(p),'exec'),name;modules.append(name)
    assert 'guarddesk.audit_sort' in modules
    for area in ('static','windows'):
        for p in (ROOT/'guarddesk'/area).rglob('*'):
            if p.is_file():assert p.read_bytes()==(app/'_internal/guarddesk'/area/p.relative_to(ROOT/'guarddesk'/area)).read_bytes(),p
    manifest=read(app/'_internal/agent-release.json');assert manifest['version']==VERSION and manifest['files']=={k:v for k,v in actual.items() if k!='_internal/agent-release.json'}
    from guarddesk.native_installer import source_files
    verified,total=source_files(app);assert verified==actual
    previous=read(ROOT/'evidence/security/0.4.46/requirements-review.json');prior=previous['prior_archives_unchanged']
    for v in read(ROOT/'evidence/release-0.4.46-final.json')['archives']:prior[v['name']]=v['sha256']
    for name,digest in prior.items():assert sha(ROOT/'dist'/name)==digest,name
    allowed={'guarddesk/__init__.py','guarddesk/audit_search.py','guarddesk/audit_search_index.py','guarddesk/pagination.py','guarddesk/server.py','guarddesk/static/app.js','guarddesk/static/audit_ui.js','guarddesk/static/style.css','guarddesk/static/index.html'}
    build_changes={'tools/GuardDesk.spec'}
    changed=set();unchanged=[]
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.46-source.zip') as z:
        for name in z.namelist():
            if name.startswith(('guarddesk/','browser-extension/')) or name in ('requirements.txt','requirements-build.txt','app.py','tools/GuardDesk.spec','Setup-Management.cmd','Install-Endpoint.cmd','Install-Endpoint.ps1','Uninstall-Endpoint.cmd','Start-GuardDesk.ps1','Start-Remote.cmd','Diagnose-Remote.cmd'):
                assert (ROOT/name).is_file(),name
                if z.read(name)!=(ROOT/name).read_bytes():changed.add(name)
                else:unchanged.append(name)
        added={p.relative_to(ROOT).as_posix() for p in (ROOT/'guarddesk').glob('*.py') if p.relative_to(ROOT).as_posix() not in z.namelist()}
        def methods(raw):
            result={}
            for n in ast.parse(raw).body:
                if isinstance(n,ast.FunctionDef):result[n.name]=ast.dump(n,include_attributes=False)
                if isinstance(n,ast.ClassDef):
                    for f in n.body:
                        if isinstance(f,ast.FunctionDef):result[n.name+'.'+f.name]=ast.dump(f,include_attributes=False)
            return result
        method_changes={}
        for name,expected in [('guarddesk/server.py',{'Handler.route'}),('guarddesk/audit_search_index.py',{'install','Worker.run'})]:
            before=methods(z.read(name));after=methods((ROOT/name).read_bytes())
            assert before.keys()==after.keys()
            changed_methods={k for k in before if before[k]!=after[k]};assert changed_methods==expected
            method_changes[name]=sorted(changed_methods)
    assert changed==allowed|build_changes,(changed,allowed|build_changes);assert added=={'guarddesk/audit_sort.py'},added
    gate=read(ROOT/f'evidence/build-version-gate-{VERSION}.json')
    assert gate['passed'] and gate['actual_source_ui_accepted'] and gate['sealed_046_ui_rejected_before_Analysis']
    static=read(ROOT/f'evidence/static-finalization-{VERSION}.json')
    assert static['passed'] and static['exe_sha256']==actual['GuardDesk.exe'] and static['executables_unchanged'] and static['source_js_sha256']==sha(ROOT/'guarddesk/static/app.js')
    for name in ('event_storage','store','mail_reports','audit_reports','agent','native_installer','updater_maintenance','updater_refresh','custom_library'):
        assert 'guarddesk/'+name+'.py' in unchanged,name
    signatures=read(folder/'signatures.json')
    for v in signatures:assert sha(ROOT/v['path'])==v['sha256']
    links=0
    for name in ('README.md','doc/README.md','doc/60-engineering-lessons-and-regression-rules.md','doc/67-audit-column-sorting-0.4.47.md'):
        p=ROOT/name
        for target in re.findall(r'\]\(([^)]+)\)',p.read_text(encoding='utf-8-sig')):
            if target.startswith(('http:','https:','#','mailto:')):continue
            resolved=(p.parent/target.split('#')[0]).resolve();assert resolved.exists() or resolved==(folder/'requirements-review.json').resolve(),(name,target)
            links+=1
    report={'version':VERSION,'status':'unsigned_internal_trial','passed_with_gaps':True,'review_type':'developer_self_review_not_independent',
        'requirements':['SEC-01','SEC-04','SEC-05','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11','DEF-02','DEF-04'],'lessons':['GD-005','GD-014','GD-015','GD-016','GD-017','GD-020','GD-021'],
        'change':'Global column sorting with snapshot/anchor pagination and matching CSV; cooperatively prepared deduplicated full-text display keys',
        'controls':['Whitelisted fields/directions and parameterized comparisons; no sort key in cursor tokens; session/filter HMAC binding','Stable sort value/id tuples, immutable source snapshot, no truncation, device-name snapshot invalidation','Background derived tables independent of receipt transaction, bounded preparation/write slices, ingress priority and atomic coverage prefix; free-disk reserve','Queries over metadata/derived strings, not payload sort; shared two-query admission, SQL deadline/cancellation; no partial success','First-load/today/50 retained, real waiting and disabled repeat sorts, drafts/keyboard/aria arrows, failed-navigation recovery, CSV verified before download','Existing storage/collector/policy/mail/native installer/updater/remote sources byte-identical to sealed 46; dependencies unchanged'],
        'threat_analysis':{'assets':'Existing sensitive paths/accounts/URLs and immutable audit evidence','boundary':'Authenticated authorized audit reader -> validated metadata/key query -> escaped UI or formula-escaped CSV; background source decoding -> protected main database derived dictionary','risks':'SQL injection, cursor tampering or secret URLs, duplicate/skipped pages, payload decompression/DoS, index corruption and ingestion contention; controlled by whitelist/bind/HMAC/stable tuples/budgets/atomic slices','retention':'Derived strings add sensitive storage in existing protected control database and backups; no new collection, destinations or retention cleanup; company classification/encryption/retention still pending'},
        'tests':{'full_suite_rerun':True,'full_run_cases':int(m[1]),'seconds':float(m[2]),'log_sha256':sha(log),'new_sort_cases':13,'final_sort_seconds':float(fm[2]),'final_sort_log_sha256':sha(final_log),'final_unique_cases':509,'counting':'508 complete regression + 13 final sort tests, 12 overlapping = 509 distinct cases. Complete 509-case run not claimed; product Python unchanged after full run, final client dates/automatic-nonce and UI version/build gate verified in targeted/frozen exact-tree checks.'},
        'sort_performance':perf,'ingestion_performance':ingest,'fts_vs_sort_ingestion_comparison':comparison,'frozen_browsers':browsers,'compiled_modules_equal_source':modules,'application_files':len(actual),'application_bytes':total,'critical_sources_unchanged':unchanged,'changed_method_boundaries':method_changes,'source_files':{n:sha(ROOT/n) for n in sorted(allowed|added|build_changes)},'build_version_preflight':gate,'final_static_asset_tree':static,'prior_archives_unchanged':prior,'signatures':signatures,'document_links_checked':links,
        'candidate_failures':{name:sha(ROOT/'runtime'/name) for name in ('audit-sort-packaged-smoke-0447.txt','audit-search-browser-frozen-0447.txt','mail-reports-browser-frozen-0447.txt')},
        'development_findings':['Initial packaged HTTPS root still stamped 0.4.46 although EXE was 47; corrected index, added build-spec preflight with sealed old HTML rejection, rebuilt and reran final integration before packaging','Initial parallel audit-search/mail browser waits timed out; isolated checks passed unchanged EXEs, cause not established; all final integration runs serialized, no unsupported product fix claim','Initial unit oracle included device.enrolled despite a file-only query; corrected test scope, not production filtering','Initial browser wait_for_function used an eval-style string blocked by existing CSP; replaced by function polling, did not relax CSP','Initial ingestion fixture reset only FTS after historical seeding; final fixture resets both new-index states to the pre-upgrade head and waits for both coverages; initial log retained under runtime','Initial capacity fixture had only 754 shared strings; strengthened final fixture to 150004 strings so disk/cost is not inferred from duplicate-heavy data','Final extractor explicitly treats non-object/nontext legacy values as empty sort keys; original evidence unchanged'],
        'gaps':['No office Server/endpoint or tenant access/deployment; no actual company fleet latency acceptance','Initial history preparation consumes CPU/I/O/disk and may take minutes; ingestion can postpone readiness; no zero-cost claim','One full-index ingestion run had 2.376-second maximum/1.887-second P95 versus no-index 0.313/0.100; narrower FTS-only vs FTS+sort comparison measured 81-to-136ms P95, did not establish cause or fix for earlier spike; both retained in evidence','Broad metadata sorts may use temporary B-trees and time out; long unique paths increase storage beyond synthetic fixture','Unsigned, no full SBOM/vulnerability or independent review; company Win10/11 Defender/EDR lifecycle and rollback acceptance pending','Prior GD-006 generic source error and installer cloud-scan delay field gaps outside scope'],
        'office_server_or_endpoints_changed':False,'live_mail_sent':False}
    (folder/'requirements-review.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    shutil.copyfile(ROOT/'evidence/packaged-smoke.json',ROOT/f'evidence/packaged-smoke-{VERSION}.json')
    print(json.dumps({'passed':True,'full_tests':int(m[1]),'compiled_modules':len(modules),'runtime_files_changed':len(allowed|added),'document_links':links,'application_files':len(actual),'office_deployed':False}))

if __name__=='__main__':main()
