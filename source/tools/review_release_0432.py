"""Self-review of the exact tested audit/storage optimization build; no deployment."""
import hashlib
import json
import re
import zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
VERSION='0.4.32'


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads((ROOT/path).read_text(encoding='utf-8-sig'))


def main():
    paths={'regression':f'evidence/server-deployment-check-{VERSION}.json',
           'frozen':'evidence/packaged-smoke.json',
           'frozen_storage':f'evidence/packaged-storage-optimization-{VERSION}.json',
           'performance':f'evidence/storage-performance-{VERSION}.json',
           'navigation':f'evidence/navigation-performance-{VERSION}.json',
           'metadata_plan':f'evidence/metadata-query-plan-{VERSION}.json',
           'browser':f'evidence/improvements-browser-{VERSION}.json',
           'legacy':f'evidence/server-source-legacy-{VERSION}.json'}
    results={key:read(path) for key,path in paths.items()}
    assert all(r['passed'] for r in results.values())
    assert results['regression']['version']==VERSION and results['regression']['tests_run']>=308
    assert results['browser']['page_errors']==[] and not results['regression'].get('cleanup_error')
    assert results['performance']['events']>=1648034 and results['performance']['optimization']['history_preserved']
    assert results['navigation']['late_response_did_not_overwrite'] and results['navigation']['stats_skipped_for_audit_and_report']
    focused=(ROOT/f'evidence/storage-optimization-unit-{VERSION}.txt').read_text(encoding='utf-8-sig')
    assert 'Ran 12 tests' in focused and focused.rstrip().endswith('OK')
    signatures=read(f'evidence/security/{VERSION}/signatures.json')
    assert results['frozen']['exe_sha256']==results['frozen_storage']['exe_sha256']==signatures[0]['sha256']
    for item in signatures:assert sha(ROOT/item['path'])==item['sha256']
    actual={p.relative_to(ROOT/'dist/GuardDesk').as_posix():sha(p) for p in (ROOT/'dist/GuardDesk').rglob('*') if p.is_file()}
    assert actual==results['frozen']['application_files']
    assert (ROOT/'dist/GuardDesk/_internal/guarddesk/static/index.html').read_bytes()==(ROOT/'guarddesk/static/index.html').read_bytes()
    assert (ROOT/'dist/GuardDesk/_internal/guarddesk/static/app.js').read_bytes()==(ROOT/'guarddesk/static/app.js').read_bytes()
    previous={'GuardDesk-0.4.31-windows-x64.zip':'ca0fc27008d7de3a0aa042fa7f7f5bfb8d4f9c1ad310445c00953e14b2affd87',
              'GuardDesk-0.4.31-source.zip':'fad38f67aa4246635b97759f2b3497b94b3da793f03d15672c2858315fbf5a90'}
    for name,value in previous.items():assert sha(ROOT/'dist'/name)==value
    unchanged=['guarddesk/update_native.py','guarddesk/update_client.py','guarddesk/updater_refresh.py',
               'guarddesk/source_permissions.py','guarddesk/policy.py','guarddesk/file_exclusions.py',
               'requirements.txt','requirements-build.txt']
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.31-source.zip') as prior:
        for name in unchanged:assert prior.read(name)==(ROOT/name).read_bytes(),name
    documents=['README.md','doc/README.md','doc/02-architecture.md','doc/45-audit-query-and-storage-optimization-0.4.32.md'];links=0
    for name in documents:
        source=ROOT/name
        for link in re.findall(r'\]\(([^)]+)\)',source.read_text(encoding='utf-8')):
            if link.startswith(('http:','https:','#','mailto:')):continue
            resolved=(source.parent/link.split('#')[0]).resolve()
            assert resolved==(ROOT/f'evidence/security/{VERSION}/requirements-review.json').resolve() or resolved.exists(),(name,link)
            links+=1
    report={'version':VERSION,'passed':True,'release_status':'unsigned_internal_trial',
        'review_type':'developer_self_review_not_independent',
        'applicable':['SEC-01','SEC-03','SEC-04','SEC-05','SEC-06','SEC-07','SEC-08','SEC-09','SEC-10','SEC-11','DEF-01','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],
        'data_flow':'Authenticated event -> durable control transaction -> bounded WAL day writer -> metadata-first query and selected payload verification; offline lease -> complete backup -> lossless migration/index/chain verification -> compaction',
        'threats_and_controls':[
            'Existing role/CSRF/TLS/wire validation retained; stats omission is read-only and does not expand access',
            'Request generations, user checks and cancellation prevent stale page or prior-login data overwrites; POST mutations not cancelled',
            'Pure metadata view/family indexes and two PK head seeks avoid payload scans for lists and summary progress',
            'Exact original IDs, timestamps, details text and hashes retained; atomic catalog/pending/source removal and post-FULL finalization',
            'Mixed legacy/catalog ID allocation uses the true maximum; broken hash, ID conflict and disk errors stop without skipping history',
            'OS lease for Server/optimizer and explicit shared listener lifetime; fixed local paths, private backup/day folders and reparse checks',
            'At most two WAL writers, 2048 rows/2 MiB batch, 64 MiB pending cap, bounded payload expansion and rollup batches',
            'SQLite backup includes committed WAL and referenced day files; original-chain and integrity checks precede success',
            'No new collection types, elevated permission, startup tasks, third-party dependency, external destination or Defender/EDR changes',
            'Global indexes and retained history still grow; no implicit history deletion or unlimited-capacity claim'],
        'tests_run':results['regression']['tests_run'],'focused_tests':12,
        'evidence':{key:{'path':path,'sha256':sha(ROOT/path),'passed':results[key]['passed']} for key,path in paths.items()},
        'signatures':signatures,'document_links_checked':links,'prior_sealed_archives_unchanged':previous,
        'unchanged_sensitive_sources':unchanged,
        'feature_document':'doc/45-audit-query-and-storage-optimization-0.4.32.md',
        'validation_note':'Initial regression issues and intermediate Windows cleanup failure are preserved; final report requires clean fixtures. Large copy resumed after bounded bulk/WAL and metadata-affinity fixes; not a fresh full-run throughput benchmark. Header-plan regressions and explicit cached-writer ownership/offline missing-day test verified. Final binary smoke is tied to exact application hashes.',
        'performance_scope':results['performance']['limits'],
        'limitations':[
            'Large benchmark uses a read-only older development DB and private disposable copy; not office Server HTTP/250 physical Agents',
            'Full text/date-wide searches can still cost more than ordinary indexed first-page browsing',
            'Central catalog/statistics and all logical history retained; backups separate; no automatic retention deletion',
            'Original Store hash-chain format remains; no external WORM/signature anchor added',
            'Windows 10, actual office SYSTEM update, company signing/full supply-chain gates, independent review and Defender/EDR remain incomplete']}
    (ROOT/f'evidence/security/{VERSION}/requirements-review.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(f'{VERSION}: exact tested build, focused/full evidence, {links} links and unchanged prior ZIPs verified; unsigned internal trial.')


if __name__=='__main__':main()
