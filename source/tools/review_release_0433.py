"""Developer self-review: date-default UI scope and exact tested trial build."""
import hashlib
import json
from pathlib import Path
import re
import zipfile

ROOT=Path(__file__).resolve().parents[1]
VERSION='0.4.33'


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads((ROOT/path).read_text(encoding='utf-8-sig'))


def main():
    paths={'regression':f'evidence/server-deployment-check-{VERSION}.json',
           'dates':f'evidence/audit-date-defaults-{VERSION}.json',
           'browser':f'evidence/improvements-browser-{VERSION}.json',
           'navigation':f'evidence/navigation-performance-{VERSION}.json',
           'frozen':'evidence/packaged-smoke.json',
           'frozen_storage':f'evidence/packaged-storage-optimization-{VERSION}.json'}
    results={key:read(path) for key,path in paths.items()}
    assert all(r['passed'] for r in results.values())
    assert results['regression']['version']==VERSION and results['regression']['tests_run']>=308
    assert not results['regression']['cleanup_error']
    for key in ('dates','browser','navigation'):assert results[key]['page_errors']==[]
    signatures=read(f'evidence/security/{VERSION}/signatures.json')
    assert results['frozen']['exe_sha256']==results['frozen_storage']['exe_sha256']==signatures[0]['sha256']
    for item in signatures:assert sha(ROOT/item['path'])==item['sha256']
    app=ROOT/'dist/GuardDesk'
    actual={p.relative_to(app).as_posix():sha(p) for p in app.rglob('*') if p.is_file()}
    assert actual==results['frozen']['application_files']
    for p in (ROOT/'guarddesk/static').rglob('*'):
        if p.is_file():assert p.read_bytes()==(app/'_internal/guarddesk/static'/p.relative_to(ROOT/'guarddesk/static')).read_bytes()
    previous={'GuardDesk-0.4.32-windows-x64.zip':'4301e2c220a2cb2d6b3e19d4790c06324a610c11650e13624abe2216e088777b',
              'GuardDesk-0.4.32-source.zip':'872b129ae1f6d8a36cf2c9fdd36ad766e1d278277790aee1c3e60c1934ff2506'}
    for name,value in previous.items():assert sha(ROOT/'dist'/name)==value
    unchanged=[]
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.32-source.zip') as prior:
        changed=[n for n in prior.namelist() if n.startswith('guarddesk/') and (ROOT/n).is_file() and prior.read(n)!=(ROOT/n).read_bytes()]
        assert set(changed)=={'guarddesk/__init__.py','guarddesk/static/app.js','guarddesk/static/audit_ui.js','guarddesk/static/audit_reports_ui.js','guarddesk/static/index.html'}
        for name in prior.namelist():
            is_core=name.startswith('guarddesk/') and (name.endswith('.py') or name.startswith('guarddesk/windows/')) and name!='guarddesk/__init__.py'
            if is_core or name.startswith('browser-extension/') or name in ('requirements.txt','requirements-build.txt'):
                assert prior.read(name)==(ROOT/name).read_bytes(),name
                unchanged.append(name)
    links=0
    documents=['README.md','doc/README.md','doc/46-audit-today-defaults-0.4.33.md']
    for name in documents:
        source=ROOT/name
        for link in re.findall(r'\]\(([^)]+)\)',source.read_text(encoding='utf-8')):
            if link.startswith(('http:','https:','#','mailto:')):continue
            target=(source.parent/link.split('#')[0]).resolve()
            assert target==(ROOT/f'evidence/security/{VERSION}/requirements-review.json').resolve() or target.exists(),(name,link)
            links+=1
    report={'version':VERSION,'passed':True,'release_status':'unsigned_internal_trial',
        'review_type':'developer_self_review_not_independent',
        'applicable':['SEC-01','SEC-04','SEC-06','SEC-07','SEC-10','SEC-11','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],
        'data_flow':'Authenticated MIS/auditor UI -> explicit Taipei occurred-date bounds and existing session-bound 50-row cursor -> existing authorized metadata-first API; summary remains whole-period bounded aggregates with 50-device display pages',
        'threats_and_controls':[
            'Taipei day uses explicit UTC+8 epoch conversion; inclusive start and exclusive next-midnight end retain the final millisecond and prevent adjacent-day leakage',
            'Search/category/date quick filters retain end semantics; existing cursor filter identity resets paging when query changes',
            'Only Today mode rolls at midnight; custom history and report drilldowns remain fixed; login resets day defaults',
            'Existing role/CSRF/parameterized SQL/device scopes/signed cursors/response generation checks unchanged',
            'Summary total/pie/trend cover entire selected range while bar/ranking show 50 devices; no claim of new summary backend paging',
            'No new collection, elevated permissions, startup jobs, network destinations, dependencies, Defender changes or logical event deletion'],
        'tests_run':results['regression']['tests_run'],'document_links_checked':links,
        'evidence':{key:{'path':path,'sha256':sha(ROOT/path),'passed':results[key]['passed']} for key,path in paths.items()},
        'signatures':signatures,'unchanged_backend_windows_browser_sources':unchanged,
        'changed_product_files_from_sealed_0_4_32':changed,
        'prior_sealed_archives_unchanged':previous,'feature_document':'doc/46-audit-today-defaults-0.4.33.md',
        'limitations':[
            'Browser fixtures prove behavior, not office Server latency or 250 physical endpoints',
            'UI defaults only; APIs without explicit date bounds retain compatibility behavior',
            'Total/pie aggregate the entire selected range; summary returns at most 1000 ranked rows as before',
            'History capacity/retention unchanged; large text searches can still cost more',
            'Unsigned internal trial; company Authenticode/full SBOM/weakness gates, independent review, Windows10/office Server/Defender EDR/fleet acceptance incomplete']}
    (ROOT/f'evidence/security/{VERSION}/requirements-review.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(f'{VERSION}: exact application tree, date/paging browser tests, {report["tests_run"]} regressions, {len(unchanged)} unchanged core files and {links} links verified; unsigned internal trial.')


if __name__=='__main__':main()
