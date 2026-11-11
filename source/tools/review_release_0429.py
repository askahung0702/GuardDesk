"""Check the exact evidence and unsigned build before local packaging."""
import hashlib
import json
import re
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
VERSION='0.4.29'


def read(path):return json.loads((ROOT/path).read_text(encoding='utf-8-sig'))


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    evidence={key:read(path) for key,path in {
        'regression':f'evidence/server-deployment-check-{VERSION}.json',
        'browser':f'evidence/improvements-browser-{VERSION}.json',
        'legacy':f'evidence/server-source-legacy-{VERSION}.json',
        'frozen':'evidence/packaged-smoke.json',
        'frozen_feature':f'evidence/packaged-improvements-{VERSION}.json',
        'capacity':'evidence/daily-storage-benchmark-0.4.28.json',
    }.items()}
    assert all(r['passed'] for r in evidence.values())
    assert evidence['regression']['version']==VERSION and evidence['regression']['tests_run']>=281
    assert evidence['browser']['page_errors']==[]
    focused=(ROOT/f'evidence/source-permissions-unit-{VERSION}.txt').read_text(encoding='utf-8-sig')
    assert 'Ran 20 tests' in focused and focused.rstrip().endswith('OK')
    signatures=read(f'evidence/security/{VERSION}/signatures.json')
    assert evidence['frozen']['exe_sha256']==evidence['frozen_feature']['exe_sha256']==signatures[0]['sha256']
    for item in signatures:assert sha(ROOT/item['path'])==item['sha256']
    actual={p.relative_to(ROOT/'dist/GuardDesk').as_posix():sha(p) for p in (ROOT/'dist/GuardDesk').rglob('*') if p.is_file()}
    assert actual==evidence['frozen']['application_files']
    assert (ROOT/'dist/GuardDesk/_internal/guarddesk/static/improvements_ui.js').read_bytes()==(ROOT/'guarddesk/static/improvements_ui.js').read_bytes()
    assert (ROOT/'dist/GuardDesk/_internal/guarddesk/static/style.css').read_bytes()==(ROOT/'guarddesk/static/style.css').read_bytes()
    previous={'GuardDesk-0.4.28-windows-x64.zip':'24824ae7d52ec91b3e2c0331747fcba7a0e98799f4e103be31df27882fcff581',
              'GuardDesk-0.4.28-source.zip':'975ec0d5059f3c01a5dd0375d7ef35fd77236ddff294b1bbfe6810f89f0b5724'}
    for name,value in previous.items():assert sha(ROOT/'dist'/name)==value
    documents=['doc/42-bundled-release-source-permissions-0.4.29.md','README.md','doc/07-ui-reference-and-policy-model.md','doc/40-ipguard-shared-installation-and-storage-analysis.md','doc/41-daily-storage-and-policy-workflow-0.4.28.md']
    links=0
    for filename in documents:
        source=ROOT/filename
        for link in re.findall(r'\]\(([^)]+)\)',source.read_text(encoding='utf-8')):
            if link.startswith(('http:','https:','#','mailto:')):continue
            target=link.split('#')[0]
            resolved=(source.parent/target).resolve()
            assert resolved==(ROOT/f'evidence/security/{VERSION}/requirements-review.json').resolve() or resolved.exists(),(filename,link)
            links+=1
    import zipfile
    with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.28-source.zip') as prior:
        assert prior.read('guarddesk/update_native.py')==(ROOT/'guarddesk/update_native.py').read_bytes()
        assert prior.read('guarddesk/event_storage.py')==(ROOT/'guarddesk/event_storage.py').read_bytes()
    report={'version':VERSION,'release_status':'unsigned_internal_trial','review_type':'developer_self_review_not_independent',
        'passed':True,'applicable':['SEC-01','SEC-03','SEC-04','SEC-05','SEC-06','SEC-07','SEC-08','SEC-10','SEC-11','DEF-02','DEF-03','DEF-04','DEF-05','DEF-06'],
        'data_flows':['MIS field operations -> Server-resolved complete legacy-compatible policy -> existing authenticated Agent channel',
                      'Authenticated events -> bounded durable catalog/pending transaction -> FULL day commit -> catalog finalization -> original-hash-verified read',
                      'MIS daily activation -> private pre-switch snapshot -> transactional view switch, no historic deletion',
                      'Authorized queries -> HMAC session/filter/snapshot cursor -> bounded page; optional date export and consistent control/day backup',
                      'MIS context -> query/assignment/update target preselection; never automatic grants or deployment'],
        'controls':['Existing MIS, auditor, support, CSRF, TLS and revision checks retained',
                    'Append restricted to exclusion lists, validation after resolved compositions; old policies keep whole-module semantics',
                    'Bounded decompression, pending backpressure, two read handles, transaction replay and missing/corrupt-day failures',
                    'Private directory ACL/reparse guards, no arbitrary SQL or shell input, backup includes referenced day files',
                    'No new collection kind, privilege, startup task, dependency, external destination or Defender setting change',
                    'State receipt and reported configuration are explicitly separated from physical enforcement',
                    'Local storage contains numeric column sizes only; target context and drafts cleared on logout'],
        'tests_run':evidence['regression']['tests_run'],'focused_tests':20,
        'evidence':{key:{'passed':value['passed'],'sha256':sha(ROOT/path)} for key,path in {
            'regression':f'evidence/server-deployment-check-{VERSION}.json','browser':f'evidence/improvements-browser-{VERSION}.json',
            'legacy':f'evidence/server-source-legacy-{VERSION}.json','frozen':'evidence/packaged-smoke.json',
            'frozen_feature':f'evidence/packaged-improvements-{VERSION}.json','capacity':'evidence/daily-storage-benchmark-0.4.28.json'}.items() for value in [evidence[key]]},
        'signatures':signatures,'document_links_checked':links,'prior_sealed_archives_unchanged':True,
        'capacity_observation':evidence['capacity'],
        'limitations':['Old history is retained; no immediate size reduction or automatic retention/cleanup',
                       'Daily queries add payload decompression and original-hash verification; do not claim universal speedup',
                       '250 synthetic identifiers/page checks are not 250 concurrent physical Agents or daily capacity acceptance',
                       'Office DB switch, actual SYSTEM update/rollback, Windows 10 and company Defender/EDR were not accepted',
                       'Authenticode, complete SBOM/vulnerability gates and independent security review remain incomplete',
                       'Daily storage needs control plus day files for restore; old EXE alone cannot reverse the schema',
                       'Broader search indexing, offline day lifecycle and controlled migration of legacy data remain future work'],
        'feature_document':'doc/42-bundled-release-source-permissions-0.4.29.md',
        'current_change':['Dedicated read-only server source ACL validation; original SYSTEM broker validation unchanged',
                          'TrustedInstaller owner accepted, inherit-only ACE applies to children; source children checked individually',
                          'Ancestor FILE_ADD_SUBDIRECTORY alone allowed, all other original write masks retained',
                          'Actual nontrusted write/owner, unknown grants, reparse and bad manifest remain rejected',
                          'Structured failed-source path/reason shown only to MIS; no ACL modification API or arbitrary source selector'],
        'validation_order':'Full regression plus final 20 focused tests and frozen build; a final narrowing of ancestor EA/attribute rights was verified by the focused negative tests and final frozen positive registration',
        'capacity_scope':'0.4.28 unchanged storage engine synthetic measurement; not newly measured in this permission fix'}
    (ROOT/f'evidence/security/{VERSION}/requirements-review.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(f'{VERSION}: exact build/evidence, {links} local links and sealed prior archives verified; unsigned internal trial.')


if __name__=='__main__':main()
